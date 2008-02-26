#include "xenvbd.h"
#include <io/blkif.h>
#include <scsi.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <stdlib.h>
#include <xen_public.h>
#include <io/xenbus.h>
#include <io/protocols.h>

#pragma warning(disable: 4127)

#define wmb() KeMemoryBarrier()
#define mb() KeMemoryBarrier()

DRIVER_INITIALIZE DriverEntry;

static ULONG
XenVbd_HwScsiFindAdapter(PVOID DeviceExtension, PVOID HwContext, PVOID BusInformation, PCHAR ArgumentString, PPORT_CONFIGURATION_INFORMATION ConfigInfo, PBOOLEAN Again);
static BOOLEAN
XenVbd_HwScsiInitialize(PVOID DeviceExtension);
static BOOLEAN
XenVbd_HwScsiStartIo(PVOID DeviceExtension, PSCSI_REQUEST_BLOCK Srb);
static BOOLEAN
XenVbd_HwScsiInterrupt(PVOID DeviceExtension);
static BOOLEAN
XenVbd_HwScsiResetBus(PVOID DeviceExtension, ULONG PathId);
static BOOLEAN
XenVbd_HwScsiAdapterState(PVOID DeviceExtension, PVOID Context, BOOLEAN SaveState);
static SCSI_ADAPTER_CONTROL_STATUS
XenVbd_HwScsiAdapterControl(PVOID DeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif

static BOOLEAN DumpMode;

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  ULONG Status;
  HW_INITIALIZATION_DATA HwInitializationData;

  KdPrint((__DRIVER_NAME " --> "__FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  RtlZeroMemory(&HwInitializationData, sizeof(HW_INITIALIZATION_DATA));

  HwInitializationData.HwInitializationDataSize = sizeof(HW_INITIALIZATION_DATA);
  HwInitializationData.AdapterInterfaceType = Internal; //PNPBus;
  HwInitializationData.HwInitialize = XenVbd_HwScsiInitialize;
  HwInitializationData.HwStartIo = XenVbd_HwScsiStartIo;
  HwInitializationData.HwInterrupt = XenVbd_HwScsiInterrupt;
  HwInitializationData.HwFindAdapter = XenVbd_HwScsiFindAdapter;
  HwInitializationData.HwResetBus = XenVbd_HwScsiResetBus;
  HwInitializationData.HwDmaStarted = NULL;
  HwInitializationData.HwAdapterState = XenVbd_HwScsiAdapterState;
  HwInitializationData.DeviceExtensionSize = sizeof(XENVBD_DEVICE_EXTENSION); //sizeof(XENVBD_DEVICE_DATA);
  HwInitializationData.SpecificLuExtensionSize = 0;
  HwInitializationData.SrbExtensionSize = 0;
  HwInitializationData.NumberOfAccessRanges = 1;
  HwInitializationData.MapBuffers = TRUE;
  HwInitializationData.NeedPhysicalAddresses = FALSE;
  HwInitializationData.TaggedQueuing = TRUE;
  HwInitializationData.AutoRequestSense = FALSE;
  HwInitializationData.MultipleRequestPerLu = TRUE;
  HwInitializationData.ReceiveEvent = FALSE;
  HwInitializationData.VendorIdLength = 0;
  HwInitializationData.VendorId = NULL;
  HwInitializationData.DeviceIdLength = 0;
  HwInitializationData.DeviceId = NULL;
  HwInitializationData.HwAdapterControl = XenVbd_HwScsiAdapterControl;

  DumpMode = FALSE;

  Status = ScsiPortInitialize(DriverObject, RegistryPath, &HwInitializationData, NULL);

  if(!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME " ScsiPortInitialize failed with status 0x%08x\n", Status));
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return Status;
}

static __inline uint64_t
GET_ID_FROM_FREELIST(PXENVBD_TARGET_DATA TargetData)
{
  uint64_t free;
  free = TargetData->shadow_free;
  TargetData->shadow_free = TargetData->shadow[free].req.id;
  TargetData->shadow[free].req.id = 0x0fffffee; /* debug */
  return free;
}

static __inline VOID
ADD_ID_TO_FREELIST(PXENVBD_TARGET_DATA TargetData, uint64_t Id)
{
  TargetData->shadow[Id].req.id  = TargetData->shadow_free;
  TargetData->shadow[Id].Srb = NULL;
  TargetData->shadow_free = Id;
}

static BOOLEAN
XenVbd_Interrupt(PKINTERRUPT Interrupt, PVOID DeviceExtension)
{
  PXENVBD_TARGET_DATA TargetData = (PXENVBD_TARGET_DATA)DeviceExtension;

  UNREFERENCED_PARAMETER(Interrupt);

if (DumpMode)
{
  KdPrint((__DRIVER_NAME " --> Interrupt\n"));
}

  TargetData->PendingInterrupt = TRUE;

if (DumpMode)
{
  KdPrint((__DRIVER_NAME " <-- Interrupt\n"));
}

  return TRUE;
}

static blkif_response_t *
XenVbd_GetResponse(PXENVBD_TARGET_DATA TargetData, int i)
{
  blkif_other_response_t *rep;
  if (!TargetData->use_other)
    return RING_GET_RESPONSE(&TargetData->Ring, i);
  rep = RING_GET_RESPONSE(&TargetData->OtherRing, i);
  TargetData->tmp_rep.id = rep->id;
  TargetData->tmp_rep.operation = rep->operation;
  TargetData->tmp_rep.status = rep->status;
  return &TargetData->tmp_rep;
}

static VOID
XenVbd_HwScsiInterruptTarget(PVOID DeviceExtension)
{
  PXENVBD_TARGET_DATA TargetData = (PXENVBD_TARGET_DATA)DeviceExtension;
  PSCSI_REQUEST_BLOCK Srb;
  RING_IDX i, rp;
  blkif_response_t *rep;
  int BlockCount;
  PXENVBD_DEVICE_DATA DeviceData = (PXENVBD_DEVICE_DATA)TargetData->DeviceData;
  int more_to_do = TRUE;

if (DumpMode)
{
  KdPrint((__DRIVER_NAME " --> HwScsiInterruptTarget\n"));
}

  while (more_to_do)
  {
    rp = TargetData->Ring.sring->rsp_prod;
    KeMemoryBarrier();
    for (i = TargetData->Ring.rsp_cons; i != rp; i++)
    {
      rep = XenVbd_GetResponse(TargetData, i);

      //KdPrint((__DRIVER_NAME "     rep = %p\n", rep));
      //KdPrint((__DRIVER_NAME "     rep->id = %d\n", rep->id));

      /*
       * This code is to automatically detect if the backend is using the same
       * bit width or a different bit width to us. Later versions of Xen do this
       * via a xenstore value, but not all. That 0x0fffffff (notice
       * that the msb is not actually set, so we don't have any problems with
       * sign extending) is to signify the last entry on the right, which is
       * different under 32 and 64 bits, and that is why we set it up there.

       * To do the detection, we put two initial entries on the ring, with an op
       * of 0xff (which is invalid). The first entry is mostly okay, but the
       * second will be grossly misaligned if the backend bit width is different,
       * and we detect this and switch frontend structures.
       */
      switch (TargetData->ring_detect_state)
      {
      case 0:
        KdPrint((__DRIVER_NAME "     ring_detect_state = %d, operation = %x, id = %lx, status = %d\n", TargetData->ring_detect_state, rep->operation, rep->id, rep->status));
        TargetData->ring_detect_state = 1;
        break;
      case 1:
        KdPrint((__DRIVER_NAME "     ring_detect_state = %d, operation = %x, id = %lx, status = %d\n", TargetData->ring_detect_state, rep->operation, rep->id, rep->status));
        if (rep->operation != 0xff)
        {
          TargetData->Ring.nr_ents = BLK_OTHER_RING_SIZE;
          TargetData->use_other = TRUE;
        }
        TargetData->shadow[TargetData->Ring.nr_ents - 1].req.id = 0x0fffffff;
        DeviceData->BusChangePending = 1;
        TargetData->ring_detect_state = 2;
        break;
      case 2:
        Srb = TargetData->shadow[rep->id].Srb;
        if (Srb != NULL)
        {
          BlockCount = (Srb->Cdb[7] << 8) | Srb->Cdb[8];
  
          if (rep->status == BLKIF_RSP_OKAY)
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
          else
          {
            KdPrint((__DRIVER_NAME "     Xen Operation returned error\n"));
            if (Srb->Cdb[0] == SCSIOP_READ)
              KdPrint((__DRIVER_NAME "     Operation = Read\n"));
            else
              KdPrint((__DRIVER_NAME "     Operation = Write\n"));     
            KdPrint((__DRIVER_NAME "     Sector = %08X, Count = %d\n", TargetData->shadow[rep->id].req.sector_number, BlockCount));
            Srb->SrbStatus = SRB_STATUS_ERROR;
          }
          if (Srb->Cdb[0] == SCSIOP_READ)
            memcpy(Srb->DataBuffer, TargetData->shadow[rep->id].Buf, BlockCount * TargetData->BytesPerSector);
    
          ScsiPortNotification(RequestComplete, DeviceData->DeviceExtension, Srb);
          if (!DumpMode)
            ScsiPortNotification(NextLuRequest, DeviceData->DeviceExtension, Srb->PathId, Srb->TargetId, Srb->Lun);
          else
            ScsiPortNotification(NextRequest, DeviceData->DeviceExtension);
        }
        ADD_ID_TO_FREELIST(TargetData, rep->id);
      }
    }

    TargetData->Ring.rsp_cons = i;
    if (i != TargetData->Ring.req_prod_pvt)
    {
      RING_FINAL_CHECK_FOR_RESPONSES(&TargetData->Ring, more_to_do);
    }
    else
    {
      TargetData->Ring.sring->rsp_event = i + 1;
      more_to_do = FALSE;
    }
  }

if (DumpMode)
{
  KdPrint((__DRIVER_NAME " <-- HwScsiInterruptTarget\n"));
}
}

static BOOLEAN
XenVbd_HwScsiInterrupt(PVOID DeviceExtension)
{
  PXENVBD_DEVICE_DATA DeviceData;
  PXENVBD_TARGET_DATA TargetData;
  int i, j;

if (DumpMode)
{
  KdPrint((__DRIVER_NAME " --> HwScsiInterrupt\n"));
}

  DeviceData = ((PXENVBD_DEVICE_EXTENSION)DeviceExtension)->XenVbdDeviceData;

  KeMemoryBarrier();
  for (i = 0; i < SCSI_BUSES; i++)
  {
    for (j = 0; j < SCSI_TARGETS_PER_BUS; j++)
    {
      TargetData = &DeviceData->BusData[i].TargetData[j];
      if (TargetData->PendingInterrupt || (TargetData->Present && DumpMode))
        XenVbd_HwScsiInterruptTarget(TargetData);
      TargetData->PendingInterrupt = FALSE;
    }
  }
if (DumpMode)
{
  KdPrint((__DRIVER_NAME " <-- HwScsiInterrupt\n"));
}

  return FALSE;
}

static VOID
XenVbd_BackEndStateHandler(char *Path, PVOID Data)
{
  PXENVBD_TARGET_DATA TargetData;
  PXENVBD_DEVICE_DATA DeviceData;
  char TmpPath[128];
  char *Value;
  int NewState;
  PMDL Mdl;
  grant_ref_t ref;
  blkif_sring_t *SharedRing;
  ULONG PFN;
  ULONG i, j;
  blkif_request_t *req;
  int notify;

  KdPrint((__DRIVER_NAME " --> BackEndStateHandler\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  TargetData = (PXENVBD_TARGET_DATA)Data;
  DeviceData = (PXENVBD_DEVICE_DATA)TargetData->DeviceData;

  DeviceData->XenDeviceData->XenInterface.XenBus_Read(
    DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
    XBT_NIL, Path, &Value);

  NewState = atoi(Value);
  switch (NewState)
  {
  case XenbusStateUnknown:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Unknown\n"));  
    break;

  case XenbusStateInitialising:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialising\n"));  
    break;

  case XenbusStateInitWait:
    KdPrint((__DRIVER_NAME "     Backend State Changed to InitWait\n"));  

    TargetData->EventChannel = DeviceData->XenDeviceData->XenInterface.EvtChn_AllocUnbound(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context, 0);
    DeviceData->XenDeviceData->XenInterface.EvtChn_Bind(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      TargetData->EventChannel, XenVbd_Interrupt, TargetData);
    Mdl = AllocatePage();
    PFN = (ULONG)*MmGetMdlPfnArray(Mdl);
    SharedRing = (blkif_sring_t *)MmGetMdlVirtualAddress(Mdl);
    RtlZeroMemory(SharedRing, PAGE_SIZE);
    SHARED_RING_INIT(SharedRing);
    FRONT_RING_INIT(&TargetData->Ring, SharedRing, PAGE_SIZE);
    ref = DeviceData->XenDeviceData->XenInterface.GntTbl_GrantAccess(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      0, PFN, FALSE);
    ASSERT((signed short)ref >= 0);
    TargetData->ring_detect_state = 0;
    TargetData->shadow = ExAllocatePoolWithTag(NonPagedPool, sizeof(blkif_shadow_t) * max(BLK_RING_SIZE, BLK_OTHER_RING_SIZE), XENVBD_POOL_TAG);

    memset(TargetData->shadow, 0, sizeof(blkif_shadow_t) * max(BLK_RING_SIZE, BLK_OTHER_RING_SIZE));
    for (i = 0; i < max(BLK_RING_SIZE, BLK_OTHER_RING_SIZE); i++)
    {
      TargetData->shadow[i].req.id = i + 1;
      TargetData->shadow[i].Mdl = AllocatePages(BLKIF_MAX_SEGMENTS_PER_REQUEST); // stupid that we have to do this!
      TargetData->shadow[i].Buf = MmGetMdlVirtualAddress(TargetData->shadow[i].Mdl);
      for (j = 0; j < BLKIF_MAX_SEGMENTS_PER_REQUEST; j++)
      {
        TargetData->shadow[i].req.seg[j].gref = DeviceData->XenDeviceData->XenInterface.GntTbl_GrantAccess(
          DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
          0, (ULONG)MmGetMdlPfnArray(TargetData->shadow[i].Mdl)[j], FALSE);
        ASSERT((signed short)TargetData->shadow[i].req.seg[j].gref >= 0);
      }
    }
    TargetData->shadow_free = 0;

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/protocol");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%s", XEN_IO_PROTO_ABI_NATIVE);

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/ring-ref");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", ref);

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/event-channel");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", TargetData->EventChannel);

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/state");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context, 
      XBT_NIL, TmpPath, "%d", XenbusStateInitialised);

/*
    KdPrint((__DRIVER_NAME "     sizeof(blkif_request) = %d\n", sizeof(struct blkif_request)));
    KdPrint((__DRIVER_NAME "     sizeof(blkif_request_segment) = %d\n", sizeof(struct blkif_request_segment)));
    KdPrint((__DRIVER_NAME "     sizeof(blkif_response) = %d\n", sizeof(struct blkif_response)));
    KdPrint((__DRIVER_NAME "     operation = %d\n", (int)((char *)(&req.operation) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     nr_segments = %d\n", (int)((char *)(&req.nr_segments) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     handle = %d\n", (int)((char *)(&req.handle) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     id = %d\n", (int)((char *)(&req.id) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     sector_number = %d\n", (int)((char *)(&req.sector_number) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     seg = %d\n", (int)((char *)(&req.seg) - (char *)(&req))));

    KdPrint((__DRIVER_NAME "     id = %d\n", (int)((char *)(&rep.id) - (char *)(&rep))));
    KdPrint((__DRIVER_NAME "     operation = %d\n", (int)((char *)(&rep.operation) - (char *)(&rep))));
    KdPrint((__DRIVER_NAME "     status = %d\n", (int)((char *)(&rep.status) - (char *)(&rep))));

    KdPrint((__DRIVER_NAME "     sizeof(union blkif_sring_entry) = %d\n", sizeof(union blkif_sring_entry)));
    KdPrint((__DRIVER_NAME "     %d\n", (int)((char *)(&entries[1]) - (char *)(&entries[0]))));
*/
    KdPrint((__DRIVER_NAME "     Set Frontend state to Initialised\n"));
    break;

  case XenbusStateInitialised:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialised\n"));
    break;

  case XenbusStateConnected:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Connected\n"));  

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/device-type");
    DeviceData->XenDeviceData->XenInterface.XenBus_Read(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    if (strcmp(Value, "disk") == 0)
    {
      KdPrint((__DRIVER_NAME "     DeviceType = Disk\n"));    
      TargetData->DeviceType = XENVBD_DEVICETYPE_DISK;
    }
    else if (strcmp(Value, "cdrom") == 0)
    {
      KdPrint((__DRIVER_NAME "     DeviceType = CDROM\n"));    
      TargetData->DeviceType = XENVBD_DEVICETYPE_CDROM;
    }
    else
    {
      KdPrint((__DRIVER_NAME "     DeviceType = %s (This probably won't work!)\n", Value));
      TargetData->DeviceType = XENVBD_DEVICETYPE_UNKNOWN;
    }

    RtlStringCbCopyA(TmpPath, 128, TargetData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/type"); // should probably check that this is 'phy' or 'file' or at least not ''
    DeviceData->XenDeviceData->XenInterface.XenBus_Read(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    KdPrint((__DRIVER_NAME "     Backend Type = %s\n", Value));
    ExFreePool(Value);

    RtlStringCbCopyA(TmpPath, 128, TargetData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/mode"); // should store this...
    DeviceData->XenDeviceData->XenInterface.XenBus_Read(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    KdPrint((__DRIVER_NAME "     Backend Mode = %s\n", Value));
    ExFreePool(Value);

    RtlStringCbCopyA(TmpPath, 128, TargetData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/sector-size");
    DeviceData->XenDeviceData->XenInterface.XenBus_Read(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    // should complain if Value == NULL
    TargetData->BytesPerSector = atoi(Value);

    KdPrint((__DRIVER_NAME "     BytesPerSector = %d\n", TargetData->BytesPerSector));    

    RtlStringCbCopyA(TmpPath, 128, TargetData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/sectors");
    DeviceData->XenDeviceData->XenInterface.XenBus_Read(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    // should complain if Value == NULL
    TargetData->TotalSectors = (ULONGLONG)atol(Value);

    KdPrint((__DRIVER_NAME "     TotalSectors = %d\n", TargetData->TotalSectors));    

    // should probably use the partition table (if one exists) here for the sectorspertrack and trackspercylinder values
    TargetData->Geometry.MediaType = FixedMedia;
    TargetData->Geometry.BytesPerSector = TargetData->BytesPerSector;
    TargetData->Geometry.SectorsPerTrack = 63;
    TargetData->Geometry.TracksPerCylinder = 255;
    TargetData->Geometry.Cylinders.QuadPart = TargetData->TotalSectors / TargetData->Geometry.SectorsPerTrack / TargetData->Geometry.TracksPerCylinder;
    KdPrint((__DRIVER_NAME "     Geometry C/H/S = %d/%d/%d\n", TargetData->Geometry.Cylinders.LowPart, TargetData->Geometry.TracksPerCylinder, TargetData->Geometry.SectorsPerTrack));
    
    req = RING_GET_REQUEST(&TargetData->Ring, TargetData->Ring.req_prod_pvt);
    req->operation = 0xff;
    req->nr_segments = 0;
    for (i = 0; i < req->nr_segments; i++)
    {
      req->seg[i].gref = 0xffffffff;
      req->seg[i].first_sect = 0xff;
      req->seg[i].last_sect = 0xff;
    }
    TargetData->Ring.req_prod_pvt++;
    req = RING_GET_REQUEST(&TargetData->Ring, TargetData->Ring.req_prod_pvt);
    req->operation = 0xff;
    req->nr_segments = 0;
    for (i = 0; i < req->nr_segments; i++)
    {
      req->seg[i].gref = 0xffffffff;
      req->seg[i].first_sect = 0xff;
      req->seg[i].last_sect = 0xff;
    }
    TargetData->Ring.req_prod_pvt++;
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&TargetData->Ring, notify);
    if (notify)
      DeviceData->XenDeviceData->XenInterface.EvtChn_Notify(
        DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
        TargetData->EventChannel);

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/state");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context, XBT_NIL, TmpPath, "%d", XenbusStateConnected);

    KdPrint((__DRIVER_NAME "     Set Frontend state to Connected\n"));
    InterlockedIncrement(&DeviceData->EnumeratedDevices);
    KdPrint((__DRIVER_NAME "     Added a device\n"));  

// now ask windows to rescan the scsi bus...
//    DeviceData->BusChangePending = 1;
    break;

  case XenbusStateClosing:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closing\n"));  
    // this behaviour is only to properly close down to then restart in the case of a dump
    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/state");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context, XBT_NIL, TmpPath, "%d", XenbusStateClosed);
    KdPrint((__DRIVER_NAME "     Set Frontend state to Closed\n"));
    break;

  case XenbusStateClosed:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closed\n"));  
    // this behaviour is only to properly close down to then restart in the case of a dump
    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/state");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context, XBT_NIL, TmpPath, "%d", XenbusStateInitialising);
    KdPrint((__DRIVER_NAME "     Set Frontend state to Initialising\n"));
    break;

  default:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Undefined = %d\n", NewState));
    break;
  }

  KdPrint((__DRIVER_NAME " <-- BackEndStateHandler\n"));
}

static VOID
XenVbd_WatchHandler(char *Path, PVOID DeviceExtension)
{
  PXENVBD_DEVICE_DATA DeviceData = (PXENVBD_DEVICE_DATA)DeviceExtension;
  char **Bits;
  int Count;
  char TmpPath[128];
  char *Value;
  int CurrentBus, CurrentTarget;
  PXENVBD_TARGET_DATA TargetData, VacantTarget;
  KIRQL OldIrql;
  int i;

  KdPrint((__DRIVER_NAME " --> WatchHandler (DeviceData = %p)\n", DeviceData));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  KdPrint((__DRIVER_NAME "     Path = %s\n", Path));

  Bits = SplitString(Path, '/', 4, &Count);
  switch (Count)
  {
  case 0:
  case 1:
  case 2:
    break; // should never happen
  case 3:
    break;
  case 4:
    if (strcmp(Bits[3], "state") != 0) // we only care when the state appears
      break;

    KeAcquireSpinLock(&DeviceData->Lock, &OldIrql);

    for (VacantTarget = NULL,i = 0; i < SCSI_BUSES * SCSI_TARGETS_PER_BUS; i++)
    {
      CurrentBus = i / SCSI_TARGETS_PER_BUS;
      CurrentTarget = i % SCSI_TARGETS_PER_BUS;
      if (CurrentTarget == 7) // don't use 7 - it would be for the controller
        continue;
      TargetData = &DeviceData->BusData[CurrentBus].TargetData[CurrentTarget];
      if (TargetData->Present && strncmp(TargetData->Path, Path, strlen(TargetData->Path)) == 0 && Path[strlen(TargetData->Path)] == '/')
        break; // already exists
      else if (!TargetData->Present && VacantTarget == NULL)
        VacantTarget = TargetData;
    }
    if (i == SCSI_BUSES * SCSI_TARGETS_PER_BUS && VacantTarget != NULL)
    {
      VacantTarget->Present = 1;
      KeReleaseSpinLock(&DeviceData->Lock, OldIrql);

      DeviceData->XenDeviceData->XenInterface.XenBus_Read(
        DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
        XBT_NIL, Path, &Value);

      if (Value == NULL)
      {
        KdPrint((__DRIVER_NAME "     blank state?\n"));
        break;
      }
      if (atoi(Value) != XenbusStateInitialising)
        DeviceData->XenDeviceData->XenInterface.XenBus_Printf(
          DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
          XBT_NIL, Path, "%d", XenbusStateClosing);

      RtlStringCbCopyA(VacantTarget->Path, 128, Bits[0]);
      RtlStringCbCatA(VacantTarget->Path, 128, "/");
      RtlStringCbCatA(VacantTarget->Path, 128, Bits[1]);
      RtlStringCbCatA(VacantTarget->Path, 128, "/");
      RtlStringCbCatA(VacantTarget->Path, 128, Bits[2]);

      VacantTarget->DeviceIndex = atoi(Bits[2]);

      RtlStringCbCopyA(TmpPath, 128, VacantTarget->Path);
      RtlStringCbCatA(TmpPath, 128, "/backend");
      DeviceData->XenDeviceData->XenInterface.XenBus_Read(
        DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
        XBT_NIL, TmpPath, &Value);
      if (Value == NULL)
        KdPrint((__DRIVER_NAME "     Read Failed\n"));
      else
        RtlStringCbCopyA(VacantTarget->BackendPath, 128, Value);
      RtlStringCbCopyA(TmpPath, 128, VacantTarget->BackendPath);
      RtlStringCbCatA(TmpPath, 128, "/state");

      DeviceData->XenDeviceData->XenInterface.XenBus_AddWatch(
        DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
        XBT_NIL, TmpPath, XenVbd_BackEndStateHandler, VacantTarget);
    }
    else
      KeReleaseSpinLock(&DeviceData->Lock, OldIrql);
    break;
  }
  
  FreeSplitString(Bits, Count);

  KdPrint((__DRIVER_NAME " <-- WatchHandler\n"));  

  return;
}

static VOID
XenVbd_EnumerateExisting(PXENVBD_DEVICE_DATA DeviceData)
{
  char *msg;
  ULONG i;
  char **VbdDevices;
  char buffer[128];
  int TotalInitialDevices = 0;

  msg = DeviceData->XenDeviceData->XenInterface.XenBus_List(
    DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
    XBT_NIL, "device/vbd", &VbdDevices);
  if (!msg)
  {
    for (i = 0; VbdDevices[i]; i++)
    {
      KdPrint((__DRIVER_NAME "     found existing vbd device %s\n", VbdDevices[i]));
      RtlStringCbPrintfA(buffer, ARRAY_SIZE(buffer), "device/vbd/%s/state", VbdDevices[i]);
      XenVbd_WatchHandler(buffer, DeviceData);
      TotalInitialDevices++;
    }  
  }
  DeviceData->TotalInitialDevices = TotalInitialDevices;
}

static PXENPCI_XEN_DEVICE_DATA
XenVbd_GetXenDeviceData(PPORT_CONFIGURATION_INFORMATION ConfigInfo)
{
  int i;
  PACCESS_RANGE AccessRange;
  PXENPCI_XEN_DEVICE_DATA XenDeviceData = NULL;

  for (i = 0; i < ConfigInfo->NumberOfAccessRanges; i++)
  {
    AccessRange = &(*(ConfigInfo->AccessRanges))[i];
    KdPrint((__DRIVER_NAME "     AccessRange %2d: RangeStart = %p, RangeLength = %x, RangeInMemory = %d\n", i, AccessRange->RangeStart.QuadPart, AccessRange->RangeLength, AccessRange->RangeInMemory));
    switch (i)
    {
    case 0:
      XenDeviceData = (PVOID)(xen_ulong_t)AccessRange->RangeStart.QuadPart;
      KdPrint((__DRIVER_NAME "     Mapped to virtual address %p\n", XenDeviceData));
      KdPrint((__DRIVER_NAME "     Magic = %08x\n", XenDeviceData->Magic));
      break;
    default:
      break;
    }
  }
  return XenDeviceData;
}

static VOID
XenVbd_InitDeviceData(PXENVBD_DEVICE_DATA DeviceData, PPORT_CONFIGURATION_INFORMATION ConfigInfo)
{
  ULONG i, j;
  PXENPCI_XEN_DEVICE_DATA XenDeviceData;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));  

  KeInitializeSpinLock(&DeviceData->Lock);

  DeviceData->XenDeviceData = XenVbd_GetXenDeviceData(ConfigInfo);

  for (i = 0; i < SCSI_BUSES; i++)
  {
    for (j = 0; j < SCSI_TARGETS_PER_BUS; j++)
    {
      DeviceData->BusData[i].TargetData[j].Present = 0;
      DeviceData->BusData[i].TargetData[j].DeviceData = DeviceData;
    }
  }

  DeviceData->XenDeviceData->WatchContext = DeviceData;
  KeMemoryBarrier();
  DeviceData->XenDeviceData->WatchHandler = XenVbd_WatchHandler;

  DeviceData->EnumeratedDevices = 0;
  DeviceData->TotalInitialDevices = 0;

  if (DeviceData->XenDeviceData->AutoEnumerate)
  {
    DeviceData->TotalInitialDevices = SCSI_BUSES * SCSI_TARGETS_PER_BUS;
    XenVbd_EnumerateExisting(DeviceData);
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static ULONG
XenVbd_HwScsiFindAdapter(PVOID DeviceExtension, PVOID HwContext, PVOID BusInformation, PCHAR ArgumentString, PPORT_CONFIGURATION_INFORMATION ConfigInfo, PBOOLEAN Again)
{
  ULONG i, j, k;
  PACCESS_RANGE AccessRange;
  PXENVBD_DEVICE_DATA DeviceData; // = ((PXENVBD_DEVICE_EXTENSION)DeviceExtension)->XenVbdDeviceData;
  ULONG status;
  PXENPCI_XEN_DEVICE_DATA XenDeviceData;

  UNREFERENCED_PARAMETER(HwContext);
  UNREFERENCED_PARAMETER(BusInformation);
  UNREFERENCED_PARAMETER(ArgumentString);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));  
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  KdPrint((__DRIVER_NAME "     BusInterruptLevel = %d\n", ConfigInfo->BusInterruptLevel));
  KdPrint((__DRIVER_NAME "     BusInterruptVector = %d\n", ConfigInfo->BusInterruptVector));

  KdPrint((__DRIVER_NAME "     AccessRanges = %d\n", ConfigInfo->NumberOfAccessRanges));

  if (KeGetCurrentIrql() == PASSIVE_LEVEL)
  {
    DeviceData = ((PXENVBD_DEVICE_EXTENSION)DeviceExtension)->XenVbdDeviceData = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENVBD_DEVICE_DATA), XENVBD_POOL_TAG);
    XenVbd_InitDeviceData(DeviceData, ConfigInfo);
    if (DeviceData->XenDeviceData->Magic != XEN_DATA_MAGIC)
      return SP_RETURN_NOT_FOUND;
  }
  else
  {
    DumpMode = TRUE;
    XenDeviceData = XenVbd_GetXenDeviceData(ConfigInfo);
    if (XenDeviceData == NULL || XenDeviceData->Magic != XEN_DATA_MAGIC)
    {
      return SP_RETURN_NOT_FOUND;
    }
    DeviceData = XenDeviceData->WatchContext;
    ((PXENVBD_DEVICE_EXTENSION)DeviceExtension)->XenVbdDeviceData = DeviceData;
    DeviceData->XenDeviceData->WatchHandler = XenVbd_WatchHandler;


    for (i = 0; i < SCSI_BUSES; i++)
    {
      for (j = 0; j < SCSI_TARGETS_PER_BUS; j++)
      {
        for (k = 0; k < max(BLK_RING_SIZE, BLK_OTHER_RING_SIZE); k++)
        {
          if (DeviceData->BusData[i].TargetData[j].Present)
            DeviceData->BusData[i].TargetData[j].shadow[k].Srb = NULL;
        }
      }
    }
  }
  KdPrint((__DRIVER_NAME "     DeviceData = %p\n", DeviceData));

  DeviceData->DeviceExtension = DeviceExtension;

#if defined(__x86_64__)
  ConfigInfo->Master = TRUE; // Won't work under x64 without this...
#endif
  ConfigInfo->MaximumTransferLength = BLKIF_MAX_SEGMENTS_PER_REQUEST * PAGE_SIZE;
  ConfigInfo->NumberOfPhysicalBreaks = BLKIF_MAX_SEGMENTS_PER_REQUEST - 1;
  ConfigInfo->ScatterGather = TRUE;
  ConfigInfo->AlignmentMask = 0;
  ConfigInfo->NumberOfBuses = SCSI_BUSES;
  for (i = 0; i < ConfigInfo->NumberOfBuses; i++)
  {
    ConfigInfo->InitiatorBusId[i] = 7;
  }
  ConfigInfo->MaximumNumberOfLogicalUnits = 1;
  ConfigInfo->MaximumNumberOfTargets = SCSI_TARGETS_PER_BUS;
  if (ConfigInfo->Dma64BitAddresses == SCSI_DMA64_SYSTEM_SUPPORTED)
    ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;

  // This all has to be initialized here as the real Initialize routine
  // is called at DIRQL, and the XenBus stuff has to be called at
  // <= DISPATCH_LEVEL

  *Again = FALSE;

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));  

  return SP_RETURN_FOUND;
}

static VOID 
XenVbd_CheckBusChangedTimer(PVOID DeviceExtension);

static VOID 
XenVbd_CheckBusEnumeratedTimer(PVOID DeviceExtension)
{
  PXENVBD_DEVICE_DATA DeviceData = ((PXENVBD_DEVICE_EXTENSION)DeviceExtension)->XenVbdDeviceData;

if (DumpMode)
{
  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));
}
  if (DeviceData->EnumeratedDevices >= DeviceData->TotalInitialDevices)
  {
    DeviceData->BusChangePending = 0;
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    ScsiPortNotification(RequestTimerCall, DeviceExtension, XenVbd_CheckBusChangedTimer, 1000000);
  }
  else
  {
    ScsiPortNotification(RequestTimerCall, DeviceExtension, XenVbd_CheckBusEnumeratedTimer, 100000);
  }
if (DumpMode)
{
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}
}

static VOID 
XenVbd_CheckBusChangedTimer(PVOID DeviceExtension)
{
  PXENVBD_DEVICE_DATA DeviceData = ((PXENVBD_DEVICE_EXTENSION)DeviceExtension)->XenVbdDeviceData;

  if (DeviceData->BusChangePending)
  {
    ScsiPortNotification(BusChangeDetected, DeviceExtension, 0);
    DeviceData->BusChangePending = 0;
  }
  ScsiPortNotification(RequestTimerCall, DeviceExtension, XenVbd_CheckBusChangedTimer, 1000000);
}

static BOOLEAN
XenVbd_HwScsiInitialize(PVOID DeviceExtension)
{
  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  ScsiPortNotification(RequestTimerCall, DeviceExtension, XenVbd_CheckBusEnumeratedTimer, 100000);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

static ULONG
XenVbd_FillModePage(PXENVBD_DEVICE_DATA DeviceData, UCHAR PageCode, PUCHAR DataBuffer, ULONG BufferLength, PULONG Offset)
{
  //PMODE_RIGID_GEOMETRY_PAGE ModeRigidGeometry;

  UNREFERENCED_PARAMETER(DeviceData);
  UNREFERENCED_PARAMETER(DataBuffer);
  UNREFERENCED_PARAMETER(BufferLength);
  UNREFERENCED_PARAMETER(Offset);

  switch (PageCode)
  {
/*
  case MODE_PAGE_RIGID_GEOMETRY:
    if (DeviceData->ScsiData->DeviceType == XENVBD_DEVICETYPE_CDROM)
    {
    KdPrint((__DRIVER_NAME "     MODE_PAGE_RIGID_GEOMETRY\n"));
    if (*Offset + sizeof(MODE_RIGID_GEOMETRY_PAGE) > BufferLength)
      return 1;
    ModeRigidGeometry = (PMODE_RIGID_GEOMETRY_PAGE)(DataBuffer + *Offset);
    memset(ModeRigidGeometry, 0, sizeof(MODE_RIGID_GEOMETRY_PAGE));
    ModeRigidGeometry->PageCode = PageCode;
    ModeRigidGeometry->PageSavable = 0;
    ModeRigidGeometry->PageLength = sizeof(MODE_RIGID_GEOMETRY_PAGE);
    ModeRigidGeometry->NumberOfCylinders[0] = (DeviceData->Geometry.Cylinders.LowPart >> 16) & 0xFF;
    ModeRigidGeometry->NumberOfCylinders[1] = (DeviceData->Geometry.Cylinders.LowPart >> 8) & 0xFF;
    ModeRigidGeometry->NumberOfCylinders[2] = (DeviceData->Geometry.Cylinders.LowPart >> 0) & 0xFF;
    ModeRigidGeometry->NumberOfHeads = DeviceData->Geometry.TracksPerCylinder;
    //ModeRigidGeometry->LandZoneCyclinder = 0;
    ModeRigidGeometry->RoataionRate[0] = 0x05;
    ModeRigidGeometry->RoataionRate[0] = 0x39;
    *Offset += sizeof(MODE_RIGID_GEOMETRY_PAGE);
    }
    break;
*/
  case MODE_PAGE_FAULT_REPORTING:
    break;
  default:
    break;
  }
  return 0;
}

static VOID
XenVbd_PutRequest(PXENVBD_TARGET_DATA TargetData, blkif_request_t *req)
{
  blkif_other_request_t *other_req;

  if (!TargetData->use_other)
  {
    *RING_GET_REQUEST(&TargetData->Ring, TargetData->Ring.req_prod_pvt) = *req;
  }
  else
  {  
    other_req = RING_GET_REQUEST(&TargetData->OtherRing, TargetData->Ring.req_prod_pvt);
    other_req->operation = req->operation;
    other_req->nr_segments = req->nr_segments;
    other_req->handle = req->handle;
    other_req->id = req->id;
    other_req->sector_number = req->sector_number;
    memcpy(other_req->seg, req->seg, sizeof(struct blkif_request_segment) * req->nr_segments);
  }
  TargetData->Ring.req_prod_pvt++;
}

// Call with device lock held
static VOID
XenVbd_PutSrbOnRing(PXENVBD_TARGET_DATA TargetData, PSCSI_REQUEST_BLOCK Srb)
{
  //PUCHAR DataBuffer;
  int i;
  int BlockCount;
  blkif_shadow_t *shadow;
  uint64_t id;

// can use SRB_STATUS_BUSY to push the SRB back to windows...

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  if (RING_FULL(&TargetData->Ring))
  {
    KdPrint((__DRIVER_NAME "     RING IS FULL - EXPECT BADNESS\n"));
    // TODO: Fail badly here
  }

  id = GET_ID_FROM_FREELIST(TargetData);
  if (id == 0x0fffffff)
  {
    KdPrint((__DRIVER_NAME "     Something is horribly wrong in PutSrbOnRing\n"));
  }

  shadow = &TargetData->shadow[id];
  shadow->req.id = id;

  shadow->req.sector_number = (Srb->Cdb[2] << 24) | (Srb->Cdb[3] << 16) | (Srb->Cdb[4] << 8) | Srb->Cdb[5];
  BlockCount = (Srb->Cdb[7] << 8) | Srb->Cdb[8];
  shadow->req.handle = 0;
  shadow->req.operation = (Srb->Cdb[0] == SCSIOP_READ)?BLKIF_OP_READ:BLKIF_OP_WRITE;
  shadow->Srb = Srb;

  shadow->req.nr_segments = (UINT8)((BlockCount * TargetData->BytesPerSector + PAGE_SIZE - 1) / PAGE_SIZE);

  for (i = 0; i < shadow->req.nr_segments; i++)
  {
/*
    shadow->req.seg[i].gref = DeviceData->XenDeviceData->XenInterface.GntTbl_GrantAccess(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      0, (ULONG)MmGetMdlPfnArray(TargetData->shadow[shadow->req.id].Mdl)[i], FALSE);
    ASSERT((signed short)shadow->req.seg[i].gref >= 0);
*/
    shadow->req.seg[i].first_sect = 0;
    if (i == shadow->req.nr_segments - 1)
      shadow->req.seg[i].last_sect = (UINT8)((BlockCount - 1) % (PAGE_SIZE / TargetData->BytesPerSector));
    else
      shadow->req.seg[i].last_sect = (UINT8)(PAGE_SIZE / TargetData->BytesPerSector - 1);
  }
  if (Srb->Cdb[0] == SCSIOP_WRITE)
    memcpy(TargetData->shadow[shadow->req.id].Buf, Srb->DataBuffer, BlockCount * TargetData->BytesPerSector);

  XenVbd_PutRequest(TargetData, &shadow->req);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static BOOLEAN
XenVbd_HwScsiStartIo(PVOID DeviceExtension, PSCSI_REQUEST_BLOCK Srb)
{
  PUCHAR DataBuffer;
  PCDB cdb;
  PXENVBD_DEVICE_DATA DeviceData = ((PXENVBD_DEVICE_EXTENSION)DeviceExtension)->XenVbdDeviceData;
  PXENVBD_TARGET_DATA TargetData;
  unsigned int i;
  int notify;

if (DumpMode)
{
  KdPrint((__DRIVER_NAME " --> HwScsiStartIo PathId = %d, TargetId = %d, Lun = %d\n", Srb->PathId, Srb->TargetId, Srb->Lun));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));
}

  // If we haven't enumerated all the devices yet then just defer the request
  // A timer will issue a NextRequest to get things started again...
  if (DeviceData->EnumeratedDevices < DeviceData->TotalInitialDevices)
  {
    Srb->SrbStatus = SRB_STATUS_BUSY;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    KdPrint((__DRIVER_NAME " --- HwScsiStartIo (NotEnumeratedYet)\n"));
    return TRUE;
  }

  if (Srb->PathId >= SCSI_BUSES || Srb->TargetId >= SCSI_TARGETS_PER_BUS)
  {
    Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    KdPrint((__DRIVER_NAME " --- HwScsiStartIo (Out of bounds)\n"));
    return TRUE;
  }

  TargetData = &DeviceData->BusData[Srb->PathId].TargetData[Srb->TargetId];

  if (!TargetData->Present)
  {
    Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    KdPrint((__DRIVER_NAME " --- HwScsiStartIo (Not Present)\n"));
    return TRUE;
  }

  switch (Srb->Function)
  {
  case SRB_FUNCTION_EXECUTE_SCSI:
    cdb = (PCDB)Srb->Cdb;
if (DumpMode)
{
    KdPrint((__DRIVER_NAME "     SRB_FUNCTION_EXECUTE_SCSI\n"));
}
    switch(cdb->CDB6GENERIC.OperationCode)
    {
    case SCSIOP_TEST_UNIT_READY:
//      KdPrint((__DRIVER_NAME "     Command = TEST_UNIT_READY\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      Srb->ScsiStatus = 0;
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);
      break;
    case SCSIOP_INQUIRY:
      KdPrint((__DRIVER_NAME "     Command = INQUIRY\n"));
      KdPrint((__DRIVER_NAME "     (LUN = %d, EVPD = %d, Page Code = %02X)\n", Srb->Cdb[1] >> 5, Srb->Cdb[1] & 1, Srb->Cdb[2]));
      KdPrint((__DRIVER_NAME "     (Length = %d)\n", Srb->DataTransferLength));
      KdPrint((__DRIVER_NAME "     (Srb->Databuffer = %08x)\n", Srb->DataBuffer));
      DataBuffer = Srb->DataBuffer;
      RtlZeroMemory(DataBuffer, Srb->DataTransferLength);
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      switch (TargetData->DeviceType)
      {
      case XENVBD_DEVICETYPE_DISK:
        if ((Srb->Cdb[1] & 1) == 0)
        {
          DataBuffer[0] = DIRECT_ACCESS_DEVICE;
          DataBuffer[1] = 0x00; // not removable
          DataBuffer[3] = 32;
          memcpy(DataBuffer + 8, "XEN     ", 8); // vendor id
          memcpy(DataBuffer + 16, "PV VBD          ", 16); // product id
          memcpy(DataBuffer + 32, "0000", 4); // product revision level
        }
        else
        {
          switch (Srb->Cdb[2])
          {
          case 0x00:
            DataBuffer[0] = DIRECT_ACCESS_DEVICE;
            DataBuffer[1] = 0x00;
            DataBuffer[2] = 0x00;
            DataBuffer[3] = 2;
            DataBuffer[4] = 0x00;
            DataBuffer[5] = 0x80;
            break;
          case 0x80:
            DataBuffer[0] = DIRECT_ACCESS_DEVICE;
            DataBuffer[1] = 0x80;
            DataBuffer[2] = 0x00;
            DataBuffer[3] = 8;
            DataBuffer[4] = 0x31;
            DataBuffer[5] = 0x32;
            DataBuffer[6] = 0x33;
            DataBuffer[7] = 0x34;
            DataBuffer[8] = 0x35;
            DataBuffer[9] = 0x36;
            DataBuffer[10] = 0x37;
            DataBuffer[11] = 0x38;
            break;
          default:
            KdPrint((__DRIVER_NAME "     Unknown Page %02x requested\n", Srb->Cdb[2]));
            Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            break;
          }
        }
        break;
      case XENVBD_DEVICETYPE_CDROM:
        if ((Srb->Cdb[1] & 1) == 0)
        {
          DataBuffer[0] = READ_ONLY_DIRECT_ACCESS_DEVICE;
          DataBuffer[1] = 0x01; // removable
          DataBuffer[3] = 32;
          memcpy(DataBuffer + 8, "XEN     ", 8); // vendor id
          memcpy(DataBuffer + 16, "PV VBD          ", 16); // product id
          memcpy(DataBuffer + 32, "0000", 4); // product revision level
        }
        else
        {
          switch (Srb->Cdb[2])
          {
          case 0x00:
            DataBuffer[0] = READ_ONLY_DIRECT_ACCESS_DEVICE;
            DataBuffer[1] = 0x00;
            DataBuffer[2] = 0x00;
            DataBuffer[3] = 2;
            DataBuffer[4] = 0x00;
            DataBuffer[5] = 0x80;
            break;
          case 0x80:
            DataBuffer[0] = READ_ONLY_DIRECT_ACCESS_DEVICE;
            DataBuffer[1] = 0x80;
            DataBuffer[2] = 0x00;
            DataBuffer[3] = 8;
            DataBuffer[4] = 0x31;
            DataBuffer[5] = 0x32;
            DataBuffer[6] = 0x33;
            DataBuffer[7] = 0x34;
            DataBuffer[8] = 0x35;
            DataBuffer[9] = 0x36;
            DataBuffer[10] = 0x37;
            DataBuffer[11] = 0x38;
            break;
          default:
            KdPrint((__DRIVER_NAME "     Unknown Page %02x requested\n", Srb->Cdb[2]));
            Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            break;
          }
        }
        break;
      default:
        KdPrint((__DRIVER_NAME "     Unknown DeviceType %02x requested\n", TargetData->DeviceType));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
      }
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);
      break;
    case SCSIOP_READ_CAPACITY:
      KdPrint((__DRIVER_NAME "     Command = READ_CAPACITY\n"));
      DataBuffer = Srb->DataBuffer;
      RtlZeroMemory(DataBuffer, Srb->DataTransferLength);
      DataBuffer[0] = (unsigned char)((TargetData->TotalSectors - 1) >> 24) & 0xff;
      DataBuffer[1] = (unsigned char)((TargetData->TotalSectors - 1) >> 16) & 0xff;
      DataBuffer[2] = (unsigned char)((TargetData->TotalSectors - 1) >> 8) & 0xff;
      DataBuffer[3] = (unsigned char)((TargetData->TotalSectors - 1) >> 0) & 0xff;
      DataBuffer[4] = (unsigned char)(TargetData->BytesPerSector >> 24) & 0xff;
      DataBuffer[5] = (unsigned char)(TargetData->BytesPerSector >> 16) & 0xff;
      DataBuffer[6] = (unsigned char)(TargetData->BytesPerSector >> 8) & 0xff;
      DataBuffer[7] = (unsigned char)(TargetData->BytesPerSector >> 0) & 0xff;
      Srb->ScsiStatus = 0;
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);
      break;
    case SCSIOP_MODE_SENSE:
      KdPrint((__DRIVER_NAME "     Command = MODE_SENSE (DBD = %d, PC = %d, Page Code = %02x)\n", Srb->Cdb[1] & 0x10, Srb->Cdb[2] & 0xC0, Srb->Cdb[2] & 0x3F));
      KdPrint((__DRIVER_NAME "     Length = %d\n", Srb->DataTransferLength));

      Srb->ScsiStatus = 0;
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      Srb->DataTransferLength = 0;
      DataBuffer = Srb->DataBuffer;
      RtlZeroMemory(DataBuffer, Srb->DataTransferLength);
      switch(cdb->MODE_SENSE.PageCode)
      {
      case MODE_SENSE_RETURN_ALL:
        //Ptr = (UCHAR *)Srb->DataBuffer;
        for (i = 0; i < MODE_SENSE_RETURN_ALL; i++)
        {
          if (XenVbd_FillModePage(DeviceData, cdb->MODE_SENSE.PageCode, DataBuffer, cdb->MODE_SENSE.AllocationLength, &Srb->DataTransferLength))
          {
            break;
          }
        }
        break;
      default:
        XenVbd_FillModePage(DeviceData, cdb->MODE_SENSE.PageCode, DataBuffer, cdb->MODE_SENSE.AllocationLength, &Srb->DataTransferLength);
        break;
      }
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);
      break;
    case SCSIOP_READ:
    case SCSIOP_WRITE:
if (DumpMode)
{
      KdPrint((__DRIVER_NAME "     Command = READ/WRITE\n"));
}
      XenVbd_PutSrbOnRing(TargetData, Srb);
      RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&TargetData->Ring, notify);
      if (notify)
        DeviceData->XenDeviceData->XenInterface.EvtChn_Notify(
          DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
          TargetData->EventChannel);
      if (!RING_FULL(&TargetData->Ring) && !DumpMode)
        ScsiPortNotification(NextLuRequest, DeviceExtension, Srb->PathId, Srb->TargetId, Srb->Lun);
      else
        ScsiPortNotification(NextRequest, DeviceExtension);
      break;
    case SCSIOP_VERIFY:
      // Should we do more here?
      KdPrint((__DRIVER_NAME "     Command = VERIFY\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS; //SRB_STATUS_INVALID_REQUEST;
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);      
      ScsiPortNotification(NextLuRequest, DeviceExtension, Srb->PathId, Srb->TargetId, Srb->Lun);
      break;
    case SCSIOP_REPORT_LUNS:
      KdPrint((__DRIVER_NAME "     Command = REPORT_LUNS\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS; //SRB_STATUS_INVALID_REQUEST;
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);
      break;
    case SCSIOP_READ_TOC:
      DataBuffer = Srb->DataBuffer;
//      DataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);
/*
#define READ_TOC_FORMAT_TOC         0x00
#define READ_TOC_FORMAT_SESSION     0x01
#define READ_TOC_FORMAT_FULL_TOC    0x02
#define READ_TOC_FORMAT_PMA         0x03
#define READ_TOC_FORMAT_ATIP        0x04
*/
      KdPrint((__DRIVER_NAME "     Command = READ_TOC\n"));
      KdPrint((__DRIVER_NAME "     Msf = %d\n", cdb->READ_TOC.Msf));
      KdPrint((__DRIVER_NAME "     LogicalUnitNumber = %d\n", cdb->READ_TOC.LogicalUnitNumber));
      KdPrint((__DRIVER_NAME "     Format2 = %d\n", cdb->READ_TOC.Format2));
      KdPrint((__DRIVER_NAME "     StartingTrack = %d\n", cdb->READ_TOC.StartingTrack));
      KdPrint((__DRIVER_NAME "     AllocationLength = %d\n", (cdb->READ_TOC.AllocationLength[0] << 8) | cdb->READ_TOC.AllocationLength[1]));
      KdPrint((__DRIVER_NAME "     Control = %d\n", cdb->READ_TOC.Control));
      KdPrint((__DRIVER_NAME "     Format = %d\n", cdb->READ_TOC.Format));
      switch (cdb->READ_TOC.Format2)
      {
      case READ_TOC_FORMAT_TOC:
        DataBuffer[0] = 0; // length MSB
        DataBuffer[1] = 10; // length LSB
        DataBuffer[2] = 1; // First Track
        DataBuffer[3] = 1; // Last Track
        DataBuffer[4] = 0; // Reserved
        DataBuffer[5] = 0x14; // current position data + uninterrupted data
        DataBuffer[6] = 1; // last complete track
        DataBuffer[7] = 0; // reserved
        DataBuffer[8] = 0; // MSB Block
        DataBuffer[9] = 0;
        DataBuffer[10] = 0;
        DataBuffer[11] = 0; // LSB Block
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
      case READ_TOC_FORMAT_SESSION:
      case READ_TOC_FORMAT_FULL_TOC:
      case READ_TOC_FORMAT_PMA:
      case READ_TOC_FORMAT_ATIP:
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
      }
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);
      break;
    case SCSIOP_START_STOP_UNIT:
      KdPrint((__DRIVER_NAME "     Command = SCSIOP_START_STOP_UNIT\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);
      break;
    default:
      KdPrint((__DRIVER_NAME "     Unhandled EXECUTE_SCSI Command = %02X\n", Srb->Cdb[0]));
      Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);
      break;
    }
    break;
  case SRB_FUNCTION_CLAIM_DEVICE:
    KdPrint((__DRIVER_NAME "     SRB_FUNCTION_CLAIM_DEVICE\n"));
//    ObReferenceObject(WdfDeviceWdmGetDeviceObject(Device));
//    Srb->DataBuffer = WdfDeviceWdmGetDeviceObject(Device);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    break;
  case SRB_FUNCTION_IO_CONTROL:
    KdPrint((__DRIVER_NAME "     SRB_FUNCTION_IO_CONTROL\n"));
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    break;
  case SRB_FUNCTION_FLUSH:
    KdPrint((__DRIVER_NAME "     SRB_FUNCTION_FLUSH\n"));
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unhandled Srb->Function = %08X\n", Srb->Function));
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    break;
  }

if (DumpMode)
{
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}
  return TRUE;
}

static BOOLEAN
XenVbd_HwScsiResetBus(PVOID DeviceExtension, ULONG PathId)
{
  UNREFERENCED_PARAMETER(DeviceExtension);
  UNREFERENCED_PARAMETER(PathId);


  KdPrint((__DRIVER_NAME " --> HwScsiResetBus\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  KdPrint((__DRIVER_NAME " <-- HwScsiResetBus\n"));

  return TRUE;
}


static BOOLEAN
XenVbd_HwScsiAdapterState(PVOID DeviceExtension, PVOID Context, BOOLEAN SaveState)
{
  UNREFERENCED_PARAMETER(DeviceExtension);
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(SaveState);

  KdPrint((__DRIVER_NAME " --> HwScsiAdapterState\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  KdPrint((__DRIVER_NAME " <-- HwScsiAdapterState\n"));

  return TRUE;
}

static SCSI_ADAPTER_CONTROL_STATUS
XenVbd_HwScsiAdapterControl(PVOID DeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters)
{
  SCSI_ADAPTER_CONTROL_STATUS Status = ScsiAdapterControlSuccess;
  PSCSI_SUPPORTED_CONTROL_TYPE_LIST SupportedControlTypeList;

  UNREFERENCED_PARAMETER(DeviceExtension);

  KdPrint((__DRIVER_NAME " --> HwScsiAdapterControl\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  switch (ControlType)
  {
  case ScsiQuerySupportedControlTypes:
    SupportedControlTypeList = (PSCSI_SUPPORTED_CONTROL_TYPE_LIST)Parameters;
    KdPrint((__DRIVER_NAME "     ScsiQuerySupportedControlTypes (Max = %d)\n", SupportedControlTypeList->MaxControlType));
    SupportedControlTypeList->SupportedTypeList[ScsiQuerySupportedControlTypes] = TRUE;
    SupportedControlTypeList->SupportedTypeList[ScsiStopAdapter] = TRUE;
    break;
  case ScsiStopAdapter:
    KdPrint((__DRIVER_NAME "     ScsiStopAdapter\n"));
    break;
  case ScsiRestartAdapter:
    KdPrint((__DRIVER_NAME "     ScsiRestartAdapter\n"));
    break;
  case ScsiSetBootConfig:
    KdPrint((__DRIVER_NAME "     ScsiSetBootConfig\n"));
    break;
  case ScsiSetRunningConfig:
    KdPrint((__DRIVER_NAME "     ScsiSetRunningConfig\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     UNKNOWN\n"));
    break;
  }

  KdPrint((__DRIVER_NAME " <-- HwScsiAdapterControl\n"));

  return Status;
}
