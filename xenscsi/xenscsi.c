#include "xenscsi.h"
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
XenScsi_HwScsiFindAdapter(PVOID DeviceExtension, PVOID HwContext, PVOID BusInformation, PCHAR ArgumentString, PPORT_CONFIGURATION_INFORMATION ConfigInfo, PBOOLEAN Again);
static BOOLEAN
XenScsi_HwScsiInitialize(PVOID DeviceExtension);
static BOOLEAN
XenScsi_HwScsiStartIo(PVOID DeviceExtension, PSCSI_REQUEST_BLOCK Srb);
static BOOLEAN
XenScsi_HwScsiInterrupt(PVOID DeviceExtension);
static BOOLEAN
XenScsi_HwScsiResetBus(PVOID DeviceExtension, ULONG PathId);
static BOOLEAN
XenScsi_HwScsiAdapterState(PVOID DeviceExtension, PVOID Context, BOOLEAN SaveState);
static SCSI_ADAPTER_CONTROL_STATUS
XenScsi_HwScsiAdapterControl(PVOID DeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif

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
  HwInitializationData.HwInitialize = XenScsi_HwScsiInitialize;
  HwInitializationData.HwStartIo = XenScsi_HwScsiStartIo;
  HwInitializationData.HwInterrupt = XenScsi_HwScsiInterrupt;
  HwInitializationData.HwFindAdapter = XenScsi_HwScsiFindAdapter;
  HwInitializationData.HwResetBus = XenScsi_HwScsiResetBus;
  HwInitializationData.HwDmaStarted = NULL;
  HwInitializationData.HwAdapterState = XenScsi_HwScsiAdapterState;
  HwInitializationData.DeviceExtensionSize = sizeof(XENSCSI_DEVICE_DATA);
  HwInitializationData.SpecificLuExtensionSize = 0;
  HwInitializationData.SrbExtensionSize = 0;
  HwInitializationData.NumberOfAccessRanges = 1;
  HwInitializationData.MapBuffers = TRUE;
  HwInitializationData.NeedPhysicalAddresses = FALSE;
  HwInitializationData.TaggedQueuing = TRUE;
  HwInitializationData.AutoRequestSense = TRUE;
  HwInitializationData.MultipleRequestPerLu = FALSE;
  HwInitializationData.ReceiveEvent = FALSE;
  HwInitializationData.VendorIdLength = 0;
  HwInitializationData.VendorId = NULL;
  HwInitializationData.DeviceIdLength = 0;
  HwInitializationData.DeviceId = NULL;
  HwInitializationData.HwAdapterControl = XenScsi_HwScsiAdapterControl;

  Status = ScsiPortInitialize(DriverObject, RegistryPath, &HwInitializationData, NULL);

  if(!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME " ScsiPortInitialize failed with status 0x%08x\n", Status));
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return Status;
}

static __inline uint16_t
GET_ID_FROM_FREELIST(PXENSCSI_TARGET_DATA TargetData)
{
  uint16_t free;
  free = TargetData->shadow_free;
  TargetData->shadow_free = TargetData->shadow[free].req.rqid;
  TargetData->shadow[free].req.rqid = 0x0fff; /* debug */
  return free;
}

static __inline VOID
ADD_ID_TO_FREELIST(PXENSCSI_TARGET_DATA TargetData, uint16_t Id)
{
  TargetData->shadow[Id].req.rqid  = TargetData->shadow_free;
  TargetData->shadow[Id].Srb = NULL;
  TargetData->shadow_free = Id;
}

static BOOLEAN
XenScsi_Interrupt(PKINTERRUPT Interrupt, PVOID DeviceExtension)
{
  PXENSCSI_TARGET_DATA TargetData = (PXENSCSI_TARGET_DATA)DeviceExtension;

  UNREFERENCED_PARAMETER(Interrupt);

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  TargetData->PendingInterrupt = TRUE;

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

static VOID
XenScsi_HwScsiInterruptTarget(PVOID DeviceExtension)
{
  PXENSCSI_TARGET_DATA TargetData = (PXENSCSI_TARGET_DATA)DeviceExtension;
  PSCSI_REQUEST_BLOCK Srb;
  RING_IDX i, rp;
  vscsiif_response_t *rep;
  PXENSCSI_DEVICE_DATA DeviceData = (PXENSCSI_DEVICE_DATA)TargetData->DeviceData;
  int more_to_do = TRUE;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  while (more_to_do)
  {
    rp = TargetData->Ring.sring->rsp_prod;
    KeMemoryBarrier();
    for (i = TargetData->Ring.rsp_cons; i != rp; i++)
    {
      rep = RING_GET_RESPONSE(&TargetData->Ring, i);
      Srb = TargetData->shadow[rep->rqid].Srb;
      Srb->ScsiStatus = (UCHAR)rep->rslt;
      if (!rep->rslt)
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
      else
      {
        KdPrint((__DRIVER_NAME "     Xen Operation returned error (result = 0x%08x)\n", rep->rslt));
        Srb->SrbStatus = SRB_STATUS_ERROR;
        if (rep->sense_len > 0 && rep->sense_len <= Srb->SenseInfoBufferLength && !(Srb->SrbFlags & SRB_FLAGS_DISABLE_AUTOSENSE) && Srb->SenseInfoBuffer != NULL)
        {
          Srb->SrbStatus |= SRB_STATUS_AUTOSENSE_VALID;
          memcpy(Srb->SenseInfoBuffer, rep->sense_buffer, rep->sense_len);
        }
      }
      if (Srb->SrbFlags & SRB_FLAGS_DATA_IN)
        memcpy(Srb->DataBuffer, TargetData->shadow[rep->rqid].Buf, Srb->DataTransferLength);

      ScsiPortNotification(RequestComplete, DeviceData, Srb);
      ScsiPortNotification(NextLuRequest, DeviceData, Srb->PathId, Srb->TargetId, Srb->Lun);
//      ScsiPortNotification(NextRequest, DeviceData);

      ADD_ID_TO_FREELIST(TargetData, rep->rqid);
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

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static BOOLEAN
XenScsi_HwScsiInterrupt(PVOID DeviceExtension)
{
  PXENSCSI_DEVICE_DATA DeviceData;
  PXENSCSI_TARGET_DATA TargetData;
  int i, j;

  //KdPrint((__DRIVER_NAME " --> HwScsiInterrupt\n"));

  DeviceData = (PXENSCSI_DEVICE_DATA)DeviceExtension;

  KeMemoryBarrier();
  for (i = 0; i < SCSI_BUSES; i++)
  {
    for (j = 0; j < SCSI_TARGETS_PER_BUS; j++)
    {
      TargetData = &DeviceData->BusData[i].TargetData[j];
      if (TargetData->PendingInterrupt)
        XenScsi_HwScsiInterruptTarget(TargetData);
      TargetData->PendingInterrupt = FALSE;
    }
  }
  //KdPrint((__DRIVER_NAME " <-- HwScsiInterrupt\n"));

  return FALSE;
}

static VOID
XenScsi_BackEndStateHandler(char *Path, PVOID Data)
{
  PXENSCSI_TARGET_DATA TargetData;
  PXENSCSI_DEVICE_DATA DeviceData;
  char TmpPath[128];
  char *Value;
  int NewState;
  int scanning;
  PMDL Mdl;
  grant_ref_t ref;
  vscsiif_sring_t *SharedRing;
  ULONG PFN;
  ULONG i, j;

  KdPrint((__DRIVER_NAME " --> BackEndStateHandler\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  TargetData = (PXENSCSI_TARGET_DATA)Data;
  DeviceData = (PXENSCSI_DEVICE_DATA)TargetData->DeviceData;

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
      TargetData->EventChannel, XenScsi_Interrupt, TargetData);
    Mdl = AllocatePage();
    PFN = (ULONG)*MmGetMdlPfnArray(Mdl);
    SharedRing = (vscsiif_sring_t *)MmGetMdlVirtualAddress(Mdl);
    RtlZeroMemory(SharedRing, PAGE_SIZE);
    SHARED_RING_INIT(SharedRing);
    FRONT_RING_INIT(&TargetData->Ring, SharedRing, PAGE_SIZE);
    ref = DeviceData->XenDeviceData->XenInterface.GntTbl_GrantAccess(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      0, PFN, FALSE);
    ASSERT((signed short)ref >= 0);
    TargetData->ring_detect_state = 0;
    TargetData->shadow = ExAllocatePoolWithTag(NonPagedPool, sizeof(vscsiif_shadow_t) * VSCSIIF_RING_SIZE, XENSCSI_POOL_TAG);

    memset(TargetData->shadow, 0, sizeof(vscsiif_shadow_t) * VSCSIIF_RING_SIZE);
    for (i = 0; i < VSCSIIF_RING_SIZE; i++)
    {
      TargetData->shadow[i].req.rqid = (uint16_t)i + 1;
      TargetData->shadow[i].Mdl = AllocatePages(VSCSIIF_SG_TABLESIZE); // stupid that we have to do this!
      TargetData->shadow[i].Buf = MmGetMdlVirtualAddress(TargetData->shadow[i].Mdl);
      for (j = 0; j < VSCSIIF_SG_TABLESIZE; j++)
      {
        TargetData->shadow[i].req.seg[j].gref = DeviceData->XenDeviceData->XenInterface.GntTbl_GrantAccess(
          DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
          0, (ULONG)MmGetMdlPfnArray(TargetData->shadow[i].Mdl)[j], FALSE);
        ASSERT((signed short)TargetData->shadow[i].req.seg[j].gref >= 0);
      }
    }
    TargetData->shadow_free = 0;

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

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/b-dev");
    DeviceData->XenDeviceData->XenInterface.XenBus_Read(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);

    KdPrint((__DRIVER_NAME "     dev string = %s\n", Value));  
    
    i = 0;
    j = 0;
    scanning = TRUE;
    while (scanning)
    {
      if (Value[i] == 0)
        scanning = FALSE;
      if (Value[i] == ':' || Value[i] == 0)
      {
         Value[i] = 0;
         TargetData->host = TargetData->channel;
         TargetData->channel = TargetData->id;
         TargetData->id = TargetData->lun;
         TargetData->lun = atoi(&Value[j]);
         j = i + 1;
      }
      i++;
    }
    KdPrint((__DRIVER_NAME "     host = %d, channel = %d, id = %d, lun = %d\n",
      TargetData->host, TargetData->channel, TargetData->id, TargetData->lun));  

/*
    KdPrint((__DRIVER_NAME "     sizeof(vscsiif_request) = %d\n", sizeof(struct vscsiif_request)));
    KdPrint((__DRIVER_NAME "     sizeof(vscsiif_request_segment) = %d\n", sizeof(struct vscsiif_request_segment)));
    KdPrint((__DRIVER_NAME "     sizeof(vscsiif_response) = %d\n", sizeof(struct vscsiif_response)));
    KdPrint((__DRIVER_NAME "     operation = %d\n", (int)((char *)(&req.operation) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     nr_segments = %d\n", (int)((char *)(&req.nr_segments) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     handle = %d\n", (int)((char *)(&req.handle) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     id = %d\n", (int)((char *)(&req.rqid) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     sector_number = %d\n", (int)((char *)(&req.sector_number) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     seg = %d\n", (int)((char *)(&req.seg) - (char *)(&req))));

    KdPrint((__DRIVER_NAME "     id = %d\n", (int)((char *)(&rep.id) - (char *)(&rep))));
    KdPrint((__DRIVER_NAME "     operation = %d\n", (int)((char *)(&rep.operation) - (char *)(&rep))));
    KdPrint((__DRIVER_NAME "     status = %d\n", (int)((char *)(&rep.status) - (char *)(&rep))));

    KdPrint((__DRIVER_NAME "     sizeof(union vscsiif_sring_entry) = %d\n", sizeof(union vscsiif_sring_entry)));
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
    RtlStringCbCatA(TmpPath, 128, "/state");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context, XBT_NIL, TmpPath, "%d", XenbusStateConnected);

    KdPrint((__DRIVER_NAME "     Set Frontend state to Connected\n"));
    InterlockedIncrement(&DeviceData->EnumeratedDevices);
    KdPrint((__DRIVER_NAME "     Added a device\n"));  

// now ask windows to rescan the scsi bus...
    DeviceData->BusChangePending = 1;
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
XenScsi_WatchHandler(char *Path, PVOID DeviceExtension)
{
  PXENSCSI_DEVICE_DATA DeviceData = (PXENSCSI_DEVICE_DATA)DeviceExtension;
  char **Bits;
  int Count;
  char TmpPath[128];
  char *Value;
  int CurrentBus, CurrentTarget;
  PXENSCSI_TARGET_DATA TargetData, VacantTarget;
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
        XBT_NIL, TmpPath, XenScsi_BackEndStateHandler, VacantTarget);
    }
    else
      KeReleaseSpinLock(&DeviceData->Lock, OldIrql);
    break;
  }
  
  FreeSplitString(Bits, Count);

  KdPrint((__DRIVER_NAME " <-- WatchHandler\n"));  

  return;
}

static ULONG
XenScsi_HwScsiFindAdapter(PVOID DeviceExtension, PVOID HwContext, PVOID BusInformation, PCHAR ArgumentString, PPORT_CONFIGURATION_INFORMATION ConfigInfo, PBOOLEAN Again)
{
  ULONG i, j;
  PACCESS_RANGE AccessRange;
  PXENSCSI_DEVICE_DATA DeviceData = (PXENSCSI_DEVICE_DATA)DeviceExtension;
  char **ScsiDevices;
  char *msg;
  char buffer[128];

  UNREFERENCED_PARAMETER(HwContext);
  UNREFERENCED_PARAMETER(BusInformation);
  UNREFERENCED_PARAMETER(ArgumentString);
  KeInitializeSpinLock(&DeviceData->Lock);
  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));  
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  // testing this for dump mode
//  if (KeGetCurrentIrql() > ConfigInfo->BusInterruptLevel)
//    ConfigInfo->BusInterruptLevel = KeGetCurrentIrql();

  KdPrint((__DRIVER_NAME "     BusInterruptLevel = %d\n", ConfigInfo->BusInterruptLevel));
  KdPrint((__DRIVER_NAME "     BusInterruptVector = %d\n", ConfigInfo->BusInterruptVector));

  KdPrint((__DRIVER_NAME "     AccessRanges = %d\n", ConfigInfo->NumberOfAccessRanges));

  for (i = 0; i < ConfigInfo->NumberOfAccessRanges; i++)
  {
    AccessRange = &(*(ConfigInfo->AccessRanges))[i];
    KdPrint((__DRIVER_NAME "     AccessRange %2d: RangeStart = %p, RangeLength = %x, RangeInMemory = %d\n", i, AccessRange->RangeStart.QuadPart, AccessRange->RangeLength, AccessRange->RangeInMemory));
    switch (i)
    {
    case 0:
      DeviceData->XenDeviceData = (PVOID)(xen_ulong_t)AccessRange->RangeStart.QuadPart;
      KdPrint((__DRIVER_NAME "     Mapped to virtual address %p\n", DeviceData->XenDeviceData));
      KdPrint((__DRIVER_NAME "     Magic = %08x\n", DeviceData->XenDeviceData->Magic));
      if (DeviceData->XenDeviceData->Magic != XEN_DATA_MAGIC)
      {
        KdPrint((__DRIVER_NAME "     Invalid Magic Number\n"));
        return SP_RETURN_NOT_FOUND;
      }
      break;
    default:
      break;
    }
  }
#if defined(__x86_64__)
  ConfigInfo->Master = TRUE; // Won't work under x64 without this...
#endif
  ConfigInfo->MaximumTransferLength = VSCSIIF_SG_TABLESIZE * PAGE_SIZE;
  ConfigInfo->NumberOfPhysicalBreaks = VSCSIIF_SG_TABLESIZE - 1;
  ConfigInfo->ScatterGather = TRUE;
  ConfigInfo->AlignmentMask = 0;
  ConfigInfo->NumberOfBuses = SCSI_BUSES;
  for (i = 0; i < ConfigInfo->NumberOfBuses; i++)
  {
    ConfigInfo->InitiatorBusId[i] = 7;
  }
  ConfigInfo->MaximumNumberOfLogicalUnits = 1;
  ConfigInfo->MaximumNumberOfTargets = SCSI_TARGETS_PER_BUS;
//  ConfigInfo->TaggedQueueing = TRUE;
  if (ConfigInfo->Dma64BitAddresses == SCSI_DMA64_SYSTEM_SUPPORTED)
    ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;
  // This all has to be initialized here as the real Initialize routine
  // is called at DIRQL, and the XenBus stuff has to be called at
  // <= DISPATCH_LEVEL

  for (i = 0; i < SCSI_BUSES; i++)
  {
    for (j = 0; j < SCSI_TARGETS_PER_BUS; j++)
    {
      DeviceData->BusData[i].TargetData[j].Present = 0;
      DeviceData->BusData[i].TargetData[j].DeviceData = DeviceData;
    }
  }

  DeviceData->XenDeviceData->WatchContext = DeviceExtension;
  KeMemoryBarrier();
  DeviceData->XenDeviceData->WatchHandler = XenScsi_WatchHandler;

//  KeInitializeEvent(&DeviceData->WaitDevicesEvent, SynchronizationEvent, FALSE);  
  DeviceData->EnumeratedDevices = 0;
  DeviceData->TotalInitialDevices = 0;

  if (DeviceData->XenDeviceData->AutoEnumerate)
  {
    msg = DeviceData->XenDeviceData->XenInterface.XenBus_List(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, "device/vscsi", &ScsiDevices);
    if (!msg)
    {
      for (i = 0; ScsiDevices[i]; i++)
      {
        KdPrint((__DRIVER_NAME "     found existing scsi device %s\n", ScsiDevices[i]));
        RtlStringCbPrintfA(buffer, ARRAY_SIZE(buffer), "device/vscsi/%s/state", ScsiDevices[i]);
        XenScsi_WatchHandler(buffer, DeviceData);
        DeviceData->TotalInitialDevices++;
      }  
    }
  }

  *Again = FALSE;

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));  

  return SP_RETURN_FOUND;
}

static VOID 
XenScsi_CheckBusChangedTimer(PVOID DeviceExtension);

static VOID 
XenScsi_CheckBusEnumeratedTimer(PVOID DeviceExtension)
{
  PXENSCSI_DEVICE_DATA DeviceData = (PXENSCSI_DEVICE_DATA)DeviceExtension;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
//  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  if (DeviceData->BusChangePending && DeviceData->EnumeratedDevices >= DeviceData->TotalInitialDevices)
  {
    DeviceData->BusChangePending = 0;
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    ScsiPortNotification(RequestTimerCall, DeviceExtension, XenScsi_CheckBusChangedTimer, 1000000);
  }
  else
  {
    ScsiPortNotification(RequestTimerCall, DeviceExtension, XenScsi_CheckBusEnumeratedTimer, 100000);
  }
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static VOID 
XenScsi_CheckBusChangedTimer(PVOID DeviceExtension)
{
  PXENSCSI_DEVICE_DATA DeviceData = (PXENSCSI_DEVICE_DATA)DeviceExtension;

  if (DeviceData->BusChangePending)
  {
    ScsiPortNotification(BusChangeDetected, DeviceData, 0);
    DeviceData->BusChangePending = 0;
  }
  ScsiPortNotification(RequestTimerCall, DeviceExtension, XenScsi_CheckBusChangedTimer, 1000000);
}

static BOOLEAN
XenScsi_HwScsiInitialize(PVOID DeviceExtension)
{
  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  ScsiPortNotification(RequestTimerCall, DeviceExtension, XenScsi_CheckBusEnumeratedTimer, 100000);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

// Call with device lock held
static VOID
XenScsi_PutSrbOnRing(PXENSCSI_TARGET_DATA TargetData, PSCSI_REQUEST_BLOCK Srb)
{
  //PUCHAR DataBuffer;
  int i;
  vscsiif_shadow_t *shadow;
  uint16_t id;
  int remaining;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  if (RING_FULL(&TargetData->Ring))
  {
    KdPrint((__DRIVER_NAME "     RING IS FULL - EXPECT BADNESS\n"));
    // TODO: Fail badly here
  }

  id = GET_ID_FROM_FREELIST(TargetData);
  if (id == 0x0fff)
  {
    KdPrint((__DRIVER_NAME "     Something is horribly wrong in PutSrbOnRing\n"));
  }

  shadow = &TargetData->shadow[id];
  shadow->Srb = Srb;
  shadow->req.rqid = id;
  shadow->req.cmd = VSCSIIF_CMND_SCSI;
  memset(shadow->req.cmnd, 0, VSCSIIF_MAX_COMMAND_SIZE);
  memcpy(shadow->req.cmnd, Srb->Cdb, 16);
  shadow->req.cmd_len = Srb->CdbLength;
  shadow->req.id = (USHORT)TargetData->id;
  shadow->req.lun = (USHORT)TargetData->lun;
  shadow->req.channel = (USHORT)TargetData->channel;
  if (Srb->DataTransferLength && (Srb->SrbFlags & SRB_FLAGS_DATA_IN) && (Srb->SrbFlags & SRB_FLAGS_DATA_OUT))
    shadow->req.sc_data_direction = DMA_BIDIRECTIONAL;
  else if (Srb->DataTransferLength && (Srb->SrbFlags & SRB_FLAGS_DATA_IN))
    shadow->req.sc_data_direction = DMA_FROM_DEVICE;
  else if (Srb->DataTransferLength && (Srb->SrbFlags & SRB_FLAGS_DATA_OUT))
    shadow->req.sc_data_direction = DMA_TO_DEVICE;
  else
    shadow->req.sc_data_direction = DMA_NONE;
  shadow->req.use_sg = (UINT8)((Srb->DataTransferLength + PAGE_SIZE - 1) >> PAGE_SHIFT);
  shadow->req.request_bufflen = Srb->DataTransferLength;

//  KdPrint((__DRIVER_NAME "     pages = %d\n", shadow->req.use_sg));
  remaining = Srb->DataTransferLength;
  shadow->req.seg[0].offset = 0;
  shadow->req.seg[0].length = 0;
  for (i = 0; remaining != 0; i++)
  {
    shadow->req.seg[i].offset = 0; // this is the offset into the page
    if (remaining >= PAGE_SIZE)
    {
      shadow->req.seg[i].length = PAGE_SIZE;
      remaining -= PAGE_SIZE;
    }
    else
    {
      shadow->req.seg[i].length = (USHORT)remaining;
      remaining = 0;
    }
//    KdPrint((__DRIVER_NAME "     sg %d: offset = %d, size = %d\n", i, shadow->req.seg[i].offset, shadow->req.seg[i].length));
  }
  if (Srb->SrbFlags & SRB_FLAGS_DATA_OUT)
    memcpy(TargetData->shadow[shadow->req.rqid].Buf, Srb->DataBuffer, Srb->DataTransferLength);

  *RING_GET_REQUEST(&TargetData->Ring, TargetData->Ring.req_prod_pvt) = shadow->req;
  TargetData->Ring.req_prod_pvt++;

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static BOOLEAN
XenScsi_HwScsiStartIo(PVOID DeviceExtension, PSCSI_REQUEST_BLOCK Srb)
{
  PXENSCSI_DEVICE_DATA DeviceData = (PXENSCSI_DEVICE_DATA)DeviceExtension;
  PXENSCSI_TARGET_DATA TargetData;
  int notify;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ " PathId = %d, TargetId = %d, Lun = %d\n", Srb->PathId, Srb->TargetId, Srb->Lun));

  // If we haven't enumerated all the devices yet then just defer the request
  // A timer will issue a NextRequest to get things started again...
  if (DeviceData->EnumeratedDevices < DeviceData->TotalInitialDevices)
  {
    Srb->SrbStatus = SRB_STATUS_BUSY;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    KdPrint((__DRIVER_NAME " --- HwScsiStartIo (Bus not enumerated yet)\n"));
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
#if 0
    KdPrint((__DRIVER_NAME "     SRB_FUNCTION_EXECUTE_SCSI\n"));
    KdPrint((__DRIVER_NAME "      CdbLength = %d\n", Srb->CdbLength));
    for (i = 0; i < Srb->CdbLength; i++)
      KdPrint((__DRIVER_NAME "      %02x: %02x\n", i, Srb->Cdb[i]));
    KdPrint((__DRIVER_NAME "      SrbFlags = 0x%02x\n", Srb->SrbFlags));
    KdPrint((__DRIVER_NAME "      DataTransferLength = %d\n", Srb->DataTransferLength));
#endif
    XenScsi_PutSrbOnRing(TargetData, Srb);
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&TargetData->Ring, notify);
    if (notify)
      DeviceData->XenDeviceData->XenInterface.EvtChn_Notify(
        DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
        TargetData->EventChannel);
    if (!RING_FULL(&TargetData->Ring))
      ScsiPortNotification(NextLuRequest, DeviceExtension, Srb->PathId, Srb->TargetId, Srb->Lun);
    else
      ScsiPortNotification(NextRequest, DeviceExtension);
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

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

static BOOLEAN
XenScsi_HwScsiResetBus(PVOID DeviceExtension, ULONG PathId)
{
  UNREFERENCED_PARAMETER(DeviceExtension);
  UNREFERENCED_PARAMETER(PathId);


  KdPrint((__DRIVER_NAME " --> HwScsiResetBus\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  KdPrint((__DRIVER_NAME " <-- HwScsiResetBus\n"));

  return TRUE;
}


static BOOLEAN
XenScsi_HwScsiAdapterState(PVOID DeviceExtension, PVOID Context, BOOLEAN SaveState)
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
XenScsi_HwScsiAdapterControl(PVOID DeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters)
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
