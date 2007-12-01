#include "xenvbddev.h"
#include <io/blkif.h>
#include <scsi.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <stdlib.h>
#include <xen_public.h>
#include <io/xenbus.h>
//#include <ntddft.h>
//#include <ntifs.h>

#define wmb() KeMemoryBarrier()
#define mb() KeMemoryBarrier()

DRIVER_INITIALIZE DriverEntry;

static ULONG
XenVbdDev_HwScsiFindAdapter(PVOID DeviceExtension, PVOID HwContext, PVOID BusInformation, PCHAR ArgumentString, PPORT_CONFIGURATION_INFORMATION ConfigInfo, PBOOLEAN Again);
static BOOLEAN
XenVbdDev_HwScsiInitialize(PVOID DeviceExtension);
static BOOLEAN
XenVbdDev_HwScsiStartIo(PVOID DeviceExtension, PSCSI_REQUEST_BLOCK Srb);
//static BOOLEAN
//XenVbdDev_HwScsiInterrupt(PVOID DeviceExtension);
static BOOLEAN
XenVbdDev_HwScsiResetBus(PVOID DeviceExtension, ULONG PathId);
static BOOLEAN
XenVbdDev_HwScsiAdapterState(PVOID DeviceExtension, PVOID Context, BOOLEAN SaveState);
static SCSI_ADAPTER_CONTROL_STATUS
XenVbdDev_HwScsiAdapterControl(PVOID DeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif

LIST_ENTRY DeviceListHead;
//XEN_IFACE_EVTCHN EvtChnInterface;
//XEN_IFACE_XENBUS XenBusInterface;
//XEN_IFACE_XEN XenInterface;
XEN_IFACE_GNTTBL GntTblInterface;

static BOOLEAN AutoEnumerate;

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  ULONG Status;
  HW_INITIALIZATION_DATA HwInitializationData;

  KdPrint((__DRIVER_NAME " --> DriverEntry\n"));

  RtlZeroMemory(&HwInitializationData, sizeof(HW_INITIALIZATION_DATA));

  HwInitializationData.HwInitializationDataSize = sizeof(HW_INITIALIZATION_DATA);
  HwInitializationData.AdapterInterfaceType = Internal; //PNPBus;
  HwInitializationData.HwInitialize = XenVbdDev_HwScsiInitialize;
  HwInitializationData.HwStartIo = XenVbdDev_HwScsiStartIo;
  //HwInitializationData.HwInterrupt = XenVbdDev_HwScsiInterrupt;
  HwInitializationData.HwFindAdapter = XenVbdDev_HwScsiFindAdapter;
  HwInitializationData.HwResetBus = XenVbdDev_HwScsiResetBus;
  HwInitializationData.HwDmaStarted = NULL;
  HwInitializationData.HwAdapterState = NULL;
  HwInitializationData.DeviceExtensionSize = sizeof(XENVBDDEV_DEVICE_DATA);
  HwInitializationData.SpecificLuExtensionSize = 0;
  HwInitializationData.SrbExtensionSize = 0;
  HwInitializationData.NumberOfAccessRanges = 1;
  HwInitializationData.MapBuffers = TRUE; //FALSE;
  HwInitializationData.NeedPhysicalAddresses = FALSE; //TRUE;
  //HwInitializationData.TaggedQueueing = FALSE;
  HwInitializationData.AutoRequestSense = FALSE;
  HwInitializationData.MultipleRequestPerLu = FALSE;
  HwInitializationData.ReceiveEvent = FALSE; // check this
  HwInitializationData.VendorIdLength = 0;
  HwInitializationData.VendorId = NULL;
  HwInitializationData.DeviceIdLength = 0;
  HwInitializationData.DeviceId = NULL;
  HwInitializationData.HwAdapterControl = XenVbdDev_HwScsiAdapterControl;

  Status = ScsiPortInitialize(DriverObject, RegistryPath, &HwInitializationData, NULL);

  if(!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME " ScsiPortInitialize failed with status 0x%08x\n", Status));
  }

  KdPrint((__DRIVER_NAME " <-- DriverEntry\n"));

  return Status;
}

static PMDL
AllocatePages(int Pages)
{
  PMDL Mdl;
  PVOID Buf;

  Buf = ExAllocatePoolWithTag(NonPagedPool, Pages * PAGE_SIZE, XENVBDDEV_POOL_TAG);
  if (Buf == NULL)
  {
    KdPrint((__DRIVER_NAME "     AllocatePages Failed at ExAllocatePoolWithTag\n"));
  }
  Mdl = IoAllocateMdl(Buf, Pages * PAGE_SIZE, FALSE, FALSE, NULL);
  if (Mdl == NULL)
  {
    KdPrint((__DRIVER_NAME "     AllocatePages Failed at IoAllocateMdl\n"));
  }
  MmBuildMdlForNonPagedPool(Mdl);
  
  return Mdl;
}

static PMDL
AllocatePage()
{
  return AllocatePages(1);
}

static VOID
FreePages(PMDL Mdl)
{
  PVOID Buf = MmGetMdlVirtualAddress(Mdl);
  //KdPrint((__DRIVER_NAME "     FreePages Failed at IoAllocateMdl\n"));
  //KdPrint((__DRIVER_NAME "     FreePages Buf = %08x\n", Buf));
  IoFreeMdl(Mdl);
  ExFreePoolWithTag(Buf, XENVBDDEV_POOL_TAG);
}

static ULONG
XenVbdDev_HwScsiFindAdapter(PVOID DeviceExtension, PVOID HwContext, PVOID BusInformation, PCHAR ArgumentString, PPORT_CONFIGURATION_INFORMATION ConfigInfo, PBOOLEAN Again)
{
  ULONG Status = SP_RETURN_FOUND;
  ULONG i;
  PACCESS_RANGE AccessRange;
  PXENVBDDEV_DEVICE_DATA DeviceData = (PXENVBDDEV_DEVICE_DATA)DeviceExtension;

  KdPrint((__DRIVER_NAME " --> HwScsiFindAdapter\n"));

  KdPrint((__DRIVER_NAME "     BusInterruptVector = %d\n", ConfigInfo->BusInterruptVector));

  KdPrint((__DRIVER_NAME "     AccessRanges = %d\n", ConfigInfo->NumberOfAccessRanges));

  for (i = 0; i < ConfigInfo->NumberOfAccessRanges; i++)
  {
    AccessRange = &(*(ConfigInfo->AccessRanges))[i];
    KdPrint((__DRIVER_NAME "     AccessRange %2d: RangeStart = %08x, RangeLength = %08x, RangeInMemory = %d\n", i, AccessRange->RangeStart.LowPart, AccessRange->RangeLength, AccessRange->RangeInMemory));
    switch (i)
    {
    case 0:
      //DeviceData->ScsiData = ScsiPortGetDeviceBase(DeviceExtension, ConfigInfo->AdapterInterfaceType, ConfigInfo->SystemIoBusNumber, AccessRange->RangeStart, PAGE_SIZE, FALSE);
      //DeviceData->ScsiData = MmMapIoSpace(AccessRange->RangeStart, PAGE_SIZE, MmCached);
      DeviceData->ScsiData = (PXENVBDDEV_SCSI_DATA)AccessRange->RangeStart.LowPart;
      KdPrint((__DRIVER_NAME "     Mapped to virtual address %08x\n", DeviceData->ScsiData));
      if (DeviceData->ScsiData->Magic == SCSI_DATA_MAGIC)
      {
      }
      KdPrint((__DRIVER_NAME "     Magic = %08x\n", DeviceData->ScsiData->Magic));
      break;
    default:
      break;
    }
  }

  ConfigInfo->NumberOfBuses = 1;
  ConfigInfo->MaximumTransferLength = 45056;
  ConfigInfo->NumberOfPhysicalBreaks = 11 - 1;
  ConfigInfo->ScatterGather = FALSE;
  ConfigInfo->Master = TRUE;
  ConfigInfo->AlignmentMask =  0;
  ConfigInfo->MaximumNumberOfLogicalUnits = 1;
  ConfigInfo->MaximumNumberOfTargets = 2;

  *Again = FALSE;

  KdPrint((__DRIVER_NAME " <-- HwScsiFindAdapter\n"));  

  return Status;
}

static __inline uint64_t
GET_ID_FROM_FREELIST(PXENVBDDEV_DEVICE_DATA DeviceData)
{
  uint64_t free;
  free = DeviceData->shadow_free;
  DeviceData->shadow_free = DeviceData->shadow[free].req.id;
  DeviceData->shadow[free].req.id = 0x0fffffee; /* debug */
  return free;
}

static __inline VOID
ADD_ID_TO_FREELIST(PXENVBDDEV_DEVICE_DATA DeviceData, uint64_t Id)
{
  DeviceData->shadow[Id].req.id  = DeviceData->shadow_free;
  DeviceData->shadow[Id].Srb = NULL;
  DeviceData->shadow_free = Id;
}

//static HANDLE XenVbdDev_ScsiPortThreadHandle;
//static KEVENT XenVbdDev_ScsiPortThreadEvent;

static VOID
XenVbdDev_Interrupt(PVOID DeviceExtension)
{
  PXENVBDDEV_DEVICE_DATA DeviceData = (PXENVBDDEV_DEVICE_DATA)DeviceExtension;
  PSCSI_REQUEST_BLOCK Srb;
  RING_IDX i, rp;
  int j;
  blkif_response_t *rep;
  char *DataBuffer;
  int more_to_do;
  int BlockCount;
  KIRQL KIrql;
  int notify;
  KAPC_STATE ApcState;
  PIRP Irp;
  SCSI_REQUEST_BLOCK TmpSrb;

  //!!!IRQL_DISPATCH!!!

  KdPrint((__DRIVER_NAME " --> Interrupt\n"));

  more_to_do = TRUE;
//  KeAcquireSpinLock(&DeviceData->Lock, &KIrql);

  while (more_to_do)
  {
    rp = DeviceData->ScsiData->Ring.sring->rsp_prod;
    KeMemoryBarrier();
    for (i = DeviceData->ScsiData->Ring.rsp_cons; i != rp; i++)
    {
      rep = RING_GET_RESPONSE(&DeviceData->ScsiData->Ring, i);
      Srb = DeviceData->shadow[rep->id].Srb;

      KdPrint((__DRIVER_NAME "     Response Id = %d\n", rep->id));

      if (rep->status != BLKIF_RSP_OKAY)
      {
        KdPrint((__DRIVER_NAME "     Xen Operation returned error\n"));
      }
      for (j = 0; j < DeviceData->shadow[rep->id].req.nr_segments; j++)
      {
        GntTblInterface.EndAccess(DeviceData->shadow[rep->id].req.seg[j].gref);
      }
      BlockCount = (Srb->Cdb[7] << 8) | Srb->Cdb[8];
      if (Srb->Cdb[0] == SCSIOP_READ)
      {
        memcpy(Srb->DataBuffer, DeviceData->shadow[rep->id].Buf, BlockCount * DeviceData->ScsiData->BytesPerSector);
        KdPrint((__DRIVER_NAME "     Read Sector = %08X, Sectors = %d\n", (int)DeviceData->shadow[rep->id].req.sector_number, BlockCount));
        KdPrint((__DRIVER_NAME "     (504-511 = %02X%02X%02X%02X%02X%02X%02X%02X)\n", ((PUCHAR)Srb->DataBuffer)[504], ((PUCHAR)Srb->DataBuffer)[505], ((PUCHAR)Srb->DataBuffer)[506], ((PUCHAR)Srb->DataBuffer)[507], ((PUCHAR)Srb->DataBuffer)[508], ((PUCHAR)Srb->DataBuffer)[509], ((PUCHAR)Srb->DataBuffer)[510], ((PUCHAR)Srb->DataBuffer)[511])); 
      }
      else
      {
        KdPrint((__DRIVER_NAME "     Write Sector = %08X, Sectors = %d\n", (int)DeviceData->shadow[rep->id].req.sector_number, BlockCount));
      }

      FreePages(DeviceData->shadow[rep->id].Mdl);
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      //KdPrint((__DRIVER_NAME "     Attaching to Process %08x\n", DeviceData->Process));
      //KeStackAttachProcess(DeviceData->Process, &ApcState);
      //KdPrint((__DRIVER_NAME "     Attached\n"));
      //ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      //KdPrint((__DRIVER_NAME "     Detaching\n"));
      //KeUnstackDetachProcess(&ApcState);
      //KdPrint((__DRIVER_NAME "     Detached\n"));

/*
      RtlZeroMemory(&TmpSrb, sizeof(SCSI_REQUEST_BLOCK));
      TmpSrb.Length = SCSI_REQUEST_BLOCK_SIZE;
      TmpSrb.PathId = LunInfo->PathId;
      TmpSrb.TargetId = LunInfo->TargetId;
      TmpSrb.Lun = LunInfo->Lun;
      TmpSrb.Function = SRB_FUNCTION_CLAIM_DEVICE;

      Irp = IoBuildDeviceIoControlRequest(IOCTL_SCSI_EXECUTE_NONE, PortDeviceObject, NULL, 0, NULL, 0, TRUE, &Event, &IoStatusBlock);

      IoCallDriver(DeviceData->DeviceObject, Irp);
*/

      ADD_ID_TO_FREELIST(DeviceData, rep->id);
    }

    DeviceData->ScsiData->Ring.rsp_cons = i;
    if (i != DeviceData->ScsiData->Ring.req_prod_pvt)
    {
      RING_FINAL_CHECK_FOR_RESPONSES(&DeviceData->ScsiData->Ring, more_to_do);
    }
    else
    {
      DeviceData->ScsiData->Ring.sring->rsp_event = i + 1;
      more_to_do = FALSE;
    }
  }

//  ScsiPortNotification(NextRequest, DeviceExtension, NULL);

//  KeReleaseSpinLock(&DeviceData->Lock, KIrql);

  KdPrint((__DRIVER_NAME " <-- Interrupt\n"));

  return;
}

/*
static VOID
XenVbdDev_ScsiPortThreadProc(PVOID DeviceExtension)
{
  PXENVBDDEV_DEVICE_DATA DeviceData = (PXENVBDDEV_DEVICE_DATA)DeviceExtension;
  PSCSI_REQUEST_BLOCK Srb;
  RING_IDX i, rp;
  int j;
  blkif_response_t *rep;
  char *DataBuffer;
  int more_to_do;
  int BlockCount;
  KIRQL KIrql;
  int notify;

  //!!!IRQL_DISPATCH!!!

  KdPrint((__DRIVER_NAME " --> ScsiPortThreadProc\n"));

  for(;;)
  {
    KeWaitForSingleObject(&XenVbdDev_ScsiPortThreadEvent, Executive, KernelMode, FALSE, NULL);
    KdPrint((__DRIVER_NAME " --- Thread woke up\n"));
    more_to_do = TRUE;
//  KeAcquireSpinLock(&DeviceData->Lock, &KIrql);

    while (more_to_do)
    {
      rp = DeviceData->ScsiData->Ring.sring->rsp_prod;
      KeMemoryBarrier();
      for (i = DeviceData->ScsiData->Ring.rsp_cons; i != rp; i++)
      {
        rep = RING_GET_RESPONSE(&DeviceData->ScsiData->Ring, i);
        Srb = DeviceData->shadow[rep->id].Srb;
  
        KdPrint((__DRIVER_NAME "     Response Id = %d\n", rep->id));
  
        if (rep->status != BLKIF_RSP_OKAY)
        {
          KdPrint((__DRIVER_NAME "     Xen Operation returned error\n"));
        }
        for (j = 0; j < DeviceData->shadow[rep->id].req.nr_segments; j++)
        {
          GntTblInterface.EndAccess(DeviceData->shadow[rep->id].req.seg[j].gref);
        }
        BlockCount = (Srb->Cdb[7] << 8) | Srb->Cdb[8];
        if (Srb->Cdb[0] == SCSIOP_READ)
        {
          memcpy(Srb->DataBuffer, DeviceData->shadow[rep->id].Buf, BlockCount * DeviceData->ScsiData->BytesPerSector);
          KdPrint((__DRIVER_NAME "     Read Sector = %08X, Sectors = %d\n", (int)DeviceData->shadow[rep->id].req.sector_number, BlockCount));
          KdPrint((__DRIVER_NAME "     (504-511 = %02X%02X%02X%02X%02X%02X%02X%02X)\n", ((PUCHAR)Srb->DataBuffer)[504], ((PUCHAR)Srb->DataBuffer)[505], ((PUCHAR)Srb->DataBuffer)[506], ((PUCHAR)Srb->DataBuffer)[507], ((PUCHAR)Srb->DataBuffer)[508], ((PUCHAR)Srb->DataBuffer)[509], ((PUCHAR)Srb->DataBuffer)[510], ((PUCHAR)Srb->DataBuffer)[511])); 
        }
        else
        {
          KdPrint((__DRIVER_NAME "     Write Sector = %08X, Sectors = %d\n", (int)DeviceData->shadow[rep->id].req.sector_number, BlockCount));
        }
  
        FreePages(DeviceData->shadow[rep->id].Mdl);
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
  
        ADD_ID_TO_FREELIST(DeviceData, rep->id);
      }
  
      DeviceData->ScsiData->Ring.rsp_cons = i;
      if (i != DeviceData->ScsiData->Ring.req_prod_pvt)
      {
        RING_FINAL_CHECK_FOR_RESPONSES(&DeviceData->ScsiData->Ring, more_to_do);
      }
      else
      {
        DeviceData->ScsiData->Ring.sring->rsp_event = i + 1;
        more_to_do = FALSE;
      }
    }
  }
}

static VOID
XenVbdDev_StartThread(PVOID DeviceExtension)
{
  NTSTATUS Status;
  OBJECT_ATTRIBUTES oa;

  KdPrint((__DRIVER_NAME " --> StartThread\n"));

  InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
  Status = PsCreateSystemThread(&XenVbdDev_ScsiPortThreadHandle, THREAD_ALL_ACCESS, &oa, NULL, NULL, XenVbdDev_ScsiPortThreadProc, DeviceExtension);

  KdPrint((__DRIVER_NAME " <-- StartThread\n"));
}
*/

static BOOLEAN
XenVbdDev_HwScsiInitialize(PVOID DeviceExtension)
{
  PXENVBDDEV_DEVICE_DATA DeviceData = (PXENVBDDEV_DEVICE_DATA)DeviceExtension;
  unsigned int i;
  NTSTATUS Status;

  KdPrint((__DRIVER_NAME " --> HwScsiInitialize\n"));

  GntTblInterface = DeviceData->ScsiData->GntTblInterface;

  KdPrint((__DRIVER_NAME "     A\n"));

  DeviceData->ScsiData->IsrContext = DeviceExtension;
// might we need a barrier here???
  DeviceData->ScsiData->IsrRoutine = XenVbdDev_Interrupt;

  KdPrint((__DRIVER_NAME "     B\n"));

  DeviceData->shadow = ExAllocatePoolWithTag(NonPagedPool, sizeof(blkif_shadow_t) * BLK_RING_SIZE, XENVBDDEV_POOL_TAG);

  KdPrint((__DRIVER_NAME "     C - %08x\n", DeviceData->shadow));

  memset(DeviceData->shadow, 0, sizeof(blkif_shadow_t) * BLK_RING_SIZE);
  for (i = 0; i < BLK_RING_SIZE; i++)
    DeviceData->shadow[i].req.id = i + 1;
  DeviceData->shadow_free = 0;
  DeviceData->shadow[BLK_RING_SIZE - 1].req.id = 0x0fffffff;

  KdPrint((__DRIVER_NAME "     D\n"));

  KeInitializeSpinLock(&DeviceData->Lock);

  KdPrint((__DRIVER_NAME "     E\n"));

//  KeInitializeEvent(&XenVbdDev_ScsiPortThreadEvent, SynchronizationEvent, FALSE);

  KdPrint((__DRIVER_NAME "     F\n"));

//  Status = PsCreateSystemThread(&XenVbdDev_ScsiPortThreadHandle, THREAD_ALL_ACCESS, &oa, NULL, NULL, XenVbdDev_ScsiPortThreadProc, DeviceExtension);

//  ScsiPortNotification(RequestTimerCall, DeviceExtension, XenVbdDev_StartThread, 1);

  DeviceData->Process = IoGetCurrentProcess();
  KdPrint((__DRIVER_NAME "     Process = %08x\n", DeviceData->Process));

  KdPrint((__DRIVER_NAME " <-- HwScsiInitialize\n"));


  return TRUE;
}

static ULONG
XenVbdDev_FillModePage(PXENVBDDEV_DEVICE_DATA DeviceData, UCHAR PageCode, PUCHAR DataBuffer, ULONG BufferLength, PULONG Offset)
{
  PMODE_RIGID_GEOMETRY_PAGE ModeRigidGeometry;

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

// Call with device lock held
static VOID
XenVbdDev_PutSrbOnRing(PXENVBDDEV_DEVICE_DATA DeviceData, PSCSI_REQUEST_BLOCK Srb)
{
  //PUCHAR DataBuffer;
  blkif_request_t *req;
  int i;
  int j;
  int BlockCount;
  int sect_offset;

// can use SRB_STATUS_BUSY to push the SRB back to windows...

  KdPrint((__DRIVER_NAME " --> PutSrbOnRing\n"));

  if (RING_FULL(&DeviceData->ScsiData->Ring))
  {
    KdPrint((__DRIVER_NAME "     RING IS FULL - EXPECT BADNESS\n"));
    // TODO: Fail badly here
  }

  req = RING_GET_REQUEST(&DeviceData->ScsiData->Ring, DeviceData->ScsiData->Ring.req_prod_pvt);

  //KdPrint((__DRIVER_NAME "     req = %08x\n", req));

  req->sector_number = (Srb->Cdb[2] << 24) | (Srb->Cdb[3] << 16) | (Srb->Cdb[4] << 8) | Srb->Cdb[5];
  BlockCount = (Srb->Cdb[7] << 8) | Srb->Cdb[8];

  req->id = GET_ID_FROM_FREELIST(DeviceData);

  KdPrint((__DRIVER_NAME "     Request Id = %d\n", req->id));

  if (req->id == 0x0fffffff)
  {
    KdPrint((__DRIVER_NAME "     Something is horribly wrong in PutSrbOnRing\n"));
  }

  req->handle = 0;
  req->operation = (Srb->Cdb[0] == SCSIOP_READ)?BLKIF_OP_READ:BLKIF_OP_WRITE;
  DeviceData->shadow[req->id].Srb = Srb;

  DeviceData->shadow[req->id].Mdl = AllocatePages((BlockCount * DeviceData->ScsiData->BytesPerSector + PAGE_SIZE - 1) / PAGE_SIZE);
  DeviceData->shadow[req->id].Buf = MmGetMdlVirtualAddress(DeviceData->shadow[req->id].Mdl);
  if (DeviceData->shadow[req->id].Buf == NULL)
  {
    KdPrint((__DRIVER_NAME "     MmGetMdlVirtualAddress returned NULL in PutSrbOnRing\n"));
  }
  sect_offset = MmGetMdlByteOffset(DeviceData->shadow[req->id].Mdl) >> 9;
  for (i = 0, req->nr_segments = 0; i < BlockCount; req->nr_segments++)
  {
    req->seg[req->nr_segments].gref = GntTblInterface.GrantAccess(0, MmGetMdlPfnArray(DeviceData->shadow[req->id].Mdl)[req->nr_segments], FALSE);
    req->seg[req->nr_segments].first_sect = sect_offset;
    for (j = sect_offset; i < BlockCount && j < PAGE_SIZE / DeviceData->ScsiData->BytesPerSector; j++, i++)
      req->seg[req->nr_segments].last_sect = (uint8_t)j;
    sect_offset = 0;
  }
  if (Srb->Cdb[0] == SCSIOP_READ) // && DeviceData->shadow[req->id].Buf != NULL)
  {
    KdPrint((__DRIVER_NAME "     Read Sector = %08X, Sectors = %d\n", (int)req->sector_number, BlockCount));
  }
  else
  {
    KdPrint((__DRIVER_NAME "     Write Sector = %08X, Sectors = %d\n", (int)req->sector_number, BlockCount));
    memcpy(DeviceData->shadow[req->id].Buf, Srb->DataBuffer, BlockCount * DeviceData->ScsiData->BytesPerSector);
  }
  DeviceData->shadow[req->id].req = *req;

  DeviceData->ScsiData->Ring.req_prod_pvt++;

  KdPrint((__DRIVER_NAME " <-- PutSrbOnRing\n"));
}

static BOOLEAN
XenVbdDev_HwScsiStartIo(PVOID DeviceExtension, PSCSI_REQUEST_BLOCK Srb)
{
  PUCHAR DataBuffer;
  PCDB cdb;
  PXENVBDDEV_DEVICE_DATA DeviceData = (PXENVBDDEV_DEVICE_DATA)DeviceExtension;
  unsigned int i;
  KIRQL KIrql;
  int notify;
  SCSI_PHYSICAL_ADDRESS ScsiPhysicalAddress;
  ULONG Length;

  KdPrint((__DRIVER_NAME " --> HwScsiStartIo PathId = %d, TargetId = %d, Lun = %d\n", Srb->PathId, Srb->TargetId, Srb->Lun));

  KdPrint((__DRIVER_NAME "     Process = %08x\n", IoGetCurrentProcess()));

  if (Srb->TargetId != 0 || Srb->Lun != 0)
  {
    Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    KdPrint((__DRIVER_NAME " <-- HwScsiStartIo (No Device)\n"));
    return TRUE;
  }

  switch (Srb->Function)
  {
  case SRB_FUNCTION_EXECUTE_SCSI:
    cdb = (PCDB)Srb->Cdb;
    KdPrint((__DRIVER_NAME "     SRB_FUNCTION_EXECUTE_SCSI\n"));
    switch(cdb->CDB6GENERIC.OperationCode)
    {
    case SCSIOP_TEST_UNIT_READY:
      KdPrint((__DRIVER_NAME "     Command = TEST_UNIT_READY\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      Srb->ScsiStatus = 0;
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);
      break;
    case SCSIOP_INQUIRY:
      KdPrint((__DRIVER_NAME "     Command = INQUIRY\n"));
      KdPrint((__DRIVER_NAME "     (LUN = %d, EVPD = %d, Page Code = %02X)\n", Srb->Cdb[1] >> 5, Srb->Cdb[1] & 1, Srb->Cdb[2]));
      KdPrint((__DRIVER_NAME "     (Length = %d)\n", Srb->DataTransferLength));
      KdPrint((__DRIVER_NAME "     (Databuffer = %08x)\n", Srb->DataBuffer));
      DataBuffer = Srb->DataBuffer;
      RtlZeroMemory(DataBuffer, Srb->DataTransferLength);
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      if ((Srb->Cdb[1] & 1) == 0)
      {
        DataBuffer[0] = DIRECT_ACCESS_DEVICE;
        DataBuffer[1] = 0x00; // not removable
        DataBuffer[3] = 32;
        memcpy(DataBuffer + 8, "James   ", 8); // vendor id
        memcpy(DataBuffer + 16, "XenVBD          ", 16); // product id
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
//        KdPrint((__DRIVER_NAME "     Command = INQUIRY (LUN = %d, EVPD = %d, Page Code = %02X)\n", Srb->Cdb[1] >> 5, Srb->Cdb[1] & 1, Srb->Cdb[2]));
      }
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);
      break;
    case SCSIOP_READ_CAPACITY:
      KdPrint((__DRIVER_NAME "     Command = READ_CAPACITY\n"));
      DataBuffer = Srb->DataBuffer;
      RtlZeroMemory(DataBuffer, Srb->DataTransferLength);
      DataBuffer[0] = (unsigned char)(DeviceData->ScsiData->TotalSectors >> 24) & 0xff;
      DataBuffer[1] = (unsigned char)(DeviceData->ScsiData->TotalSectors >> 16) & 0xff;
      DataBuffer[2] = (unsigned char)(DeviceData->ScsiData->TotalSectors >> 8) & 0xff;
      DataBuffer[3] = (unsigned char)(DeviceData->ScsiData->TotalSectors >> 0) & 0xff;
      DataBuffer[4] = (unsigned char)(DeviceData->ScsiData->BytesPerSector >> 24) & 0xff;
      DataBuffer[5] = (unsigned char)(DeviceData->ScsiData->BytesPerSector >> 16) & 0xff;
      DataBuffer[6] = (unsigned char)(DeviceData->ScsiData->BytesPerSector >> 8) & 0xff;
      DataBuffer[7] = (unsigned char)(DeviceData->ScsiData->BytesPerSector >> 0) & 0xff;
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
      ScsiPhysicalAddress = ScsiPortGetPhysicalAddress(DeviceData, Srb, Srb->DataBuffer, &Srb->DataTransferLength);
      DataBuffer = ScsiPortGetVirtualAddress(DeviceData, ScsiPhysicalAddress);
      RtlZeroMemory(DataBuffer, Srb->DataTransferLength);
      switch(cdb->MODE_SENSE.PageCode)
      {
      case MODE_SENSE_RETURN_ALL:
        //Ptr = (UCHAR *)Srb->DataBuffer;
        for (i = 0; i < MODE_SENSE_RETURN_ALL; i++)
        {
          if (XenVbdDev_FillModePage(DeviceData, cdb->MODE_SENSE.PageCode, DataBuffer, cdb->MODE_SENSE.AllocationLength, &Srb->DataTransferLength))
          {
            break;
          }
        }
        break;
      default:
        XenVbdDev_FillModePage(DeviceData, cdb->MODE_SENSE.PageCode, DataBuffer, cdb->MODE_SENSE.AllocationLength, &Srb->DataTransferLength);
        break;
      }
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);
      break;
    case SCSIOP_READ:
    case SCSIOP_WRITE:
      KdPrint((__DRIVER_NAME "     Command = READ/WRITE\n"));

      for (i = 0; i < 10; i++)
      {
        KdPrint((__DRIVER_NAME "     %02x: %02x\n", i, Srb->Cdb[i]));
      }
      //KeAcquireSpinLock(&DeviceData->Lock, &KIrql);

      XenVbdDev_PutSrbOnRing(DeviceData, Srb);
      RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&DeviceData->ScsiData->Ring, notify);
      if (notify)
        DeviceData->ScsiData->NotifyRoutine(DeviceData->ScsiData->NotifyContext);
      //KeReleaseSpinLock(&DeviceData->Lock, KIrql);
//      Srb->SrbStatus = SRB_STATUS_SUCCESS;
//      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextRequest, DeviceExtension, NULL);

      break;
    case SCSIOP_REPORT_LUNS:
      KdPrint((__DRIVER_NAME "     Command = REPORT_LUNS\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS; //SRB_STATUS_INVALID_REQUEST;
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

  KdPrint((__DRIVER_NAME " <-- HwScsiStartIo\n"));

  return TRUE;
}

/*
static BOOLEAN
XenVbdDev_HwScsiInterrupt(PVOID DeviceExtension)
{
  KdPrint((__DRIVER_NAME " --> HwScsiInterrupt\n"));

  KdPrint((__DRIVER_NAME " <-- HwScsiInterrupt\n"));

  return TRUE;
}
*/

static BOOLEAN
XenVbdDev_HwScsiResetBus(PVOID DeviceExtension, ULONG PathId)
{
  KdPrint((__DRIVER_NAME " --> HwScsiResetBus\n"));

  KdPrint((__DRIVER_NAME " <-- HwScsiResetBus\n"));

  return TRUE;
}


static BOOLEAN
XenVbdDev_HwScsiAdapterState(PVOID DeviceExtension, PVOID Context, BOOLEAN SaveState)
{
  KdPrint((__DRIVER_NAME " --> HwScsiAdapterState\n"));

  KdPrint((__DRIVER_NAME " <-- HwScsiAdapterState\n"));

  return TRUE;
}

static SCSI_ADAPTER_CONTROL_STATUS
XenVbdDev_HwScsiAdapterControl(PVOID DeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters)
{
  SCSI_ADAPTER_CONTROL_STATUS Status = ScsiAdapterControlSuccess;
  PSCSI_SUPPORTED_CONTROL_TYPE_LIST SupportedControlTypeList;

  KdPrint((__DRIVER_NAME " --> HwScsiAdapterControl\n"));

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
