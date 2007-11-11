#include "xenvbd.h"
#include <io/blkif.h>
#include <srb.h>
#include <scsi.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <stdlib.h>
#include <xen_public.h>
#include <gnttbl_public.h>
#include <io/xenbus.h>

#define wmb() KeMemoryBarrier()
#define mb() KeMemoryBarrier()

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS
XenVbd_AddDevice(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit);

static NTSTATUS
XenVbd_PrepareHardware(WDFDEVICE hDevice, WDFCMRESLIST Resources, WDFCMRESLIST ResourcesTranslated);

static NTSTATUS
XenVbd_ReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated);

static NTSTATUS
XenVbd_D0Entry(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState);

static NTSTATUS
XenVbd_D0EntryPostInterruptsEnabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState);

static NTSTATUS
XenVbd_D0Exit(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState);

static VOID
XenVbd_IoDefault(WDFQUEUE Queue, WDFREQUEST Request);
static VOID
XenVbd_IoRead(WDFQUEUE Queue, WDFREQUEST Request, size_t  Length);
static VOID
XenVbd_IoWrite(WDFQUEUE Queue, WDFREQUEST Request, size_t  Length);
static VOID
XenVbd_IoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, IN size_t  OutputBufferLength, size_t  InputBufferLength, ULONG IoControlCode);

static NTSTATUS
XenVbd_ChildListCreateDevice(WDFCHILDLIST ChildList, PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription, PWDFDEVICE_INIT ChildInit);
//static NTSTATUS
//XenVbd_DeviceResourceRequirementsQuery(WDFDEVICE Device, WDFIORESREQLIST IoResourceRequirementsList);
static NTSTATUS
XenVbd_Child_PreprocessWdmIrpSCSI(WDFDEVICE Device, PIRP Irp);
static VOID 
XenVbd_Child_IoDefault(WDFQUEUE  Queue, WDFREQUEST  Request);
static VOID 
XenVbd_Child_IoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode);

static VOID
XenVbd_HotPlugHandler(char *Path, PVOID Data);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, XenVbd_AddDevice)
#endif

LIST_ENTRY DeviceListHead;
XEN_IFACE_EVTCHN EvtChnInterface;
XEN_IFACE_XENBUS XenBusInterface;
XEN_IFACE_XEN XenInterface;
XEN_IFACE_GNTTBL GntTblInterface;

static BOOLEAN AutoEnumerate;

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  WDF_DRIVER_CONFIG config;
  ULONG status;
  UNICODE_STRING RegKeyName;
  UNICODE_STRING RegValueName;
  HANDLE RegHandle;
  OBJECT_ATTRIBUTES RegObjectAttributes;
  char Buf[200];
  ULONG BufLen = 200;
  PKEY_VALUE_PARTIAL_INFORMATION KeyPartialValue;
  int State = 0;
  int StartPos = 0;
  WCHAR *SystemStartOptions;
  size_t SystemStartOptionsLen;
  size_t i;

  KdPrint((__DRIVER_NAME " --> DriverEntry\n"));

  WDF_DRIVER_CONFIG_INIT(&config, XenVbd_AddDevice);
  status = WdfDriverCreate(
                      DriverObject,
                      RegistryPath,
                      WDF_NO_OBJECT_ATTRIBUTES,
                      &config,
                      WDF_NO_HANDLE);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME " WdfDriverCreate failed with status 0x%08x\n", status));
  }

  RtlInitUnicodeString(&RegKeyName, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control");
  InitializeObjectAttributes(&RegObjectAttributes, &RegKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
  status = ZwOpenKey(&RegHandle, KEY_READ, &RegObjectAttributes);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     ZwOpenKey returned %08x\n", status));
  }

  RtlInitUnicodeString(&RegValueName, L"SystemStartOptions");
  status = ZwQueryValueKey(RegHandle, &RegValueName, KeyValuePartialInformation, Buf, BufLen, &BufLen);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     ZwQueryKeyValue returned %08x\n", status));
  }
  //KdPrint((__DRIVER_NAME "     BufLen = %d\n", BufLen));
  KeyPartialValue = (PKEY_VALUE_PARTIAL_INFORMATION)Buf;
  KdPrint((__DRIVER_NAME "     Buf = %ws\n", KeyPartialValue->Data));
  SystemStartOptions = (WCHAR *)KeyPartialValue->Data;

  AutoEnumerate = FALSE;

  RtlStringCbLengthW(SystemStartOptions, KeyPartialValue->DataLength, &SystemStartOptionsLen);

  for (i = 0; i <= SystemStartOptionsLen/2; i++)
  {
    //KdPrint((__DRIVER_NAME "     pos = %d, state = %d, char = '%wc' (%d)\n", i, State, SystemStartOptions[i], SystemStartOptions[i]));
    
    switch (State)
    {
    case 0:
      if (SystemStartOptions[i] == L'G')
      {
        StartPos = i;
        State = 2;
      } else if (SystemStartOptions[i] != L' ')
      {
        State = 1;
      }
      break;
    case 1:
      if (SystemStartOptions[i] == L' ')
        State = 0;
      break;
    case 2:
      if (SystemStartOptions[i] == L'P')
        State = 3;
      else
        State = 0;
      break;
    case 3:
      if (SystemStartOptions[i] == L'L')
        State = 4;
      else
        State = 0;
      break;
    case 4:
      if (SystemStartOptions[i] == L'P')
        State = 5;
      else
        State = 0;
      break;
    case 5:
      if (SystemStartOptions[i] == L'V')
        State = 6;
      else
        State = 0;
      break;
    case 6:
      if (SystemStartOptions[i] == L' ' || SystemStartOptions[i] == 0)
        AutoEnumerate = TRUE;
      State = 0;
      break;
    }
  }

  KdPrint((__DRIVER_NAME "     AutoEnumerate = %d\n", AutoEnumerate));

  KdPrint((__DRIVER_NAME " <-- DriverEntry\n"));

  return status;
}

static WDFDEVICE GlobalDevice;
static PDEVICE_OBJECT Pdo;

static NTSTATUS
XenVbd_AddDevice(
    IN WDFDRIVER Driver,
    IN PWDFDEVICE_INIT DeviceInit
    )
{
  WDF_CHILD_LIST_CONFIG ChildListConfig;
  NTSTATUS status;
  WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;

  UNREFERENCED_PARAMETER(Driver);

  KdPrint((__DRIVER_NAME " --> DeviceAdd\n"));

  Pdo = WdfFdoInitWdmGetPhysicalDevice(DeviceInit);

  //*** just changed ***
  //WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);
  WDF_CHILD_LIST_CONFIG_INIT(&ChildListConfig, sizeof(XENVBD_DEVICE_IDENTIFICATION_DESCRIPTION), XenVbd_ChildListCreateDevice);
  WdfFdoInitSetDefaultChildListConfig(DeviceInit, &ChildListConfig, WDF_NO_OBJECT_ATTRIBUTES);

  WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_CONTROLLER);
  //WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);
  WdfDeviceInitSetExclusive(DeviceInit, FALSE);
  
  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
  pnpPowerCallbacks.EvtDevicePrepareHardware = XenVbd_PrepareHardware;
  pnpPowerCallbacks.EvtDeviceReleaseHardware = XenVbd_ReleaseHardware;
  pnpPowerCallbacks.EvtDeviceD0Entry = XenVbd_D0Entry;
  pnpPowerCallbacks.EvtDeviceD0EntryPostInterruptsEnabled = XenVbd_D0EntryPostInterruptsEnabled;
  pnpPowerCallbacks.EvtDeviceD0Exit = XenVbd_D0Exit;
  WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

  /*initialize storage for the device context*/
  //WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, XENVBD_DEVICE_DATA);

  /*create a device instance.*/
  status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &GlobalDevice);  
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "WdfDeviceCreate failed with status 0x%08x\n", status));
    return status;
  }
  
  status = STATUS_SUCCESS;

  KdPrint((__DRIVER_NAME " <-- DeviceAdd\n"));
  return status;
}

static NTSTATUS
XenVbd_PrepareHardware(
  IN WDFDEVICE    Device,
  IN WDFCMRESLIST ResourceList,
  IN WDFCMRESLIST ResourceListTranslated)
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(ResourceList);
  UNREFERENCED_PARAMETER(ResourceListTranslated);

  //KdPrint((__DRIVER_NAME " --> EvtDevicePrepareHardware\n"));

  status = WdfFdoQueryForInterface(Device, &GUID_XEN_IFACE_EVTCHN, (PINTERFACE) &EvtChnInterface, sizeof(XEN_IFACE_EVTCHN), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfFdoQueryForInterface (EvtChn) failed with status 0x%08x\n", status));
  }

  status = WdfFdoQueryForInterface(Device, &GUID_XEN_IFACE_XENBUS, (PINTERFACE)&XenBusInterface, sizeof(XEN_IFACE_XENBUS), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfFdoQueryForInterface (XenBus) failed with status 0x%08x\n", status));
  }

  status = WdfFdoQueryForInterface(Device, &GUID_XEN_IFACE_XEN, (PINTERFACE)&XenInterface, sizeof(XEN_IFACE_XEN), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfFdoQueryForInterface (Xen) failed with status 0x%08x\n", status));
  }

  status = WdfFdoQueryForInterface(Device, &GUID_XEN_IFACE_GNTTBL, (PINTERFACE)&GntTblInterface, sizeof(XEN_IFACE_GNTTBL), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfFdoQueryForInterface (GntTbl) failed with status 0x%08x\n", status));
  }
  
  //KdPrint((__DRIVER_NAME " <-- EvtDevicePrepareHardware\n"));

  InitializeListHead(&DeviceListHead);

  return status;
}

static NTSTATUS
XenVbd_ReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)
{
  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(ResourcesTranslated);

  // release interfaces here...

  //XenVbd_Close();

  return STATUS_SUCCESS;
}

static NTSTATUS
XenVbd_D0Entry(
    IN WDFDEVICE  Device,
    IN WDF_POWER_DEVICE_STATE PreviousState
    )
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(PreviousState);

  //KdPrint((__DRIVER_NAME " --> EvtDeviceD0Entry\n"));

  
  //KdPrint((__DRIVER_NAME " <-- EvtDeviceD0Entry\n"));

  return status;
}

static int EnumeratedDevices;
static KEVENT WaitDevicesEvent;

static NTSTATUS
XenVbd_D0EntryPostInterruptsEnabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)
{
  //OBJECT_ATTRIBUTES oa;
  NTSTATUS status = STATUS_SUCCESS;
  //HANDLE nothing;
  //char *response;
  PXENPCI_XEN_DEVICE_DATA PdoDeviceData;
  char **VbdDevices;
  char *msg;
  char buffer[128];
  int i;
  LARGE_INTEGER WaitTimeout;

  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(PreviousState);

  //KdPrint((__DRIVER_NAME " --> EvtDeviceD0EntryPostInterruptsEnabled\n"));

  PdoDeviceData = (PXENPCI_XEN_DEVICE_DATA)Pdo->DeviceExtension; //GetXenDeviceData(Device);

  //KdPrint((__DRIVER_NAME "     BasePath = %s\n", PdoDeviceData->BasePath));
  PdoDeviceData->WatchHandler = XenVbd_HotPlugHandler;

  EnumeratedDevices = 0;
  KeInitializeEvent(&WaitDevicesEvent, SynchronizationEvent, FALSE);  

  if (AutoEnumerate)
  {
    msg = XenBusInterface.List(XBT_NIL, "device/vbd", &VbdDevices);
    if (!msg) {
      for (i = 0; VbdDevices[i]; i++)
      {
        KdPrint((__DRIVER_NAME "     found existing vbd device %s\n", VbdDevices[i]));
        RtlStringCbPrintfA(buffer, ARRAY_SIZE(buffer), "device/vbd/%s/state", VbdDevices[i]);
        XenVbd_HotPlugHandler(buffer, NULL);
        //ExFreePoolWithTag(bdDevices[i], XENPCI_POOL_TAG);
      }
      KdPrint((__DRIVER_NAME "     Waiting for devices to be enumerated\n"));
      while (EnumeratedDevices != i)
      {
// TODO: need to not wait forever here...
        WaitTimeout.QuadPart = -600000000;
        if (KeWaitForSingleObject(&WaitDevicesEvent, Executive, KernelMode, FALSE, &WaitTimeout) == STATUS_TIMEOUT)
        {
          KdPrint((__DRIVER_NAME "     Wait timed out\n"));
          break;
        }
        KdPrint((__DRIVER_NAME "     %d out of %d devices enumerated\n", EnumeratedDevices, i));
      }  
    }
  }

  //KdPrint((__DRIVER_NAME " <-- EvtDeviceD0EntryPostInterruptsEnabled\n"));

  return status;
}

static NTSTATUS
XenVbd_D0Exit(
    IN WDFDEVICE Device,
    IN WDF_POWER_DEVICE_STATE  TargetState
    )
{
  NTSTATUS status = STATUS_SUCCESS;
  //char *response;

  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(TargetState);

  //KdPrint((__DRIVER_NAME " --> EvtDeviceD0Exit\n"));

  //response = XenBusInterface.RemWatch(XBT_NIL, XenBusInterface.InterfaceHeader.Context, XenVbd_HotPlugHandler, NULL);

  //KdPrint((__DRIVER_NAME " <-- EvtDeviceD0Exit\n"));

  return status;
}

static VOID 
XenVbd_IoDefault(
    IN WDFQUEUE  Queue,
    IN WDFREQUEST  Request
    )
{
  UNREFERENCED_PARAMETER(Queue);

  //KdPrint((__DRIVER_NAME " --> EvtDeviceIoDefault\n"));

  WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);

  //KdPrint((__DRIVER_NAME " <-- EvtDeviceIoDefault\n"));
}

static __inline uint64_t
GET_ID_FROM_FREELIST(PXENVBD_CHILD_DEVICE_DATA ChildDeviceData)
{
  uint64_t free;

  free = ChildDeviceData->shadow_free;

  //KdPrint((__DRIVER_NAME "     A free = %d\n", free));
  
  ChildDeviceData->shadow_free = ChildDeviceData->shadow[free].req.id;

  //KdPrint((__DRIVER_NAME "     A shadow_free now = %d\n", ChildDeviceData->shadow_free));

  ChildDeviceData->shadow[free].req.id = 0x0fffffee; /* debug */
  return free;
}

static __inline VOID
ADD_ID_TO_FREELIST(PXENVBD_CHILD_DEVICE_DATA ChildDeviceData, uint64_t Id)
{
  ChildDeviceData->shadow[Id].req.id  = ChildDeviceData->shadow_free;
  ChildDeviceData->shadow[Id].Irp = NULL;
  ChildDeviceData->shadow_free = Id;
}

static VOID
XenVbd_PutIrpOnRing(WDFDEVICE Device, PIRP Irp);

static PMDL
AllocatePages(int Pages)
{
  PMDL Mdl;
  PVOID Buf;

  Buf = ExAllocatePoolWithTag(NonPagedPool, Pages * PAGE_SIZE, XENVBD_POOL_TAG);
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
  ExFreePoolWithTag(Buf, XENVBD_POOL_TAG);
}

static VOID
XenVbd_DpcThreadProc(WDFDPC Dpc)
{
  PIRP Irp;
  RING_IDX i, rp;
  int j;
  blkif_response_t *rep;
  PXENVBD_CHILD_DEVICE_DATA ChildDeviceData;
  PSCSI_REQUEST_BLOCK Srb;
  PIO_STACK_LOCATION IrpSp;
  char *DataBuffer;
  int more_to_do;
  int IrpCount;
  PIRP Irps[100];
  int BlockCount;
  KIRQL KIrql;
  WDFDEVICE ChildDevice;
  XenVbd_ListEntry *ListEntry;

  //!!!IRQL_DISPATCH!!!

  //KdPrint((__DRIVER_NAME " --> XenVbd_DpcThreadProc\n"));

  ChildDevice = WdfDpcGetParentObject(Dpc);

  ChildDeviceData = *GetChildDeviceData(ChildDevice);

  IrpCount = 0;
  more_to_do = TRUE;
  KeAcquireSpinLock(&ChildDeviceData->Lock, &KIrql);

  //ChildDeviceData->IrpAddedToRingAtLastDpc = ChildDeviceData->IrpAddedToRing;

  while (more_to_do)
  {
    rp = ChildDeviceData->Ring.sring->rsp_prod;
    KeMemoryBarrier();
    for (i = ChildDeviceData->Ring.rsp_cons; i != rp; i++)
    {
      rep = RING_GET_RESPONSE(&ChildDeviceData->Ring, i);
      //ChildDeviceData->IrpRemovedFromRing++;
      Irp = ChildDeviceData->shadow[rep->id].Irp;
      IrpSp = IoGetCurrentIrpStackLocation(Irp);
      Srb = IrpSp->Parameters.Scsi.Srb;

      if (rep->status != BLKIF_RSP_OKAY)
      {
        KdPrint((__DRIVER_NAME "     Xen Operation returned error in DpcThreadProc\n"));
        KdPrint((__DRIVER_NAME "       operation = %d, nr_segments = %d, sector_number = %d\n", ChildDeviceData->shadow[rep->id].req.operation, ChildDeviceData->shadow[rep->id].req.nr_segments, ChildDeviceData->shadow[rep->id].req.sector_number));
        for (j = 0; j < ChildDeviceData->shadow[rep->id].req.nr_segments; j++)
        {
          KdPrint((__DRIVER_NAME "       gref[%d] = %d\n", j, ChildDeviceData->shadow[rep->id].req.seg[j].gref));
        }
        KdPrint((__DRIVER_NAME "       MmGetMdlByteOffset = %d\n", MmGetMdlByteOffset(Irp->MdlAddress)));
      }
      for (j = 0; j < ChildDeviceData->shadow[rep->id].req.nr_segments; j++)
      {
        GntTblInterface.EndAccess(ChildDeviceData->shadow[rep->id].req.seg[j].gref);
      }
      BlockCount = (Srb->Cdb[7] << 8) | Srb->Cdb[8];
      if (Srb->Cdb[0] == SCSIOP_READ && ChildDeviceData->shadow[rep->id].Buf != NULL)
      {
        DataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);
        if (DataBuffer == NULL)
          KdPrint((__DRIVER_NAME "     MmGetSystemAddressForMdlSafe Failed in DpcThreadProc\n"));
        memcpy(DataBuffer, ChildDeviceData->shadow[rep->id].Buf, BlockCount * ChildDeviceData->BytesPerSector);
        FreePages(ChildDeviceData->shadow[rep->id].Mdl);
      }
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      Srb->ScsiStatus = 0;
      Irp->IoStatus.Status = STATUS_SUCCESS;
      Irp->IoStatus.Information = BlockCount * ChildDeviceData->BytesPerSector;

      Irps[IrpCount++] = Irp;

      ADD_ID_TO_FREELIST(ChildDeviceData, rep->id);
    }

    ChildDeviceData->Ring.rsp_cons = i;
    if (i != ChildDeviceData->Ring.req_prod_pvt)
    {
      RING_FINAL_CHECK_FOR_RESPONSES(&ChildDeviceData->Ring, more_to_do);
    }
    else
    {
      ChildDeviceData->Ring.sring->rsp_event = i + 1;
      more_to_do = FALSE;
    }
  }

  KeReleaseSpinLock(&ChildDeviceData->Lock, KIrql);

  for (j = 0; j < IrpCount; j++)
  {
    IoCompleteRequest(Irps[j], IO_NO_INCREMENT);
    //ChildDeviceData->IrpCompleted++;
  }

  KeAcquireSpinLock(&ChildDeviceData->Lock, &KIrql);

  while (!RING_FULL(&ChildDeviceData->Ring) && (ListEntry = (XenVbd_ListEntry *)/*ExInterlocked*/RemoveHeadList(&ChildDeviceData->IrpListHead)) != (XenVbd_ListEntry *)&ChildDeviceData->IrpListHead)
  {
    //ChildDeviceData->IrpRemovedFromList++;
    XenVbd_PutIrpOnRing(ChildDevice, ListEntry->Irp);
    ExFreePoolWithTag(ListEntry, XENVBD_POOL_TAG);
  }

  KeReleaseSpinLock(&ChildDeviceData->Lock, KIrql);
  //KdPrint((__DRIVER_NAME " <-- XenVbd_DpcThreadProc\n"));
  //KdPrint((__DRIVER_NAME " <-- XenVbd_DpcThreadProc (AddedToList = %d, RemovedFromList = %d, AddedToRing = %d, AddedToRingAtLastNotify = %d, AddedToRingAtLastInterrupt = %d, AddedToRingAtLastDpc = %d, RemovedFromRing = %d, IrpCompleted = %d)\n", ChildDeviceData->IrpAddedToList, ChildDeviceData->IrpRemovedFromList, ChildDeviceData->IrpAddedToRing, ChildDeviceData->IrpAddedToRingAtLastNotify, ChildDeviceData->IrpAddedToRingAtLastInterrupt, ChildDeviceData->IrpAddedToRingAtLastDpc, ChildDeviceData->IrpRemovedFromRing, ChildDeviceData->IrpCompleted));
}

static BOOLEAN
XenVbd_Interrupt(PKINTERRUPT Interrupt, PVOID ServiceContext)
{
  BOOLEAN RetVal;
  PXENVBD_CHILD_DEVICE_DATA ChildDeviceData;

  UNREFERENCED_PARAMETER(Interrupt);
  // !!!RUNS AT DIRQL!!!

  //KdPrint((__DRIVER_NAME " --> XenVbd_Interrupt\n"));

  ChildDeviceData = (PXENVBD_CHILD_DEVICE_DATA)ServiceContext;
  //ChildDeviceData->IrpAddedToRingAtLastInterrupt = ChildDeviceData->IrpAddedToRing;
  RetVal = WdfDpcEnqueue(ChildDeviceData->Dpc);

  //KdPrint((__DRIVER_NAME " <-- XenVbd_Interrupt (RetVal = %d)\n", RetVal));  

  return STATUS_SUCCESS;
}

static VOID
XenVbd_BackEndStateHandler(char *Path, PVOID Data)
{
  PXENVBD_CHILD_DEVICE_DATA DeviceData;
  char TmpPath[128];
  char *Value;
  int NewState;
  PMDL Mdl;
  grant_ref_t ref;
  blkif_sring_t *SharedRing;
  ULONG PFN;
  XENVBD_DEVICE_IDENTIFICATION_DESCRIPTION Description;
  NTSTATUS status;

  DeviceData = (PXENVBD_CHILD_DEVICE_DATA)Data;

  XenBusInterface.Read(XBT_NIL, Path, &Value);

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

    DeviceData->EventChannel = EvtChnInterface.AllocUnbound(0);
    EvtChnInterface.Bind(DeviceData->EventChannel, XenVbd_Interrupt, DeviceData);
    Mdl = AllocatePage();
    PFN = *MmGetMdlPfnArray(Mdl);
    SharedRing = (blkif_sring_t *)MmGetMdlVirtualAddress(Mdl);
    SHARED_RING_INIT(SharedRing);
    FRONT_RING_INIT(&DeviceData->Ring, SharedRing, PAGE_SIZE);
    ref = GntTblInterface.GrantAccess(0, PFN, FALSE);

    RtlStringCbCopyA(TmpPath, 128, DeviceData->Path);
    RtlStringCbCatA(TmpPath, 128, "/ring-ref");
    XenBusInterface.Printf(XBT_NIL, TmpPath, "%d", ref);

    RtlStringCbCopyA(TmpPath, 128, DeviceData->Path);
    RtlStringCbCatA(TmpPath, 128, "/event-channel");
    XenBusInterface.Printf(XBT_NIL, TmpPath, "%d", DeviceData->EventChannel);
  
    RtlStringCbCopyA(TmpPath, 128, DeviceData->Path);
    RtlStringCbCatA(TmpPath, 128, "/state");
    XenBusInterface.Printf(XBT_NIL, TmpPath, "%d", XenbusStateInitialised);

    KdPrint((__DRIVER_NAME "     Set Frontend state to Initialised\n"));
    break;

  case XenbusStateInitialised:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialised\n"));
    // create the device
    break;

  case XenbusStateConnected:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Connected\n"));  

    WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(&Description.Header, sizeof(Description));

    Description.DeviceData = DeviceData;

    RtlStringCbCopyA(TmpPath, 128, DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/type"); // should probably check that this is 'phy'
    XenBusInterface.Read(XBT_NIL, TmpPath, &Value);

    RtlStringCbCopyA(TmpPath, 128, DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/mode"); // should store this...
    XenBusInterface.Read(XBT_NIL, TmpPath, &Value);

    RtlStringCbCopyA(TmpPath, 128, DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/sector-size");
    XenBusInterface.Read(XBT_NIL, TmpPath, &Value);
    // should complain if Value == NULL
    DeviceData->BytesPerSector = atoi(Value);

    KdPrint((__DRIVER_NAME "     BytesPerSector = %d\n", DeviceData->BytesPerSector));    

    RtlStringCbCopyA(TmpPath, 128, DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/sectors");
    XenBusInterface.Read(XBT_NIL, TmpPath, &Value);
    // should complain if Value == NULL
    DeviceData->TotalSectors = (ULONGLONG)atol(Value);

    KdPrint((__DRIVER_NAME "     TotalSectors = %d\n", DeviceData->TotalSectors));    

    // should probably use the partition table (if one exists) here for the sectorspertrack and trackspercylinder values
    DeviceData->Geometry.MediaType = FixedMedia;
    DeviceData->Geometry.BytesPerSector = DeviceData->BytesPerSector;
    DeviceData->Geometry.SectorsPerTrack = 63;
    DeviceData->Geometry.TracksPerCylinder = 255;
    DeviceData->Geometry.Cylinders.QuadPart = DeviceData->TotalSectors / DeviceData->Geometry.SectorsPerTrack / DeviceData->Geometry.TracksPerCylinder;
    KdPrint((__DRIVER_NAME "     Geometry C/H/S = %d/%d/%d\n", DeviceData->Geometry.Cylinders.LowPart, DeviceData->Geometry.TracksPerCylinder, DeviceData->Geometry.SectorsPerTrack));

    status = WdfChildListAddOrUpdateChildDescriptionAsPresent(WdfFdoGetDefaultChildList(GlobalDevice), &Description.Header, NULL);
    if (!NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     WdfChildListAddOrUpdateChildDescriptionAsPresent failed %08x\n", status));
    } 

    RtlStringCbCopyA(TmpPath, 128, DeviceData->Path);
    RtlStringCbCatA(TmpPath, 128, "/state");
    XenBusInterface.Printf(XBT_NIL, TmpPath, "%d", XenbusStateConnected);

    KdPrint((__DRIVER_NAME "     Set Frontend state to Connected\n"));
    InterlockedIncrement(&EnumeratedDevices);
    KdPrint((__DRIVER_NAME "     Added a disk, notifying\n"));
    
    KeSetEvent(&WaitDevicesEvent, 1, FALSE);

    break;

  case XenbusStateClosing:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closing\n"));  
    break;

  case XenbusStateClosed:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closed\n"));  
    break;

  default:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Undefined = %d\n", NewState));
    break;
  }
}

static VOID
XenVbd_HotPlugHandler(char *Path, PVOID Data)
{
  PXENVBD_CHILD_DEVICE_DATA DeviceData;
  char **Bits;
  int Count;
  char TmpPath[128];
  char *Value;

  UNREFERENCED_PARAMETER(Data);  

  //KdPrint((__DRIVER_NAME " --> HotPlugHandler\n"));

  //KdPrint((__DRIVER_NAME "     Path = %s\n", Path));

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
    for (DeviceData = (PXENVBD_CHILD_DEVICE_DATA)DeviceListHead.Flink; DeviceData != (PXENVBD_CHILD_DEVICE_DATA)&DeviceListHead; DeviceData = (PXENVBD_CHILD_DEVICE_DATA)DeviceData->Entry.Flink)
    {
      if (strncmp(DeviceData->Path, Path, strlen(DeviceData->Path)) == 0 && Path[strlen(DeviceData->Path)] == '/')
      {
        break;
      }
    }
    if (DeviceData == (PXENVBD_CHILD_DEVICE_DATA)&DeviceListHead)
    {
      DeviceData = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENVBD_CHILD_DEVICE_DATA), XENVBD_POOL_TAG);
      memset(DeviceData, 0, sizeof(XENVBD_CHILD_DEVICE_DATA));

      //KdPrint((__DRIVER_NAME "     Allocated ChildDeviceData = %08x\n", DeviceData));
      
      InsertTailList(&DeviceListHead, &DeviceData->Entry);
      RtlStringCbCopyA(DeviceData->Path, 128, Bits[0]);
      RtlStringCbCatA(DeviceData->Path, 128, "/");
      RtlStringCbCatA(DeviceData->Path, 128, Bits[1]);
      RtlStringCbCatA(DeviceData->Path, 128, "/");
      RtlStringCbCatA(DeviceData->Path, 128, Bits[2]);

      DeviceData->DeviceIndex = atoi(Bits[2]);

      RtlStringCbCopyA(TmpPath, 128, DeviceData->Path);
      RtlStringCbCatA(TmpPath, 128, "/backend");
      XenBusInterface.Read(XBT_NIL, TmpPath, &Value);
      if (Value == NULL)
      {
        KdPrint((__DRIVER_NAME "     Read Failed\n"));
      }
      else
      {
        RtlStringCbCopyA(DeviceData->BackendPath, 128, Value);
      }
      RtlStringCbCopyA(TmpPath, 128, DeviceData->BackendPath);
      RtlStringCbCatA(TmpPath, 128, "/state");
      XenBusInterface.AddWatch(XBT_NIL, TmpPath, XenVbd_BackEndStateHandler, DeviceData);
    }
    break;
  }
  
  FreeSplitString(Bits, Count);

  //KdPrint((__DRIVER_NAME " <-- HotPlugHandler\n"));  

  return;
}

static NTSTATUS
XenVbd_ChildListCreateDevice(WDFCHILDLIST ChildList, PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription, PWDFDEVICE_INIT ChildInit)
{
  NTSTATUS status;
  WDFDEVICE ChildDevice;
  PXENVBD_DEVICE_IDENTIFICATION_DESCRIPTION XenVbdIdentificationDesc;
  DECLARE_UNICODE_STRING_SIZE(buffer, 50);
  WDF_OBJECT_ATTRIBUTES PdoAttributes;
  DECLARE_CONST_UNICODE_STRING(DeviceLocation, L"Xen Bus");
  PXENVBD_CHILD_DEVICE_DATA ChildDeviceData;
  WDF_IO_QUEUE_CONFIG IoQueueConfig;
  unsigned int i;
  WDF_DPC_CONFIG DpcConfig;
  WDF_OBJECT_ATTRIBUTES DpcObjectAttributes;

  UNREFERENCED_PARAMETER(ChildList);

  //KdPrint((__DRIVER_NAME " --> ChildListCreateDevice\n"));

  XenVbdIdentificationDesc = CONTAINING_RECORD(IdentificationDescription, XENVBD_DEVICE_IDENTIFICATION_DESCRIPTION, Header);

  ChildDeviceData = XenVbdIdentificationDesc->DeviceData;

  WdfDeviceInitSetDeviceType(ChildInit, FILE_DEVICE_MASS_STORAGE);

  status = RtlUnicodeStringPrintf(&buffer, L"XEN\\Disk&Ven_James&Prod_James&Rev_1.00\0");
  status = WdfPdoInitAssignDeviceID(ChildInit, &buffer);

  status = RtlUnicodeStringPrintf(&buffer, L"%02d", ChildDeviceData->DeviceIndex);
  status = WdfPdoInitAssignInstanceID(ChildInit, &buffer);

  status = RtlUnicodeStringPrintf(&buffer, L"XEN\\Disk\0");
  status = WdfPdoInitAddCompatibleID(ChildInit, &buffer);
  status = RtlUnicodeStringPrintf(&buffer, L"XEN\\RAW\0");
  status = WdfPdoInitAddCompatibleID(ChildInit, &buffer);
  status = RtlUnicodeStringPrintf(&buffer, L"GenDisk\0");
  status = WdfPdoInitAddCompatibleID(ChildInit, &buffer);

  status = RtlUnicodeStringPrintf(&buffer, L"vbd_%d", ChildDeviceData->DeviceIndex);
  status = WdfPdoInitAddDeviceText(ChildInit, &buffer, &DeviceLocation, 0x409);

  WdfPdoInitSetDefaultLocale(ChildInit, 0x409);
  
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&PdoAttributes, PXENVBD_CHILD_DEVICE_DATA);

  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSCSI, IRP_MJ_SCSI, NULL, 0);

  WdfDeviceInitSetIoType(ChildInit, WdfDeviceIoDirect);

  status = WdfDeviceCreate(&ChildInit, &PdoAttributes, &ChildDevice);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreate status = %08X\n", status));
  }

  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&IoQueueConfig, WdfIoQueueDispatchSequential);
  IoQueueConfig.EvtIoDefault = XenVbd_Child_IoDefault;
  IoQueueConfig.EvtIoDeviceControl = XenVbd_Child_IoDeviceControl;

  *GetChildDeviceData(ChildDevice) = ChildDeviceData;

  //ChildDeviceData->IrpAddedToList = 0;
  //ChildDeviceData->IrpRemovedFromList = 0;
  //ChildDeviceData->IrpAddedToRing = 0;
  //ChildDeviceData->IrpAddedToRingAtLastNotify = 0;
  //ChildDeviceData->IrpAddedToRingAtLastInterrupt = 0;
  //ChildDeviceData->IrpAddedToRingAtLastDpc = 0;
  //ChildDeviceData->IrpRemovedFromRing = 0;
  //ChildDeviceData->IrpCompleted = 0;

  status = WdfIoQueueCreate(ChildDevice, &IoQueueConfig, WDF_NO_OBJECT_ATTRIBUTES, &ChildDeviceData->IoDefaultQueue);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "WdfIoQueueCreate failed with status 0x%08x\n", status));
    return status;
  }

  ChildDeviceData->Device = ChildDevice;
  
  KeInitializeSpinLock(&ChildDeviceData->Lock);
  KeInitializeSpinLock(&ChildDeviceData->IrpListLock);
  InitializeListHead(&ChildDeviceData->IrpListHead);

  ChildDeviceData->shadow = ExAllocatePoolWithTag(NonPagedPool, sizeof(blkif_shadow_t) * BLK_RING_SIZE, XENVBD_POOL_TAG);
  memset(ChildDeviceData->shadow, 0, sizeof(blkif_shadow_t) * BLK_RING_SIZE);
  //KdPrint((__DRIVER_NAME "     Allocated shadow = %08x\n", ChildDeviceData->shadow));
  for (i = 0; i < BLK_RING_SIZE; i++)
    ChildDeviceData->shadow[i].req.id = i + 1;
  ChildDeviceData->shadow_free = 0;
  ChildDeviceData->shadow[BLK_RING_SIZE - 1].req.id = 0x0fffffff;

  WDF_DPC_CONFIG_INIT(&DpcConfig, XenVbd_DpcThreadProc);
  WDF_OBJECT_ATTRIBUTES_INIT(&DpcObjectAttributes);
  DpcObjectAttributes.ParentObject = ChildDevice;
  WdfDpcCreate(&DpcConfig, &DpcObjectAttributes, &ChildDeviceData->Dpc);

  //KdPrint((__DRIVER_NAME " <-- ChildListCreateDevice\n"));

  return status;
}


// Call with device lock held
static VOID
XenVbd_PutIrpOnRing(WDFDEVICE Device, PIRP Irp)
{
  char *DataBuffer;
  PSCSI_REQUEST_BLOCK Srb;
  PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
  PXENVBD_CHILD_DEVICE_DATA ChildDeviceData;
  blkif_request_t *req;
  int notify;
  int i;
  int j;
  int BlockCount;
  int sect_offset;

  //KdPrint((__DRIVER_NAME " --> PutIrpOnRing\n"));

  ChildDeviceData = *GetChildDeviceData(Device);

  if (RING_FULL(&ChildDeviceData->Ring))
  {
    KdPrint((__DRIVER_NAME "     RING IS FULL - EXPECT BADNESS\n"));
  }

  req = RING_GET_REQUEST(&ChildDeviceData->Ring, ChildDeviceData->Ring.req_prod_pvt);

  //KdPrint((__DRIVER_NAME "     req = %08x\n", req));

  Srb = irpSp->Parameters.Scsi.Srb;

  req->sector_number = (Srb->Cdb[2] << 24) | (Srb->Cdb[3] << 16) | (Srb->Cdb[4] << 8) | Srb->Cdb[5];
  BlockCount = (Srb->Cdb[7] << 8) | Srb->Cdb[8];

  req->id = GET_ID_FROM_FREELIST(ChildDeviceData);

  if (req->id == 0x0fffffff)
  {
    KdPrint((__DRIVER_NAME "     Something is horribly wrong in PutIrpOnRing\n"));
  }

  //KdPrint((__DRIVER_NAME "     id = %d\n", req->id));

  req->handle = 0;
  req->operation = (Srb->Cdb[0] == SCSIOP_READ)?BLKIF_OP_READ:BLKIF_OP_WRITE;
  ChildDeviceData->shadow[req->id].Irp = Irp;

  if ((MmGetMdlByteOffset(Irp->MdlAddress) & 0x1ff) == 0) // 0x1ff shouldn't be hardcoded...
  {
    // fast path - zero copy
    ChildDeviceData->shadow[req->id].Mdl = Irp->MdlAddress;
    ChildDeviceData->shadow[req->id].Buf = NULL; // we don't need the virtual address
  }
  else
  {
    // slow path - copy to bounce buffer
    ChildDeviceData->shadow[req->id].Mdl = AllocatePages((BlockCount * ChildDeviceData->BytesPerSector + PAGE_SIZE - 1) / PAGE_SIZE);
    ChildDeviceData->shadow[req->id].Buf = MmGetMdlVirtualAddress(ChildDeviceData->shadow[req->id].Mdl);
    if (ChildDeviceData->shadow[req->id].Buf == NULL)
    {
      KdPrint((__DRIVER_NAME "     MmGetMdlVirtualAddress returned NULL in PutIrpOnRing\n"));
    }
  }

//  if (MmGetMdlByteOffset(Irp->MdlAddress) != 0)
//    KdPrint((__DRIVER_NAME "     ByteOffset == %08x - we can't cope with this yet!\n", MmGetMdlByteOffset(Irp->MdlAddress)));
  sect_offset = MmGetMdlByteOffset(ChildDeviceData->shadow[req->id].Mdl) >> 9;
  for (i = 0, req->nr_segments = 0; i < BlockCount; req->nr_segments++)
  {
    req->seg[req->nr_segments].gref = GntTblInterface.GrantAccess(0, MmGetMdlPfnArray(ChildDeviceData->shadow[req->id].Mdl)[req->nr_segments], FALSE);
    req->seg[req->nr_segments].first_sect = sect_offset;
    for (j = sect_offset; i < BlockCount && j < PAGE_SIZE / ChildDeviceData->BytesPerSector; j++, i++)
      req->seg[req->nr_segments].last_sect = (uint8_t)j;
    sect_offset = 0;
  }
  if (Srb->Cdb[0] == SCSIOP_WRITE && ChildDeviceData->shadow[req->id].Buf != NULL)
  {
    DataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);
    if (DataBuffer == NULL)
      KdPrint((__DRIVER_NAME "     MmGetSystemAddressForMdlSafe failed in PutIrpOnRing\n"));
    memcpy(ChildDeviceData->shadow[req->id].Buf, DataBuffer, BlockCount * ChildDeviceData->BytesPerSector);
    //MmUnmapLockedPages(DataBuffer, Irp->MdlAddress);
  }
  ChildDeviceData->shadow[req->id].req = *req;

  ChildDeviceData->Ring.req_prod_pvt++;
  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&ChildDeviceData->Ring, notify);
  if (notify)
  {
    EvtChnInterface.Notify(ChildDeviceData->EventChannel);
    //KdPrint((__DRIVER_NAME "       Notified\n"));
    //ChildDeviceData->IrpAddedToRing++;
    //ChildDeviceData->IrpAddedToRingAtLastNotify = ChildDeviceData->IrpAddedToRing;
  }
  else
  {
    //ChildDeviceData->IrpAddedToRing++;
  }
  //KdPrint((__DRIVER_NAME " <-- PutIrpOnRing\n"));
}

static NTSTATUS
XenVbd_Child_PreprocessWdmIrpSCSI(WDFDEVICE Device, PIRP Irp)
{
  char *DataBuffer;
  NTSTATUS status = STATUS_SUCCESS;
  PSCSI_REQUEST_BLOCK Srb;
  PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
  PXENVBD_CHILD_DEVICE_DATA ChildDeviceData;
  KIRQL KIrql;
  XenVbd_ListEntry *ListEntry;

  //KdPrint((__DRIVER_NAME " --> WdmIrpPreprocessSCSI\n"));

  ChildDeviceData = *GetChildDeviceData(Device);

  Srb = irpSp->Parameters.Scsi.Srb;

  switch (Srb->Function)
  {
  case SRB_FUNCTION_EXECUTE_SCSI:
    //KdPrint((__DRIVER_NAME "     SRB_FUNCTION_EXECUTE_SCSI\n"));
    switch(Srb->Cdb[0]) {
    case SCSIOP_TEST_UNIT_READY:
      //KdPrint((__DRIVER_NAME "     Command = TEST_UNIT_READY\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      Srb->ScsiStatus = 0;
      status = STATUS_SUCCESS;
      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      break;
    case SCSIOP_INQUIRY:
      //KdPrint((__DRIVER_NAME "     Command = INQUIRY (LUN = %d, EVPD = %d, Page Code = %02X)\n", Srb->Cdb[1] >> 5, Srb->Cdb[1] & 1, Srb->Cdb[2]));
      if ((Srb->Cdb[1] & 1) == 0)
      {
        memset(Srb->DataBuffer, 0, Srb->DataTransferLength);
        DataBuffer = Srb->DataBuffer;
        DataBuffer[0] = 0x00; // disk
        DataBuffer[1] = 0x00; // not removable
        memcpy(DataBuffer + 8, "James", 5); // vendor id
        memcpy(DataBuffer + 16, "XenVBD", 6); // product id
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
      }
      else
      {
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
      }
      Srb->ScsiStatus = 0;
      status = STATUS_SUCCESS;
      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      break;
    case SCSIOP_READ_CAPACITY:
      DataBuffer = Srb->DataBuffer;
      DataBuffer[0] = (unsigned char)(ChildDeviceData->TotalSectors >> 24) & 0xff;
      DataBuffer[1] = (unsigned char)(ChildDeviceData->TotalSectors >> 16) & 0xff;
      DataBuffer[2] = (unsigned char)(ChildDeviceData->TotalSectors >> 8) & 0xff;
      DataBuffer[3] = (unsigned char)(ChildDeviceData->TotalSectors >> 0) & 0xff;
      DataBuffer[4] = 0x00;
      DataBuffer[5] = 0x00;
      DataBuffer[6] = 0x02;
      DataBuffer[7] = 0x00;
      Srb->ScsiStatus = 0;
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      status = STATUS_SUCCESS;
      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      break;
    case SCSIOP_MODE_SENSE:
      //KdPrint((__DRIVER_NAME "     Command = MODE_SENSE (DBD = %d, PC = %d, Page Code = %02x)\n", Srb->Cdb[1] & 0x10, Srb->Cdb[2] & 0xC0, Srb->Cdb[2] & 0x3F));
      switch(Srb->Cdb[2] & 0x3F)
      {
      default:
        memset(Srb->DataBuffer, 0, Srb->DataTransferLength);
        Srb->ScsiStatus = 0;
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        status = STATUS_SUCCESS;
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = Srb->DataTransferLength;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
      }
      break;
    case SCSIOP_READ:
    case SCSIOP_WRITE:
      IoMarkIrpPending(Irp);

      //KdPrint((__DRIVER_NAME "     Irp Acquiring Lock\n"));
      KeAcquireSpinLock(&ChildDeviceData->Lock, &KIrql);
      //KdPrint((__DRIVER_NAME "A    Got It\n"));

      if (RING_FULL(&ChildDeviceData->Ring))
      {
        //KdPrint((__DRIVER_NAME "A    Inserting into list\n"));
        ListEntry = (XenVbd_ListEntry *)ExAllocatePoolWithTag(NonPagedPool, sizeof(XenVbd_ListEntry), XENVBD_POOL_TAG);
        //KdPrint((__DRIVER_NAME "     Allocate ListEntry = %08x\n", ListEntry));
        if (ListEntry == NULL)
        {
          KdPrint((__DRIVER_NAME "     CANNOT ALLOCATE MEMORY FOR ListEntry!!!\n"));
        }
        ListEntry->Irp = Irp;
        InsertTailList(&ChildDeviceData->IrpListHead, &ListEntry->Entry);
        //ChildDeviceData->IrpAddedToList++;
      }
      else
      {
        XenVbd_PutIrpOnRing(Device, Irp);
        //KdPrint((__DRIVER_NAME "     WdmIrpPreprocessSCSI (AddedToList = %d, RemovedFromList = %d, AddedToRing = %d, AddedToRingAtLastNotify = %d, AddedToRingAtLastInterrupt = %d, AddedToRingAtLastDpc = %d, RemovedFromRing = %d, IrpCompleted = %d)\n", ChildDeviceData->IrpAddedToList, ChildDeviceData->IrpRemovedFromList, ChildDeviceData->IrpAddedToRing, ChildDeviceData->IrpAddedToRingAtLastNotify, ChildDeviceData->IrpAddedToRingAtLastInterrupt, ChildDeviceData->IrpAddedToRingAtLastDpc, ChildDeviceData->IrpRemovedFromRing, ChildDeviceData->IrpCompleted));
      }
      KeReleaseSpinLock(&ChildDeviceData->Lock, KIrql);
      status = STATUS_PENDING;
      break;
    default:
      status = STATUS_NOT_IMPLEMENTED;
      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      KdPrint((__DRIVER_NAME "     Unhandled EXECUTE_SCSI Command = %02X\n", Srb->Cdb[0]));
      break;
    }
    //status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
    break;
  case SRB_FUNCTION_CLAIM_DEVICE:
    //KdPrint((__DRIVER_NAME "     SRB_FUNCTION_CLAIM_DEVICE\n"));
    ObReferenceObject(WdfDeviceWdmGetDeviceObject(Device));
    Srb->DataBuffer = WdfDeviceWdmGetDeviceObject(Device);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
    status = STATUS_SUCCESS;
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    break;
  case SRB_FUNCTION_IO_CONTROL:
    //KdPrint((__DRIVER_NAME "     SRB_FUNCTION_IO_CONTROL\n"));
    //status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    status = STATUS_NOT_IMPLEMENTED;
    //Irp->IoStatus.Status = status;
    //Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    break;
  case SRB_FUNCTION_FLUSH:
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
    status = STATUS_SUCCESS;
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unhandled Srb->Function = %08X\n", Srb->Function));
    status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
    break;
  }

  //KdPrint((__DRIVER_NAME " <-- WdmIrpPreprocessSCSI (AddedToList = %d, RemovedFromList = %d, AddedToRing = %d, AddedToRingAtLastNotify = %d, AddedToRingAtLastInterrupt = %d, RemovedFromRing = %d)\n", ChildDeviceData->IrpAddedToList, ChildDeviceData->IrpRemovedFromList, ChildDeviceData->IrpAddedToRing, ChildDeviceData->IrpAddedToRingAtLastNotify, ChildDeviceData->IrpAddedToRingAtLastInterrupt, ChildDeviceData->IrpCompleted));
  //KdPrint((__DRIVER_NAME " <-- WdmIrpPreprocessSCSI\n"));

  return status;
}

static VOID 
XenVbd_Child_IoDefault(WDFQUEUE  Queue, WDFREQUEST  Request)
{
  UNREFERENCED_PARAMETER(Queue);

  //KdPrint((__DRIVER_NAME " --> EvtDeviceIoDefault\n"));

  WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);

  //KdPrint((__DRIVER_NAME " <-- EvtDeviceIoDefault\n"));
}

static VOID 
XenVbd_Child_IoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode)
{
  WDFDEVICE Device;
  PXENVBD_CHILD_DEVICE_DATA ChildDeviceData;  
  PIRP Irp;
  PSTORAGE_PROPERTY_QUERY Spq;
  PSTORAGE_ADAPTER_DESCRIPTOR Sad;
  PSTORAGE_DEVICE_DESCRIPTOR Sdd;
  PSCSI_ADDRESS Sa;

  UNREFERENCED_PARAMETER(Queue);
  //UNREFERENCED_PARAMETER(Request);
  UNREFERENCED_PARAMETER(OutputBufferLength);
  UNREFERENCED_PARAMETER(InputBufferLength);

  Device = WdfIoQueueGetDevice(Queue);

  ChildDeviceData = *GetChildDeviceData(Device);

  //KdPrint((__DRIVER_NAME " --> IoDeviceControl\n"));
  //KdPrint((__DRIVER_NAME "     InputBufferLength = %d\n", InputBufferLength));
  //KdPrint((__DRIVER_NAME "     OutputBufferLength = %d\n", OutputBufferLength));

  Irp = WdfRequestWdmGetIrp(Request);

  switch (IoControlCode)
  {
  case IOCTL_STORAGE_QUERY_PROPERTY:
    //KdPrint((__DRIVER_NAME "     IOCTL_STORAGE_QUERY_PROPERTY\n"));    
    Spq = (PSTORAGE_PROPERTY_QUERY)Irp->AssociatedIrp.SystemBuffer;
    if (Spq->PropertyId == StorageAdapterProperty && Spq->QueryType == PropertyStandardQuery)
    {
      //KdPrint((__DRIVER_NAME "     PropertyId = StorageAdapterProperty, QueryType = PropertyStandardQuery\n"));
      if (OutputBufferLength >= 8)
      {
        Sad = (PSTORAGE_ADAPTER_DESCRIPTOR)Irp->AssociatedIrp.SystemBuffer;
        Sad->Version = 1;
        Sad->Size = sizeof(STORAGE_ADAPTER_DESCRIPTOR);
        if (OutputBufferLength >= sizeof(STORAGE_ADAPTER_DESCRIPTOR))
        {
          Sad->MaximumTransferLength = 45056;
          Sad->MaximumPhysicalPages = 11;
          Sad->AlignmentMask = 0;
          Sad->AdapterUsesPio = FALSE;
          Sad->AdapterScansDown = FALSE;
          Sad->CommandQueueing = FALSE;
          Sad->AcceleratedTransfer = FALSE;
          Sad->BusType = BusTypeScsi;
          Sad->BusMajorVersion = 0;
          Sad->BusMinorVersion = 0;
        }
      }
      WdfRequestComplete(Request, STATUS_SUCCESS);
    }
    else if (Spq->PropertyId == StorageDeviceProperty && Spq->QueryType == PropertyStandardQuery)
    {
      //KdPrint((__DRIVER_NAME "     PropertyId = StorageDeviceProperty, QueryType = PropertyStandardQuery\n"));
      if (OutputBufferLength >= 8)
      {
        Sdd = (PSTORAGE_DEVICE_DESCRIPTOR)Irp->AssociatedIrp.SystemBuffer;
        Sdd->Version = 1;
        Sdd->Size = sizeof(STORAGE_DEVICE_DESCRIPTOR) + 31 - 1;
        // 0       0        1         2       3
        // 0       7        5         4       1
        //"VENDOR\0PRODUCT\0Revision\0Serial\0"
        if (OutputBufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR) - 1 + 31)
        {
          Sdd->DeviceType = 0x00;
          Sdd->DeviceTypeModifier = 0x00;
          Sdd->RemovableMedia = FALSE;
          Sdd->CommandQueueing = FALSE;
          Sdd->VendorIdOffset = sizeof(STORAGE_DEVICE_DESCRIPTOR) - 1 + 0;
          Sdd->ProductIdOffset = sizeof(STORAGE_DEVICE_DESCRIPTOR) - 1 + 7;
          Sdd->ProductRevisionOffset = sizeof(STORAGE_DEVICE_DESCRIPTOR) - 1 + 15;
          Sdd->SerialNumberOffset = sizeof(STORAGE_DEVICE_DESCRIPTOR) - 1 + 24;
          Sdd->BusType = BusTypeScsi;
          Sdd->RawPropertiesLength = 31;
          memcpy(Sdd->RawDeviceProperties, "VENDOR\0PRODUCT\0Revision\0Serial\0", 31);
        }
      }
      WdfRequestComplete(Request, STATUS_SUCCESS);
    }
    else
    {
      switch (Spq->PropertyId)
      {
      case StorageDeviceProperty:
        //KdPrint((__DRIVER_NAME "     StorageDeviceProperty\n"));
        break;        
      case StorageAccessAlignmentProperty:
        //KdPrint((__DRIVER_NAME "     StorageAccessAlignmentProperty\n"));
        break;
      case StorageAdapterProperty:
        //KdPrint((__DRIVER_NAME "     StorageAdapterProperty\n"));
         break;
      case StorageDeviceIdProperty:
        //KdPrint((__DRIVER_NAME "     StorageDeviceIdProperty\n"));
         break;
      case StorageDeviceUniqueIdProperty:
        //KdPrint((__DRIVER_NAME "     StorageDeviceUniqueIdProperty\n"));
        break;
      case StorageDeviceWriteCacheProperty:
        //KdPrint((__DRIVER_NAME "     StorageDeviceWriteCacheProperty\n"));
        break;
      default:
        //KdPrint((__DRIVER_NAME "     Unknown Property %08x\n", Spq->PropertyId));
         break;
      }
      switch (Spq->QueryType)
      {
      case PropertyStandardQuery:
        //KdPrint((__DRIVER_NAME "     PropertyStandardQuery\n"));
        break;        
       //case PropertyIncludeSwIds:
      //  //KdPrint((__DRIVER_NAME "     PropertyIncludeSwIds\n"));
      //  break;        
      case PropertyExistsQuery:
        //KdPrint((__DRIVER_NAME "     PropertyExistsQuery\n"));
        break;        
      default:
        //KdPrint((__DRIVER_NAME "     Unknown Query %08x\n", Spq->QueryType));
        break;
      }
      WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);
    }
    break;
  // http://www.osronline.com/article.cfm?article=229
  // 0x00070000 device = 0x70, Function = 0x000 = IOCTL_DISK_GET_DRIVE_GEOMETRY
  // 0x00041018 device = 0x04, function = 0x406 = IOCTL_SCSI_GET_ADDRESS 
  // 0x00049400 device = 0x04, function = 0x500 = ???IOCTL_STORAGE_QUERY_PROPERTY
  // 0x00560030 device = 0x56, Function = 0x00c = 
  case IOCTL_DISK_GET_DRIVE_GEOMETRY:
    KdPrint((__DRIVER_NAME "     IOCTL_DISK_GET_DRIVE_GEOMETRY\n"));
    memcpy(Irp->AssociatedIrp.SystemBuffer, &ChildDeviceData->Geometry, sizeof(DISK_GEOMETRY));
    WdfRequestComplete(Request, STATUS_SUCCESS);
    break;
  case IOCTL_SCSI_GET_ADDRESS:
    //KdPrint((__DRIVER_NAME "     IOCTL_SCSI_GET_ADDRESS\n"));
    Sa = (PSCSI_ADDRESS)Irp->AssociatedIrp.SystemBuffer;
    Sa->Length = sizeof(SCSI_ADDRESS);
    Sa->PortNumber = 0;
    Sa->PathId = 0;
    Sa->TargetId = 0;
    Sa->Lun = 0;
    WdfRequestComplete(Request, STATUS_SUCCESS);
    break;
  default:
    //KdPrint((__DRIVER_NAME "     Not Implemented IoControlCode=%08X\n", IoControlCode));
    WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);
    break;
  }

  //KdPrint((__DRIVER_NAME " <-- IoDeviceControl\n"));
}
