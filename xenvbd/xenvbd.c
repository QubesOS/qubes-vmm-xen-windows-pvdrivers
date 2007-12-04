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
#include <ntddft.h>

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
static NTSTATUS
XenVbd_DeviceUsageNotification(WDFDEVICE Device, WDF_SPECIAL_FILE_TYPE NotificationType, BOOLEAN IsInNotificationPath);

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
static NTSTATUS
XenVbd_Child_PreprocessWdmIrpDEVICE_CONTROL(WDFDEVICE Device, PIRP Irp);
static NTSTATUS
XenVbd_Child_PreprocessWdmIrpSomethingSomething(WDFDEVICE Device, PIRP Irp);
static VOID 
XenVbd_Child_IoDefault(WDFQUEUE Queue, WDFREQUEST Request);
static VOID 
XenVbd_Child_IoReadWrite(WDFQUEUE Queue, WDFREQUEST Request, size_t Length);
static VOID 
XenVbd_Child_IoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode);
static VOID 
XenVbd_Child_IoInternalDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode);

static VOID
XenVbd_HotPlugHandler(char *Path, PVOID Data);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, XenVbd_AddDevice)
#endif

#pragma warning(disable: 4127) // disable conditional expression is constant

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
XenVbd_AddDevice(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
{
  WDF_CHILD_LIST_CONFIG ChildListConfig;
  NTSTATUS status;
  WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;

  UNREFERENCED_PARAMETER(Driver);

  KdPrint((__DRIVER_NAME " --> DeviceAdd\n"));

  Pdo = WdfFdoInitWdmGetPhysicalDevice(DeviceInit);

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
  pnpPowerCallbacks.EvtDeviceUsageNotification = XenVbd_DeviceUsageNotification;
  WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

  /*initialize storage for the device context*/
  //WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, XENVBD_DEVICE_DATA);

  //WdfDeviceInitSetPowerNotPageable(DeviceInit);

  /*create a device instance.*/
  status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &GlobalDevice);  
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "WdfDeviceCreate failed with status 0x%08x\n", status));
    return status;
  }

  WdfDeviceSetSpecialFileSupport(GlobalDevice, WdfSpecialFilePaging, TRUE);
  WdfDeviceSetSpecialFileSupport(GlobalDevice, WdfSpecialFileHibernation, TRUE);
  WdfDeviceSetSpecialFileSupport(GlobalDevice, WdfSpecialFileDump, TRUE);
  
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

#if 0 // not used yet
  status = WdfFdoQueryForInterface(Device, &GUID_XEN_IFACE_XEN, (PINTERFACE)&XenInterface, sizeof(XEN_IFACE_XEN), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfFdoQueryForInterface (Xen) failed with status 0x%08x\n", status));
  }
#endif

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

static LONG EnumeratedDevices;
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

  // TODO: Should probably do this in an EvtChildListScanForChildren
  if (AutoEnumerate)
  {
    msg = XenBusInterface.List(XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, "device/vbd", &VbdDevices);
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

static NTSTATUS
XenVbd_DeviceUsageNotification(
  WDFDEVICE Device,
  WDF_SPECIAL_FILE_TYPE NotificationType,
  BOOLEAN IsInNotificationPath)
{
  UNREFERENCED_PARAMETER(Device);

  KdPrint((__DRIVER_NAME " --> DeviceUsageNotification\n"));

  switch (NotificationType)
  {
  case WdfSpecialFilePaging:
    KdPrint((__DRIVER_NAME "     NotificationType = WdfSpecialFilePaging, Using = %d\n", IsInNotificationPath));
    break;
  case WdfSpecialFileHibernation:
    KdPrint((__DRIVER_NAME "     NotificationType = WdfSpecialFileHibernation, Using = %d\n", IsInNotificationPath));
    break;
  case WdfSpecialFileDump:
    KdPrint((__DRIVER_NAME "     NotificationType = WdfSpecialFileDump, Using = %d\n", IsInNotificationPath));
    break;
  default:
    KdPrint((__DRIVER_NAME "     NotificationType = %d, Using = %d\n", NotificationType, IsInNotificationPath));
    break;
  }
  KdPrint((__DRIVER_NAME " <-- DeviceUsageNotification\n"));

  return TRUE;
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
  int notify;

  //!!!IRQL_DISPATCH!!!

  //KdPrint((__DRIVER_NAME " --> XenVbd_DpcThreadProc\n"));

  ChildDevice = WdfDpcGetParentObject(Dpc);

  ChildDeviceData = *GetChildDeviceData(ChildDevice);

  IrpCount = 0;
  more_to_do = TRUE;
  KeAcquireSpinLock(&ChildDeviceData->Lock, &KIrql);

  ChildDeviceData->IrpAddedToRingAtLastDpc = ChildDeviceData->IrpAddedToRing;

  while (more_to_do)
  {
    rp = ChildDeviceData->Ring.sring->rsp_prod;
    KeMemoryBarrier();
    for (i = ChildDeviceData->Ring.rsp_cons; i != rp; i++)
    {
      rep = RING_GET_RESPONSE(&ChildDeviceData->Ring, i);
      ChildDeviceData->IrpRemovedFromRing++;
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
        GntTblInterface.EndAccess(GntTblInterface.InterfaceHeader.Context,
          ChildDeviceData->shadow[rep->id].req.seg[j].gref);
      }
      BlockCount = (Srb->Cdb[7] << 8) | Srb->Cdb[8];
      if (ChildDeviceData->shadow[rep->id].Buf != NULL)
      {
        if (Srb->Cdb[0] == SCSIOP_READ)
        {
          DataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);
          if (DataBuffer == NULL)
            KdPrint((__DRIVER_NAME "     MmGetSystemAddressForMdlSafe Failed in DpcThreadProc\n"));
          memcpy(DataBuffer, ChildDeviceData->shadow[rep->id].Buf, BlockCount * ChildDeviceData->BytesPerSector);
        }
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

  notify = 0;
  while (!RING_FULL(&ChildDeviceData->Ring) && (ListEntry = (XenVbd_ListEntry *)RemoveHeadList(&ChildDeviceData->IrpListHead)) != (XenVbd_ListEntry *)&ChildDeviceData->IrpListHead)
  {
    ChildDeviceData->IrpRemovedFromList++;
    XenVbd_PutIrpOnRing(ChildDevice, ListEntry->Irp);
    ExFreePoolWithTag(ListEntry, XENVBD_POOL_TAG);
    notify = 1;
  }
  if (notify)
  {
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&ChildDeviceData->Ring, notify);
    if (notify)
      EvtChnInterface.Notify(EvtChnInterface.InterfaceHeader.Context,
        ChildDeviceData->EventChannel);
  }
  KeReleaseSpinLock(&ChildDeviceData->Lock, KIrql);

  for (j = 0; j < IrpCount; j++)
  {
    IoCompleteRequest(Irps[j], IO_NO_INCREMENT);
    ChildDeviceData->IrpCompleted++;
  }

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
  ChildDeviceData->IrpAddedToRingAtLastInterrupt = ChildDeviceData->IrpAddedToRing;
  RetVal = WdfDpcEnqueue(ChildDeviceData->Dpc);

  //KdPrint((__DRIVER_NAME " <-- XenVbd_Interrupt (RetVal = %d)\n", RetVal));  

  return STATUS_SUCCESS;
}

static VOID
XenVbd_BackEndStateHandler(char *Path, PVOID Data)
{
  PXENVBD_CHILD_DEVICE_DATA DeviceData = Data;
  char TmpPath[128];
  char *Value;
  int NewState;
  PMDL Mdl;
  grant_ref_t ref;
  blkif_sring_t *SharedRing;
  ULONG PFN;
  XENVBD_DEVICE_IDENTIFICATION_DESCRIPTION Description;
  NTSTATUS status;

  XenBusInterface.Read(XenBusInterface.InterfaceHeader.Context,
    XBT_NIL, Path, &Value);
  NewState = atoi(Value);
  ExFreePool(Value);

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

    DeviceData->EventChannel = EvtChnInterface.AllocUnbound(
      EvtChnInterface.InterfaceHeader.Context, 0);
    EvtChnInterface.Bind(EvtChnInterface.InterfaceHeader.Context,
      DeviceData->EventChannel, XenVbd_Interrupt, DeviceData);
    Mdl = AllocatePage();
    PFN = *MmGetMdlPfnArray(Mdl);
    SharedRing = (blkif_sring_t *)MmGetMdlVirtualAddress(Mdl);
    SHARED_RING_INIT(SharedRing);
    FRONT_RING_INIT(&DeviceData->Ring, SharedRing, PAGE_SIZE);
    ref = GntTblInterface.GrantAccess(GntTblInterface.InterfaceHeader.Context,
      0, PFN, FALSE);

    RtlStringCbCopyA(TmpPath, ARRAY_SIZE(TmpPath), DeviceData->Path);
    RtlStringCbCatA(TmpPath, ARRAY_SIZE(TmpPath), "/ring-ref");
    XenBusInterface.Printf(XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", ref);

    RtlStringCbCopyA(TmpPath, ARRAY_SIZE(TmpPath), DeviceData->Path);
    RtlStringCbCatA(TmpPath, ARRAY_SIZE(TmpPath), "/event-channel");
    XenBusInterface.Printf(XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", DeviceData->EventChannel);
  
    RtlStringCbCopyA(TmpPath, ARRAY_SIZE(TmpPath), DeviceData->Path);
    RtlStringCbCatA(TmpPath, ARRAY_SIZE(TmpPath), "/state");
    XenBusInterface.Printf(XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", XenbusStateInitialised);

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

    RtlStringCbCopyA(TmpPath, ARRAY_SIZE(TmpPath), DeviceData->Path);
    RtlStringCbCatA(TmpPath, ARRAY_SIZE(TmpPath), "/device-type");
    XenBusInterface.Read(XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    if (strcmp(Value, "disk") == 0)
    {
      KdPrint((__DRIVER_NAME "     DeviceType = Disk\n"));    
      DeviceData->DeviceType = XENVBD_DEVICETYPE_DISK;
    }
    else if (strcmp(Value, "cdrom") == 0)
    {
      KdPrint((__DRIVER_NAME "     DeviceType = CDROM\n"));    
      DeviceData->DeviceType = XENVBD_DEVICETYPE_CDROM;
    }
    else
    {
      KdPrint((__DRIVER_NAME "     DeviceType = %s (This probably won't work!)\n", Value));
    }

    RtlStringCbCopyA(TmpPath, ARRAY_SIZE(TmpPath), DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, ARRAY_SIZE(TmpPath), "/type"); // should probably check that this is 'phy' or 'file' or at least not ''
    XenBusInterface.Read(XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    KdPrint((__DRIVER_NAME "     Backend Type = %s\n", Value));
    ExFreePool(Value);

    RtlStringCbCopyA(TmpPath, ARRAY_SIZE(TmpPath), DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, ARRAY_SIZE(TmpPath), "/mode"); // should store this...
    XenBusInterface.Read(XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    KdPrint((__DRIVER_NAME "     Backend Mode = %s\n", Value));
    ExFreePool(Value);

    RtlStringCbCopyA(TmpPath, ARRAY_SIZE(TmpPath), DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, ARRAY_SIZE(TmpPath), "/sector-size");
    XenBusInterface.Read(XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    // should complain if Value == NULL
    DeviceData->BytesPerSector = atoi(Value);
    ExFreePool(Value);

    KdPrint((__DRIVER_NAME "     BytesPerSector = %d\n", DeviceData->BytesPerSector));    

    RtlStringCbCopyA(TmpPath, ARRAY_SIZE(TmpPath), DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, ARRAY_SIZE(TmpPath), "/sectors");
    XenBusInterface.Read(XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    // should complain if Value == NULL
    DeviceData->TotalSectors = (ULONGLONG)atol(Value);
    ExFreePool(Value);

    KdPrint((__DRIVER_NAME "     TotalSectors = %d\n", DeviceData->TotalSectors));    

    // should probably use the partition table (if one exists) here for the sectorspertrack and trackspercylinder values
    DeviceData->Geometry.MediaType = FixedMedia;
    DeviceData->Geometry.BytesPerSector = DeviceData->BytesPerSector;
    DeviceData->Geometry.SectorsPerTrack = 63;
    DeviceData->Geometry.TracksPerCylinder = 255;
    DeviceData->Geometry.Cylinders.QuadPart = DeviceData->TotalSectors / DeviceData->Geometry.SectorsPerTrack / DeviceData->Geometry.TracksPerCylinder;
    KdPrint((__DRIVER_NAME "     Geometry C/H/S = %d/%d/%d\n", DeviceData->Geometry.Cylinders.LowPart, DeviceData->Geometry.TracksPerCylinder, DeviceData->Geometry.SectorsPerTrack));

    // if we detected something wrong, we should not enumarate the device and should instead initiate a close

    status = WdfChildListAddOrUpdateChildDescriptionAsPresent(WdfFdoGetDefaultChildList(GlobalDevice), &Description.Header, NULL);
    if (!NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     WdfChildListAddOrUpdateChildDescriptionAsPresent failed %08x\n", status));
    } 

    RtlStringCbCopyA(TmpPath, ARRAY_SIZE(TmpPath), DeviceData->Path);
    RtlStringCbCatA(TmpPath, ARRAY_SIZE(TmpPath), "/state");
    XenBusInterface.Printf(XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", XenbusStateConnected);

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
  if (Count != 4)
  {
    KdPrint((__FUNCTION__ ": Count = %d, not 4!\n", Count));
    goto cleanup;
  }

  if (strcmp(Bits[3], "state") != 0) // we only care when the state appears
    goto cleanup;

  /* ignore already known devices */
  for (DeviceData = (PXENVBD_CHILD_DEVICE_DATA)DeviceListHead.Flink; DeviceData != (PXENVBD_CHILD_DEVICE_DATA)&DeviceListHead; DeviceData = (PXENVBD_CHILD_DEVICE_DATA)DeviceData->Entry.Flink)
  {
    if (strncmp(DeviceData->Path, Path, strlen(DeviceData->Path)) == 0 && Path[strlen(DeviceData->Path)] == '/')
    {
      goto cleanup;
    }
  }

  /* new device found, alloc and init dev extension */
  DeviceData = ExAllocatePoolWithTag(NonPagedPool,
    sizeof(XENVBD_CHILD_DEVICE_DATA), XENVBD_POOL_TAG);
  memset(DeviceData, 0, sizeof(XENVBD_CHILD_DEVICE_DATA));

  //KdPrint((__DRIVER_NAME "     Allocated ChildDeviceData = %08x\n", DeviceData));
  
  InsertTailList(&DeviceListHead, &DeviceData->Entry);
  RtlStringCbPrintfA(DeviceData->Path, ARRAY_SIZE(DeviceData->Path),
    "%s/%s/%s", Bits[0], Bits[1], Bits[2]);
  DeviceData->DeviceIndex = atoi(Bits[2]);

  /* Get backend path */
  RtlStringCbCopyA(TmpPath, ARRAY_SIZE(TmpPath), DeviceData->Path);
  RtlStringCbCatA(TmpPath, ARRAY_SIZE(TmpPath), "/backend");
  XenBusInterface.Read(XenBusInterface.InterfaceHeader.Context,
    XBT_NIL, TmpPath, &Value);
  if (!Value)
  {
    KdPrint((__DRIVER_NAME "     Read Failed\n"));
  }
  else
  {
    RtlStringCbCopyA(DeviceData->BackendPath,
      ARRAY_SIZE(DeviceData->BackendPath), Value);
  }
  ExFreePool(Value);

  /* Add watch on backend state */
  RtlStringCbCopyA(TmpPath, ARRAY_SIZE(TmpPath), DeviceData->BackendPath);
  RtlStringCbCatA(TmpPath, ARRAY_SIZE(TmpPath), "/state");
  XenBusInterface.AddWatch(XenBusInterface.InterfaceHeader.Context,
    XBT_NIL, TmpPath, XenVbd_BackEndStateHandler, DeviceData);

cleanup:
  FreeSplitString(Bits, Count);

  //KdPrint((__DRIVER_NAME " <-- HotPlugHandler\n"));  
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
  WDF_DEVICE_STATE DeviceState;
  //UCHAR ScsiMinors[1] = { IRP_MN_SCSI_CLASS };

  UNREFERENCED_PARAMETER(ChildList);

  KdPrint((__DRIVER_NAME " --> ChildListCreateDevice\n"));

  XenVbdIdentificationDesc = CONTAINING_RECORD(IdentificationDescription, XENVBD_DEVICE_IDENTIFICATION_DESCRIPTION, Header);

  ChildDeviceData = XenVbdIdentificationDesc->DeviceData;

  // Capabilities = CM_DEVCAP_UNIQUEID
  // Devnode Flages = DN_NEED_RESTART??? DN_DISABLEABLE???

  switch (ChildDeviceData->DeviceType)
  {
  case XENVBD_DEVICETYPE_DISK:
    WdfDeviceInitSetDeviceType(ChildInit, FILE_DEVICE_DISK);

    status = RtlUnicodeStringPrintf(&buffer, L"XEN\\Disk\0");
    //status = RtlUnicodeStringPrintf(&buffer, L"XEN\\Disk&Ven_James&Prod_James&Rev_1.00\0");
    status = WdfPdoInitAssignDeviceID(ChildInit, &buffer);

    status = RtlUnicodeStringPrintf(&buffer, L"%02d\0", ChildDeviceData->DeviceIndex);
    status = WdfPdoInitAssignInstanceID(ChildInit, &buffer);

    status = RtlUnicodeStringPrintf(&buffer, L"GenDisk\0");
    status = WdfPdoInitAddCompatibleID(ChildInit, &buffer);
    status = WdfPdoInitAddHardwareID(ChildInit, &buffer);

    status = RtlUnicodeStringPrintf(&buffer, L"Xen PV Disk (%d)", ChildDeviceData->DeviceIndex);
    status = WdfPdoInitAddDeviceText(ChildInit, &buffer, &DeviceLocation, 0x409);
    break;
  case XENVBD_DEVICETYPE_CDROM:
    WdfDeviceInitSetDeviceType(ChildInit, FILE_DEVICE_MASS_STORAGE);
    WdfDeviceInitSetCharacteristics(ChildInit, FILE_READ_ONLY_DEVICE|FILE_REMOVABLE_MEDIA, TRUE);

    status = RtlUnicodeStringPrintf(&buffer, L"XEN\\CDROM\0");
    status = WdfPdoInitAssignDeviceID(ChildInit, &buffer);

    status = RtlUnicodeStringPrintf(&buffer, L"%02d\0", ChildDeviceData->DeviceIndex);
    status = WdfPdoInitAssignInstanceID(ChildInit, &buffer);

    status = RtlUnicodeStringPrintf(&buffer, L"GenCdRom\0");
    status = WdfPdoInitAddCompatibleID(ChildInit, &buffer);
    status = WdfPdoInitAddHardwareID(ChildInit, &buffer);

    status = RtlUnicodeStringPrintf(&buffer, L"Xen PV CDROM (%d)\0", ChildDeviceData->DeviceIndex);
    status = WdfPdoInitAddDeviceText(ChildInit, &buffer, &DeviceLocation, 0x409);
    break;
  default:
    // wtf?
    break;
  }

  WdfPdoInitSetDefaultLocale(ChildInit, 0x409);
  
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&PdoAttributes, PXENVBD_CHILD_DEVICE_DATA);

  //WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSCSI, IRP_MJ_SCSI, ScsiMinors, 1);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSCSI, IRP_MJ_SCSI, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpDEVICE_CONTROL, IRP_MJ_DEVICE_CONTROL, NULL, 0);

  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_CLEANUP, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_CLOSE, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_CREATE, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_DIRECTORY_CONTROL, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_FILE_SYSTEM_CONTROL, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_FLUSH_BUFFERS, NULL, 0);
///  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_INTERNAL_DEVICE_CONTROL, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_LOCK_CONTROL, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_POWER, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_QUERY_EA, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_QUERY_INFORMATION, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_QUERY_SECURITY, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_QUERY_VOLUME_INFORMATION, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_READ, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_SET_INFORMATION, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_SET_SECURITY, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_SET_VOLUME_INFORMATION, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_SHUTDOWN, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_SYSTEM_CONTROL, NULL, 0);
  WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpSomethingSomething, IRP_MJ_WRITE, NULL, 0);

  WdfDeviceInitSetIoType(ChildInit, WdfDeviceIoDirect);

  //WdfDeviceInitSetPowerNotPageable(ChildInit);

  status = WdfDeviceCreate(&ChildInit, &PdoAttributes, &ChildDevice);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreate status = %08X\n", status));
  }

  switch (ChildDeviceData->DeviceType)
  {
  case XENVBD_DEVICETYPE_DISK:
    WDF_DEVICE_STATE_INIT(&DeviceState);
    DeviceState.NotDisableable = WdfTrue;
    WdfDeviceSetDeviceState(ChildDevice, &DeviceState);
    WdfDeviceSetSpecialFileSupport(ChildDevice, WdfSpecialFilePaging, TRUE);
    WdfDeviceSetSpecialFileSupport(ChildDevice, WdfSpecialFileHibernation, TRUE);
    WdfDeviceSetSpecialFileSupport(ChildDevice, WdfSpecialFileDump, TRUE);
    break;
  case XENVBD_DEVICETYPE_CDROM:
    break;
  }
  *GetChildDeviceData(ChildDevice) = ChildDeviceData;

  ChildDeviceData->FastPathUsed = 0;
  ChildDeviceData->SlowPathUsed = 0;
  ChildDeviceData->IrpAddedToList = 0;
  ChildDeviceData->IrpRemovedFromList = 0;
  ChildDeviceData->IrpAddedToRing = 0;
  ChildDeviceData->IrpAddedToRingAtLastNotify = 0;
  ChildDeviceData->IrpAddedToRingAtLastInterrupt = 0;
  ChildDeviceData->IrpAddedToRingAtLastDpc = 0;
  ChildDeviceData->IrpRemovedFromRing = 0;
  ChildDeviceData->IrpCompleted = 0;

  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&IoQueueConfig, WdfIoQueueDispatchSequential);
  IoQueueConfig.AllowZeroLengthRequests = TRUE;
  //IoQueueConfig.EvtIoDefault = XenVbd_Child_IoDefault;
  //IoQueueConfig.EvtIoRead = XenVbd_Child_IoReadWrite;
  //IoQueueConfig.EvtIoWrite = XenVbd_Child_IoReadWrite;
  IoQueueConfig.EvtIoDeviceControl = XenVbd_Child_IoDeviceControl;
  //IoQueueConfig.EvtIoInternalDeviceControl = XenVbd_Child_IoInternalDeviceControl; // is IRP_MJ_SCSI

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

  KdPrint((__DRIVER_NAME " <-- ChildListCreateDevice (status = %08x)\n", status));

  return status;
}


// if the list isn't empty, then we should always add the request to the end of the list and then try and clear the list onto the ring

// Call with device lock held
static VOID
XenVbd_PutIrpOnRing(WDFDEVICE Device, PIRP Irp)
{
  char *DataBuffer;
  PSCSI_REQUEST_BLOCK Srb;
  PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
  PXENVBD_CHILD_DEVICE_DATA ChildDeviceData;
  blkif_request_t *req;
  int i;
  ULONG j;
  int BlockCount;
  UINT8 sect_offset;

  ChildDeviceData = *GetChildDeviceData(Device);

//  if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
    KdPrint((__DRIVER_NAME " --> PutIrpOnRing\n"));

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
    ChildDeviceData->FastPathUsed++;
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
    ChildDeviceData->SlowPathUsed++;
  }

//  if (((ChildDeviceData->FastPathUsed + ChildDeviceData->SlowPathUsed) & 0x2FF) == 0)
//  {
//    KdPrint((__DRIVER_NAME "     Fast Path = %d, Slow Path = %d\n", ChildDeviceData->FastPathUsed, ChildDeviceData->SlowPathUsed));
//    KdPrint((__DRIVER_NAME "     AddedToList = %d, RemovedFromList = %d, AddedToRing = %d, AddedToRingAtLastNotify = %d, AddedToRingAtLastInterrupt = %d, AddedToRingAtLastDpc = %d, RemovedFromRing = %d, IrpCompleted = %d\n", ChildDeviceData->IrpAddedToList, ChildDeviceData->IrpRemovedFromList, ChildDeviceData->IrpAddedToRing, ChildDeviceData->IrpAddedToRingAtLastNotify, ChildDeviceData->IrpAddedToRingAtLastInterrupt, ChildDeviceData->IrpAddedToRingAtLastDpc, ChildDeviceData->IrpRemovedFromRing, ChildDeviceData->IrpCompleted));
//  }

  sect_offset = (UINT8)(MmGetMdlByteOffset(ChildDeviceData->shadow[req->id].Mdl) >> 9);
  for (i = 0, req->nr_segments = 0; i < BlockCount; req->nr_segments++)
  {
    req->seg[req->nr_segments].gref = GntTblInterface.GrantAccess(
      GntTblInterface.InterfaceHeader.Context,
      0,
      MmGetMdlPfnArray(ChildDeviceData->shadow[req->id].Mdl)[req->nr_segments],
      FALSE);
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
  }
  ChildDeviceData->shadow[req->id].req = *req;

  ChildDeviceData->Ring.req_prod_pvt++;

  ChildDeviceData->IrpAddedToRing++;

//  if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
    KdPrint((__DRIVER_NAME " <-- PutIrpOnRing\n"));
}

static ULONG
XenVBD_FillModePage(PXENVBD_CHILD_DEVICE_DATA ChildDeviceData, UCHAR PageCode, PUCHAR DataBuffer, ULONG BufferLength, PULONG Offset)
{
  PMODE_RIGID_GEOMETRY_PAGE ModeRigidGeometry;

  switch (PageCode)
  {
  case MODE_PAGE_RIGID_GEOMETRY:
    if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_DISK)
    {
    KdPrint((__DRIVER_NAME "     MODE_PAGE_RIGID_GEOMETRY\n"));
    if (*Offset + sizeof(MODE_RIGID_GEOMETRY_PAGE) > BufferLength)
      return 1;
    ModeRigidGeometry = (PMODE_RIGID_GEOMETRY_PAGE)(DataBuffer + *Offset);
    memset(ModeRigidGeometry, 0, sizeof(MODE_RIGID_GEOMETRY_PAGE));
    ModeRigidGeometry->PageCode = PageCode;
    ModeRigidGeometry->PageSavable = 0;
    ModeRigidGeometry->PageLength = sizeof(MODE_RIGID_GEOMETRY_PAGE);
    ModeRigidGeometry->NumberOfCylinders[0] = (UCHAR)((ChildDeviceData->Geometry.Cylinders.LowPart >> 16) & 0xFF);
    ModeRigidGeometry->NumberOfCylinders[1] = (UCHAR)((ChildDeviceData->Geometry.Cylinders.LowPart >> 8) & 0xFF);
    ModeRigidGeometry->NumberOfCylinders[2] = (UCHAR)((ChildDeviceData->Geometry.Cylinders.LowPart >> 0) & 0xFF);
    ModeRigidGeometry->NumberOfHeads = (UCHAR)ChildDeviceData->Geometry.TracksPerCylinder;
    //ModeRigidGeometry->LandZoneCyclinder = 0;
    ModeRigidGeometry->RoataionRate[0] = 0x05;
    ModeRigidGeometry->RoataionRate[0] = 0x39;
    *Offset += sizeof(MODE_RIGID_GEOMETRY_PAGE);
    }
    break;
  case MODE_PAGE_FAULT_REPORTING:
    break;
  default:
    break;
  }
  return 0;
}

static NTSTATUS
XenVbd_Child_PreprocessWdmIrpDEVICE_CONTROL(WDFDEVICE Device, PIRP Irp)
{
  NTSTATUS Status;
  PIO_STACK_LOCATION IrpStack;
  PSCSI_ADDRESS ScsiAddress;

  KdPrint((__DRIVER_NAME " --> PreprocessWdmIrpDEVICE_CONTROL\n"));

  IrpStack = IoGetCurrentIrpStackLocation(Irp);

  switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
  {
  case IOCTL_SCSI_GET_ADDRESS:
    KdPrint((__DRIVER_NAME "     IOCTL_SCSI_GET_ADDRESS\n"));
    Irp->IoStatus.Information = sizeof(SCSI_ADDRESS);
    if (IrpStack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(SCSI_ADDRESS))
    {
      ScsiAddress = (PSCSI_ADDRESS)Irp->AssociatedIrp.SystemBuffer;
      ScsiAddress->Length = sizeof(SCSI_ADDRESS);
      ScsiAddress->PortNumber = 0;
      ScsiAddress->PathId = 0;
      ScsiAddress->TargetId = 0;
      ScsiAddress->Lun = 0;
      Status = STATUS_SUCCESS;
      Irp->IoStatus.Status = Status;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);      
    }
    else
    {
      KdPrint((__DRIVER_NAME "     (Buffer size too small @ %d\n", IrpStack->Parameters.DeviceIoControl.OutputBufferLength));    
    }
    break;  
  default:
    KdPrint((__DRIVER_NAME "     Control Code = %08x\n", IrpStack->Parameters.DeviceIoControl.IoControlCode));
    IoSkipCurrentIrpStackLocation(Irp);
    Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
  }

  KdPrint((__DRIVER_NAME " <-- PreprocessWdmIrpDEVICE_CONTROL\n"));

  return Status;
}

static NTSTATUS
XenVbd_Child_PreprocessWdmIrpSomethingSomething(WDFDEVICE Device, PIRP Irp)
{
  NTSTATUS Status;
  PIO_STACK_LOCATION IrpStack;

  KdPrint((__DRIVER_NAME " --> XenVbd_Child_PreprocessWdmIrpSomethingSomething\n"));

  IrpStack = IoGetCurrentIrpStackLocation(Irp);
  KdPrint((__DRIVER_NAME "     Major = %02X, Minor = %02X\n", IrpStack->MajorFunction, IrpStack->MinorFunction));

  IoSkipCurrentIrpStackLocation(Irp);

  Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);

  KdPrint((__DRIVER_NAME " <-- XenVbd_Child_PreprocessWdmIrpSomethingSomething\n"));

  return Status;
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
  int notify;
  PCDB cdb;
  //PUCHAR Ptr;
  ULONG i;

  ChildDeviceData = *GetChildDeviceData(Device);

//  if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
    KdPrint((__DRIVER_NAME " --> WdmIrpPreprocessSCSI\n"));

  //KdPrint((__DRIVER_NAME "     SCSI Minor = %02X\n", irpSp->MinorFunction));

  Srb = irpSp->Parameters.Scsi.Srb;

  switch (Srb->Function)
  {
  case SRB_FUNCTION_EXECUTE_SCSI:
    cdb = (PCDB)Srb->Cdb;
//    if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
      KdPrint((__DRIVER_NAME "     SRB_FUNCTION_EXECUTE_SCSI\n"));
    switch(cdb->CDB6GENERIC.OperationCode) //Srb->Cdb[0])
    {
    case SCSIOP_TEST_UNIT_READY:
//      if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
        KdPrint((__DRIVER_NAME "     Command = TEST_UNIT_READY\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      Srb->ScsiStatus = 0;
      status = STATUS_SUCCESS;
      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      break;
    case SCSIOP_INQUIRY:
      KdPrint((__DRIVER_NAME "     Command = INQUIRY\n"));
      KdPrint((__DRIVER_NAME "     (LUN = %d, EVPD = %d, Page Code = %02X)\n", Srb->Cdb[1] >> 5, Srb->Cdb[1] & 1, Srb->Cdb[2]));
      if ((Srb->Cdb[1] & 1) == 0)
      {
//        DataBuffer = Srb->DataBuffer;
        DataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);
        RtlZeroMemory(DataBuffer, Srb->DataTransferLength);

        DataBuffer[0] = 0x00; // disk
        DataBuffer[1] = 0x00; // not removable
        memcpy(DataBuffer + 8, "James   ", 8); // vendor id
        memcpy(DataBuffer + 16, "XenVBD          ", 8); // product id
        memcpy(DataBuffer + 32, "000", 8); // product revision level
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
      }
      else
      {
        //KdPrint((__DRIVER_NAME "     Command = INQUIRY (LUN = %d, EVPD = %d, Page Code = %02X)\n", Srb->Cdb[1] >> 5, Srb->Cdb[1] & 1, Srb->Cdb[2]));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
      }
      Srb->ScsiStatus = 0;
      status = STATUS_SUCCESS;
      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      break;
    case SCSIOP_READ_CAPACITY:
//      if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
        KdPrint((__DRIVER_NAME "     Command = READ_CAPACITY\n"));
//      DataBuffer = Srb->DataBuffer;
      DataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);
      DataBuffer[0] = (unsigned char)(ChildDeviceData->TotalSectors >> 24) & 0xff;
      DataBuffer[1] = (unsigned char)(ChildDeviceData->TotalSectors >> 16) & 0xff;
      DataBuffer[2] = (unsigned char)(ChildDeviceData->TotalSectors >> 8) & 0xff;
      DataBuffer[3] = (unsigned char)(ChildDeviceData->TotalSectors >> 0) & 0xff;
      DataBuffer[4] = (unsigned char)(ChildDeviceData->BytesPerSector >> 24) & 0xff;
      DataBuffer[5] = (unsigned char)(ChildDeviceData->BytesPerSector >> 16) & 0xff;
      DataBuffer[6] = (unsigned char)(ChildDeviceData->BytesPerSector >> 8) & 0xff;
      DataBuffer[7] = (unsigned char)(ChildDeviceData->BytesPerSector >> 0) & 0xff;
      Srb->ScsiStatus = 0;
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      status = STATUS_SUCCESS;
      Irp->IoStatus.Status = status;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      break;
    case SCSIOP_MODE_SENSE:
      KdPrint((__DRIVER_NAME "     Command = MODE_SENSE (DBD = %d, PC = %d, Page Code = %02x)\n", Srb->Cdb[1] & 0x10, Srb->Cdb[2] & 0xC0, Srb->Cdb[2] & 0x3F));
      KdPrint((__DRIVER_NAME "     Length = %d\n", Srb->DataTransferLength));

      status = STATUS_SUCCESS; 
      DataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);
//      DataBuffer = Srb->DataBuffer;
      RtlZeroMemory(DataBuffer, Srb->DataTransferLength);
      switch(cdb->MODE_SENSE.PageCode) //Srb->Cdb[2] & 0x3F)
      {
      case MODE_SENSE_RETURN_ALL:
        Irp->IoStatus.Information = 0;
        //Ptr = (UCHAR *)Srb->DataBuffer;
        for (i = 0; i < MODE_SENSE_RETURN_ALL; i++)
        {
          if (XenVBD_FillModePage(ChildDeviceData, cdb->MODE_SENSE.PageCode, DataBuffer, cdb->MODE_SENSE.AllocationLength, &Irp->IoStatus.Information))
          {
            break;
          }
        }
        break;
      default:
        XenVBD_FillModePage(ChildDeviceData, cdb->MODE_SENSE.PageCode, DataBuffer, cdb->MODE_SENSE.AllocationLength, &Irp->IoStatus.Information);
        break;
      }
      Srb->DataTransferLength = Irp->IoStatus.Information;
//      Srb->ScsiStatus = 0;
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      Irp->IoStatus.Status = status;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      break;
    case SCSIOP_READ:
    case SCSIOP_WRITE:
      if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
        KdPrint((__DRIVER_NAME "     Command = READ/WRITE\n"));

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
        ChildDeviceData->IrpAddedToList++;
      }
      else
      {
        XenVbd_PutIrpOnRing(Device, Irp);
        RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&ChildDeviceData->Ring, notify);
        if (notify)
          EvtChnInterface.Notify(EvtChnInterface.InterfaceHeader.Context,
            ChildDeviceData->EventChannel);
        //KdPrint((__DRIVER_NAME "     WdmIrpPreprocessSCSI (AddedToList = %d, RemovedFromList = %d, AddedToRing = %d, AddedToRingAtLastNotify = %d, AddedToRingAtLastInterrupt = %d, AddedToRingAtLastDpc = %d, RemovedFromRing = %d, IrpCompleted = %d)\n", ChildDeviceData->IrpAddedToList, ChildDeviceData->IrpRemovedFromList, ChildDeviceData->IrpAddedToRing, ChildDeviceData->IrpAddedToRingAtLastNotify, ChildDeviceData->IrpAddedToRingAtLastInterrupt, ChildDeviceData->IrpAddedToRingAtLastDpc, ChildDeviceData->IrpRemovedFromRing, ChildDeviceData->IrpCompleted));
      }
      KeReleaseSpinLock(&ChildDeviceData->Lock, KIrql);
      status = STATUS_PENDING;
      break;
    case SCSIOP_READ_TOC:
      DataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);
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
      Irp->IoStatus.Status = status;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      break;
/*
    case SCSIOP_GET_CONFIGURATION:
#define SCSI_GET_CONFIGURATION_REQUEST_TYPE_ALL     0x0
#define SCSI_GET_CONFIGURATION_REQUEST_TYPE_CURRENT 0x1
#define SCSI_GET_CONFIGURATION_REQUEST_TYPE_ONE     0x2

        UCHAR OperationCode;       // 0x46 - SCSIOP_GET_CONFIGURATION
        UCHAR RequestType : 2;     // SCSI_GET_CONFIGURATION_REQUEST_TYPE_*
        UCHAR Reserved1   : 6;     // includes obsolete LUN field
        UCHAR StartingFeature[2];
        UCHAR Reserved2[3];
        UCHAR AllocationLength[2];
        UCHAR Control;
      break;
*/     
    default:
      KdPrint((__DRIVER_NAME "     Unhandled EXECUTE_SCSI Command = %02X\n", Srb->Cdb[0]));
      Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
      Irp->IoStatus.Status = status;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      break;
    }
    //status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
    break;
  case SRB_FUNCTION_CLAIM_DEVICE:
//    if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
      KdPrint((__DRIVER_NAME "     SRB_FUNCTION_CLAIM_DEVICE\n"));
//    ObReferenceObject(WdfDeviceWdmGetDeviceObject(Device));
    Srb->DataBuffer = WdfDeviceWdmGetDeviceObject(Device);
//    Srb->DataBuffer = WdfDeviceWdmGetAttachedDevice(Device);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
    status = STATUS_SUCCESS;
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    break;
  case SRB_FUNCTION_IO_CONTROL:
//    if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
      KdPrint((__DRIVER_NAME "     SRB_FUNCTION_IO_CONTROL\n"));
    //status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    status = STATUS_NOT_IMPLEMENTED;
    //Irp->IoStatus.Status = status;
    //Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    break;
  case SRB_FUNCTION_FLUSH:
//    if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
      KdPrint((__DRIVER_NAME "     SRB_FUNCTION_FLUSH\n"));
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

//  if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
    KdPrint((__DRIVER_NAME " <-- WdmIrpPreprocessSCSI (AddedToList = %d, RemovedFromList = %d, AddedToRing = %d, AddedToRingAtLastNotify = %d, AddedToRingAtLastInterrupt = %d, RemovedFromRing = %d)\n", ChildDeviceData->IrpAddedToList, ChildDeviceData->IrpRemovedFromList, ChildDeviceData->IrpAddedToRing, ChildDeviceData->IrpAddedToRingAtLastNotify, ChildDeviceData->IrpAddedToRingAtLastInterrupt, ChildDeviceData->IrpCompleted));
  //KdPrint((__DRIVER_NAME " <-- WdmIrpPreprocessSCSI\n"));

  return status;
}

static VOID 
XenVbd_Child_IoDefault(WDFQUEUE  Queue, WDFREQUEST  Request)
{
  UNREFERENCED_PARAMETER(Queue);

  KdPrint((__DRIVER_NAME " --> EvtDeviceIoDefault\n"));

  WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);

  KdPrint((__DRIVER_NAME " <-- EvtDeviceIoDefault\n"));
}

static VOID 
XenVbd_Child_IoReadWrite(WDFQUEUE Queue, WDFREQUEST Request, size_t Length)
{
  UNREFERENCED_PARAMETER(Queue);
  UNREFERENCED_PARAMETER(Length);

  KdPrint((__DRIVER_NAME " --> IoReadWrite\n"));

  WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);

  KdPrint((__DRIVER_NAME " <-- IoReadWrite\n"));
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
  PSTORAGE_DEVICE_ID_DESCRIPTOR Sdid;
  PSTORAGE_IDENTIFIER Si;
  PSCSI_ADDRESS Sa;
  ULONG Information;
  //NTSTATUS Status;
  int StructEndOffset;

  UNREFERENCED_PARAMETER(Queue);
  //UNREFERENCED_PARAMETER(Request);
  UNREFERENCED_PARAMETER(OutputBufferLength);
  UNREFERENCED_PARAMETER(InputBufferLength);

  Device = WdfIoQueueGetDevice(Queue);

  ChildDeviceData = *GetChildDeviceData(Device);

//  if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
    KdPrint((__DRIVER_NAME " --> IoDeviceControl\n"));
  //KdPrint((__DRIVER_NAME "     InputBufferLength = %d\n", InputBufferLength));
  //KdPrint((__DRIVER_NAME "     OutputBufferLength = %d\n", OutputBufferLength));

  Irp = WdfRequestWdmGetIrp(Request);

  switch (IoControlCode)
  {
  case IOCTL_STORAGE_QUERY_PROPERTY:
    KdPrint((__DRIVER_NAME "     IOCTL_STORAGE_QUERY_PROPERTY\n"));    
    Spq = (PSTORAGE_PROPERTY_QUERY)Irp->AssociatedIrp.SystemBuffer;
    if (Spq->PropertyId == StorageAdapterProperty && Spq->QueryType == PropertyStandardQuery)
    {
      KdPrint((__DRIVER_NAME "     PropertyId = StorageAdapterProperty, QueryType = PropertyStandardQuery\n"));
      Information = 0;
      if (OutputBufferLength >= 8)
      {
        Information = 8;
        Sad = (PSTORAGE_ADAPTER_DESCRIPTOR)Irp->AssociatedIrp.SystemBuffer;
        Sad->Version = 1;
        Sad->Size = sizeof(STORAGE_ADAPTER_DESCRIPTOR);
        if (OutputBufferLength >= Sad->Size)
        {
          Information = Sad->Size;
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
      WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, Information);
    }
    else if (Spq->PropertyId == StorageDeviceProperty && Spq->QueryType == PropertyStandardQuery)
    {
      KdPrint((__DRIVER_NAME "     PropertyId = StorageDeviceProperty, QueryType = PropertyStandardQuery\n"));
      Information = 0;
      if (OutputBufferLength >= 8)
      {
        Information = 8;
        Sdd = (PSTORAGE_DEVICE_DESCRIPTOR)Irp->AssociatedIrp.SystemBuffer;
        Sdd->Version = 1;
        Sdd->Size = &Sdd->RawDeviceProperties[36] - (PUCHAR)Sdd + 1;
        // 0       0        1         2       3
        // 0       7        5         4       1
        //"VENDOR\0PRODUCT\0Revision\0Serial\0"
        if (OutputBufferLength >= Sdd->Size)
        {
          Information = Sdd->Size;
          switch (ChildDeviceData->DeviceType)
          { 
          case XENVBD_DEVICETYPE_DISK:
            Sdd->DeviceType = DIRECT_ACCESS_DEVICE;
            Sdd->DeviceTypeModifier = 0x00;
            Sdd->RemovableMedia = FALSE;
            break;
          case XENVBD_DEVICETYPE_CDROM:
            Sdd->DeviceType = READ_ONLY_DIRECT_ACCESS_DEVICE;
            Sdd->DeviceTypeModifier = 0x00;
            Sdd->RemovableMedia = TRUE;
            break;
          default:
            // wtf
            break;
          }
          Sdd->CommandQueueing = FALSE;
          StructEndOffset = Sdd->RawDeviceProperties - (PUCHAR)Sdd;
          Sdd->VendorIdOffset = StructEndOffset + 0;
          Sdd->ProductIdOffset = StructEndOffset + 7;
          Sdd->ProductRevisionOffset = StructEndOffset + 15;
          Sdd->SerialNumberOffset = StructEndOffset + 24;
          Sdd->BusType = BusTypeScsi;
          Sdd->RawPropertiesLength = 36;
          memcpy(Sdd->RawDeviceProperties, "VENDOR\0PRODUCT\0Revision\0Serial99999\0", 36);
        }
      }
      WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, Information);
    }
    else if (Spq->PropertyId == StorageDeviceIdProperty && Spq->QueryType == PropertyStandardQuery)
    {
      KdPrint((__DRIVER_NAME "     PropertyId = StorageDeviceIdProperty, QueryType = PropertyStandardQuery\n"));
      Information = 0;
      if (OutputBufferLength >= 8)
      {
        Information = 8;
        Sdid = (PSTORAGE_DEVICE_ID_DESCRIPTOR)Irp->AssociatedIrp.SystemBuffer;
        Sdid->Version = 1;
        Si = (PSTORAGE_IDENTIFIER)Sdid->Identifiers;
        Sdid->Size = &Si->Identifier[8] - (PUCHAR)Sdid + 1;
        if (OutputBufferLength >= Sdid->Size)
        {
          Information = Sdid->Size;
          Sdid->NumberOfIdentifiers = 1;
          Si->CodeSet = StorageIdCodeSetAscii;
          Si->Type = StorageIdTypeScsiNameString;
          //Si->CodeSet = StorageIdCodeSetBinary;
          //Si->Type = StorageIdTypeEUI64;
          Si->IdentifierSize = 9;
          Si->NextOffset = 0;
          Si->Association = StorageIdAssocPort;
          Si->Identifier[0] = 'S';
          Si->Identifier[1] = 'e';
          Si->Identifier[2] = 'r';
          Si->Identifier[3] = 'i';
          Si->Identifier[4] = 'a';
          Si->Identifier[5] = 'l';
          Si->Identifier[6] = '9';
          Si->Identifier[7] = '9';
          Si->Identifier[6] = '9';
          Si->Identifier[7] = '9';
          Si->Identifier[8] = '9';
          //Si->Identifier[8] = 0;
        }
      }
      WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, Information);
    }
    else
    {
      switch (Spq->PropertyId)
      {
      case StorageDeviceProperty:
        KdPrint((__DRIVER_NAME "     StorageDeviceProperty\n"));
        break;        
      case StorageAccessAlignmentProperty:
        KdPrint((__DRIVER_NAME "     StorageAccessAlignmentProperty\n"));
        break;
      case StorageAdapterProperty:
        KdPrint((__DRIVER_NAME "     StorageAdapterProperty\n"));
        break;
      case StorageDeviceIdProperty:
        KdPrint((__DRIVER_NAME "     StorageDeviceIdProperty\n"));
        break;
      case StorageDeviceUniqueIdProperty:
        KdPrint((__DRIVER_NAME "     StorageDeviceUniqueIdProperty\n"));
        break;
      case StorageDeviceWriteCacheProperty:
        KdPrint((__DRIVER_NAME "     StorageDeviceWriteCacheProperty\n"));
        break;
      default:
        KdPrint((__DRIVER_NAME "     Unknown Property %08x\n", Spq->PropertyId));
        break;
      }
      switch (Spq->QueryType)
      {
      case PropertyStandardQuery:
        KdPrint((__DRIVER_NAME "     PropertyStandardQuery\n"));
        break;        
      case PropertyExistsQuery:
        KdPrint((__DRIVER_NAME "     PropertyExistsQuery\n"));
        break;        
      default:
        KdPrint((__DRIVER_NAME "     Unknown Query %08x\n", Spq->QueryType));
        break;
      }
      WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);
    }
    break;
  // http://www.osronline.com/article.cfm?article=229
  // 0x00560030 device = 0x56, Function = 0x00c = 
  case IOCTL_DISK_GET_DRIVE_GEOMETRY:
    KdPrint((__DRIVER_NAME "     IOCTL_DISK_GET_DRIVE_GEOMETRY\n"));
    memcpy(Irp->AssociatedIrp.SystemBuffer, &ChildDeviceData->Geometry, sizeof(DISK_GEOMETRY));
    WdfRequestComplete(Request, STATUS_SUCCESS);
    break;
  case IOCTL_SCSI_GET_ADDRESS:
    KdPrint((__DRIVER_NAME "     IOCTL_SCSI_GET_ADDRESS\n"));
    Sa = (PSCSI_ADDRESS)Irp->AssociatedIrp.SystemBuffer;
    Sa->Length = sizeof(SCSI_ADDRESS);
    Sa->PortNumber = 0;
    Sa->PathId = 0;
    Sa->TargetId = 0;
    Sa->Lun = 0;
    WdfRequestComplete(Request, STATUS_SUCCESS);
    break;
  case FT_BALANCED_READ_MODE: // just pretend we know what this is...
    KdPrint((__DRIVER_NAME "     FT_BALANCED_READ_MODE\n"));
    WdfRequestComplete(Request, STATUS_SUCCESS);
    break;
  default:
    KdPrint((__DRIVER_NAME "     Not Implemented IoControlCode=%08X\n", IoControlCode));
    WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);
    break;
  }

//  if (ChildDeviceData->DeviceType == XENVBD_DEVICETYPE_CDROM)
    KdPrint((__DRIVER_NAME " <-- IoDeviceControl\n"));
}

static VOID 
XenVbd_Child_IoInternalDeviceControl(
  WDFQUEUE Queue,
  WDFREQUEST Request,
  size_t OutputBufferLength,
  size_t InputBufferLength,
  ULONG IoControlCode)
{
  UNREFERENCED_PARAMETER(Queue);
  UNREFERENCED_PARAMETER(Request);
  UNREFERENCED_PARAMETER(OutputBufferLength);
  UNREFERENCED_PARAMETER(InputBufferLength);
  UNREFERENCED_PARAMETER(IoControlCode);

  KdPrint((__DRIVER_NAME " --> IoInternalDeviceControl\n"));
  KdPrint((__DRIVER_NAME " <-- IoInternalDeviceControl\n"));
}
