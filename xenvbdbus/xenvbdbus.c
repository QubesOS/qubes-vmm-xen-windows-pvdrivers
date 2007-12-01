#include "xenvbdbus.h"
#include <io/blkif.h>
#include <srb.h>
#include <scsi.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <stdlib.h>
#include <xen_public.h>
#include <io/xenbus.h>
#include <ntddft.h>

#define wmb() KeMemoryBarrier()
#define mb() KeMemoryBarrier()

DRIVER_INITIALIZE DriverEntry;

/*static NTSTATUS
XenPCI_FilterAddResourceRequirements(WDFDEVICE Device, WDFIORESREQLIST RequirementsList);
static NTSTATUS
XenPCI_RemoveAddedResources(WDFDEVICE Device, WDFCMRESLIST ResourcesRaw, WDFCMRESLIST ResourcesTranslated);
*/
static NTSTATUS
XenVbdBus_AddDevice(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit);
static NTSTATUS
XenVbdBus_PrepareHardware(WDFDEVICE hDevice, WDFCMRESLIST Resources, WDFCMRESLIST ResourcesTranslated);
static NTSTATUS
XenVbdBus_ReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated);
static NTSTATUS
XenVbdBus_D0Entry(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState);
static NTSTATUS
XenVbdBus_D0EntryPostInterruptsEnabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState);
static NTSTATUS
XenVbdBus_D0Exit(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState);
static NTSTATUS
XenVbdBus_DeviceUsageNotification(WDFDEVICE Device, WDF_SPECIAL_FILE_TYPE NotificationType, BOOLEAN IsInNotificationPath);

static NTSTATUS
XenVbdBus_ChildListCreateDevice(WDFCHILDLIST ChildList, PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription, PWDFDEVICE_INIT ChildInit);
static NTSTATUS
XenVbdBus_DeviceResourceRequirementsQuery(WDFDEVICE Device, WDFIORESREQLIST IoResourceRequirementsList);

static VOID
XenVbdBus_HotPlugHandler(char *Path, PVOID Data);

static NTSTATUS
XenVbd_Child_PreprocessWdmIrpPnp(WDFDEVICE Device, PIRP Irp);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, XenVbdBus_AddDevice)
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

  WDF_DRIVER_CONFIG_INIT(&config, XenVbdBus_AddDevice);
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

DEFINE_GUID( GUID_XENPCI_DEVCLASS, 0xC828ABE9, 0x14CA, 0x4445, 0xBA, 0xA6, 0x82, 0xC2, 0x37, 0x6C, 0x65, 0x18);

static WDFDEVICE GlobalDevice;
static PDEVICE_OBJECT Pdo;

static NTSTATUS
XenVbdBus_AddDevice(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
{
  WDF_CHILD_LIST_CONFIG ChildListConfig;
  NTSTATUS status;
  WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
  PNP_BUS_INFORMATION BusInfo;
  
//  PWDF_FDO_EVENT_CALLBACKS FdoCallbacks;

  UNREFERENCED_PARAMETER(Driver);

  KdPrint((__DRIVER_NAME " --> DeviceAdd\n"));

  Pdo = WdfFdoInitWdmGetPhysicalDevice(DeviceInit);

  //WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);
  WDF_CHILD_LIST_CONFIG_INIT(&ChildListConfig, sizeof(XENVBDBUS_DEVICE_IDENTIFICATION_DESCRIPTION), XenVbdBus_ChildListCreateDevice);
  WdfFdoInitSetDefaultChildListConfig(DeviceInit, &ChildListConfig, WDF_NO_OBJECT_ATTRIBUTES);

  WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_CONTROLLER);
  //WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);
  WdfDeviceInitSetExclusive(DeviceInit, FALSE);

//  WDF_FDO_EVENT_CALLBACKS_INIT(&FdoCallbacks);
//  //FdoCallbacks.EvtDeviceFilterRemoveResourceRequirements = XenVbdBus_FilterRemoveResourceRequirements;
//  FdoCallbacks.EvtDeviceFilterAddResourceRequirements = XenVbdBus_FilterAddResourceRequirements;
//  FdoCallbacks.EvtDeviceRemoveAddedResources = XenVbdBus_RemoveAddedResources;
//  WdfFdoInitSetEventCallbacks(DeviceInit, &FdoCallbacks);

  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
  pnpPowerCallbacks.EvtDevicePrepareHardware = XenVbdBus_PrepareHardware;
  pnpPowerCallbacks.EvtDeviceReleaseHardware = XenVbdBus_ReleaseHardware;
  pnpPowerCallbacks.EvtDeviceD0Entry = XenVbdBus_D0Entry;
  pnpPowerCallbacks.EvtDeviceD0EntryPostInterruptsEnabled = XenVbdBus_D0EntryPostInterruptsEnabled;
  pnpPowerCallbacks.EvtDeviceD0Exit = XenVbdBus_D0Exit;
  pnpPowerCallbacks.EvtDeviceUsageNotification = XenVbdBus_DeviceUsageNotification;
  WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

  /*initialize storage for the device context*/
  //WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, XENVBDBUS_DEVICE_DATA);

  //WdfDeviceInitSetPowerNotPageable(DeviceInit);

  /*create a device instance.*/
  status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &GlobalDevice);  
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "WdfDeviceCreate failed with status 0x%08x\n", status));
    return status;
  }

  BusInfo.BusTypeGuid = GUID_XENPCI_DEVCLASS;
  BusInfo.LegacyBusType = Internal; //PNPBus;
  BusInfo.BusNumber = 0;

  WdfDeviceSetBusInformationForChildren(GlobalDevice, &BusInfo);

  WdfDeviceSetSpecialFileSupport(GlobalDevice, WdfSpecialFilePaging, TRUE);
  WdfDeviceSetSpecialFileSupport(GlobalDevice, WdfSpecialFileHibernation, TRUE);
  WdfDeviceSetSpecialFileSupport(GlobalDevice, WdfSpecialFileDump, TRUE);
  
  status = STATUS_SUCCESS;

  KdPrint((__DRIVER_NAME " <-- DeviceAdd\n"));
  return status;
}

static NTSTATUS
XenVbdBus_PrepareHardware(
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
XenVbdBus_ReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)
{
  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(ResourcesTranslated);

  // release interfaces here...

  //XenVbdBus_Close();

  return STATUS_SUCCESS;
}

static NTSTATUS
XenVbdBus_D0Entry(
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
XenVbdBus_D0EntryPostInterruptsEnabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)
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
  PdoDeviceData->WatchHandler = XenVbdBus_HotPlugHandler;

  EnumeratedDevices = 0;
  KeInitializeEvent(&WaitDevicesEvent, SynchronizationEvent, FALSE);  

  // TODO: Should probably do this in an EvtChildListScanForChildren
  if (AutoEnumerate)
  {
    msg = XenBusInterface.List(XBT_NIL, "device/vbd", &VbdDevices);
    if (!msg) {
      for (i = 0; VbdDevices[i]; i++)
      {
        KdPrint((__DRIVER_NAME "     found existing vbd device %s\n", VbdDevices[i]));
        RtlStringCbPrintfA(buffer, ARRAY_SIZE(buffer), "device/vbd/%s/state", VbdDevices[i]);
        XenVbdBus_HotPlugHandler(buffer, NULL);
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
XenVbdBus_D0Exit(
    IN WDFDEVICE Device,
    IN WDF_POWER_DEVICE_STATE  TargetState
    )
{
  NTSTATUS status = STATUS_SUCCESS;
  //char *response;

  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(TargetState);

  //KdPrint((__DRIVER_NAME " --> EvtDeviceD0Exit\n"));

  //response = XenBusInterface.RemWatch(XBT_NIL, XenBusInterface.InterfaceHeader.Context, XenVbdBus_HotPlugHandler, NULL);

  //KdPrint((__DRIVER_NAME " <-- EvtDeviceD0Exit\n"));

  return status;
}

static NTSTATUS
XenVbdBus_DeviceUsageNotification(WDFDEVICE Device, WDF_SPECIAL_FILE_TYPE NotificationType, BOOLEAN IsInNotificationPath)
{
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
XenVbdBus_IoDefault(
    IN WDFQUEUE  Queue,
    IN WDFREQUEST  Request
    )
{
  UNREFERENCED_PARAMETER(Queue);

  //KdPrint((__DRIVER_NAME " --> EvtDeviceIoDefault\n"));

  WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);

  //KdPrint((__DRIVER_NAME " <-- EvtDeviceIoDefault\n"));
}


static PMDL
AllocatePages(int Pages)
{
  PMDL Mdl;
  PVOID Buf;

  Buf = ExAllocatePoolWithTag(NonPagedPool, Pages * PAGE_SIZE, XENVBDBUS_POOL_TAG);
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
  ExFreePoolWithTag(Buf, XENVBDBUS_POOL_TAG);
}

static VOID
XenVbdBus_Notify(PVOID Data)
{
  PXENVBDBUS_CHILD_DEVICE_DATA ChildDeviceData;

  KdPrint((__DRIVER_NAME " --> XenVbdBus_Notify\n"));

  ChildDeviceData = (PXENVBDBUS_CHILD_DEVICE_DATA)Data;

  EvtChnInterface.Notify(ChildDeviceData->EventChannel);

  KdPrint((__DRIVER_NAME " <-- XenVbdBus_Notify\n"));
}

static BOOLEAN
XenVbdBus_Interrupt(PKINTERRUPT Interrupt, PVOID ServiceContext)
{
  PXENVBDBUS_CHILD_DEVICE_DATA ChildDeviceData;

  UNREFERENCED_PARAMETER(Interrupt);
  // !!!RUNS AT DIRQL!!!

  KdPrint((__DRIVER_NAME " --> XenVbdBus_Interrupt\n"));

  ChildDeviceData = (PXENVBDBUS_CHILD_DEVICE_DATA)ServiceContext;
  if (ChildDeviceData->ScsiDeviceData->IsrRoutine != NULL)
    ChildDeviceData->ScsiDeviceData->IsrRoutine(ChildDeviceData->ScsiDeviceData->IsrContext);
  else
    KdPrint((__DRIVER_NAME "     Isr Not Set\n"));  

  KdPrint((__DRIVER_NAME " <-- XenVbdBus_Interrupt\n"));

  return STATUS_SUCCESS;
}

static VOID
XenVbdBus_BackEndStateHandler(char *Path, PVOID Data)
{
  PXENVBDBUS_CHILD_DEVICE_DATA DeviceData;
  char TmpPath[128];
  char *Value;
  int NewState;
  grant_ref_t ref;
  blkif_sring_t *SharedRing;
  //ULONG PFN;
  XENVBDBUS_DEVICE_IDENTIFICATION_DESCRIPTION Description;
  NTSTATUS status;

  DeviceData = (PXENVBDBUS_CHILD_DEVICE_DATA)Data;

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

    // We create the Windows device node here
    WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(&Description.Header, sizeof(Description));
    Description.DeviceData = DeviceData;
    DeviceData->EventChannel = EvtChnInterface.AllocUnbound(0);
    EvtChnInterface.BindDpc(DeviceData->EventChannel, XenVbdBus_Interrupt, DeviceData);
    
    DeviceData->SharedRingMDL = AllocatePage();
    SharedRing = (blkif_sring_t *)MmGetMdlVirtualAddress(DeviceData->SharedRingMDL);
    SHARED_RING_INIT(SharedRing);

    DeviceData->ScsiDeviceDataMdl = AllocatePage();
    DeviceData->ScsiDeviceData = MmGetMdlVirtualAddress(DeviceData->ScsiDeviceDataMdl);

    DeviceData->ScsiDeviceData->Magic = SCSI_DATA_MAGIC;
    FRONT_RING_INIT(&DeviceData->ScsiDeviceData->Ring, SharedRing, PAGE_SIZE);
    ref = GntTblInterface.GrantAccess(0, *MmGetMdlPfnArray(DeviceData->SharedRingMDL), FALSE);
    DeviceData->ScsiDeviceData->NotifyContext = DeviceData;
    DeviceData->ScsiDeviceData->NotifyRoutine = XenVbdBus_Notify;
    DeviceData->ScsiDeviceData->GntTblInterface = GntTblInterface;

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

    RtlStringCbCopyA(TmpPath, 128, DeviceData->Path);
    RtlStringCbCatA(TmpPath, 128, "/device-type");
    XenBusInterface.Read(XBT_NIL, TmpPath, &Value);
    if (strcmp(Value, "disk") == 0)
    {
      KdPrint((__DRIVER_NAME "     DeviceType = Disk\n"));    
      DeviceData->ScsiDeviceData->DeviceType = XENVBD_DEVICETYPE_DISK;
    }
    else if (strcmp(Value, "cdrom") == 0)
    {
      KdPrint((__DRIVER_NAME "     DeviceType = CDROM\n"));    
      DeviceData->ScsiDeviceData->DeviceType = XENVBD_DEVICETYPE_CDROM;
    }
    else
    {
      KdPrint((__DRIVER_NAME "     DeviceType = %s (This probably won't work!)\n", Value));
    }

    RtlStringCbCopyA(TmpPath, 128, DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/type"); // should probably check that this is 'phy' or 'file' or at least not ''
    XenBusInterface.Read(XBT_NIL, TmpPath, &Value);
    KdPrint((__DRIVER_NAME "     Backend Type = %s\n", Value));

    RtlStringCbCopyA(TmpPath, 128, DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/mode"); // should store this...
    XenBusInterface.Read(XBT_NIL, TmpPath, &Value);
    KdPrint((__DRIVER_NAME "     Backend Mode = %s\n", Value));

    RtlStringCbCopyA(TmpPath, 128, DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/sector-size");
    XenBusInterface.Read(XBT_NIL, TmpPath, &Value);
    // should complain if Value == NULL
    DeviceData->ScsiDeviceData->BytesPerSector = atoi(Value);

    KdPrint((__DRIVER_NAME "     BytesPerSector = %d\n", DeviceData->ScsiDeviceData->BytesPerSector));    

    RtlStringCbCopyA(TmpPath, 128, DeviceData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/sectors");
    XenBusInterface.Read(XBT_NIL, TmpPath, &Value);
    // should complain if Value == NULL
    DeviceData->ScsiDeviceData->TotalSectors = (ULONGLONG)atol(Value);

    KdPrint((__DRIVER_NAME "     TotalSectors = %d\n", DeviceData->ScsiDeviceData->TotalSectors));    

/*
    // should probably use the partition table (if one exists) here for the sectorspertrack and trackspercylinder values
    DeviceData->Geometry.MediaType = FixedMedia;
    DeviceData->Geometry.BytesPerSector = DeviceData->BytesPerSector;
    DeviceData->Geometry.SectorsPerTrack = 63;
    DeviceData->Geometry.TracksPerCylinder = 255;
    DeviceData->Geometry.Cylinders.QuadPart = DeviceData->TotalSectors / DeviceData->Geometry.SectorsPerTrack / DeviceData->Geometry.TracksPerCylinder;
    KdPrint((__DRIVER_NAME "     Geometry C/H/S = %d/%d/%d\n", DeviceData->Geometry.Cylinders.LowPart, DeviceData->Geometry.TracksPerCylinder, DeviceData->Geometry.SectorsPerTrack));
*/
    // if we detected something wrong, we should not enumerate the device and should instead initiate a close

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
    KdPrint((__DRIVER_NAME "     Added a controller, notifying\n"));
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
XenVbdBus_HotPlugHandler(char *Path, PVOID Data)
{
  PXENVBDBUS_CHILD_DEVICE_DATA DeviceData;
  char **Bits;
  int Count;
  char TmpPath[128];
  char *Value;

  UNREFERENCED_PARAMETER(Data);  

  //KdPrint((__DRIVER_NAME " --> HotPlugHandler\n"));

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
    KdPrint((__DRIVER_NAME "     Bits[0] = %s\n", Bits[0]));
    KdPrint((__DRIVER_NAME "     Bits[1] = %s\n", Bits[1]));
    KdPrint((__DRIVER_NAME "     Bits[2] = %s\n", Bits[2]));
    for (DeviceData = (PXENVBDBUS_CHILD_DEVICE_DATA)DeviceListHead.Flink; DeviceData != (PXENVBDBUS_CHILD_DEVICE_DATA)&DeviceListHead; DeviceData = (PXENVBDBUS_CHILD_DEVICE_DATA)DeviceData->Entry.Flink)
    {

      KdPrint((__DRIVER_NAME "     Comparing '%s' and '%s'\n", DeviceData->Path, Path));
      if (strncmp(DeviceData->Path, Path, strlen(DeviceData->Path)) == 0 && Path[strlen(DeviceData->Path)] == '/')
      {
        KdPrint((__DRIVER_NAME "     Matched\n"));
        break;
      }
    }
    if (DeviceData == (PXENVBDBUS_CHILD_DEVICE_DATA)&DeviceListHead)
    {
      DeviceData = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENVBDBUS_CHILD_DEVICE_DATA), XENVBDBUS_POOL_TAG);
      memset(DeviceData, 0, sizeof(XENVBDBUS_CHILD_DEVICE_DATA));

      KdPrint((__DRIVER_NAME "     Allocated ChildDeviceData = %08x\n", DeviceData));
      
      RtlStringCbCopyA(DeviceData->Path, 128, Bits[0]);
      RtlStringCbCatA(DeviceData->Path, 128, "/");
      RtlStringCbCatA(DeviceData->Path, 128, Bits[1]);
      RtlStringCbCatA(DeviceData->Path, 128, "/");
      RtlStringCbCatA(DeviceData->Path, 128, Bits[2]);
      InsertTailList(&DeviceListHead, &DeviceData->Entry);

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
      XenBusInterface.AddWatch(XBT_NIL, TmpPath, XenVbdBus_BackEndStateHandler, DeviceData);
    }
    break;
  }
  
  FreeSplitString(Bits, Count);

  //KdPrint((__DRIVER_NAME " <-- HotPlugHandler\n"));  

  return;
}

static NTSTATUS
XenVbdBus_ChildListCreateDevice(WDFCHILDLIST ChildList, PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription, PWDFDEVICE_INIT ChildInit)
{
  NTSTATUS status;
  WDFDEVICE ChildDevice;
  PXENVBDBUS_DEVICE_IDENTIFICATION_DESCRIPTION XenVbdBusIdentificationDesc;
  DECLARE_UNICODE_STRING_SIZE(buffer, 50);
  WDF_OBJECT_ATTRIBUTES PdoAttributes;
  DECLARE_CONST_UNICODE_STRING(DeviceLocation, L"Xen Bus");
  PXENVBDBUS_CHILD_DEVICE_DATA ChildDeviceData;
  WDF_PDO_EVENT_CALLBACKS PdoCallbacks;
  UCHAR PnpMinors[2] = { IRP_MN_START_DEVICE, IRP_MN_STOP_DEVICE };

  UNREFERENCED_PARAMETER(ChildList);

  KdPrint((__DRIVER_NAME " --> ChildListCreateDevice\n"));

  XenVbdBusIdentificationDesc = CONTAINING_RECORD(IdentificationDescription, XENVBDBUS_DEVICE_IDENTIFICATION_DESCRIPTION, Header);

  ChildDeviceData = XenVbdBusIdentificationDesc->DeviceData;

  WdfDeviceInitSetDeviceType(ChildInit, FILE_DEVICE_CONTROLLER);

  status = RtlUnicodeStringPrintf(&buffer, L"XEN\\VBDDev\0");
  status = WdfPdoInitAssignDeviceID(ChildInit, &buffer);

  status = RtlUnicodeStringPrintf(&buffer, L"%02d\0", ChildDeviceData->DeviceIndex);
  status = WdfPdoInitAssignInstanceID(ChildInit, &buffer);

  status = RtlUnicodeStringPrintf(&buffer, L"XEN\\VBDDev\0");
  status = WdfPdoInitAddCompatibleID(ChildInit, &buffer);
  status = WdfPdoInitAddHardwareID(ChildInit, &buffer);

  //status = RtlUnicodeStringPrintf(&buffer, L"Xen PV Disk (%d)", ChildDeviceData->DeviceIndex);
  //status = WdfPdoInitAddDeviceText(ChildInit, &buffer, &DeviceLocation, 0x409);
  //WdfPdoInitSetDefaultLocale(ChildInit, 0x409);

  WDF_PDO_EVENT_CALLBACKS_INIT(&PdoCallbacks);
  PdoCallbacks.EvtDeviceResourceRequirementsQuery = XenVbdBus_DeviceResourceRequirementsQuery;
  WdfPdoInitSetEventCallbacks(ChildInit, &PdoCallbacks);

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&PdoAttributes, PXENVBDBUS_CHILD_DEVICE_DATA);

//  status = WdfDeviceInitAssignWdmIrpPreprocessCallback(ChildInit, XenVbd_Child_PreprocessWdmIrpPnp, IRP_MJ_PNP, PnpMinors, 2);
//  if (!NT_SUCCESS(status))
//    KdPrint((__DRIVER_NAME "     WdfDeviceInitAssignWdmIrpPreprocessCallback(IRP_MJ_PNP) status = %08X\n", status));

  status = WdfDeviceCreate(&ChildInit, &PdoAttributes, &ChildDevice);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreate status = %08X\n", status));
  }

  *GetChildDeviceData(ChildDevice) = ChildDeviceData;

  KdPrint((__DRIVER_NAME " <-- ChildListCreateDevice (status = %08x)\n", status));

  return status;
}

static NTSTATUS
XenVbd_Child_PreprocessWdmIrpPnp(WDFDEVICE Device, PIRP Irp)
{
  NTSTATUS Status;
  PIO_STACK_LOCATION IrpStackLocation;
  PCM_PARTIAL_RESOURCE_LIST PartialResourceList;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptor;
  int i;  

  KdPrint((__DRIVER_NAME " --> PreprocessWdmIrpPnp\n"));

  IrpStackLocation = IoGetCurrentIrpStackLocation(Irp);

  switch (IrpStackLocation->MinorFunction)
  {
  case IRP_MN_START_DEVICE:
    KdPrint((__DRIVER_NAME "     START_DEVICE\n"));
    PartialResourceList = &IrpStackLocation->Parameters.StartDevice.AllocatedResources->List[0].PartialResourceList;
    for (i = 0; i < PartialResourceList->Count; i++)
    {
      PartialDescriptor = &PartialResourceList->PartialDescriptors[i];
      switch (PartialDescriptor->Type)
      {
      case CmResourceTypeInterrupt:
        KdPrint((__DRIVER_NAME "     CmResourceTypeInterrupt\n"));
        KdPrint((__DRIVER_NAME "     Level = %d, Vector = %08x\n", PartialDescriptor->u.Interrupt.Level, PartialDescriptor->u.Interrupt.Vector));
        break;
      default:
        KdPrint((__DRIVER_NAME "     Other Resource %02X\n", PartialDescriptor->Type));
        break;
      }
    }
    PartialResourceList = &IrpStackLocation->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList;
    for (i = 0; i < PartialResourceList->Count; i++)
    {
      PartialDescriptor = &PartialResourceList->PartialDescriptors[i];
      switch (PartialDescriptor->Type)
      {
      case CmResourceTypeInterrupt:
        KdPrint((__DRIVER_NAME "     CmResourceTypeInterrupt\n"));
        KdPrint((__DRIVER_NAME "     Level = %d, Vector = %08x\n", PartialDescriptor->u.Interrupt.Level, PartialDescriptor->u.Interrupt.Vector));
        break;
      default:
        KdPrint((__DRIVER_NAME "     Other Resource %02X\n", PartialDescriptor->Type));
        break;
      }
    }
    break;
  case IRP_MN_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     STOP_DEVICE\n"));
    // Unbind the PIRQ here
    break;
  default:
    break;
  }

  IoSkipCurrentIrpStackLocation(Irp);

  Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);

  KdPrint((__DRIVER_NAME " <-- PreprocessWdmIrpPnp\n"));

  return Status;
}

static NTSTATUS
XenVbdBus_DeviceResourceRequirementsQuery(WDFDEVICE ChildDevice, WDFIORESREQLIST IoResourceRequirementsList)
{
  NTSTATUS  status = STATUS_SUCCESS;
  WDFIORESLIST resourceList;
  IO_RESOURCE_DESCRIPTOR descriptor;
  PXENVBDBUS_CHILD_DEVICE_DATA ChildDeviceData;

  ChildDeviceData = *GetChildDeviceData(ChildDevice);

  KdPrint((__DRIVER_NAME " --> DeviceResourceRequirementsQuery\n"));

  status = WdfIoResourceListCreate(IoResourceRequirementsList, WDF_NO_OBJECT_ATTRIBUTES, &resourceList);
  if (!NT_SUCCESS(status))
    return status;

  RtlZeroMemory(&descriptor, sizeof(descriptor));

  descriptor.Type = CmResourceTypeMemory;
  descriptor.ShareDisposition = CmResourceShareDeviceExclusive;
  descriptor.Flags = CM_RESOURCE_MEMORY_READ_WRITE;
  descriptor.u.Memory.Length = 0; //PAGE_SIZE;
  descriptor.u.Memory.Alignment = PAGE_SIZE;
  //descriptor.u.Memory.MinimumAddress.QuadPart = *MmGetMdlPfnArray(ChildDeviceData->ScsiDeviceDataMdl) << PAGE_SHIFT;
  descriptor.u.Memory.MinimumAddress.QuadPart = MmGetSystemAddressForMdlSafe(ChildDeviceData->ScsiDeviceDataMdl, NormalPagePriority);
  descriptor.u.Memory.MaximumAddress.QuadPart = descriptor.u.Memory.MinimumAddress.QuadPart;

  KdPrint((__DRIVER_NAME "     MinimumAddress = %08x, MaximumAddress = %08x\n", descriptor.u.Memory.MinimumAddress.LowPart, descriptor.u.Memory.MaximumAddress.LowPart));

  status = WdfIoResourceListAppendDescriptor(resourceList, &descriptor);
  if (!NT_SUCCESS(status))
    return status;
/*
  RtlZeroMemory(&descriptor, sizeof(descriptor));

  descriptor.Type = CmResourceTypeInterrupt;
  descriptor.ShareDisposition = CmResourceShareDeviceExclusive;
  descriptor.Flags = CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
  descriptor.u.Interrupt.MinimumVector = 16;
  descriptor.u.Interrupt.MaximumVector = 255;

  KdPrint((__DRIVER_NAME "     MinimumVector = %d, MaximumVector = %d\n", descriptor.u.Interrupt.MinimumVector, descriptor.u.Interrupt.MaximumVector));

  status = WdfIoResourceListAppendDescriptor(resourceList, &descriptor);
  if (!NT_SUCCESS(status))
    return status;
*/

  status = WdfIoResourceRequirementsListAppendIoResList(IoResourceRequirementsList, resourceList);
  if (!NT_SUCCESS(status))
  {
    return status;
  }

  KdPrint((__DRIVER_NAME " <-- DeviceResourceRequirementsQuery\n"));

  return status;
}
