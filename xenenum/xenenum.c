#include "xenenum.h"
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

static NTSTATUS
XenEnum_AddDevice(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit);
static NTSTATUS
XenEnum_PrepareHardware(WDFDEVICE hDevice, WDFCMRESLIST Resources, WDFCMRESLIST ResourcesTranslated);
static NTSTATUS
XenEnum_ReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated);
static NTSTATUS
XenEnum_D0Entry(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState);
static NTSTATUS
XenEnum_D0EntryPostInterruptsEnabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState);
static NTSTATUS
XenEnum_D0Exit(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState);
static NTSTATUS
XenEnum_DeviceUsageNotification(WDFDEVICE Device, WDF_SPECIAL_FILE_TYPE NotificationType, BOOLEAN IsInNotificationPath);

static NTSTATUS
XenEnum_ChildListCreateDevice(WDFCHILDLIST ChildList, PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription, PWDFDEVICE_INIT ChildInit);

static VOID
XenEnum_WatchHandler(char *Path, PVOID Data);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, XenEnum_AddDevice)
#endif

typedef struct {
  LIST_ENTRY DeviceListHead;
  XEN_IFACE XenInterface;
  PDEVICE_OBJECT Pdo;
  BOOLEAN AutoEnumerate;
  KGUARDED_MUTEX WatchHandlerMutex;
} XENENUM_DEVICE_DATA, *PXENENUM_DEVICE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(XENENUM_DEVICE_DATA, GetDeviceData);

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  WDF_DRIVER_CONFIG config;
  ULONG status;

  KdPrint((__DRIVER_NAME " --> DriverEntry\n"));

  WDF_DRIVER_CONFIG_INIT(&config, XenEnum_AddDevice);
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

  KdPrint((__DRIVER_NAME " <-- DriverEntry\n"));

  return status;
}

DEFINE_GUID( GUID_XENPCI_DEVCLASS, 0xC828ABE9, 0x14CA, 0x4445, 0xBA, 0xA6, 0x82, 0xC2, 0x37, 0x6C, 0x65, 0x18);

static NTSTATUS
XenEnum_AddDevice(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
{
  WDF_CHILD_LIST_CONFIG ChildListConfig;
  NTSTATUS status;
  WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
  PNP_BUS_INFORMATION BusInfo;
  WDFDEVICE Device;
  WDF_OBJECT_ATTRIBUTES attributes;
  PXENENUM_DEVICE_DATA xedd;
  PDEVICE_OBJECT Pdo;
  
  UNREFERENCED_PARAMETER(Driver);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  Pdo = WdfFdoInitWdmGetPhysicalDevice(DeviceInit);

  WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);
  WDF_CHILD_LIST_CONFIG_INIT(&ChildListConfig, sizeof(XENPCI_IDENTIFICATION_DESCRIPTION), XenEnum_ChildListCreateDevice);
  WdfFdoInitSetDefaultChildListConfig(DeviceInit, &ChildListConfig, WDF_NO_OBJECT_ATTRIBUTES);
  WdfDeviceInitSetExclusive(DeviceInit, FALSE);

  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
  pnpPowerCallbacks.EvtDevicePrepareHardware = XenEnum_PrepareHardware;
  pnpPowerCallbacks.EvtDeviceReleaseHardware = XenEnum_ReleaseHardware;
  pnpPowerCallbacks.EvtDeviceD0Entry = XenEnum_D0Entry;
  pnpPowerCallbacks.EvtDeviceD0EntryPostInterruptsEnabled = XenEnum_D0EntryPostInterruptsEnabled;
  pnpPowerCallbacks.EvtDeviceD0Exit = XenEnum_D0Exit;
  pnpPowerCallbacks.EvtDeviceUsageNotification = XenEnum_DeviceUsageNotification;
  WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, XENENUM_DEVICE_DATA);

  status = WdfDeviceCreate(&DeviceInit, &attributes, &Device);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "WdfDeviceCreate failed with status 0x%08x\n", status));
    return status;
  }

  xedd = GetDeviceData(Device);

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
  KeInitializeGuardedMutex(&xedd->WatchHandlerMutex);
#endif

  xedd->Pdo = Pdo;

  BusInfo.BusTypeGuid = GUID_XENPCI_DEVCLASS;
  BusInfo.LegacyBusType = Internal;
  BusInfo.BusNumber = 0;

  WdfDeviceSetBusInformationForChildren(Device, &BusInfo);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return status;
}

static NTSTATUS
XenEnum_PrepareHardware(
  IN WDFDEVICE    Device,
  IN WDFCMRESLIST ResourceList,
  IN WDFCMRESLIST ResourceListTranslated)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENENUM_DEVICE_DATA xedd = GetDeviceData(Device);

  UNREFERENCED_PARAMETER(ResourceList);
  UNREFERENCED_PARAMETER(ResourceListTranslated);

  KdPrint((__DRIVER_NAME " --> EvtDevicePrepareHardware\n"));

  status = WdfFdoQueryForInterface(Device, &GUID_XEN_IFACE, (PINTERFACE)&xedd->XenInterface, sizeof(XEN_IFACE), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfFdoQueryForInterface (EvtChn) failed with status 0x%08x\n", status));
  }

  InitializeListHead(&xedd->DeviceListHead);

  KdPrint((__DRIVER_NAME " <-- EvtDevicePrepareHardware\n"));

  return status;
}

static NTSTATUS
XenEnum_ReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)
{
  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(ResourcesTranslated);

  // release interfaces here...

  return STATUS_SUCCESS;
}

static NTSTATUS
XenEnum_D0Entry(
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

static NTSTATUS
XenEnum_D0EntryPostInterruptsEnabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_XEN_DEVICE_DATA PdoDeviceData;
  char **Devices;
  char *msg;
  char buffer[128];
  int i;
  PXENENUM_DEVICE_DATA xedd = GetDeviceData(Device);

  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(PreviousState);

  KdPrint((__DRIVER_NAME " --> EvtDeviceD0EntryPostInterruptsEnabled\n"));

  PdoDeviceData = (PXENPCI_XEN_DEVICE_DATA)xedd->Pdo->DeviceExtension; //GetXenDeviceData(Device);

  //KdPrint((__DRIVER_NAME "     Path = %s\n", PdoDeviceData->Path));
  PdoDeviceData->WatchHandler = XenEnum_WatchHandler;
  PdoDeviceData->WatchContext = Device;
  xedd->AutoEnumerate = PdoDeviceData->AutoEnumerate;

  // TODO: Should probably do this in an EvtChildListScanForChildren
  msg = xedd->XenInterface.XenBus_List(xedd->XenInterface.InterfaceHeader.Context, XBT_NIL, PdoDeviceData->Path, &Devices);
  if (!msg)
  {
    for (i = 0; Devices[i]; i++)
    {
      KdPrint((__DRIVER_NAME "     found existing device %s\n", Devices[i]));
      KdPrint((__DRIVER_NAME "     faking watch event for %s/%s", PdoDeviceData->Path, Devices[i]));
      RtlStringCbPrintfA(buffer, ARRAY_SIZE(buffer), "%s/%s", PdoDeviceData->Path, Devices[i]);
      XenEnum_WatchHandler(buffer, Device);
      //ExFreePoolWithTag(Devices[i], XENPCI_POOL_TAG);
    }
  }

  KdPrint((__DRIVER_NAME " <-- EvtDeviceD0EntryPostInterruptsEnabled\n"));

  return status;
}

static NTSTATUS
XenEnum_D0Exit(
    IN WDFDEVICE Device,
    IN WDF_POWER_DEVICE_STATE  TargetState
    )
{
  NTSTATUS status = STATUS_SUCCESS;
  //char *response;

  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(TargetState);

  //KdPrint((__DRIVER_NAME " --> EvtDeviceD0Exit\n"));

  //response = XenBusInterface.RemWatch(XBT_NIL, XenBusInterface.InterfaceHeader.Context, XenEnum_WatchHandler, NULL);

  //KdPrint((__DRIVER_NAME " <-- EvtDeviceD0Exit\n"));

  return status;
}

static NTSTATUS
XenEnum_DeviceUsageNotification(WDFDEVICE Device, WDF_SPECIAL_FILE_TYPE NotificationType, BOOLEAN IsInNotificationPath)
{
  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(IsInNotificationPath);

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
XenEnum_IoDefault(
    IN WDFQUEUE  Queue,
    IN WDFREQUEST  Request
    )
{
  UNREFERENCED_PARAMETER(Queue);

  //KdPrint((__DRIVER_NAME " --> EvtDeviceIoDefault\n"));

  WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);

  //KdPrint((__DRIVER_NAME " <-- EvtDeviceIoDefault\n"));
}

static VOID
XenEnum_WatchHandler(char *Path, PVOID Data)
{
  NTSTATUS Status;
  XENPCI_IDENTIFICATION_DESCRIPTION IdentificationDescription;
  char **Bits;
  int Count;
  WDFCHILDLIST ChildList;
  WDFDEVICE Device = Data;
  WDF_CHILD_LIST_ITERATOR ChildIterator;
  WDFDEVICE ChildDevice;
  PXENPCI_XEN_DEVICE_DATA ChildDeviceData;
// we only use this if we have guarded mutexes available
#if (NTDDI_VERSION >= NTDDI_WS03SP1)
  PXENENUM_DEVICE_DATA xedd = GetDeviceData(Device);
#endif

  UNREFERENCED_PARAMETER(Data);  

  KdPrint((__DRIVER_NAME " --> WatchHandler\n"));

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
  KeAcquireGuardedMutex(&xedd->WatchHandlerMutex);
#endif

  KdPrint((__DRIVER_NAME "     Path = %s\n", Path));

  Bits = SplitString(Path, '/', 4, &Count);
  if (Count == 3)
  {
    KdPrint((__DRIVER_NAME "     Creating %s\n", Bits[2]));
    ChildList = WdfFdoGetDefaultChildList(Device);
    RtlZeroMemory(&IdentificationDescription, sizeof(IdentificationDescription));
    WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(&IdentificationDescription.Header, sizeof(IdentificationDescription));
    strncpy(IdentificationDescription.Path, Path, 128);
    strncpy(IdentificationDescription.DeviceType, Bits[1], 128);
    strncat(IdentificationDescription.DeviceType, "dev", 128);
/*
    RtlInitAnsiString(&AnsiBuf, Bits[1]);
    RtlAnsiStringToUnicodeString(&IdentificationDescription.DeviceType, &AnsiBuf, TRUE);
*/
    IdentificationDescription.DeviceIndex = atoi(Bits[2]);
    Status = WdfChildListAddOrUpdateChildDescriptionAsPresent(ChildList, &IdentificationDescription.Header, NULL);
  }
  else if (Count > 3)
  {
    WDF_CHILD_LIST_ITERATOR_INIT(&ChildIterator, WdfRetrievePresentChildren);
    ChildList = WdfFdoGetDefaultChildList(Device);
    WdfChildListBeginIteration(ChildList, &ChildIterator);
    while (NT_SUCCESS(WdfChildListRetrieveNextDevice(ChildList, &ChildIterator, &ChildDevice, NULL)))
    {
      ChildDeviceData = GetXenDeviceData(ChildDevice);
      if (!ChildDeviceData)
      {
        KdPrint((__FUNCTION__ " No child device data, should never happen\n"));
        continue;
      }
      if (strncmp(ChildDeviceData->Path, Path, strlen(ChildDeviceData->Path)) == 0 && Path[strlen(ChildDeviceData->Path)] == '/')
      {
        KdPrint((__DRIVER_NAME "     Child Path = %s (Match - WatchHandler = %08x)\n", ChildDeviceData->Path, ChildDeviceData->WatchHandler));
        if (ChildDeviceData->WatchHandler != NULL)
          ChildDeviceData->WatchHandler(Path, ChildDeviceData->WatchContext);
      }
      else
      {
        //KdPrint((__DRIVER_NAME "     Child Path = %s (No Match)\n", ChildDeviceData->Path));
      }
    }
    WdfChildListEndIteration(ChildList, &ChildIterator);
  }
  FreeSplitString(Bits, Count);

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
  KeReleaseGuardedMutex(&xedd->WatchHandlerMutex);
#endif

  KdPrint((__DRIVER_NAME " <-- WatchHandler\n"));  

  return;
}

static NTSTATUS
XenEnum_ChildListCreateDevice(WDFCHILDLIST ChildList, PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription, PWDFDEVICE_INIT ChildInit)
{
  NTSTATUS status;
  WDFDEVICE ChildDevice;
  PXENPCI_IDENTIFICATION_DESCRIPTION XenIdentificationDesc;
  DECLARE_UNICODE_STRING_SIZE(buffer, 50);
  WDF_OBJECT_ATTRIBUTES PdoAttributes;
  DECLARE_CONST_UNICODE_STRING(DeviceLocation, L"Xen Bus");
  PXENPCI_XEN_DEVICE_DATA ChildDeviceData = NULL;
  WDF_QUERY_INTERFACE_CONFIG  qiConfig;
  PXENENUM_DEVICE_DATA xedd = GetDeviceData(WdfChildListGetDevice(ChildList));
  UNICODE_STRING DeviceType;
  ANSI_STRING AnsiBuf;

  UNREFERENCED_PARAMETER(ChildList);

  KdPrint((__DRIVER_NAME " --> ChildListCreateDevice\n"));

  XenIdentificationDesc = CONTAINING_RECORD(IdentificationDescription, XENPCI_IDENTIFICATION_DESCRIPTION, Header);

  RtlInitAnsiString(&AnsiBuf, XenIdentificationDesc->DeviceType);
  RtlAnsiStringToUnicodeString(&DeviceType, &AnsiBuf, TRUE);

  WdfDeviceInitSetDeviceType(ChildInit, FILE_DEVICE_UNKNOWN);

  status = RtlUnicodeStringPrintf(&buffer, L"XEN\\%wZ\0", &DeviceType);

  KdPrint((__DRIVER_NAME "     %ws", buffer.Buffer));

  status = WdfPdoInitAssignDeviceID(ChildInit, &buffer);
  status = WdfPdoInitAddCompatibleID(ChildInit, &buffer);
  status = WdfPdoInitAddHardwareID(ChildInit, &buffer);

  status = RtlUnicodeStringPrintf(&buffer, L"%02d\0", XenIdentificationDesc->DeviceIndex);
  status = WdfPdoInitAssignInstanceID(ChildInit, &buffer);

  status = RtlUnicodeStringPrintf(&buffer, L"Xen %wZ Device (%d)", &DeviceType, XenIdentificationDesc->DeviceIndex);
  status = WdfPdoInitAddDeviceText(ChildInit, &buffer, &DeviceLocation, 0x409);
  WdfPdoInitSetDefaultLocale(ChildInit, 0x409);

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&PdoAttributes, XENPCI_XEN_DEVICE_DATA);

  status = WdfDeviceCreate(&ChildInit, &PdoAttributes, &ChildDevice);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreate status = %08X\n", status));
  }

  WdfDeviceSetSpecialFileSupport(ChildDevice, WdfSpecialFilePaging, TRUE);
  WdfDeviceSetSpecialFileSupport(ChildDevice, WdfSpecialFileHibernation, TRUE);
  WdfDeviceSetSpecialFileSupport(ChildDevice, WdfSpecialFileDump, TRUE);

  ChildDeviceData = GetXenDeviceData(ChildDevice);
  ChildDeviceData->Magic = XEN_DATA_MAGIC;
  ChildDeviceData->AutoEnumerate = xedd->AutoEnumerate;
  ChildDeviceData->WatchHandler = NULL;
  strncpy(ChildDeviceData->Path, XenIdentificationDesc->Path, 128);
  
  ChildDeviceData->XenInterface.InterfaceHeader.Size = sizeof(ChildDeviceData->XenInterface);
  ChildDeviceData->XenInterface.InterfaceHeader.Version = 1;
  ChildDeviceData->XenInterface.InterfaceHeader.Context = xedd->XenInterface.InterfaceHeader.Context;
  ChildDeviceData->XenInterface.InterfaceHeader.InterfaceReference = WdfDeviceInterfaceReferenceNoOp;
  ChildDeviceData->XenInterface.InterfaceHeader.InterfaceDereference = WdfDeviceInterfaceDereferenceNoOp;

  ChildDeviceData->XenInterface.AllocMMIO = xedd->XenInterface.AllocMMIO;
  ChildDeviceData->XenInterface.FreeMem = xedd->XenInterface.FreeMem;

  ChildDeviceData->XenInterface.EvtChn_Bind = xedd->XenInterface.EvtChn_Bind;
  ChildDeviceData->XenInterface.EvtChn_Unbind = xedd->XenInterface.EvtChn_Unbind;
  ChildDeviceData->XenInterface.EvtChn_Mask = xedd->XenInterface.EvtChn_Mask;
  ChildDeviceData->XenInterface.EvtChn_Unmask = xedd->XenInterface.EvtChn_Unmask;
  ChildDeviceData->XenInterface.EvtChn_Notify = xedd->XenInterface.EvtChn_Notify;
  ChildDeviceData->XenInterface.EvtChn_AllocUnbound = xedd->XenInterface.EvtChn_AllocUnbound;
  ChildDeviceData->XenInterface.EvtChn_BindDpc = xedd->XenInterface.EvtChn_BindDpc;

  ChildDeviceData->XenInterface.GntTbl_GrantAccess = xedd->XenInterface.GntTbl_GrantAccess;
  ChildDeviceData->XenInterface.GntTbl_EndAccess = xedd->XenInterface.GntTbl_EndAccess;

  ChildDeviceData->XenInterface.XenBus_Read = xedd->XenInterface.XenBus_Read;
  ChildDeviceData->XenInterface.XenBus_Write = xedd->XenInterface.XenBus_Write;
  ChildDeviceData->XenInterface.XenBus_Printf = xedd->XenInterface.XenBus_Printf;
  ChildDeviceData->XenInterface.XenBus_StartTransaction = xedd->XenInterface.XenBus_StartTransaction;
  ChildDeviceData->XenInterface.XenBus_EndTransaction = xedd->XenInterface.XenBus_EndTransaction;
  ChildDeviceData->XenInterface.XenBus_List = xedd->XenInterface.XenBus_List;
  ChildDeviceData->XenInterface.XenBus_AddWatch = xedd->XenInterface.XenBus_AddWatch;
  ChildDeviceData->XenInterface.XenBus_RemWatch = xedd->XenInterface.XenBus_RemWatch;

  WDF_QUERY_INTERFACE_CONFIG_INIT(&qiConfig, (PINTERFACE)&ChildDeviceData->XenInterface, &GUID_XEN_IFACE, NULL);
  status = WdfDeviceAddQueryInterface(ChildDevice, &qiConfig);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  KdPrint((__DRIVER_NAME " <-- ChildListCreateDevice (status = %08x)\n", status));

  return status;
}
