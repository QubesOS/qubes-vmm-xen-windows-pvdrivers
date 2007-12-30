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

LIST_ENTRY DeviceListHead;
//XEN_IFACE_EVTCHN EvtChnInterface;
//XEN_IFACE_XENBUS XenBusInterface;
XEN_IFACE XenInterface;
//XEN_IFACE_GNTTBL GntTblInterface;

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
XenEnum_AddDevice(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
{
  WDF_CHILD_LIST_CONFIG ChildListConfig;
  NTSTATUS status;
  WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
  PNP_BUS_INFORMATION BusInfo;
  
  UNREFERENCED_PARAMETER(Driver);

  KdPrint((__DRIVER_NAME " --> DeviceAdd\n"));

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

  /*create a device instance.*/
  status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &GlobalDevice);  
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "WdfDeviceCreate failed with status 0x%08x\n", status));
    return status;
  }

  BusInfo.BusTypeGuid = GUID_XENPCI_DEVCLASS;
  BusInfo.LegacyBusType = Internal;
  BusInfo.BusNumber = 0;

  WdfDeviceSetBusInformationForChildren(GlobalDevice, &BusInfo);

/*
  WdfDeviceSetSpecialFileSupport(GlobalDevice, WdfSpecialFilePaging, TRUE);
  WdfDeviceSetSpecialFileSupport(GlobalDevice, WdfSpecialFileHibernation, TRUE);
  WdfDeviceSetSpecialFileSupport(GlobalDevice, WdfSpecialFileDump, TRUE);
*/

  status = STATUS_SUCCESS;

  KdPrint((__DRIVER_NAME " <-- DeviceAdd\n"));
  return status;
}

static NTSTATUS
XenEnum_PrepareHardware(
  IN WDFDEVICE    Device,
  IN WDFCMRESLIST ResourceList,
  IN WDFCMRESLIST ResourceListTranslated)
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(ResourceList);
  UNREFERENCED_PARAMETER(ResourceListTranslated);

  KdPrint((__DRIVER_NAME " --> EvtDevicePrepareHardware\n"));

  status = WdfFdoQueryForInterface(Device, &GUID_XEN_IFACE, (PINTERFACE)&XenInterface, sizeof(XEN_IFACE), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfFdoQueryForInterface (EvtChn) failed with status 0x%08x\n", status));
  }

  InitializeListHead(&DeviceListHead);

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

static int EnumeratedDevices;
static KEVENT WaitDevicesEvent;

static NTSTATUS
XenEnum_D0EntryPostInterruptsEnabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_XEN_DEVICE_DATA PdoDeviceData;
  char **Devices;
  char *msg;
  char buffer[128];
  int i;
  LARGE_INTEGER WaitTimeout;

  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(PreviousState);

  KdPrint((__DRIVER_NAME " --> EvtDeviceD0EntryPostInterruptsEnabled\n"));

  PdoDeviceData = (PXENPCI_XEN_DEVICE_DATA)Pdo->DeviceExtension; //GetXenDeviceData(Device);

  //KdPrint((__DRIVER_NAME "     Path = %s\n", PdoDeviceData->Path));
  PdoDeviceData->WatchHandler = XenEnum_WatchHandler;
  PdoDeviceData->WatchContext = Device;

  EnumeratedDevices = 0;
  KeInitializeEvent(&WaitDevicesEvent, SynchronizationEvent, FALSE);  

  // TODO: Should probably do this in an EvtChildListScanForChildren
  if (AutoEnumerate)
  {
    // TODO: Get the correct path from parent here...
    msg = XenInterface.XenBus_List(XenInterface.InterfaceHeader.Context, XBT_NIL, PdoDeviceData->Path, &Devices);
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
/*
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
*/
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
  char TmpPath[128];
  char *Value;
  ANSI_STRING AnsiBuf;
  WDFCHILDLIST ChildList;
  WDFDEVICE Device = Data;
  WDF_CHILD_LIST_ITERATOR ChildIterator;
  WDFDEVICE ChildDevice;
  PXENPCI_XEN_DEVICE_DATA ChildDeviceData;

  UNREFERENCED_PARAMETER(Data);  

  KdPrint((__DRIVER_NAME " --> WatchHandler\n"));

  KdPrint((__DRIVER_NAME "     Path = %s\n", Path));

  Bits = SplitString(Path, '/', 4, &Count);
  if (Count == 3)
  {
    KdPrint((__DRIVER_NAME "     Creating %s\n", Bits[2]));
    ChildList = WdfFdoGetDefaultChildList(Device);
    WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(&IdentificationDescription.Header, sizeof(IdentificationDescription));
    strncpy(IdentificationDescription.Path, Path, 128);
    RtlInitAnsiString(&AnsiBuf, Bits[1]);
    RtlAnsiStringToUnicodeString(&IdentificationDescription.DeviceType, &AnsiBuf, TRUE);
    IdentificationDescription.DeviceIndex = atoi(Bits[2]);
//    if (IdentificationDescription.DeviceIndex > 0)
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
//  WDF_PDO_EVENT_CALLBACKS PdoCallbacks;
//  UCHAR PnpMinors[2] = { IRP_MN_START_DEVICE, IRP_MN_STOP_DEVICE };

  UNREFERENCED_PARAMETER(ChildList);

  KdPrint((__DRIVER_NAME " --> ChildListCreateDevice\n"));

  XenIdentificationDesc = CONTAINING_RECORD(IdentificationDescription, XENPCI_IDENTIFICATION_DESCRIPTION, Header);

//  ChildDeviceData = XenEnumIdentificationDesc->DeviceData;

  WdfDeviceInitSetDeviceType(ChildInit, FILE_DEVICE_UNKNOWN);

  status = RtlUnicodeStringPrintf(&buffer, L"XEN\\%wsdev\0", XenIdentificationDesc->DeviceType.Buffer);

  KdPrint((__DRIVER_NAME "     %ws", buffer.Buffer));

  status = WdfPdoInitAssignDeviceID(ChildInit, &buffer);
  status = WdfPdoInitAddCompatibleID(ChildInit, &buffer);
  status = WdfPdoInitAddHardwareID(ChildInit, &buffer);

  status = RtlUnicodeStringPrintf(&buffer, L"%02d\0", XenIdentificationDesc->DeviceIndex);
  status = WdfPdoInitAssignInstanceID(ChildInit, &buffer);

  status = RtlUnicodeStringPrintf(&buffer, L"Xen %ws Device (%d)", XenIdentificationDesc->DeviceType.Buffer, XenIdentificationDesc->DeviceIndex);
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
  ChildDeviceData->AutoEnumerate = AutoEnumerate;
  ChildDeviceData->WatchHandler = NULL;
  strncpy(ChildDeviceData->Path, XenIdentificationDesc->Path, 128);
//  memcpy(&ChildDeviceData->InterruptRaw, &InterruptRaw, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
//  memcpy(&ChildDeviceData->InterruptTranslated, &InterruptTranslated, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
  
  ChildDeviceData->XenInterface.InterfaceHeader.Size = sizeof(ChildDeviceData->XenInterface);
  ChildDeviceData->XenInterface.InterfaceHeader.Version = 1;
  ChildDeviceData->XenInterface.InterfaceHeader.Context = XenInterface.InterfaceHeader.Context;
  ChildDeviceData->XenInterface.InterfaceHeader.InterfaceReference = WdfDeviceInterfaceReferenceNoOp;
  ChildDeviceData->XenInterface.InterfaceHeader.InterfaceDereference = WdfDeviceInterfaceDereferenceNoOp;

  ChildDeviceData->XenInterface.AllocMMIO = XenInterface.AllocMMIO;
  ChildDeviceData->XenInterface.FreeMem = XenInterface.FreeMem;

  ChildDeviceData->XenInterface.EvtChn_Bind = XenInterface.EvtChn_Bind;
  ChildDeviceData->XenInterface.EvtChn_Unbind = XenInterface.EvtChn_Unbind;
  ChildDeviceData->XenInterface.EvtChn_Mask = XenInterface.EvtChn_Mask;
  ChildDeviceData->XenInterface.EvtChn_Unmask = XenInterface.EvtChn_Unmask;
  ChildDeviceData->XenInterface.EvtChn_Notify = XenInterface.EvtChn_Notify;
  ChildDeviceData->XenInterface.EvtChn_AllocUnbound = XenInterface.EvtChn_AllocUnbound;
  ChildDeviceData->XenInterface.EvtChn_BindDpc = XenInterface.EvtChn_BindDpc;

  ChildDeviceData->XenInterface.GntTbl_GrantAccess = XenInterface.GntTbl_GrantAccess;
  ChildDeviceData->XenInterface.GntTbl_EndAccess = XenInterface.GntTbl_EndAccess;

  ChildDeviceData->XenInterface.XenBus_Read = XenInterface.XenBus_Read;
  ChildDeviceData->XenInterface.XenBus_Write = XenInterface.XenBus_Write;
  ChildDeviceData->XenInterface.XenBus_Printf = XenInterface.XenBus_Printf;
  ChildDeviceData->XenInterface.XenBus_StartTransaction = XenInterface.XenBus_StartTransaction;
  ChildDeviceData->XenInterface.XenBus_EndTransaction = XenInterface.XenBus_EndTransaction;
  ChildDeviceData->XenInterface.XenBus_List = XenInterface.XenBus_List;
  ChildDeviceData->XenInterface.XenBus_AddWatch = XenInterface.XenBus_AddWatch;
  ChildDeviceData->XenInterface.XenBus_RemWatch = XenInterface.XenBus_RemWatch;

  WDF_QUERY_INTERFACE_CONFIG_INIT(&qiConfig, (PINTERFACE)&ChildDeviceData->XenInterface, &GUID_XEN_IFACE, NULL);
  status = WdfDeviceAddQueryInterface(ChildDevice, &qiConfig);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  KdPrint((__DRIVER_NAME " <-- ChildListCreateDevice (status = %08x)\n", status));

  return status;
}
