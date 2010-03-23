/*
PV Drivers for Windows Xen HVM Domains
Copyright (C) 2007 James Harper

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#define INITGUID
#include "xenpci.h"
#include <aux_klib.h>
#include <stdlib.h>

#define SYSRQ_PATH "control/sysrq"
#define SHUTDOWN_PATH "control/shutdown"
#define BALLOON_PATH "memory/target"

#pragma warning(disable : 4200) // zero-sized array

/* Not really necessary but keeps PREfast happy */
DRIVER_INITIALIZE DriverEntry;
static EVT_WDF_DRIVER_DEVICE_ADD XenPci_EvtDeviceAdd;
static EVT_WDF_DEVICE_USAGE_NOTIFICATION XenPci_EvtDeviceUsageNotification;
static EVT_WDF_DEVICE_PREPARE_HARDWARE XenHide_EvtDevicePrepareHardware;

static VOID
XenPci_EvtDeviceUsageNotification(WDFDEVICE device, WDF_SPECIAL_FILE_TYPE notification_type, BOOLEAN is_in_notification_path)
{
  FUNCTION_ENTER();
  
  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(is_in_notification_path);

  switch (notification_type)
  {
  case WdfSpecialFilePaging:
    KdPrint((__DRIVER_NAME "     notification_type = Paging, flag = %d\n", is_in_notification_path));
    break;
  case WdfSpecialFileHibernation:
    KdPrint((__DRIVER_NAME "     notification_type = Hibernation, flag = %d\n", is_in_notification_path));
    break;
  case WdfSpecialFileDump:
    KdPrint((__DRIVER_NAME "     notification_type = Dump, flag = %d\n", is_in_notification_path));
    break;
  default:
    KdPrint((__DRIVER_NAME "     notification_type = %d, flag = %d\n", notification_type, is_in_notification_path));
    break;
  }

  FUNCTION_EXIT();  
}

static NTSTATUS
XenPci_EvtDeviceAdd_XenPci(WDFDRIVER driver, PWDFDEVICE_INIT device_init)
{
  NTSTATUS status;
//  PDEVICE_OBJECT fdo = NULL;
//  PNP_BUS_INFORMATION busInfo;
//  DECLARE_CONST_UNICODE_STRING(DeviceName, L"\\Device\\XenShutdown");
//  DECLARE_CONST_UNICODE_STRING(SymbolicName, L"\\DosDevices\\XenShutdown");
  WDF_CHILD_LIST_CONFIG child_list_config;
  WDFDEVICE device;
  PXENPCI_DEVICE_DATA xpdd;
  UNICODE_STRING reference;
  WDF_OBJECT_ATTRIBUTES device_attributes;
  PNP_BUS_INFORMATION pbi;
  WDF_PNPPOWER_EVENT_CALLBACKS pnp_power_callbacks;
  WDF_INTERRUPT_CONFIG interrupt_config;
  WDF_OBJECT_ATTRIBUTES file_attributes;
  WDF_FILEOBJECT_CONFIG file_config;
  WDF_IO_QUEUE_CONFIG queue_config;
  WDFCOLLECTION veto_devices;
  WDFKEY param_key;
  DECLARE_CONST_UNICODE_STRING(veto_devices_name, L"veto_devices");
  WDF_DEVICE_POWER_CAPABILITIES power_capabilities;
  int i;
  
  UNREFERENCED_PARAMETER(driver);

  FUNCTION_ENTER();

  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp_power_callbacks);
  pnp_power_callbacks.EvtDeviceD0Entry = XenPci_EvtDeviceD0Entry;
  pnp_power_callbacks.EvtDeviceD0EntryPostInterruptsEnabled = XenPci_EvtDeviceD0EntryPostInterruptsEnabled;
  pnp_power_callbacks.EvtDeviceD0Exit = XenPci_EvtDeviceD0Exit;
  pnp_power_callbacks.EvtDeviceD0ExitPreInterruptsDisabled = XenPci_EvtDeviceD0ExitPreInterruptsDisabled;
  pnp_power_callbacks.EvtDevicePrepareHardware = XenPci_EvtDevicePrepareHardware;
  pnp_power_callbacks.EvtDeviceReleaseHardware = XenPci_EvtDeviceReleaseHardware;
  pnp_power_callbacks.EvtDeviceQueryRemove = XenPci_EvtDeviceQueryRemove;
  pnp_power_callbacks.EvtDeviceUsageNotification = XenPci_EvtDeviceUsageNotification;

  WdfDeviceInitSetPnpPowerEventCallbacks(device_init, &pnp_power_callbacks);

  WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_BUS_EXTENDER);
  WdfDeviceInitSetExclusive(device_init, FALSE);

  WDF_CHILD_LIST_CONFIG_INIT(&child_list_config, sizeof(XENPCI_PDO_IDENTIFICATION_DESCRIPTION), XenPci_EvtChildListCreateDevice);
  child_list_config.EvtChildListScanForChildren = XenPci_EvtChildListScanForChildren;
  WdfFdoInitSetDefaultChildListConfig(device_init, &child_list_config, WDF_NO_OBJECT_ATTRIBUTES);

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&file_attributes, XENPCI_DEVICE_INTERFACE_DATA);
  WDF_FILEOBJECT_CONFIG_INIT(&file_config, XenPci_EvtDeviceFileCreate, XenPci_EvtFileClose, XenPci_EvtFileCleanup);
  WdfDeviceInitSetFileObjectConfig(device_init, &file_config, &file_attributes);
  
  WdfDeviceInitSetIoType(device_init, WdfDeviceIoBuffered);

  WdfDeviceInitSetPowerNotPageable(device_init);
  
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&device_attributes, XENPCI_DEVICE_DATA);
  status = WdfDeviceCreate(&device_init, &device_attributes, &device);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Error creating device %08x\n", status));
    return status;
  }

  xpdd = GetXpdd(device);
  xpdd->wdf_device = device;
  xpdd->child_list = WdfFdoGetDefaultChildList(device);

  WdfCollectionCreate(WDF_NO_OBJECT_ATTRIBUTES, &veto_devices);
  status = WdfDriverOpenParametersRegistryKey(driver, KEY_QUERY_VALUE, WDF_NO_OBJECT_ATTRIBUTES, &param_key);
  if (NT_SUCCESS(status))
  {
    status = WdfRegistryQueryMultiString(param_key, &veto_devices_name, WDF_NO_OBJECT_ATTRIBUTES, veto_devices);
    if (!NT_SUCCESS(status))
    {
      KdPrint(("Error reading parameters/veto_devices value %08x\n", status));
    }
    WdfRegistryClose(param_key);
  }
  else
  {
    KdPrint(("Error opening parameters key %08x\n", status));
  }

  InitializeListHead(&xpdd->veto_list);
  for (i = 0; i < (int)WdfCollectionGetCount(veto_devices); i++)
  {
    WDFOBJECT ws;
    UNICODE_STRING val;
    ANSI_STRING s;
    PVOID entry;
    ws = WdfCollectionGetItem(veto_devices, i);
    WdfStringGetUnicodeString(ws, &val);
    RtlUnicodeStringToAnsiString(&s, &val, TRUE);
    entry = ExAllocatePoolWithTag(NonPagedPool, sizeof(LIST_ENTRY) + s.Length + 1, XENPCI_POOL_TAG);
    memcpy((PUCHAR)entry + sizeof(LIST_ENTRY), s.Buffer, s.Length + 1);
    RtlFreeAnsiString(&s);
    InsertTailList(&xpdd->veto_list, (PLIST_ENTRY)entry);
  }
  WDF_DEVICE_POWER_CAPABILITIES_INIT(&power_capabilities);
  power_capabilities.DeviceD1 = WdfTrue;
  power_capabilities.WakeFromD1 = WdfTrue;
  power_capabilities.DeviceWake = PowerDeviceD1;
  power_capabilities.DeviceState[PowerSystemWorking]   = PowerDeviceD1;
  power_capabilities.DeviceState[PowerSystemSleeping1] = PowerDeviceD1;
  power_capabilities.DeviceState[PowerSystemSleeping2] = PowerDeviceD2;
  power_capabilities.DeviceState[PowerSystemSleeping3] = PowerDeviceD2;
  power_capabilities.DeviceState[PowerSystemHibernate] = PowerDeviceD3;
  power_capabilities.DeviceState[PowerSystemShutdown]  = PowerDeviceD3;
  WdfDeviceSetPowerCapabilities(device, &power_capabilities);  

  WdfDeviceSetSpecialFileSupport(device, WdfSpecialFilePaging, TRUE);
  WdfDeviceSetSpecialFileSupport(device, WdfSpecialFileHibernation, TRUE);
  WdfDeviceSetSpecialFileSupport(device, WdfSpecialFileDump, TRUE);

  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config, WdfIoQueueDispatchParallel);
  queue_config.EvtIoDefault = XenPci_EvtIoDefault;
  status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, &xpdd->io_queue);
  if (!NT_SUCCESS(status)) {
      KdPrint(("Error creating queue 0x%x\n", status));
      return status;
  }
  
  WDF_INTERRUPT_CONFIG_INIT(&interrupt_config, EvtChn_EvtInterruptIsr, NULL);
  interrupt_config.EvtInterruptEnable  = EvtChn_EvtInterruptEnable;
  interrupt_config.EvtInterruptDisable = EvtChn_EvtInterruptDisable;

  status = WdfInterruptCreate(device, &interrupt_config, WDF_NO_OBJECT_ATTRIBUTES, &xpdd->interrupt);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Error creating interrupt 0x%x\n", status));
    return status;
  }
  
  RtlInitUnicodeString(&reference, L"xenbus");
  status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_XENBUS, &reference);
  if (!NT_SUCCESS(status)) {
      KdPrint(("Error registering device interface 0x%x\n", status));
      return status;
  }

  RtlInitUnicodeString(&reference, L"evtchn");
  status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_EVTCHN, &reference);
  if (!NT_SUCCESS(status)) {
      KdPrint(("Error registering device interface 0x%x\n", status));
      return status;
  }

  RtlInitUnicodeString(&reference, L"gntdev");
  status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_GNTDEV, &reference);
  if (!NT_SUCCESS(status)) {
      KdPrint(("Error registering device interface 0x%x\n", status));
      return status;
  }

  pbi.BusTypeGuid = GUID_BUS_TYPE_XEN;
  pbi.LegacyBusType = PNPBus;
  pbi.BusNumber = 0;
  WdfDeviceSetBusInformationForChildren(device, &pbi);

  xpdd->removable = TRUE;

  FUNCTION_EXIT();
  return status;
}

NTSTATUS
XenHide_EvtDevicePrepareHardware(WDFDEVICE device, WDFCMRESLIST resources_raw, WDFCMRESLIST resources_translated)
{
  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(resources_raw);
  UNREFERENCED_PARAMETER(resources_translated);
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return STATUS_UNSUCCESSFUL;
}

static BOOLEAN
XenPci_IdSuffixMatches(PWDFDEVICE_INIT device_init, PWCHAR matching_id)
{
  NTSTATUS status;
  WDFMEMORY memory;
  ULONG remaining;
  size_t string_length;
  PWCHAR ids;
  PWCHAR ptr;
  size_t ids_length;
  ULONG properties[] = {DevicePropertyCompatibleIDs, DevicePropertyHardwareID};
  int i;
  
//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  for (i = 0; i < ARRAY_SIZE(properties); i++)
  {

    status = WdfFdoInitAllocAndQueryProperty(device_init, properties[i], NonPagedPool, WDF_NO_OBJECT_ATTRIBUTES, &memory);
    if (!NT_SUCCESS(status))
      continue;
    ids = WdfMemoryGetBuffer(memory, &ids_length);

    if (!NT_SUCCESS(status))
    {
//      KdPrint((__DRIVER_NAME "     i = %d, status = %x, ids_length = %d\n", i, status, ids_length));
      continue;
    }
    
    remaining = (ULONG)ids_length / 2;
    for (ptr = ids; *ptr != 0; ptr += string_length + 1)
    {
      RtlStringCchLengthW(ptr, remaining, &string_length);
      remaining -= (ULONG)string_length + 1;
      if (string_length >= wcslen(matching_id))
      {
        ptr += string_length - wcslen(matching_id);
        string_length = wcslen(matching_id);
      }
//      KdPrint((__DRIVER_NAME "     Comparing '%S' and '%S'\n", ptr, matching_id));
      if (wcscmp(ptr, matching_id) == 0)
      {
        //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (Match)\n"));
        WdfObjectDelete(memory);
        return TRUE;
      }
    }
    WdfObjectDelete(memory);
  }
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (No match)\n"));
  return FALSE;
}

WDFCOLLECTION qemu_hide_devices;
USHORT qemu_hide_flags_value;

static NTSTATUS
XenPci_EvtDeviceAdd_XenHide(WDFDRIVER driver, PWDFDEVICE_INIT device_init)
{
  NTSTATUS status;
  WDFMEMORY memory;
  PWCHAR device_description;
  WDF_PNPPOWER_EVENT_CALLBACKS pnp_power_callbacks;
  WDF_OBJECT_ATTRIBUTES device_attributes;
  BOOLEAN hide_required = FALSE;
  WDFDEVICE device;
  ULONG i;

  UNREFERENCED_PARAMETER(driver);

  FUNCTION_ENTER();

  status = WdfFdoInitAllocAndQueryProperty(device_init, DevicePropertyDeviceDescription, NonPagedPool, WDF_NO_OBJECT_ATTRIBUTES, &memory);
  if (NT_SUCCESS(status))
  {
    device_description = WdfMemoryGetBuffer(memory, NULL);
  }
  else
  {
    device_description = L"<unknown device>";
  }

  for (i = 0; i < WdfCollectionGetCount(qemu_hide_devices); i++)
  {
    WDFSTRING wdf_string = WdfCollectionGetItem(qemu_hide_devices, i);
    UNICODE_STRING unicode_string;
    WdfStringGetUnicodeString(wdf_string, &unicode_string);
    if (XenPci_IdSuffixMatches(device_init, unicode_string.Buffer))
    {
      hide_required = TRUE;
      break;
    }
  }
  if (!hide_required)
  {
    WdfObjectDelete(memory);
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (filter not required for %S)\n", device_description));
    return STATUS_SUCCESS;
  }
  
  KdPrint((__DRIVER_NAME "     Installing Filter for %S\n", device_description));

  WdfFdoInitSetFilter(device_init);
  WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_UNKNOWN);
  WdfDeviceInitSetExclusive(device_init, FALSE);

  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp_power_callbacks);
  pnp_power_callbacks.EvtDevicePrepareHardware = XenHide_EvtDevicePrepareHardware;
  WdfDeviceInitSetPnpPowerEventCallbacks(device_init, &pnp_power_callbacks);
  
  WDF_OBJECT_ATTRIBUTES_INIT(&device_attributes);
  status = WdfDeviceCreate(&device_init, &device_attributes, &device);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Error creating device %08x\n", status));
    WdfObjectDelete(memory);
    FUNCTION_EXIT();
    return status;
  }

  WdfObjectDelete(memory);
  FUNCTION_EXIT();

  return status;
}

static NTSTATUS
XenPci_EvtDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT device_init)
{
  if (XenPci_IdSuffixMatches(device_init, L"VEN_5853&DEV_0001"))
  {
    KdPrint((__DRIVER_NAME "     Xen PCI device found - must be fdo\n"));
    return XenPci_EvtDeviceAdd_XenPci(driver, device_init);
  }
  else if (WdfCollectionGetCount(qemu_hide_devices) > 0)
  {
    KdPrint((__DRIVER_NAME "     Xen PCI device not found - must be filter\n"));
    return XenPci_EvtDeviceAdd_XenHide(driver, device_init);  
  }
  else
    return STATUS_SUCCESS;
}

ULONG qemu_protocol_version;
ULONG tpr_patch_requested;
extern PULONG InitSafeBootMode;

VOID
XenPci_HideQemuDevices()
{
  WRITE_PORT_USHORT(XEN_IOPORT_DEVICE_MASK, (USHORT)qemu_hide_flags_value); //QEMU_UNPLUG_ALL_IDE_DISKS|QEMU_UNPLUG_ALL_NICS);
  KdPrint((__DRIVER_NAME "     Disabled qemu devices\n"));\
}

static BOOLEAN
XenPci_CheckHideQemuDevices()
{
  if (READ_PORT_USHORT(XEN_IOPORT_MAGIC) == 0x49d2)
  {
    qemu_protocol_version = READ_PORT_UCHAR(XEN_IOPORT_VERSION);
    KdPrint((__DRIVER_NAME "     Version = %d\n", qemu_protocol_version));
    switch(qemu_protocol_version)
    {
    case 1:
      WRITE_PORT_USHORT(XEN_IOPORT_PRODUCT, XEN_PV_PRODUCT_NUMBER);
      WRITE_PORT_ULONG(XEN_IOPORT_BUILD, XEN_PV_PRODUCT_BUILD);
      if (READ_PORT_USHORT(XEN_IOPORT_MAGIC) != 0x49d2)
      {
        KdPrint((__DRIVER_NAME "     Blacklisted\n"));
        break;
      }
      /* fall through */
    case 0:
      return TRUE;
    default:
      KdPrint((__DRIVER_NAME "     Unknown qemu version %d\n", qemu_protocol_version));
      break;
    }
  }
  return FALSE;
}

/*
make sure the load order is System Reserved, Dummy Group, WdfLoadGroup, XenPCI, Boot Bus Extender
*/

static VOID
XenPci_FixLoadOrder()
{
  NTSTATUS status;
  WDFCOLLECTION old_load_order, new_load_order;
  DECLARE_CONST_UNICODE_STRING(sgo_name, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\ServiceGroupOrder");
  DECLARE_CONST_UNICODE_STRING(list_name, L"List");
  WDFKEY sgo_key;
  ULONG i;
  LONG dummy_group_index = -1;
  LONG boot_bus_extender_index = -1;
  LONG xenpci_group_index = -1;
  LONG wdf_load_group_index = -1;
  DECLARE_CONST_UNICODE_STRING(dummy_group_name, L"Dummy Group");
  DECLARE_CONST_UNICODE_STRING(wdf_load_group_name, L"WdfLoadGroup");
  DECLARE_CONST_UNICODE_STRING(xenpci_group_name, L"XenPCI Group");
  DECLARE_CONST_UNICODE_STRING(boot_bus_extender_name, L"Boot Bus Extender");

  FUNCTION_ENTER();
  
  status = WdfRegistryOpenKey(NULL, &sgo_name, KEY_QUERY_VALUE, WDF_NO_OBJECT_ATTRIBUTES, &sgo_key);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     Error opening ServiceGroupOrder key %08x\n", status));
    return;
  }
  WdfCollectionCreate(WDF_NO_OBJECT_ATTRIBUTES, &old_load_order);
  WdfCollectionCreate(WDF_NO_OBJECT_ATTRIBUTES, &new_load_order);  
  status = WdfRegistryQueryMultiString(sgo_key, &list_name, WDF_NO_OBJECT_ATTRIBUTES, old_load_order);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     Error reading ServiceGroupOrder\\List value %08x\n", status));
    WdfObjectDelete(new_load_order);
    WdfObjectDelete(old_load_order);
    return;
  }
  //KdPrint((__DRIVER_NAME "     Current Order:\n"));        
  for (i = 0; i < WdfCollectionGetCount(old_load_order); i++)
  {
    WDFOBJECT ws = WdfCollectionGetItem(old_load_order, i);
    UNICODE_STRING val;
    WdfStringGetUnicodeString(ws, &val);
    if (!RtlCompareUnicodeString(&val, &dummy_group_name, TRUE))
      dummy_group_index = (ULONG)i;
    if (!RtlCompareUnicodeString(&val, &wdf_load_group_name, TRUE))
      wdf_load_group_index = (ULONG)i;         
    if (!RtlCompareUnicodeString(&val, &xenpci_group_name, TRUE))
      xenpci_group_index = (ULONG)i;         
    if (!RtlCompareUnicodeString(&val, &boot_bus_extender_name, TRUE))
      boot_bus_extender_index = (ULONG)i;         
    //KdPrint((__DRIVER_NAME "       %wZ\n", &val));        
  }
  KdPrint((__DRIVER_NAME "     dummy_group_index = %d\n", dummy_group_index));
  KdPrint((__DRIVER_NAME "     wdf_load_group_index = %d\n", wdf_load_group_index));
  KdPrint((__DRIVER_NAME "     xenpci_group_index = %d\n", xenpci_group_index));
  KdPrint((__DRIVER_NAME "     boot_bus_extender_index = %d\n", boot_bus_extender_index));
  if (boot_bus_extender_index == -1)
  {
    WdfObjectDelete(new_load_order);
    WdfObjectDelete(old_load_order);
    WdfRegistryClose(sgo_key);
    return; /* something is very wrong */
  }
  if (dummy_group_index == 1 && (wdf_load_group_index == -1 || 
    (dummy_group_index < wdf_load_group_index
    && wdf_load_group_index < xenpci_group_index
    && xenpci_group_index < boot_bus_extender_index)))
  {
    return; /* our work here is done */
  }
  for (i = 0; i < WdfCollectionGetCount(old_load_order); i++)
  {
    WDFOBJECT ws;
    if (i == 1)
    {
      WDFSTRING tmp_wdf_string;
      WdfStringCreate(&dummy_group_name, WDF_NO_OBJECT_ATTRIBUTES, &tmp_wdf_string);
      WdfCollectionAdd(new_load_order, tmp_wdf_string);
      WdfObjectDelete(tmp_wdf_string);
    }
    if (i == 1 && wdf_load_group_index != -1)
    {
      WDFSTRING tmp_wdf_string;
      WdfStringCreate(&wdf_load_group_name, WDF_NO_OBJECT_ATTRIBUTES, &tmp_wdf_string);
      WdfCollectionAdd(new_load_order, tmp_wdf_string);
      WdfObjectDelete(tmp_wdf_string);
    }
    if (i == 1)
    {
      WDFSTRING tmp_wdf_string;
      WdfStringCreate(&xenpci_group_name, WDF_NO_OBJECT_ATTRIBUTES, &tmp_wdf_string);
      WdfCollectionAdd(new_load_order, tmp_wdf_string);
      WdfObjectDelete(tmp_wdf_string);
    }
    if (i == (ULONG)dummy_group_index || i == (ULONG)wdf_load_group_index || i == (ULONG)xenpci_group_index)
      continue;
    ws = WdfCollectionGetItem(old_load_order, i);
    WdfCollectionAdd(new_load_order, ws);
  }
  WdfRegistryAssignMultiString(sgo_key, &list_name, new_load_order);
  //KdPrint((__DRIVER_NAME "     New Order:\n"));        
  for (i = 0; i < WdfCollectionGetCount(new_load_order); i++)
  {
    WDFOBJECT ws = WdfCollectionGetItem(new_load_order, i);
    UNICODE_STRING val;
    WdfStringGetUnicodeString(ws, &val);
    //KdPrint((__DRIVER_NAME "       %wZ\n", &val));        
  }
  WdfObjectDelete(new_load_order);
  WdfObjectDelete(old_load_order);
  WdfRegistryClose(sgo_key);
  
  FUNCTION_EXIT();
  
  return;
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  NTSTATUS status = STATUS_SUCCESS;
  WDF_DRIVER_CONFIG config;
  WDFDRIVER driver;
  PCONFIGURATION_INFORMATION conf_info;
  WCHAR *SystemStartOptions;
  UNICODE_STRING RegKeyName;
  UNICODE_STRING RegValueName;
  HANDLE RegHandle;
  OBJECT_ATTRIBUTES RegObjectAttributes;
  char Buf[300];// Sometimes bigger then 200 if system reboot from crash
  ULONG BufLen = 300;
  PKEY_VALUE_PARTIAL_INFORMATION KeyPartialValue;
  WDFKEY param_key;
  
  UNREFERENCED_PARAMETER(RegistryPath);

  KdPrint((__DRIVER_NAME " " VER_FILEVERSION_STR "\n"));

  FUNCTION_ENTER();

  status = AuxKlibInitialize();
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     AuxKlibInitialize failed %08x - expect a crash soon\n", status));
  }
  
  #if DBG
  XenPci_HookDbgPrint();
  #endif

  XenPci_FixLoadOrder();

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
  else
    ZwClose(RegHandle);
  KeyPartialValue = (PKEY_VALUE_PARTIAL_INFORMATION)Buf;
  SystemStartOptions = (WCHAR *)KeyPartialValue->Data;

  KdPrint((__DRIVER_NAME "     SystemStartOptions = %S\n", SystemStartOptions));
  
  if (wcsstr(SystemStartOptions, L"PATCHTPR"))
  {
    WDFKEY memory_key;
    UNICODE_STRING verifier_key_name;
    UNICODE_STRING verifier_value_name;
    ULONG verifier_value;
    
    KdPrint((__DRIVER_NAME "     PATCHTPR found\n"));
    
    RtlInitUnicodeString(&verifier_key_name, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management");
    status = WdfRegistryOpenKey(NULL, &verifier_key_name, KEY_READ, WDF_NO_OBJECT_ATTRIBUTES, &memory_key);
    if (!NT_SUCCESS(status))
    {
      tpr_patch_requested = TRUE;
    }  
    else
    {
      RtlInitUnicodeString(&verifier_value_name, L"VerifyDriverLevel");
      status = WdfRegistryQueryULong(memory_key, &verifier_value_name, &verifier_value);
      if (NT_SUCCESS(status) && verifier_value != 0)
      {
        KdPrint((__DRIVER_NAME "     Verifier active - not patching\n"));
      }
      else
      {
        tpr_patch_requested = TRUE;
      }
      WdfRegistryClose(memory_key);
    }
  }
  
  WDF_DRIVER_CONFIG_INIT(&config, XenPci_EvtDeviceAdd);
  status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);

  WdfCollectionCreate(WDF_NO_OBJECT_ATTRIBUTES, &qemu_hide_devices);

  if (!NT_SUCCESS(status)) {
    KdPrint((__DRIVER_NAME "     WdfDriverCreate failed with status 0x%x\n", status));
    FUNCTION_EXIT();
    return status;
  }

  qemu_hide_flags_value = 0;

  if (wcsstr(SystemStartOptions, L"NOGPLPV"))
    KdPrint((__DRIVER_NAME "     NOGPLPV found\n"));
  conf_info = IoGetConfigurationInformation();
  
  status = WdfDriverOpenParametersRegistryKey(driver, KEY_QUERY_VALUE, WDF_NO_OBJECT_ATTRIBUTES, &param_key);
  if (NT_SUCCESS(status))
  {
    ULONG always_hide = 0;
    DECLARE_CONST_UNICODE_STRING(always_hide_name, L"hide_qemu_always");
    
    WdfRegistryQueryULong(param_key, &always_hide_name, &always_hide);
    if (always_hide || ((conf_info == NULL || conf_info->DiskCount == 0)
        && !wcsstr(SystemStartOptions, L"NOGPLPV")
        && !*InitSafeBootMode))
    {
      if (wcsstr(SystemStartOptions, L"GPLPVUSEFILTERHIDE") == 0 && XenPci_CheckHideQemuDevices())
      {
        DECLARE_CONST_UNICODE_STRING(qemu_hide_flags_name, L"qemu_hide_flags");
        WDFCOLLECTION qemu_hide_flags;
        ULONG i;
        
        WdfCollectionCreate(WDF_NO_OBJECT_ATTRIBUTES, &qemu_hide_flags);
        status = WdfRegistryQueryMultiString(param_key, &qemu_hide_flags_name, WDF_NO_OBJECT_ATTRIBUTES, qemu_hide_flags);
        if (!NT_SUCCESS(status))
        {
          KdPrint(("Error reading parameters/qemu_hide_flags value %08x\n", status));
        }
        else
        {
          for (i = 0; i < WdfCollectionGetCount(qemu_hide_flags); i++)
          {
            ULONG value;
            WDFSTRING wdf_string = WdfCollectionGetItem(qemu_hide_flags, i);
            UNICODE_STRING unicode_string;
            WdfStringGetUnicodeString(wdf_string, &unicode_string);
            KdPrint(("\n", status));
            status = RtlUnicodeStringToInteger(&unicode_string, 0, &value);
            qemu_hide_flags_value |= value;
          }
        }
        XenPci_HideQemuDevices();
      }
      else
      {
        DECLARE_CONST_UNICODE_STRING(hide_devices_name, L"hide_devices");
        status = WdfRegistryQueryMultiString(param_key, &hide_devices_name, WDF_NO_OBJECT_ATTRIBUTES, qemu_hide_devices);
        if (!NT_SUCCESS(status))
        {
          KdPrint(("Error reading parameters/hide_devices value %08x\n", status));
        }
      }
    }
    WdfRegistryClose(param_key);
  }
  else
  {
    KdPrint(("Error opening parameters key %08x\n", status));
  }

  FUNCTION_EXIT();

  return STATUS_SUCCESS;
}
