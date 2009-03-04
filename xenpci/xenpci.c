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
#include <stdlib.h>

#define SYSRQ_PATH "control/sysrq"
#define SHUTDOWN_PATH "control/shutdown"
#define BALLOON_PATH "memory/target"

#pragma warning(disable : 4200) // zero-sized array

static VOID
XenPci_EvtDeviceUsageNotification(WDFDEVICE device, WDF_SPECIAL_FILE_TYPE notification_type, BOOLEAN is_in_notification_path)
{
  FUNCTION_ENTER();
  
  UNREFERENCED_PARAMETER(device);

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
XenPci_EvtDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT device_init)
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
  WDFKEY param_key;
  DECLARE_CONST_UNICODE_STRING(veto_devices_name, L"veto_devices");
  WDF_DEVICE_POWER_CAPABILITIES power_capabilities;
  
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

  WdfCollectionCreate(WDF_NO_OBJECT_ATTRIBUTES, &xpdd->veto_devices);
  status = WdfDriverOpenParametersRegistryKey(driver, KEY_QUERY_VALUE, WDF_NO_OBJECT_ATTRIBUTES, &param_key);
  if (NT_SUCCESS(status))
  {
    status = WdfRegistryQueryMultiString(param_key, &veto_devices_name, WDF_NO_OBJECT_ATTRIBUTES, xpdd->veto_devices);
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
  queue_config.EvtIoRead = XenPci_EvtIoRead;
  queue_config.EvtIoWrite = XenPci_EvtIoWrite;
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

  pbi.BusTypeGuid = GUID_BUS_TYPE_XEN;
  pbi.LegacyBusType = PNPBus;
  pbi.BusNumber = 0;
  WdfDeviceSetBusInformationForChildren(device, &pbi);

  xpdd->removable = TRUE;

  FUNCTION_EXIT();
  return status;
}

ULONG qemu_filtered;
ULONG qemu_filtered_by_qemu;
ULONG qemu_protocol_version;
ULONG tpr_patch_requested;
extern PULONG InitSafeBootMode;

VOID
XenPci_HideQemuDevices()
{
  qemu_filtered_by_qemu = FALSE;
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
      qemu_filtered = TRUE;
      qemu_filtered_by_qemu = TRUE;
      WRITE_PORT_USHORT(XEN_IOPORT_DEVICE_MASK, QEMU_UNPLUG_ALL_IDE_DISKS|QEMU_UNPLUG_ALL_NICS);
      KdPrint((__DRIVER_NAME "     Disabled qemu devices\n"));
      break;
    default:
      KdPrint((__DRIVER_NAME "     Unknown qemu version %d\n", qemu_protocol_version));
      break;
    }
  }
}

/*
make sure the load order is System Reserved, Dummy Group, WdfLoadGroup, Boot Bus Extender
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
  LONG wdf_load_group_index = -1;
  DECLARE_CONST_UNICODE_STRING(dummy_group_name, L"Dummy Group");
  DECLARE_CONST_UNICODE_STRING(wdf_load_group_name, L"WdfLoadGroup");
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
  KdPrint((__DRIVER_NAME "     Current Order:\n"));        
  for (i = 0; i < WdfCollectionGetCount(old_load_order); i++)
  {
    WDFOBJECT ws = WdfCollectionGetItem(old_load_order, i);
    UNICODE_STRING val;
    WdfStringGetUnicodeString(ws, &val);
    if (!RtlCompareUnicodeString(&val, &dummy_group_name, TRUE))
      dummy_group_index = (ULONG)i;
    if (!RtlCompareUnicodeString(&val, &wdf_load_group_name, TRUE))
      wdf_load_group_index = (ULONG)i;         
    if (!RtlCompareUnicodeString(&val, &boot_bus_extender_name, TRUE))
      boot_bus_extender_index = (ULONG)i;         
    KdPrint((__DRIVER_NAME "       %wZ\n", &val));        
  }
  KdPrint((__DRIVER_NAME "     dummy_group_index = %d\n", dummy_group_index));
  KdPrint((__DRIVER_NAME "     wdf_load_group_index = %d\n", wdf_load_group_index));
  KdPrint((__DRIVER_NAME "     boot_bus_extender_index = %d\n", boot_bus_extender_index));
  if (boot_bus_extender_index == -1)
  {
    WdfObjectDelete(new_load_order);
    WdfObjectDelete(old_load_order);
    WdfRegistryClose(sgo_key);
    return; /* something is very wrong */
  }
  if (dummy_group_index == 1 && (wdf_load_group_index == -1 || (wdf_load_group_index > dummy_group_index && wdf_load_group_index < boot_bus_extender_index)))
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
    if (i == (ULONG)dummy_group_index || i == (ULONG)wdf_load_group_index)
      continue;
    ws = WdfCollectionGetItem(old_load_order, i);
    WdfCollectionAdd(new_load_order, ws);
  }
  WdfRegistryAssignMultiString(sgo_key, &list_name, new_load_order);
  KdPrint((__DRIVER_NAME "     New Order:\n"));        
  for (i = 0; i < WdfCollectionGetCount(new_load_order); i++)
  {
    WDFOBJECT ws = WdfCollectionGetItem(new_load_order, i);
    UNICODE_STRING val;
    WdfStringGetUnicodeString(ws, &val);
    KdPrint((__DRIVER_NAME "       %wZ\n", &val));        
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
#if 0
  WDF_TIMER_CONFIG  timer_config;
  OBJECT_ATTRIBUTES timer_attributes;
#endif

  UNREFERENCED_PARAMETER(RegistryPath);

  FUNCTION_ENTER();
  
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
    KdPrint((__DRIVER_NAME "     PATCHTPR found\n"));
    tpr_patch_requested = TRUE;
  }
  
  if (wcsstr(SystemStartOptions, L"NOGPLPV"))
    KdPrint((__DRIVER_NAME "     NOGPLPV found\n"));
  conf_info = IoGetConfigurationInformation();
  if ((conf_info == NULL || conf_info->DiskCount == 0)
      && !wcsstr(SystemStartOptions, L"NOGPLPV")
      && !*InitSafeBootMode)
  {
    /* see if the qemu method of disabling the PCI devices exists */
    XenPci_HideQemuDevices();
    /* if not, tell the filter to deny the pci devices their resources */
    if (!qemu_filtered)
    {
      OBJECT_ATTRIBUTES oa;
      UNICODE_STRING dir_name;
      NTSTATUS status;
      HANDLE handle;
      
      KdPrint((__DRIVER_NAME "     Adding DirectoryObject\n"));
      RtlInitUnicodeString(&dir_name, L"\\NEED_GPLPV_FILTER");
      InitializeObjectAttributes(&oa, &dir_name, OBJ_KERNEL_HANDLE, NULL, NULL);
      status = ZwCreateDirectoryObject(&handle, DIRECTORY_CREATE_OBJECT, &oa);
      KdPrint((__DRIVER_NAME "     ZwCreateDirectoryObject = %08x\n", status));
      if (!NT_SUCCESS(status))
      {
        return status;
      }
      qemu_filtered = TRUE;
    }
  }
  
  if (qemu_filtered)
    KdPrint((__DRIVER_NAME "     PV Devices Active\n"));
  else
    KdPrint((__DRIVER_NAME "     PV Devices Inactive\n"));
  
  WDF_DRIVER_CONFIG_INIT(&config, XenPci_EvtDeviceAdd);
  status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);

  if (!NT_SUCCESS(status)) {
    KdPrint((__DRIVER_NAME "     WdfDriverCreate failed with status 0x%x\n", status));
  }

  FUNCTION_EXIT();

  return status;
}
