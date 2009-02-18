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
  
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&device_attributes, XENPCI_DEVICE_DATA);
  status = WdfDeviceCreate(&device_init, &device_attributes, &device);
  if (!NT_SUCCESS(status)) {
      KdPrint(("Error creating device 0x%x\n", status));
      return status;
  }

  xpdd = GetXpdd(device);

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

  UNREFERENCED_PARAMETER(RegistryPath);

  FUNCTION_ENTER();

  //TestStuff();  
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
    KdPrint((__DRIVER_NAME "     PV Devices InActive\n"));
  
  WDF_DRIVER_CONFIG_INIT(&config, XenPci_EvtDeviceAdd);
  status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);

  if (!NT_SUCCESS(status)) {
    KdPrint( ("WdfDriverCreate failed with status 0x%x\n", status));
  }

  FUNCTION_EXIT();

  return status;
}
