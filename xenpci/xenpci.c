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

#if 0
#ifdef ALLOC_PRAGMA
DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text (INIT, DriverEntry)
#endif

#pragma warning(disable : 4200) // zero-sized array

static DDKAPI NTSTATUS
XenPci_Pnp(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_COMMON common = device_object->DeviceExtension;
  
  if (common->lower_do)
    status = XenPci_Pnp_Fdo(device_object, irp);
  else
    status = XenPci_Pnp_Pdo(device_object, irp);  

  return status;
}

static DDKAPI NTSTATUS
XenPci_Power(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_COMMON common = device_object->DeviceExtension;
  
  if (common->lower_do)
    status = XenPci_Power_Fdo(device_object, irp);
  else
    status = XenPci_Power_Pdo(device_object, irp);  

  return status;
}

static DDKAPI NTSTATUS
XenPci_Irp_Create(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_COMMON common = device_object->DeviceExtension;
  
  if (common->lower_do)
    status = XenPci_Irp_Create_Fdo(device_object, irp);
  else
    status = XenPci_Irp_Create_Pdo(device_object, irp);  

  return status;
}

static DDKAPI NTSTATUS
XenPci_Irp_Close(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_COMMON common = device_object->DeviceExtension;
  
  if (common->lower_do)
    status = XenPci_Irp_Close_Fdo(device_object, irp);
  else
    status = XenPci_Irp_Close_Pdo(device_object, irp);  

  return status;
}

static DDKAPI NTSTATUS
XenPci_Irp_Read(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_COMMON common = device_object->DeviceExtension;
  
  if (common->lower_do)
    status = XenPci_Irp_Read_Fdo(device_object, irp);
  else
    status = XenPci_Irp_Read_Pdo(device_object, irp);  

  return status;
}

static DDKAPI NTSTATUS
XenPci_Irp_Write(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_COMMON common = device_object->DeviceExtension;
  
  if (common->lower_do)
    status = XenPci_Irp_Write_Fdo(device_object, irp);
  else
    status = XenPci_Irp_Write_Pdo(device_object, irp);  

  return status;
}

static DDKAPI NTSTATUS
XenPci_Irp_Cleanup(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_COMMON common = device_object->DeviceExtension;
  
  if (common->lower_do)
    status = XenPci_Irp_Cleanup_Fdo(device_object, irp);
  else
    status = XenPci_Irp_Cleanup_Pdo(device_object, irp);  

  return status;
}

static DDKAPI NTSTATUS
XenPci_SystemControl(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_COMMON common = device_object->DeviceExtension;
  
  if (common->lower_do)
    status = XenPci_SystemControl_Fdo(device_object, irp);
  else
    status = XenPci_SystemControl_Pdo(device_object, irp);  

  return status;
}

static DDKAPI NTSTATUS
XenPci_Dummy(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PXENPCI_COMMON common = device_object->DeviceExtension;
  
  FUNCTION_ENTER();

  UNREFERENCED_PARAMETER(device_object);

  stack = IoGetCurrentIrpStackLocation(irp);
  KdPrint((__DRIVER_NAME "     Major = %d, Minor = %d\n", stack->MajorFunction, stack->MinorFunction));
  IoSkipCurrentIrpStackLocation(irp);
  status = IoCallDriver(common->lower_do, irp);

  FUNCTION_EXIT();
  
  return status;
}
#endif

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

#if 0
  xpdd->shutdown_prod = 0;
  xpdd->shutdown_cons = 0;
  KeInitializeSpinLock(&xpdd->shutdown_ring_lock);
#endif

  FUNCTION_EXIT();
  return status;
  
#if 0                                
  status = IoCreateDevice(DriverObject,
    sizeof(XENPCI_DEVICE_DATA),
    NULL,
    FILE_DEVICE_BUS_EXTENDER,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    &fdo);

  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     IoCreateDevice failed 0x%08x\n", status));
    return status;
  }

  fdo->Flags |= DO_BUFFERED_IO;
  
  xpdd = (PXENPCI_DEVICE_DATA)fdo->DeviceExtension;

  RtlZeroMemory(xpdd, sizeof(XENPCI_DEVICE_DATA));

  xpdd->shutdown_prod = 0;
  xpdd->shutdown_cons = 0;
  KeInitializeSpinLock(&xpdd->shutdown_ring_lock);

  xpdd->common.fdo = fdo;
  xpdd->common.pdo = PhysicalDeviceObject;
  xpdd->common.lower_do = IoAttachDeviceToDeviceStack(fdo, PhysicalDeviceObject);
  if(xpdd->common.lower_do == NULL) {
    IoDeleteDevice(fdo);
    return STATUS_NO_SUCH_DEVICE;
  }
  INIT_PNP_STATE(&xpdd->common);
  xpdd->common.device_usage_paging = 0;
  xpdd->common.device_usage_dump = 0;
  xpdd->common.device_usage_hibernation = 0;

  InitializeListHead(&xpdd->child_list);

  RtlInitUnicodeString(&reference, L"legacy");
  status = IoRegisterDeviceInterface(
    PhysicalDeviceObject,
    &GUID_XEN_IFACE,
    &reference,
    &xpdd->legacy_interface_name);

  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     IoRegisterDeviceInterface(GUID_XEN_IFACE) failed with status 0x%08x\n", status));
  }
  else
  {
    KdPrint((__DRIVER_NAME "     IoRegisterDeviceInterface(GUID_XEN_IFACE) succeeded - %wZ\n", &xpdd->legacy_interface_name));
  }

  RtlInitUnicodeString(&reference, L"xenbus");
  status = IoRegisterDeviceInterface(
    PhysicalDeviceObject,
    &GUID_XENBUS_IFACE,
    &reference,
    &xpdd->interface_name);

  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     IoRegisterDeviceInterface(GUID_XENBUS_IFACE) failed with status 0x%08x\n", status));
  }
  else
  {
    KdPrint((__DRIVER_NAME "     IoRegisterDeviceInterface(GUID_XENBUS_IFACE) succeeded - %wZ\n", &xpdd->interface_name));
  }

  fdo->Flags &= ~DO_DEVICE_INITIALIZING;

  FUNCTION_EXIT();
  return status;
#endif
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

  WDF_DRIVER_CONFIG_INIT(&config, XenPci_EvtDeviceAdd);
  status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);

  if (!NT_SUCCESS(status)) {
    KdPrint( ("WdfDriverCreate failed with status 0x%x\n", status));
  }

#if 0
  DriverObject->DriverExtension->AddDevice = XenPci_AddDevice;
  DriverObject->MajorFunction[IRP_MJ_PNP] = XenPci_Pnp;
  DriverObject->MajorFunction[IRP_MJ_POWER] = XenPci_Power;
  DriverObject->MajorFunction[IRP_MJ_CREATE] = XenPci_Irp_Create;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = XenPci_Irp_Close;
  DriverObject->MajorFunction[IRP_MJ_CLEANUP] = XenPci_Irp_Cleanup;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = XenPci_Dummy;
  DriverObject->MajorFunction[IRP_MJ_READ] = XenPci_Irp_Read;
  DriverObject->MajorFunction[IRP_MJ_WRITE] = XenPci_Irp_Write;
  DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = XenPci_SystemControl;
#endif

  FUNCTION_EXIT();

  return status;
}
