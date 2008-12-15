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

static DDKAPI NTSTATUS
XenPci_AddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject)
{
  NTSTATUS status;
  PDEVICE_OBJECT fdo = NULL;
//  PNP_BUS_INFORMATION busInfo;
//  DECLARE_CONST_UNICODE_STRING(DeviceName, L"\\Device\\XenShutdown");
//  DECLARE_CONST_UNICODE_STRING(SymbolicName, L"\\DosDevices\\XenShutdown");
//  WDFDEVICE Device;
  PXENPCI_DEVICE_DATA xpdd;
  //PWSTR InterfaceList;

  FUNCTION_ENTER();

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

  status = IoRegisterDeviceInterface(
    PhysicalDeviceObject,
    &GUID_XEN_IFACE,
    NULL,
    &xpdd->interface_name);

  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     IoRegisterDeviceInterface failed with status 0x%08x\n", status));
  }
  else
  {
    KdPrint((__DRIVER_NAME "     IoRegisterDeviceInterface succeeded - %wZ\n", &xpdd->interface_name));
  }
  
  fdo->Flags &= ~DO_DEVICE_INITIALIZING;

  FUNCTION_EXIT();
  return status;
}
//DECLARE_UNICODE_STRING_SIZE(service_path, 512);

#define XEN_GLOBAL_IOPORT_PORT_BASE 0x10

ULONG need_gplpv_filter;
extern PULONG InitSafeBootMode;

NTSTATUS DDKAPI
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  NTSTATUS status = STATUS_SUCCESS;
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

  KdPrint((__DRIVER_NAME "     SystemStartOptions = %s\n", SystemStartOptions));
  if (wcsstr(SystemStartOptions, L"NOGPLPV"))
    KdPrint((__DRIVER_NAME "     NOGPLPV found\n"));
  conf_info = IoGetConfigurationInformation();
  if ((conf_info == NULL || conf_info->DiskCount == 0)
      && !wcsstr(SystemStartOptions, L"NOGPLPV")
      && !*InitSafeBootMode)
  {
    /* see if the qemu method of disabling the PCI devices exists */
    if (READ_PORT_UCHAR((PUCHAR)UlongToPtr(XEN_GLOBAL_IOPORT_PORT_BASE + 0)) == 'X'
        && READ_PORT_UCHAR((PUCHAR)UlongToPtr(XEN_GLOBAL_IOPORT_PORT_BASE + 1)) == 'E'
        && READ_PORT_UCHAR((PUCHAR)UlongToPtr(XEN_GLOBAL_IOPORT_PORT_BASE + 2)) == 'N')
    {
      UCHAR version = READ_PORT_UCHAR((PUCHAR)UlongToPtr(XEN_GLOBAL_IOPORT_PORT_BASE + 3));
      switch(version)
      {
      case 1:
        need_gplpv_filter = TRUE;
        WRITE_PORT_UCHAR((PUCHAR)UlongToPtr(XEN_GLOBAL_IOPORT_PORT_BASE + 8), 1);
        KdPrint((__DRIVER_NAME "     Disabled PCI devices\n"));
        break;
      default:
        KdPrint((__DRIVER_NAME "     Unknown version %d\n", (ULONG)version));
        break;
      }
    }
    else
    {
      KdPrint((__DRIVER_NAME "     Missing XEN signature\n"));
    }
    /* if not, tell the filter to deny the pci devices their resources */
    if (!need_gplpv_filter)
    {
      OBJECT_ATTRIBUTES oa;
      UNICODE_STRING dir_name;
      NTSTATUS status;
      HANDLE handle;
      
      RtlInitUnicodeString(&dir_name, L"\\NEED_GPLPV_FILTER");
      InitializeObjectAttributes(&oa, &dir_name, OBJ_KERNEL_HANDLE, NULL, NULL);
      status = ZwCreateDirectoryObject(&handle, DIRECTORY_CREATE_OBJECT, &oa);
      KdPrint((__DRIVER_NAME "     ZwCreateDirectoryObject = %08x\n", status));
      if (!NT_SUCCESS(status))
      {
        return status;
      }
      need_gplpv_filter = TRUE;
    }
  }
  
  DriverObject->DriverExtension->AddDevice = XenPci_AddDevice;
  DriverObject->MajorFunction[IRP_MJ_PNP] = XenPci_Pnp;
  DriverObject->MajorFunction[IRP_MJ_POWER] = XenPci_Power;
  DriverObject->MajorFunction[IRP_MJ_CREATE] = XenPci_Irp_Create;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = XenPci_Irp_Close;
  DriverObject->MajorFunction[IRP_MJ_CLEANUP] = XenPci_Irp_Cleanup;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = XenPci_Dummy;
  DriverObject->MajorFunction[IRP_MJ_READ] = XenPci_Irp_Read;
  DriverObject->MajorFunction[IRP_MJ_WRITE] = XenPci_Dummy;
  DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = XenPci_SystemControl;

  FUNCTION_EXIT();

  return status;
}
