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

#include "xenpci.h"
#include <stdlib.h>

#define SYSRQ_PATH "control/sysrq"
#define SHUTDOWN_PATH "control/shutdown"
#define BALLOON_PATH "memory/target"

DRIVER_INITIALIZE DriverEntry;

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif

#pragma warning(disable : 4200) // zero-sized array

static NTSTATUS
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

static NTSTATUS
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

static NTSTATUS
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

static NTSTATUS
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

static NTSTATUS
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

static NTSTATUS
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

static NTSTATUS
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

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

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
    (LPGUID)&GUID_XEN_IFACE,
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

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));
  return status;
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(RegistryPath);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  //InitializeListHead(&ShutdownMsgList);
  //KeInitializeSpinLock(&ShutdownMsgLock);

  DriverObject->DriverExtension->AddDevice = XenPci_AddDevice;
  DriverObject->MajorFunction[IRP_MJ_PNP] = XenPci_Pnp;
  DriverObject->MajorFunction[IRP_MJ_POWER] = XenPci_Power;
  DriverObject->MajorFunction[IRP_MJ_CREATE] = XenPci_Irp_Create;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = XenPci_Irp_Close;
  DriverObject->MajorFunction[IRP_MJ_CLEANUP] = XenPci_Irp_Cleanup;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NULL; //XenPci_Dummy;
  DriverObject->MajorFunction[IRP_MJ_READ] = XenPci_Irp_Read;
  DriverObject->MajorFunction[IRP_MJ_WRITE] = NULL; //XenPci_Dummy;
  DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = NULL; //XenPci_Dummy;

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return status;
}