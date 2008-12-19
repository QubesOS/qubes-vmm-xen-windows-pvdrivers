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

#include "xenhide.h"
#include <stdlib.h>

extern PULONG InitSafeBootMode;
static BOOLEAN need_gplpv_filter;
static BOOLEAN gplpv_interrogated;

static NTSTATUS
XenHide_Power(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENHIDE_DEVICE_DATA xhdd = (PXENHIDE_DEVICE_DATA)device_object->DeviceExtension;

  PoStartNextPowerIrp(irp);
  IoSkipCurrentIrpStackLocation(irp);
  status = PoCallDriver(xhdd->lower_do, irp);
  return status;
}

static BOOLEAN
XenHide_IdSuffixMatches(PDEVICE_OBJECT pdo, PWCHAR matching_id)
{
  NTSTATUS status;
  ULONG remaining;
  size_t string_length;
  WCHAR ids[512];
  PWCHAR ptr;
  ULONG ids_length;
  int i;
  
//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  for (i = 0; i < 2; i++)
  {
    if (i == 0)
      status = IoGetDeviceProperty(pdo, DevicePropertyCompatibleIDs, sizeof(ids), ids, &ids_length);
    else
      status = IoGetDeviceProperty(pdo, DevicePropertyHardwareID, sizeof(ids), ids, &ids_length);
      
    if (!NT_SUCCESS(status))
    {
//      KdPrint((__DRIVER_NAME "     i = %d, status = %x, ids_length = %d\n", i, status, ids_length));
      continue;
    }
    
    remaining = ids_length / 2;
    for (ptr = ids; *ptr != 0; ptr += string_length + 1)
    {
      RtlStringCchLengthW(ptr, remaining, &string_length);
      remaining -= (ULONG)string_length + 1;
      if (string_length >= wcslen(matching_id))
      {
        ptr += string_length - wcslen(matching_id);
        string_length = (ULONG)wcslen(matching_id);
      }
//      KdPrint((__DRIVER_NAME "     Comparing '%S' and '%S'\n", ptr, matching_id));
      if (wcscmp(ptr, matching_id) == 0)
      {
        //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (Match)\n"));
        return TRUE;
      }
    }
  }
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (No match)\n"));
  return FALSE;
}

static NTSTATUS
XenHide_AddDevice(
  PDRIVER_OBJECT DriverObject,
  PDEVICE_OBJECT PhysicalDeviceObject
  )
{
  NTSTATUS status;
  PDEVICE_OBJECT deviceObject = NULL;
  PXENHIDE_DEVICE_DATA xhdd;
  ULONG length;
  WCHAR device_description[256];
  USHORT hide_type;
  OBJECT_ATTRIBUTES oa;
  UNICODE_STRING dir_name;
  HANDLE handle;

  FUNCTION_ENTER();

  if (!gplpv_interrogated)
  {
    gplpv_interrogated = TRUE;
    RtlInitUnicodeString(&dir_name, L"\\NEED_GPLPV_FILTER");
    InitializeObjectAttributes(&oa, &dir_name, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenDirectoryObject(&handle, DIRECTORY_QUERY, &oa);
    KdPrint((__DRIVER_NAME "     ZwOpenDirectoryObject = %08x\n", status));
    if (NT_SUCCESS(status))
      need_gplpv_filter = TRUE;
  }
  
  length = 512;
  status = IoGetDeviceProperty(PhysicalDeviceObject, DevicePropertyDeviceDescription, length, device_description, &length);
  if (!NT_SUCCESS(status))
  {
    device_description[0] = 0;
  }

  //KdPrint((__DRIVER_NAME "     Checking '%S'\n", device_description));

  hide_type = XENHIDE_TYPE_NONE;
  if (need_gplpv_filter)
  {
    /* hide only specific devices */
    if (XenHide_IdSuffixMatches(PhysicalDeviceObject, L"VEN_8086&DEV_7010")) // Qemu IDE
    {
      hide_type = XENHIDE_TYPE_DEVICE;
    }
    else if (XenHide_IdSuffixMatches(PhysicalDeviceObject, L"VEN_1000&DEV_0012"))// Qemu SCSI
    {
      hide_type = XENHIDE_TYPE_DEVICE;
    }
    else if (XenHide_IdSuffixMatches(PhysicalDeviceObject, L"VEN_10EC&DEV_8139")) // Qemu Network
    {
      hide_type = XENHIDE_TYPE_DEVICE;
    }
  }

  if (hide_type == XENHIDE_TYPE_NONE)
  {
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (filter not required for %S)\n", device_description));
    return STATUS_SUCCESS;
  }

  KdPrint((__DRIVER_NAME "     Installing Filter for %S\n", device_description));

  status = IoCreateDevice (DriverObject,
    sizeof(XENHIDE_DEVICE_DATA),
    NULL,
    FILE_DEVICE_UNKNOWN,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    &deviceObject);

  xhdd = (PXENHIDE_DEVICE_DATA)deviceObject->DeviceExtension;

  xhdd->hide_type = hide_type;
  
  xhdd->lower_do = IoAttachDeviceToDeviceStack(
    deviceObject, PhysicalDeviceObject);
  deviceObject->Flags |= xhdd->lower_do->Flags;

  deviceObject->DeviceType = xhdd->lower_do->DeviceType;

  deviceObject->Characteristics = 
    xhdd->lower_do->Characteristics;

  xhdd->filter_do = deviceObject;

  deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

  FUNCTION_EXIT();

  return STATUS_SUCCESS;
}

static NTSTATUS
XenHide_Pass(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  PXENHIDE_DEVICE_DATA xhdd = (PXENHIDE_DEVICE_DATA)DeviceObject->DeviceExtension;
  NTSTATUS status;
    
  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  IoSkipCurrentIrpStackLocation(Irp);
  status = IoCallDriver(xhdd->lower_do, Irp);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

static NTSTATUS
XenHide_Pnp_IoCompletion(PDEVICE_OBJECT device_object, PIRP irp, PVOID context)
{
  PKEVENT event = (PKEVENT)context;

  UNREFERENCED_PARAMETER(device_object);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  if (irp->PendingReturned)
  {
    KeSetEvent(event, IO_NO_INCREMENT, FALSE);
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
XenHide_QueueWorkItem(PDEVICE_OBJECT device_object, PIO_WORKITEM_ROUTINE routine, PVOID context)
{
  PIO_WORKITEM work_item;
  NTSTATUS status = STATUS_SUCCESS;

  work_item = IoAllocateWorkItem(device_object);
  IoQueueWorkItem(work_item, routine, DelayedWorkQueue, context);

  return status;
}

static VOID
XenHide_Pnp_StartDeviceCallback(PDEVICE_OBJECT device_object, PVOID context)
{
  NTSTATUS status = STATUS_SUCCESS;
  PIRP irp = context;

  UNREFERENCED_PARAMETER(device_object);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  status = STATUS_UNSUCCESSFUL;
  irp->IoStatus.Status = status;

  IoCompleteRequest(irp, IO_NO_INCREMENT);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));
}

static NTSTATUS
XenHide_SendAndWaitForIrp(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENHIDE_DEVICE_DATA xhdd = (PXENHIDE_DEVICE_DATA)device_object->DeviceExtension;
  KEVENT event;

  UNREFERENCED_PARAMETER(device_object);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  KeInitializeEvent(&event, NotificationEvent, FALSE);

  IoCopyCurrentIrpStackLocationToNext(irp);
  IoSetCompletionRoutine(irp, XenHide_Pnp_IoCompletion, &event, TRUE, TRUE, TRUE);

  status = IoCallDriver(xhdd->lower_do, irp);

  if (status == STATUS_PENDING)
  {
    KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
    status = irp->IoStatus.Status;
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

XenHide_Pnp_StartDevice(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  IoMarkIrpPending(irp);
  status = XenHide_SendAndWaitForIrp(device_object, irp);
  XenHide_QueueWorkItem(device_object, XenHide_Pnp_StartDeviceCallback, irp);

  FUNCTION_EXIT();

  return STATUS_PENDING;
}

static NTSTATUS
XenHide_Pnp(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status = STATUS_SUCCESS;
  PIO_STACK_LOCATION stack;
  PXENHIDE_DEVICE_DATA xhdd = (PXENHIDE_DEVICE_DATA)device_object->DeviceExtension;

  FUNCTION_ENTER();

  stack = IoGetCurrentIrpStackLocation(irp);

  switch (stack->MinorFunction) {
  case IRP_MN_START_DEVICE:
    status = XenHide_Pnp_StartDevice(device_object, irp);
    break;
  case IRP_MN_REMOVE_DEVICE:
    //KdPrint((__DRIVER_NAME "     IRP_MN_REMOVE_DEVICE\n"));
    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(xhdd->lower_do, irp);
    IoDetachDevice(xhdd->lower_do);
    IoDeleteDevice(device_object);
    //irp->IoStatus.Status = status;
    //IoCompleteRequest(irp, IO_NO_INCREMENT);
    break;
  default:
    //KdPrint((__DRIVER_NAME "     Unhandled Minor = %d\n", stack->MinorFunction));
    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(xhdd->lower_do, irp);
    break;
  }

  FUNCTION_EXIT();

  return status;
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  NTSTATUS status = STATUS_SUCCESS;
  int i;
  
  UNREFERENCED_PARAMETER(RegistryPath);

  FUNCTION_ENTER();

  need_gplpv_filter = FALSE;
  gplpv_interrogated = FALSE;
  
  for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    DriverObject->MajorFunction[i] = XenHide_Pass;
  DriverObject->MajorFunction[IRP_MJ_PNP] = XenHide_Pnp;
  DriverObject->MajorFunction[IRP_MJ_POWER] = XenHide_Power;
  DriverObject->DriverExtension->AddDevice = XenHide_AddDevice;

  FUNCTION_EXIT();

  return status;
}
