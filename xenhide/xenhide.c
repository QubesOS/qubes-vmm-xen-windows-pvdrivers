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
XenHide_EvtDeviceFilterRemoveResourceRequirements(WDFDEVICE device, WDFIORESREQLIST irrl)
{
  ULONG i;
  WDFIORESLIST irl;
  
  UNREFERENCED_PARAMETER(device);
  
  FUNCTION_ENTER();
  
  for (i = 0; i < WdfIoResourceRequirementsListGetCount(irrl); i++)
  {
    KdPrint((__DRIVER_NAME "     Processing irrl #%d\n", i));
    irl = WdfIoResourceRequirementsListGetIoResList(irrl, i);
    while(WdfIoResourceListGetCount(irl) > 0)
    {
      KdPrint((__DRIVER_NAME "     Removing irl\n"));
      WdfIoResourceListRemove(irl, 0);
    }
  }
  
  FUNCTION_EXIT();
  
  return STATUS_SUCCESS;
}

/*
static NTSTATUS
XenHide_EvtDeviceD0Entry(WDFDEVICE device, WDF_POWER_DEVICE_STATE previous_state)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  
  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(previous_state);

  FUNCTION_ENTER();
  WdfDeviceSetFailed(device, WdfDeviceFailedNoRestart);
  FUNCTION_EXIT();
  return status;
}
*/

NTSTATUS
XenHide_EvtDevicePrepareHardware (WDFDEVICE device, WDFCMRESLIST resources_raw, WDFCMRESLIST resources_translated)
{
  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(resources_raw);
  UNREFERENCED_PARAMETER(resources_translated);
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return STATUS_SUCCESS; //UNSUCCESSFUL;
}

/*
NTSTATUS
XenHide_EvtDeviceReleaseHardware(WDFDEVICE device, WDFCMRESLIST resources_translated)
{
  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(resources_translated);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  
  return STATUS_SUCCESS;
}
*/


static BOOLEAN
XenHide_IdSuffixMatches(PWDFDEVICE_INIT device_init, PWCHAR matching_id)
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
    
    remaining = ids_length / 2;
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

static NTSTATUS
XenHide_EvtDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT device_init)
{
  NTSTATUS status;
  WDFMEMORY memory;
  PWCHAR device_description;
  WDF_PNPPOWER_EVENT_CALLBACKS pnp_power_callbacks;
  WDF_FDO_EVENT_CALLBACKS fdo_callbacks;
  WDF_OBJECT_ATTRIBUTES device_attributes;
  UNICODE_STRING dir_name;
  OBJECT_ATTRIBUTES oa;
  HANDLE handle;
  BOOLEAN hide_required = FALSE;
  WDFDEVICE device;
  //PXENHIDE_DEVICE_DATA xhdd;

  UNREFERENCED_PARAMETER(driver);
#if 0
  PDEVICE_OBJECT deviceObject = NULL;
  ULONG length;
  WCHAR device_description[256];
  USHORT hide_type;
#endif

  FUNCTION_ENTER();

  if (!gplpv_interrogated)
  {
    gplpv_interrogated = TRUE;
    RtlInitUnicodeString(&dir_name, L"\\NEED_GPLPV_FILTER");
    InitializeObjectAttributes(&oa, &dir_name, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenDirectoryObject(&handle, DIRECTORY_QUERY, &oa);
    KdPrint((__DRIVER_NAME "     ZwOpenDirectoryObject = %08x\n", status));
    if (NT_SUCCESS(status))
    {
      need_gplpv_filter = TRUE;
      ZwClose(handle);
    }
  }
  
  status = WdfFdoInitAllocAndQueryProperty(device_init, DevicePropertyDeviceDescription, NonPagedPool, WDF_NO_OBJECT_ATTRIBUTES, &memory);
  if (NT_SUCCESS(status))
  {
    device_description = WdfMemoryGetBuffer(memory, NULL);
  }
  else
  {
    device_description = L"<unknown device>";
  }

  if (need_gplpv_filter)
  {
    /* hide only specific devices */
    if (XenHide_IdSuffixMatches(device_init, L"VEN_8086&DEV_7010")) // Qemu IDE
    {
      hide_required = TRUE;
    }
    else if (XenHide_IdSuffixMatches(device_init, L"VEN_1000&DEV_0012"))// Qemu SCSI
    {
      hide_required = TRUE;
    }
    else if (XenHide_IdSuffixMatches(device_init, L"VEN_10EC&DEV_8139")) // Qemu Network
    {
      hide_required = TRUE;
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
  //pnp_power_callbacks.EvtDeviceReleaseHardware = XenHide_EvtDeviceReleaseHardware;
  //pnp_power_callbacks.EvtDeviceD0Entry = XenHide_EvtDeviceD0Entry;
  //pnp_power_callbacks.EvtDeviceD0Exit = XenHide_EvtDeviceD0Exit;
  WdfDeviceInitSetPnpPowerEventCallbacks(device_init, &pnp_power_callbacks);
  
  WDF_FDO_EVENT_CALLBACKS_INIT(&fdo_callbacks);
  fdo_callbacks.EvtDeviceFilterRemoveResourceRequirements = XenHide_EvtDeviceFilterRemoveResourceRequirements;
  WdfFdoInitSetEventCallbacks(device_init, &fdo_callbacks);

  //WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&device_attributes, XENHIDE_DEVICE_DATA);
  WDF_OBJECT_ATTRIBUTES_INIT(&device_attributes);
  status = WdfDeviceCreate(&device_init, &device_attributes, &device);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Error creating device %08x\n", status));
    WdfObjectDelete(memory);
    FUNCTION_EXIT();
    return status;
  }

  //xhdd = GetXhdd(device);

  //xhdd->filter_do = deviceObject;

  WdfObjectDelete(memory);
  FUNCTION_EXIT();

  return status;
}



#if 0
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
#endif

static VOID
XenHide_EvtDriverUnload(WDFDRIVER driver)
{
  UNREFERENCED_PARAMETER(driver);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  NTSTATUS status = STATUS_SUCCESS;
  WDF_DRIVER_CONFIG config;
  WDFDRIVER driver;
  PDRIVER_OBJECT wdm_driver;

  FUNCTION_ENTER();

  need_gplpv_filter = FALSE;
  gplpv_interrogated = FALSE;
  
  WDF_DRIVER_CONFIG_INIT(&config, XenHide_EvtDeviceAdd);
  config.EvtDriverUnload = XenHide_EvtDriverUnload;
  status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
  if (NT_SUCCESS(status))
  {
    wdm_driver = WdfDriverWdmGetDriverObject(driver);
    ObReferenceObject(wdm_driver);
  }
  FUNCTION_EXIT();

  return status;
}
