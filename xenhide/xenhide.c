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

DRIVER_INITIALIZE DriverEntry;
static NTSTATUS
XenHide_AddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject);
static NTSTATUS
XenHide_Pass(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS
XenHide_Pnp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS
XenHide_AddDevice();
//static NTSTATUS
//XenHide_Unload();

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, XenHide_AddDevice)
#endif

static BOOLEAN gplpv;
static BOOLEAN at_boot;
static BOOLEAN qemu_ide_device_filter_installed;
static BOOLEAN qemu_scsi_device_filter_installed;
static KEVENT add_device_event;
static XENHIDE_DRIVER_DATA xenhide_global_data;

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

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  NTSTATUS status;
  UNICODE_STRING RegKeyName;
  UNICODE_STRING RegValueName;
  HANDLE RegHandle;
  OBJECT_ATTRIBUTES RegObjectAttributes;
  char Buf[300];// Sometimes bigger then 200 if system reboot from crash
  ULONG BufLen = 300;
  PKEY_VALUE_PARTIAL_INFORMATION KeyPartialValue;
  int State = 0;
  size_t StartPos = 0;
  WCHAR *SystemStartOptions;
  size_t SystemStartOptionsLen;
  size_t i;

  UNREFERENCED_PARAMETER(RegistryPath);

  KdPrint((__DRIVER_NAME " --> DriverEntry\n"));

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

  qemu_ide_device_filter_installed = FALSE;
  qemu_scsi_device_filter_installed = FALSE;
  KeInitializeEvent(&add_device_event, SynchronizationEvent, FALSE);

  gplpv = FALSE;

  RtlStringCbLengthW(SystemStartOptions, KeyPartialValue->DataLength, &SystemStartOptionsLen);

  for (i = 0; i <= SystemStartOptionsLen/2; i++)
  {
    //KdPrint((__DRIVER_NAME "     pos = %d, state = %d, char = '%wc' (%d)\n", i, State, SystemStartOptions[i], SystemStartOptions[i]));
    
    switch (State)
    {
    case 0:
      if (SystemStartOptions[i] == L'G')
      {
        StartPos = (int)i;
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
        gplpv = TRUE;
      State = 0;
      break;
    }
  }

  KdPrint((__DRIVER_NAME "     gplpv = %d\n", gplpv));

  for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    DriverObject->MajorFunction[i] = XenHide_Pass;
  DriverObject->MajorFunction[IRP_MJ_PNP] = XenHide_Pnp;
  DriverObject->MajorFunction[IRP_MJ_POWER] = XenHide_Power;
  DriverObject->DriverExtension->AddDevice = XenHide_AddDevice;

  RtlZeroMemory(&xenhide_global_data, sizeof(XENHIDE_DRIVER_DATA));

  InitializeListHead(&xenhide_global_data.hide_list_head);
  KeInitializeSpinLock(&xenhide_global_data.hide_list_lock);
  KeInitializeEvent(&xenhide_global_data.hide_list_event, SynchronizationEvent, FALSE);

  KdPrint((__DRIVER_NAME " <-- DriverEntry\n"));

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
        KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (Match)\n"));
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
  GUID bus_type;
  WCHAR device_description[256];
  KIRQL old_irql;
  USHORT hide_type;
  PXENHIDE_HIDE_LIST_ENTRY list_entry;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  
  length = 512;
  status = IoGetDeviceProperty(PhysicalDeviceObject, DevicePropertyDeviceDescription, length, device_description, &length);
  if (!NT_SUCCESS(status))
  {
    device_description[0] = 0;
  }

  //KdPrint((__DRIVER_NAME "     Checking '%S'\n", device_description));

  length = sizeof(GUID);
  status = IoGetDeviceProperty(PhysicalDeviceObject, DevicePropertyBusTypeGuid, length, &bus_type, &length);
  if (!NT_SUCCESS(status))
  {
    RtlZeroMemory(&bus_type, sizeof(GUID));
  }

  hide_type = XENHIDE_TYPE_NONE;
  if (gplpv)
  {
    /* hide only specific devices */
    if (XenHide_IdSuffixMatches(PhysicalDeviceObject, L"VEN_8086&DEV_7010")) // Qemu IDE
    {
      hide_type = XENHIDE_TYPE_DEVICE;
      qemu_ide_device_filter_installed = TRUE;
      KeSetEvent(&add_device_event, IO_NO_INCREMENT, FALSE);
    }
    else if (XenHide_IdSuffixMatches(PhysicalDeviceObject, L"VEN_1000&DEV_0012"))// Qemu SCSI
    {
      hide_type = XENHIDE_TYPE_DEVICE;
      qemu_scsi_device_filter_installed = TRUE;
      KeSetEvent(&add_device_event, IO_NO_INCREMENT, FALSE);
    }
    else if (XenHide_IdSuffixMatches(PhysicalDeviceObject, L"VEN_10EC&DEV_8139")) // Qemu Network
    {
      hide_type = XENHIDE_TYPE_DEVICE;
    }
    else if (XenHide_IdSuffixMatches(PhysicalDeviceObject, L"PNP0A03"))
    {
      hide_type = XENHIDE_TYPE_PCI_BUS;
    }
  }
  else
  {
    /* hide everything on the xen bus */
    if (memcmp(&bus_type, &GUID_BUS_TYPE_XEN, sizeof(GUID)) == 0)
      hide_type = XENHIDE_TYPE_DEVICE;
  }

  if (hide_type == XENHIDE_TYPE_NONE)
  {
    //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (filter not required for %S)\n", device_description));
    return STATUS_SUCCESS;
  }

  //KdPrint((__DRIVER_NAME "     Installing Filter for %S\n", device_description));

  if (gplpv && hide_type == XENHIDE_TYPE_DEVICE)
  {
    KeAcquireSpinLock(&xenhide_global_data.hide_list_lock, &old_irql);
    list_entry = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENHIDE_HIDE_LIST_ENTRY), XENHIDE_POOL_TAG);
    list_entry->pdo = PhysicalDeviceObject;
    InsertTailList(&xenhide_global_data.hide_list_head, (PLIST_ENTRY)list_entry);
    KeReleaseSpinLock(&xenhide_global_data.hide_list_lock, old_irql);
    KeSetEvent(&xenhide_global_data.hide_list_event, IO_NO_INCREMENT, FALSE);
    ASSERT(xenhide_global_data.pci_bus_pdo);
    IoInvalidateDeviceRelations(xenhide_global_data.pci_bus_pdo, BusRelations);
  }
  else if (hide_type == XENHIDE_TYPE_PCI_BUS)
  {
    ASSERT(!xenhide_global_data.pci_bus_pdo);
    xenhide_global_data.pci_bus_pdo = PhysicalDeviceObject;
  }

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

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

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
  
  irp->IoStatus.Status = status;
  
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));
}

/*
The FDO will take the existance of a 0 CmResourceTypeMemory resource to mean that it should not do anything.
In the case of xenvbd this means it will not report any disks. In the case of xennet ???
*/
static NTSTATUS
XenHide_Pnp_StartDevice_AddHideFlag(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PCM_RESOURCE_LIST old_crl, new_crl;
  PCM_PARTIAL_RESOURCE_LIST prl;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR prd;
  ULONG old_length, new_length;

  UNREFERENCED_PARAMETER(device_object);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stack = IoGetCurrentIrpStackLocation(irp);

  old_crl = stack->Parameters.StartDevice.AllocatedResourcesTranslated;
  old_length = FIELD_OFFSET(CM_RESOURCE_LIST, List) + 
    FIELD_OFFSET(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList) +
    FIELD_OFFSET(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors) +
    sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * old_crl->List[0].PartialResourceList.Count;
  new_length = old_length + sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * 1;
  new_crl = ExAllocatePoolWithTag(PagedPool, new_length, XENHIDE_POOL_TAG);
  memcpy(new_crl, old_crl, old_length);
  prl = &new_crl->List[0].PartialResourceList;
  prd = &prl->PartialDescriptors[prl->Count++];
  prd->Type = CmResourceTypeMemory;
  prd->ShareDisposition = CmResourceShareDeviceExclusive;
  prd->Flags = CM_RESOURCE_MEMORY_READ_WRITE;
  prd->u.Memory.Start.QuadPart = 0;
  prd->u.Memory.Length = 0;
  stack->Parameters.StartDevice.AllocatedResourcesTranslated = new_crl;

  old_crl = stack->Parameters.StartDevice.AllocatedResources;
  new_crl = ExAllocatePoolWithTag(PagedPool, new_length, XENHIDE_POOL_TAG);
  memcpy(new_crl, old_crl, old_length);
  prl = &new_crl->List[0].PartialResourceList;
  prd = &prl->PartialDescriptors[prl->Count++];
  prd->Type = CmResourceTypeMemory;
  prd->ShareDisposition = CmResourceShareDeviceExclusive;
  prd->Flags = CM_RESOURCE_MEMORY_READ_WRITE;
  prd->u.Memory.Start.QuadPart = (ULONGLONG)0;
  prd->u.Memory.Length = 0;
  stack->Parameters.StartDevice.AllocatedResources = new_crl;

  // free the original resource lists???

  IoMarkIrpPending(irp);
  status = XenHide_SendAndWaitForIrp(device_object, irp);

  XenHide_QueueWorkItem(device_object, XenHide_Pnp_StartDeviceCallback, irp);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));
  
  return STATUS_PENDING;
}

static NTSTATUS
XenHide_Pnp(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status = STATUS_SUCCESS;
  PIO_STACK_LOCATION stack;
  PXENHIDE_DEVICE_DATA xhdd = (PXENHIDE_DEVICE_DATA)device_object->DeviceExtension;
  PDEVICE_RELATIONS relations;
  PXENHIDE_HIDE_LIST_ENTRY list_entry;
  ULONG i, j;
  KIRQL old_irql;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ " (device_object = %p)\n", device_object));

  stack = IoGetCurrentIrpStackLocation(irp);

  switch (stack->MinorFunction) {
  case IRP_MN_START_DEVICE:
    //KdPrint((__DRIVER_NAME "     IRP_MN_START_DEVICE\n"));
    if (xhdd->hide_type == XENHIDE_TYPE_DEVICE)
    {
      //KdPrint((__DRIVER_NAME "     hide_type == XENHIDE_TYPE_DEVICE\n"));
      //status = irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
      //IoCompleteRequest(irp, IO_NO_INCREMENT);
      status = XenHide_Pnp_StartDevice_AddHideFlag(device_object, irp);
    }
    else
    {
      //KdPrint((__DRIVER_NAME "     hide_type != XENHIDE_TYPE_DEVICE\n"));
      IoSkipCurrentIrpStackLocation(irp);
      status = IoCallDriver(xhdd->lower_do, irp);
    }
    break;
  case IRP_MN_QUERY_DEVICE_RELATIONS:
    if (xhdd->hide_type == XENHIDE_TYPE_PCI_BUS && stack->Parameters.QueryDeviceRelations.Type == BusRelations)
    {
      //KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_DEVICE_RELATIONS - BusRelations\n"));
      //IoMarkIrpPending(irp);
      status = XenHide_SendAndWaitForIrp(device_object, irp);
      relations = (PDEVICE_RELATIONS)irp->IoStatus.Information;
      for (i = 0, j = 0; i < relations->Count; i++)
      {
        if (i != j)
          relations->Objects[j] = relations->Objects[i];
        KeAcquireSpinLock(&xenhide_global_data.hide_list_lock, &old_irql);
        list_entry = (PXENHIDE_HIDE_LIST_ENTRY)xenhide_global_data.hide_list_head.Flink;
        while (list_entry != (PXENHIDE_HIDE_LIST_ENTRY)&xenhide_global_data.hide_list_head)
        {
          if (relations->Objects[i] == list_entry->pdo)
          {
            //KdPrint((__DRIVER_NAME "     Hiding %p\n", relations->Objects[i]));
            break;
          }
          list_entry = (PXENHIDE_HIDE_LIST_ENTRY)list_entry->entry.Flink;
        }
        if (list_entry == (PXENHIDE_HIDE_LIST_ENTRY)&xenhide_global_data.hide_list_head)
          j++;
        KeReleaseSpinLock(&xenhide_global_data.hide_list_lock, old_irql);
      }
      relations->Count = j;
      irp->IoStatus.Status = status;
      IoCompleteRequest (irp, IO_NO_INCREMENT);
    }
    else
    {
      //KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_DEVICE_RELATIONS - %d\n", stack->Parameters.QueryDeviceRelations.Type));
      IoSkipCurrentIrpStackLocation(irp);
      status = IoCallDriver(xhdd->lower_do, irp);
    }
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

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (returning with status %08x)\n", status));

  return status;
}
