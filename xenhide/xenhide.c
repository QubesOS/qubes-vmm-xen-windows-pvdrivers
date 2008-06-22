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
  char Buf[200];
  ULONG BufLen = 200;
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
  ULONG string_length;
  WCHAR ids[512];
  PWCHAR ptr;
  ULONG ids_length;
  int i;
  
  for (i = 0; i < 2; i++)
  {
    if (i == 0)
      status = IoGetDeviceProperty(pdo, DevicePropertyCompatibleIDs, sizeof(ids), ids, &ids_length);
    else
      status = IoGetDeviceProperty(pdo, DevicePropertyHardwareID, sizeof(ids), ids, &ids_length);
      
    if (!NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     i = %d, status = %x, ids_length = %d\n", i, status, ids_length));
      continue;
    }
    
    remaining = ids_length / 2;
    for (ptr = ids; *ptr != 0; ptr += string_length + 1)
    {
      RtlStringCchLengthW(ptr, remaining, (size_t *)&string_length);
      remaining -= string_length - 1;
      if (string_length >= wcslen(matching_id))
      {
        ptr += string_length - wcslen(matching_id);
        string_length -= wcslen(matching_id);
      }
      KdPrint((__DRIVER_NAME "     Comparing '%S' and '%S'\n", ptr, matching_id));
      if (wcscmp(ptr, matching_id) == 0)
       return TRUE;
    }
  }
  KdPrint((__DRIVER_NAME "     No match\n"));  
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

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  
  length = 512;
  status = IoGetDeviceProperty(PhysicalDeviceObject, DevicePropertyDeviceDescription, length, device_description, &length);
  if (!NT_SUCCESS(status))
  {
    device_description[0] = 0;
  }

  KdPrint((__DRIVER_NAME "     Checking '%S'\n", device_description));

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
    if (XenHide_IdSuffixMatches(PhysicalDeviceObject, L"VEN_8086&DEV_7010")
      || XenHide_IdSuffixMatches(PhysicalDeviceObject, L"VEN_10EC&DEV_8139"))
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
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (filter not required for %S)\n", device_description));
    return STATUS_SUCCESS;
  }

  KdPrint((__DRIVER_NAME "     Installing Filter for %S\n", device_description));

  if (gplpv && hide_type == XENHIDE_TYPE_DEVICE)
  {
    KeAcquireSpinLock(&xenhide_global_data.hide_list_lock, &old_irql);
    list_entry = ExAllocatePoolWithTag(PagedPool, sizeof(XENHIDE_HIDE_LIST_ENTRY), XENHIDE_POOL_TAG);
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

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}

static NTSTATUS
XenHide_Pass(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  PXENHIDE_DEVICE_DATA xhdd = (PXENHIDE_DEVICE_DATA)DeviceObject->DeviceExtension;
  NTSTATUS status;
    
  IoSkipCurrentIrpStackLocation(Irp);
  status = IoCallDriver(xhdd->lower_do, Irp);
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
XenHide_Pnp(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status = STATUS_SUCCESS;
  PIO_STACK_LOCATION stack;
  PXENHIDE_DEVICE_DATA xhdd = (PXENHIDE_DEVICE_DATA)device_object->DeviceExtension;
  PDEVICE_RELATIONS relations;
  PXENHIDE_HIDE_LIST_ENTRY list_entry;
  ULONG i, j;
  KIRQL old_irql;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stack = IoGetCurrentIrpStackLocation(irp);

  switch (stack->MinorFunction) {
  case IRP_MN_START_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_START_DEVICE\n"));
    if (xhdd->hide_type == XENHIDE_TYPE_DEVICE)
    {
      KdPrint((__DRIVER_NAME "     hide_type == XENHIDE_TYPE_DEVICE\n"));
      status = irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
      IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
    else
    {
      KdPrint((__DRIVER_NAME "     hide_type != XENHIDE_TYPE_DEVICE\n"));
      IoSkipCurrentIrpStackLocation(irp);
      status = IoCallDriver(xhdd->lower_do, irp);
    }
    break;
  case IRP_MN_QUERY_DEVICE_RELATIONS:
    if (xhdd->hide_type == XENHIDE_TYPE_PCI_BUS && stack->Parameters.QueryDeviceRelations.Type == BusRelations)
    {
      KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_DEVICE_RELATIONS - BusRelations\n"));
      IoMarkIrpPending(irp);
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
            KdPrint((__DRIVER_NAME "     Hiding %p\n", relations->Objects[i]));
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
      IoSkipCurrentIrpStackLocation(irp);
      status = IoCallDriver(xhdd->lower_do, irp);
    }
    break;
  default:
    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(xhdd->lower_do, irp);
    break;
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (returning with status %08x)\n", status));

  return status;
}
