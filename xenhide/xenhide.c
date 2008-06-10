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
  int StartPos = 0;
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
  DriverObject->DriverExtension->AddDevice = XenHide_AddDevice;

  KdPrint((__DRIVER_NAME " <-- DriverEntry\n"));

  return status;
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
  WCHAR buffer[256];
//  size_t StrLen;
//  int Match;
//  PWCHAR Ptr;
  GUID bus_type;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  length = 256;
  status = IoGetDeviceProperty(PhysicalDeviceObject, DevicePropertyDeviceDescription, length, buffer, &length);
//  if (!NT_SUCCESS(status))
//    KdPrint((__DRIVER_NAME "     (failed to get DevicePropertyDeviceDescription %08x)\n", status));
//  else
//    KdPrint((__DRIVER_NAME "     Description = %S\n", buffer));

  length = sizeof(GUID);
  status = IoGetDeviceProperty(PhysicalDeviceObject, DevicePropertyBusTypeGuid, length, &bus_type, &length);
  if (!NT_SUCCESS(status))
  {
//    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (failed to get DevicePropertyBusTypeGuid %08x)\n", status));
    return STATUS_SUCCESS;
  }

  if (!gplpv && memcmp(&bus_type, &GUID_BUS_TYPE_XEN, sizeof(GUID)) != 0)
  {
//    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (gplpv == FALSE && bus_type != GUID_BUS_TYPE_XEN)\n"));
    return STATUS_SUCCESS;
  }
  
  if (gplpv && memcmp(&bus_type, &GUID_BUS_TYPE_PCI, sizeof(GUID)) != 0)
  {
//    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (gplpv == TRUE && bus_type != GUID_BUS_TYPE_PCI)\n"));
    return STATUS_SUCCESS;
  }

//  KdPrint((__DRIVER_NAME "     Installing Filter\n"));

  status = IoCreateDevice (DriverObject,
    sizeof(XENHIDE_DEVICE_DATA),
    NULL,
    FILE_DEVICE_UNKNOWN,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    &deviceObject);

  xhdd = (PXENHIDE_DEVICE_DATA)deviceObject->DeviceExtension;

  xhdd->lower_do = IoAttachDeviceToDeviceStack(
    deviceObject, PhysicalDeviceObject);
  deviceObject->Flags |= xhdd->lower_do->Flags;

  deviceObject->DeviceType = xhdd->lower_do->DeviceType;

  deviceObject->Characteristics = 
    xhdd->lower_do->Characteristics;

  xhdd->filter_do = deviceObject;

  deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

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
//    KdPrint((__DRIVER_NAME "     waiting ...\n"));
    KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
//    KdPrint((__DRIVER_NAME "     ... done\n"));
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

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stack = IoGetCurrentIrpStackLocation(irp);

  switch (stack->MinorFunction) {
  case IRP_MN_START_DEVICE:
    status = irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    break;
  case IRP_MN_QUERY_CAPABILITIES:
//    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_CAPABILITIES\n"));
    stack->Parameters.DeviceCapabilities.Capabilities->NoDisplayInUI = 1;
    status = XenHide_SendAndWaitForIrp(device_object, irp);
    status = irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
//    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));
    return status;
  default:
    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(xhdd->lower_do, irp);
    break;
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (returning with status %08x)\n", status));

  return status;
}
