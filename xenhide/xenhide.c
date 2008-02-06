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

static BOOLEAN AutoEnumerate;

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

  KdPrint((__DRIVER_NAME " --> DriverEntry\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

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

  AutoEnumerate = FALSE;

  RtlStringCbLengthW(SystemStartOptions, KeyPartialValue->DataLength, &SystemStartOptionsLen);

  for (i = 0; i <= SystemStartOptionsLen/2; i++)
  {
    //KdPrint((__DRIVER_NAME "     pos = %d, state = %d, char = '%wc' (%d)\n", i, State, SystemStartOptions[i], SystemStartOptions[i]));
    
    switch (State)
    {
    case 0:
      if (SystemStartOptions[i] == L'G')
      {
        StartPos = i;
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
        AutoEnumerate = TRUE;
      State = 0;
      break;
    }
  }

  KdPrint((__DRIVER_NAME "     AutoEnumerate = %d\n", AutoEnumerate));

  for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    DriverObject->MajorFunction[i] = XenHide_Pass;
  if (AutoEnumerate)
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
  PDEVICE_EXTENSION DeviceExtension;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  status = IoCreateDevice (DriverObject,
    sizeof(DEVICE_EXTENSION),
    NULL,
    FILE_DEVICE_UNKNOWN,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    &deviceObject);

  DeviceExtension = (PDEVICE_EXTENSION)deviceObject->DeviceExtension;

  DeviceExtension->NextLowerDevice = IoAttachDeviceToDeviceStack(
    deviceObject,
    PhysicalDeviceObject);
  deviceObject->Flags |= DeviceExtension->NextLowerDevice->Flags;

  deviceObject->DeviceType = DeviceExtension->NextLowerDevice->DeviceType;

  deviceObject->Characteristics = 
    DeviceExtension->NextLowerDevice->Characteristics;

  DeviceExtension->Self = deviceObject;

  //INITIALIZE_PNP_STATE(DeviceExtension);

  if (AutoEnumerate)
  {
    status = IoRegisterDeviceInterface(PhysicalDeviceObject, (LPGUID)&GUID_XENHIDE_IFACE, NULL, &DeviceExtension->InterfaceName);
    if (!NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     IoRegisterDeviceInterface failed 0x%08x\n", status));
      return status;
    }
    KdPrint((__DRIVER_NAME "     IoRegisterDeviceInterface complete, SymbolicLinkName = %wZ\n", &DeviceExtension->InterfaceName));
    status = IoSetDeviceInterfaceState(&DeviceExtension->InterfaceName, TRUE);
    if (!NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     IoSetDeviceInterfaceState failed 0x%08x\n", status));
      return status;
    }
  }
  else
  {
    KdPrint((__DRIVER_NAME "     Not registering Interface\n"));
  }

  deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}

static int
XenHide_StringMatches(PWCHAR String1, PWCHAR String2)
{
  for(;*String1 != 0 && *String2 != 0 && *String1 == *String2; String1++, String2++);
  return ((*String1 == 0 && *String2 == 0) || (*String1 == 0 && *String2 == L'\n') || (*String1 == L'\n' && *String2 == 0));
}

static NTSTATUS
XenHide_IoCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
  ULONG i, j;
  PDEVICE_RELATIONS Relations;
  WCHAR Buffer[1000];
  PWCHAR Ptr;
  ULONG Length;
  size_t StrLen;
  int Match;
  int Offset = 0;

  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Context);

  KdPrint((__DRIVER_NAME " --> IoCompletion\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  Relations = (PDEVICE_RELATIONS)Irp->IoStatus.Information;

  for (i = 0; i < Relations->Count; i++)
  {
    if (Offset != 0)
      Relations->Objects[i - Offset] = Relations->Objects[i];

    Match = 0;
    for (j = 0; j < 2 && !Match; j++)
    {
      Length = sizeof(Buffer);
      if (j == 0)
        IoGetDeviceProperty(Relations->Objects[i - Offset], DevicePropertyCompatibleIDs, Length, Buffer, &Length);
      else
        IoGetDeviceProperty(Relations->Objects[i - Offset], DevicePropertyHardwareID, Length, Buffer, &Length);
      StrLen = 0;
      for (Ptr = Buffer; *Ptr != 0; Ptr += StrLen + 1)
      {
        // Qemu PCI
        if (XenHide_StringMatches(Ptr, L"PCI\\VEN_8086&DEV_7010")) {
          Match = 1;
          break;
        }
        // Qemu Network
        if (XenHide_StringMatches(Ptr, L"PCI\\VEN_10EC&DEV_8139")) {
          Match = 1;
          break;
        }
        RtlStringCchLengthW(Ptr, Length, &StrLen);
      }
    }
    if (Match)
    {
      Offset++;
    }
  }
  Relations->Count -= Offset;
  
  KdPrint((__DRIVER_NAME " <-- IoCompletion\n"));

  return Irp->IoStatus.Status;
}

static NTSTATUS
XenHide_Pass(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  PDEVICE_EXTENSION DeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
  NTSTATUS status;
    
  IoSkipCurrentIrpStackLocation(Irp);
  status = IoCallDriver(DeviceExtension->NextLowerDevice, Irp);
  return status;
}

static NTSTATUS
XenHide_Pnp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  NTSTATUS Status = STATUS_SUCCESS;
  PIO_STACK_LOCATION Stack;
  PDEVICE_EXTENSION DeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  Stack = IoGetCurrentIrpStackLocation(Irp);

  switch (Stack->MinorFunction) {
  case IRP_MN_QUERY_DEVICE_RELATIONS:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_DEVICE_RELATIONS\n"));
    switch (Stack->Parameters.QueryDeviceRelations.Type)
    {
    case BusRelations:
      KdPrint((__DRIVER_NAME "       BusRelations\n"));
      IoCopyCurrentIrpStackLocationToNext(Irp);
      IoSetCompletionRoutine(Irp, XenHide_IoCompletion, NULL, TRUE, TRUE, TRUE);
      Status = IoCallDriver(DeviceExtension->NextLowerDevice, Irp);
      break;  
    default:
      IoSkipCurrentIrpStackLocation(Irp);
      Status = IoCallDriver(DeviceExtension->NextLowerDevice, Irp);
      break;  
    }
    break;
  default:
    IoSkipCurrentIrpStackLocation(Irp);
    Status = IoCallDriver(DeviceExtension->NextLowerDevice, Irp);
    break;
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (returning with status %08x)\n", Status));

  return Status;
}
