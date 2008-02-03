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
XenHide_AddDevice(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit);
static VOID
XenHide_IoInternalDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, XenHide_AddDevice)
#endif

static BOOLEAN AutoEnumerate;

static WDFDEVICE Device;

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  WDF_DRIVER_CONFIG config;
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
//  KdPrint((__DRIVER_NAME "     BufLen = %d\n", BufLen));
  KeyPartialValue = (PKEY_VALUE_PARTIAL_INFORMATION)Buf;
//  KdPrint((__DRIVER_NAME "     Buf = %ws\n", KeyPartialValue->Data));
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

  WDF_DRIVER_CONFIG_INIT(&config, XenHide_AddDevice);
  status = WdfDriverCreate(
                      DriverObject,
                      RegistryPath,
                      WDF_NO_OBJECT_ATTRIBUTES,
                      &config,
                      WDF_NO_HANDLE);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME " WdfDriverCreate failed with status 0x%08x\n", status));
  }

  KdPrint((__DRIVER_NAME " <-- DriverEntry\n"));

  return status;
}

static NTSTATUS
XenHide_PreprocessWdmIrpPNP(WDFDEVICE Device, PIRP Irp);

static VOID 
XenPCI_IoDefault(
    IN WDFQUEUE  Queue,
    IN WDFREQUEST  Request
    )
{
  UNREFERENCED_PARAMETER(Queue);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static VOID 
XenPCI_IoRead(WDFQUEUE Queue, WDFREQUEST Request, size_t Length)
{
  PCHAR Buffer;
  size_t BufLen;

  UNREFERENCED_PARAMETER(Queue);
  UNREFERENCED_PARAMETER(Length);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  WdfRequestRetrieveOutputBuffer(Request, 1, &Buffer, &BufLen);

  ASSERT(BufLen > 0);

  Buffer[0] = 1;

  WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, 1);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static NTSTATUS
XenHide_AddDevice(
    IN WDFDRIVER Driver,
    IN PWDFDEVICE_INIT DeviceInit
    )
{
  NTSTATUS status;
  WDF_OBJECT_ATTRIBUTES attributes;
  UCHAR MinorFunctions[3] = { IRP_MN_QUERY_DEVICE_RELATIONS };

  UNREFERENCED_PARAMETER(Driver);

  KdPrint((__DRIVER_NAME " --> DeviceAdd\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  WdfFdoInitSetFilter(DeviceInit);

  status = WdfDeviceInitAssignWdmIrpPreprocessCallback(DeviceInit, XenHide_PreprocessWdmIrpPNP, IRP_MJ_PNP, MinorFunctions, 3);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceInitAssignWdmIrpPreprocessCallback failed with status 0x%08x\n", status));
    return status;
  }

  WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

  status = WdfDeviceCreate(&DeviceInit, &attributes, &Device);  
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreate failed with status 0x%08x\n", status));
    return status;
  }

  if (AutoEnumerate)
  {
    status = WdfDeviceCreateDeviceInterface(Device, (LPGUID)&GUID_XENHIDE_IFACE, NULL);
    if (!NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     WdfDeviceCreateDeviceInterface failed 0x%08x\n", status));
      return status;
    }
  }

  KdPrint((__DRIVER_NAME " <-- DeviceAdd\n"));

  return status;
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
  ULONG i;
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

//    Length = sizeof(Buffer);
//    IoGetDeviceProperty(Relations->Objects[i - Offset], DevicePropertyDeviceDescription, Length, Buffer, &Length);
//    KdPrint((__DRIVER_NAME "     %3d - %ws\n", i, Buffer));

//    Length = sizeof(Buffer);
//    IoGetDeviceProperty(Relations->Objects[i - Offset], DevicePropertyPhysicalDeviceObjectName, Length, Buffer, &Length);
//    KdPrint((__DRIVER_NAME "     %3d - %ws\n", i, Buffer));

    Length = sizeof(Buffer);
    IoGetDeviceProperty(Relations->Objects[i - Offset], DevicePropertyCompatibleIDs, Length, Buffer, &Length);
    Match = 0;
    StrLen = 0;
    for (Ptr = Buffer; *Ptr != 0; Ptr += StrLen + 1)
    {
//      KdPrint((__DRIVER_NAME "         - %ws\n", Ptr));
      // Qemu PCI
//      if (XenHide_StringMatches(Ptr, L"PCI\\VEN_8086&DEV_7010&SUBSYS_00015853")) {
      if (XenHide_StringMatches(Ptr, L"PCI\\VEN_8086&DEV_7010")) {
        Match = 1;
        break;
      }
      // Qemu Network
//      if (XenHide_StringMatches(Ptr, L"PCI\\VEN_10EC&DEV_8139&SUBSYS_00015853")) {
      if (XenHide_StringMatches(Ptr, L"PCI\\VEN_10EC&DEV_8139")) {
        Match = 1;
        break;
      }
      RtlStringCchLengthW(Ptr, Length, &StrLen);
    }
    if (Match)
    {
//      KdPrint((__DRIVER_NAME "           (Match)\n"));
      Offset++;
    }
  }
  Relations->Count -= Offset;
  
  KdPrint((__DRIVER_NAME " <-- IoCompletion\n"));

  return Irp->IoStatus.Status;
}

static NTSTATUS
XenHide_PreprocessWdmIrpPNP(WDFDEVICE Device, PIRP Irp)
{
  NTSTATUS Status = STATUS_SUCCESS;
  PIO_STACK_LOCATION Stack;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  Stack = IoGetCurrentIrpStackLocation(Irp);

  switch (Stack->MinorFunction) {
  case IRP_MN_QUERY_DEVICE_RELATIONS:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_DEVICE_RELATIONS Device = %08x Irp = %08x, Stack = %08x\n", Device, Irp, Stack));
    switch (Stack->Parameters.QueryDeviceRelations.Type)
    {
    case BusRelations:
      KdPrint((__DRIVER_NAME "       BusRelations\n"));
      if (AutoEnumerate)
      {
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, XenHide_IoCompletion, NULL, TRUE, TRUE, TRUE);
        Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
      }
      else
      {
        IoSkipCurrentIrpStackLocation(Irp);
        Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
      }
      break;  
    case EjectionRelations: 
      IoSkipCurrentIrpStackLocation(Irp);
      Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
      KdPrint((__DRIVER_NAME "       EjectionRelations\n"));
      break;  
    case RemovalRelations:
      IoSkipCurrentIrpStackLocation(Irp);
      Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
      KdPrint((__DRIVER_NAME "       RemovalRelations\n"));
      break;  
    case TargetDeviceRelation:
      IoSkipCurrentIrpStackLocation(Irp);
      Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
      KdPrint((__DRIVER_NAME "       TargetDeviceRelation\n"));
      break;  
    default:
      IoSkipCurrentIrpStackLocation(Irp);
      Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
      KdPrint((__DRIVER_NAME "     Unknown Type %d\n", Stack->Parameters.QueryDeviceRelations.Type));
      break;  
    }
    break;
  case IRP_MN_QUERY_INTERFACE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_INTERFACE\n"));
    if (memcmp(Stack->Parameters.QueryInterface.InterfaceType, &GUID_XENHIDE_IFACE, sizeof(GUID)) == 0)
    {
      KdPrint((__DRIVER_NAME "     Interface == GUID_XENHIDE_IFACE\n"));
    }
    IoSkipCurrentIrpStackLocation(Irp);
    Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
    break;
  case IRP_MN_QUERY_BUS_INFORMATION:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_BUS_INFORMATION\n"));
    IoSkipCurrentIrpStackLocation(Irp);
    Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
    break;
/*
  case IRP_MN_START_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_START_DEVICE\n"));
    IoSkipCurrentIrpStackLocation(Irp);
    Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
    break;
*/
  default:
    IoSkipCurrentIrpStackLocation(Irp);
    Status = WdfDeviceWdmDispatchPreprocessedIrp(Device, Irp);
    KdPrint((__DRIVER_NAME "     Unknown Minor %d\n", Stack->MinorFunction));
    break;
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (returning with status %08x)\n", Status));

  return Status;
}
