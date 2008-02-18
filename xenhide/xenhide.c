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
XenHide_Power(PDEVICE_OBJECT DeviceObject, PIRP Irp);
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

  UNREFERENCED_PARAMETER(RegistryPath);

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

  DriverObject->MajorFunction[IRP_MJ_POWER] = XenHide_Power;

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
  PDEVICE_OBJECT DeviceObject = NULL;
  PDEVICE_EXTENSION DeviceExtension;
  ULONG Length;
  WCHAR Buffer[1000];

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  Length = 1000;
  status = IoGetDeviceProperty(PhysicalDeviceObject, DevicePropertyDeviceDescription, Length, Buffer, &Length);
  KdPrint((__DRIVER_NAME "     status = %08x, DevicePropertyDeviceDescription = %ws\n", status, Buffer));

  if (!NT_SUCCESS(status) || wcscmp(Buffer, L"PCI bus") != 0)
  {
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
    return STATUS_SUCCESS;
  }
  KdPrint((__DRIVER_NAME "     Found\n"));

  status = IoCreateDevice(DriverObject,
    sizeof(DEVICE_EXTENSION),
    NULL,
    FILE_DEVICE_UNKNOWN,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    &DeviceObject);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     IoCreateDevice failed 0x%08x\n", status));
    return status;
  }

  DeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

  DeviceExtension->Self = DeviceObject;
  DeviceExtension->PhysicalDeviceObject = PhysicalDeviceObject;
  DeviceExtension->DriverObject = DriverObject;
  DeviceExtension->Type = XENHIDE_TYPE_PCI;
  DeviceExtension->InternalState = 0;

  DeviceExtension->NextLowerDevice = IoAttachDeviceToDeviceStack(
    DeviceObject,
    PhysicalDeviceObject);

  DeviceObject->Flags |= DeviceExtension->NextLowerDevice->Flags;

  DeviceObject->DeviceType = DeviceExtension->NextLowerDevice->DeviceType;

  DeviceObject->Characteristics = 
    DeviceExtension->NextLowerDevice->Characteristics;

//  IoInitializeRemoveLock(&DeviceExtension->RemoveLock, XENHIDE_POOL_TAG, 1, 100);

#if 0
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
#endif

  DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

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
XenHide_IoCompletionPciQueryDeviceRelations(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
  ULONG i, j;
  PDEVICE_RELATIONS Relations;
  WCHAR Buffer[1000];
  PWCHAR Ptr;
  ULONG Length;
  size_t StrLen;
  int Match;
  NTSTATUS status;
  PDEVICE_OBJECT NewDeviceObject;
  PDEVICE_EXTENSION DeviceExtension = (PDEVICE_EXTENSION)Context;
  PDEVICE_EXTENSION NewDeviceExtension;

  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Context);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));
  KdPrint((__DRIVER_NAME "     InternalState = %d\n", DeviceExtension->InternalState));

  if (Irp->PendingReturned)
    IoMarkIrpPending(Irp);

  switch (DeviceExtension->InternalState)
  {
  case 0:
    DeviceExtension->InternalState = 1;
    break;
  case 1:
    DeviceExtension->InternalState = 2;
    Relations = (PDEVICE_RELATIONS)Irp->IoStatus.Information;
  
    for (i = 0; i < Relations->Count; i++)
    {
      Match = 0;
      for (j = 0; j < 2 && !Match; j++)
      {
        Length = sizeof(Buffer);
        if (j == 0)
          IoGetDeviceProperty(Relations->Objects[i], DevicePropertyCompatibleIDs, Length, Buffer, &Length);
        else
          IoGetDeviceProperty(Relations->Objects[i], DevicePropertyHardwareID, Length, Buffer, &Length);
        StrLen = 0;
        for (Ptr = Buffer; *Ptr != 0; Ptr += StrLen + 1)
        {
          // Qemu PCI
          if (XenHide_StringMatches(Ptr, L"PCI\\VEN_8086&DEV_7010")) {
            KdPrint((__DRIVER_NAME "     %ws\n", Ptr));
            Match = 1;
            break;
          }
          // Qemu Network
          if (XenHide_StringMatches(Ptr, L"PCI\\VEN_10EC&DEV_8139")) {
            KdPrint((__DRIVER_NAME "     %ws\n", Ptr));
            Match = 1;
            break;
          }
          RtlStringCchLengthW(Ptr, Length, &StrLen);
        }
      }
      if (Match)
      {
        KdPrint((__DRIVER_NAME "     Creating and attaching Device\n"));
        NewDeviceObject = NULL;
        status = IoCreateDevice(DeviceExtension->DriverObject,
          sizeof(DEVICE_EXTENSION),
          NULL,
          FILE_DEVICE_UNKNOWN,
          FILE_DEVICE_SECURE_OPEN,
          FALSE,
          &NewDeviceObject);
        if (!NT_SUCCESS(status))
        {
          KdPrint((__DRIVER_NAME "     IoCreateDevice failed 0x%08x\n", status));
          continue;
        }
  
        NewDeviceExtension = (PDEVICE_EXTENSION)NewDeviceObject->DeviceExtension;
        NewDeviceExtension->PhysicalDeviceObject = Relations->Objects[i];
        NewDeviceExtension->InternalState = 0;
        NewDeviceExtension->NextLowerDevice = IoAttachDeviceToDeviceStack(
          NewDeviceObject,
          Relations->Objects[i]);
        NewDeviceObject->Flags |= NewDeviceExtension->NextLowerDevice->Flags;
          
        NewDeviceObject->DeviceType = NewDeviceExtension->NextLowerDevice->DeviceType;
      
        NewDeviceObject->Characteristics = 
          NewDeviceExtension->NextLowerDevice->Characteristics;

//        IoInitializeRemoveLock(&NewDeviceExtension->RemoveLock, XENHIDE_POOL_TAG, 1, 100);
      
        NewDeviceExtension->Self = NewDeviceObject;
        NewDeviceExtension->Type = XENHIDE_TYPE_HIDE;
      
        NewDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
      }
    }
    break;
  default:
    break;
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS; //Irp->IoStatus.Status;
}

static NTSTATUS
XenHide_IoCompletionHideQueryPnpDeviceState(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Context);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  if (Irp->PendingReturned)
    IoMarkIrpPending(Irp);

  Irp->IoStatus.Information |= PNP_DEVICE_DONT_DISPLAY_IN_UI|PNP_DEVICE_DISABLED;

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return STATUS_SUCCESS;
}

static NTSTATUS
XenHide_IoCompletionPciQueryId(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
  PIO_STACK_LOCATION Stack;

  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Context);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  if (Irp->PendingReturned)
    IoMarkIrpPending(Irp);

  Stack = IoGetCurrentIrpStackLocation(Irp);

  switch (Stack->Parameters.QueryId.IdType)
  {
  case BusQueryDeviceID:
    KdPrint((__DRIVER_NAME "     IdType = BusQueryDeviceID\n"));
    KdPrint((__DRIVER_NAME "     %ws\n", Irp->IoStatus.Information));
    break;
  case BusQueryHardwareIDs:
    KdPrint((__DRIVER_NAME "     IdType = BusQueryHardwareIDs\n"));
    KdPrint((__DRIVER_NAME "     %ws\n", Irp->IoStatus.Information));
    break;
  case BusQueryCompatibleIDs:
    KdPrint((__DRIVER_NAME "     IdType = BusQueryCompatibleIDs\n"));
    KdPrint((__DRIVER_NAME "     %ws\n", Irp->IoStatus.Information));
    break;
  case BusQueryInstanceID:
    KdPrint((__DRIVER_NAME "     IdType = BusQueryInstanceID\n"));
    KdPrint((__DRIVER_NAME "     %ws\n", Irp->IoStatus.Information));
    break;
  default:
    KdPrint((__DRIVER_NAME "     IdType = %08x\n", Stack->Parameters.QueryId.IdType));
    KdPrint((__DRIVER_NAME "     %ws\n", Irp->IoStatus.Information));
    break;
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return STATUS_SUCCESS;
}

static NTSTATUS
XenHide_IoCompletionHideStartDevice(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Context);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  if (Irp->PendingReturned)
    IoMarkIrpPending(Irp);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return STATUS_SUCCESS;
}

static NTSTATUS
XenHide_Pass(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  PDEVICE_EXTENSION DeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
  NTSTATUS Status;

#if 0
  Status = IoAcquireRemoveLock (&DeviceExtension->RemoveLock, Irp);
  if (!NT_SUCCESS(Status)) {
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
  }
#endif
  IoSkipCurrentIrpStackLocation(Irp);
  Status = IoCallDriver(DeviceExtension->NextLowerDevice, Irp);
//  IoReleaseRemoveLock(&DeviceExtension->RemoveLock, Irp); 
  return Status;
}

static NTSTATUS
XenHide_Power(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  NTSTATUS Status = STATUS_SUCCESS;
  PDEVICE_EXTENSION DeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

//  Status = IoAcquireRemoveLock (&DeviceExtension->RemoveLock, Irp);
  if (!NT_SUCCESS(Status)) {
    Irp->IoStatus.Status = Status;
    PoStartNextPowerIrp(Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
  }

  PoStartNextPowerIrp(Irp);
  IoSkipCurrentIrpStackLocation(Irp);
  Status = PoCallDriver(DeviceExtension->NextLowerDevice, Irp);
//  IoReleaseRemoveLock(&DeviceExtension->RemoveLock, Irp); 
  return Status;
}

static NTSTATUS
XenHide_Pnp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  NTSTATUS Status = STATUS_SUCCESS;
  PIO_STACK_LOCATION Stack;
  PDEVICE_EXTENSION DeviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     DeviceObject = %p\n", DeviceObject));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

/*
  Status = IoAcquireRemoveLock (&DeviceExtension->RemoveLock, Irp);
  if (!NT_SUCCESS(Status)) {
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (returning with status %08x)\n", Status));
    return Status;
  }
*/
  Stack = IoGetCurrentIrpStackLocation(Irp);

  switch (Stack->MinorFunction)
  {
  case IRP_MN_START_DEVICE:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_START_DEVICE\n"));
    break;
  case IRP_MN_QUERY_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_QUERY_STOP_DEVICE\n"));
    break;
  case IRP_MN_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_STOP_DEVICE\n"));
    break;
  case IRP_MN_CANCEL_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_CANCEL_STOP_DEVICE\n"));
    break;
  case IRP_MN_QUERY_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_QUERY_REMOVE_DEVICE\n"));
    break;
  case IRP_MN_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_REMOVE_DEVICE\n"));
    break;
  case IRP_MN_CANCEL_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_CANCEL_REMOVE_DEVICE\n"));
    break;
  case IRP_MN_SURPRISE_REMOVAL:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_SURPRISE_REMOVAL\n"));
    break;
  case IRP_MN_QUERY_CAPABILITIES:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_QUERY_CAPABILITIES\n"));
    break;
  case IRP_MN_QUERY_PNP_DEVICE_STATE:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_QUERY_PNP_DEVICE_STATE\n"));
    break;
  case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_FILTER_RESOURCE_REQUIREMENTS\n"));
    break;
  case IRP_MN_DEVICE_USAGE_NOTIFICATION:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_DEVICE_USAGE_NOTIFICATION\n"));
    break;
  case IRP_MN_QUERY_DEVICE_RELATIONS:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_QUERY_DEVICE_RELATIONS\n"));
    break;
  case IRP_MN_QUERY_RESOURCES:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_QUERY_RESOURCES\n"));
    break;
  case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_QUERY_RESOURCE_REQUIREMENTS\n"));
    break;
  case IRP_MN_QUERY_ID:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_QUERY_ID\n"));
    break;
  case IRP_MN_QUERY_DEVICE_TEXT:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_QUERY_DEVICE_TEXT\n"));
    break;
  case IRP_MN_QUERY_BUS_INFORMATION:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_QUERY_BUS_INFORMATION\n"));
    break;
  case IRP_MN_QUERY_INTERFACE:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_QUERY_INTERFACE\n"));
    break;
  case IRP_MN_READ_CONFIG:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_READ_CONFIG\n"));
    break;
  case IRP_MN_WRITE_CONFIG:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_WRITE_CONFIG\n"));
    break;
  case IRP_MN_EJECT:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_EJECT\n"));
    break;
  case IRP_MN_SET_LOCK:
    KdPrint((__DRIVER_NAME "     MinorFunction = IRP_MN_SET_LOCK\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     MinorFunction = %02x\n", Stack->MinorFunction));
    break;
  }

  switch (DeviceExtension->Type)
  {
  case XENHIDE_TYPE_PCI:
    KdPrint((__DRIVER_NAME "     As PCI\n"));

    switch (Stack->MinorFunction) {
    case IRP_MN_QUERY_DEVICE_RELATIONS:
      KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_DEVICE_RELATIONS\n"));
      switch (Stack->Parameters.QueryDeviceRelations.Type)
      {
      case BusRelations:
        KdPrint((__DRIVER_NAME "       BusRelations\n"));
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, XenHide_IoCompletionPciQueryDeviceRelations, DeviceExtension, TRUE, TRUE, TRUE);
        break;
      default:
        IoSkipCurrentIrpStackLocation(Irp);
        break;  
      }
      break;
    case IRP_MN_QUERY_ID:
      IoCopyCurrentIrpStackLocationToNext(Irp);
      IoSetCompletionRoutine(Irp, XenHide_IoCompletionPciQueryId, DeviceExtension, TRUE, TRUE, TRUE);
      break;
    case IRP_MN_QUERY_CAPABILITIES:
    default:
      IoSkipCurrentIrpStackLocation(Irp);
      break;
    }
    Status = IoCallDriver(DeviceExtension->NextLowerDevice, Irp);
    break;
  case XENHIDE_TYPE_HIDE:
    KdPrint((__DRIVER_NAME "     As Hide\n"));
    switch (Stack->MinorFunction)
    {
/*
    case IRP_MN_START_DEVICE:
      IoCopyCurrentIrpStackLocationToNext(Irp);
      IoSetCompletionRoutine(Irp, XenHide_IoCompletionHideStartDevice, DeviceExtension, TRUE, TRUE, TRUE);
      IoCopyCurrentIrpStackLocationToNext(Irp);
      Stack = IoGetNextIrpStackLocation(Irp);
      Stack->Parameters.StartDevice.AllocatedResources = ExAllocatePoolWithTag(NonPagedPool, sizeof(CM_RESOURCE_LIST), XENHIDE_POOL_TAG);
      Stack->Parameters.StartDevice.AllocatedResources->Count = 1;
      Stack->Parameters.StartDevice.AllocatedResources->List[0].InterfaceType = Internal;
      Stack->Parameters.StartDevice.AllocatedResources->List[0].BusNumber = 0;
      Stack->Parameters.StartDevice.AllocatedResources->List[0].PartialResourceList.Version = 1;
      Stack->Parameters.StartDevice.AllocatedResources->List[0].PartialResourceList.Revision = 1;
      Stack->Parameters.StartDevice.AllocatedResources->List[0].PartialResourceList.Count = 0;
      Stack->Parameters.StartDevice.AllocatedResourcesTranslated = ExAllocatePoolWithTag(NonPagedPool, sizeof(CM_RESOURCE_LIST), XENHIDE_POOL_TAG);
      Stack->Parameters.StartDevice.AllocatedResourcesTranslated->Count = 1;
      Stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].InterfaceType = Internal;
      Stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].BusNumber = 0;
      Stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList.Version = 1;
      Stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList.Revision = 1;
      Stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList.Count = 0;
      break;
    case IRP_MN_QUERY_PNP_DEVICE_STATE:
      IoCopyCurrentIrpStackLocationToNext(Irp);
      IoSetCompletionRoutine(Irp, XenHide_IoCompletionHideQueryPnpDeviceState, DeviceExtension, TRUE, TRUE, TRUE);
      break;
*/
    case IRP_MN_QUERY_ID:
      switch (Stack->Parameters.QueryId.IdType)
      {
      case BusQueryDeviceID:
        KdPrint((__DRIVER_NAME "     BusQueryDeviceID\n"));
        break;
      case BusQueryHardwareIDs:
        KdPrint((__DRIVER_NAME "     BusQueryHardwareIDs\n"));
        break;
      case BusQueryCompatibleIDs:
        KdPrint((__DRIVER_NAME "     BusQueryCompatibleIDs\n"));
        break;
      case BusQueryInstanceID:
        KdPrint((__DRIVER_NAME "     BusQueryInstanceID\n"));
        break;
      default:
        KdPrint((__DRIVER_NAME "     %08x\n", Stack->Parameters.QueryId.IdType));
        break;
      }
      IoCopyCurrentIrpStackLocationToNext(Irp);
      IoSetCompletionRoutine(Irp, XenHide_IoCompletionPciQueryId, DeviceExtension, TRUE, TRUE, TRUE);
      break;
    default:
      IoSkipCurrentIrpStackLocation(Irp);
      break;
    }
    Status = IoCallDriver(DeviceExtension->NextLowerDevice, Irp);
    break;
  }

//  IoReleaseRemoveLock(&DeviceExtension->RemoveLock, Irp); 
  
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (returning with status %08x)\n", Status));

  return Status;
}
