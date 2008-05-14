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
XenPci_AddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject)
{
  NTSTATUS status;
  PDEVICE_OBJECT fdo = NULL;
/*
  WDF_CHILD_LIST_CONFIG config;
  WDF_OBJECT_ATTRIBUTES attributes;
  WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
  WDF_IO_QUEUE_CONFIG IoQConfig;
  WDF_INTERRUPT_CONFIG InterruptConfig;
*/
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

  xpdd = (PXENPCI_DEVICE_DATA)fdo->DeviceExtension;

  RtlZeroMemory(xpdd, sizeof(XENPCI_DEVICE_DATA));

  xpdd->common.fdo = fdo;
  xpdd->common.pdo = PhysicalDeviceObject;
  xpdd->common.lower_do = IoAttachDeviceToDeviceStack(fdo, PhysicalDeviceObject);
  if(xpdd->common.lower_do == NULL) {
    IoDeleteDevice(fdo);
    return STATUS_NO_SUCH_DEVICE;
  }
  InitializeListHead(&xpdd->child_list);

  fdo->Flags &= ~DO_DEVICE_INITIALIZING;

#if 0
  WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);
  WDF_CHILD_LIST_CONFIG_INIT(&config, sizeof(XENPCI_IDENTIFICATION_DESCRIPTION), XenPCI_ChildListCreateDevice);
  WdfFdoInitSetDefaultChildListConfig(DeviceInit, &config, WDF_NO_OBJECT_ATTRIBUTES);

  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
  pnpPowerCallbacks.EvtDevicePrepareHardware = XenPCI_PrepareHardware;
  pnpPowerCallbacks.EvtDeviceReleaseHardware = XenPCI_ReleaseHardware;
  pnpPowerCallbacks.EvtDeviceD0Entry = XenPCI_D0Entry;
  pnpPowerCallbacks.EvtDeviceD0EntryPostInterruptsEnabled
    = XenPCI_D0EntryPostInterruptsEnabled;
  pnpPowerCallbacks.EvtDeviceD0ExitPreInterruptsDisabled
    = XenPCI_D0ExitPreInterruptsDisabled;
  pnpPowerCallbacks.EvtDeviceD0Exit = XenPCI_D0Exit;
  WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

  WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);

  Status = WdfDeviceInitAssignName(DeviceInit, &DeviceName);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceInitAssignName failed 0x%08x\n", Status));
    return Status;
  }

  /*initialize storage for the device context*/
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, XENPCI_DEVICE_DATA);

  /*create a device instance.*/
  Status = WdfDeviceCreate(&DeviceInit, &attributes, &Device);  
  if(!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreate failed with Status 0x%08x\n", Status));
    return Status;
  }
  xpdd = GetDeviceData(Device);
  xpdd->Device = Device;

  WdfDeviceSetSpecialFileSupport(Device, WdfSpecialFilePaging, TRUE);
  WdfDeviceSetSpecialFileSupport(Device, WdfSpecialFileHibernation, TRUE);
  WdfDeviceSetSpecialFileSupport(Device, WdfSpecialFileDump, TRUE);

  Status = IoGetDeviceInterfaces(&GUID_XENHIDE_IFACE, NULL, 0, &InterfaceList);
  if (!NT_SUCCESS(Status) || InterfaceList == NULL || *InterfaceList == 0)
  {
    AutoEnumerate = FALSE;
    KdPrint((__DRIVER_NAME "     XenHide not loaded or GPLPV not specified\n", Status));
  }
  else
  {
    AutoEnumerate = TRUE;
    KdPrint((__DRIVER_NAME "     XenHide loaded and GPLPV specified\n", Status));
  }

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
  KeInitializeGuardedMutex(&xpdd->WatchHandlerMutex);
#endif
  busInfo.BusTypeGuid = GUID_XENPCI_DEVCLASS;
  busInfo.LegacyBusType = Internal;
  busInfo.BusNumber = 0;

  WdfDeviceSetBusInformationForChildren(Device, &busInfo);

  WDF_INTERRUPT_CONFIG_INIT(&InterruptConfig, EvtChn_Interrupt, NULL);
  InterruptConfig.EvtInterruptEnable = XenPCI_InterruptEnable;
  InterruptConfig.EvtInterruptDisable = XenPCI_InterruptDisable;
  Status = WdfInterruptCreate(Device, &InterruptConfig, WDF_NO_OBJECT_ATTRIBUTES, &xpdd->XenInterrupt);
  if (!NT_SUCCESS (Status))
  {
    KdPrint((__DRIVER_NAME "     WdfInterruptCreate failed 0x%08x\n", Status));
    return Status;
  }

  Status = WdfDeviceCreateDeviceInterface(Device, (LPGUID)&GUID_XEN_IFACE, NULL);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreateDeviceInterface failed 0x%08x\n", Status));
    return Status;
  }
  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&IoQConfig, WdfIoQueueDispatchSequential);
  IoQConfig.EvtIoDefault = XenPCI_IoDefault;

  Status = WdfIoQueueCreate(Device, &IoQConfig, WDF_NO_OBJECT_ATTRIBUTES, NULL);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfIoQueueCreate failed 0x%08x\n", Status));
    return Status;
  }

  WDF_IO_QUEUE_CONFIG_INIT(&IoQConfig, WdfIoQueueDispatchSequential);
  IoQConfig.EvtIoRead = XenPCI_IoRead;

  Status = WdfIoQueueCreate(Device, &IoQConfig, WDF_NO_OBJECT_ATTRIBUTES, &ReadQueue);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfIoQueueCreate (ReadQueue) failed 0x%08x\n", Status));
    return Status;
  }

  WdfIoQueueStopSynchronously(ReadQueue);
  WdfDeviceConfigureRequestDispatching(Device, ReadQueue, WdfRequestTypeRead);

  Status = WdfDeviceCreateSymbolicLink(Device, &SymbolicName);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreateSymbolicLink failed 0x%08x\n", Status));
    return Status;
  }
#endif

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
  DriverObject->MajorFunction[IRP_MJ_CREATE] = NULL; //XenPci_Dummy;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = NULL; //XenPci_Dummy;
  DriverObject->MajorFunction[IRP_MJ_CLEANUP] = NULL; //XenPci_Dummy;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NULL; //XenPci_Dummy;
  DriverObject->MajorFunction[IRP_MJ_READ] = NULL; //XenPci_Dummy;
  DriverObject->MajorFunction[IRP_MJ_WRITE] = NULL; //XenPci_Dummy;
  DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = NULL; //XenPci_Dummy;

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return status;
}