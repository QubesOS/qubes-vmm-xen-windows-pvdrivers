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

#include "XenStub.h"
#include <stdlib.h>

DRIVER_INITIALIZE DriverEntry;
static NTSTATUS
XenStub_AddDevice(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit);
static NTSTATUS
XenStub_PrepareHardware(WDFDEVICE hDevice, WDFCMRESLIST Resources, WDFCMRESLIST ResourcesTranslated);
static NTSTATUS
XenStub_ReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated);
static NTSTATUS
XenStub_D0Entry(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState);
static NTSTATUS
XenStub_D0Exit(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, XenStub_AddDevice)
#endif

#pragma warning(disable : 4200) // zero-sized array

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  WDF_DRIVER_CONFIG config;
  NTSTATUS status;

  KdPrint((__DRIVER_NAME " --> DriverEntry\n"));

  WDF_DRIVER_CONFIG_INIT(&config, XenStub_AddDevice);
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
XenStub_AddDevice(
    IN WDFDRIVER Driver,
    IN PWDFDEVICE_INIT DeviceInit
    )
{
  NTSTATUS Status;
  WDF_OBJECT_ATTRIBUTES attributes;
  WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
  WDFDEVICE Device;

  UNREFERENCED_PARAMETER(Driver);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
  pnpPowerCallbacks.EvtDevicePrepareHardware = XenStub_PrepareHardware;
  pnpPowerCallbacks.EvtDeviceReleaseHardware = XenStub_ReleaseHardware;
  pnpPowerCallbacks.EvtDeviceD0Entry = XenStub_D0Entry;
  pnpPowerCallbacks.EvtDeviceD0Exit = XenStub_D0Exit;
  WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

  WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

  Status = WdfDeviceCreate(&DeviceInit, &attributes, &Device);  
  if(!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreate failed with Status 0x%08x\n", Status));
    return Status;
  }

  KdPrint((__DRIVER_NAME " <-- DeviceAdd\n"));
  return Status;
}

static NTSTATUS
XenStub_PrepareHardware(
  WDFDEVICE Device,
  WDFCMRESLIST ResourceList,
  WDFCMRESLIST ResourceListTranslated)
{
  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(ResourceList);
  UNREFERENCED_PARAMETER(ResourceListTranslated);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}

static NTSTATUS
XenStub_ReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)
{
  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(ResourcesTranslated);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}

static NTSTATUS
XenStub_D0Entry(
  WDFDEVICE Device,
  WDF_POWER_DEVICE_STATE PreviousState
  )
{
  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(PreviousState);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}

static NTSTATUS
XenStub_D0Exit(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState)
{
  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(TargetState);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}
