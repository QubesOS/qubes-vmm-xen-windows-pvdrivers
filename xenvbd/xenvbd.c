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

#include "xenvbd.h"
#include <io/blkif.h>
#include <scsi.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <stdlib.h>
#include <xen_public.h>
#include <io/xenbus.h>
#include <io/protocols.h>

#pragma warning(disable: 4127)

DRIVER_INITIALIZE DriverEntry;

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  ULONG status;
  HW_INITIALIZATION_DATA HwInitializationData;

  KdPrint((__DRIVER_NAME " --> "__FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  RtlZeroMemory(&HwInitializationData, sizeof(HW_INITIALIZATION_DATA));

  HwInitializationData.HwInitializationDataSize = sizeof(HW_INITIALIZATION_DATA);
  HwInitializationData.AdapterInterfaceType = Internal;
  HwInitializationData.DeviceExtensionSize = sizeof(XENVBD_DEVICE_DATA);
  HwInitializationData.SpecificLuExtensionSize = 0;
  /* SrbExtension is not always aligned to a page boundary, so we add PAGE_SIZE-1 to it to make sure we have at least UNALIGNED_DOUBLE_BUFFER_SIZE bytes of page aligned memory */
  HwInitializationData.SrbExtensionSize = UNALIGNED_DOUBLE_BUFFER_SIZE + PAGE_SIZE - 1;
  HwInitializationData.NumberOfAccessRanges = 1;
  HwInitializationData.MapBuffers = TRUE;
  HwInitializationData.NeedPhysicalAddresses = FALSE;
  HwInitializationData.TaggedQueuing = FALSE;
  HwInitializationData.AutoRequestSense = TRUE;
  HwInitializationData.MultipleRequestPerLu = TRUE;
  HwInitializationData.ReceiveEvent = FALSE;
  HwInitializationData.VendorIdLength = 0;
  HwInitializationData.VendorId = NULL;
  HwInitializationData.DeviceIdLength = 0;
  HwInitializationData.DeviceId = NULL;

  XenVbd_FillInitCallbacks(&HwInitializationData);

  status = ScsiPortInitialize(DriverObject, RegistryPath, &HwInitializationData, NULL);
  
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME " ScsiPortInitialize failed with status 0x%08x\n", status));
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return status;
}
