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

#if 0
static PDRIVER_DISPATCH XenVbd_Pnp_Original;

static NTSTATUS
XenVbd_Pnp(PDEVICE_OBJECT device_object, PIRP irp)
{
  PIO_STACK_LOCATION stack;
  NTSTATUS status;
  PCM_RESOURCE_LIST old_crl, new_crl;
  ULONG i;
  PCM_PARTIAL_RESOURCE_LIST prl;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR prd;
  ULONG old_length, new_length;
  PMDL mdl;
  PUCHAR start, ptr;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stack = IoGetCurrentIrpStackLocation(irp);

  // check if the Irp is meant for us... maybe the stack->DeviceObject field?
  
  switch (stack->MinorFunction)
  {
  case IRP_MN_START_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_START_DEVICE - DeviceObject = %p\n", stack->DeviceObject));
    old_crl = stack->Parameters.StartDevice.AllocatedResourcesTranslated;
    if (old_crl != NULL)
    {
      mdl = AllocateUncachedPage();
      old_length = FIELD_OFFSET(CM_RESOURCE_LIST, List) + 
        FIELD_OFFSET(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList) +
        FIELD_OFFSET(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors) +
        sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * old_crl->List[0].PartialResourceList.Count;
      new_length = old_length + sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * 1;
      new_crl = ExAllocatePoolWithTag(PagedPool, new_length, XENVBD_POOL_TAG);
      memcpy(new_crl, old_crl, old_length);
      prl = &new_crl->List[0].PartialResourceList;
      prd = &prl->PartialDescriptors[prl->Count++];
      prd->Type = CmResourceTypeMemory;
      prd->ShareDisposition = CmResourceShareDeviceExclusive;
      prd->Flags = CM_RESOURCE_MEMORY_READ_WRITE; //|CM_RESOURCE_MEMORY_PREFETCHABLE; //|CM_RESOURCE_MEMORY_CACHEABLE;
      KdPrint((__DRIVER_NAME "     PFN[0] = %p\n", MmGetMdlPfnArray(mdl)[0]));
      prd->u.Memory.Start.QuadPart = MmGetMdlPfnArray(mdl)[0] << PAGE_SHIFT;
      prd->u.Memory.Length = PAGE_SIZE;
      KdPrint((__DRIVER_NAME "     Start = %08x:%08x, Length = %d\n", prd->u.Memory.Start.HighPart, prd->u.Memory.Start.LowPart, prd->u.Memory.Length));
      ptr = start = MmGetMdlVirtualAddress(mdl);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_RING, "ring-ref", NULL);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_EVENT_CHANNEL_IRQ, "event-channel", NULL);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_FRONT, "device-type", NULL);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_BACK, "sectors", NULL);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_BACK, "sector-size", NULL);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_VECTORS, NULL, NULL);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_GRANT_ENTRIES, NULL, UlongToPtr(GRANT_ENTRIES));
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_END, NULL, NULL);
      
      stack->Parameters.StartDevice.AllocatedResourcesTranslated = new_crl;

      old_crl = stack->Parameters.StartDevice.AllocatedResources;
      new_crl = ExAllocatePoolWithTag(PagedPool, new_length, XENVBD_POOL_TAG);
      memcpy(new_crl, old_crl, old_length);
      prl = &new_crl->List[0].PartialResourceList;
      prd = &prl->PartialDescriptors[prl->Count++];
      prd->Type = CmResourceTypeMemory;
      prd->ShareDisposition = CmResourceShareDeviceExclusive;
      prd->Flags = CM_RESOURCE_MEMORY_READ_WRITE|CM_RESOURCE_MEMORY_PREFETCHABLE|CM_RESOURCE_MEMORY_CACHEABLE;
      prd->u.Memory.Start.QuadPart = MmGetMdlPfnArray(mdl)[0] << PAGE_SHIFT;
      prd->u.Memory.Length = PAGE_SIZE;
      stack->Parameters.StartDevice.AllocatedResources = new_crl;
      IoCopyCurrentIrpStackLocationToNext(irp);
    }
    status = XenVbd_Pnp_Original(device_object, irp);

    break;
#if 0
  case IRP_MN_QUERY_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_STOP_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_STOP_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_CANCEL_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_STOP_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_QUERY_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_REMOVE_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_REMOVE_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_CANCEL_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_REMOVE_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_SURPRISE_REMOVAL:
    KdPrint((__DRIVER_NAME "     IRP_MN_SURPRISE_REMOVAL\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;
#endif

  default:
    //KdPrint((__DRIVER_NAME "     Unknown Minor = %d\n", stack->MinorFunction));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}
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
  

#if 0
  /* DriverObject will be NULL if we are being called in dump mode */
  if (DriverObject != NULL)
  {
    /* this is a bit naughty... */
    XenVbd_Pnp_Original = DriverObject->MajorFunction[IRP_MJ_PNP];
    DriverObject->MajorFunction[IRP_MJ_PNP] = XenVbd_Pnp;
  }
  else
    XenVbd_Pnp_Original = NULL;
#endif

  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME " ScsiPortInitialize failed with status 0x%08x\n", status));
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return status;
}
