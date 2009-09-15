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

#include "xenusb.h"

static BOOLEAN
XenUsb_ExecuteRequestCallback(
  WDFDMATRANSACTION dma_transaction,
  WDFDEVICE device,
  PVOID context,
  WDF_DMA_DIRECTION direction,
  PSCATTER_GATHER_LIST sg_list)
{
  usbif_shadow_t *shadow = context;
  PXENUSB_DEVICE_DATA xudd = GetXudd(device);
  ULONG i;
  int notify;
  KIRQL old_irql;

  UNREFERENCED_PARAMETER(direction);
  UNREFERENCED_PARAMETER(dma_transaction);

  //FUNCTION_ENTER();

  shadow->req.buffer_length = 0;
  for (i = 0; i < sg_list->NumberOfElements; i++)
  {
    shadow->req.seg[i].gref = (grant_ref_t)(sg_list->Elements->Address.QuadPart >> PAGE_SHIFT);
    shadow->req.seg[i].offset = (USHORT)sg_list->Elements->Address.LowPart & (PAGE_SIZE - 1);
    shadow->req.seg[i].length = (USHORT)sg_list->Elements->Length;
    shadow->req.buffer_length = shadow->req.buffer_length + (USHORT)sg_list->Elements->Length;
  }
  shadow->req.nr_buffer_segs = (USHORT)sg_list->NumberOfElements;
  //KdPrint((__DRIVER_NAME "     buffer_length = %d\n", shadow->req.buffer_length));
  //KdPrint((__DRIVER_NAME "     nr_buffer_segs = %d\n", shadow->req.nr_buffer_segs));

  KeAcquireSpinLock(&xudd->ring_lock, &old_irql);
  *RING_GET_REQUEST(&xudd->ring, xudd->ring.req_prod_pvt) = shadow->req;
  xudd->ring.req_prod_pvt++;
  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xudd->ring, notify);
  if (notify)
  {
    //KdPrint((__DRIVER_NAME "     Notifying\n"));
    xudd->vectors.EvtChn_Notify(xudd->vectors.context, xudd->event_channel);
  }
  KeReleaseSpinLock(&xudd->ring_lock, old_irql);

  //FUNCTION_EXIT();
  
  return TRUE;
}

NTSTATUS
XenUsb_ExecuteRequest(
 PXENUSB_DEVICE_DATA xudd,
 usbif_shadow_t *shadow,
 PVOID transfer_buffer,
 PMDL transfer_buffer_mdl,
 ULONG transfer_buffer_length)
{
  NTSTATUS status;
  KIRQL old_irql;
  PMDL mdl;
  int notify;
  
  //FUNCTION_ENTER();
  
  //KdPrint((__DRIVER_NAME "     transfer_buffer_length = %d\n", transfer_buffer_length));
  shadow->total_length = 0;
  if (!transfer_buffer_length)
  {
    shadow->mdl = NULL;
    shadow->dma_transaction = NULL;
    shadow->req.nr_buffer_segs = 0;
    shadow->req.buffer_length = 0;

    KeAcquireSpinLock(&xudd->ring_lock, &old_irql);
    *RING_GET_REQUEST(&xudd->ring, xudd->ring.req_prod_pvt) = shadow->req;
    xudd->ring.req_prod_pvt++;
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xudd->ring, notify);
    if (notify)
    {
      //KdPrint((__DRIVER_NAME "     Notifying\n"));
      xudd->vectors.EvtChn_Notify(xudd->vectors.context, xudd->event_channel);
    }
    KeReleaseSpinLock(&xudd->ring_lock, old_irql);
    //FUNCTION_EXIT();
    return STATUS_SUCCESS;
  }
  ASSERT(transfer_buffer || transfer_buffer_mdl);
  if (transfer_buffer)
  {
    mdl = IoAllocateMdl(transfer_buffer, transfer_buffer_length, FALSE, FALSE, NULL);
    ASSERT(mdl);
    MmBuildMdlForNonPagedPool(mdl);
    shadow->mdl = mdl;
  }
  else
  {
    if (!MmGetMdlVirtualAddress(transfer_buffer_mdl))
    {
      /* WdfDmaTransactionInitialize has a bug where it crashes on VirtualAddress == 0 */
      PVOID addr = MmGetSystemAddressForMdlSafe(transfer_buffer_mdl, LowPagePriority);
      //KdPrint((__DRIVER_NAME "     Mapping MDL with NULL VA to work around bug in WdfDmaTransactionInitialize\n"));
      if (!addr)
      {
        KdPrint((__DRIVER_NAME "     Could not map MDL\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
      }
      mdl = IoAllocateMdl(addr, transfer_buffer_length, FALSE, FALSE, NULL);
      ASSERT(mdl);
      MmBuildMdlForNonPagedPool(mdl);
      shadow->mdl = mdl;
    }
    else
    {
      mdl = transfer_buffer_mdl;
      shadow->mdl = NULL;
    }
  }
  status = WdfDmaTransactionCreate(xudd->dma_enabler, WDF_NO_OBJECT_ATTRIBUTES, &shadow->dma_transaction);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfDmaTransactionCreate status = %08x\n", status));
    if (shadow->mdl)
    {
      IoFreeMdl(shadow->mdl);
    }
    FUNCTION_EXIT();
    return status;
  }

  ASSERT(shadow->dma_transaction);  
  ASSERT(mdl);
  ASSERT(transfer_buffer_length);

  status = WdfDmaTransactionInitialize(
    shadow->dma_transaction,
    XenUsb_ExecuteRequestCallback,
    (shadow->req.pipe & LINUX_PIPE_DIRECTION_IN)?WdfDmaDirectionReadFromDevice:WdfDmaDirectionWriteToDevice,
    mdl,
    MmGetMdlVirtualAddress(mdl),
    transfer_buffer_length);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfDmaTransactionInitialize status = %08x\n", status));
    WdfObjectDelete(shadow->dma_transaction);
    if (shadow->mdl)
    {
      IoFreeMdl(shadow->mdl);
    }
    //FUNCTION_EXIT();
    return status;
  }
  WdfDmaTransactionSetMaximumLength(shadow->dma_transaction, (USBIF_MAX_SEGMENTS_PER_REQUEST - 1) * PAGE_SIZE);
  status = WdfDmaTransactionExecute(shadow->dma_transaction, shadow);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfDmaTransactionExecute status = %08x\n", status));
    WdfObjectDelete(shadow->dma_transaction);
    if (shadow->mdl)
    {
      IoFreeMdl(shadow->mdl);
    }
    //FUNCTION_EXIT();
    return status;
  }
  //FUNCTION_EXIT();
  return status;
}

NTSTATUS
XenUsb_EvtDeviceQueryRemove(WDFDEVICE device)
{
  //PXENUSB_DEVICE_DATA xudd = GetXudd(device);
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(device);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenUsb_EvtDeviceWdmIrpPreprocessQUERY_INTERFACE(WDFDEVICE device, PIRP irp)
{
  PIO_STACK_LOCATION stack;
 
  FUNCTION_ENTER();
 
  stack = IoGetCurrentIrpStackLocation(irp);

  if (memcmp(stack->Parameters.QueryInterface.InterfaceType, &USB_BUS_INTERFACE_HUB_GUID, sizeof(GUID)) == 0)
    KdPrint((__DRIVER_NAME "     USB_BUS_INTERFACE_HUB_GUID\n"));
  else if (memcmp(stack->Parameters.QueryInterface.InterfaceType, &USB_BUS_INTERFACE_USBDI_GUID, sizeof(GUID)) == 0)
    KdPrint((__DRIVER_NAME "     USB_BUS_INTERFACE_USBDI_GUID\n"));
  else
    KdPrint((__DRIVER_NAME "     GUID = %08X-%04X-%04X-%04X-%02X%02X%02X%02X%02X%02X\n",
      stack->Parameters.QueryInterface.InterfaceType->Data1,
      stack->Parameters.QueryInterface.InterfaceType->Data2,
      stack->Parameters.QueryInterface.InterfaceType->Data3,
      (stack->Parameters.QueryInterface.InterfaceType->Data4[0] << 8) |
       stack->Parameters.QueryInterface.InterfaceType->Data4[1],
      stack->Parameters.QueryInterface.InterfaceType->Data4[2],
      stack->Parameters.QueryInterface.InterfaceType->Data4[3],
      stack->Parameters.QueryInterface.InterfaceType->Data4[4],
      stack->Parameters.QueryInterface.InterfaceType->Data4[5],
      stack->Parameters.QueryInterface.InterfaceType->Data4[6],
      stack->Parameters.QueryInterface.InterfaceType->Data4[7]));

  KdPrint((__DRIVER_NAME "     Size = %d\n", stack->Parameters.QueryInterface.Size));
  KdPrint((__DRIVER_NAME "     Version = %d\n", stack->Parameters.QueryInterface.Version));
  KdPrint((__DRIVER_NAME "     Interface = %p\n", stack->Parameters.QueryInterface.Interface));


  IoSkipCurrentIrpStackLocation(irp);
  
  FUNCTION_EXIT();

  return WdfDeviceWdmDispatchPreprocessedIrp(device, irp);
}

/* called at DISPATCH_LEVEL */
static BOOLEAN
XenUsb_HandleEvent(PVOID context)
{
  PXENUSB_DEVICE_DATA xudd = context;
  RING_IDX prod, cons;
  usbif_response_t *rsp;
  int more_to_do = TRUE;
  usbif_shadow_t *complete_head = NULL, *complete_tail = NULL;
  usbif_shadow_t *shadow;

  //FUNCTION_ENTER();

  KeAcquireSpinLockAtDpcLevel(&xudd->ring_lock);
  while (more_to_do)
  {
    prod = xudd->ring.sring->rsp_prod;
    KeMemoryBarrier();
    for (cons = xudd->ring.rsp_cons; cons != prod; cons++)
    {
      rsp = RING_GET_RESPONSE(&xudd->ring, cons);
      shadow = &xudd->shadows[rsp->id];
      ASSERT(shadow->callback);
      shadow->rsp = *rsp;
      shadow->next = NULL;
      shadow->total_length += rsp->actual_length;
#if 0
      KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
      KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
      KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
      KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
      KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));
      KdPrint((__DRIVER_NAME "     total_length = %d\n", shadow->total_length));
#endif
      if (complete_tail)
      {
        complete_tail->next = shadow;
      }
      else
      {
        complete_head = shadow;
      }
      complete_tail = shadow;
    }

    xudd->ring.rsp_cons = cons;
    if (cons != xudd->ring.req_prod_pvt)
    {
      RING_FINAL_CHECK_FOR_RESPONSES(&xudd->ring, more_to_do);
    }
    else
    {
      xudd->ring.sring->rsp_event = cons + 1;
      more_to_do = FALSE;
    }
  }
  KeReleaseSpinLockFromDpcLevel(&xudd->ring_lock);

  shadow = complete_head;
  while (shadow != NULL)
  {
    if (shadow->dma_transaction)
    {
      NTSTATUS status;
      BOOLEAN dma_complete;
      if (shadow->rsp.status != 0 || shadow->rsp.actual_length != shadow->req.buffer_length)
      {
        WdfDmaTransactionDmaCompletedFinal(shadow->dma_transaction, shadow->total_length, &status);
        WdfObjectDelete(shadow->dma_transaction);
        if (shadow->mdl)
        {
          IoFreeMdl(shadow->mdl);
        }
        shadow->callback(shadow);
      }
      else
      {
        dma_complete = WdfDmaTransactionDmaCompleted(shadow->dma_transaction, &status);
        if (dma_complete)
        {
          WdfObjectDelete(shadow->dma_transaction);
          if (shadow->mdl)
          {
            IoFreeMdl(shadow->mdl);
          }
          shadow->callback(shadow);
        }
      }
    }
    else
    {
      shadow->callback(shadow);
    }
    shadow = shadow->next;
  }
  //FUNCTION_EXIT();

  return TRUE;
}

static NTSTATUS
XenUsb_StartXenbusInit(PXENUSB_DEVICE_DATA xudd)
{
  PUCHAR ptr;
  USHORT type;
  PCHAR setting, value, value2;

  xudd->sring = NULL;
  xudd->event_channel = 0;

  xudd->inactive = TRUE;
  ptr = xudd->config_page;
  while((type = GET_XEN_INIT_RSP(&ptr, (PVOID)&setting, (PVOID)&value, (PVOID)&value2)) != XEN_INIT_TYPE_END)
  {
    switch(type)
    {
    case XEN_INIT_TYPE_READ_STRING_BACK:
    case XEN_INIT_TYPE_READ_STRING_FRONT:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = %s\n", setting, value));
      break;
    case XEN_INIT_TYPE_VECTORS:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_VECTORS\n"));
      if (((PXENPCI_VECTORS)value)->length != sizeof(XENPCI_VECTORS) ||
        ((PXENPCI_VECTORS)value)->magic != XEN_DATA_MAGIC)
      {
        KdPrint((__DRIVER_NAME "     vectors mismatch (magic = %08x, length = %d)\n",
          ((PXENPCI_VECTORS)value)->magic, ((PXENPCI_VECTORS)value)->length));
        KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
        return STATUS_UNSUCCESSFUL;
      }
      else
        memcpy(&xudd->vectors, value, sizeof(XENPCI_VECTORS));
      break;
    case XEN_INIT_TYPE_STATE_PTR:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_DEVICE_STATE - %p\n", PtrToUlong(value)));
      xudd->device_state = (PXENPCI_DEVICE_STATE)value;
      break;
    case XEN_INIT_TYPE_ACTIVE:
      xudd->inactive = FALSE;
      break;
#if 0
    case XEN_INIT_TYPE_GRANT_ENTRIES:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_GRANT_ENTRIES - entries = %d\n", PtrToUlong(setting)));
      memcpy(xudd->dump_grant_refs, value, PtrToUlong(setting) * sizeof(grant_ref_t));
      break;
#endif
    default:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_%d\n", type));
      break;
    }
  }

  return STATUS_SUCCESS;
}

static NTSTATUS
XenUsb_CompleteXenbusInit(PXENUSB_DEVICE_DATA xudd)
{
  PUCHAR ptr;
  USHORT type;
  PCHAR setting, value, value2;

  ptr = xudd->config_page;
  while((type = GET_XEN_INIT_RSP(&ptr, (PVOID)&setting, (PVOID)&value, (PVOID)&value2)) != XEN_INIT_TYPE_END)
  {
    switch(type)
    {
    case XEN_INIT_TYPE_RING: /* frontend ring */
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_RING - %s = %p\n", setting, value));
      if (strcmp(setting, "ring-ref") == 0)
      {
        xudd->sring = (usbif_sring_t *)value;
        FRONT_RING_INIT(&xudd->ring, xudd->sring, PAGE_SIZE);
      }
      break;
    case XEN_INIT_TYPE_EVENT_CHANNEL_DPC: /* frontend event channel */
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_EVENT_CHANNEL_DPC - %s = %d\n", setting, PtrToUlong(value) & 0x3FFFFFFF));
      if (strcmp(setting, "event-channel") == 0)
      {
        xudd->event_channel = PtrToUlong(value);
      }
      break;
    case XEN_INIT_TYPE_READ_STRING_BACK:
    case XEN_INIT_TYPE_READ_STRING_FRONT:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = %s\n", setting, value));
      break;
    default:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_%d\n", type));
      break;
    }
  }
  if (!xudd->inactive && (xudd->sring == NULL || xudd->event_channel == 0))
  {
    KdPrint((__DRIVER_NAME "     Missing settings\n"));
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
    return STATUS_UNSUCCESSFUL;
  }
  
  if (xudd->inactive)
  {
    KdPrint((__DRIVER_NAME "     Device is inactive\n"));
  }
  else
  {
    ULONG i;
    xudd->shadow_free = 0;
    memset(xudd->shadows, 0, sizeof(usbif_shadow_t) * SHADOW_ENTRIES);
    for (i = 0; i < SHADOW_ENTRIES; i++)
    {
      xudd->shadows[i].id = (uint16_t)i;
      put_shadow_on_freelist(xudd, &xudd->shadows[i]);
    }
  }
  
  return STATUS_SUCCESS;
}

NTSTATUS
XenUsb_EvtDevicePrepareHardware(WDFDEVICE device, WDFCMRESLIST resources_raw, WDFCMRESLIST resources_translated)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENUSB_DEVICE_DATA xudd = GetXudd(device);
  PCM_PARTIAL_RESOURCE_DESCRIPTOR raw_descriptor, translated_descriptor;
  ULONG i;
  PUCHAR ptr;

  FUNCTION_ENTER();
  
  ASSERT(WdfCmResourceListGetCount(resources_raw) == WdfCmResourceListGetCount(resources_translated));
  
  for (i = 0; i < WdfCmResourceListGetCount(resources_raw); i++)
  {
    raw_descriptor = WdfCmResourceListGetDescriptor(resources_raw, i);
    translated_descriptor = WdfCmResourceListGetDescriptor(resources_translated, i);
    switch (raw_descriptor->Type) {
    case CmResourceTypePort:
      KdPrint((__DRIVER_NAME "     IoPort Address(%x) Length: %d\n", translated_descriptor->u.Port.Start.LowPart, translated_descriptor->u.Port.Length));
      break;
    case CmResourceTypeMemory:
      KdPrint((__DRIVER_NAME "     Memory (%x:%x) Length:(%d)\n", translated_descriptor->u.Memory.Start.LowPart, translated_descriptor->u.Memory.Start.HighPart, translated_descriptor->u.Memory.Length));
      KdPrint((__DRIVER_NAME "     Memory flags = %04X\n", translated_descriptor->Flags));
      xudd->config_page = MmMapIoSpace(translated_descriptor->u.Memory.Start, translated_descriptor->u.Memory.Length, MmNonCached);
      KdPrint((__DRIVER_NAME "     Memory mapped to %p\n", xudd->config_page));
      break;
    case CmResourceTypeInterrupt:
      KdPrint((__DRIVER_NAME "     irq_number = %03x\n", raw_descriptor->u.Interrupt.Vector));
      KdPrint((__DRIVER_NAME "     irq_vector = %03x\n", translated_descriptor->u.Interrupt.Vector));
      KdPrint((__DRIVER_NAME "     irq_level = %03x\n", translated_descriptor->u.Interrupt.Level));
      break;
    case CmResourceTypeDevicePrivate:
      KdPrint((__DRIVER_NAME "     Private Data: 0x%02x 0x%02x 0x%02x\n", translated_descriptor->u.DevicePrivate.Data[0], translated_descriptor->u.DevicePrivate.Data[1], translated_descriptor->u.DevicePrivate.Data[2]));
      break;
    default:
      KdPrint((__DRIVER_NAME "     Unhandled resource type (0x%x)\n", translated_descriptor->Type));
      break;
    }
  }

  status = XenUsb_StartXenbusInit(xudd);

  ptr = xudd->config_page;
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_RUN, NULL, NULL, NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_RING, "ring-ref", NULL, NULL);
  #pragma warning(suppress:4054)
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_EVENT_CHANNEL_DPC, "event-channel", (PVOID)XenUsb_HandleEvent, xudd);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_END, NULL, NULL, NULL);
  status = xudd->vectors.XenPci_XenConfigDevice(xudd->vectors.context);

  status = XenUsb_CompleteXenbusInit(xudd);
  
  FUNCTION_EXIT();

  return status;
}

NTSTATUS
XenUsb_EvtDeviceD0Entry(WDFDEVICE device, WDF_POWER_DEVICE_STATE previous_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  //PXENUSB_DEVICE_DATA xudd = GetXudd(device);

  UNREFERENCED_PARAMETER(device);

  FUNCTION_ENTER();

  switch (previous_state)
  {
  case WdfPowerDeviceD0:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD1:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD2:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD2\n"));
    break;
  case WdfPowerDeviceD3:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3\n"));
    break;
  case WdfPowerDeviceD3Final:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3Final\n"));
    break;
  case WdfPowerDevicePrepareForHibernation:
    KdPrint((__DRIVER_NAME "     WdfPowerDevicePrepareForHibernation\n"));
    break;  
  default:
    KdPrint((__DRIVER_NAME "     Unknown WdfPowerDevice state %d\n", previous_state));
    break;  
  }

  FUNCTION_EXIT();

  return status;
}

NTSTATUS
XenUsb_EvtDeviceD0EntryPostInterruptsEnabled(WDFDEVICE device, WDF_POWER_DEVICE_STATE previous_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  //PXENUSB_DEVICE_DATA xudd = GetXudd(device);

  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(previous_state);

  FUNCTION_ENTER();
  
  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenUsb_EvtDeviceD0ExitPreInterruptsDisabled(WDFDEVICE device, WDF_POWER_DEVICE_STATE target_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  
  UNREFERENCED_PARAMETER(device);
  
  FUNCTION_ENTER();
  
  switch (target_state)
  {
  case WdfPowerDeviceD0:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD1:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD2:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD2\n"));
    break;
  case WdfPowerDeviceD3:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3\n"));
    break;
  case WdfPowerDeviceD3Final:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3Final\n"));
    break;
  case WdfPowerDevicePrepareForHibernation:
    KdPrint((__DRIVER_NAME "     WdfPowerDevicePrepareForHibernation\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unknown WdfPowerDevice state %d\n", target_state));
    break;  
  }
  
  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenUsb_EvtDeviceD0Exit(WDFDEVICE device, WDF_POWER_DEVICE_STATE target_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  //PXENUSB_DEVICE_DATA xudd = GetXudd(device);
  
  FUNCTION_ENTER();

  UNREFERENCED_PARAMETER(device);

  switch (target_state)
  {
  case WdfPowerDeviceD0:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD1:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD2:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD2\n"));
    break;
  case WdfPowerDeviceD3:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3\n"));
    break;
  case WdfPowerDeviceD3Final:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3Final\n"));
    break;
  case WdfPowerDevicePrepareForHibernation:
    KdPrint((__DRIVER_NAME "     WdfPowerDevicePrepareForHibernation\n"));
    break;  
  default:
    KdPrint((__DRIVER_NAME "     Unknown WdfPowerDevice state %d\n", target_state));
    break;  
  }
  
  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenUsb_EvtDeviceReleaseHardware(WDFDEVICE device, WDFCMRESLIST resources_translated)
{
  NTSTATUS status = STATUS_SUCCESS;
  
  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(resources_translated);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  
  return status;
}

#if 0
VOID
XenUsb_PrepareShadow(usbif_shadow_t *shadow, PVOID setup_packet, ULONG data_length)
{
}
#endif

VOID
XenUsb_EvtChildListScanForChildren(WDFCHILDLIST child_list)
{
  NTSTATUS status;
  PXENUSB_DEVICE_DATA xudd = GetXudd(WdfChildListGetDevice(child_list));
  XENUSB_PDO_IDENTIFICATION_DESCRIPTION child_description;
  CHAR path[128];
  PCHAR err;
  PCHAR value;
  ULONG i;

  FUNCTION_ENTER();

  WdfChildListBeginScan(child_list);

  // hold the queue on each device and set each device to a pending state
  // read backend/num_ports
  RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/num-ports", xudd->vectors.backend_path);
  err = xudd->vectors.XenBus_Read(xudd->vectors.context, XBT_NIL, path, &value);
  if (err)
  {
    XenPci_FreeMem(err);
    WdfChildListEndScan(child_list);
    KdPrint((__DRIVER_NAME "     Failed to read num-ports\n"));
    return;
  }
  xudd->num_ports = (ULONG)parse_numeric_string(value);  
  XenPci_FreeMem(value);
  KdPrint((__DRIVER_NAME "     num-ports = %d\n", xudd->num_ports));

  for (i = 0; i < 8; i++)
  {
    xudd->ports[i].port_number = i + 1;
    xudd->ports[i].port_type = USB_PORT_TYPE_NOT_CONNECTED;
    xudd->ports[i].port_status = 0x0002;
    xudd->ports[i].port_change = 0x0000;
  }  

  /* only a single root hub is enumerated */
  WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(&child_description.header, sizeof(child_description));

  child_description.device_number = 0; //TODO: get the proper index from parent

  status = WdfChildListAddOrUpdateChildDescriptionAsPresent(child_list, &child_description.header, NULL);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfChildListAddOrUpdateChildDescriptionAsPresent failed with status 0x%08x\n", status));
  }

  WdfChildListEndScan(child_list);
  
  FUNCTION_EXIT();
}

static VOID
XenUsb_EvtIoDeviceControl(
  WDFQUEUE queue,
  WDFREQUEST request,
  size_t output_buffer_length,
  size_t input_buffer_length,
  ULONG io_control_code)
{
  NTSTATUS status;
  WDFDEVICE device = WdfIoQueueGetDevice(queue);
  PXENUSB_DEVICE_DATA xudd = GetXudd(device);
  //WDF_REQUEST_PARAMETERS wrp;
  //PURB urb;
  //xenusb_device_t *usb_device;

  UNREFERENCED_PARAMETER(queue);
  UNREFERENCED_PARAMETER(input_buffer_length);
  UNREFERENCED_PARAMETER(output_buffer_length);

  FUNCTION_ENTER();

  status = STATUS_UNSUCCESSFUL;

  //WDF_REQUEST_PARAMETERS_INIT(&wrp);
  //WdfRequestGetParameters(request, &wrp);

  // these are in api\usbioctl.h
  switch(io_control_code)
  {
#if 0
  case IOCTL_USB_GET_NODE_INFORMATION:
  {
    PUSB_NODE_INFORMATION uni;
    size_t length;
    
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_INFORMATION\n"));
    KdPrint((__DRIVER_NAME "      output_buffer_length = %d\n", output_buffer_length));
    // make sure size is >= bDescriptorLength
    status = WdfRequestRetrieveOutputBuffer(request, output_buffer_length, (PVOID *)&uni, &length);
    if (NT_SUCCESS(status))
    {
      switch(uni->NodeType)
      {
      case UsbHub:
        KdPrint((__DRIVER_NAME "      NodeType = UsbHub\n"));
        uni->u.HubInformation.HubDescriptor.bDescriptorLength = FIELD_OFFSET(USB_HUB_DESCRIPTOR, bRemoveAndPowerMask) + 3;
        if (output_buffer_length >= FIELD_OFFSET(USB_NODE_INFORMATION, u.HubInformation.HubDescriptor.bRemoveAndPowerMask) + 3)
        {
          uni->u.HubInformation.HubDescriptor.bDescriptorType = 0x29;
          uni->u.HubInformation.HubDescriptor.bNumberOfPorts = 8;
          uni->u.HubInformation.HubDescriptor.wHubCharacteristics = 0x0012; // no power switching no overcurrent protection
          uni->u.HubInformation.HubDescriptor.bPowerOnToPowerGood = 1; // 2ms units
          uni->u.HubInformation.HubDescriptor.bHubControlCurrent = 0;
          // DeviceRemovable bits (includes an extra bit at the start)
          uni->u.HubInformation.HubDescriptor.bRemoveAndPowerMask[0] = 0;
          uni->u.HubInformation.HubDescriptor.bRemoveAndPowerMask[1] = 0;
          // PortPwrCtrlMask
          uni->u.HubInformation.HubDescriptor.bRemoveAndPowerMask[2] = 0xFF;
          uni->u.HubInformation.HubIsBusPowered = TRUE;
        }
        WdfRequestSetInformation(request, FIELD_OFFSET(USB_NODE_INFORMATION, u.HubInformation.HubDescriptor.bRemoveAndPowerMask) + 3);
        break;
      case UsbMIParent:
        KdPrint((__DRIVER_NAME "      NodeType = UsbMIParent\n"));
        status = STATUS_UNSUCCESSFUL;
        break;
      }
    }
    else
    {
      KdPrint((__DRIVER_NAME "     WdfRequestRetrieveOutputBuffer = %08x\n", status));
    }    
    break;
  }
#endif
  case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_CONNECTION_INFORMATION\n"));
    break;
  case IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION\n"));
    break;
  case IOCTL_USB_GET_NODE_CONNECTION_NAME:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_CONNECTION_NAME\n"));
    break;
  case IOCTL_USB_DIAG_IGNORE_HUBS_ON:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_DIAG_IGNORE_HUBS_ON\n"));
    break;
  case IOCTL_USB_DIAG_IGNORE_HUBS_OFF:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_DIAG_IGNORE_HUBS_OFF\n"));
    break;
  case IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME\n"));
    break;
  case IOCTL_USB_GET_HUB_CAPABILITIES:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_HUB_CAPABILITIES\n"));
    break;
  case IOCTL_USB_HUB_CYCLE_PORT:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_HUB_CYCLE_PORT\n"));
    break;
  case IOCTL_USB_GET_NODE_CONNECTION_ATTRIBUTES:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_CONNECTION_ATTRIBUTES\n"));
    break;
  case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX\n"));
    break;
  case IOCTL_USB_GET_ROOT_HUB_NAME:
  {
    PUSB_HCD_DRIVERKEY_NAME uhdn;
    size_t length;
    
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_ROOT_HUB_NAME\n"));
    KdPrint((__DRIVER_NAME "      output_buffer_length = %d\n", output_buffer_length));
      
    if (output_buffer_length < sizeof(USB_HCD_DRIVERKEY_NAME))
      status = STATUS_INSUFFICIENT_RESOURCES;
    else
    {
      status = WdfRequestRetrieveOutputBuffer(request, output_buffer_length, (PVOID *)&uhdn, &length);
      if (NT_SUCCESS(status))
      {
        WDFSTRING symbolic_link_wdfstring;
        UNICODE_STRING symbolic_link;
        
        uhdn->DriverKeyName[0] = 0;
        status = WdfStringCreate(NULL, WDF_NO_OBJECT_ATTRIBUTES, &symbolic_link_wdfstring);
        status = WdfDeviceRetrieveDeviceInterfaceString(xudd->root_hub_device, &GUID_DEVINTERFACE_USB_HUB, NULL, symbolic_link_wdfstring);
        if (NT_SUCCESS(status))
        {
          WdfStringGetUnicodeString(symbolic_link_wdfstring, &symbolic_link);
          /* remove leading \??\ from name */
          symbolic_link.Buffer += 4;
          symbolic_link.Length -= 4 * sizeof(WCHAR);
          uhdn->ActualLength = FIELD_OFFSET(USB_HCD_DRIVERKEY_NAME, DriverKeyName) + symbolic_link.Length + sizeof(WCHAR);
          if (output_buffer_length >= uhdn->ActualLength)
          {
            memcpy(uhdn->DriverKeyName, symbolic_link.Buffer, symbolic_link.Length);
            uhdn->DriverKeyName[symbolic_link.Length / 2] = 0;
          }
        }
        else
        {
          KdPrint((__DRIVER_NAME "     WdfDeviceRetrieveDeviceInterfaceString = %08x\n", status));
          status = STATUS_INVALID_PARAMETER;
        }
      }
      else
      {
        KdPrint((__DRIVER_NAME "     WdfRequestRetrieveOutputBuffer = %08x\n", status));
      }
      KdPrint((__DRIVER_NAME "      uhdn->ActualLength = %d\n", uhdn->ActualLength));
      KdPrint((__DRIVER_NAME "      uhdn->DriverKeyName = %S\n", uhdn->DriverKeyName));
      WdfRequestSetInformation(request, uhdn->ActualLength);
    }
    break;
  }
  case IOCTL_GET_HCD_DRIVERKEY_NAME:
  {
    PUSB_HCD_DRIVERKEY_NAME uhdn;
    size_t length;
    
    KdPrint((__DRIVER_NAME "     IOCTL_GET_HCD_DRIVERKEY_NAME\n"));
    KdPrint((__DRIVER_NAME "      output_buffer_length = %d\n", output_buffer_length));
      
    if (output_buffer_length < sizeof(USB_HCD_DRIVERKEY_NAME))
      status = STATUS_INSUFFICIENT_RESOURCES;
    else
    {
      status = WdfRequestRetrieveOutputBuffer(request, output_buffer_length, (PVOID *)&uhdn, &length);
      if (NT_SUCCESS(status))
      {
        ULONG key_length;
        status = WdfDeviceQueryProperty(device, DevicePropertyDriverKeyName, 0, NULL, &key_length);
        status = STATUS_SUCCESS;
        uhdn->ActualLength = FIELD_OFFSET(USB_HCD_DRIVERKEY_NAME, DriverKeyName) + key_length;
        if (output_buffer_length >= uhdn->ActualLength)
        {
          status = WdfDeviceQueryProperty(device, DevicePropertyDriverKeyName, 
            uhdn->ActualLength - FIELD_OFFSET(USB_HCD_DRIVERKEY_NAME, DriverKeyName), uhdn->DriverKeyName,
            &key_length);
        }
        else
        {
          uhdn->DriverKeyName[0] = 0;
        }
      }
      else
      {
        KdPrint((__DRIVER_NAME "     WdfRequestRetrieveOutputBuffer = %08x\n", status));
      }
      KdPrint((__DRIVER_NAME "      uhdn->ActualLength = %d\n", uhdn->ActualLength));
      KdPrint((__DRIVER_NAME "      uhdn->DriverKeyName = %S\n", uhdn->DriverKeyName));
      WdfRequestSetInformation(request, uhdn->ActualLength);
    }
    break;
  }
#if 0
  case IOCTL_USB_RESET_HUB:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_RESET_HUB\n"));
    break;
#endif
  default:
    KdPrint((__DRIVER_NAME "     Unknown IOCTL %08x\n", io_control_code));
    break;
  }
  KdPrint((__DRIVER_NAME "     Calling WdfRequestComplete with status = %08x\n", status));
  WdfRequestComplete(request, status);

  FUNCTION_EXIT();
}

static VOID
XenUsb_EvtIoInternalDeviceControl(
  WDFQUEUE queue,
  WDFREQUEST request,
  size_t output_buffer_length,
  size_t input_buffer_length,
  ULONG io_control_code)
{
  WDFDEVICE device = WdfIoQueueGetDevice(queue);
  PXENUSB_DEVICE_DATA xudd = GetXudd(device);

  UNREFERENCED_PARAMETER(input_buffer_length);
  UNREFERENCED_PARAMETER(output_buffer_length);

  FUNCTION_ENTER();

  switch(io_control_code)
  {
  case IOCTL_XEN_RECONFIGURE:
    KdPrint((__DRIVER_NAME "     IOCTL_XEN_RECONFIGURE\n"));
    // TODO: Only enumerate once the root hub callback has been called...
    XenUsb_EnumeratePorts(xudd->root_hub_device);
    KdPrint((__DRIVER_NAME "     Completing\n"));
    WdfRequestComplete(request, STATUS_SUCCESS);
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unknown IOCTL %08x\n", io_control_code));
    WdfRequestComplete(request, WdfRequestGetStatus(request));
    break;
  }

  FUNCTION_EXIT();
}

static VOID
XenUsb_EvtIoDefault(
  WDFQUEUE queue,
  WDFREQUEST request)
{
  NTSTATUS status;
  WDF_REQUEST_PARAMETERS parameters;

  FUNCTION_ENTER();

  UNREFERENCED_PARAMETER(queue);

  status = STATUS_UNSUCCESSFUL;

  WDF_REQUEST_PARAMETERS_INIT(&parameters);
  WdfRequestGetParameters(request, &parameters);

  switch (parameters.Type)
  {
  case WdfRequestTypeCreate:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeCreate\n"));
    break;
  case WdfRequestTypeClose:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeClose\n"));
    break;
  case WdfRequestTypeRead:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeRead\n"));
    break;
  case WdfRequestTypeWrite:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeWrite\n"));
    break;
  case WdfRequestTypeDeviceControl:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeDeviceControl\n"));
    
    break;
  case WdfRequestTypeDeviceControlInternal:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeDeviceControlInternal\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unknown type %x\n", parameters.Type));
    break;
  }
  WdfRequestComplete(request, status);  

  FUNCTION_EXIT();
}

NTSTATUS
XenUsb_EvtDriverDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT device_init)
{
  NTSTATUS status;
  WDF_CHILD_LIST_CONFIG child_list_config;
  WDFDEVICE device;
  PXENUSB_DEVICE_DATA xudd;
  //UNICODE_STRING reference;
  WDF_OBJECT_ATTRIBUTES device_attributes;
  PNP_BUS_INFORMATION pbi;
  WDF_PNPPOWER_EVENT_CALLBACKS pnp_power_callbacks;
  WDF_DEVICE_POWER_CAPABILITIES power_capabilities;
  WDF_IO_QUEUE_CONFIG queue_config;
  WDF_DMA_ENABLER_CONFIG dma_config;
  UCHAR pnp_minor_functions[] = { IRP_MN_QUERY_INTERFACE };
  
  UNREFERENCED_PARAMETER(driver);

  FUNCTION_ENTER();

  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp_power_callbacks);
  pnp_power_callbacks.EvtDeviceD0Entry = XenUsb_EvtDeviceD0Entry;
  pnp_power_callbacks.EvtDeviceD0EntryPostInterruptsEnabled = XenUsb_EvtDeviceD0EntryPostInterruptsEnabled;
  pnp_power_callbacks.EvtDeviceD0Exit = XenUsb_EvtDeviceD0Exit;
  pnp_power_callbacks.EvtDeviceD0ExitPreInterruptsDisabled = XenUsb_EvtDeviceD0ExitPreInterruptsDisabled;
  pnp_power_callbacks.EvtDevicePrepareHardware = XenUsb_EvtDevicePrepareHardware;
  pnp_power_callbacks.EvtDeviceReleaseHardware = XenUsb_EvtDeviceReleaseHardware;
  pnp_power_callbacks.EvtDeviceQueryRemove = XenUsb_EvtDeviceQueryRemove;
  //pnp_power_callbacks.EvtDeviceUsageNotification = XenUsb_EvtDeviceUsageNotification;

  WdfDeviceInitSetPnpPowerEventCallbacks(device_init, &pnp_power_callbacks);

  status = WdfDeviceInitAssignWdmIrpPreprocessCallback(device_init, XenUsb_EvtDeviceWdmIrpPreprocessQUERY_INTERFACE,
    IRP_MJ_PNP, pnp_minor_functions, ARRAY_SIZE(pnp_minor_functions));
  if (!NT_SUCCESS(status))
  {
    return status;
  }

  WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_BUS_EXTENDER);
  WdfDeviceInitSetExclusive(device_init, FALSE);

  WDF_CHILD_LIST_CONFIG_INIT(&child_list_config, sizeof(XENUSB_PDO_IDENTIFICATION_DESCRIPTION), XenUsb_EvtChildListCreateDevice);
  child_list_config.EvtChildListScanForChildren = XenUsb_EvtChildListScanForChildren;
  WdfFdoInitSetDefaultChildListConfig(device_init, &child_list_config, WDF_NO_OBJECT_ATTRIBUTES);

  WdfDeviceInitSetIoType(device_init, WdfDeviceIoBuffered);

  WdfDeviceInitSetPowerNotPageable(device_init);
  
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&device_attributes, XENUSB_DEVICE_DATA);
  status = WdfDeviceCreate(&device_init, &device_attributes, &device);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Error creating device %08x\n", status));
    return status;
  }

  xudd = GetXudd(device);
  xudd->child_list = WdfFdoGetDefaultChildList(device);

  KeInitializeSpinLock(&xudd->ring_lock);
  
  WdfDeviceSetAlignmentRequirement(device, 0);
  WDF_DMA_ENABLER_CONFIG_INIT(&dma_config, WdfDmaProfileScatterGather64Duplex, PAGE_SIZE);
  status = WdfDmaEnablerCreate(device, &dma_config, WDF_NO_OBJECT_ATTRIBUTES, &xudd->dma_enabler);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Error creating DMA enabler %08x\n", status));
    return status;
  }

  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config, WdfIoQueueDispatchParallel);
  queue_config.EvtIoDeviceControl = XenUsb_EvtIoDeviceControl;
  queue_config.EvtIoInternalDeviceControl = XenUsb_EvtIoInternalDeviceControl;
  queue_config.EvtIoDefault = XenUsb_EvtIoDefault;
  status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, &xudd->io_queue);
  if (!NT_SUCCESS(status)) {
      KdPrint((__DRIVER_NAME "     Error creating io_queue 0x%x\n", status));
      return status;
  }

  WDF_DEVICE_POWER_CAPABILITIES_INIT(&power_capabilities);
  power_capabilities.DeviceD1 = WdfTrue;
  power_capabilities.WakeFromD1 = WdfTrue;
  power_capabilities.DeviceWake = PowerDeviceD1;
  power_capabilities.DeviceState[PowerSystemWorking]   = PowerDeviceD1;
  power_capabilities.DeviceState[PowerSystemSleeping1] = PowerDeviceD1;
  power_capabilities.DeviceState[PowerSystemSleeping2] = PowerDeviceD2;
  power_capabilities.DeviceState[PowerSystemSleeping3] = PowerDeviceD2;
  power_capabilities.DeviceState[PowerSystemHibernate] = PowerDeviceD3;
  power_capabilities.DeviceState[PowerSystemShutdown]  = PowerDeviceD3;
  WdfDeviceSetPowerCapabilities(device, &power_capabilities);  

  WdfDeviceSetSpecialFileSupport(device, WdfSpecialFilePaging, TRUE);
  WdfDeviceSetSpecialFileSupport(device, WdfSpecialFileHibernation, TRUE);
  WdfDeviceSetSpecialFileSupport(device, WdfSpecialFileDump, TRUE);
  
  pbi.BusTypeGuid = GUID_BUS_TYPE_XEN;
  pbi.LegacyBusType = PNPBus;
  pbi.BusNumber = 0;
  WdfDeviceSetBusInformationForChildren(device, &pbi);

  status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_USB_HOST_CONTROLLER, NULL);
  if (!NT_SUCCESS(status))
    return status;

  //status = WdfDeviceOpenRegistryKey(device, 
  
  FUNCTION_EXIT();
  return status;
}
