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


typedef struct {
  LIST_ENTRY entry;
  PVOID data;
  ULONG length;
  ULONG offset;
} xenbus_read_queue_item_t;

typedef struct
{
  LIST_ENTRY entry;
  CHAR path[128];
  CHAR token[128];
  WDFFILEOBJECT file_object;
} watch_context_t;

VOID
XenPci_EvtDeviceFileCreate(WDFDEVICE device, WDFREQUEST request, WDFFILEOBJECT file_object)
{
  NTSTATUS status;
  PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
  WDF_IO_QUEUE_CONFIG queue_config;
  
  FUNCTION_ENTER();
  
  xpdid->type = DEVICE_INTERFACE_TYPE_XENBUS;
  KeInitializeSpinLock(&xpdid->lock);
  InitializeListHead(&xpdid->read_list_head);
  InitializeListHead(&xpdid->watch_list_head);
  xpdid->len = 0;
  WDF_IO_QUEUE_CONFIG_INIT(&queue_config, WdfIoQueueDispatchManual);
  //queue_config.EvtIoRead = XenPci_EvtIoRead;
  status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, &xpdid->io_queue);
  if (!NT_SUCCESS(status)) {
      KdPrint(("Error creating queue 0x%x\n", status));
      WdfRequestComplete(request, STATUS_UNSUCCESSFUL);
  }
  //WdfIoQueueStop(xpdid->io_queue, NULL, NULL);

  WdfRequestComplete(request, STATUS_SUCCESS);
  
  FUNCTION_EXIT();
}

VOID
XenPci_ProcessReadRequest(WDFQUEUE queue, WDFREQUEST request, size_t length)
{
  NTSTATUS status;
  WDFFILEOBJECT file_object = WdfRequestGetFileObject(request);
  PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
  ULONG dst_length = length;
  ULONG dst_offset = 0;
  ULONG copy_length;
  xenbus_read_queue_item_t *list_entry;
  PVOID buffer;

  UNREFERENCED_PARAMETER(queue);
  
  status = WdfRequestRetrieveOutputBuffer(request, length, &buffer, NULL);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME, "     WdfRequestRetrieveOutputBuffer failed status = %08x\n", status));
    WdfRequestSetInformation(request, 0);
    return;
  }
  ASSERT(NT_SUCCESS(status)); // lazy?

  while(dst_offset < dst_length && (list_entry = (xenbus_read_queue_item_t *)RemoveHeadList(&xpdid->read_list_head)) != (xenbus_read_queue_item_t *)&xpdid->read_list_head)
  {
    copy_length = min(list_entry->length - list_entry->offset, dst_length - dst_offset);
    memcpy((PUCHAR)buffer + dst_offset, (PUCHAR)list_entry->data + list_entry->offset, copy_length);
    list_entry->offset += copy_length;
    dst_offset += copy_length;
    if (list_entry->offset == list_entry->length)
    {
      // free the list entry
      // free the data
    }
    else
    {
      InsertHeadList(&xpdid->read_list_head, (PLIST_ENTRY)list_entry);
    }      
  }
  WdfRequestSetInformation(request, dst_offset);
  
  FUNCTION_EXIT();
}

static VOID
XenPci_IoWatch(char *path, PVOID context)
{
  NTSTATUS status;
  watch_context_t *watch_context = context;
  WDFFILEOBJECT file_object = watch_context->file_object;
  PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
  KIRQL old_irql;
  struct xsd_sockmsg *rep;
  xenbus_read_queue_item_t *list_entry;
  WDFREQUEST request;

  FUNCTION_ENTER();
  
  KeAcquireSpinLock(&xpdid->lock, &old_irql);
  
  rep = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct xsd_sockmsg) + strlen(path) + 1 + strlen(watch_context->token) + 1, XENPCI_POOL_TAG);
  rep->type = XS_WATCH_EVENT;
  rep->req_id = 0;
  rep->tx_id = 0;
  rep->len = strlen(path) + 1 + strlen(watch_context->token) + 1;
  strcpy((PCHAR)(rep + 1), path);
  strcpy((PCHAR)(rep + 1) + strlen(path) + 1, watch_context->token);
  
  list_entry = (xenbus_read_queue_item_t *)ExAllocatePoolWithTag(NonPagedPool, sizeof(xenbus_read_queue_item_t), XENPCI_POOL_TAG);
  list_entry->data = rep;
  list_entry->length = sizeof(*rep) + rep->len;
  list_entry->offset = 0;
  InsertTailList(&xpdid->read_list_head, (PLIST_ENTRY)list_entry);
    
  status = WdfIoQueueRetrieveNextRequest(xpdid->io_queue, &request);
  if (NT_SUCCESS(status))
  {
    WDF_REQUEST_PARAMETERS parameters;
    WDF_REQUEST_PARAMETERS_INIT(&parameters);
    WdfRequestGetParameters(request, &parameters);
    
    KdPrint((__DRIVER_NAME "     found pending read - MinorFunction = %d, length = %d\n", (ULONG)parameters.MinorFunction, (ULONG)parameters.Parameters.Read.Length));
    XenPci_ProcessReadRequest(xpdid->io_queue, request, parameters.Parameters.Read.Length);
    KeReleaseSpinLock(&xpdid->lock, old_irql);
    WdfRequestComplete(request, STATUS_SUCCESS);
  }
  else
  {
    KdPrint((__DRIVER_NAME "     no pending read (%08x)\n", status));
    KeReleaseSpinLock(&xpdid->lock, old_irql);
  }
  
  FUNCTION_EXIT();
}

VOID
XenPci_EvtFileCleanup(WDFFILEOBJECT file_object)
{
  PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(WdfFileObjectGetDevice(file_object));
  watch_context_t *watch_context;
  KIRQL old_irql;
  PCHAR msg;

  FUNCTION_ENTER();

  KeAcquireSpinLock(&xpdid->lock, &old_irql);

  while (!IsListEmpty(&xpdid->watch_list_head))
  {
    watch_context = (watch_context_t *)RemoveHeadList(&xpdid->watch_list_head);
    KeReleaseSpinLock(&xpdid->lock, old_irql);
    msg = XenBus_RemWatch(xpdd, XBT_NIL, watch_context->path, XenPci_IoWatch, watch_context);
    if (msg != NULL)
    {
      KdPrint((__DRIVER_NAME "     Error freeing watch (%s)\n", msg));
      XenPci_FreeMem(msg);
    }
    ExFreePoolWithTag(watch_context, XENPCI_POOL_TAG);
    WdfObjectDereference(file_object);
    KeAcquireSpinLock(&xpdid->lock, &old_irql);
  }

  KeReleaseSpinLock(&xpdid->lock, old_irql);
  
  FUNCTION_EXIT();
}

VOID
XenPci_EvtFileClose(WDFFILEOBJECT file_object)
{
  UNREFERENCED_PARAMETER(file_object);
  FUNCTION_ENTER();
  FUNCTION_EXIT();
}

VOID
XenPci_EvtIoRead(WDFQUEUE queue, WDFREQUEST request, size_t length)
{
  NTSTATUS status;
  WDFFILEOBJECT file_object = WdfRequestGetFileObject(request);
  PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
  KIRQL old_irql;

  FUNCTION_ENTER();
  status = WdfRequestForwardToIoQueue(request, xpdid->io_queue);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     could not forward request (%08x)\n", status));
  }
  KeAcquireSpinLock(&xpdid->lock, &old_irql);
  if (!IsListEmpty(&xpdid->read_list_head))
  {
    status = WdfIoQueueRetrieveNextRequest(xpdid->io_queue, &request);
    if (NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     found pending read\n"));
      XenPci_ProcessReadRequest(xpdid->io_queue, request, length);
      KeReleaseSpinLock(&xpdid->lock, old_irql);
      WdfRequestComplete(request, STATUS_SUCCESS);
    }
    else
    {
      KdPrint((__DRIVER_NAME "     no pending read (%08x)\n", status));
      KeReleaseSpinLock(&xpdid->lock, old_irql);
    }
  }
  else
  {
    KdPrint((__DRIVER_NAME "     no data to read\n"));
    KeReleaseSpinLock(&xpdid->lock, old_irql);
  }
  
  FUNCTION_EXIT();
  return;
}

VOID
XenPci_EvtIoWrite(WDFQUEUE queue, WDFREQUEST request, size_t length)
{
  NTSTATUS status;
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(WdfIoQueueGetDevice(queue));
  WDFFILEOBJECT file_object = WdfRequestGetFileObject(request);
  PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
  KIRQL old_irql;
  PUCHAR buffer;
  PUCHAR src_ptr;
  ULONG src_len;
  PUCHAR dst_ptr;
  ULONG copy_len;
  struct xsd_sockmsg *rep;
  xenbus_read_queue_item_t *list_entry;
  watch_context_t *watch_context;
  PCHAR watch_path;
  PCHAR watch_token;
  PCHAR msg;
  
  FUNCTION_ENTER();
  
  status = WdfRequestRetrieveInputBuffer(request, length, &buffer, NULL);
  ASSERT(NT_SUCCESS(status));
  
  src_ptr = (PUCHAR)buffer;
  src_len = length;
  dst_ptr = xpdid->u.buffer + xpdid->len;
  while (src_len != 0)
  {
    KdPrint((__DRIVER_NAME "     %d bytes of write buffer remaining\n", src_len));
    /* get a complete msg header */
    if (xpdid->len < sizeof(xpdid->u.msg))
    {
      copy_len = min(sizeof(xpdid->u.msg) - xpdid->len, src_len);
      if (!copy_len)
        continue;
      memcpy(dst_ptr, src_ptr, copy_len);
      dst_ptr += copy_len;
      src_ptr += copy_len;
      src_len -= copy_len;
      xpdid->len += copy_len;
    }
    /* exit if we can't get that */
    if (xpdid->len < sizeof(xpdid->u.msg))
      continue;
    /* get a complete msg body */
    if (xpdid->len < sizeof(xpdid->u.msg) + xpdid->u.msg.len)
    {
      copy_len = min(sizeof(xpdid->u.msg) + xpdid->u.msg.len - xpdid->len, src_len);
      if (!copy_len)
        continue;
      memcpy(dst_ptr, src_ptr, copy_len);
      dst_ptr += copy_len;
      src_ptr += copy_len;
      src_len -= copy_len;
      xpdid->len += copy_len;
    }
    /* exit if we can't get that */
    if (xpdid->len < sizeof(xpdid->u.msg) + xpdid->u.msg.len)
    {
      continue;
    }
    
    switch (xpdid->u.msg.type)
    {
    case XS_WATCH:
    case XS_UNWATCH:
      KeAcquireSpinLock(&xpdid->lock, &old_irql);
      watch_context = (watch_context_t *)ExAllocatePoolWithTag(NonPagedPool, sizeof(watch_context_t), XENPCI_POOL_TAG);
      watch_path = xpdid->u.buffer + sizeof(struct xsd_sockmsg);
      watch_token = xpdid->u.buffer + sizeof(struct xsd_sockmsg) + strlen(watch_path) + 1;
      strcpy(watch_context->path, watch_path);
      strcpy(watch_context->token, watch_token);
      watch_context->file_object = file_object;
      if (xpdid->u.msg.type == XS_WATCH)
        InsertTailList(&xpdid->watch_list_head, &watch_context->entry);
      KeReleaseSpinLock(&xpdid->lock, old_irql);
      if (xpdid->u.msg.type == XS_WATCH)
        msg = XenBus_AddWatch(xpdd, XBT_NIL, watch_path, XenPci_IoWatch, watch_context);
      else
        msg = XenBus_RemWatch(xpdd, XBT_NIL, watch_path, XenPci_IoWatch, watch_context);
      KeAcquireSpinLock(&xpdid->lock, &old_irql);
      if (msg != NULL)
      {
        rep = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct xsd_sockmsg) + strlen(msg) + 1, XENPCI_POOL_TAG);
        rep->type = XS_ERROR;
        rep->req_id = xpdid->u.msg.req_id;
        rep->tx_id = xpdid->u.msg.tx_id;
        rep->len = strlen(msg) + 0;
        strcpy((PCHAR)(rep + 1), msg);
        if (xpdid->u.msg.type == XS_WATCH)
          RemoveEntryList(&watch_context->entry);
      }
      else
      {
        if (xpdid->u.msg.type == XS_WATCH)
        {
          WdfObjectReference(file_object);
        }
        else
        {
          RemoveEntryList(&watch_context->entry);
          WdfObjectDereference(file_object);
        }
        rep = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct xsd_sockmsg), XENPCI_POOL_TAG);
        rep->type = xpdid->u.msg.type;
        rep->req_id = xpdid->u.msg.req_id;
        rep->tx_id = xpdid->u.msg.tx_id;
        rep->len = 0;
      }
      KeReleaseSpinLock(&xpdid->lock, old_irql);
      break;
    default:
      rep = XenBus_Raw(xpdd, &xpdid->u.msg);
      break;
    }
    xpdid->len = 0;
    
    KeAcquireSpinLock(&xpdid->lock, &old_irql);
    list_entry = (xenbus_read_queue_item_t *)ExAllocatePoolWithTag(NonPagedPool, sizeof(xenbus_read_queue_item_t), XENPCI_POOL_TAG);
    list_entry->data = rep;
    list_entry->length = sizeof(*rep) + rep->len;
    list_entry->offset = 0;
    InsertTailList(&xpdid->read_list_head, (PLIST_ENTRY)list_entry);
    KeReleaseSpinLock(&xpdid->lock, old_irql);
  }
  KdPrint((__DRIVER_NAME "     completing request with length %d\n", length));
  WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, length);

  FUNCTION_EXIT();
}

#if 0
NTSTATUS
XenPci_Irp_Create_XenBus(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PFILE_OBJECT file;
  device_interface_xenbus_context_t *dixc;
  
  FUNCTION_ENTER();
  
  UNREFERENCED_PARAMETER(device_object);
  stack = IoGetCurrentIrpStackLocation(irp);
  file = stack->FileObject;
  dixc = (device_interface_xenbus_context_t *)ExAllocatePoolWithTag(NonPagedPool, sizeof(device_interface_xenbus_context_t), XENPCI_POOL_TAG);
  dixc->type = DEVICE_INTERFACE_TYPE_XENBUS;
  KeInitializeSpinLock(&dixc->lock);
  InitializeListHead(&dixc->read_list_head);
  dixc->len = 0;
  file->FsContext = dixc;
  status = STATUS_SUCCESS;    
  dixc->pending_read_irp = NULL;
  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  
  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenPci_Irp_Close_XenBus(PDEVICE_OBJECT device_object, PIRP irp)
{
  PXENPCI_DEVICE_DATA xpdd;
  NTSTATUS status;

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  status = STATUS_SUCCESS;    
  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  // cleanup dixc here
  
  return status;
}

static NTSTATUS
XenPci_Irp_Read_XenBus_Complete(device_interface_xenbus_context_t *dixc, PIRP irp)
{
  KIRQL old_irql;
  ULONG dst_length;
  ULONG dst_offset;
  ULONG copy_length;
  xenbus_read_queue_item_t *list_entry;
  PIO_STACK_LOCATION stack;
  NTSTATUS status;

  FUNCTION_ENTER();
  
KdPrint((__DRIVER_NAME "     A - dixc = %p, irp = %p\n", dixc, irp));
  stack = IoGetCurrentIrpStackLocation(irp);
KdPrint((__DRIVER_NAME "     Aa\n"));
  dst_length = stack->Parameters.Read.Length;
KdPrint((__DRIVER_NAME "     B - dst_length = %d\n", dst_length));
  dst_offset = 0;
KdPrint((__DRIVER_NAME "     C\n"));
  KeAcquireSpinLock(&dixc->lock, &old_irql);
KdPrint((__DRIVER_NAME "     D"));
  while(dst_offset < dst_length && (list_entry = (xenbus_read_queue_item_t *)RemoveHeadList(&dixc->read_list_head)) != (xenbus_read_queue_item_t *)&dixc->read_list_head)
  {
KdPrint((__DRIVER_NAME "     E\n"));
    copy_length = min(list_entry->length - list_entry->offset, dst_length - dst_offset);
    KdPrint((__DRIVER_NAME "     copying %d bytes\n", copy_length));
    memcpy((PUCHAR)irp->AssociatedIrp.SystemBuffer + dst_offset, (PUCHAR)list_entry->data + list_entry->offset, copy_length);
    list_entry->offset += copy_length;
    dst_offset += copy_length;
    if (list_entry->offset == list_entry->length)
    {
      // free the list entry
      // free the data
    }
    else
    {
      InsertHeadList(&dixc->read_list_head, (PLIST_ENTRY)list_entry);
    }      
  }
  KeReleaseSpinLock(&dixc->lock, old_irql);
KdPrint((__DRIVER_NAME "     F\n"));
  
  if (dst_offset > 0)
  {
    KdPrint((__DRIVER_NAME "     completing request\n"));
    status = STATUS_SUCCESS;
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = dst_offset;
    IoSetCancelRoutine(irp, NULL);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
  }
  else
  {
    KdPrint((__DRIVER_NAME "     pending request\n"));
    status = STATUS_PENDING;
  }

  FUNCTION_EXIT();

  return status;
}

static VOID
XenPci_Irp_Read_Cancel(PDEVICE_OBJECT device_object, PIRP irp)
{
  PIO_STACK_LOCATION stack;
  PFILE_OBJECT file;
  device_interface_xenbus_context_t *dixc;
  KIRQL old_irql;

  FUNCTION_ENTER();

  UNREFERENCED_PARAMETER(device_object);

  stack = IoGetCurrentIrpStackLocation(irp);
  file = stack->FileObject;
  dixc = file->FsContext;
  IoReleaseCancelSpinLock(irp->CancelIrql);
  KeAcquireSpinLock(&dixc->lock, &old_irql);
  if (irp != dixc->pending_read_irp)
  {
    KdPrint((__DRIVER_NAME "     Not the current irp???\n"));
  }
  dixc->pending_read_irp = NULL;
  irp->IoStatus.Status = STATUS_CANCELLED;
  irp->IoStatus.Information = 0;
  KeReleaseSpinLock(&dixc->lock, old_irql);
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  FUNCTION_EXIT();
}

NTSTATUS
XenPci_Irp_Read_XenBus(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PFILE_OBJECT file;
  device_interface_xenbus_context_t *dixc;
  KIRQL old_irql;

  UNREFERENCED_PARAMETER(device_object);

  stack = IoGetCurrentIrpStackLocation(irp);
  file = stack->FileObject;
  dixc = file->FsContext;

  ASSERT(!dixc->pending_read_irp);
  
  if (stack->Parameters.Read.Length == 0)
  {
    status = STATUS_SUCCESS;    
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
  }
  else 
  {
    status = XenPci_Irp_Read_XenBus_Complete(dixc, irp);
    if (status == STATUS_PENDING)
    {
      IoMarkIrpPending(irp);
      KeAcquireSpinLock(&dixc->lock, &old_irql);
      dixc->pending_read_irp = irp;
      KeReleaseSpinLock(&dixc->lock, old_irql);
      IoSetCancelRoutine(irp, XenPci_Irp_Read_Cancel);
    }
  }
  return status;
}

NTSTATUS
XenPci_Irp_Write_XenBus(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PFILE_OBJECT file;
  device_interface_xenbus_context_t *dixc;
  PUCHAR src_ptr;
  ULONG src_len;
  PUCHAR dst_ptr;
  ULONG copy_len;
  struct xsd_sockmsg *rep;
  PXENPCI_DEVICE_DATA xpdd;
  KIRQL old_irql;
  xenbus_read_queue_item_t *list_entry;
  PIRP read_irp;
  NTSTATUS read_status;
  
  FUNCTION_ENTER();
  
  xpdd = device_object->DeviceExtension;
  stack = IoGetCurrentIrpStackLocation(irp);
  file = stack->FileObject;
  dixc = file->FsContext;
  
  KdPrint((__DRIVER_NAME "     write length = %d\n", stack->Parameters.Write.Length));
  
  src_ptr = (PUCHAR)irp->AssociatedIrp.SystemBuffer;
  src_len = stack->Parameters.Write.Length;
  dst_ptr = dixc->u.buffer + dixc->len;
  while (src_len != 0)
  {
    /* get a complete msg header */
    if (dixc->len < sizeof(dixc->u.msg))
    {
      copy_len = min(sizeof(dixc->u.msg) - dixc->len, src_len);
      if (!copy_len)
        continue;
      memcpy(dst_ptr, src_ptr, copy_len);
      dst_ptr += copy_len;
      src_ptr += copy_len;
      src_len -= copy_len;
      dixc->len += copy_len;
    }
    /* exit if we can't get that */
    if (dixc->len < sizeof(dixc->u.msg))
      continue;
    /* get a complete msg body */
    if (dixc->len < sizeof(dixc->u.msg) + dixc->u.msg.len)
    {
      copy_len = min(sizeof(dixc->u.msg) + dixc->u.msg.len - dixc->len, src_len);
      if (!copy_len)
        continue;
      memcpy(dst_ptr, src_ptr, copy_len);
      dst_ptr += copy_len;
      src_ptr += copy_len;
      src_len -= copy_len;
      dixc->len += copy_len;
    }
    /* exit if we can't get that */
    if (dixc->len < sizeof(dixc->u.msg) + dixc->u.msg.len)
    {
      continue;
    }
    
    rep = XenBus_Raw(xpdd, &dixc->u.msg);
    KeAcquireSpinLock(&dixc->lock, &old_irql);
    list_entry = (xenbus_read_queue_item_t *)ExAllocatePoolWithTag(NonPagedPool, sizeof(xenbus_read_queue_item_t), XENPCI_POOL_TAG);
    list_entry->data = rep;
    list_entry->length = sizeof(*rep) + rep->len;
    list_entry->offset = 0;
    InsertTailList(&dixc->read_list_head, (PLIST_ENTRY)list_entry);
    read_irp = dixc->pending_read_irp;
    dixc->pending_read_irp = NULL;
    KeReleaseSpinLock(&dixc->lock, old_irql);
    if (read_irp)
    {
      read_status = XenPci_Irp_Read_XenBus_Complete(dixc, read_irp);
      ASSERT(read_status == STATUS_SUCCESS);
    }
  }
  status = STATUS_SUCCESS;    
  irp->IoStatus.Status = status;
  irp->IoStatus.Information = stack->Parameters.Write.Length;

  KdPrint((__DRIVER_NAME "     Information = %d\n", irp->IoStatus.Information));

  IoCompleteRequest(irp, IO_NO_INCREMENT);

  FUNCTION_EXIT();

  return status;
}

NTSTATUS
XenPci_Irp_Cleanup_XenBus(PDEVICE_OBJECT device_object, PIRP irp)
{
  PXENPCI_DEVICE_DATA xpdd;
  NTSTATUS status;

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  status = STATUS_SUCCESS;    
  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  return status;
}
#endif