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
  ULONG dst_length = (ULONG)length;
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
      ExFreePoolWithTag(list_entry->data, XENPCI_POOL_TAG);
      ExFreePoolWithTag(list_entry, XENPCI_POOL_TAG);
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
  size_t remaining;
  WDFREQUEST request;

  FUNCTION_ENTER();
  
  KeAcquireSpinLock(&xpdid->lock, &old_irql);
  
  remaining = sizeof(struct xsd_sockmsg) + strlen(path) + 1 + strlen(watch_context->token) + 1;
  rep = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct xsd_sockmsg) + strlen(path) + 1 + strlen(watch_context->token) + 1, XENPCI_POOL_TAG);
  rep->type = XS_WATCH_EVENT;
  rep->req_id = 0;
  rep->tx_id = 0;
  rep->len = (ULONG)(strlen(path) + 1 + strlen(watch_context->token) + 1);
  remaining -= sizeof(struct xsd_sockmsg);
  RtlStringCbCopyA((PCHAR)(rep + 1), remaining, path);
  remaining -= strlen(path) + 1;
  RtlStringCbCopyA((PCHAR)(rep + 1) + strlen(path) + 1, remaining, watch_context->token);
  
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

  UNREFERENCED_PARAMETER(queue);
  
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
  src_len = (ULONG)length;
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
      watch_path = (PCHAR)(xpdid->u.buffer + sizeof(struct xsd_sockmsg));
      watch_token = (PCHAR)(xpdid->u.buffer + sizeof(struct xsd_sockmsg) + strlen(watch_path) + 1);
      RtlStringCbCopyA(watch_context->path, ARRAY_SIZE(watch_context->path), watch_path);
      RtlStringCbCopyA(watch_context->token, ARRAY_SIZE(watch_context->path), watch_token);
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
        rep->len = (ULONG)(strlen(msg) + 0);
        RtlStringCbCopyA((PCHAR)(rep + 1), strlen(msg) + 1, msg);
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