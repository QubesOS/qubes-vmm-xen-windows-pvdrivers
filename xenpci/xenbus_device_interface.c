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

NTSTATUS
XenPci_Irp_Create_XenBus(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PFILE_OBJECT file;
  device_interface_xenbus_context_t *dixc;
  
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
  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
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

typedef struct {
  LIST_ENTRY entry;
  PVOID data;
  ULONG length;
  ULONG offset;
} xenbus_read_queue_item_t;

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
  
  dixc->pending_read_irp = NULL;
  stack = IoGetCurrentIrpStackLocation(irp);
  dst_length = stack->Parameters.Read.Length;
  dst_offset = 0;
  KeAcquireSpinLock(&dixc->lock, &old_irql);
  while(dst_offset < dst_length && (list_entry = (xenbus_read_queue_item_t *)RemoveHeadList(&dixc->read_list_head)) != (xenbus_read_queue_item_t *)&dixc->read_list_head)
  {
    copy_length = min(list_entry->length - list_entry->offset, dst_length - dst_offset);
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
    
  if (dst_offset > 0)
  {
    status = STATUS_SUCCESS;
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = dst_offset;
    //IoSetCancelRoutine(irp, NULL);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
  }
  else
  {
    status = STATUS_PENDING;
  }
  return status;
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

  ASSERT(dixc->pending_read_irp);
  
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
      //IoSetCancelRoutine(irp, XenBus_ShutdownIoCancel);
      KeReleaseSpinLock(&dixc->lock, old_irql);
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
  
  xpdd = device_object->DeviceExtension;
  stack = IoGetCurrentIrpStackLocation(irp);
  file = stack->FileObject;
  dixc = file->FsContext;
  
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
  IoCompleteRequest(irp, IO_NO_INCREMENT);
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
