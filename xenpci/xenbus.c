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
#include "io/xs_wire.h"
#include <stdlib.h>

#pragma warning( disable : 4204 ) 
#pragma warning( disable : 4221 ) 

struct write_req {
    const void *data;
    unsigned len;
};

static DDKAPI void
XenBus_ReadThreadProc(PVOID StartContext);
static DDKAPI void
XenBus_WatchThreadProc(PVOID StartContext);
static DDKAPI BOOLEAN
XenBus_Interrupt(PKINTERRUPT Interrupt, PVOID ServiceContext);

static int allocate_xenbus_id(PXENPCI_DEVICE_DATA xpdd)
{
  static int probe;
  int o_probe;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  for (;;)
  {
//    spin_lock(&req_lock);
    if (xpdd->nr_live_reqs < NR_XB_REQS)
      break;
//    spin_unlock(&req_lock);
//    wait_event(req_wq, (nr_live_reqs < NR_REQS));
  }

  o_probe = probe;

  for (;;)
  {
    if (!xpdd->req_info[o_probe].In_Use)
      break;
    o_probe = (o_probe + 1) % NR_XB_REQS;
//    BUG_ON(o_probe == probe);
  }
  xpdd->nr_live_reqs++;
  xpdd->req_info[o_probe].In_Use = 1;
  probe = (o_probe + 1) % NR_XB_REQS;
  //spin_unlock(&req_lock);
  //init_waitqueue_head(&req_info[o_probe].waitq);
  KeInitializeEvent(&xpdd->req_info[o_probe].WaitEvent, SynchronizationEvent, FALSE);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return o_probe;
}

static void release_xenbus_id(PXENPCI_DEVICE_DATA xpdd, int id)
{
//    BUG_ON(!req_info[id].in_use);
//    spin_lock(&req_lock);
    xpdd->req_info[id].In_Use = 0;
    xpdd->nr_live_reqs--;
    xpdd->req_info[id].In_Use = 0;
//    if (nr_live_reqs == NR_REQS - 1)
//        wake_up(&req_wq);
//    spin_unlock(&req_lock);
}

// This routine free's the rep structure if there was an error!!!
static char *errmsg(struct xsd_sockmsg *rep)
{
  char *res;

  if (!rep) {
    char msg[] = "No reply";
    size_t len = strlen(msg) + 1;
    return memcpy(ExAllocatePoolWithTag(NonPagedPool, len, XENPCI_POOL_TAG), msg, len);
  }
  if (rep->type != XS_ERROR)
    return NULL;
  res = ExAllocatePoolWithTag(NonPagedPool, rep->len + 1, XENPCI_POOL_TAG);
  memcpy(res, rep + 1, rep->len);
  res[rep->len] = 0;
  ExFreePoolWithTag(rep, XENPCI_POOL_TAG);
  return res;
}

static void memcpy_from_ring(const void *Ring,
        void *Dest,
        int off,
        int len)
{
  int c1, c2;
  const char *ring = Ring;
  char *dest = Dest;
  c1 = min(len, XENSTORE_RING_SIZE - off);
  c2 = len - c1;
  memcpy(dest, ring + off, c1);
  memcpy(dest + c1, ring, c2);
}

static void xb_write(
  PXENPCI_DEVICE_DATA xpdd,
  int type,
  int req_id,
  xenbus_transaction_t trans_id,
  const struct write_req *req,
  int nr_reqs)
{
  XENSTORE_RING_IDX prod;
  int r;
  size_t len = 0;
  const struct write_req *cur_req;
  size_t req_off;
  size_t total_off;
  size_t this_chunk;
  struct xsd_sockmsg m = {type, req_id, trans_id };
  struct write_req header_req = { &m, sizeof(m) };

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  for (r = 0; r < nr_reqs; r++)
    len += (size_t)req[r].len;
  m.len = (ULONG)len;
  len += sizeof(m);

  cur_req = &header_req;

//  BUG_ON(len > XENSTORE_RING_SIZE);
  /* Wait for the ring to drain to the point where we can send the
     message. */
  prod = xpdd->xen_store_interface->req_prod;

  //KdPrint((__DRIVER_NAME " prod = %08x\n", prod));

  if (prod + len - xpdd->xen_store_interface->req_cons > XENSTORE_RING_SIZE)
  {
    /* Wait for there to be space on the ring */
    //KdPrint((__DRIVER_NAME " prod %d, len %d, cons %d, size %d; waiting.\n", prod, len, xen_store_interface->req_cons, XENSTORE_RING_SIZE));
//    wait_event(xb_waitq, xen_store_interface->req_prod + len - xen_store_interface->req_cons <= XENSTORE_RING_SIZE);
    //KdPrint((__DRIVER_NAME " Back from wait.\n"));
    prod = xpdd->xen_store_interface->req_prod;
  }

  /* We're now guaranteed to be able to send the message without
     overflowing the ring.  Do so. */

  total_off = 0;
  req_off = 0;

  while (total_off < len)
  {
    this_chunk = min(cur_req->len - req_off,XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod));
    memcpy((char *)xpdd->xen_store_interface->req + MASK_XENSTORE_IDX(prod), (char *)cur_req->data + req_off, this_chunk);
    prod += (XENSTORE_RING_IDX)this_chunk;
    req_off += this_chunk;
    total_off += this_chunk;
    if (req_off == cur_req->len)
    {
      req_off = 0;
      if (cur_req == &header_req)
        cur_req = req;
      else
        cur_req++;
    }
  }

  //KdPrint((__DRIVER_NAME " Complete main loop of xb_write.\n"));

//  BUG_ON(req_off != 0);
//  BUG_ON(total_off != len);
//  BUG_ON(prod > xen_store_interface->req_cons + XENSTORE_RING_SIZE);

  /* Remote must see entire message before updating indexes */
  //_WriteBarrier();
  KeMemoryBarrier();

  xpdd->xen_store_interface->req_prod += (XENSTORE_RING_IDX)len;

  //KdPrint((__DRIVER_NAME " prod = %08x\n", xen_store_interface->req_prod));

  /* Send evtchn to notify remote */
  EvtChn_Notify(xpdd, xpdd->xen_store_evtchn);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static struct xsd_sockmsg *
xenbus_msg_reply(
  PXENPCI_DEVICE_DATA xpdd,
  int type,
  xenbus_transaction_t trans,
  struct write_req *io,
  int nr_reqs)
{
  int id;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  id = allocate_xenbus_id(xpdd);

  xb_write(xpdd, type, id, trans, io, nr_reqs);

  KeWaitForSingleObject(&xpdd->req_info[id].WaitEvent, Executive, KernelMode, FALSE, NULL);

  release_xenbus_id(xpdd, id);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return xpdd->req_info[id].Reply;
}

char *
XenBus_Read(
  PVOID Context,
  xenbus_transaction_t xbt,
  const char *path,
  char **value)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  struct write_req req[] = { {path, (ULONG)strlen(path) + 1} };
  struct xsd_sockmsg *rep;
  char *res;
  char *msg;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  rep = xenbus_msg_reply(xpdd, XS_READ, xbt, req, ARRAY_SIZE(req));
  msg = errmsg(rep);
  if (msg) {
    *value = NULL;
    return msg;
  }
  res = ExAllocatePoolWithTag(NonPagedPool, rep->len + 1, XENPCI_POOL_TAG);
  memcpy(res, rep + 1, rep->len);
  res[rep->len] = 0;
  ExFreePoolWithTag(rep, XENPCI_POOL_TAG);
  *value = res;

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NULL;
}

char *
XenBus_Write(
  PVOID Context,
  xenbus_transaction_t xbt,
  const char *path,
  const char *value)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  struct write_req req[] = {
    {path, (ULONG)strlen(path) + 1},
    {value, (ULONG)strlen(value)},
//    {path, (ULONG)strlen(path)},
//    {value, (ULONG)strlen(value)},
  };
  struct xsd_sockmsg *rep;
  char *msg;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  rep = xenbus_msg_reply(xpdd, XS_WRITE, xbt, req, ARRAY_SIZE(req));
  msg = errmsg(rep);
  if (msg)
    return msg;
  ExFreePoolWithTag(rep, XENPCI_POOL_TAG);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NULL;
}

static VOID
XenBus_Connect(PXENPCI_DEVICE_DATA xpdd)
{
  PHYSICAL_ADDRESS pa_xen_store_interface;
  xen_ulong_t xen_store_mfn;

  xpdd->xen_store_evtchn = (evtchn_port_t)hvm_get_parameter(xpdd, HVM_PARAM_STORE_EVTCHN);
  xen_store_mfn = (xen_ulong_t)hvm_get_parameter(xpdd, HVM_PARAM_STORE_PFN);
  pa_xen_store_interface.QuadPart = (ULONGLONG)xen_store_mfn << PAGE_SHIFT;
  xpdd->xen_store_interface = MmMapIoSpace(pa_xen_store_interface, PAGE_SIZE, MmNonCached);

  EvtChn_BindDpc(xpdd, xpdd->xen_store_evtchn, XenBus_Interrupt, xpdd);
}

NTSTATUS
XenBus_Init(PXENPCI_DEVICE_DATA xpdd)
{
  NTSTATUS Status;
  int i;
    
//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  KeInitializeSpinLock(&xpdd->WatchLock);

  for (i = 0; i < MAX_WATCH_ENTRIES; i++)
  {
    xpdd->XenBus_WatchEntries[i].Active = 0;
    xpdd->XenBus_WatchEntries[i].Running = 0;
    KeInitializeEvent(&xpdd->XenBus_WatchEntries[i].CompleteEvent, SynchronizationEvent, FALSE);  
  }

  KeInitializeEvent(&xpdd->XenBus_ReadThreadEvent, SynchronizationEvent, FALSE);
  KeInitializeEvent(&xpdd->XenBus_WatchThreadEvent, SynchronizationEvent, FALSE);
  xpdd->XenBus_ShuttingDown = FALSE;

  Status = PsCreateSystemThread(&xpdd->XenBus_ReadThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, XenBus_ReadThreadProc, xpdd);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME " Could not start read thread\n"));
    return STATUS_UNSUCCESSFUL;
  }

  Status = PsCreateSystemThread(&xpdd->XenBus_WatchThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, XenBus_WatchThreadProc, xpdd);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME " Could not start watch thread\n"));
    return STATUS_UNSUCCESSFUL;
  }

  XenBus_Connect(xpdd);
  
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
XenBus_Stop(PXENPCI_DEVICE_DATA xpdd)
{
  int i;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  for (i = 0; i < MAX_WATCH_ENTRIES; i++)
  {
    if (xpdd->XenBus_WatchEntries[i].Active)
      XenBus_RemWatch(xpdd, XBT_NIL, xpdd->XenBus_WatchEntries[i].Path,
        xpdd->XenBus_WatchEntries[i].ServiceRoutine,
        xpdd->XenBus_WatchEntries[i].ServiceContext);
  }

  EvtChn_Unbind(xpdd, xpdd->xen_store_evtchn);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
XenBus_Close(PXENPCI_DEVICE_DATA xpdd)
{
  //KWAIT_BLOCK WaitBlockArray[2];
  PVOID WaitArray[2];

  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  xpdd->XenBus_ShuttingDown = TRUE;

  KeSetEvent(&xpdd->XenBus_ReadThreadEvent, IO_NO_INCREMENT, FALSE);
  KeSetEvent(&xpdd->XenBus_WatchThreadEvent, IO_NO_INCREMENT, FALSE);
  ObReferenceObjectByHandle(xpdd->XenBus_ReadThreadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, &WaitArray[0], NULL);
  ObReferenceObjectByHandle(xpdd->XenBus_WatchThreadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, &WaitArray[1], NULL);
  KeWaitForSingleObject(WaitArray[0], Executive, KernelMode, FALSE, NULL);
  KeWaitForSingleObject(WaitArray[1], Executive, KernelMode, FALSE, NULL);
  xpdd->XenBus_ShuttingDown = FALSE;

  ZwClose(xpdd->XenBus_WatchThreadHandle);
  ZwClose(xpdd->XenBus_ReadThreadHandle);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}

char *
XenBus_List(
  PVOID Context,
  xenbus_transaction_t xbt,
  const char *pre,
  char ***contents)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  struct xsd_sockmsg *reply, *repmsg;
  struct write_req req[] = { { pre, (ULONG)strlen(pre)+1 } };
  ULONG nr_elems, x, i;
  char **res;
  char *msg;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  repmsg = xenbus_msg_reply(xpdd, XS_DIRECTORY, xbt, req, ARRAY_SIZE(req));
  msg = errmsg(repmsg);
  if (msg)
  {
    *contents = NULL;
//    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
    return msg;
  }
  reply = repmsg + 1;
  for (x = nr_elems = 0; x < repmsg->len; x++)
  {
    nr_elems += (((char *)reply)[x] == 0);
  }
  res = ExAllocatePoolWithTag(NonPagedPool, sizeof(res[0]) * (nr_elems + 1),
    XENPCI_POOL_TAG);
  for (x = i = 0; i < nr_elems; i++)
  {
    int l = (int)strlen((char *)reply + x);
    res[i] = ExAllocatePoolWithTag(NonPagedPool, l + 1, XENPCI_POOL_TAG);
    memcpy(res[i], (char *)reply + x, l + 1);
    x += l + 1;
  }
  res[i] = NULL;
  ExFreePoolWithTag(repmsg, XENPCI_POOL_TAG);
  *contents = res;
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return NULL;
}

static DDKAPI void
XenBus_ReadThreadProc(PVOID StartContext)
{
  int NewWriteIndex;
  struct xsd_sockmsg msg;
  char *payload;
  char *path, *token;
  PXENPCI_DEVICE_DATA xpdd = StartContext;

  for(;;)
  {
    KeWaitForSingleObject(&xpdd->XenBus_ReadThreadEvent, Executive, KernelMode, FALSE, NULL);
    if (xpdd->XenBus_ShuttingDown)
    {
      KdPrint((__DRIVER_NAME "     Shutdown detected in ReadThreadProc\n"));
      PsTerminateSystemThread(0);
    }
    while (xpdd->xen_store_interface->rsp_prod != xpdd->xen_store_interface->rsp_cons)
    {
      //KdPrint((__DRIVER_NAME "     a - Rsp_cons %d, rsp_prod %d.\n", xen_store_interface->rsp_cons, xen_store_interface->rsp_prod));
      if (xpdd->xen_store_interface->rsp_prod - xpdd->xen_store_interface->rsp_cons < sizeof(msg))
      {
        //KdPrint((__DRIVER_NAME " +++ Message incomplete (not even a full header)\n"));
        break;
      }
      //_ReadBarrier();
      KeMemoryBarrier();
      memcpy_from_ring(xpdd->xen_store_interface->rsp, &msg,
        MASK_XENSTORE_IDX(xpdd->xen_store_interface->rsp_cons), sizeof(msg));
      if (xpdd->xen_store_interface->rsp_prod - xpdd->xen_store_interface->rsp_cons < sizeof(msg) + msg.len)
      {
        //KdPrint((__DRIVER_NAME " +++ Message incomplete (header but not full body)\n"));
        break;
      }
  
      if (msg.type != XS_WATCH_EVENT)
      {
        xpdd->req_info[msg.req_id].Reply = ExAllocatePoolWithTag(NonPagedPool, sizeof(msg) + msg.len, XENPCI_POOL_TAG);
        memcpy_from_ring(xpdd->xen_store_interface->rsp,
          xpdd->req_info[msg.req_id].Reply,
          MASK_XENSTORE_IDX(xpdd->xen_store_interface->rsp_cons),
          msg.len + sizeof(msg));
        xpdd->xen_store_interface->rsp_cons += msg.len + sizeof(msg);
        KeSetEvent(&xpdd->req_info[msg.req_id].WaitEvent, IO_NO_INCREMENT, FALSE);
      }
      else // a watch: add to watch ring and signal watch thread
      {
        payload = ExAllocatePoolWithTag(NonPagedPool, sizeof(msg) + msg.len, XENPCI_POOL_TAG);
        memcpy_from_ring(xpdd->xen_store_interface->rsp, payload,
          MASK_XENSTORE_IDX(xpdd->xen_store_interface->rsp_cons), msg.len + sizeof(msg));
        xpdd->xen_store_interface->rsp_cons += msg.len + sizeof(msg);
        path = payload + sizeof(msg);
        token = path + strlen(path) + 1;

        NewWriteIndex = (xpdd->XenBus_WatchRingWriteIndex + 1) & 127;
        if (NewWriteIndex != xpdd->XenBus_WatchRingReadIndex)
        {
          strncpy(xpdd->XenBus_WatchRing[NewWriteIndex].Path, path, 128);
          strncpy(xpdd->XenBus_WatchRing[NewWriteIndex].Token, token, 10);
          xpdd->XenBus_WatchRingWriteIndex = NewWriteIndex;
        }
        else
        {
          KdPrint((__DRIVER_NAME " +++ Queue full Path = %s Token = %s\n", path, token));
          // drop the message on the floor
          continue;
        }

        ExFreePoolWithTag(payload, XENPCI_POOL_TAG);
        //KdPrint((__DRIVER_NAME " +++ Watch Path = %s Token = %s\n", path, token));
        KeSetEvent(&xpdd->XenBus_WatchThreadEvent, IO_NO_INCREMENT, FALSE);
      }
    }
  }
}

static DDKAPI void
XenBus_WatchThreadProc(PVOID StartContext)
{
  int index;
  PXENBUS_WATCH_ENTRY entry;
  PXENPCI_DEVICE_DATA xpdd = StartContext;
  KIRQL OldIrql;

  for(;;)
  {
    KeWaitForSingleObject(&xpdd->XenBus_WatchThreadEvent, Executive, KernelMode, FALSE, NULL);
    if (xpdd->XenBus_ShuttingDown)
    {
      KdPrint((__DRIVER_NAME "     Shutdown detected in WatchThreadProc\n"));
      PsTerminateSystemThread(0);
    }
    while (xpdd->XenBus_WatchRingReadIndex != xpdd->XenBus_WatchRingWriteIndex)
    {
      xpdd->XenBus_WatchRingReadIndex = 
        (xpdd->XenBus_WatchRingReadIndex + 1) % WATCH_RING_SIZE;
      index = atoi(xpdd->XenBus_WatchRing[xpdd->XenBus_WatchRingReadIndex].Token);

      entry = &xpdd->XenBus_WatchEntries[index];
      KeAcquireSpinLock(&xpdd->WatchLock, &OldIrql);
      if (!entry->Active || !entry->ServiceRoutine)
      {
        KeReleaseSpinLock(&xpdd->WatchLock, OldIrql);
        KdPrint((__DRIVER_NAME "     No watch for index %d\n", index));
        continue;
      }
      if (entry->RemovePending)
      {
        KeReleaseSpinLock(&xpdd->WatchLock, OldIrql);
        KdPrint((__DRIVER_NAME "     Not calling watch - remove is pending\n"));
        continue;
      }        
      entry->Running = 1;
      KeReleaseSpinLock(&xpdd->WatchLock, OldIrql);
      entry->Count++;
      entry->ServiceRoutine(xpdd->XenBus_WatchRing[xpdd->XenBus_WatchRingReadIndex].Path, entry->ServiceContext);
      entry->Running = 0;
      KeSetEvent(&entry->CompleteEvent, IO_NO_INCREMENT, FALSE);
    }
  }
}    

static char *
XenBus_SendAddWatch(
  PVOID Context,
  xenbus_transaction_t xbt,
  const char *Path,
  int slot)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  struct xsd_sockmsg *rep;
  char *msg;
  char Token[20];
  struct write_req req[2];

  req[0].data = Path;
  req[0].len = (ULONG)strlen(Path) + 1;

  RtlStringCbPrintfA(Token, ARRAY_SIZE(Token), "%d", slot);
  req[1].data = Token;
  req[1].len = (ULONG)strlen(Token) + 1;

  rep = xenbus_msg_reply(xpdd, XS_WATCH, xbt, req, ARRAY_SIZE(req));
  msg = errmsg(rep);
  if (!msg)
    ExFreePoolWithTag(rep, XENPCI_POOL_TAG);

  return msg;
}

/* called at PASSIVE_LEVEL */
VOID
XenBus_Resume(PXENPCI_DEVICE_DATA xpdd)
{
  int i;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  XenBus_Connect(xpdd);
  
  for (i = 0; i < MAX_WATCH_ENTRIES; i++)
  {
    if (xpdd->XenBus_WatchEntries[i].Active)
    {
      KdPrint((__DRIVER_NAME "     Adding watch for path = %s\n", xpdd->XenBus_WatchEntries[i].Path));
      XenBus_SendAddWatch(xpdd, XBT_NIL, xpdd->XenBus_WatchEntries[i].Path, i);
    }
  }
  KdPrint((__DRIVER_NAME " <-- XenBus_AddWatch\n"));
}

char *
XenBus_AddWatch(
  PVOID Context,
  xenbus_transaction_t xbt,
  const char *Path,
  PXENBUS_WATCH_CALLBACK ServiceRoutine,
  PVOID ServiceContext)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  char *msg;
  int i;
  PXENBUS_WATCH_ENTRY w_entry;
  KIRQL OldIrql;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  ASSERT(strlen(Path) < ARRAY_SIZE(w_entry->Path));

  KeAcquireSpinLock(&xpdd->WatchLock, &OldIrql);

  for (i = 0; i < MAX_WATCH_ENTRIES; i++)
    if (xpdd->XenBus_WatchEntries[i].Active == 0)
      break;
  
  if (i == MAX_WATCH_ENTRIES)
  {
    KdPrint((__DRIVER_NAME " +++ No more watch slots left\n"));
    KeReleaseSpinLock(&xpdd->WatchLock, OldIrql);
    return NULL;
  }

  /* must init watchentry before starting watch */
  
  w_entry = &xpdd->XenBus_WatchEntries[i];
  strncpy(w_entry->Path, Path, ARRAY_SIZE(w_entry->Path));
  w_entry->ServiceRoutine = ServiceRoutine;
  w_entry->ServiceContext = ServiceContext;
  w_entry->Count = 0;
  w_entry->Active = 1;

  KeReleaseSpinLock(&xpdd->WatchLock, OldIrql);

  msg = XenBus_SendAddWatch(xpdd, xbt, Path, i);

  if (msg)
  {
    xpdd->XenBus_WatchEntries[i].Active = 0;
    //KdPrint((__DRIVER_NAME " <-- XenBus_AddWatch (%s)\n", msg));
    return msg;
  }

  //KdPrint((__DRIVER_NAME " <-- XenBus_AddWatch\n"));

  return NULL;
}

char *
XenBus_RemWatch(
  PVOID Context,
  xenbus_transaction_t xbt,
  const char *Path,
  PXENBUS_WATCH_CALLBACK ServiceRoutine,
  PVOID ServiceContext)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  struct xsd_sockmsg *rep;
  char *msg;
  int i;
  char Token[20];
  struct write_req req[2];
  KIRQL OldIrql;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  KeAcquireSpinLock(&xpdd->WatchLock, &OldIrql);

  // check that Path < 128 chars

  for (i = 0; i < MAX_WATCH_ENTRIES; i++) {
    if (xpdd->XenBus_WatchEntries[i].Active == 1
      && strcmp(xpdd->XenBus_WatchEntries[i].Path, Path) == 0
      && xpdd->XenBus_WatchEntries[i].ServiceRoutine == ServiceRoutine
      && xpdd->XenBus_WatchEntries[i].ServiceContext == ServiceContext)
      break;
  }

  if (i == MAX_WATCH_ENTRIES)
  {
    KeReleaseSpinLock(&xpdd->WatchLock, OldIrql);
    KdPrint((__DRIVER_NAME "     Watch not set - can't remove\n"));
    return NULL;
  }

  if (xpdd->XenBus_WatchEntries[i].RemovePending)
  {
    KeReleaseSpinLock(&xpdd->WatchLock, OldIrql);
    KdPrint((__DRIVER_NAME "     Remove already pending - can't remove\n"));
    return NULL;
  }
  KeReleaseSpinLock(&xpdd->WatchLock, OldIrql);

  while (xpdd->XenBus_WatchEntries[i].Running)
    KeWaitForSingleObject(&xpdd->XenBus_WatchEntries[i].CompleteEvent, Executive, KernelMode, FALSE, NULL);

  KeAcquireSpinLock(&xpdd->WatchLock, &OldIrql);

  xpdd->XenBus_WatchEntries[i].Active = 0;
  xpdd->XenBus_WatchEntries[i].RemovePending = 0;
  xpdd->XenBus_WatchEntries[i].Path[0] = 0;

  KeReleaseSpinLock(&xpdd->WatchLock, OldIrql);

  req[0].data = Path;
  req[0].len = (ULONG)strlen(Path) + 1;

  RtlStringCbPrintfA(Token, ARRAY_SIZE(Token), "%d", i);
  req[1].data = Token;
  req[1].len = (ULONG)strlen(Token) + 1;

  rep = xenbus_msg_reply(xpdd, XS_UNWATCH, xbt, req, ARRAY_SIZE(req));

  msg = errmsg(rep);
  if (msg)
  {
    return msg;
  }

  ExFreePoolWithTag(rep, XENPCI_POOL_TAG);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NULL;
}


char *
XenBus_StartTransaction(PVOID Context, xenbus_transaction_t *xbt)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  /* xenstored becomes angry if you send a length 0 message, so just
     shove a nul terminator on the end */
  struct write_req req = { "", 1};
  struct xsd_sockmsg *rep;
  char *err;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  rep = xenbus_msg_reply(xpdd, XS_TRANSACTION_START, 0, &req, 1);
  err = errmsg(rep);
  if (err)
    return err;
  *xbt = atoi((char *)(rep + 1));
  //sscanf((char *)(rep + 1), "%u", xbt);
  ExFreePoolWithTag(rep, XENPCI_POOL_TAG);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NULL;
}

char *
XenBus_EndTransaction(
  PVOID Context,
  xenbus_transaction_t t,
  int abort,
  int *retry)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  struct xsd_sockmsg *rep;
  struct write_req req;
  char *err;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  *retry = 0;

  req.data = abort ? "F" : "T";
  req.len = 2;
  rep = xenbus_msg_reply(xpdd, XS_TRANSACTION_END, t, &req, 1);
  err = errmsg(rep);
  if (err) {
    if (!strcmp(err, "EAGAIN")) {
      *retry = 1;
      ExFreePoolWithTag(err, XENPCI_POOL_TAG);
      return NULL;
    } else {
      return err;
    }
  }
  ExFreePoolWithTag(rep, XENPCI_POOL_TAG);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NULL;
}

static DDKAPI BOOLEAN
XenBus_Interrupt(PKINTERRUPT Interrupt, PVOID ServiceContext)
{
  PXENPCI_DEVICE_DATA xpdd = ServiceContext;

  UNREFERENCED_PARAMETER(Interrupt);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  KeSetEvent(&xpdd->XenBus_ReadThreadEvent, IO_NO_INCREMENT, FALSE);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

char *
XenBus_Printf(
  PVOID Context,
  xenbus_transaction_t xbt,
  const char *path,
  const char *fmt,
  ...)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  va_list ap;
  char buf[512];
  char *retval;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  va_start(ap, fmt);
  RtlStringCbVPrintfA(buf, ARRAY_SIZE(buf), fmt, ap);
  va_end(ap);
  retval = XenBus_Write(xpdd, xbt, path, buf);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return retval;
}
