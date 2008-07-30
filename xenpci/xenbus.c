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

/* called with xenbus_mutex held */
static int allocate_xenbus_id(PXENPCI_DEVICE_DATA xpdd)
{
  static int probe;
  int o_probe;
  KIRQL old_irql;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  for (;;)
  {
    KeAcquireSpinLock(&xpdd->xenbus_id_lock, &old_irql);
    if (xpdd->nr_live_reqs < NR_XB_REQS)
      break;
    KeReleaseSpinLock(&xpdd->xenbus_id_lock, old_irql);
    KeWaitForSingleObject(&xpdd->xenbus_id_event, Executive, KernelMode, FALSE, NULL);
  }

  o_probe = probe;

  for (;;)
  {
    if (!xpdd->req_info[o_probe].In_Use)
      break;
    o_probe = (o_probe + 1) % NR_XB_REQS;
    ASSERT(o_probe != probe);
  }
  xpdd->nr_live_reqs++;
  xpdd->req_info[o_probe].In_Use = 1;
  probe = (o_probe + 1) % NR_XB_REQS;
  KeReleaseSpinLock(&xpdd->xenbus_id_lock, old_irql);
  KeInitializeEvent(&xpdd->req_info[o_probe].WaitEvent, SynchronizationEvent, FALSE);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return o_probe;
}

/* called with xenbus_mutex held */
static void release_xenbus_id(PXENPCI_DEVICE_DATA xpdd, int id)
{
  KIRQL old_irql;

  ASSERT(xpdd->req_info[id].In_Use);
  KeAcquireSpinLock(&xpdd->xenbus_id_lock, &old_irql);
  xpdd->req_info[id].In_Use = 0;
  xpdd->nr_live_reqs--;
  xpdd->req_info[id].In_Use = 0;
  if (xpdd->nr_live_reqs == NR_XB_REQS - 1)
    KeSetEvent(&xpdd->xenbus_id_event, IO_NO_INCREMENT, FALSE);
  KeReleaseSpinLock(&xpdd->xenbus_id_lock, old_irql);
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

/* called with xenbus_mutex held */
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

  ASSERT(len <= XENSTORE_RING_SIZE);
  /* Wait for the ring to drain to the point where we can send the
     message. */
  prod = xpdd->xen_store_interface->req_prod;

  while (prod + len - xpdd->xen_store_interface->req_cons > XENSTORE_RING_SIZE)
  {
    /* Wait for there to be space on the ring */
    KeWaitForSingleObject(&xpdd->XenBus_ReadThreadEvent, Executive, KernelMode, FALSE, NULL);
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

  /* Remote must see entire message before updating indexes */
  KeMemoryBarrier();

  xpdd->xen_store_interface->req_prod += (XENSTORE_RING_IDX)len;

  /* Send evtchn to notify remote */
  EvtChn_Notify(xpdd, xpdd->xen_store_evtchn);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

/* called with xenbus_mutex held */
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

/*
Called at PASSIVE_LEVEL
Acquires the mutex
*/
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

  // get mutex or wait for mutex to be acquired
  
  ExAcquireFastMutex(&xpdd->xenbus_mutex);
  rep = xenbus_msg_reply(xpdd, XS_READ, xbt, req, ARRAY_SIZE(req));
  ExReleaseFastMutex(&xpdd->xenbus_mutex);
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

/*
Called at PASSIVE_LEVEL
Acquires the mutex
*/
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
  };
  struct xsd_sockmsg *rep;
  char *msg;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  ExAcquireFastMutex(&xpdd->xenbus_mutex);
  rep = xenbus_msg_reply(xpdd, XS_WRITE, xbt, req, ARRAY_SIZE(req));
  ExReleaseFastMutex(&xpdd->xenbus_mutex);
  msg = errmsg(rep);
  if (msg)
    return msg;
  ExFreePoolWithTag(rep, XENPCI_POOL_TAG);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NULL;
}

NTSTATUS
XenBus_Connect(PXENPCI_DEVICE_DATA xpdd)
{
  PHYSICAL_ADDRESS pa_xen_store_interface;
  xen_ulong_t xen_store_mfn;

  xpdd->xen_store_evtchn = (evtchn_port_t)hvm_get_parameter(xpdd, HVM_PARAM_STORE_EVTCHN);
  xen_store_mfn = (xen_ulong_t)hvm_get_parameter(xpdd, HVM_PARAM_STORE_PFN);
  pa_xen_store_interface.QuadPart = (ULONGLONG)xen_store_mfn << PAGE_SHIFT;
  xpdd->xen_store_interface = MmMapIoSpace(pa_xen_store_interface, PAGE_SIZE, MmNonCached);

  EvtChn_BindDpc(xpdd, xpdd->xen_store_evtchn, XenBus_Interrupt, xpdd);

  xpdd->XenBus_ShuttingDown = FALSE;
  KeMemoryBarrier();
  
  return STATUS_SUCCESS;
}

NTSTATUS
XenBus_Init(PXENPCI_DEVICE_DATA xpdd)
{
  NTSTATUS status;
  HANDLE thread_handle;
  int i;
    
  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  ExInitializeFastMutex(&xpdd->watch_mutex);
  ExInitializeFastMutex(&xpdd->xenbus_mutex);

  for (i = 0; i < MAX_WATCH_ENTRIES; i++)
  {
    xpdd->XenBus_WatchEntries[i].Active = 0;
  }

  KeInitializeEvent(&xpdd->XenBus_ReadThreadEvent, SynchronizationEvent, FALSE);
  KeInitializeEvent(&xpdd->XenBus_WatchThreadEvent, SynchronizationEvent, FALSE);
  KeInitializeEvent(&xpdd->xenbus_id_event, SynchronizationEvent, FALSE);
  KeInitializeSpinLock(&xpdd->xenbus_id_lock);
  xpdd->XenBus_ShuttingDown = FALSE;

  status = XenBus_Connect(xpdd);
  if (!NT_SUCCESS(status))
  {
    return status;
  }

  status = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, XenBus_ReadThreadProc, xpdd);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     Could not start read thread\n"));
    return status;
  }
  KdPrint((__DRIVER_NAME "    Started ReadThread\n"));
  
  status = ObReferenceObjectByHandle(thread_handle, THREAD_ALL_ACCESS, NULL, KernelMode, &xpdd->XenBus_ReadThread, NULL);
  ZwClose(thread_handle);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     ObReferenceObjectByHandle(XenBus_ReadThread) = %08x\n", status));
    return status;
  }

  status = PsCreateSystemThread(&thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, XenBus_WatchThreadProc, xpdd);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME " Could not start watch thread\n"));
    return status;
  }
  KdPrint((__DRIVER_NAME "    Started WatchThread\n"));
  status = ObReferenceObjectByHandle(thread_handle, THREAD_ALL_ACCESS, NULL, KernelMode, &xpdd->XenBus_WatchThread, NULL);
  ZwClose(thread_handle);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     ObReferenceObjectByHandle(XenBus_WatchThread) = %08x\n", status));
  }
  
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}

#if 0
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
#endif

char *
XenBus_SendRemWatch(
  PVOID context,
  xenbus_transaction_t xbt,
  const char *path,
  const int index)
{
  struct xsd_sockmsg *rep;
  char *msg;
  char Token[20];
  struct write_req req[2];

  req[0].data = path;
  req[0].len = (ULONG)strlen(path) + 1;

  RtlStringCbPrintfA(Token, ARRAY_SIZE(Token), "%d", index);
  req[1].data = Token;
  req[1].len = (ULONG)strlen(Token) + 1;

  rep = xenbus_msg_reply(context, XS_UNWATCH, xbt, req, ARRAY_SIZE(req));

  msg = errmsg(rep);
  if (msg)
    return msg;

  ExFreePoolWithTag(rep, XENPCI_POOL_TAG);

  return NULL;
}

NTSTATUS
XenBus_StopThreads(PXENPCI_DEVICE_DATA xpdd)
{
  NTSTATUS status;
  //KWAIT_BLOCK WaitBlockArray[2];
  int i;
  LARGE_INTEGER timeout;

  FUNCTION_ENTER();
  
  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  /* we need to remove the watches as a watch firing could lead to a XenBus_Read/Write/Printf */
  ExAcquireFastMutex(&xpdd->watch_mutex);
  for (i = 0; i < MAX_WATCH_ENTRIES; i++) {
    if (xpdd->XenBus_WatchEntries[i].Active)
      XenBus_SendRemWatch(xpdd, XBT_NIL, xpdd->XenBus_WatchEntries[i].Path, i);
  }
  ExReleaseFastMutex(&xpdd->watch_mutex);

  xpdd->XenBus_ShuttingDown = TRUE;
  KeMemoryBarrier();

KdPrint((__DRIVER_NAME "     Setting ReadThreadEvent\n"));
  KeSetEvent(&xpdd->XenBus_ReadThreadEvent, IO_NO_INCREMENT, FALSE);
KdPrint((__DRIVER_NAME "     Setting WatchThreadEvent\n"));
  KeSetEvent(&xpdd->XenBus_WatchThreadEvent, IO_NO_INCREMENT, FALSE);
  
KdPrint((__DRIVER_NAME "     Waiting for ReadThread\n"));
  timeout.QuadPart = (LONGLONG)-1 * 1000 * 1000 * 10;
  while ((status = KeWaitForSingleObject(xpdd->XenBus_ReadThread, Executive, KernelMode, FALSE, &timeout)) != STATUS_SUCCESS)
  {
KdPrint((__DRIVER_NAME "     Still waiting for ReadThread (status = %08x)\n", status));
    timeout.QuadPart = (LONGLONG)-1 * 1000 * 1000 * 10;
  }
  ObDereferenceObject(xpdd->XenBus_ReadThread);
KdPrint((__DRIVER_NAME "     Waiting for WatchThread\n"));
  timeout.QuadPart = (LONGLONG)-1 * 1000 * 1000 * 10;
  while ((status = KeWaitForSingleObject(xpdd->XenBus_WatchThread, Executive, KernelMode, FALSE, &timeout)) != STATUS_SUCCESS)
  {
KdPrint((__DRIVER_NAME "     Still waiting for WatchThread (status = %08x)\n", status));
    timeout.QuadPart = (LONGLONG)-1 * 1000 * 1000 * 10;
  }
  ObDereferenceObject(xpdd->XenBus_WatchThread);
KdPrint((__DRIVER_NAME "     Done\n"));
  
  xpdd->XenBus_ShuttingDown = FALSE;

  FUNCTION_EXIT();

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
      KdPrint((__DRIVER_NAME "     ReadThreadProc still running... wtf?\n"));
    }
    while (xpdd->xen_store_interface->rsp_prod != xpdd->xen_store_interface->rsp_cons)
    {
      //KdPrint((__DRIVER_NAME "     a - Rsp_cons %d, rsp_prod %d.\n", xen_store_interface->rsp_cons, xen_store_interface->rsp_prod));
      if (xpdd->xen_store_interface->rsp_prod - xpdd->xen_store_interface->rsp_cons < sizeof(msg))
      {
        //KdPrint((__DRIVER_NAME " +++ Message incomplete (not even a full header)\n"));
        break;
      }
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

  for(;;)
  {
    KeWaitForSingleObject(&xpdd->XenBus_WatchThreadEvent, Executive, KernelMode, FALSE, NULL);
    ExAcquireFastMutex(&xpdd->watch_mutex);
    if (xpdd->XenBus_ShuttingDown)
    {
      KdPrint((__DRIVER_NAME "     Shutdown detected in WatchThreadProc\n"));
      ExReleaseFastMutex(&xpdd->watch_mutex);
      PsTerminateSystemThread(0);
      KdPrint((__DRIVER_NAME "     WatchThreadProc still running... wtf?\n"));
    }
    while (xpdd->XenBus_WatchRingReadIndex != xpdd->XenBus_WatchRingWriteIndex)
    {
      xpdd->XenBus_WatchRingReadIndex = 
        (xpdd->XenBus_WatchRingReadIndex + 1) % WATCH_RING_SIZE;
      index = atoi(xpdd->XenBus_WatchRing[xpdd->XenBus_WatchRingReadIndex].Token);

      entry = &xpdd->XenBus_WatchEntries[index];
      if (!entry->Active || !entry->ServiceRoutine)
      {
        KdPrint((__DRIVER_NAME "     No watch for index %d\n", index));
        continue;
      }
      entry->Count++;
      entry->ServiceRoutine(xpdd->XenBus_WatchRing[xpdd->XenBus_WatchRingReadIndex].Path, entry->ServiceContext);
    }
    ExReleaseFastMutex(&xpdd->watch_mutex);
  }
}    

/*
Called at PASSIVE_LEVEL
Acquires the mutex
*/
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

  ExAcquireFastMutex(&xpdd->xenbus_mutex);
  rep = xenbus_msg_reply(xpdd, XS_WATCH, xbt, req, ARRAY_SIZE(req));
  ExReleaseFastMutex(&xpdd->xenbus_mutex);

  msg = errmsg(rep);
  if (!msg)
    ExFreePoolWithTag(rep, XENPCI_POOL_TAG);

  return msg;
}

/* called at PASSIVE_LEVEL */
NTSTATUS
XenBus_Suspend(PXENPCI_DEVICE_DATA xpdd)
{
  int i;
  
  /* we need to remove the watches as a watch firing could lead to a XenBus_Read/Write/Printf */
  ExAcquireFastMutex(&xpdd->watch_mutex);
  for (i = 0; i < MAX_WATCH_ENTRIES; i++) {
    if (xpdd->XenBus_WatchEntries[i].Active)
      XenBus_SendRemWatch(xpdd, XBT_NIL, xpdd->XenBus_WatchEntries[i].Path, i);
  }
  ExReleaseFastMutex(&xpdd->watch_mutex);

  // need to synchronise with readthread here too to ensure that it won't do anything silly
  
  return STATUS_SUCCESS;
}

/* called at PASSIVE_LEVEL */
NTSTATUS
XenBus_Resume(PXENPCI_DEVICE_DATA xpdd)
{
  NTSTATUS status;
  int i;

  FUNCTION_ENTER();

  status = XenBus_Connect(xpdd);
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  
  for (i = 0; i < MAX_WATCH_ENTRIES; i++)
  {
    if (xpdd->XenBus_WatchEntries[i].Active)
    {
      KdPrint((__DRIVER_NAME "     Adding watch for path = %s\n", xpdd->XenBus_WatchEntries[i].Path));
      XenBus_SendAddWatch(xpdd, XBT_NIL, xpdd->XenBus_WatchEntries[i].Path, i);
    }
  }
  FUNCTION_EXIT();
  
  return STATUS_SUCCESS;
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

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  ASSERT(strlen(Path) < ARRAY_SIZE(w_entry->Path));

  ExAcquireFastMutex(&xpdd->watch_mutex);

  for (i = 0; i < MAX_WATCH_ENTRIES; i++)
    if (xpdd->XenBus_WatchEntries[i].Active == 0)
      break;
  
  if (i == MAX_WATCH_ENTRIES)
  {
    KdPrint((__DRIVER_NAME " +++ No more watch slots left\n"));
    ExReleaseFastMutex(&xpdd->watch_mutex);
    return NULL;
  }

  /* must init watchentry before starting watch */
  
  w_entry = &xpdd->XenBus_WatchEntries[i];
  strncpy(w_entry->Path, Path, ARRAY_SIZE(w_entry->Path));
  w_entry->ServiceRoutine = ServiceRoutine;
  w_entry->ServiceContext = ServiceContext;
  w_entry->Count = 0;
  w_entry->Active = 1;

  ExReleaseFastMutex(&xpdd->watch_mutex);

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
  char *msg;
  int i;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  ExAcquireFastMutex(&xpdd->watch_mutex);

  // check that Path < 128 chars

  for (i = 0; i < MAX_WATCH_ENTRIES; i++)
  {
#if 0
    if (xpdd->XenBus_WatchEntries[i].Active)
    {
    KdPrint((__DRIVER_NAME "     (%d == 1) = %d\n", xpdd->XenBus_WatchEntries[i].Active, xpdd->XenBus_WatchEntries[i].Active == 1));
    KdPrint((__DRIVER_NAME "     strcmp(%s, %s) = %d\n", xpdd->XenBus_WatchEntries[i].Path, Path, strcmp(xpdd->XenBus_WatchEntries[i].Path, Path)));
    KdPrint((__DRIVER_NAME "     (%p == %p) = %d\n", xpdd->XenBus_WatchEntries[i].ServiceRoutine, ServiceRoutine, xpdd->XenBus_WatchEntries[i].ServiceRoutine == ServiceRoutine));
    KdPrint((__DRIVER_NAME "     (%p == %p) = %d\n", xpdd->XenBus_WatchEntries[i].ServiceContext, ServiceContext, xpdd->XenBus_WatchEntries[i].ServiceContext == ServiceContext));
#endif
    if (xpdd->XenBus_WatchEntries[i].Active == 1
      && strcmp(xpdd->XenBus_WatchEntries[i].Path, Path) == 0
      && xpdd->XenBus_WatchEntries[i].ServiceRoutine == ServiceRoutine
      && xpdd->XenBus_WatchEntries[i].ServiceContext == ServiceContext)
    {
      KdPrint((__DRIVER_NAME "     Match\n"));
      break;
    }
#if 0
    }
#endif
  }

  if (i == MAX_WATCH_ENTRIES)
  {
    ExReleaseFastMutex(&xpdd->watch_mutex);
    KdPrint((__DRIVER_NAME "     Watch not set - can't remove\n"));
    return NULL;
  }

  xpdd->XenBus_WatchEntries[i].Active = 0;
  xpdd->XenBus_WatchEntries[i].Path[0] = 0;

  ExReleaseFastMutex(&xpdd->watch_mutex);

  msg = XenBus_SendRemWatch(Context, xbt, Path, i);
  
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return msg;
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
