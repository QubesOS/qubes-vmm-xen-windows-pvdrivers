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

struct xenbus_req_info
{
  int In_Use:1;
  KEVENT WaitEvent;
  void *Reply;
};

typedef struct {
  char Path[128];
  PXENBUS_WATCH_CALLBACK ServiceRoutine;
  PVOID ServiceContext;
  int Count;
  int Active;
} XENBUS_WATCH_ENTRY, *PXENBUS_WATCH_ENTRY;

typedef struct {
  char Path[128];
  char Token[10];
} XENBUS_WATCH_RING;

#define WATCH_RING_SIZE 128

static XENBUS_WATCH_RING XenBus_WatchRing[WATCH_RING_SIZE];
static int XenBus_WatchRingReadIndex;
static int XenBus_WatchRingWriteIndex;

#define MAX_WATCH_ENTRIES 128

static XENBUS_WATCH_ENTRY XenBus_WatchEntries[MAX_WATCH_ENTRIES];

#define NR_REQS 32
//#define XENSTORE_RING_SIZE 1024

//#define XENSTORE_RING_SIZE 1024
//typedef uint32_t XENSTORE_RING_IDX;
//#define MASK_XENSTORE_IDX(idx) ((idx) & (XENSTORE_RING_SIZE-1))

static struct xenstore_domain_interface *xen_store_interface;

static struct xenbus_req_info req_info[NR_REQS];
static int nr_live_reqs;
//static spinlock_t req_lock = SPIN_LOCK_UNLOCKED;

static HANDLE XenBus_ReadThreadHandle;
static KEVENT XenBus_ReadThreadEvent;

static HANDLE XenBus_WatchThreadHandle;
static KEVENT XenBus_WatchThreadEvent;

static BOOLEAN XenBus_ShuttingDown;

static void
XenBus_ReadThreadProc(PVOID StartContext);
static void
XenBus_WatchThreadProc(PVOID StartContext);

static BOOLEAN
XenBus_Interrupt(PKINTERRUPT Interrupt, PVOID ServiceContext);

static int allocate_xenbus_id(void)
{
  static int probe;
  int o_probe;

  //KdPrint((__DRIVER_NAME " --> allocate_xenbus_id\n"));

  for (;;)
  {
//    spin_lock(&req_lock);
    if (nr_live_reqs < NR_REQS)
      break;
//    spin_unlock(&req_lock);
//    wait_event(req_wq, (nr_live_reqs < NR_REQS));
  }

  o_probe = probe;

  for (;;)
  {
    if (!req_info[o_probe].In_Use)
      break;
    o_probe = (o_probe + 1) % NR_REQS;
//    BUG_ON(o_probe == probe);
  }
  nr_live_reqs++;
  req_info[o_probe].In_Use = 1;
  probe = (o_probe + 1) % NR_REQS;
  //spin_unlock(&req_lock);
  //init_waitqueue_head(&req_info[o_probe].waitq);
  KeInitializeEvent(&req_info[o_probe].WaitEvent, SynchronizationEvent, FALSE);

  //KdPrint((__DRIVER_NAME " <-- allocate_xenbus_id\n"));

  return o_probe;
}

static void release_xenbus_id(int id)
{
//    BUG_ON(!req_info[id].in_use);
//    spin_lock(&req_lock);
    req_info[id].In_Use = 0;
    nr_live_reqs--;
    req_info[id].In_Use = 0;
//    if (nr_live_reqs == NR_REQS - 1)
//        wake_up(&req_wq);
//    spin_unlock(&req_lock);
}


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

void wait_for_watch(void)
{
//    DEFINE_WAIT(w);
//    add_waiter(w,watch_queue);
//    schedule();
//    remove_waiter(w);
//    wake(current);
}

struct write_req {
    const void *data;
    unsigned len;
};

static evtchn_port_t xen_store_evtchn;

static void xb_write(int type, int req_id, xenbus_transaction_t trans_id,
                     const struct write_req *req, int nr_reqs)
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

  //KdPrint((__DRIVER_NAME " --> xb_write\n"));

  for (r = 0; r < nr_reqs; r++)
    len += req[r].len;
  m.len = len;
  len += sizeof(m);

  cur_req = &header_req;

//  BUG_ON(len > XENSTORE_RING_SIZE);
  /* Wait for the ring to drain to the point where we can send the
     message. */
  prod = xen_store_interface->req_prod;

  //KdPrint((__DRIVER_NAME " prod = %08x\n", prod));

  if (prod + len - xen_store_interface->req_cons > XENSTORE_RING_SIZE)
  {
    /* Wait for there to be space on the ring */
    //KdPrint((__DRIVER_NAME " prod %d, len %d, cons %d, size %d; waiting.\n", prod, len, xen_store_interface->req_cons, XENSTORE_RING_SIZE));
//    wait_event(xb_waitq, xen_store_interface->req_prod + len - xen_store_interface->req_cons <= XENSTORE_RING_SIZE);
    //KdPrint((__DRIVER_NAME " Back from wait.\n"));
    prod = xen_store_interface->req_prod;
  }

  /* We're now guaranteed to be able to send the message without
     overflowing the ring.  Do so. */

  total_off = 0;
  req_off = 0;

  while (total_off < len)
  {
    this_chunk = min(cur_req->len - req_off,XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod));
    memcpy((char *)xen_store_interface->req + MASK_XENSTORE_IDX(prod), (char *)cur_req->data + req_off, this_chunk);
    prod += this_chunk;
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

  xen_store_interface->req_prod += len;

  //KdPrint((__DRIVER_NAME " prod = %08x\n", xen_store_interface->req_prod));

  /* Send evtchn to notify remote */
  EvtChn_Notify(xen_store_evtchn);

  //KdPrint((__DRIVER_NAME " <-- xb_write\n"));
}

static struct xsd_sockmsg *
xenbus_msg_reply(int type, xenbus_transaction_t trans, struct write_req *io, int nr_reqs)
{
  int id;
//  DEFINE_WAIT(w);
  struct xsd_sockmsg *rep;

//  KdPrint((__DRIVER_NAME " --> xenbus_msg_reply\n"));

  id = allocate_xenbus_id();
//  add_waiter(w, req_info[id].waitq);

  xb_write(type, id, trans, io, nr_reqs);
//
//  schedule();
//  remove_waiter(w);
//  wake(current);
//
//  KdPrint((__DRIVER_NAME "     starting wait\n"));

  KeWaitForSingleObject(&req_info[id].WaitEvent, Executive, KernelMode, FALSE, NULL);

  //KdPrint((__DRIVER_NAME "     wait complete\n"));

  rep = req_info[id].Reply;
//  BUG_ON(rep->req_id != id);
  release_xenbus_id(id);
//  KdPrint((__DRIVER_NAME " <-- xenbus_msg_reply\n"));
  return rep;
}

char *
XenBus_Read(xenbus_transaction_t xbt, const char *path, char **value)
{
    struct write_req req[] = { {path, strlen(path) + 1} };
    struct xsd_sockmsg *rep;
    char *res;
    char *msg;

    rep = xenbus_msg_reply(XS_READ, xbt, req, ARRAY_SIZE(req));
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
    return NULL;
}

char *
XenBus_Write(xenbus_transaction_t xbt, const char *path, const char *value)
{
    struct write_req req[] = {
        {path, strlen(path) + 1},
        {value, strlen(value) + 1},
    };
    struct xsd_sockmsg *rep;
    char *msg;

    rep = xenbus_msg_reply(XS_WRITE, xbt, req, ARRAY_SIZE(req));
    msg = errmsg(rep);
    if (msg)
      return msg;
    ExFreePoolWithTag(rep, XENPCI_POOL_TAG);
    return NULL;
}

char* xenbus_wait_for_value(const char* path,const char* value)
{
  UNREFERENCED_PARAMETER(path);
  UNREFERENCED_PARAMETER(value);
//  for(;;)
//  {
//    char *res, *msg;
//    int r;
//
//    msg = xenbus_read(XBT_NIL, path, &res);
//    if(msg) return msg;
//
//    r = strcmp(value,res);
//    ExFreePoolWithTag(res, XENPCI_POOL_TAG);
//
//    if(r==0)
//      break;
//    else
//      wait_for_watch();
//    }
    return NULL;
}

NTSTATUS
XenBus_Init()
{
  NTSTATUS Status;
  OBJECT_ATTRIBUTES oa;
  int i;

  KdPrint((__DRIVER_NAME " --> XenBus_Init\n"));

  xen_store_evtchn = EvtChn_GetXenStorePort();
  xen_store_interface = EvtChn_GetXenStoreRingAddr();

  for (i = 0; i < MAX_WATCH_ENTRIES; i++)
    XenBus_WatchEntries[i].Active = 0;

  KeInitializeEvent(&XenBus_ReadThreadEvent, SynchronizationEvent, FALSE);
  KeInitializeEvent(&XenBus_WatchThreadEvent, SynchronizationEvent, FALSE);
  XenBus_ShuttingDown = FALSE;

  //InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
  //Status = PsCreateSystemThread(&XenBus_ReadThreadHandle, THREAD_ALL_ACCESS, &oa, NULL, NULL, XenBus_ReadThreadProc, NULL);
  Status = PsCreateSystemThread(&XenBus_ReadThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, XenBus_ReadThreadProc, NULL);

  //InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
  //Status = PsCreateSystemThread(&XenBus_WatchThreadHandle, THREAD_ALL_ACCESS, &oa, NULL, NULL, XenBus_WatchThreadProc, NULL);
  Status = PsCreateSystemThread(&XenBus_WatchThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, XenBus_WatchThreadProc, NULL);

  KdPrint((__DRIVER_NAME " <-- XenBus_Init\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
XenBus_Start()
{
  KdPrint((__DRIVER_NAME " --> XenBus_Start\n"));

  EvtChn_Bind(xen_store_evtchn, XenBus_Interrupt, NULL);

  KdPrint((__DRIVER_NAME " <-- XenBus_Start\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
XenBus_Stop()
{
  int i;

  KdPrint((__DRIVER_NAME " --> XenBus_Stop\n"));

  for (i = 0; i < MAX_WATCH_ENTRIES; i++)
  {
    if (XenBus_WatchEntries[i].Active)
      XenBus_RemWatch(XBT_NIL, XenBus_WatchEntries[i].Path, XenBus_WatchEntries[i].ServiceRoutine, XenBus_WatchEntries[i].ServiceContext);
  }

  EvtChn_Unbind(xen_store_evtchn);

  KdPrint((__DRIVER_NAME " <-- XenBus_Stop\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
XenBus_Close()
{
  PKWAIT_BLOCK WaitBlockArray[2];
  PVOID WaitArray[2];

  XenBus_ShuttingDown = TRUE;

  KdPrint((__DRIVER_NAME "     Signalling Threads\n"));
  KeSetEvent(&XenBus_ReadThreadEvent, 1, FALSE);
  KeSetEvent(&XenBus_WatchThreadEvent, 1, FALSE);
  KdPrint((__DRIVER_NAME "     Waiting for threads to die\n"));
  ObReferenceObjectByHandle(XenBus_ReadThreadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, &WaitArray[0], NULL);
  ObReferenceObjectByHandle(XenBus_WatchThreadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, &WaitArray[1], NULL);
  KeWaitForMultipleObjects(2, WaitArray, WaitAll, Executive, KernelMode, FALSE, NULL, WaitBlockArray);
  KdPrint((__DRIVER_NAME "     Threads are dead\n"));

  XenBus_ShuttingDown = FALSE;

  ObDereferenceObject(WaitArray[0]);
  ObDereferenceObject(WaitArray[1]);

  ZwClose(XenBus_WatchThreadHandle);
  ZwClose(XenBus_ReadThreadHandle);

  KdPrint((__DRIVER_NAME " <-- XenBus_Close\n"));

  return STATUS_SUCCESS;
}

char *
XenBus_List(xenbus_transaction_t xbt, const char *pre, char ***contents)
{
  struct xsd_sockmsg *reply, *repmsg;
  struct write_req req[] = { { pre, strlen(pre)+1 } };
  ULONG nr_elems, x, i;
  char **res;
  char *msg;

  //KdPrint((__DRIVER_NAME " --> xenbus_ls\n"));

  repmsg = xenbus_msg_reply(XS_DIRECTORY, xbt, req, ARRAY_SIZE(req));
  msg = errmsg(repmsg);
  if (msg) {
    *contents = NULL;
    //KdPrint((__DRIVER_NAME " <-- xenbus_ls (error)\n"));
    return msg;
  }
  reply = repmsg + 1;
  for (x = nr_elems = 0; x < repmsg->len; x++)
    nr_elems += (((char *)reply)[x] == 0);
  res = ExAllocatePoolWithTag(NonPagedPool, sizeof(res[0]) * (nr_elems + 1), XENPCI_POOL_TAG);
  for (x = i = 0; i < nr_elems; i++) {
    int l = strlen((char *)reply + x);
    res[i] = ExAllocatePoolWithTag(NonPagedPool, l + 1, XENPCI_POOL_TAG);
    memcpy(res[i], (char *)reply + x, l + 1);
    x += l + 1;
  }
  res[i] = NULL;
  ExFreePoolWithTag(repmsg, XENPCI_POOL_TAG);
  *contents = res;
  //KdPrint((__DRIVER_NAME " <-- xenbus_ls\n"));
  return NULL;
}

void
do_ls_test(const char *pre)
{
  char **dirs;
  int x;
  char *msg;

  //KdPrint((__DRIVER_NAME " <-- do_ls_test(\"%s\")\n", pre));

  msg = XenBus_List(XBT_NIL, pre, &dirs);
  if (msg)
  {
    //KdPrint((__DRIVER_NAME "     Error in xenbus ls: %s\n", msg));
    ExFreePoolWithTag(msg, XENPCI_POOL_TAG);
    return;
  }
  for (x = 0; dirs[x]; x++)
  {
    //KdPrint((__DRIVER_NAME "     ls %s[%d] -> %s\n", pre, x, dirs[x]));
    ExFreePoolWithTag(dirs[x], XENPCI_POOL_TAG);
  }
  ExFreePoolWithTag(dirs, XENPCI_POOL_TAG);
  //KdPrint((__DRIVER_NAME " --> do_ls_test\n"));
}

static void
XenBus_ReadThreadProc(PVOID StartContext) {
  int NewWriteIndex;
  struct xsd_sockmsg msg;
  char *payload;
  char *path, *token;

  UNREFERENCED_PARAMETER(StartContext);

  for(;;)
  {
    KeWaitForSingleObject(&XenBus_ReadThreadEvent, Executive, KernelMode, FALSE, NULL);
    if (XenBus_ShuttingDown)
    {
      KdPrint((__DRIVER_NAME "     Shutdown detected in ReadThreadProc\n"));
      PsTerminateSystemThread(0);
    }
    //KdPrint((__DRIVER_NAME "     ReadThread Woken (Count = %d)\n", ReadThreadWaitCount++));
    while (xen_store_interface->rsp_prod != xen_store_interface->rsp_cons)
    {
      //KdPrint((__DRIVER_NAME "     a - Rsp_cons %d, rsp_prod %d.\n", xen_store_interface->rsp_cons, xen_store_interface->rsp_prod));
      if (xen_store_interface->rsp_prod - xen_store_interface->rsp_cons < sizeof(msg))
      {
        //KdPrint((__DRIVER_NAME " +++ Message incomplete (not even a full header)\n"));
        break;
      }
      //_ReadBarrier();
      KeMemoryBarrier();
      memcpy_from_ring(xen_store_interface->rsp, &msg, MASK_XENSTORE_IDX(xen_store_interface->rsp_cons), sizeof(msg));
      if (xen_store_interface->rsp_prod - xen_store_interface->rsp_cons < sizeof(msg) + msg.len)
      {
        //KdPrint((__DRIVER_NAME " +++ Message incomplete (header but not full body)\n"));
        break;
      }
  
      if(msg.type == XS_WATCH_EVENT)
      {
        payload = ExAllocatePoolWithTag(NonPagedPool, sizeof(msg) + msg.len, XENPCI_POOL_TAG);
  
        memcpy_from_ring(xen_store_interface->rsp, payload, MASK_XENSTORE_IDX(xen_store_interface->rsp_cons), msg.len + sizeof(msg));
  
        xen_store_interface->rsp_cons += msg.len + sizeof(msg);
        //KdPrint((__DRIVER_NAME "     b - Rsp_cons %d, rsp_prod %d.\n", xen_store_interface->rsp_cons, xen_store_interface->rsp_prod));
  
        path = payload + sizeof(msg);
        token = path + strlen(path) + 1;

        NewWriteIndex = (XenBus_WatchRingWriteIndex + 1) & 127;
        if (NewWriteIndex != XenBus_WatchRingReadIndex)
        {
          strncpy(XenBus_WatchRing[NewWriteIndex].Path, path, 128);
          strncpy(XenBus_WatchRing[NewWriteIndex].Token, token, 10);
          XenBus_WatchRingWriteIndex = NewWriteIndex;
        }
        else
        {
          KdPrint((__DRIVER_NAME " +++ Queue full Path = %s Token = %s\n", path, token));
          // drop the message on the floor
          continue;
        }

        ExFreePoolWithTag(payload, XENPCI_POOL_TAG);
        //KdPrint((__DRIVER_NAME " +++ Watch Path = %s Token = %s\n", path, token));
        KeSetEvent(&XenBus_WatchThreadEvent, 1, FALSE);
      }
      else
      {  
        req_info[msg.req_id].Reply = ExAllocatePoolWithTag(NonPagedPool, sizeof(msg) + msg.len, XENPCI_POOL_TAG);
        memcpy_from_ring(xen_store_interface->rsp, req_info[msg.req_id].Reply, MASK_XENSTORE_IDX(xen_store_interface->rsp_cons), msg.len + sizeof(msg));
        xen_store_interface->rsp_cons += msg.len + sizeof(msg);
        //KdPrint((__DRIVER_NAME "     c - Rsp_cons %d, rsp_prod %d.\n", xen_store_interface->rsp_cons, xen_store_interface->rsp_prod));
        //KdPrint((__DRIVER_NAME " +++ Message = %s\n", ((char *)req_info[msg.req_id].Reply) + sizeof(msg)));
        KeSetEvent(&req_info[msg.req_id].WaitEvent, 1, FALSE);
      }
    }
  }
}

static void
XenBus_WatchThreadProc(PVOID StartContext)
{
  int index;
  PXENBUS_WATCH_ENTRY entry;

  UNREFERENCED_PARAMETER(StartContext);

  for(;;)
  {
    KeWaitForSingleObject(&XenBus_WatchThreadEvent, Executive, KernelMode, FALSE, NULL);
    if (XenBus_ShuttingDown)
    {
      KdPrint((__DRIVER_NAME "     Shutdown detected in WatchThreadProc\n"));
      PsTerminateSystemThread(0);
    }
    while (XenBus_WatchRingReadIndex != XenBus_WatchRingWriteIndex)
    {
      XenBus_WatchRingReadIndex = (XenBus_WatchRingReadIndex + 1) & 127;
      index = atoi(XenBus_WatchRing[XenBus_WatchRingReadIndex].Token);
      //XenBus_WatchRing[XenBus_WatchRingReadIndex].Path
      //XenBus_WatchRing[XenBus_WatchRingReadIndex].Token

      entry = &XenBus_WatchEntries[index];
      if (!entry->Active)
      {
        KdPrint((__DRIVER_NAME " +++ Watch not active! = %s Token = %s\n", XenBus_WatchRing[XenBus_WatchRingReadIndex].Path, XenBus_WatchRing[XenBus_WatchRingReadIndex].Token));
        continue;
      }
      entry->Count++;
      if (!entry->ServiceRoutine)
      {
        KdPrint((__DRIVER_NAME " +++ no handler for watch! = %s Token = %s\n", XenBus_WatchRing[XenBus_WatchRingReadIndex].Path, XenBus_WatchRing[XenBus_WatchRingReadIndex].Token));
        continue;
      }
      //KdPrint((__DRIVER_NAME " +++ Watch Triggered Path = %s Token = %d (%s)\n", XenBus_WatchRing[XenBus_WatchRingReadIndex].Path, index, XenBus_WatchRing[XenBus_WatchRingReadIndex].Token));
      entry->ServiceRoutine(XenBus_WatchRing[XenBus_WatchRingReadIndex].Path, entry->ServiceContext);
    }
  }
}    

char *
XenBus_AddWatch(xenbus_transaction_t xbt, const char *Path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext)
{
  struct xsd_sockmsg *rep;
  char *msg;
  int i;
  char Token[20];
  struct write_req req[2];

//  KdPrint((__DRIVER_NAME " --> XenBus_AddWatch\n"));

  // check that Path < 128 chars

  for (i = 0; i < MAX_WATCH_ENTRIES; i++)
    if (XenBus_WatchEntries[i].Active == 0)
      break;
  
  if (i == MAX_WATCH_ENTRIES)
  {
    KdPrint((__DRIVER_NAME " +++ No more watch slots left\n"));
    return NULL;
  }

  req[0].data = Path;
  req[0].len = strlen(Path) + 1;

  RtlStringCbPrintfA(Token, ARRAY_SIZE(Token), "%d", i);
  req[1].data = Token;
  req[1].len = strlen(Token) + 1;

  rep = xenbus_msg_reply(XS_WATCH, xbt, req, ARRAY_SIZE(req));

  msg = errmsg(rep);
  if (msg)
    return msg;

  ExFreePoolWithTag(rep, XENPCI_POOL_TAG);

  strncpy(XenBus_WatchEntries[i].Path, Path, 128);
  XenBus_WatchEntries[i].ServiceRoutine = ServiceRoutine;
  XenBus_WatchEntries[i].ServiceContext = ServiceContext;
  XenBus_WatchEntries[i].Count = 0;
  XenBus_WatchEntries[i].Active = 1;

//  KdPrint((__DRIVER_NAME " <-- XenBus_AddWatch\n"));

  return NULL;
}

char *
XenBus_RemWatch(xenbus_transaction_t xbt, const char *Path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext)
{
  struct xsd_sockmsg *rep;
  char *msg;
  int i;
  char Token[20];
  struct write_req req[2];

  //KdPrint((__DRIVER_NAME " --> XenBus_RemWatch\n"));

  // check that Path < 128 chars

  for (i = 0; i < MAX_WATCH_ENTRIES; i++) {
    if (XenBus_WatchEntries[i].Active == 1 && strcmp(XenBus_WatchEntries[i].Path, Path) == 0 && XenBus_WatchEntries[i].ServiceRoutine == ServiceRoutine && XenBus_WatchEntries[i].ServiceContext == ServiceContext)
      break;
  }

  if (i == MAX_WATCH_ENTRIES)
  {
    KdPrint((__DRIVER_NAME "     Watch not set - can't remove\n"));
    return NULL;
  }

  req[0].data = Path;
  req[0].len = strlen(Path) + 1;

  RtlStringCbPrintfA(Token, ARRAY_SIZE(Token), "%d", i);
  req[1].data = Token;
  req[1].len = strlen(Token) + 1;

  rep = xenbus_msg_reply(XS_UNWATCH, xbt, req, ARRAY_SIZE(req));

  msg = errmsg(rep);
  if (msg)
    return msg;

  ExFreePoolWithTag(rep, XENPCI_POOL_TAG);

  XenBus_WatchEntries[i].Active = 0;

  //KdPrint((__DRIVER_NAME " <-- XenBus_RemWatch\n"));

  return NULL;
}


char *
XenBus_StartTransaction(xenbus_transaction_t *xbt)
{
  /* xenstored becomes angry if you send a length 0 message, so just
     shove a nul terminator on the end */
  struct write_req req = { "", 1};
  struct xsd_sockmsg *rep;
  char *err;

  rep = xenbus_msg_reply(XS_TRANSACTION_START, 0, &req, 1);
  err = errmsg(rep);
  if (err)
    return err;
  *xbt = atoi((char *)(rep + 1));
  //sscanf((char *)(rep + 1), "%u", xbt);
  ExFreePoolWithTag(rep, XENPCI_POOL_TAG);
  return NULL;
}

char *
XenBus_EndTransaction(xenbus_transaction_t t, int abort, int *retry)
{
  struct xsd_sockmsg *rep;
  struct write_req req;
  char *err;

  *retry = 0;

  req.data = abort ? "F" : "T";
  req.len = 2;
  rep = xenbus_msg_reply(XS_TRANSACTION_END, t, &req, 1);
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
  return NULL;
}
/*
void
XenBus_ThreadProc(PVOID StartContext)
{
  char *response;

  //KdPrint((__DRIVER_NAME " --> XenBus_ThreadProc\n"));

  //do_ls_test("device");

//  do_ls_test("local");

//  do_ls_test("control");

//  do_ls_test(".");

  response = XenBus_AddWatch(XBT_NIL, SHUTDOWN_PATH, XenBus_ShutdownHandler, NULL);

  //KdPrint((__DRIVER_NAME " <-- watch response = '%s'\n", response)); 

  //KdPrint((__DRIVER_NAME " <-- XenBus_ThreadProc\n"));
}
*/

static BOOLEAN
XenBus_Interrupt(PKINTERRUPT Interrupt, PVOID ServiceContext)
{
  UNREFERENCED_PARAMETER(Interrupt);
  UNREFERENCED_PARAMETER(ServiceContext);

  //KdPrint((__DRIVER_NAME " --> XenBus_Interrupt (Count = %d)\n", ReadThreadSetCount++));

  KeSetEvent(&XenBus_ReadThreadEvent, 1, FALSE);

  //KdPrint((__DRIVER_NAME " <-- XenBus_Interrupt\n"));

  return TRUE;
}

char *
XenBus_Printf(xenbus_transaction_t xbt, const char *path, const char *fmt, ...)
{
  va_list ap;
  char buf[1024];

  va_start(ap, fmt);
  RtlStringCbVPrintfA(buf, ARRAY_SIZE(buf), fmt, ap);
  va_end(ap);
  return XenBus_Write(xbt, path, buf);
}