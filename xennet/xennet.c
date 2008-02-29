/*
PV Net Driver for Windows Xen HVM Domains
Copyright (C) 2007 James Harper
Copyright (C) 2007 Andrew Grover <andy.grover@oracle.com>

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

#include <stdlib.h>
#include <io/xenbus.h>
#include "xennet.h"

/* Xen macros use these, so they need to be redefined to Win equivs */
#define wmb() KeMemoryBarrier()
#define mb() KeMemoryBarrier()

//#if !defined (NDIS51_MINIPORT)
//#error requires NDIS 5.1 compilation environment
//#endif

#define GRANT_INVALID_REF 0

/* couldn't get regular xen ring macros to work...*/
#define __NET_RING_SIZE(type, _sz) \
    (__RD32( \
    (_sz - sizeof(struct type##_sring) + sizeof(union type##_sring_entry)) \
    / sizeof(union type##_sring_entry)))

#define NET_TX_RING_SIZE __NET_RING_SIZE(netif_tx, PAGE_SIZE)
#define NET_RX_RING_SIZE __NET_RING_SIZE(netif_rx, PAGE_SIZE)

#pragma warning(disable: 4127) // conditional expression is constant

struct _buffer_entry
{
  char data[PAGE_SIZE - sizeof(LIST_ENTRY) - sizeof(PNDIS_BUFFER)];
  LIST_ENTRY entry;
  PNDIS_BUFFER buffer;
} typedef buffer_entry_t;

static LARGE_INTEGER ProfTime_TxBufferGC;
static LARGE_INTEGER ProfTime_TxBufferFree;
static LARGE_INTEGER ProfTime_RxBufferAlloc;
static LARGE_INTEGER ProfTime_RxBufferFree;
static LARGE_INTEGER ProfTime_ReturnPacket;
static LARGE_INTEGER ProfTime_RxBufferCheck;
static LARGE_INTEGER ProfTime_Linearize;
static LARGE_INTEGER ProfTime_SendPackets;
static LARGE_INTEGER ProfTime_SendQueuedPackets;

static int ProfCount_TxBufferGC;
static int ProfCount_TxBufferFree;
static int ProfCount_RxBufferAlloc;
static int ProfCount_RxBufferFree;
static int ProfCount_ReturnPacket;
static int ProfCount_RxBufferCheck;
static int ProfCount_Linearize;
static int ProfCount_SendPackets;
static int ProfCount_SendQueuedPackets;

struct xennet_info
{
  /* Base device vars */
  PDEVICE_OBJECT pdo;
  PDEVICE_OBJECT fdo;
  PDEVICE_OBJECT lower_do;
  WDFDEVICE wdf_device;
  WCHAR dev_desc[NAME_SIZE];

  /* NDIS-related vars */
  NDIS_HANDLE adapter_handle;
  NDIS_HANDLE packet_pool;
  NDIS_HANDLE buffer_pool;
  ULONG packet_filter;
  int connected;
  UINT8 perm_mac_addr[ETH_ALEN];
  UINT8 curr_mac_addr[ETH_ALEN];

  /* Misc. Xen vars */
  XEN_IFACE XenInterface;
  PXENPCI_XEN_DEVICE_DATA pdo_data;
  evtchn_port_t event_channel;
  ULONG state;
  KEVENT backend_state_change_event;
  KEVENT shutdown_event;
  char backend_path[MAX_XENBUS_STR_LEN];
  ULONG backend_state;

  /* Xen ring-related vars */
  KSPIN_LOCK rx_lock;
  KSPIN_LOCK tx_lock;

  LIST_ENTRY tx_waiting_pkt_list;
  LIST_ENTRY rx_free_buf_list;

  struct netif_tx_front_ring tx;
  struct netif_rx_front_ring rx;
  grant_ref_t tx_ring_ref;
  grant_ref_t rx_ring_ref;

  /* ptrs to the actual rings themselvves */
  struct netif_tx_sring *tx_pgs;
  struct netif_rx_sring *rx_pgs;

  /* MDLs for the above */
  PMDL tx_mdl;
  PMDL rx_mdl;

  /* Packets given to netback. The first entry in tx_pkts
   * is an index into a chain of free entries. */
  int tx_pkt_ids_used;
  PNDIS_PACKET tx_pkts[NET_TX_RING_SIZE+1];
  PNDIS_BUFFER rx_buffers[NET_RX_RING_SIZE];

  grant_ref_t gref_tx_head;
  grant_ref_t grant_tx_ref[NET_TX_RING_SIZE+1];
  grant_ref_t gref_rx_head;
  grant_ref_t grant_rx_ref[NET_RX_RING_SIZE];

  /* Receive-ring batched refills. */
#define RX_MIN_TARGET 8
#define RX_DFL_MIN_TARGET 64
#define RX_MAX_TARGET min(NET_RX_RING_SIZE, 256)
  ULONG rx_target;
  ULONG rx_max_target;
  ULONG rx_min_target;

  /* how many packets are in the net stack atm */
  LONG rx_outstanding;
  LONG tx_outstanding;

  /* stats */
  ULONG64 stat_tx_ok;
  ULONG64 stat_rx_ok;
  ULONG64 stat_tx_error;
  ULONG64 stat_rx_error;
  ULONG64 stat_rx_no_buffer;
};

/* This function copied from linux's lib/vsprintf.c, see it for attribution */
static unsigned long
simple_strtoul(const char *cp,char **endp,unsigned int base)
{
  unsigned long result = 0,value;

  if (!base) {
    base = 10;
    if (*cp == '0') {
      base = 8;
      cp++;
      if ((toupper(*cp) == 'X') && isxdigit(cp[1])) {
        cp++;
        base = 16;
      }
    }
  } else if (base == 16) {
    if (cp[0] == '0' && toupper(cp[1]) == 'X')
    cp += 2;
  }
  while (isxdigit(*cp) &&
  (value = isdigit(*cp) ? *cp-'0' : toupper(*cp)-'A'+10) < base) {
    result = result*base + value;
    cp++;
  }
  if (endp)
  *endp = (char *)cp;
  return result;
}

static void
add_id_to_freelist(struct xennet_info *xi, unsigned short id)
{
  xi->tx_pkts[id] = xi->tx_pkts[0];
  xi->tx_pkts[0]  = IntToPtr(id);
  xi->tx_pkt_ids_used--;
}

static unsigned short
get_id_from_freelist(struct xennet_info *xi)
{
  unsigned short id;
  if (xi->tx_pkt_ids_used >= NET_TX_RING_SIZE)
    return 0;
  id = (unsigned short)(unsigned long)xi->tx_pkts[0];
  xi->tx_pkts[0] = xi->tx_pkts[id];
  xi->tx_pkt_ids_used++;
  return id;
}

VOID
XenNet_SendQueuedPackets(struct xennet_info *xi);

// Called at DISPATCH_LEVEL
static NDIS_STATUS
XenNet_TxBufferGC(struct xennet_info *xi)
{
  RING_IDX cons, prod;
  unsigned short id;
  PNDIS_PACKET pkt;
  PMDL pmdl;
  PVOID ptr;
  LARGE_INTEGER tsc, dummy;

  ASSERT(xi->connected);
  ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  tsc = KeQueryPerformanceCounter(&dummy);

  KeAcquireSpinLockAtDpcLevel(&xi->tx_lock);

  do {
    prod = xi->tx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'rp'. */

    for (cons = xi->tx.rsp_cons; cons != prod; cons++) {
      struct netif_tx_response *txrsp;

      txrsp = RING_GET_RESPONSE(&xi->tx, cons);
      if (txrsp->status == NETIF_RSP_NULL)
        continue;

      id  = txrsp->id;
      pkt = xi->tx_pkts[id];
      xi->XenInterface.GntTbl_EndAccess(xi->XenInterface.InterfaceHeader.Context,
        xi->grant_tx_ref[id]);
      xi->grant_tx_ref[id] = GRANT_INVALID_REF;
      add_id_to_freelist(xi, id);

      /* free linearized data page */
      pmdl = *(PMDL *)pkt->MiniportReservedEx;
      ptr = MmGetMdlVirtualAddress(pmdl);
      IoFreeMdl(pmdl);
      NdisFreeMemory(ptr, 0, 0); // <= DISPATCH_LEVEL
      InterlockedDecrement(&xi->tx_outstanding);
      xi->stat_tx_ok++;
      NdisMSendComplete(xi->adapter_handle, pkt, NDIS_STATUS_SUCCESS);
    }

    xi->tx.rsp_cons = prod;

    /*
     * Set a new event, then check for race with update of tx_cons.
     * Note that it is essential to schedule a callback, no matter
     * how few buffers are pending. Even if there is space in the
     * transmit ring, higher layers may be blocked because too much
     * data is outstanding: in such cases notification from Xen is
     * likely to be the only kick that we'll get.
     */
    xi->tx.sring->rsp_event =
      prod + ((xi->tx.sring->req_prod - prod) >> 1) + 1;
    KeMemoryBarrier();
  } while ((cons == prod) && (prod != xi->tx.sring->rsp_prod));

  KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);

  /* if queued packets, send them now */
  XenNet_SendQueuedPackets(xi);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  ProfTime_TxBufferGC.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_TxBufferGC++;

  return NDIS_STATUS_SUCCESS;
}

static void
XenNet_TxBufferFree(struct xennet_info *xi)
{
  PNDIS_PACKET packet;
  PMDL pmdl;
  PLIST_ENTRY entry;
  unsigned short id;
  PVOID ptr;

  ASSERT(!xi->connected);

  /* Free packets in tx queue */
  entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  while (entry != &xi->tx_waiting_pkt_list)
  {
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);

    /* free linearized data page */
    pmdl = *(PMDL *)packet->MiniportReservedEx;
    ptr = MmGetMdlVirtualAddress(pmdl);
    IoFreeMdl(pmdl);
    NdisFreeMemory(ptr, 0, 0); // <= DISPATCH_LEVEL
    NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_FAILURE);
    entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  }

  /* free sent-but-not-completed packets */
  for (id = 1; id < NET_TX_RING_SIZE+1; id++) {
    if (xi->grant_tx_ref[id] == GRANT_INVALID_REF)
      continue;

    packet = xi->tx_pkts[id];
    xi->XenInterface.GntTbl_EndAccess(xi->XenInterface.InterfaceHeader.Context,
      xi->grant_tx_ref[id]);
    xi->grant_tx_ref[id] = GRANT_INVALID_REF;
    add_id_to_freelist(xi, id);

    /* free linearized data page */
    pmdl = *(PMDL *)packet->MiniportReservedEx;
    ptr = MmGetMdlVirtualAddress(pmdl);
    IoFreeMdl(pmdl);
    NdisFreeMemory(ptr, 0, 0); // <= DISPATCH_LEVEL

    NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_FAILURE);
  }
}

// Called at DISPATCH_LEVEL with rx lock held

static NDIS_STATUS
XenNet_RxBufferAlloc(struct xennet_info *xi)
{
  unsigned short id;
  PNDIS_BUFFER buffer;
  int i, batch_target, notify;
  RING_IDX req_prod = xi->rx.req_prod_pvt;
  grant_ref_t ref;
  netif_rx_request_t *req;
  PLIST_ENTRY entry;
  buffer_entry_t *buffer_entry;
  NDIS_STATUS status;
  LARGE_INTEGER tsc, dummy;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  tsc = KeQueryPerformanceCounter(&dummy);

  batch_target = xi->rx_target - (req_prod - xi->rx.rsp_cons);

  for (i = 0; i < batch_target; i++)
  {
    /* reuse entries off the free buffer list, unless it's exhausted */
    entry = RemoveHeadList(&xi->rx_free_buf_list);
    if (entry != &xi->rx_free_buf_list)
    {
      buffer = CONTAINING_RECORD(entry, buffer_entry_t, entry)->buffer;
    }
    else
    {
      status = NdisAllocateMemoryWithTag(&buffer_entry,
        sizeof(buffer_entry_t), XENNET_POOL_TAG);
      if (status != NDIS_STATUS_SUCCESS)
      {
        KdPrint(("NdisAllocateMemoryWithTag Failed! status = 0x%x\n", status));
        break;
      }
      NdisAllocateBuffer(&status, &buffer_entry->buffer, xi->buffer_pool,
        buffer_entry, sizeof(buffer_entry->data));
      ASSERT(status == NDIS_STATUS_SUCCESS); // should never fail
      buffer = buffer_entry->buffer;
    }

    /* Give to netback */
    id = (unsigned short)(req_prod + i) & (NET_RX_RING_SIZE - 1);
    ASSERT(!xi->rx_buffers[id]);
    xi->rx_buffers[id] = buffer;
    req = RING_GET_REQUEST(&xi->rx, req_prod + i);
    /* an NDIS_BUFFER is just a MDL, so we can get its pfn array */
    ref = xi->XenInterface.GntTbl_GrantAccess(
      xi->XenInterface.InterfaceHeader.Context, 0,
      *MmGetMdlPfnArray(buffer), FALSE);
    ASSERT((signed short)ref >= 0);
    xi->grant_rx_ref[id] = ref;

    req->id = id;
    req->gref = ref;
  }

  xi->rx.req_prod_pvt = req_prod + i;
  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xi->rx, notify);
  if (notify)
  {
    xi->XenInterface.EvtChn_Notify(xi->XenInterface.InterfaceHeader.Context,
      xi->event_channel);
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  ProfTime_RxBufferAlloc.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_RxBufferAlloc++;

  return NDIS_STATUS_SUCCESS;
}

/* Free all Rx buffers (on halt, for example) */
static void
XenNet_RxBufferFree(struct xennet_info *xi)
{
  int i;
  grant_ref_t ref;
  PNDIS_BUFFER buffer;
  KIRQL OldIrql;
  PVOID buff_va;
  PLIST_ENTRY entry;
  int ungranted;
  LARGE_INTEGER tsc, dummy;

  ASSERT(!xi->connected);

  tsc = KeQueryPerformanceCounter(&dummy);

  KeAcquireSpinLock(&xi->rx_lock, &OldIrql);

  for (i = 0; i < NET_RX_RING_SIZE; i++)
  {
    if (!xi->rx_buffers[i])
      continue;

    buffer = xi->rx_buffers[i];
    ref = xi->grant_rx_ref[i];

    /* don't check return, what can we do about it on failure? */
    ungranted = xi->XenInterface.GntTbl_EndAccess(xi->XenInterface.InterfaceHeader.Context, ref);

    NdisAdjustBufferLength(buffer, sizeof(buffer_entry_t));
    buff_va = NdisBufferVirtualAddressSafe(buffer, NormalPagePriority);
    NdisFreeBuffer(buffer);
    if (ungranted)
    {
      NdisFreeMemory(buff_va, 0, 0); // <= DISPATCH_LEVEL
    }
  }

  while ((entry = RemoveHeadList(&xi->rx_free_buf_list)) != &xi->rx_free_buf_list)
  {
    buffer = CONTAINING_RECORD(entry, buffer_entry_t, entry)->buffer;
    NdisAdjustBufferLength(buffer, sizeof(buffer_entry_t));
    buff_va = NdisBufferVirtualAddressSafe(buffer, NormalPagePriority);
    NdisFreeBuffer(buffer);
    NdisFreeMemory(buff_va, 0, 0); // <= DISPATCH_LEVEL
  }

  KeReleaseSpinLock(&xi->rx_lock, OldIrql);

  ProfTime_RxBufferFree.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_RxBufferFree++;
}

VOID
XenNet_ReturnPacket(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PNDIS_PACKET Packet
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
  PNDIS_BUFFER buffer;
  buffer_entry_t *buffer_entry;
  LARGE_INTEGER tsc, dummy;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  tsc = KeQueryPerformanceCounter(&dummy);

  NdisUnchainBufferAtBack(Packet, &buffer);
  while (buffer)
  {
    NdisAdjustBufferLength(buffer, sizeof(buffer_entry_t));
    buffer_entry = NdisBufferVirtualAddressSafe(buffer, NormalPagePriority);
    InsertTailList(&xi->rx_free_buf_list, &buffer_entry->entry);
    NdisUnchainBufferAtBack(Packet, &buffer);
  }

  NdisFreePacket(Packet);
  
  InterlockedDecrement(&xi->rx_outstanding);

  // if we are no longer connected then _halt needs to know when rx_outstanding reaches zero
  if (!xi->connected && !xi->rx_outstanding)
    KeSetEvent(&xi->shutdown_event, 1, FALSE);  

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  ProfTime_ReturnPacket.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_ReturnPacket++;
}

// Called at DISPATCH_LEVEL
static NDIS_STATUS
XenNet_RxBufferCheck(struct xennet_info *xi)
{
  RING_IDX cons, prod;
  PNDIS_PACKET packets[NET_RX_RING_SIZE];
  ULONG packet_count;
  PNDIS_BUFFER buffer;
  int moretodo;
  KIRQL OldIrql;
  struct netif_rx_response *rxrsp = NULL;
  int more_frags = 0;
  NDIS_STATUS status;
  LARGE_INTEGER tsc, dummy;
  LARGE_INTEGER time_received;
  
//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  tsc = KeQueryPerformanceCounter(&dummy);

  ASSERT(xi->connected);

  NdisGetCurrentSystemTime(&time_received);
  KeAcquireSpinLock(&xi->rx_lock, &OldIrql);

  packet_count = 0;
  do {
    prod = xi->rx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'rp'. */

    for (cons = xi->rx.rsp_cons; cons != prod; cons++) {

      rxrsp = RING_GET_RESPONSE(&xi->rx, cons);
      if (rxrsp->status <= 0
        || rxrsp->offset + rxrsp->status > PAGE_SIZE)
      {
        KdPrint((__DRIVER_NAME ": Error: rxrsp offset %d, size %d\n",
          rxrsp->offset, rxrsp->status));
        continue;
      }

      if (!more_frags) // handling the packet's 1st buffer
      {
        NdisAllocatePacket(&status, &packets[packet_count], xi->packet_pool);
        ASSERT(status == NDIS_STATUS_SUCCESS);
        NDIS_SET_PACKET_HEADER_SIZE(packets[packet_count], XN_HDR_SIZE);
      }

      buffer = xi->rx_buffers[rxrsp->id];
      xi->rx_buffers[rxrsp->id] = NULL;
      NdisAdjustBufferLength(buffer, rxrsp->status);
      NdisChainBufferAtBack(packets[packet_count], buffer);
      xi->XenInterface.GntTbl_EndAccess(xi->XenInterface.InterfaceHeader.Context,
        xi->grant_rx_ref[rxrsp->id]);
      xi->grant_rx_ref[rxrsp->id] = GRANT_INVALID_REF;

      ASSERT(!(rxrsp->flags & NETRXF_extra_info)); // not used on RX

      more_frags = rxrsp->flags & NETRXF_more_data;

      /* Packet done, pass it up */
      if (!more_frags)
      {
        xi->stat_rx_ok++;
        InterlockedIncrement(&xi->rx_outstanding);
        NDIS_SET_PACKET_STATUS(packets[packet_count], NDIS_STATUS_SUCCESS);
        NDIS_SET_PACKET_TIME_RECEIVED(packets[packet_count], time_received.QuadPart);
        packet_count++;
        if (packet_count == NET_RX_RING_SIZE)
        {
          NdisMIndicateReceivePacket(xi->adapter_handle, packets, packet_count);
          packet_count = 0;
        }
      }
    }
    xi->rx.rsp_cons = prod;

    RING_FINAL_CHECK_FOR_RESPONSES(&xi->rx, moretodo);
  } while (moretodo);

  if (more_frags)
  {
    KdPrint((__DRIVER_NAME "     Missing fragments\n"));
    XenNet_ReturnPacket(xi, packets[packet_count]);
  }

  if (packet_count != 0)
  {
    NdisMIndicateReceivePacket(xi->adapter_handle, packets, packet_count);
  }

  /* Give netback more buffers */
  XenNet_RxBufferAlloc(xi);

  KeReleaseSpinLock(&xi->rx_lock, OldIrql);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  ProfTime_RxBufferCheck.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_RxBufferCheck++;

  return NDIS_STATUS_SUCCESS;
}

// Called at DISPATCH_LEVEL

static BOOLEAN
XenNet_Interrupt(
  PKINTERRUPT Interrupt,
  PVOID ServiceContext
  )
{
  struct xennet_info *xi = ServiceContext;

  UNREFERENCED_PARAMETER(Interrupt);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  if (xi->connected)
  {
    XenNet_TxBufferGC(xi);
    XenNet_RxBufferCheck(xi);
  }
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

// Called at <= DISPATCH_LEVEL

static VOID
XenNet_BackEndStateHandler(char *Path, PVOID Data)
{
  struct xennet_info *xi = Data;
  char *Value;
  char *err;
  ULONG new_backend_state;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
//  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  err = xi->XenInterface.XenBus_Read(xi->XenInterface.InterfaceHeader.Context,
    XBT_NIL, Path, &Value);
  if (err)
  {
    KdPrint(("Failed to read %s\n", Path, err));
    return;
  }
  new_backend_state = atoi(Value);
  xi->XenInterface.FreeMem(Value);

  if (xi->backend_state == new_backend_state)
  {
    KdPrint((__DRIVER_NAME "     state unchanged\n"));
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
    return;
  }    

  xi->backend_state = new_backend_state;

  switch (xi->backend_state)
  {
  case XenbusStateUnknown:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Unknown\n"));  
    break;

  case XenbusStateInitialising:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialising\n"));  
    break;

  case XenbusStateInitWait:
    KdPrint((__DRIVER_NAME "     Backend State Changed to InitWait\n"));  
    break;

  case XenbusStateInitialised:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialised\n"));
    break;

  case XenbusStateConnected:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Connected\n"));  
    break;

  case XenbusStateClosing:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closing\n"));  
    break;

  case XenbusStateClosed:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closed\n"));  
    break;

  default:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Undefined = %d\n", xi->backend_state));
    break;
  }

  KeSetEvent(&xi->backend_state_change_event, 1, FALSE);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return;
}

static NDIS_STATUS
XenNet_Init(
  OUT PNDIS_STATUS OpenErrorStatus,
  OUT PUINT SelectedMediumIndex,
  IN PNDIS_MEDIUM MediumArray,
  IN UINT MediumArraySize,
  IN NDIS_HANDLE MiniportAdapterHandle,
  IN NDIS_HANDLE WrapperConfigurationContext
  )
{
  NDIS_STATUS status;
  UINT i;
  BOOLEAN medium_found = FALSE;
  struct xennet_info *xi = NULL;
  ULONG length;
  WDF_OBJECT_ATTRIBUTES wdf_attrs;
  char *res;
  char *Value;
  char TmpPath[MAX_XENBUS_STR_LEN];
  struct set_params {
    char *name;
    int value;
  } params[] = {
    {"tx-ring-ref", 0},
    {"rx-ring-ref", 0},
    {"event-channel", 0},
    {"request-rx-copy", 1},
    {"feature-rx-notify", 1},
    {"feature-no-csum-offload", 1},
    {"feature-sg", 1},
    {"feature-gso-tcpv4", 0},
    {NULL, 0},
  };
  int retry = 0;
  char *err;
  xenbus_transaction_t xbt = 0;
  KIRQL OldIrql;

  UNREFERENCED_PARAMETER(OpenErrorStatus);
  UNREFERENCED_PARAMETER(WrapperConfigurationContext);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  /* deal with medium stuff */
  for (i = 0; i < MediumArraySize; i++)
  {
    if (MediumArray[i] == NdisMedium802_3)
    {
      medium_found = TRUE;
      break;
    }
  }
  if (!medium_found)
  {
    KdPrint(("NIC_MEDIA_TYPE not in MediumArray\n"));
    return NDIS_STATUS_UNSUPPORTED_MEDIA;
  }
  *SelectedMediumIndex = i;

  /* Alloc memory for adapter private info */
  status = NdisAllocateMemoryWithTag(&xi, sizeof(*xi), XENNET_POOL_TAG);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("NdisAllocateMemoryWithTag failed with 0x%x\n", status));
    status = NDIS_STATUS_RESOURCES;
    goto err;
  }
  RtlZeroMemory(xi, sizeof(*xi));

  /* init xennet_info */
  xi->adapter_handle = MiniportAdapterHandle;
  xi->rx_target     = RX_DFL_MIN_TARGET;
  xi->rx_min_target = RX_DFL_MIN_TARGET;
  xi->rx_max_target = RX_MAX_TARGET;

  xi->state = XenbusStateUnknown;
  xi->backend_state = XenbusStateUnknown;

  KeInitializeSpinLock(&xi->tx_lock);
  KeInitializeSpinLock(&xi->rx_lock);

  InitializeListHead(&xi->rx_free_buf_list);
  InitializeListHead(&xi->tx_waiting_pkt_list);
  
  NdisAllocatePacketPool(&status, &xi->packet_pool, XN_RX_QUEUE_LEN,
    PROTOCOL_RESERVED_SIZE_IN_PACKET);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint(("NdisAllocatePacketPool failed with 0x%x\n", status));
    status = NDIS_STATUS_RESOURCES;
    goto err;
  }
  NdisSetPacketPoolProtocolId(xi->packet_pool, NDIS_PROTOCOL_ID_TCP_IP);

  NdisAllocateBufferPool(&status, &xi->buffer_pool, XN_RX_QUEUE_LEN);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint(("NdisAllocateBufferPool failed with 0x%x\n", status));
    status = NDIS_STATUS_RESOURCES;
    goto err;
  }

  NdisMGetDeviceProperty(MiniportAdapterHandle, &xi->pdo, &xi->fdo,
    &xi->lower_do, NULL, NULL);
  xi->pdo_data = (PXENPCI_XEN_DEVICE_DATA)xi->pdo->DeviceExtension;

  /* Initialize tx_pkts as a free chain containing every entry. */
  for (i = 0; i < NET_TX_RING_SIZE+1; i++) {
    xi->tx_pkts[i] = IntToPtr(i + 1);
    xi->grant_tx_ref[i] = GRANT_INVALID_REF;
  }
  for (i = 0; i < NET_RX_RING_SIZE; i++) {
    xi->rx_buffers[i] = NULL;
    xi->grant_rx_ref[i] = GRANT_INVALID_REF;
  }

  xi->packet_filter = NDIS_PACKET_TYPE_PROMISCUOUS;

  status = IoGetDeviceProperty(xi->pdo, DevicePropertyDeviceDescription,
    NAME_SIZE, xi->dev_desc, &length);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("IoGetDeviceProperty failed with 0x%x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  NdisMSetAttributesEx(xi->adapter_handle, (NDIS_HANDLE) xi,
    0, (NDIS_ATTRIBUTE_DESERIALIZE /*| NDIS_ATTRIBUTE_BUS_MASTER*/),
    NdisInterfaceInternal);

  WDF_OBJECT_ATTRIBUTES_INIT(&wdf_attrs);

  status = WdfDeviceMiniportCreate(WdfGetDriver(), &wdf_attrs, xi->fdo,
    xi->lower_do, xi->pdo, &xi->wdf_device);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("WdfDeviceMiniportCreate failed with 0x%x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  /* get lower (Xen) interfaces */

  status = WdfFdoQueryForInterface(xi->wdf_device, &GUID_XEN_IFACE,
    (PINTERFACE) &xi->XenInterface, sizeof(XEN_IFACE), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint(("WdfFdoQueryForInterface failed with status 0x%08x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath),
      "%s/backend", xi->pdo_data->Path);
  res = xi->XenInterface.XenBus_Read(xi->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
  if (res)
  {
    KdPrint((__DRIVER_NAME "    Failed to read backend path\n"));
    xi->XenInterface.FreeMem(res);
    status = NDIS_STATUS_FAILURE;
    goto err;
  }
  RtlStringCbCopyA(xi->backend_path, ARRAY_SIZE(xi->backend_path), Value);
  xi->XenInterface.FreeMem(Value);
  KdPrint((__DRIVER_NAME "backend path = %s\n", xi->backend_path));

  KeInitializeEvent(&xi->backend_state_change_event, SynchronizationEvent, FALSE);  
  KeInitializeEvent(&xi->shutdown_event, SynchronizationEvent, FALSE);  

  /* Add watch on backend state */
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->backend_path);
  xi->XenInterface.XenBus_AddWatch(xi->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, XenNet_BackEndStateHandler, xi);

  /* Tell backend we're coming up */
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(xi->XenInterface.InterfaceHeader.Context,
    XBT_NIL, TmpPath, "%d", XenbusStateInitialising);

  // wait here for signal that we are all set up
  while (xi->backend_state != XenbusStateInitWait)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive, KernelMode, FALSE, NULL);

  xi->event_channel = xi->XenInterface.EvtChn_AllocUnbound(
    xi->XenInterface.InterfaceHeader.Context, 0);
  xi->XenInterface.EvtChn_BindDpc(xi->XenInterface.InterfaceHeader.Context,
    xi->event_channel, XenNet_Interrupt, xi);

  xi->tx_mdl = AllocatePage();
  xi->tx_pgs = MmGetMdlVirtualAddress(xi->tx_mdl);
  SHARED_RING_INIT(xi->tx_pgs);
  FRONT_RING_INIT(&xi->tx, xi->tx_pgs, PAGE_SIZE);
  xi->tx_ring_ref = xi->XenInterface.GntTbl_GrantAccess(
    xi->XenInterface.InterfaceHeader.Context, 0,
    *MmGetMdlPfnArray(xi->tx_mdl), FALSE);

  xi->rx_mdl = AllocatePage();
  xi->rx_pgs = MmGetMdlVirtualAddress(xi->rx_mdl);
  SHARED_RING_INIT(xi->rx_pgs);
  FRONT_RING_INIT(&xi->rx, xi->rx_pgs, PAGE_SIZE);
  xi->rx_ring_ref = xi->XenInterface.GntTbl_GrantAccess(
    xi->XenInterface.InterfaceHeader.Context, 0,
    *MmGetMdlPfnArray(xi->rx_mdl), FALSE);

  /* fixup array for dynamic values */
  params[0].value = xi->tx_ring_ref;
  params[1].value = xi->rx_ring_ref;
  params[2].value = xi->event_channel;
  xi->XenInterface.XenBus_StartTransaction(
    xi->XenInterface.InterfaceHeader.Context, &xbt);

  for (err = NULL, i = 0; params[i].name; i++)
  {
    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/%s",
      xi->pdo_data->Path, params[i].name);
    err = xi->XenInterface.XenBus_Printf(xi->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", params[i].value);
    if (err)
    {
      KdPrint(("setting %s failed, err = %s\n", params[i].name, err));
      break;
    }
  }

  xi->XenInterface.XenBus_EndTransaction(xi->XenInterface.InterfaceHeader.Context,
    xbt, 1, &retry);
  if (err)
  {
    status = NDIS_STATUS_FAILURE;
    goto err;
  } 

  xi->connected = TRUE;

  KeMemoryBarrier(); // packets could be received anytime after we set Frontent to Connected

  xi->state = XenbusStateConnected;
  KdPrint((__DRIVER_NAME "     Set Frontend state to Connected\n"));
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(xi->XenInterface.InterfaceHeader.Context,
    XBT_NIL, TmpPath, "%d", xi->state);

  KdPrint((__DRIVER_NAME "     Waiting for backend to connect\n"));

  // wait here for signal that we are all set up
  while (xi->backend_state != XenbusStateConnected)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive, KernelMode, FALSE, NULL);

  KdPrint((__DRIVER_NAME "     Connected\n"));

  KeAcquireSpinLock(&xi->rx_lock, &OldIrql);
  XenNet_RxBufferAlloc(xi);
  KeReleaseSpinLock(&xi->rx_lock, OldIrql);

  /* get mac address */
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/mac", xi->backend_path);
  xi->XenInterface.XenBus_Read(xi->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
  if (!Value)
  {
    KdPrint((__DRIVER_NAME "    mac Read Failed\n"));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }
  else
  {
    char *s, *e;
    s = Value;
    for (i = 0; i < ETH_ALEN; i++) {
      xi->perm_mac_addr[i] = (UINT8)simple_strtoul(s, &e, 16);
      if ((s == e) || (*e != ((i == ETH_ALEN-1) ? '\0' : ':'))) {
        KdPrint((__DRIVER_NAME "Error parsing MAC address\n"));
        xi->XenInterface.FreeMem(Value);
        status = NDIS_STATUS_FAILURE;
        goto err;
      }
      s = e + 1;
    }
    memcpy(xi->curr_mac_addr, xi->perm_mac_addr, ETH_ALEN);
    xi->XenInterface.FreeMem(Value);
  }

  /* send fake arp? */

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NDIS_STATUS_SUCCESS;

err:
  NdisFreeMemory(xi, 0, 0);
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return status;
}

// Q = Query Mandatory, S = Set Mandatory
NDIS_OID supported_oids[] =
{
  /* general OIDs */
  OID_GEN_SUPPORTED_LIST,        // Q
  OID_GEN_HARDWARE_STATUS,       // Q
  OID_GEN_MEDIA_SUPPORTED,       // Q
  OID_GEN_MEDIA_IN_USE,          // Q
  OID_GEN_MAXIMUM_LOOKAHEAD,     // Q
  OID_GEN_MAXIMUM_FRAME_SIZE,    // Q
  OID_GEN_LINK_SPEED,            // Q
  OID_GEN_TRANSMIT_BUFFER_SPACE, // Q
  OID_GEN_RECEIVE_BUFFER_SPACE,  // Q
  OID_GEN_TRANSMIT_BLOCK_SIZE,   // Q
  OID_GEN_RECEIVE_BLOCK_SIZE,    // Q
  OID_GEN_VENDOR_ID,             // Q
  OID_GEN_VENDOR_DESCRIPTION,    // Q
  OID_GEN_CURRENT_PACKET_FILTER, // QS
  OID_GEN_CURRENT_LOOKAHEAD,     // QS
  OID_GEN_DRIVER_VERSION,        // Q
  OID_GEN_MAXIMUM_TOTAL_SIZE,    // Q
  OID_GEN_PROTOCOL_OPTIONS,      // S
  OID_GEN_MAC_OPTIONS,           // Q
  OID_GEN_MEDIA_CONNECT_STATUS,  // Q
  OID_GEN_MAXIMUM_SEND_PACKETS,  // Q
  /* stats */
  OID_GEN_XMIT_OK,               // Q
  OID_GEN_RCV_OK,                // Q
  OID_GEN_XMIT_ERROR,            // Q
  OID_GEN_RCV_ERROR,             // Q
  OID_GEN_RCV_NO_BUFFER,         // Q
  /* media-specific OIDs */
  OID_802_3_PERMANENT_ADDRESS,
  OID_802_3_CURRENT_ADDRESS,
  OID_802_3_MULTICAST_LIST,
  OID_802_3_MAXIMUM_LIST_SIZE,
  /* tcp offload */
  OID_TCP_TASK_OFFLOAD,
};

/* return 4 or 8 depending on size of buffer */
#define HANDLE_STAT_RETURN \
  {if (InformationBufferLength == 4) { \
    len = 4; *BytesNeeded = 8; \
    } else { \
    len = 8; \
    } }

//#define OFFLOAD_LARGE_SEND

NDIS_STATUS 
XenNet_QueryInformation(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN NDIS_OID Oid,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength,
  OUT PULONG BytesWritten,
  OUT PULONG BytesNeeded)
{
  struct xennet_info *xi = MiniportAdapterContext;
  UCHAR vendor_desc[] = XN_VENDOR_DESC;
  ULONG64 temp_data;
  PVOID data = &temp_data;
  UINT len = 4;
  BOOLEAN used_temp_buffer = TRUE;
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  PNDIS_TASK_OFFLOAD_HEADER ntoh;
  PNDIS_TASK_OFFLOAD nto;
  PNDIS_TASK_TCP_IP_CHECKSUM nttic;
#ifdef OFFLOAD_LARGE_SEND
  PNDIS_TASK_TCP_LARGE_SEND nttls;
#endif

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  switch(Oid)
  {
    case OID_GEN_SUPPORTED_LIST:
      data = supported_oids;
      len = sizeof(supported_oids);
      break;
    case OID_GEN_HARDWARE_STATUS:
      if (!xi->connected)
        temp_data = NdisHardwareStatusInitializing;
      else
        temp_data = NdisHardwareStatusReady;
      break;
    case OID_GEN_MEDIA_SUPPORTED:
      temp_data = NdisMedium802_3;
      break;
    case OID_GEN_MEDIA_IN_USE:
      temp_data = NdisMedium802_3;
      break;
    case OID_GEN_MAXIMUM_LOOKAHEAD:
      temp_data = XN_DATA_SIZE;
      break;
    case OID_GEN_MAXIMUM_FRAME_SIZE:
      // According to the specs, OID_GEN_MAXIMUM_FRAME_SIZE does not include the header, so
      // it is XN_DATA_SIZE not XN_MAX_PKT_SIZE
      temp_data = XN_DATA_SIZE; // XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_LINK_SPEED:
      temp_data = 10000000; /* 1Gb */
      break;
    case OID_GEN_TRANSMIT_BUFFER_SPACE:
      /* pkts times sizeof ring, maybe? */
      temp_data = XN_MAX_PKT_SIZE * NET_TX_RING_SIZE;
      break;
    case OID_GEN_RECEIVE_BUFFER_SPACE:
      /* pkts times sizeof ring, maybe? */
      temp_data = XN_MAX_PKT_SIZE * NET_RX_RING_SIZE;
      break;
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
      temp_data = XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_RECEIVE_BLOCK_SIZE:
      temp_data = XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_VENDOR_ID:
      temp_data = 0xFFFFFF; // Not guaranteed to be XENSOURCE_MAC_HDR;
      break;
    case OID_GEN_VENDOR_DESCRIPTION:
      data = vendor_desc;
      len = sizeof(vendor_desc);
      break;
    case OID_GEN_CURRENT_PACKET_FILTER:
      temp_data = xi->packet_filter;
      break;
    case OID_GEN_CURRENT_LOOKAHEAD:
      // TODO: we should store this...
      temp_data = XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_DRIVER_VERSION:
      temp_data = (NDIS_MINIPORT_MAJOR_VERSION << 8) | NDIS_MINIPORT_MINOR_VERSION;
      len = 2;
      break;
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
      temp_data = XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_MAC_OPTIONS:
      temp_data = NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | 
        NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |
        NDIS_MAC_OPTION_NO_LOOPBACK;
      break;
    case OID_GEN_MEDIA_CONNECT_STATUS:
      if (xi->connected)
        temp_data = NdisMediaStateConnected;
      else
        temp_data = NdisMediaStateDisconnected;
      break;
    case OID_GEN_MAXIMUM_SEND_PACKETS:
      temp_data = XN_MAX_SEND_PKTS;
      break;
    case OID_GEN_XMIT_OK:
      temp_data = xi->stat_tx_ok;
      HANDLE_STAT_RETURN;
      break;
    case OID_GEN_RCV_OK:
      temp_data = xi->stat_rx_ok;
      HANDLE_STAT_RETURN;
      break;
    case OID_GEN_XMIT_ERROR:
      temp_data = xi->stat_tx_error;
      HANDLE_STAT_RETURN;
      break;
    case OID_GEN_RCV_ERROR:
      temp_data = xi->stat_rx_error;
      HANDLE_STAT_RETURN;
      break;
    case OID_GEN_RCV_NO_BUFFER:
      temp_data = xi->stat_rx_no_buffer;
      HANDLE_STAT_RETURN;
      break;
    case OID_802_3_PERMANENT_ADDRESS:
      data = xi->perm_mac_addr;
      len = ETH_ALEN;
      break;
    case OID_802_3_CURRENT_ADDRESS:
      data = xi->curr_mac_addr;
      len = ETH_ALEN;
      break;
    case OID_802_3_MULTICAST_LIST:
      data = NULL;
      len = 0;
    case OID_802_3_MAXIMUM_LIST_SIZE:
      temp_data = 0; /* no mcast support */
      break;
    case OID_TCP_TASK_OFFLOAD:
      KdPrint(("Get OID_TCP_TASK_OFFLOAD\n"));
      /* it's times like this that C really sucks */

      len = sizeof(NDIS_TASK_OFFLOAD_HEADER);

      len += FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer)
        + sizeof(NDIS_TASK_TCP_IP_CHECKSUM);
#ifdef OFFLOAD_LARGE_SEND
      len += FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer)
        + sizeof(NDIS_TASK_TCP_LARGE_SEND);
#endif

      if (len > InformationBufferLength)
      {
          break;
      }

      ntoh = (PNDIS_TASK_OFFLOAD_HEADER)InformationBuffer;
      if (ntoh->Version != NDIS_TASK_OFFLOAD_VERSION
        || ntoh->Size != sizeof(*ntoh)
        || ntoh->EncapsulationFormat.Encapsulation != IEEE_802_3_Encapsulation)
      {
        status = NDIS_STATUS_NOT_SUPPORTED;
        break;
      }
      ntoh->OffsetFirstTask = ntoh->Size;

      /* fill in first nto */
      nto = (PNDIS_TASK_OFFLOAD)((PCHAR)(ntoh) + ntoh->OffsetFirstTask);
      nto->Version = NDIS_TASK_OFFLOAD_VERSION;
      nto->Size = sizeof(NDIS_TASK_OFFLOAD);
      nto->Task = TcpIpChecksumNdisTask;
      nto->TaskBufferLength = sizeof(NDIS_TASK_TCP_IP_CHECKSUM);

      /* fill in checksum offload struct */
      nttic = (PNDIS_TASK_TCP_IP_CHECKSUM)nto->TaskBuffer;
      nttic->V4Transmit.IpOptionsSupported = 0;
      nttic->V4Transmit.TcpOptionsSupported = 0;
      nttic->V4Transmit.TcpChecksum = 0;
      nttic->V4Transmit.UdpChecksum = 0;
      nttic->V4Transmit.IpChecksum = 0;
      nttic->V4Receive.IpOptionsSupported = 1;
      nttic->V4Receive.TcpOptionsSupported = 1;
      nttic->V4Receive.TcpChecksum = 1;
      nttic->V4Receive.UdpChecksum = 1;
      nttic->V4Receive.IpChecksum = 1;
      nttic->V6Transmit.IpOptionsSupported = 0;
      nttic->V6Transmit.TcpOptionsSupported = 0;
      nttic->V6Transmit.TcpChecksum = 0;
      nttic->V6Transmit.UdpChecksum = 0;
      nttic->V6Receive.IpOptionsSupported = 0;
      nttic->V6Receive.TcpOptionsSupported = 0;
      nttic->V6Receive.TcpChecksum = 0;
      nttic->V6Receive.UdpChecksum = 0;

#ifdef OFFLOAD_LARGE_SEND
      /* offset from start of current NTO to start of next NTO */
      nto->OffsetNextTask = FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer)
        + nto->TaskBufferLength;

      /* fill in second nto */
      nto = (PNDIS_TASK_OFFLOAD)((PCHAR)(ntoh) + nto->OffsetNextTask);
      nto->Version = NDIS_TASK_OFFLOAD_VERSION;
      nto->Size = sizeof(NDIS_TASK_OFFLOAD);
      nto->Task = TcpLargeSendNdisTask;
      nto->TaskBufferLength = sizeof(NDIS_TASK_TCP_LARGE_SEND);

      /* fill in large send struct */
      nttls = (PNDIS_TASK_TCP_LARGE_SEND)nto->TaskBuffer;
      nttls->Version = 0;
      nttls->MaxOffLoadSize = 1024*64; /* made up, fixme */
      nttls->MinSegmentCount = 4; /* also made up */
      nttls->TcpOptions = FALSE;
      nttls->IpOptions = FALSE;
#endif
      nto->OffsetNextTask = 0; /* last one */

      used_temp_buffer = FALSE;
      break;
    default:
      KdPrint(("Get Unknown OID 0x%x\n", Oid));
      status = NDIS_STATUS_NOT_SUPPORTED;
  }

  if (!NT_SUCCESS(status))
  {
  //  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (returned error)\n"));
    return status;
  }

  if (len > InformationBufferLength)
  {
    *BytesNeeded = len;
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (BUFFER_TOO_SHORT)\n"));
    return NDIS_STATUS_BUFFER_TOO_SHORT;
  }

  *BytesWritten = len;
  if (len && used_temp_buffer)
  {
    NdisMoveMemory((PUCHAR)InformationBuffer, data, len);
  }

  //KdPrint(("Got OID 0x%x\n", Oid));
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return status;
}

NDIS_STATUS 
XenNet_SetInformation(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN NDIS_OID Oid,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength,
  OUT PULONG BytesRead,
  OUT PULONG BytesNeeded
  )
{
  NTSTATUS status;
  struct xennet_info *xi = MiniportAdapterContext;
  PULONG64 data = InformationBuffer;
  PNDIS_TASK_OFFLOAD_HEADER ntoh;
  PNDIS_TASK_OFFLOAD nto;
  PNDIS_TASK_TCP_IP_CHECKSUM nttic;
  int offset;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  UNREFERENCED_PARAMETER(MiniportAdapterContext);
  UNREFERENCED_PARAMETER(InformationBufferLength);
  UNREFERENCED_PARAMETER(BytesRead);
  UNREFERENCED_PARAMETER(BytesNeeded);

  switch(Oid)
  {
    case OID_GEN_SUPPORTED_LIST:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_SUPPORTED_LIST\n"));
      break;
    case OID_GEN_HARDWARE_STATUS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_HARDWARE_STATUS\n"));
      break;
    case OID_GEN_MEDIA_SUPPORTED:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MEDIA_SUPPORTED\n"));
      break;
    case OID_GEN_MEDIA_IN_USE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MEDIA_IN_USE\n"));
      break;
    case OID_GEN_MAXIMUM_LOOKAHEAD:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MAXIMUM_LOOKAHEAD\n"));
      break;
    case OID_GEN_MAXIMUM_FRAME_SIZE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MAXIMUM_FRAME_SIZE\n"));
      break;
    case OID_GEN_LINK_SPEED:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_LINK_SPEED\n"));
      break;
    case OID_GEN_TRANSMIT_BUFFER_SPACE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_TRANSMIT_BUFFER_SPACE\n"));
      break;
    case OID_GEN_RECEIVE_BUFFER_SPACE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_RECEIVE_BUFFER_SPACE\n"));
      break;
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_TRANSMIT_BLOCK_SIZE\n"));
      break;
    case OID_GEN_RECEIVE_BLOCK_SIZE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_RECEIVE_BLOCK_SIZE\n"));
      break;
    case OID_GEN_VENDOR_ID:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_VENDOR_ID\n"));
      break;
    case OID_GEN_VENDOR_DESCRIPTION:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_VENDOR_DESCRIPTION\n"));
      break;
    case OID_GEN_CURRENT_PACKET_FILTER:
      KdPrint(("Set OID_GEN_CURRENT_PACKET_FILTER\n"));
      xi->packet_filter = *(ULONG *)data;
      status = NDIS_STATUS_SUCCESS;
      break;
    case OID_GEN_CURRENT_LOOKAHEAD:
      KdPrint(("Set OID_GEN_CURRENT_LOOKAHEAD %d\n", *(int *)data));
      // TODO: We should do this...
      status = NDIS_STATUS_SUCCESS;
      break;
    case OID_GEN_DRIVER_VERSION:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_DRIVER_VERSION\n"));
      break;
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MAXIMUM_TOTAL_SIZE\n"));
      break;
    case OID_GEN_PROTOCOL_OPTIONS:
      KdPrint(("Unsupported set OID_GEN_PROTOCOL_OPTIONS\n"));
      // TODO - actually do this...
      status = NDIS_STATUS_SUCCESS;
      break;
    case OID_GEN_MAC_OPTIONS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MAC_OPTIONS\n"));
      break;
    case OID_GEN_MEDIA_CONNECT_STATUS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MEDIA_CONNECT_STATUS\n"));
      break;
    case OID_GEN_MAXIMUM_SEND_PACKETS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MAXIMUM_SEND_PACKETS\n"));
      break;
    case OID_GEN_XMIT_OK:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_XMIT_OK\n"));
      break;
    case OID_GEN_RCV_OK:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_RCV_OK\n"));
      break;
    case OID_GEN_XMIT_ERROR:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_XMIT_ERROR\n"));
      break;
    case OID_GEN_RCV_ERROR:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_RCV_ERROR\n"));
      break;
    case OID_GEN_RCV_NO_BUFFER:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_RCV_NO_BUFFER\n"));
      break;
    case OID_802_3_PERMANENT_ADDRESS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_802_3_PERMANENT_ADDRESS\n"));
      break;
    case OID_802_3_CURRENT_ADDRESS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_802_3_CURRENT_ADDRESS\n"));
      break;
    case OID_802_3_MULTICAST_LIST:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_802_3_MULTICAST_LIST\n"));
      break;
    case OID_802_3_MAXIMUM_LIST_SIZE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_802_3_MAXIMUM_LIST_SIZE\n"));
      break;
    case OID_TCP_TASK_OFFLOAD:
      // Just fake this for now... ultimately we need to manually calc rx checksum if offload is disabled by windows
      status = NDIS_STATUS_SUCCESS;
      KdPrint(("Set OID_TCP_TASK_OFFLOAD\n"));
      // we should disable everything here, then enable what has been set
      ntoh = (PNDIS_TASK_OFFLOAD_HEADER)InformationBuffer;
      *BytesRead = sizeof(NDIS_TASK_OFFLOAD_HEADER);
      offset = ntoh->OffsetFirstTask;
      nto = (PNDIS_TASK_OFFLOAD)ntoh; // not really, just to get the first offset right
      while (offset != 0)
      {
        *BytesRead += FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer);
        nto = (PNDIS_TASK_OFFLOAD)(((PUCHAR)nto) + offset);
        switch (nto->Task)
        {
        case TcpIpChecksumNdisTask:
          *BytesRead += sizeof(NDIS_TASK_TCP_IP_CHECKSUM);
          KdPrint(("TcpIpChecksumNdisTask\n"));
          nttic = (PNDIS_TASK_TCP_IP_CHECKSUM)nto->TaskBuffer;
          KdPrint(("  V4Transmit.IpOptionsSupported  = %d\n", nttic->V4Transmit.IpOptionsSupported));
          KdPrint(("  V4Transmit.TcpOptionsSupported = %d\n", nttic->V4Transmit.TcpOptionsSupported));
          KdPrint(("  V4Transmit.TcpChecksum         = %d\n", nttic->V4Transmit.TcpChecksum));
          KdPrint(("  V4Transmit.UdpChecksum         = %d\n", nttic->V4Transmit.UdpChecksum));
          KdPrint(("  V4Transmit.IpChecksum          = %d\n", nttic->V4Transmit.IpChecksum));
          KdPrint(("  V4Receive.IpOptionsSupported   = %d\n", nttic->V4Receive.IpOptionsSupported));
          KdPrint(("  V4Receive.TcpOptionsSupported  = %d\n", nttic->V4Receive.TcpOptionsSupported));
          KdPrint(("  V4Receive.TcpChecksum          = %d\n", nttic->V4Receive.TcpChecksum));
          KdPrint(("  V4Receive.UdpChecksum          = %d\n", nttic->V4Receive.UdpChecksum));
          KdPrint(("  V4Receive.IpChecksum           = %d\n", nttic->V4Receive.IpChecksum));
          KdPrint(("  V6Transmit.IpOptionsSupported  = %d\n", nttic->V6Transmit.IpOptionsSupported));
          KdPrint(("  V6Transmit.TcpOptionsSupported = %d\n", nttic->V6Transmit.TcpOptionsSupported));
          KdPrint(("  V6Transmit.TcpChecksum         = %d\n", nttic->V6Transmit.TcpChecksum));
          KdPrint(("  V6Transmit.UdpChecksum         = %d\n", nttic->V6Transmit.UdpChecksum));
          KdPrint(("  V6Receive.IpOptionsSupported   = %d\n", nttic->V6Receive.IpOptionsSupported));
          KdPrint(("  V6Receive.TcpOptionsSupported  = %d\n", nttic->V6Receive.TcpOptionsSupported));
          KdPrint(("  V6Receive.TcpChecksum          = %d\n", nttic->V6Receive.TcpChecksum));
          KdPrint(("  V6Receive.UdpChecksum          = %d\n", nttic->V6Receive.UdpChecksum));
          break;
        default:
          KdPrint(("  Unknown Task %d\n", nto->Task));
        }
        offset = nto->OffsetNextTask;
      }
      break;
    default:
      KdPrint(("Set Unknown OID 0x%x\n", Oid));
      status = NDIS_STATUS_NOT_SUPPORTED;
      break;
  }
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return status;
}

/* Called at DISPATCH_LEVEL with tx_lock held */
PMDL
XenNet_Linearize(PNDIS_PACKET Packet)
{
  NDIS_STATUS status;
  PMDL pmdl;
  char *start;
  PNDIS_BUFFER buffer;
  PVOID buff_va;
  UINT buff_len;
  UINT tot_buff_len;
  LARGE_INTEGER tsc, dummy;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  tsc = KeQueryPerformanceCounter(&dummy);

  NdisGetFirstBufferFromPacketSafe(Packet, &buffer, &buff_va, &buff_len,
    &tot_buff_len, NormalPagePriority);
  ASSERT(tot_buff_len <= XN_MAX_PKT_SIZE);

  status = NdisAllocateMemoryWithTag(&start, PAGE_SIZE, XENNET_POOL_TAG);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Could not allocate memory for linearization\n"));
    return NULL;
  }

  pmdl = IoAllocateMdl(start, tot_buff_len, FALSE, FALSE, NULL);
  if (!pmdl)
  {
    KdPrint(("Could not allocate MDL for linearization\n"));
    NdisFreeMemory(start, 0, 0);
    return NULL;
  }
  MmBuildMdlForNonPagedPool(pmdl);

  while (buffer)
  {
    NdisQueryBufferSafe(buffer, &buff_va, &buff_len, NormalPagePriority);
    RtlCopyMemory(start, buff_va, buff_len);
    start += buff_len;
    NdisGetNextBuffer(buffer, &buffer);
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  ProfTime_Linearize.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_Linearize++;

  return pmdl;
}

VOID
XenNet_SendQueuedPackets(struct xennet_info *xi)
{
  PLIST_ENTRY entry;
  PNDIS_PACKET packet;
  KIRQL OldIrql;
  struct netif_tx_request *tx;
  unsigned short id;
  int notify;
  PMDL pmdl;
  UINT pkt_size;
  LARGE_INTEGER tsc, dummy;
  KIRQL OldIrql2;

  KeRaiseIrql(DISPATCH_LEVEL, &OldIrql2);

  tsc = KeQueryPerformanceCounter(&dummy);
  KeAcquireSpinLock(&xi->tx_lock, &OldIrql);

  entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  /* if empty, the above returns head*, not NULL */
  while (entry != &xi->tx_waiting_pkt_list)
  {
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);

    NdisQueryPacket(packet, NULL, NULL, NULL, &pkt_size);
    pmdl = *(PMDL *)packet->MiniportReservedEx;

    id = get_id_from_freelist(xi);
    if (!id)
    {
      /* whups, out of space on the ring. requeue and get out */
      InsertHeadList(&xi->tx_waiting_pkt_list, entry);
      break;
    }
    xi->tx_pkts[id] = packet;

    tx = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
    tx->id = id;
    tx->gref = xi->XenInterface.GntTbl_GrantAccess(
      xi->XenInterface.InterfaceHeader.Context,
      0,
      *MmGetMdlPfnArray(pmdl),
      TRUE);
    xi->grant_tx_ref[id] = tx->gref;
    tx->offset = (uint16_t)MmGetMdlByteOffset(pmdl);
    tx->size = (UINT16)pkt_size;
    // NETTXF_csum_blank should only be used for tcp and udp packets...    
    tx->flags = 0; //NETTXF_csum_blank;

    xi->tx.req_prod_pvt++;

    entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  }

  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xi->tx, notify);
  if (notify)
  {
    xi->XenInterface.EvtChn_Notify(xi->XenInterface.InterfaceHeader.Context,
      xi->event_channel);
  }

  KeReleaseSpinLock(&xi->tx_lock, OldIrql);
  ProfTime_SendQueuedPackets.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_SendQueuedPackets++;

  KeLowerIrql(OldIrql2);
}

VOID
XenNet_SendPackets(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PPNDIS_PACKET PacketArray,
  IN UINT NumberOfPackets
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
  PNDIS_PACKET curr_packet;
  UINT i;
  PMDL pmdl;
  PLIST_ENTRY entry;
  KIRQL OldIrql;
  LARGE_INTEGER tsc, dummy;
  KIRQL OldIrql2;

  KeRaiseIrql(DISPATCH_LEVEL, &OldIrql2);
  tsc = KeQueryPerformanceCounter(&dummy);

  KeAcquireSpinLock(&xi->tx_lock, &OldIrql);

  //  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  for (i = 0; i < NumberOfPackets; i++)
  {
    curr_packet = PacketArray[i];
    ASSERT(curr_packet);

    //KdPrint(("sending pkt, len %d\n", pkt_size));

    pmdl = XenNet_Linearize(curr_packet);
    if (!pmdl)
    {
      KdPrint((__DRIVER_NAME "Couldn't linearize packet!\n"));
      NdisMSendComplete(xi->adapter_handle, curr_packet, NDIS_STATUS_FAILURE);
      break;
    }

    /* NOTE: 
     * We use the UCHAR[3*sizeof(PVOID)] array in each packet's MiniportReservedEx thusly:
     * 0: PMDL to linearized data
     * sizeof(PVOID)+: LIST_ENTRY for placing packet on the waiting pkt list
     */
    *(PMDL *)&curr_packet->MiniportReservedEx = pmdl;

    entry = (PLIST_ENTRY)&curr_packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(&xi->tx_waiting_pkt_list, entry);
    InterlockedIncrement(&xi->tx_outstanding);
  }
  KeReleaseSpinLock(&xi->tx_lock, OldIrql);

  ProfTime_SendPackets.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_SendPackets++;
  KeLowerIrql(OldIrql2);
  XenNet_SendQueuedPackets(xi);

  if ((ProfCount_SendPackets & 1023) == 0)
  {
    KdPrint((__DRIVER_NAME "     TxBufferGC        Count = %10d, Avg Time = %10ld\n", ProfCount_TxBufferGC, (ProfCount_TxBufferGC == 0)?0:(ProfTime_TxBufferGC.QuadPart / ProfCount_TxBufferGC)));
    KdPrint((__DRIVER_NAME "     TxBufferFree      Count = %10d, Avg Time = %10ld\n", ProfCount_TxBufferFree, (ProfCount_TxBufferFree == 0)?0:(ProfTime_TxBufferFree.QuadPart / ProfCount_TxBufferFree)));
    KdPrint((__DRIVER_NAME "     RxBufferAlloc     Count = %10d, Avg Time = %10ld\n", ProfCount_RxBufferAlloc, (ProfCount_RxBufferAlloc == 0)?0:(ProfTime_RxBufferAlloc.QuadPart / ProfCount_RxBufferAlloc)));
    KdPrint((__DRIVER_NAME "     RxBufferFree      Count = %10d, Avg Time = %10ld\n", ProfCount_RxBufferFree, (ProfCount_RxBufferFree == 0)?0:(ProfTime_RxBufferFree.QuadPart / ProfCount_RxBufferFree)));
    KdPrint((__DRIVER_NAME "     ReturnPacket      Count = %10d, Avg Time = %10ld\n", ProfCount_ReturnPacket, (ProfCount_ReturnPacket == 0)?0:(ProfTime_ReturnPacket.QuadPart / ProfCount_ReturnPacket)));
    KdPrint((__DRIVER_NAME "     RxBufferCheck     Count = %10d, Avg Time = %10ld\n", ProfCount_RxBufferCheck, (ProfCount_RxBufferCheck == 0)?0:(ProfTime_RxBufferCheck.QuadPart / ProfCount_RxBufferCheck)));
    KdPrint((__DRIVER_NAME "     Linearize         Count = %10d, Avg Time = %10ld\n", ProfCount_Linearize, (ProfCount_Linearize == 0)?0:(ProfTime_Linearize.QuadPart / ProfCount_Linearize)));
    KdPrint((__DRIVER_NAME "     SendPackets       Count = %10d, Avg Time = %10ld\n", ProfCount_SendPackets, (ProfCount_SendPackets == 0)?0:(ProfTime_SendPackets.QuadPart / ProfCount_SendPackets)));
    KdPrint((__DRIVER_NAME "     SendQueuedPackets Count = %10d, Avg Time = %10ld\n", ProfCount_SendQueuedPackets, (ProfCount_SendQueuedPackets == 0)?0:(ProfTime_SendQueuedPackets.QuadPart / ProfCount_SendQueuedPackets)));
  }
  //  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

VOID
XenNet_PnPEventNotify(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN NDIS_DEVICE_PNP_EVENT PnPEvent,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength
  )
{
  UNREFERENCED_PARAMETER(MiniportAdapterContext);
  UNREFERENCED_PARAMETER(PnPEvent);
  UNREFERENCED_PARAMETER(InformationBuffer);
  UNREFERENCED_PARAMETER(InformationBufferLength);

  KdPrint((__FUNCTION__ " called\n"));
}

/* Called when machine is shutting down, so just quiesce the HW and be done fast. */
VOID
XenNet_Shutdown(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  struct xennet_info *xi = MiniportAdapterContext;

  /* turn off interrupt */
  xi->XenInterface.EvtChn_Unbind(xi->XenInterface.InterfaceHeader.Context,
    xi->event_channel);

  KdPrint((__FUNCTION__ " called\n"));
}

/* Opposite of XenNet_Init */
VOID
XenNet_Halt(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
  CHAR TmpPath[MAX_XENBUS_STR_LEN];
  PVOID if_cxt = xi->XenInterface.InterfaceHeader.Context;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  // set frontend state to 'closing'
  xi->state = XenbusStateClosing;
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(if_cxt, XBT_NIL, TmpPath, "%d", xi->state);

  // wait for backend to set 'Closing' state

  while (xi->backend_state != XenbusStateClosing)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive,
      KernelMode, FALSE, NULL);

  // set frontend state to 'closed'
  xi->state = XenbusStateClosed;
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(if_cxt, XBT_NIL, TmpPath, "%d", xi->state);

  // wait for backend to set 'Closed' state
  while (xi->backend_state != XenbusStateClosed)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive,
      KernelMode, FALSE, NULL);

  // set frontend state to 'Initialising'
  xi->state = XenbusStateInitialising;
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(if_cxt, XBT_NIL, TmpPath, "%d", xi->state);

  // wait for backend to set 'InitWait' state
  while (xi->backend_state != XenbusStateInitWait)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive,
      KernelMode, FALSE, NULL);

  // Disables the interrupt
  XenNet_Shutdown(xi);

  xi->connected = FALSE;
  KeMemoryBarrier(); /* make sure everyone sees that we are now shut down */

  /* wait for all receive buffers to be returned */
  while (xi->rx_outstanding > 0)
    KeWaitForSingleObject(&xi->shutdown_event, Executive, KernelMode, FALSE, NULL);

  // TODO: remove event channel xenbus entry (how?)

  /* free TX resources */
  if (xi->XenInterface.GntTbl_EndAccess(if_cxt, xi->tx_ring_ref))
  {
    xi->tx_ring_ref = GRANT_INVALID_REF;
    FreePages(xi->tx_mdl);
  }
  /* if EndAccess fails then tx/rx ring pages LEAKED -- it's not safe to reuse
     pages Dom0 still has access to */
  xi->tx_pgs = NULL;

  /* free RX resources */
  if (xi->XenInterface.GntTbl_EndAccess(if_cxt, xi->rx_ring_ref))
  {
    xi->rx_ring_ref = GRANT_INVALID_REF;
    FreePages(xi->rx_mdl);
  }
  xi->rx_pgs = NULL;

  XenNet_TxBufferFree(xi);
  XenNet_RxBufferFree(MiniportAdapterContext);

  /* Remove watch on backend state */
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->backend_path);
  xi->XenInterface.XenBus_RemWatch(if_cxt, XBT_NIL, TmpPath,
    XenNet_BackEndStateHandler, xi);

  xi->XenInterface.InterfaceHeader.InterfaceDereference(NULL);

  NdisFreeBufferPool(xi->buffer_pool);
  NdisFreePacketPool(xi->packet_pool);

  NdisFreeMemory(xi, 0, 0); // <= DISPATCH_LEVEL

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

VOID
XenNet_Unload(
  PDRIVER_OBJECT  DriverObject
  )
{
  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  UNREFERENCED_PARAMETER(DriverObject);

  WdfDriverMiniportUnload(WdfGetDriver());
  
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

NTSTATUS
DriverEntry(
  PDRIVER_OBJECT DriverObject,
  PUNICODE_STRING RegistryPath
  )
{
  NTSTATUS status;
  WDF_DRIVER_CONFIG config;
  NDIS_HANDLE ndis_wrapper_handle;
  NDIS_MINIPORT_CHARACTERISTICS mini_chars;


  ProfTime_TxBufferGC.QuadPart = 0;
  ProfTime_TxBufferFree.QuadPart = 0;
  ProfTime_RxBufferAlloc.QuadPart = 0;
  ProfTime_RxBufferFree.QuadPart = 0;
  ProfTime_ReturnPacket.QuadPart = 0;
  ProfTime_RxBufferCheck.QuadPart = 0;
  ProfTime_Linearize.QuadPart = 0;
  ProfTime_SendPackets.QuadPart = 0;
  ProfTime_SendQueuedPackets.QuadPart = 0;

  ProfCount_TxBufferGC = 0;
  ProfCount_TxBufferFree = 0;
  ProfCount_RxBufferAlloc = 0;
  ProfCount_RxBufferFree = 0;
  ProfCount_ReturnPacket = 0;
  ProfCount_RxBufferCheck = 0;
  ProfCount_Linearize = 0;
  ProfCount_SendPackets = 0;
  ProfCount_SendQueuedPackets = 0;

  RtlZeroMemory(&mini_chars, sizeof(mini_chars));

  WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
  config.DriverInitFlags |= WdfDriverInitNoDispatchOverride;

  status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES,
    &config, WDF_NO_HANDLE);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("WdfDriverCreate failed err = 0x%x\n", status));
    return status;
  }

  NdisMInitializeWrapper(&ndis_wrapper_handle, DriverObject, RegistryPath, NULL);
  if (!ndis_wrapper_handle)
  {
    KdPrint(("NdisMInitializeWrapper failed\n"));
    return NDIS_STATUS_FAILURE;
  }

  /* NDIS 5.1 driver */
  mini_chars.MajorNdisVersion = NDIS_MINIPORT_MAJOR_VERSION;
  mini_chars.MinorNdisVersion = NDIS_MINIPORT_MINOR_VERSION;

  mini_chars.HaltHandler = XenNet_Halt;
  mini_chars.InitializeHandler = XenNet_Init;
  mini_chars.ISRHandler = NULL; // needed if we register interrupt?
  mini_chars.QueryInformationHandler = XenNet_QueryInformation;
  mini_chars.ResetHandler = NULL; //TODO: fill in
  mini_chars.SetInformationHandler = XenNet_SetInformation;
  /* added in v.4 -- use multiple pkts interface */
  mini_chars.ReturnPacketHandler = XenNet_ReturnPacket;
  mini_chars.SendPacketsHandler = XenNet_SendPackets;

#if defined (NDIS51_MINIPORT)
  /* added in v.5.1 */
  mini_chars.PnPEventNotifyHandler = XenNet_PnPEventNotify;
  mini_chars.AdapterShutdownHandler = XenNet_Shutdown;
#else
  // something else here
#endif

  /* set up upper-edge interface */
  status = NdisMRegisterMiniport(ndis_wrapper_handle, &mini_chars, sizeof(mini_chars));
  if (!NT_SUCCESS(status))
  {
    KdPrint(("NdisMRegisterMiniport failed, status = 0x%x\n", status));
    NdisTerminateWrapper(ndis_wrapper_handle, NULL);
    return status;
  }

  NdisMRegisterUnloadHandler(ndis_wrapper_handle, XenNet_Unload);

  return status;
}
