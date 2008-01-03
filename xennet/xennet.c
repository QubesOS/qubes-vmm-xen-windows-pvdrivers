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

#if !defined (NDIS51_MINIPORT)
#error requires NDIS 5.1 compilation environment
#endif

#define GRANT_INVALID_REF 0

/* couldn't get regular xen ring macros to work...*/
#define __NET_RING_SIZE(type, _sz) \
    (__RD32( \
    (_sz - sizeof(struct type##_sring) + sizeof(union type##_sring_entry)) \
    / sizeof(union type##_sring_entry)))

#define NET_TX_RING_SIZE __NET_RING_SIZE(netif_tx, PAGE_SIZE)
#define NET_RX_RING_SIZE __NET_RING_SIZE(netif_rx, PAGE_SIZE)

#pragma warning(disable: 4127) // conditional expression is constant

struct xennet_info
{
  PDEVICE_OBJECT pdo;
  PDEVICE_OBJECT fdo;
  PDEVICE_OBJECT lower_do;
  WDFDEVICE wdf_device;
  PXENPCI_XEN_DEVICE_DATA pdoData;

  WCHAR name[NAME_SIZE];
  NDIS_HANDLE adapter_handle;
  ULONG packet_filter;
  int connected;
  UINT8 perm_mac_addr[ETH_ALEN];
  UINT8 curr_mac_addr[ETH_ALEN];

//  char Path[128];
  char BackendPath[128];
  XEN_IFACE XenInterface;

  /* ring control structures */
  struct netif_tx_front_ring tx;
  struct netif_rx_front_ring rx;

  /* ptrs to the actual rings themselvves */
  struct netif_tx_sring *tx_pgs;
  struct netif_rx_sring *rx_pgs;

  /* MDLs for the above */
  PMDL tx_mdl;
  PMDL rx_mdl;

  /* Outstanding packets. The first entry in tx_pkts
   * is an index into a chain of free entries. */
  PNDIS_PACKET tx_pkts[NET_TX_RING_SIZE];
  PNDIS_PACKET rx_pkts[NET_RX_RING_SIZE];

  grant_ref_t gref_tx_head;
  grant_ref_t grant_tx_ref[NET_TX_RING_SIZE];
  grant_ref_t gref_rx_head;
  grant_ref_t grant_rx_ref[NET_TX_RING_SIZE];

  UINT irq;
  evtchn_port_t event_channel;

  grant_ref_t tx_ring_ref;
  grant_ref_t rx_ring_ref;

  /* Receive-ring batched refills. */
#define RX_MIN_TARGET 8
#define RX_DFL_MIN_TARGET 64
#define RX_MAX_TARGET min(NET_RX_RING_SIZE, 256)
  ULONG rx_target;
  ULONG rx_max_target;
  ULONG rx_min_target;

  NDIS_HANDLE packet_pool;
  NDIS_HANDLE buffer_pool;

  /* stats */
  ULONG64 stat_tx_ok;
  ULONG64 stat_rx_ok;
  ULONG64 stat_tx_error;
  ULONG64 stat_rx_error;
  ULONG64 stat_rx_no_buffer;

//  KEVENT backend_ready_event;
  KEVENT backend_state_change_event;

  ULONG state;
  ULONG backend_state;

  KSPIN_LOCK RxLock;
  KSPIN_LOCK TxLock;
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
add_id_to_freelist(NDIS_PACKET **list, unsigned short id)
{
  list[id] = list[0];
  list[0]  = (void *)(unsigned long)id;
}

static unsigned short
get_id_from_freelist(NDIS_PACKET **list)
{
  unsigned short id = (unsigned short)(unsigned long)list[0];
  list[0] = list[id];
  return id;
}

// Called at DISPATCH_LEVEL with spinlock held
static NDIS_STATUS
XenNet_TxBufferGC(struct xennet_info *xi)
{
  RING_IDX cons, prod;
  unsigned short id;
  PNDIS_PACKET pkt;
  PMDL pmdl;
  KIRQL OldIrql;

  ASSERT(xi->connected);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  KeAcquireSpinLock(&xi->TxLock, &OldIrql);

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
      add_id_to_freelist(xi->tx_pkts, id);

      /* free linearized data page */
      pmdl = *(PMDL *)pkt->MiniportReservedEx;
      NdisFreeMemory(MmGetMdlVirtualAddress(pmdl), 0, 0); // <= DISPATCH_LEVEL
      IoFreeMdl(pmdl);

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

  /* if queued packets, send them now?
  network_maybe_wake_tx(dev); */

  KeReleaseSpinLock(&xi->TxLock, OldIrql);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
XenNet_AllocRXBuffers(struct xennet_info *xi)
{
  unsigned short id;
  PNDIS_PACKET packet;
  PNDIS_BUFFER buffer;
  int i, batch_target, notify;
  RING_IDX req_prod = xi->rx.req_prod_pvt;
  grant_ref_t ref;
  netif_rx_request_t *req;
  NDIS_STATUS status;
  PVOID start;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  batch_target = xi->rx_target - (req_prod - xi->rx.rsp_cons);
  for (i = 0; i < batch_target; i++)
  {
    /*
     * Allocate a packet, page, and buffer. Hook them up.
     */
    status = NdisAllocateMemoryWithTag(&start, PAGE_SIZE, XENNET_POOL_TAG);
    if (status != NDIS_STATUS_SUCCESS)
    {
      KdPrint(("NdisAllocateMemoryWithTag Failed! status = 0x%x\n", status));
      break;
    }
    NdisAllocateBuffer(&status, &buffer, xi->buffer_pool, start, PAGE_SIZE);
    if (status != NDIS_STATUS_SUCCESS)
    {
      KdPrint(("NdisAllocateBuffer Failed! status = 0x%x\n", status));
      NdisFreeMemory(start, 0, 0);
      break;
    }
    NdisAllocatePacket(&status, &packet, xi->packet_pool);
    if (status != NDIS_STATUS_SUCCESS)
    {
      KdPrint(("NdisAllocatePacket Failed! status = 0x%x\n", status));
      NdisFreeMemory(start, 0, 0);
      NdisFreeBuffer(buffer);
      break;
    }
    NdisChainBufferAtBack(packet, buffer);
    NDIS_SET_PACKET_HEADER_SIZE(packet, XN_HDR_SIZE);

    /* Give to netback */
    id = (unsigned short)(req_prod + i) & (NET_RX_RING_SIZE - 1);
    ASSERT(!xi->rx_pkts[id]);
    xi->rx_pkts[id] = packet;
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

  return NDIS_STATUS_SUCCESS;
}

// Called at DISPATCH_LEVEL with spinlock held
static NDIS_STATUS
XenNet_RxBufferCheck(struct xennet_info *xi)
{
  RING_IDX cons, prod;

  PNDIS_PACKET pkt;
  PNDIS_BUFFER buffer;
  PVOID buff_va;
  UINT buff_len;
  UINT tot_buff_len;
  int moretodo;
  KIRQL OldIrql;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(xi->connected);

  KeAcquireSpinLock(&xi->RxLock, &OldIrql);

  do {
    prod = xi->rx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'rp'. */

    for (cons = xi->rx.rsp_cons; cons != prod; cons++) {
      struct netif_rx_response *rxrsp;

      rxrsp = RING_GET_RESPONSE(&xi->rx, cons);
      if (rxrsp->status == NETIF_RSP_NULL)
        continue;

    //  KdPrint((__DRIVER_NAME "     Got a packet\n"));

      pkt = xi->rx_pkts[rxrsp->id];
      xi->rx_pkts[rxrsp->id] = NULL;
      xi->XenInterface.GntTbl_EndAccess(xi->XenInterface.InterfaceHeader.Context,
        xi->grant_rx_ref[rxrsp->id]);
      xi->grant_rx_ref[rxrsp->id] = GRANT_INVALID_REF;

      NdisGetFirstBufferFromPacketSafe(pkt, &buffer, &buff_va, &buff_len,
        &tot_buff_len, NormalPagePriority);
      ASSERT(rxrsp->offset == 0);
      ASSERT(rxrsp->status > 0);
      NdisAdjustBufferLength(buffer, rxrsp->status);

      xi->stat_rx_ok++;
      NDIS_SET_PACKET_STATUS(pkt, NDIS_STATUS_SUCCESS);

      /* just indicate 1 packet for now */
    //  KdPrint((__DRIVER_NAME "     Indicating Received\n"));
      NdisMIndicateReceivePacket(xi->adapter_handle, &pkt, 1);
    //  KdPrint((__DRIVER_NAME "     Done Indicating Received\n"));
    }

    xi->rx.rsp_cons = prod;

    RING_FINAL_CHECK_FOR_RESPONSES(&xi->rx, moretodo);
  } while (moretodo);

  /* Give netback more buffers */
  XenNet_AllocRXBuffers(xi);

  KeReleaseSpinLock(&xi->RxLock, OldIrql);

  //xi->rx.sring->rsp_event = xi->rx.rsp_cons + 1;

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

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

static VOID
XenNet_BackEndStateHandler(char *Path, PVOID Data)
{
  struct xennet_info *xi = Data;
  char *Value;
  char TmpPath[128];
  xenbus_transaction_t xbt = 0;
  int retry = 0;
  char *err;
  int i;

  struct set_params {
    char *name;
    int value;
  } params[] = {
    {"tx-ring-ref", 0},
    {"rx-ring-ref", 0},
    {"event-channel", 0},
    {"request-rx-copy", 1},
#if 0 // these seemed to cause kernel messages about checksums
    {"feature-rx-notify", 1},
    {"feature-no-csum-offload", 1},
    {"feature-sg", 1},
    {"feature-gso-tcpv4", 0},
#endif
    {NULL, 0},
  };

  xi->XenInterface.XenBus_Read(xi->XenInterface.InterfaceHeader.Context,
    XBT_NIL, Path, &Value);
  xi->backend_state = atoi(Value);
  xi->XenInterface.FreeMem(Value);

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

    xi->event_channel = xi->XenInterface.EvtChn_AllocUnbound(
      xi->XenInterface.InterfaceHeader.Context, 0);  
    xi->XenInterface.EvtChn_BindDpc(xi->XenInterface.InterfaceHeader.Context,
      xi->event_channel, XenNet_Interrupt, xi);

    /* TODO: must free pages in MDL as well as MDL using MmFreePagesFromMdl and ExFreePool */
    // or, allocate mem and then get mdl, then free mdl
    xi->tx_mdl = AllocatePage();
    xi->tx_pgs = MmGetMdlVirtualAddress(xi->tx_mdl); //MmMapLockedPagesSpecifyCache(xi->tx_mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    SHARED_RING_INIT(xi->tx_pgs);
    FRONT_RING_INIT(&xi->tx, xi->tx_pgs, PAGE_SIZE);
    xi->tx_ring_ref = xi->XenInterface.GntTbl_GrantAccess(
      xi->XenInterface.InterfaceHeader.Context, 0,
      *MmGetMdlPfnArray(xi->tx_mdl), FALSE);

    xi->rx_mdl = AllocatePage();
    xi->rx_pgs = MmGetMdlVirtualAddress(xi->rx_mdl); //MmMapLockedPagesSpecifyCache(xi->rx_mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
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

    for (i = 0; params[i].name; i++)
    {
      RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/%s",
        xi->pdoData->Path, params[i].name);
      err = xi->XenInterface.XenBus_Printf(xi->XenInterface.InterfaceHeader.Context,
        XBT_NIL, TmpPath, "%d", params[i].value);
      if (err)
      {
        KdPrint(("setting %s failed, err = %s\n", params[i].name, err));
        goto trouble;
      }
    }

    /* commit transaction */
    xi->XenInterface.XenBus_EndTransaction(xi->XenInterface.InterfaceHeader.Context,
      xbt, 0, &retry);

    XenNet_AllocRXBuffers(xi);

    xi->state = XenbusStateConnected;
    KdPrint((__DRIVER_NAME "     Set Frontend state to Connected\n"));
    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdoData->Path);
    xi->XenInterface.XenBus_Printf(xi->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", xi->state);

    /* send fake arp? */

    xi->connected = TRUE;

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

  return;

trouble:
  KdPrint((__DRIVER_NAME __FUNCTION__ ": Should never happen!\n"));
  xi->XenInterface.XenBus_EndTransaction(xi->XenInterface.InterfaceHeader.Context,
    xbt, 1, &retry);

}

VOID
XenNet_Halt(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
  CHAR TmpPath[128];

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  // set frontend state to 'closing'
  xi->state = XenbusStateClosing;
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdoData->Path);
  xi->XenInterface.XenBus_Printf(xi->XenInterface.InterfaceHeader.Context,
    XBT_NIL, TmpPath, "%d", xi->state);

  // wait for backend to set 'Closing' state
  while (xi->backend_state != XenbusStateClosing)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive, KernelMode, FALSE, NULL);

  // set frontend state to 'closed'
  xi->state = XenbusStateClosed;
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdoData->Path);
  xi->XenInterface.XenBus_Printf(xi->XenInterface.InterfaceHeader.Context,
    XBT_NIL, TmpPath, "%d", xi->state);

  // wait for backend to set 'Closed' state
  while (xi->backend_state != XenbusStateClosed)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive, KernelMode, FALSE, NULL);

  // remove event channel xenbus entry
  // unbind event channel
  // remove tx/rx ring entries
  // clean up all grant table entries
  // free all memory

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
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
  char TmpPath[128];

  UNREFERENCED_PARAMETER(OpenErrorStatus);
  UNREFERENCED_PARAMETER(WrapperConfigurationContext);

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

  KeInitializeSpinLock(&xi->TxLock);
  KeInitializeSpinLock(&xi->RxLock);

  NdisAllocatePacketPool(&status, &xi->packet_pool, NET_RX_RING_SIZE,
    PROTOCOL_RESERVED_SIZE_IN_PACKET);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint(("NdisAllocatePacketPool failed with 0x%x\n", status));
    status = NDIS_STATUS_RESOURCES;
    goto err;
  }

  NdisAllocateBufferPool(&status, &xi->buffer_pool, NET_RX_RING_SIZE);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint(("NdisAllocateBufferPool failed with 0x%x\n", status));
    status = NDIS_STATUS_RESOURCES;
    goto err;
  }

  NdisMGetDeviceProperty(MiniportAdapterHandle, &xi->pdo, &xi->fdo,
    &xi->lower_do, NULL, NULL);
  xi->pdoData = (PXENPCI_XEN_DEVICE_DATA)xi->pdo->DeviceExtension;

  /* Initialize tx_pkts as a free chain containing every entry. */
  for (i = 0; i <= NET_TX_RING_SIZE; i++) {
    xi->tx_pkts[i] = (void *)((unsigned long) i+1);
    xi->grant_tx_ref[i] = GRANT_INVALID_REF;
  }

  for (i = 0; i < NET_RX_RING_SIZE; i++) {
    xi->rx_pkts[i] = NULL;
    xi->grant_rx_ref[i] = GRANT_INVALID_REF;
  }

  xi->packet_filter = NDIS_PACKET_TYPE_PROMISCUOUS;

  status = IoGetDeviceProperty(xi->pdo, DevicePropertyDeviceDescription,
    NAME_SIZE, xi->name, &length);
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
      "%s/backend", xi->pdoData->Path);
  KdPrint(("About to read %s to get backend path\n", TmpPath));
  res = xi->XenInterface.XenBus_Read(xi->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
  if (res)
  {
    KdPrint((__DRIVER_NAME "    Failed to read backend path\n"));
    xi->XenInterface.FreeMem(res);
    status = NDIS_STATUS_FAILURE;
    goto err;
  }
  RtlStringCbCopyA(xi->BackendPath, ARRAY_SIZE(xi->BackendPath), Value);
  KdPrint((__DRIVER_NAME "backend path = %s\n", xi->BackendPath));

  KeInitializeEvent(&xi->backend_state_change_event, SynchronizationEvent, FALSE);  

  /* Add watch on backend state */
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->BackendPath);
  xi->XenInterface.XenBus_AddWatch(xi->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, XenNet_BackEndStateHandler, xi);

  // wait here for signal that we are all set up
  while (xi->backend_state != XenbusStateConnected)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive, KernelMode, FALSE, NULL);

  /* get mac address */
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/mac", xi->BackendPath);
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
    int i;
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

  return NDIS_STATUS_SUCCESS;

err:
  NdisFreeMemory(xi, 0, 0);
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
};

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
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;

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
      temp_data = (NDIS_MAJOR_VER << 8) | NDIS_MINOR_VER;
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
      len = sizeof(ULONG64);
      break;
    case OID_GEN_RCV_OK:
      temp_data = xi->stat_rx_ok;
      len = sizeof(ULONG64);
      break;
    case OID_GEN_XMIT_ERROR:
      temp_data = xi->stat_tx_error;
      len = sizeof(ULONG64);
      break;
    case OID_GEN_RCV_ERROR:
      temp_data = xi->stat_rx_error;
      len = sizeof(ULONG64);
      break;
    case OID_GEN_RCV_NO_BUFFER:
      temp_data = xi->stat_rx_no_buffer;
      len = sizeof(ULONG64);
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
  //  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (returned error)\n"));
    return NDIS_STATUS_BUFFER_TOO_SHORT;
  }

  *BytesWritten = len;
  if (len)
  {
    NdisMoveMemory(InformationBuffer, data, len);
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

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

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
    default:
      KdPrint(("Set Unknown OID 0x%x\n", Oid));
      status = NDIS_STATUS_NOT_SUPPORTED;
      break;
  }
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return status;
}

VOID
XenNet_ReturnPacket(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PNDIS_PACKET Packet
  )
{
  PNDIS_BUFFER buffer;
  PVOID buff_va;
  UINT buff_len;
  UINT tot_buff_len;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  UNREFERENCED_PARAMETER(MiniportAdapterContext);

  NdisGetFirstBufferFromPacketSafe(Packet, &buffer, &buff_va, &buff_len,
    &tot_buff_len, NormalPagePriority);
  ASSERT(buff_len == tot_buff_len);

  NdisFreeMemory(buff_va, 0, 0);
  NdisFreeBuffer(buffer);
  NdisFreePacket(Packet);

  //KdPrint((__FUNCTION__ " called\n"));
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

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

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  NdisGetFirstBufferFromPacketSafe(Packet, &buffer, &buff_va, &buff_len,
    &tot_buff_len, NormalPagePriority);
  ASSERT(tot_buff_len <= XN_MAX_PKT_SIZE);

  status = NdisAllocateMemoryWithTag(&start, tot_buff_len, XENNET_POOL_TAG);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Could not allocate memory for linearization\n"));
    return NULL;
  }
  pmdl = IoAllocateMdl(start, tot_buff_len, FALSE, FALSE, FALSE);
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
  return pmdl;
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
  struct netif_tx_request *tx;
  unsigned short id;
  int notify;
  PMDL pmdl;
  UINT pkt_size;
  KIRQL OldIrql;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  KeAcquireSpinLock(&xi->TxLock, &OldIrql);

  for (i = 0; i < NumberOfPackets; i++)
  {
    curr_packet = PacketArray[i];
    ASSERT(curr_packet);

    NdisQueryPacket(curr_packet, NULL, NULL, NULL, &pkt_size);

    //KdPrint(("sending pkt, len %d\n", pkt_size));

    pmdl = XenNet_Linearize(curr_packet);
    if (!pmdl)
    {
      KdPrint((__DRIVER_NAME "Couldn't linearize packet!\n"));
      NdisMSendComplete(xi, curr_packet, NDIS_STATUS_FAILURE);
      break;
    }
    *((PMDL *)curr_packet->MiniportReservedEx) = pmdl;

    id = get_id_from_freelist(xi->tx_pkts);
    xi->tx_pkts[id] = curr_packet;

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

    // NDIS_SET_PACKET_STATUS(curr_packet, NDIS_STATUS_SUCCESS);
    // NdisMSendComplete(xi, curr_packet, NDIS_STATUS_SUCCESS);
  }

  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xi->tx, notify);
  if (notify)
  {
    xi->XenInterface.EvtChn_Notify(xi->XenInterface.InterfaceHeader.Context,
      xi->event_channel);
  }

  KeReleaseSpinLock(&xi->TxLock, OldIrql);

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

VOID
XenNet_Shutdown(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  //struct xennet_info *xi = MiniportAdapterContext;
  UNREFERENCED_PARAMETER(MiniportAdapterContext);

  // I think all we are supposed to do here is reset the adapter, which for us might be nothing...

  KdPrint((__FUNCTION__ " called\n"));
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
  mini_chars.MajorNdisVersion = NDIS_MAJOR_VER;
  mini_chars.MinorNdisVersion = NDIS_MINOR_VER;

  mini_chars.HaltHandler = XenNet_Halt;
  mini_chars.InitializeHandler = XenNet_Init;
  mini_chars.ISRHandler = NULL; // needed if we register interrupt?
  mini_chars.QueryInformationHandler = XenNet_QueryInformation;
  mini_chars.ResetHandler = NULL; //TODO: fill in
  mini_chars.SetInformationHandler = XenNet_SetInformation;
  /* added in v.4 -- use multiple pkts interface */
  mini_chars.ReturnPacketHandler = XenNet_ReturnPacket;
  mini_chars.SendPacketsHandler = XenNet_SendPackets;
  /* added in v.5.1 */
  mini_chars.PnPEventNotifyHandler = XenNet_PnPEventNotify;
  mini_chars.AdapterShutdownHandler = XenNet_Shutdown;

  /* TODO: we don't have hardware, but we have "resources", so do we need to implement fns to handle this? */

  /* set up upper-edge interface */
  status = NdisMRegisterMiniport(ndis_wrapper_handle, &mini_chars, sizeof(mini_chars));
  if (!NT_SUCCESS(status))
  {
    KdPrint(("NdisMRegisterMiniport failed, status = 0x%x\n", status));
    NdisTerminateWrapper(ndis_wrapper_handle, NULL);
    return status;
  }

  return status;
}
