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

  WCHAR name[NAME_SIZE];
  NDIS_HANDLE adapter_handle;
  ULONG packet_filter;
  int connected;
  UINT8 perm_mac_addr[ETH_ALEN];
  UINT8 curr_mac_addr[ETH_ALEN];

  char Path[128];
  char BackendPath[128];
  XEN_IFACE_EVTCHN EvtChnInterface;
  XEN_IFACE_XENBUS XenBusInterface;
  XEN_IFACE_XEN XenInterface;
  XEN_IFACE_GNTTBL GntTblInterface;

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
};

/* need to do typedef so the DECLARE below works */
typedef struct _wdf_device_info
{
  struct xennet_info *xennet_info;
} wdf_device_info;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(wdf_device_info, GetWdfDeviceInfo)

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

static PMDL
AllocatePages(int Pages)
{
  PHYSICAL_ADDRESS Min;
  PHYSICAL_ADDRESS Max;
  PHYSICAL_ADDRESS Align;
  PMDL Mdl;

  // KdPrint((__DRIVER_NAME " --> Allocate Pages\n"));

  Min.QuadPart = 0;
  Max.QuadPart = 0xFFFFFFFF;
  Align.QuadPart = PAGE_SIZE;

  Mdl = MmAllocatePagesForMdl(Min, Max, Align, Pages * PAGE_SIZE);

  // KdPrint((__DRIVER_NAME " <-- Allocate Pages (mdl = %08x)\n", Mdl));

  return Mdl;
}
  
static PMDL
AllocatePage()
{
  return AllocatePages(1);
}

static NDIS_STATUS
XenNet_TxBufferGC(struct xennet_info *xi)
{
  RING_IDX cons, prod;

  unsigned short id;
  PNDIS_PACKET pkt;
  PMDL pmdl;

  ASSERT(xi->connected);

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
      xi->GntTblInterface.EndAccess(xi->GntTblInterface.InterfaceHeader.Context,
        xi->grant_tx_ref[id]);
      xi->grant_tx_ref[id] = GRANT_INVALID_REF;
      add_id_to_freelist(xi->tx_pkts, id);

      /* free linearized data page */
      pmdl = *(PMDL *)pkt->MiniportReservedEx;
      MmFreePagesFromMdl(pmdl);
      IoFreeMdl(pmdl);

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
    mb();
  } while ((cons == prod) && (prod != xi->tx.sring->rsp_prod));

  /* if queued packets, send them now?
  network_maybe_wake_tx(dev); */

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

    /* Give to netback */
    id = (unsigned short)(req_prod + i) & (NET_RX_RING_SIZE - 1);
    ASSERT(!xi->rx_pkts[id]);
    xi->rx_pkts[id] = packet;
    req = RING_GET_REQUEST(&xi->rx, req_prod + i);
    /* an NDIS_BUFFER is just a MDL, so we can get its pfn array */
    ref = xi->GntTblInterface.GrantAccess(
      xi->GntTblInterface.InterfaceHeader.Context, 0,
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
    xi->EvtChnInterface.Notify(xi->EvtChnInterface.InterfaceHeader.Context,
      xi->event_channel);
  }

  return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
XenNet_RxBufferCheck(struct xennet_info *xi)
{
  RING_IDX cons, prod;

  unsigned short id;
  PNDIS_PACKET pkt;
  PNDIS_PACKET packets[1];
  PNDIS_BUFFER buffer;
  PVOID buff_va;
  UINT buff_len;
  UINT tot_buff_len;

  ASSERT(xi->connected);

  do {
    prod = xi->rx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'rp'. */

    for (cons = xi->rx.rsp_cons; cons != prod; cons++) {
      struct netif_rx_response *rxrsp;

      rxrsp = RING_GET_RESPONSE(&xi->rx, cons);
      if (rxrsp->status == NETIF_RSP_NULL)
        continue;

      id  = rxrsp->id;
      pkt = xi->rx_pkts[id];
      xi->GntTblInterface.EndAccess(xi->GntTblInterface.InterfaceHeader.Context,
        xi->grant_rx_ref[id]);
      xi->grant_rx_ref[id] = GRANT_INVALID_REF;
      //add_id_to_freelist(xi->rx_pkts, id);

      NdisGetFirstBufferFromPacketSafe(pkt, &buffer, &buff_va, &buff_len,
        &tot_buff_len, NormalPagePriority);
      ASSERT(rxrsp->offset == 0);
      ASSERT(rxrsp->status > 0);
      NdisAdjustBufferLength(buffer, rxrsp->status);
      /* just indicate 1 packet for now */
      packets[0] = pkt;

      NdisMIndicateReceivePacket(xi->adapter_handle, packets, 1);
    }

    xi->rx.rsp_cons = prod;

    /*
     * Set a new event, then check for race with update of rx_cons.
     * Note that it is essential to schedule a callback, no matter
     * how few buffers are pending. Even if there is space in the
     * transmit ring, higher layers may be blocked because too much
     * data is outstanding: in such cases notification from Xen is
     * likely to be the only kick that we'll get.
     */
    xi->rx.sring->rsp_event =
      prod + ((xi->rx.sring->req_prod - prod) >> 1) + 1;
    mb();
  } while ((cons == prod) && (prod != xi->rx.sring->rsp_prod));

  /* if queued packets, send them now?
  network_maybe_wake_tx(dev); */

  /* Give netback more buffers */
  XenNet_AllocRXBuffers(xi);

  return NDIS_STATUS_SUCCESS;
}

static BOOLEAN
XenNet_Interrupt(
  PKINTERRUPT Interrupt,
  PVOID ServiceContext
  )
{
  struct xennet_info *xi = ServiceContext;
  // KIRQL KIrql;

  UNREFERENCED_PARAMETER(Interrupt);

  KdPrint((__DRIVER_NAME "     ***XenNet Interrupt***\n"));  

  if (xi->connected)
  {
    XenNet_TxBufferGC(xi);
    XenNet_RxBufferCheck(xi);
  }
  // KeAcquireSpinLock(&ChildDeviceData->Lock, &KIrql);
  // KdPrint((__DRIVER_NAME " --> Setting Dpc Event\n"));
  // KeSetEvent(&ChildDeviceData->DpcThreadEvent, 1, FALSE);
  // KeReleaseSpinLock(&ChildDeviceData->Lock, KIrql);
  // KdPrint((__DRIVER_NAME " --> Dpc Event Set\n"));

  /* handle RX packets */

  return TRUE;
}

static VOID
XenNet_BackEndStateHandler(char *Path, PVOID Data)
{
  struct xennet_info *xi = Data;
  char *Value;
  int be_state;
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
    {"feature-rx-notify", 1},
    {"feature-no-csum-offload", 1},
    {"feature-sg", 1},
    {"feature-gso-tcpv4", 0},
    {NULL, 0},
  };

  xi->XenBusInterface.Read(xi->XenBusInterface.InterfaceHeader.Context,
    XBT_NIL, Path, &Value);
  be_state = atoi(Value);
  ExFreePool(Value);

  switch (be_state)
  {
  case XenbusStateUnknown:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Unknown\n"));  
    break;

  case XenbusStateInitialising:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialising\n"));  
    break;

  case XenbusStateInitWait:
    KdPrint((__DRIVER_NAME "     Backend State Changed to InitWait\n"));  

    xi->event_channel = xi->EvtChnInterface.AllocUnbound(
      xi->EvtChnInterface.InterfaceHeader.Context, 0);  
    xi->EvtChnInterface.Bind(xi->EvtChnInterface.InterfaceHeader.Context,
      xi->event_channel, XenNet_Interrupt, xi);

    /* TODO: must free pages in MDL as well as MDL using MmFreePagesFromMdl and ExFreePool */
    // or, allocate mem and then get mdl, then free mdl
    xi->tx_mdl = AllocatePage();
    xi->tx_pgs = MmMapLockedPagesSpecifyCache(xi->tx_mdl, KernelMode, MmNonCached,
      NULL, FALSE, NormalPagePriority);
    SHARED_RING_INIT(xi->tx_pgs);
    FRONT_RING_INIT(&xi->tx, xi->tx_pgs, PAGE_SIZE);
    xi->tx_ring_ref = xi->GntTblInterface.GrantAccess(
      xi->GntTblInterface.InterfaceHeader.Context, 0,
      *MmGetMdlPfnArray(xi->tx_mdl), FALSE);

    xi->rx_mdl = AllocatePage();
    xi->rx_pgs = MmMapLockedPagesSpecifyCache(xi->rx_mdl, KernelMode, MmNonCached,
      NULL, FALSE, NormalPagePriority);
    SHARED_RING_INIT(xi->rx_pgs);
    FRONT_RING_INIT(&xi->rx, xi->rx_pgs, PAGE_SIZE);
    xi->rx_ring_ref = xi->GntTblInterface.GrantAccess(
      xi->GntTblInterface.InterfaceHeader.Context, 0,
      *MmGetMdlPfnArray(xi->rx_mdl), FALSE);

    /* fixup array for dynamic values */
    params[0].value = xi->tx_ring_ref;
    params[1].value = xi->rx_ring_ref;
    params[2].value = xi->event_channel;

    xi->XenBusInterface.StartTransaction(
      xi->XenBusInterface.InterfaceHeader.Context, &xbt);

    for (i = 0; params[i].name; i++)
    {
      RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/%s",
        xi->Path, params[i].name);
      err = xi->XenBusInterface.Printf(xi->XenBusInterface.InterfaceHeader.Context,
        XBT_NIL, TmpPath, "%d", params[i].value);
      if (err)
      {
        KdPrint(("setting %s failed, err = %s\n", params[i].name, err));
        goto trouble;
      }
    }

    /* commit transaction */
    xi->XenBusInterface.EndTransaction(xi->XenBusInterface.InterfaceHeader.Context,
      xbt, 0, &retry);

    XenNet_AllocRXBuffers(xi);

    KdPrint((__DRIVER_NAME "     Set Frontend state to Connected\n"));
    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->Path);
    xi->XenBusInterface.Printf(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", XenbusStateConnected);

    /* send fake arp? */

    xi->connected = TRUE;

    break;

  case XenbusStateInitialised:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialised\n"));
    // create the device
    break;

  case XenbusStateConnected:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Connected\n"));  

    /* do more stuff here */

    KdPrint((__DRIVER_NAME "     Set Frontend state to Connected\n"));
    break;

  case XenbusStateClosing:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closing\n"));  
    break;

  case XenbusStateClosed:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closed\n"));  
    break;

  default:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Undefined = %d\n", be_state));
    break;
  }

  return;

trouble:
  KdPrint((__DRIVER_NAME __FUNCTION__ ": Should never happen!\n"));
  xi->XenBusInterface.EndTransaction(xi->XenBusInterface.InterfaceHeader.Context,
    xbt, 1, &retry);

}

VOID
XenNet_Halt(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  UNREFERENCED_PARAMETER(MiniportAdapterContext);
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
  char *msg;
  char *Value;
  char **vif_devs;
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

  /* Initialise {tx,rx}_pkts as a free chain containing every entry. */
  for (i = 0; i <= NET_TX_RING_SIZE; i++) {
    xi->tx_pkts[i] = (void *)((unsigned long) i+1);
    xi->grant_tx_ref[i] = GRANT_INVALID_REF;
  }

  for (i = 0; i < NET_RX_RING_SIZE; i++) {
    xi->rx_pkts[i] = NULL;
    xi->grant_rx_ref[i] = GRANT_INVALID_REF;
  }

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

  // status = NdisMInitializeScatterGatherDma(xi->adapter_handle, TRUE,
    // XN_MAX_PKT_SIZE);
  // if (!NT_SUCCESS(status))
  // {
    // KdPrint(("NdisMInitializeScatterGatherDma failed with 0x%x\n", status));
    // status = NDIS_STATUS_FAILURE;
    // goto err;
  // }

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&wdf_attrs, wdf_device_info);

  status = WdfDeviceMiniportCreate(WdfGetDriver(), &wdf_attrs, xi->fdo,
    xi->lower_do, xi->pdo, &xi->wdf_device);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("WdfDeviceMiniportCreate failed with 0x%x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  GetWdfDeviceInfo(xi->wdf_device)->xennet_info = xi;

  /* get lower (Xen) interfaces */

  status = WdfFdoQueryForInterface(xi->wdf_device, &GUID_XEN_IFACE_EVTCHN,
    (PINTERFACE) &xi->EvtChnInterface, sizeof(XEN_IFACE_EVTCHN), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint(("WdfFdoQueryForInterface (EvtChn) failed with status 0x%08x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  status = WdfFdoQueryForInterface(xi->wdf_device, &GUID_XEN_IFACE_XENBUS,
    (PINTERFACE) &xi->XenBusInterface, sizeof(XEN_IFACE_XENBUS), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint(("WdfFdoQueryForInterface (XenBus) failed with status 0x%08x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

#if 0
  status = WdfFdoQueryForInterface(xi->wdf_device, &GUID_XEN_IFACE_XEN,
    (PINTERFACE) &xi->XenInterface, sizeof(XEN_IFACE_XEN), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint(("WdfFdoQueryForInterface (Xen) failed with status 0x%08x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }
#endif

  status = WdfFdoQueryForInterface(xi->wdf_device, &GUID_XEN_IFACE_GNTTBL,
    (PINTERFACE) &xi->GntTblInterface, sizeof(XEN_IFACE_GNTTBL), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint(("WdfFdoQueryForInterface (GntTbl) failed with status 0x%08x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  msg = xi->XenBusInterface.List(xi->EvtChnInterface.InterfaceHeader.Context,
    XBT_NIL, "device/vif", &vif_devs);
  if (msg)
  {
    KdPrint((__DRIVER_NAME ": " __FUNCTION__ ": List retval is nonzero!\n"));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  for (i = 0; vif_devs[i]; i++)
  {
    if (i > 0)
    {
      KdPrint((__DRIVER_NAME "Can only handle 1 vif so far, ignoring vif %s\n", vif_devs[i]));
      continue;
    }
    RtlStringCbPrintfA(xi->Path, ARRAY_SIZE(xi->Path), "device/vif/%s", vif_devs[i]);

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath),
      "device/vif/%s/state", vif_devs[i]);
    KdPrint(("%s\n", TmpPath));

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/backend", xi->Path);
    xi->XenBusInterface.Read(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    if (!Value)
    {
      KdPrint((__DRIVER_NAME "    backend Read Failed\n"));
    }
    else
    {
      RtlStringCbCopyA(xi->BackendPath, ARRAY_SIZE(xi->BackendPath), Value);
      KdPrint((__DRIVER_NAME "backend path = %s\n", xi->BackendPath));
    }
    ExFreePool(Value);

    /* Add watch on backend state */
    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->BackendPath);
    xi->XenBusInterface.AddWatch(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, XenNet_BackEndStateHandler, xi);

    /* get mac address */
    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/mac", xi->Path);
    xi->XenBusInterface.Read(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    if (!Value)
    {
      KdPrint((__DRIVER_NAME "    mac Read Failed\n"));
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
          ExFreePool(Value);
          ExFreePool(vif_devs);
          status = NDIS_STATUS_FAILURE;
          goto err;
        }
        s = e + 1;
      }
      memcpy(xi->curr_mac_addr, xi->perm_mac_addr, ETH_ALEN);
    }
    ExFreePool(Value);

    //XenVbd_HotPlugHandler(buffer, NULL);
    //ExFreePoolWithTag(bdDevices[i], XENPCI_POOL_TAG);
  }
  ExFreePool(vif_devs);

  return NDIS_STATUS_SUCCESS;

err:
  NdisFreeMemory(xi, 0, 0);
  return status;
}

NDIS_OID supported_oids[] =
{
  OID_GEN_SUPPORTED_LIST,
  OID_GEN_HARDWARE_STATUS,
  OID_GEN_MEDIA_SUPPORTED,
  OID_GEN_MEDIA_IN_USE,
  OID_GEN_MAXIMUM_LOOKAHEAD,
  OID_GEN_MAXIMUM_FRAME_SIZE,
  OID_GEN_LINK_SPEED,
  OID_GEN_TRANSMIT_BUFFER_SPACE,
  OID_GEN_RECEIVE_BUFFER_SPACE,
  OID_GEN_TRANSMIT_BLOCK_SIZE,
  OID_GEN_RECEIVE_BLOCK_SIZE,
  OID_GEN_VENDOR_ID,
  OID_GEN_VENDOR_DESCRIPTION,
  OID_GEN_CURRENT_PACKET_FILTER,
  OID_GEN_CURRENT_LOOKAHEAD,
  OID_GEN_DRIVER_VERSION,
  OID_GEN_MAXIMUM_TOTAL_SIZE,
  OID_GEN_MAC_OPTIONS,
  OID_GEN_MEDIA_CONNECT_STATUS,
  OID_GEN_MAXIMUM_SEND_PACKETS,
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
  ULONG temp_data;
  PVOID data = &temp_data;
  UINT len = sizeof(temp_data);
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;

  switch(Oid)
  {
    case OID_GEN_SUPPORTED_LIST:
      data = supported_oids;
      len = sizeof(supported_oids);
      break;
    case OID_GEN_HARDWARE_STATUS:
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
      temp_data = XN_MAX_PKT_SIZE;
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
      temp_data = XN_MAX_PKT_SIZE * NET_TX_RING_SIZE;
      break;
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
      temp_data = XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_RECEIVE_BLOCK_SIZE:
      temp_data = XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_VENDOR_ID:
      temp_data = XENSOURCE_MAC_HDR;
      break;
    case OID_GEN_VENDOR_DESCRIPTION:
      data = vendor_desc;
      len = sizeof(vendor_desc);
      break;
    case OID_GEN_CURRENT_PACKET_FILTER:
      temp_data = xi->packet_filter;
      break;
    case OID_GEN_CURRENT_LOOKAHEAD:
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
      //KdPrint(("Unknown OID 0x%x\n", Oid));
      status = NDIS_STATUS_NOT_SUPPORTED;
  }

  if (!NT_SUCCESS(status))
  {
    return status;
  }

  if (len > InformationBufferLength)
  {
    *BytesNeeded = len;
    return NDIS_STATUS_BUFFER_TOO_SHORT;
  }

  *BytesWritten = len;
  if (len)
  {
    NdisMoveMemory(InformationBuffer, data, len);
  }

  KdPrint(("Got OID 0x%x\n", Oid));

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
  UNREFERENCED_PARAMETER(MiniportAdapterContext);
  UNREFERENCED_PARAMETER(Oid);
  UNREFERENCED_PARAMETER(InformationBuffer);
  UNREFERENCED_PARAMETER(InformationBufferLength);
  UNREFERENCED_PARAMETER(BytesRead);
  UNREFERENCED_PARAMETER(BytesNeeded);

  KdPrint((__FUNCTION__ " called with OID=0x%x\n", Oid));
  return NDIS_STATUS_SUCCESS;
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

  UNREFERENCED_PARAMETER(MiniportAdapterContext);

  NdisGetFirstBufferFromPacketSafe(Packet, &buffer, &buff_va, &buff_len,
    &tot_buff_len, NormalPagePriority);
  ASSERT(buff_len == tot_buff_len);

  NdisFreeMemory(buff_va, 0, 0);
  NdisFreeBuffer(buffer);
  NdisFreePacket(Packet);

  KdPrint((__FUNCTION__ " called\n"));
}

PMDL
XenNet_Linearize(PNDIS_PACKET Packet)
{
  PMDL pmdl;
  char *start;
  PNDIS_BUFFER buffer;
  PVOID buff_va;
  UINT buff_len;
  UINT tot_buff_len;

  pmdl = AllocatePage();

  start = MmGetSystemAddressForMdlSafe(pmdl, NormalPagePriority);
  if (!start)
  {
    return NULL;
  }

  NdisGetFirstBufferFromPacketSafe(Packet, &buffer, &buff_va, &buff_len,
    &tot_buff_len, NormalPagePriority);
  ASSERT(tot_buff_len <= PAGE_SIZE);

  while (buffer)
  {
    NdisQueryBufferSafe(buffer, &buff_va, &buff_len, NormalPagePriority);
    RtlCopyMemory(start, buff_va, buff_len);
    start += buff_len;
    NdisGetNextBuffer(buffer, &buffer);
  }

  return pmdl;
}

VOID
XenNet_SendPackets(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PPNDIS_PACKET PacketArray,
  IN UINT NumberOfPackets
  )
{
  /* for each packet:
    req_prod_pvt is the next entry in the cmd ring to use
    add pkt to array of saved packets
    fill out tx request for the first part of skb
    add to grant table
    do flags for csum etc
    gso (later)
    inc req_prod_pvt
    frags
    possibly notify
    network_tx)buf_gc
    stop netif if no more room
    */
  struct xennet_info *xi = MiniportAdapterContext;
  PNDIS_PACKET curr_packet;
  UINT i;
  struct netif_tx_request *tx;
  unsigned short id;
  int notify;
  PMDL pmdl;
  UINT pkt_size;

  KdPrint((__FUNCTION__ " called, sending %d pkts\n", NumberOfPackets));

  for (i = 0; i < NumberOfPackets; i++)
  {
    curr_packet = PacketArray[i];
    ASSERT(curr_packet);

    NdisQueryPacket(curr_packet, NULL, NULL, NULL, &pkt_size);

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
    tx->gref = xi->GntTblInterface.GrantAccess(
      xi->GntTblInterface.InterfaceHeader.Context,
      0,
      *MmGetMdlPfnArray(pmdl),
      TRUE);
    xi->grant_tx_ref[id] = tx->gref;
    tx->offset = 0;
    tx->size = (UINT16)pkt_size;
    tx->flags = NETTXF_csum_blank;

    xi->tx.req_prod_pvt++;

    // NDIS_SET_PACKET_STATUS(curr_packet, NDIS_STATUS_SUCCESS);
    // NdisMSendComplete(xi, curr_packet, NDIS_STATUS_SUCCESS);
  }

  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xi->tx, notify);
  if (notify)
  {
    xi->EvtChnInterface.Notify(xi->EvtChnInterface.InterfaceHeader.Context,
      xi->event_channel);
  }
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
  UNREFERENCED_PARAMETER(MiniportAdapterContext);

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
  mini_chars.MajorNdisVersion = 5;
  mini_chars.MinorNdisVersion = 1;

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
