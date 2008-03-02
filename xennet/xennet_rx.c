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

#include "xennet.h"

static USHORT
get_rx_id_from_freelist(struct xennet_info *xi)
{
  if (xi->rx_id_free == 0)
    return 0xFFFF;
  xi->rx_id_free--;
  return xi->rx_id_list[xi->rx_id_free];
}

static VOID
put_rx_id_on_freelist(struct xennet_info *xi, USHORT id)
{
  xi->rx_id_list[xi->rx_id_free] = id;
  xi->rx_id_free++;
}

// Called at DISPATCH_LEVEL with rx lock held
static NDIS_STATUS
XenNet_RxBufferAlloc(struct xennet_info *xi)
{
  unsigned short id;
  PMDL mdl;
  int i, batch_target, notify;
  RING_IDX req_prod = xi->rx.req_prod_pvt;
  netif_rx_request_t *req;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
#endif

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
#if defined(XEN_PROFILE)
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  batch_target = xi->rx_target - (req_prod - xi->rx.rsp_cons);

  for (i = 0; i < batch_target; i++)
  {
    mdl = get_page_from_freelist(xi);
    if (mdl == NULL)
      break;

    /* Give to netback */
    id = get_rx_id_from_freelist(xi);
    if (id == 0xFFFF)
    {
      put_page_on_freelist(xi, mdl);
      break;
    }
//    KdPrint((__DRIVER_NAME "     id = %d\n", id));
    ASSERT(xi->rx_buffers[id] == NULL);
    xi->rx_buffers[id] = mdl;
    req = RING_GET_REQUEST(&xi->rx, req_prod + i);
    req->gref = get_grant_ref(mdl);
    req->id = id;
  }

  xi->rx.req_prod_pvt = req_prod + i;
  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xi->rx, notify);
  if (notify)
  {
    xi->XenInterface.EvtChn_Notify(xi->XenInterface.InterfaceHeader.Context,
      xi->event_channel);
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  ProfTime_RxBufferAlloc.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_RxBufferAlloc++;
#endif

  return NDIS_STATUS_SUCCESS;
}

// Called at DISPATCH_LEVEL
NDIS_STATUS
XenNet_RxBufferCheck(struct xennet_info *xi)
{
  RING_IDX cons, prod;
  PNDIS_PACKET packets[NET_RX_RING_SIZE];
  ULONG packet_count;
  PMDL mdl;
  int moretodo;
  KIRQL OldIrql;
  struct netif_rx_response *rxrsp = NULL;
  int more_frags = 0;
  NDIS_STATUS status;
  LARGE_INTEGER time_received;
  USHORT id;
  PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
#endif
  
//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  ASSERT(xi->connected);

  NdisGetCurrentSystemTime(&time_received);
  KeAcquireSpinLock(&xi->rx_lock, &OldIrql);

  packet_count = 0;
  do {
    prod = xi->rx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'rp'. */

    for (cons = xi->rx.rsp_cons; cons != prod; cons++) {

      rxrsp = RING_GET_RESPONSE(&xi->rx, cons);
      id = rxrsp->id;
      mdl = xi->rx_buffers[id];
      xi->rx_buffers[id] = NULL;
      put_rx_id_on_freelist(xi, id);
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
        if (rxrsp->flags & (NETRXF_csum_blank|NETRXF_data_validated)) // and we are enabled for offload...
        {
          csum_info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)&NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpIpChecksumPacketInfo);
          csum_info->Receive.NdisPacketTcpChecksumSucceeded = 1;
          csum_info->Receive.NdisPacketUdpChecksumSucceeded = 1;
          csum_info->Receive.NdisPacketIpChecksumSucceeded = 1;
#if defined(XEN_PROFILE)
          ProfCount_RxPacketsOffload++;
#endif
        }
      }

      NdisAdjustBufferLength(mdl, rxrsp->status);
      NdisChainBufferAtBack(packets[packet_count], mdl);

      ASSERT(!(rxrsp->flags & NETRXF_extra_info)); // not used on RX

      more_frags = rxrsp->flags & NETRXF_more_data;

      /* Packet done, pass it up */
      if (!more_frags)
      {
#if defined(XEN_PROFILE)
        ProfCount_RxPacketsTotal++;
#endif
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

#if defined(XEN_PROFILE)
  ProfTime_RxBufferCheck.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_RxBufferCheck++;
#endif

  return NDIS_STATUS_SUCCESS;
}

/* called at DISPATCH_LEVEL with rx_lock held (as it gets called from IndicateReceived) */

VOID
XenNet_ReturnPacket(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PNDIS_PACKET Packet
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
  PMDL mdl;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
#endif

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  NdisUnchainBufferAtBack(Packet, &mdl);
  while (mdl)
  {
    NdisAdjustBufferLength(mdl, PAGE_SIZE);
    put_page_on_freelist(xi, mdl);
    NdisUnchainBufferAtBack(Packet, &mdl);
  }

  NdisFreePacket(Packet);
  
  InterlockedDecrement(&xi->rx_outstanding);

  // if we are no longer connected then _halt needs to know when rx_outstanding reaches zero
  if (!xi->connected && !xi->rx_outstanding)
    KeSetEvent(&xi->shutdown_event, 1, FALSE);  

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  ProfTime_ReturnPacket.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_ReturnPacket++;
#endif
}

/*
   Free all Rx buffers (on halt, for example) 
   The ring must be stopped at this point.
*/
static void
XenNet_RxBufferFree(struct xennet_info *xi)
{
  int i;
  PMDL mdl;

  ASSERT(!xi->connected);

  for (i = 0; i < NET_RX_RING_SIZE; i++)
  {
    if (!xi->rx_buffers[i])
      continue;

    mdl = xi->rx_buffers[i];
    NdisAdjustBufferLength(mdl, PAGE_SIZE);
    put_page_on_freelist(xi, mdl);
  }
}

BOOLEAN
XenNet_RxInit(xennet_info_t *xi)
{
  USHORT i;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  xi->rx_mdl = AllocatePage();
  xi->rx_pgs = MmGetMdlVirtualAddress(xi->rx_mdl);
  SHARED_RING_INIT(xi->rx_pgs);
  FRONT_RING_INIT(&xi->rx, xi->rx_pgs, PAGE_SIZE);
  xi->rx_ring_ref = xi->XenInterface.GntTbl_GrantAccess(
    xi->XenInterface.InterfaceHeader.Context, 0,
    *MmGetMdlPfnArray(xi->rx_mdl), FALSE);
  xi->rx_id_free = 0;
  for (i = 0; i < NET_RX_RING_SIZE; i++)
  {
    xi->rx_buffers[i] = NULL;
    put_rx_id_on_freelist(xi, i);
  }
  XenNet_RxBufferAlloc(xi);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

BOOLEAN
XenNet_RxShutdown(xennet_info_t *xi)
{
  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  XenNet_RxBufferFree(xi);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}
