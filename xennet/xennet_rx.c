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

static PMDL
get_page_from_freelist(struct xennet_info *xi)
{
  PMDL mdl;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  if (xi->page_free == 0)
  {
    mdl = AllocatePagesExtra(1, sizeof(grant_ref_t));
    *(grant_ref_t *)(((UCHAR *)mdl) + MmSizeOfMdl(0, PAGE_SIZE)) = xi->XenInterface.GntTbl_GrantAccess(
      xi->XenInterface.InterfaceHeader.Context, 0,
      *MmGetMdlPfnArray(mdl), FALSE, 0);
//    KdPrint(("New Mdl = %p, MmGetMdlVirtualAddress = %p, MmGetSystemAddressForMdlSafe = %p\n",
//      mdl, MmGetMdlVirtualAddress(mdl), MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority)));
  }
  else
  {
    xi->page_free--;
    mdl = xi->page_list[xi->page_free];
//    KdPrint(("Old Mdl = %p, MmGetMdlVirtualAddress = %p, MmGetSystemAddressForMdlSafe = %p\n",
//      mdl, MmGetMdlVirtualAddress(mdl), MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority)));
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return mdl;
}

static VOID
free_page_freelist(struct xennet_info *xi)
{
  PMDL mdl;
//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  while(xi->page_free != 0)
  {
    xi->page_free--;
    mdl = xi->page_list[xi->page_free];
    xi->XenInterface.GntTbl_EndAccess(xi->XenInterface.InterfaceHeader.Context,
      *(grant_ref_t *)(((UCHAR *)mdl) + MmSizeOfMdl(0, PAGE_SIZE)), 0);
    FreePages(mdl);
  }
}

static VOID
put_page_on_freelist(struct xennet_info *xi, PMDL mdl)
{
//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

//  KdPrint(("Mdl = %p\n",  mdl));

  xi->page_list[xi->page_free] = mdl;
  xi->page_free++;

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static __inline grant_ref_t
get_grant_ref(PMDL mdl)
{
  return *(grant_ref_t *)(((UCHAR *)mdl) + MmSizeOfMdl(0, PAGE_SIZE));
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
  int cycles = 0;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
#endif

//KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
#if defined(XEN_PROFILE)
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  batch_target = xi->rx_target - (req_prod - xi->rx.rsp_cons);

  for (i = 0; i < batch_target; i++)
  {
    ASSERT(cycles++ < 256);
    if (xi->rx_id_free == 0)
      break;
    mdl = get_page_from_freelist(xi);
    if (mdl == NULL)
      break;
    xi->rx_id_free--;

    /* Give to netback */
    id = (USHORT)((req_prod + i) & (NET_RX_RING_SIZE - 1));
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

//KdPrint((__DRIVER_NAME "     Added %d out of %d buffers to rx ring\n", i, batch_target));

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
  PMDL first_mdl = NULL;
  int moretodo;
  struct netif_rx_response *rxrsp = NULL;
  struct netif_extra_info *ei;
  int more_frags = 0;
  NDIS_STATUS status;
  USHORT id;
  PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;
  USHORT total_packet_length = 0;
  USHORT first_buffer_length = 0;
  int cycles = 0;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, tsc2, dummy;
#endif
  
//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  tsc = tsc2 = KeQueryPerformanceCounter(&dummy);
#endif

  ASSERT(xi->connected);

  KeAcquireSpinLockAtDpcLevel(&xi->rx_lock);

  packet_count = 0;
  if (xi->rx_current_packet)
  {
    packets[0] = xi->rx_current_packet;
    xi->rx_current_packet = NULL;
    first_mdl = xi->rx_first_mdl;
    more_frags = NETRXF_more_data;
    first_buffer_length = xi->rx_first_buffer_length;
  }
  do {
    ASSERT(cycles++ < 256);
    prod = xi->rx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'rp'. */

    for (cons = xi->rx.rsp_cons; cons != prod; cons++) {
      ASSERT(cycles++ < 256);
      id = (USHORT)(cons & (NET_RX_RING_SIZE - 1));
      mdl = xi->rx_buffers[id];
      xi->rx_buffers[id] = NULL;
      xi->rx_id_free++;
      if (xi->rx_extra_info)
      {
//KdPrint((__DRIVER_NAME "     RX extra info detected\n"));
        put_page_on_freelist(xi, mdl);
        ei = (struct netif_extra_info *)RING_GET_RESPONSE(&xi->rx, cons);
        xi->rx_extra_info = ei->flags & XEN_NETIF_EXTRA_FLAG_MORE;
        switch (ei->type)
        {
        case XEN_NETIF_EXTRA_TYPE_GSO:
//KdPrint((__DRIVER_NAME "     GSO detected - size = %d\n", ei->u.gso.size));
          switch (ei->u.gso.type)
          {
          case XEN_NETIF_GSO_TYPE_TCPV4:
//KdPrint((__DRIVER_NAME "     GSO_TYPE_TCPV4 detected\n"));
//            NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpLargeSendPacketInfo) = (PVOID)(xen_ulong_t)(ei->u.gso.size);
            break;
          default:
            KdPrint((__DRIVER_NAME "     Unknown GSO type (%d) detected\n", ei->u.gso.type));
            break;
          }
          break;
        default:
          KdPrint((__DRIVER_NAME "     Unknown extra info type (%d) detected\n", ei->type));
          break;
        }
      }
      else
      {
//KdPrint((__DRIVER_NAME "     normal packet detected\n"));
        rxrsp = RING_GET_RESPONSE(&xi->rx, cons);
        if (rxrsp->status <= 0
          || rxrsp->offset + rxrsp->status > PAGE_SIZE)
        {
          KdPrint((__DRIVER_NAME ": Error: rxrsp offset %d, size %d\n",
            rxrsp->offset, rxrsp->status));
          continue;
        }
        ASSERT(rxrsp->id == id);
        if (!more_frags) // handling the packet's 1st buffer
        {
          first_buffer_length = total_packet_length = rxrsp->status;
          first_mdl = mdl;
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
            ProfCount_RxPacketsCsumOffload++;
#endif
          }
          // we also need to manually split gso packets that we receive that originated on our side of the physical interface...
        }
        else
        {
          NdisAdjustBufferLength(mdl, rxrsp->status);
          NdisChainBufferAtBack(packets[packet_count], mdl);
          first_buffer_length = first_buffer_length  - (USHORT)rxrsp->status;
        }
        
        xi->rx_extra_info = rxrsp->flags & NETRXF_extra_info;
        more_frags = rxrsp->flags & NETRXF_more_data;
      }

      /* Packet done, add it to the list */
      if (!more_frags && !xi->rx_extra_info)
      {
        NdisAdjustBufferLength(first_mdl, first_buffer_length);
        NdisChainBufferAtFront(packets[packet_count], first_mdl);

//if (PtrToUlong(NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpLargeSendPacketInfo)))
//  KdPrint((__DRIVER_NAME "     first_buffer_length = %d, total length = %d\n", first_buffer_length, total_packet_length));
#if defined(XEN_PROFILE)
        ProfCount_RxPacketsTotal++;
#endif
        xi->stat_rx_ok++;
        NDIS_SET_PACKET_STATUS(packets[packet_count], NDIS_STATUS_SUCCESS);
        packet_count++;
      }
    }
    xi->rx.rsp_cons = prod;

    RING_FINAL_CHECK_FOR_RESPONSES(&xi->rx, moretodo);
  } while (moretodo);

  /* Give netback more buffers */
  XenNet_RxBufferAlloc(xi);

  if (more_frags)
  {
    xi->rx_current_packet = packets[packet_count];
    xi->rx_first_mdl = first_mdl;
    xi->rx_first_buffer_length = first_buffer_length;
  }

  KeReleaseSpinLockFromDpcLevel(&xi->rx_lock);

#if defined(XEN_PROFILE)
  ProfTime_RxBufferCheckTopHalf.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc2.QuadPart;
  tsc2 = KeQueryPerformanceCounter(&dummy);
#endif

  if (packet_count > 0)
  {
    NdisMIndicateReceivePacket(xi->adapter_handle, packets, packet_count);
#if defined(XEN_PROFILE)
    ProfCount_CallsToIndicateReceive++;
#endif
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  ProfTime_RxBufferCheck.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfTime_RxBufferCheckBotHalf.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc2.QuadPart;
  ProfCount_RxBufferCheck++;
#endif

  return NDIS_STATUS_SUCCESS;
}

/* called at DISPATCH_LEVEL */

VOID
XenNet_ReturnPacket(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PNDIS_PACKET Packet
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
  PMDL mdl;
  int cycles = 0;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
#endif

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  KeAcquireSpinLockAtDpcLevel(&xi->rx_lock);

  NdisUnchainBufferAtBack(Packet, &mdl);
  while (mdl)
  {
    ASSERT(cycles++ < 256);
    NdisAdjustBufferLength(mdl, PAGE_SIZE);
    put_page_on_freelist(xi, mdl);
    NdisUnchainBufferAtBack(Packet, &mdl);
  }

  NdisFreePacket(Packet);

  KeReleaseSpinLockFromDpcLevel(&xi->rx_lock);
  
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
  int i;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  xi->page_free = 0;
  xi->rx_current_packet = NULL;
  xi->rx_extra_info = 0;
  
  xi->rx_mdl = AllocatePage();
  xi->rx_pgs = MmGetMdlVirtualAddress(xi->rx_mdl);
  SHARED_RING_INIT(xi->rx_pgs);
  FRONT_RING_INIT(&xi->rx, xi->rx_pgs, PAGE_SIZE);
  xi->rx_ring_ref = xi->XenInterface.GntTbl_GrantAccess(
    xi->XenInterface.InterfaceHeader.Context, 0,
    *MmGetMdlPfnArray(xi->rx_mdl), FALSE, 0);
  xi->rx_id_free = NET_RX_RING_SIZE;

  for (i = 0; i < NET_RX_RING_SIZE; i++)
  {
    xi->rx_buffers[i] = NULL;
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

  free_page_freelist(xi);

  /* free RX resources */
  if (xi->XenInterface.GntTbl_EndAccess(
    xi->XenInterface.InterfaceHeader.Context, xi->rx_ring_ref, 0))
  {
    xi->rx_ring_ref = GRANT_INVALID_REF;
    FreePages(xi->rx_mdl);
  }
  xi->rx_pgs = NULL;

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}
