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

#define FREELIST_ID_ERROR 0xFFFF

#ifdef XEN_PROFILE
#define PC_INC(var) var++
#else
#define PC_INC(var)
#endif

static ULONG
free_requests(struct xennet_info *xi)
{
  return xi->tx_id_free;
}

static USHORT
get_id_from_freelist(struct xennet_info *xi)
{
  if (xi->tx_id_free - xi->tx_no_id_free == 0)
    return FREELIST_ID_ERROR;
  xi->tx_id_free--;
  return xi->tx_id_list[xi->tx_id_free];
}

static USHORT
get_no_id_from_freelist(struct xennet_info *xi)
{
  if (xi->tx_id_free - xi->tx_no_id_free == 0)
    return FREELIST_ID_ERROR;
  xi->tx_no_id_free--;
  return 0;
}

static VOID
put_id_on_freelist(struct xennet_info *xi, USHORT id)
{
  xi->tx_id_list[xi->tx_id_free] = id;
  xi->tx_id_free++;
}

static VOID
put_no_id_on_freelist(struct xennet_info *xi)
{
  xi->tx_no_id_free++;
}

static grant_ref_t
get_gref_from_freelist(struct xennet_info *xi)
{
  if (xi->tx_gref_free == 0)
    return 0;
  xi->tx_gref_free--;
  return xi->tx_gref_list[xi->tx_gref_free];
}

static VOID
put_gref_on_freelist(struct xennet_info *xi, grant_ref_t gref)
{
  xi->tx_gref_list[xi->tx_gref_free] = gref;
  xi->tx_gref_free++;
}


#define SWAP_USHORT(x) (USHORT)((((x & 0xFF) << 8)|((x >> 8) & 0xFF)))

typedef struct
{
  PFN_NUMBER pfn;
  USHORT offset;
  USHORT length;
} page_element_t;

static VOID
XenNet_BuildPageList(packet_info_t *pi, page_element_t *elements, PUSHORT num_elements)
{
  USHORT element_num = 0;
  UINT offset;
  UINT remaining;
  ULONG pages;
  USHORT page;
  PPFN_NUMBER pfns;
  ULONG i;

  for (i = 0; i < pi->mdl_count; i++)
  {
    offset = MmGetMdlByteOffset(pi->mdls[i]);
    remaining = MmGetMdlByteCount(pi->mdls[i]);
    pages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(pi->mdls[i]), remaining);
    pfns = MmGetMdlPfnArray(pi->mdls[i]);
    for (page = 0; page < pages; page++, element_num++)
    {
      ASSERT(element_num < *num_elements);
      elements[element_num].pfn = pfns[page];
      elements[element_num].offset = (USHORT)offset;
      elements[element_num].length = (USHORT)min(remaining, PAGE_SIZE - offset);
//KdPrint((__DRIVER_NAME "     adding to page list size = %d, pfn = %08x, offset = %04x\n", elements[element_num].length, elements[element_num].pfn, elements[element_num].offset));
      offset = 0;
      remaining -= elements[element_num].length;
    }
    ASSERT(remaining == 0);
  }
  *num_elements = element_num;
}

/* Place a buffer on tx ring. */
static struct netif_tx_request*
XenNet_PutOnTxRing(
  struct xennet_info *xi,
  PFN_NUMBER pfn,
  USHORT offset,
  USHORT len,
  uint16_t flags)
{
  struct netif_tx_request *tx;
  unsigned short id;

  id = get_id_from_freelist(xi);
  ASSERT(id != FREELIST_ID_ERROR);
  ASSERT(xi->tx_pkts[id] == NULL);
  tx = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);

  tx->gref = get_gref_from_freelist(xi);
  ASSERT(tx->gref != 0);
  ASSERT(xi->tx_grefs[id] == 0);
  xi->tx_grefs[id] = tx->gref;

  xi->XenInterface.GntTbl_GrantAccess(
    xi->XenInterface.InterfaceHeader.Context, 0,
    pfn, FALSE, tx->gref);
  tx->id = id;
  tx->offset = (uint16_t)offset;
  tx->size = (uint16_t)len;
  tx->flags = flags;
  PC_INC(ProfCount_TxPacketsTotal);

  return tx;
}

/* Called at DISPATCH_LEVEL with tx_lock held */
/*
 * Send one NDIS_PACKET. This may involve multiple entries on TX ring.
 */
static BOOLEAN
XenNet_HWSendPacket(struct xennet_info *xi, PNDIS_PACKET packet)
{
  struct netif_tx_request *tx = NULL;
  struct netif_extra_info *ei;
  PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;
  UINT total_packet_length;
  ULONG mss; // 0 if not using large send
  PMDL buffer;
  uint16_t flags = NETTXF_more_data;
  page_element_t elements[NET_TX_RING_SIZE];
  USHORT num_elements;
  USHORT element_num;
  packet_info_t pi;
  PUCHAR address = NULL;
  PMDL merged_buffer = NULL;
  ULONG length = 0;
  
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;

  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  RtlZeroMemory(&pi, sizeof(pi));

  csum_info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)&NDIS_PER_PACKET_INFO_FROM_PACKET(
    packet, TcpIpChecksumPacketInfo);
  mss = PtrToUlong(NDIS_PER_PACKET_INFO_FROM_PACKET(packet, TcpLargeSendPacketInfo));

  NdisQueryPacket(packet, NULL, NULL, &buffer, &total_packet_length);

  pi.mdls[0] = buffer;
  pi.mdl_count = 1;
  // only if csum offload
  if ((csum_info->Transmit.NdisPacketTcpChecksum
    || csum_info->Transmit.NdisPacketUdpChecksum
    || mss > 0)
    && XenNet_ParsePacketHeader(&pi) == PARSE_TOO_SMALL)
  {
    pi.mdls[0] = merged_buffer = AllocatePage();
    address = MmGetMdlVirtualAddress(pi.mdls[0]);
    memcpy(address, MmGetSystemAddressForMdlSafe(buffer, NormalPagePriority), MmGetMdlByteCount(buffer));
    length = MmGetMdlByteCount(buffer);
    NdisAdjustBufferLength(pi.mdls[0], length); /* do this here so that ParsePacketHeader works */
    while (buffer->Next != NULL && XenNet_ParsePacketHeader(&pi) == PARSE_TOO_SMALL)
    {
      buffer = buffer->Next;
      ASSERT(length + MmGetMdlByteCount(buffer) <= PAGE_SIZE); // I think this could happen
      memcpy(&address[length], MmGetSystemAddressForMdlSafe(buffer, NormalPagePriority), MmGetMdlByteCount(buffer));
      length += MmGetMdlByteCount(buffer);
      NdisAdjustBufferLength(pi.mdls[0], length); /* do this here so that ParsePacketHeader works */
    }
  }
  NdisGetNextBuffer(buffer, &buffer);
  while (buffer != NULL)
  {
    pi.mdls[pi.mdl_count++] = buffer;
    NdisGetNextBuffer(buffer, &buffer);
  }
  
  num_elements = NET_TX_RING_SIZE;
  XenNet_BuildPageList(&pi, elements, &num_elements);

  if (num_elements + !!mss > (int)free_requests(xi))
    return FALSE;

  if (csum_info->Transmit.NdisPacketTcpChecksum
    || csum_info->Transmit.NdisPacketUdpChecksum)
  {
    flags |= NETTXF_csum_blank | NETTXF_data_validated;
    PC_INC(ProfCount_TxPacketsCsumOffload);
  }

  if (mss > 0)
  {
    flags |= NETTXF_extra_info;
    XenNet_SumIpHeader(MmGetSystemAddressForMdlSafe(pi.mdls[0], NormalPagePriority), pi.ip4_header_length);
    PC_INC(ProfCount_TxPacketsLargeOffload);
  }

  /*
   * See io/netif.h. Must put (A) 1st request, then (B) optional extra_info, then
   * (C) rest of requests on the ring. Only (A) has csum flags.
   */
  /* (A) */
  tx = XenNet_PutOnTxRing(xi, elements[0].pfn, elements[0].offset, (USHORT)total_packet_length, flags);
  xi->tx.req_prod_pvt++;

  /* (B) */
  if (mss > 0)
  {
    get_no_id_from_freelist(xi);
    ei = (struct netif_extra_info *)RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
    ei->type = XEN_NETIF_EXTRA_TYPE_GSO;
    ei->flags = 0;
    ei->u.gso.size = (USHORT) mss;
    ei->u.gso.type = XEN_NETIF_GSO_TYPE_TCPV4;
    ei->u.gso.pad = 0;
    ei->u.gso.features = 0;

    xi->tx.req_prod_pvt++;
  }

  /* (C) */
  for (element_num = 1; element_num < num_elements; element_num++)
  {
//if (csum_info->Transmit.NdisPacketTcpChecksum || csum_info->Transmit.NdisPacketUdpChecksum)
//KdPrint((__DRIVER_NAME "                   - size = %d, pfn = %08x, offset = %04x\n", elements[element_num].length, elements[element_num].pfn, elements[element_num].offset));
    //KdPrint((__DRIVER_NAME "     i = %d\n", i));
    tx = XenNet_PutOnTxRing(xi, elements[element_num].pfn,
      elements[element_num].offset, elements[element_num].length,
      NETTXF_more_data);
    xi->tx.req_prod_pvt++;
  }

  /* only set the packet on the last buffer, clear more_data */
  ASSERT(tx);
  xi->tx_pkts[tx->id] = packet;
  xi->tx_mdls[tx->id] = merged_buffer;
  tx->flags &= ~NETTXF_more_data;

  return TRUE;
}

/* Called at DISPATCH_LEVEL with tx_lock held */

static VOID
XenNet_SendQueuedPackets(struct xennet_info *xi)
{
  PLIST_ENTRY entry;
  PNDIS_PACKET packet;
  int notify;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
#endif
  
  int cycles = 0;
  BOOLEAN success;

#if defined(XEN_PROFILE)
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  /* if empty, the above returns head*, not NULL */
  while (entry != &xi->tx_waiting_pkt_list)
  {
    ASSERT(cycles++ < 65536);
    //KdPrint((__DRIVER_NAME "     Packet ready to send\n"));
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    success = XenNet_HWSendPacket(xi, packet);
    if (!success)
      break;
    entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  }

  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xi->tx, notify);
  if (notify)
  {
    xi->XenInterface.EvtChn_Notify(xi->XenInterface.InterfaceHeader.Context,
      xi->event_channel);
  }

#if defined(XEN_PROFILE)
  ProfTime_SendQueuedPackets.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_SendQueuedPackets++;
#endif
}

// Called at DISPATCH_LEVEL
NDIS_STATUS
XenNet_TxBufferGC(struct xennet_info *xi)
{
  RING_IDX cons, prod;
  unsigned short id;
  PNDIS_PACKET packets[NET_TX_RING_SIZE];
  ULONG packet_count = 0;
  int moretodo;
  ULONG i;
  UINT total_packet_length;
  int cycles = 0;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
#endif

  ASSERT(xi->connected);
  ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  KeAcquireSpinLockAtDpcLevel(&xi->tx_lock);

  do {
    ASSERT(cycles++ < 65536);
    prod = xi->tx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'rp'. */

    for (cons = xi->tx.rsp_cons; cons != prod; cons++)
    {
      struct netif_tx_response *txrsp;

      ASSERT(cycles++ < 65536);

      txrsp = RING_GET_RESPONSE(&xi->tx, cons);
      if (txrsp->status == NETIF_RSP_NULL)
      {
//        KdPrint((__DRIVER_NAME "     NETIF_RSP_NULL\n"));
        put_no_id_on_freelist(xi);
        continue; // This would be the response to an extra_info packet
      }

      id  = txrsp->id;
      packets[packet_count] = xi->tx_pkts[id];
      if (packets[packet_count])
      {
        NdisQueryPacket(packets[packet_count], NULL, NULL, NULL, &total_packet_length);
        if (NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpLargeSendPacketInfo) != 0)
        {
          NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpLargeSendPacketInfo) = UlongToPtr(total_packet_length);
//KdPrint((__DRIVER_NAME "     Large Send Response = %d\n", NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpLargeSendPacketInfo)));
        }
        xi->tx_pkts[id] = NULL;
        packet_count++;
        xi->stat_tx_ok++;
      }
      if (xi->tx_mdls[id])
      {
        FreePages(xi->tx_mdls[id]);
        xi->tx_mdls[id] = NULL;
      }
      put_gref_on_freelist(xi, xi->tx_grefs[id]);
      xi->tx_grefs[id] = 0;
      put_id_on_freelist(xi, id);
    }

    xi->tx.rsp_cons = prod;

    RING_FINAL_CHECK_FOR_RESPONSES(&xi->tx, moretodo);
  } while (moretodo);

  /* if queued packets, send them now */
  XenNet_SendQueuedPackets(xi);

  KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);

  for (i = 0; i < packet_count; i++)
  {
    /* A miniport driver must release any spin lock that it is holding before
       calling NdisMSendComplete. */
    NdisMSendComplete(xi->adapter_handle, packets[i], NDIS_STATUS_SUCCESS);
    xi->tx_outstanding--;
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  ProfTime_TxBufferGC.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_TxBufferGC++;
#endif

  return NDIS_STATUS_SUCCESS;
}

VOID
XenNet_SendPackets(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PPNDIS_PACKET PacketArray,
  IN UINT NumberOfPackets
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
  PNDIS_PACKET packet;
  UINT i;
  PLIST_ENTRY entry;
  KIRQL OldIrql;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
  KIRQL OldIrql2;
#endif

#if defined(XEN_PROFILE)
  KeRaiseIrql(DISPATCH_LEVEL, &OldIrql2);
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  KeAcquireSpinLock(&xi->tx_lock, &OldIrql);

  //  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  for (i = 0; i < NumberOfPackets; i++)
  {
    packet = PacketArray[i];
    ASSERT(packet);
    *(ULONG *)&packet->MiniportReservedEx = 0;
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(&xi->tx_waiting_pkt_list, entry);
    xi->tx_outstanding++;
#if defined(XEN_PROFILE)
    ProfCount_PacketsPerSendPackets++;
#endif
  }

  XenNet_SendQueuedPackets(xi);

  KeReleaseSpinLock(&xi->tx_lock, OldIrql);

#if defined(XEN_PROFILE)
  ProfTime_SendPackets.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_SendPackets++;
  KeLowerIrql(OldIrql2);
#endif

#if defined(XEN_PROFILE)
  if ((ProfCount_SendPackets & 1023) == 0)
  {
    KdPrint((__DRIVER_NAME "     ***\n"));
    KdPrint((__DRIVER_NAME "     RxBufferAlloc     Count = %10d, Avg Time     = %10ld\n", ProfCount_RxBufferAlloc, (ProfCount_RxBufferAlloc == 0)?0:(ProfTime_RxBufferAlloc.QuadPart / ProfCount_RxBufferAlloc)));
    KdPrint((__DRIVER_NAME "     ReturnPacket      Count = %10d, Avg Time     = %10ld\n", ProfCount_ReturnPacket, (ProfCount_ReturnPacket == 0)?0:(ProfTime_ReturnPacket.QuadPart / ProfCount_ReturnPacket)));
    KdPrint((__DRIVER_NAME "     RxBufferCheck     Count = %10d, Avg Time     = %10ld\n", ProfCount_RxBufferCheck, (ProfCount_RxBufferCheck == 0)?0:(ProfTime_RxBufferCheck.QuadPart / ProfCount_RxBufferCheck)));
    KdPrint((__DRIVER_NAME "     RxBufferCheckTop                      Avg Time     = %10ld\n", (ProfCount_RxBufferCheck == 0)?0:(ProfTime_RxBufferCheckTopHalf.QuadPart / ProfCount_RxBufferCheck)));
    KdPrint((__DRIVER_NAME "     RxBufferCheckBot                      Avg Time     = %10ld\n", (ProfCount_RxBufferCheck == 0)?0:(ProfTime_RxBufferCheckBotHalf.QuadPart / ProfCount_RxBufferCheck)));
    KdPrint((__DRIVER_NAME "     Linearize         Count = %10d, Avg Time     = %10ld\n", ProfCount_Linearize, (ProfCount_Linearize == 0)?0:(ProfTime_Linearize.QuadPart / ProfCount_Linearize)));
    KdPrint((__DRIVER_NAME "     SendPackets       Count = %10d, Avg Time     = %10ld\n", ProfCount_SendPackets, (ProfCount_SendPackets == 0)?0:(ProfTime_SendPackets.QuadPart / ProfCount_SendPackets)));
    KdPrint((__DRIVER_NAME "     Packets per SendPackets = %10d\n", (ProfCount_SendPackets == 0)?0:(ProfCount_PacketsPerSendPackets / ProfCount_SendPackets)));
    KdPrint((__DRIVER_NAME "     SendQueuedPackets Count = %10d, Avg Time     = %10ld\n", ProfCount_SendQueuedPackets, (ProfCount_SendQueuedPackets == 0)?0:(ProfTime_SendQueuedPackets.QuadPart / ProfCount_SendQueuedPackets)));
    KdPrint((__DRIVER_NAME "     TxBufferGC        Count = %10d, Avg Time     = %10ld\n", ProfCount_TxBufferGC, (ProfCount_TxBufferGC == 0)?0:(ProfTime_TxBufferGC.QuadPart / ProfCount_TxBufferGC)));
    KdPrint((__DRIVER_NAME "     RxPackets         Total = %10d, Csum Offload = %10d, Calls To Receive = %10d\n", ProfCount_RxPacketsTotal, ProfCount_RxPacketsCsumOffload, ProfCount_CallsToIndicateReceive));
    KdPrint((__DRIVER_NAME "     TxPackets         Total = %10d, Csum Offload = %10d, Large Offload    = %10d\n", ProfCount_TxPacketsTotal, ProfCount_TxPacketsCsumOffload, ProfCount_TxPacketsLargeOffload));
  }
#endif
  //  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static void
XenNet_TxBufferFree(struct xennet_info *xi)
{
  PLIST_ENTRY entry;
  PNDIS_PACKET packet;
  USHORT i;
  grant_ref_t gref;

  ASSERT(!xi->connected);

  /* Free packets in tx queue */
  entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  while (entry != &xi->tx_waiting_pkt_list)
  {
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_FAILURE);
    entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  }

  /* free sent-but-not-completed packets */
  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    packet = xi->tx_pkts[i];
    if (packet != NULL)
      NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_FAILURE);
    gref = xi->tx_grefs[i];
    if (gref != 0)
      xi->XenInterface.GntTbl_EndAccess(
        xi->XenInterface.InterfaceHeader.Context, gref, TRUE);
  }
}

BOOLEAN
XenNet_TxInit(xennet_info_t *xi)
{
  USHORT i;

  xi->tx_mdl = AllocatePage();
  xi->tx_pgs = MmGetMdlVirtualAddress(xi->tx_mdl);
  SHARED_RING_INIT(xi->tx_pgs);
  FRONT_RING_INIT(&xi->tx, xi->tx_pgs, PAGE_SIZE);
  xi->tx_ring_ref = xi->XenInterface.GntTbl_GrantAccess(
    xi->XenInterface.InterfaceHeader.Context, 0,
    *MmGetMdlPfnArray(xi->tx_mdl), FALSE, 0);
  xi->tx_id_free = 0;
  xi->tx_no_id_free = 0;
  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    xi->tx_pkts[i] = NULL;
    put_id_on_freelist(xi, i);
  }
  xi->tx_gref_free = 0;
  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    xi->tx_grefs[i] = 0;
    put_gref_on_freelist(xi, xi->XenInterface.GntTbl_GetRef(
      xi->XenInterface.InterfaceHeader.Context));
  }
  return TRUE;
}

BOOLEAN
XenNet_TxShutdown(xennet_info_t *xi)
{
  ULONG i;

  XenNet_TxBufferFree(xi);

  /* free TX resources */
  if (xi->XenInterface.GntTbl_EndAccess(
    xi->XenInterface.InterfaceHeader.Context, xi->tx_ring_ref, 0))
  {
    xi->tx_ring_ref = GRANT_INVALID_REF;
    FreePages(xi->tx_mdl);
  }
  /* if EndAccess fails then tx/rx ring pages LEAKED -- it's not safe to reuse
     pages Dom0 still has access to */
  xi->tx_pgs = NULL;

  /* I think that NDIS takes care of this for us... */
  ASSERT(xi->tx_outstanding == 0);

  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    xi->XenInterface.GntTbl_PutRef(
      xi->XenInterface.InterfaceHeader.Context, xi->tx_gref_list[i]);
  }

  return TRUE;
}
