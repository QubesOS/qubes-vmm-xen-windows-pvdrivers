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
  return xi->tx_id_free - xi->tx_no_id_used;
}

static USHORT
get_id_from_freelist(struct xennet_info *xi)
{
  if (xi->tx_id_free - xi->tx_no_id_used == 0)
  {
    KdPrint((__DRIVER_NAME "     Out of id's\n"));    
    return FREELIST_ID_ERROR;
  }
  xi->tx_id_free--;

  return xi->tx_id_list[xi->tx_id_free];
}

static USHORT
get_no_id_from_freelist(struct xennet_info *xi)
{
  if (xi->tx_id_free - xi->tx_no_id_used == 0)
  {
    KdPrint((__DRIVER_NAME "     Out of no_id's\n"));    
    return FREELIST_ID_ERROR;
  }
  xi->tx_no_id_used++;
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
  xi->tx_no_id_used--;
}
#define SWAP_USHORT(x) (USHORT)((((x & 0xFF) << 8)|((x >> 8) & 0xFF)))

/* Place a buffer on tx ring. */
static struct netif_tx_request*
XenNet_PutOnTxRing(
  struct xennet_info *xi,
  PMDL mdl,
  uint16_t flags)
{
  struct netif_tx_request *tx;

  unsigned short id;

  id = get_id_from_freelist(xi);
  ASSERT(id != FREELIST_ID_ERROR);
  ASSERT(xi->tx_pkts[id] == NULL);
  tx = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
  tx->gref = get_grant_ref(mdl);
  xi->tx_mdls[id] = mdl;
  tx->id = id;
  tx->offset = 0;
  tx->size = (USHORT)MmGetMdlByteCount(mdl);
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
  struct netif_extra_info *ei = NULL;
  PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;
  UINT total_packet_length;
  ULONG mss;
  PMDL in_mdl;
  PUCHAR in_buffer = NULL;
  PUCHAR out_buffer;
  USHORT in_remaining;
  USHORT out_remaining;
  uint16_t flags = NETTXF_more_data;
  packet_info_t pi;
  BOOLEAN ndis_lso = FALSE;
  BOOLEAN xen_gso = FALSE;
  int pages_required;
  int page_num;
  USHORT copied;
  
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;

  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  RtlZeroMemory(&pi, sizeof(pi));

  csum_info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)&NDIS_PER_PACKET_INFO_FROM_PACKET(
    packet, TcpIpChecksumPacketInfo);
  mss = PtrToUlong(NDIS_PER_PACKET_INFO_FROM_PACKET(packet, TcpLargeSendPacketInfo));

  if (mss)
    ndis_lso = TRUE;

  NdisQueryPacket(packet, NULL, NULL, &in_mdl, &total_packet_length);

  pages_required = (total_packet_length + PAGE_SIZE - 1) / PAGE_SIZE;

  if (pages_required + !!ndis_lso > (int)free_requests(xi))
  {
    KdPrint((__DRIVER_NAME "     Full on send - required = %d, available = %d\n", pages_required + !!ndis_lso, (int)free_requests(xi)));
    return FALSE;
  }

  for (page_num = 0, in_remaining = 0; page_num < pages_required; page_num++)
  {
    pi.mdls[page_num] = XenFreelist_GetPage(&xi->tx_freelist);
    out_buffer = MmGetMdlVirtualAddress(pi.mdls[page_num]);
    out_remaining = (USHORT)min(PAGE_SIZE, total_packet_length - page_num * PAGE_SIZE);
    NdisAdjustBufferLength(pi.mdls[page_num], out_remaining);
    while (out_remaining > 0)
    {
      if (!in_remaining)
      {
        ASSERT(in_mdl);
        in_buffer = MmGetSystemAddressForMdlSafe(in_mdl, LowPagePriority);
        ASSERT(in_buffer != NULL);
        in_remaining = (USHORT)MmGetMdlByteCount(in_mdl);
      }
      copied = min(in_remaining, out_remaining);
      memcpy(out_buffer, in_buffer, copied);
      in_remaining = in_remaining - copied;
      in_buffer += copied;
      out_remaining = out_remaining - copied;
      out_buffer += copied;
      if (!in_remaining)
        in_mdl = in_mdl->Next;
    }
  }
  ASSERT(!in_mdl);

  if (csum_info->Transmit.NdisPacketTcpChecksum
    || csum_info->Transmit.NdisPacketUdpChecksum)
  {
    flags |= NETTXF_csum_blank | NETTXF_data_validated;
    PC_INC(ProfCount_TxPacketsCsumOffload);
  }

  if (ndis_lso)
  {
    XenNet_ParsePacketHeader(&pi);
    XenNet_SumIpHeader(MmGetSystemAddressForMdlSafe(pi.mdls[0], NormalPagePriority), pi.ip4_header_length);
    flags |= NETTXF_csum_blank | NETTXF_data_validated; /* these may be implied but not specified when lso is used*/
    if (pi.tcp_length >= mss)
    {
      flags |= NETTXF_extra_info;
      xen_gso = TRUE;
    }
  }

  /*
   * See io/netif.h. Must put (A) 1st request, then (B) optional extra_info, then
   * (C) rest of requests on the ring. Only (A) has csum flags.
   */

  /* (A) */
  tx = XenNet_PutOnTxRing(xi, pi.mdls[0], flags);
  tx->size = (USHORT)total_packet_length;
  xi->tx.req_prod_pvt++;

  /* (B) */
  if (xen_gso)
  {
    ASSERT(flags & NETTXF_extra_info);
    get_no_id_from_freelist(xi);
    ei = (struct netif_extra_info *)RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
    ei->type = XEN_NETIF_EXTRA_TYPE_GSO;
    ei->flags = 0;
    ei->u.gso.size = (USHORT)mss;
    ei->u.gso.type = XEN_NETIF_GSO_TYPE_TCPV4;
    ei->u.gso.pad = 0;
    ei->u.gso.features = 0;

    xi->tx.req_prod_pvt++;
  }

  /* (C) */
  for (page_num = 1; page_num < pages_required; page_num++)
  {
    tx = XenNet_PutOnTxRing(xi, pi.mdls[page_num], NETTXF_more_data);
    xi->tx.req_prod_pvt++;
  }

  /* only set the packet on the last buffer, clear more_data */
  xi->tx_pkts[tx->id] = packet;
  tx->flags &= ~NETTXF_more_data;

  if (ndis_lso)
  {
    NDIS_PER_PACKET_INFO_FROM_PACKET(packet, TcpLargeSendPacketInfo) = UlongToPtr(pi.tcp_length);
  }

  return TRUE;
}

/* Called at DISPATCH_LEVEL with tx_lock held */

static VOID
XenNet_SendQueuedPackets(struct xennet_info *xi)
{
  PLIST_ENTRY entry;
  PNDIS_PACKET packet;
  int notify;
  BOOLEAN success;

  entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  /* if empty, the above returns head*, not NULL */
  while (entry != &xi->tx_waiting_pkt_list)
  {
    //KdPrint((__DRIVER_NAME "     Packet ready to send\n"));
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    success = XenNet_HWSendPacket(xi, packet);
    if (!success)
    {
      InsertHeadList(&xi->tx_waiting_pkt_list, entry);
      break;
    }
    entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  }

  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xi->tx, notify);
  if (notify)
  {
    xi->vectors.EvtChn_Notify(xi->vectors.context, xi->event_channel);
  }
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

  ASSERT(xi->connected);
  ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));


  KeAcquireSpinLockAtDpcLevel(&xi->tx_lock);

  do {
    prod = xi->tx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'rsp_prod'. */

    for (cons = xi->tx.rsp_cons; cons != prod; cons++)
    {
      struct netif_tx_response *txrsp;

      txrsp = RING_GET_RESPONSE(&xi->tx, cons);
      if (txrsp->status == NETIF_RSP_NULL)
      {
//        KdPrint((__DRIVER_NAME "     NETIF_RSP_NULL\n"));
        put_no_id_on_freelist(xi);
        continue; // This would be the response to an extra_info packet
      }

      id = txrsp->id;
 
      packets[packet_count] = xi->tx_pkts[id];
      if (packets[packet_count])
      {
        xi->tx_pkts[id] = NULL;
        packet_count++;
        xi->stat_tx_ok++;
      }
      if (xi->tx_mdls[id])
      {
        NdisAdjustBufferLength(xi->tx_mdls[id], PAGE_SIZE);
        XenFreelist_PutPage(&xi->tx_freelist, xi->tx_mdls[id]);
        xi->tx_mdls[id] = NULL;
      }
      put_id_on_freelist(xi, id);
    }

    xi->tx.rsp_cons = prod;

    RING_FINAL_CHECK_FOR_RESPONSES(&xi->tx, moretodo);
  } while (moretodo);

  /* if queued packets, send them now */
  XenNet_SendQueuedPackets(xi);

  KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);

//  if (packet_count)
//    KdPrint((__DRIVER_NAME " --- " __FUNCTION__ " %d packets completed\n"));
  for (i = 0; i < packet_count; i++)
  {
    /* A miniport driver must release any spin lock that it is holding before
       calling NdisMSendComplete. */
    NdisMSendComplete(xi->adapter_handle, packets[i], NDIS_STATUS_SUCCESS);
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NDIS_STATUS_SUCCESS;
}

// called at <= DISPATCH_LEVEL
VOID DDKAPI
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

  KeAcquireSpinLock(&xi->tx_lock, &OldIrql);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ " (packets = %d, free_requests = %d)\n", NumberOfPackets, free_requests(xi)));
  for (i = 0; i < NumberOfPackets; i++)
  {
    packet = PacketArray[i];
    ASSERT(packet);
    *(ULONG *)&packet->MiniportReservedEx = 0;
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(&xi->tx_waiting_pkt_list, entry);
  }

  if (xi->device_state->resume_state == RESUME_STATE_RUNNING)
    XenNet_SendQueuedPackets(xi);

  KeReleaseSpinLock(&xi->tx_lock, OldIrql);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

VOID
XenNet_TxResumeStart(xennet_info_t *xi)
{
  int i;
  KIRQL old_irql;
  PLIST_ENTRY entry;

  KeAcquireSpinLock(&xi->tx_lock, &old_irql);
  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    if (xi->tx_mdls[i])
    {
      XenFreelist_PutPage(&xi->tx_freelist, xi->tx_mdls[i]);
      xi->tx_mdls[i] = NULL;
    }
    /* this may result in packets being sent out of order... I don't think it matters though */
    if (xi->tx_pkts[i])
    {
      *(ULONG *)&xi->tx_pkts[i]->MiniportReservedEx = 0;
      entry = (PLIST_ENTRY)&xi->tx_pkts[i]->MiniportReservedEx[sizeof(PVOID)];
      InsertTailList(&xi->tx_waiting_pkt_list, entry);
      xi->tx_pkts[i] = 0;
    }
  }
  XenFreelist_ResumeStart(&xi->tx_freelist);
  xi->tx_id_free = 0;
  xi->tx_no_id_used = 0;
  for (i = 0; i < NET_TX_RING_SIZE; i++)
    put_id_on_freelist(xi, (USHORT)i);
  KeReleaseSpinLock(&xi->tx_lock, old_irql);
}

VOID
XenNet_TxResumeEnd(xennet_info_t *xi)
{
  KIRQL old_irql;

  KeAcquireSpinLock(&xi->tx_lock, &old_irql);
  XenFreelist_ResumeEnd(&xi->tx_freelist);
  XenNet_SendQueuedPackets(xi);
  KeReleaseSpinLock(&xi->tx_lock, old_irql);
}

BOOLEAN
XenNet_TxInit(xennet_info_t *xi)
{
  USHORT i;

  KeInitializeSpinLock(&xi->tx_lock);

  xi->tx_id_free = 0;
  xi->tx_no_id_used = 0;
  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    put_id_on_freelist(xi, i);
  }

  XenFreelist_Init(xi, &xi->tx_freelist, &xi->tx_lock);

  return TRUE;
}

/*
The ring is completely closed down now. We just need to empty anything left
on our freelists and harvest anything left on the rings. The freelist timer
will still be running though.
*/

BOOLEAN
XenNet_TxShutdown(xennet_info_t *xi)
{
  PLIST_ENTRY entry;
  PNDIS_PACKET packet;
  PMDL mdl;
  ULONG i;
  KIRQL OldIrql;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(!xi->connected);

  KeAcquireSpinLock(&xi->tx_lock, &OldIrql);

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
    if (packet)
      NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_FAILURE);
    mdl = xi->tx_mdls[i];
    if (mdl)
      XenFreelist_PutPage(&xi->tx_freelist, xi->tx_mdls[i]);
  }

  XenFreelist_Dispose(&xi->tx_freelist);

  KeReleaseSpinLock(&xi->tx_lock, OldIrql);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}
