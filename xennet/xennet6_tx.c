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

#include "xennet6.h"

static USHORT
get_id_from_freelist(struct xennet_info *xi)
{
  ASSERT(xi->tx_id_free);
  xi->tx_id_free--;

  return xi->tx_id_list[xi->tx_id_free];
}

static VOID
put_id_on_freelist(struct xennet_info *xi, USHORT id)
{
  xi->tx_id_list[xi->tx_id_free] = id;
  xi->tx_id_free++;
}

#define SWAP_USHORT(x) (USHORT)((((x & 0xFF) << 8)|((x >> 8) & 0xFF)))

static __forceinline struct netif_tx_request *
XenNet_PutCbOnRing(struct xennet_info *xi, PVOID coalesce_buf, ULONG length, grant_ref_t gref)
{
  struct netif_tx_request *tx;
  tx = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
  xi->tx.req_prod_pvt++;
  xi->tx_ring_free--;
  tx->id = get_id_from_freelist(xi);
  ASSERT(xi->tx_shadows[tx->id].gref == INVALID_GRANT_REF);
  ASSERT(!xi->tx_shadows[tx->id].cb);
  xi->tx_shadows[tx->id].cb = coalesce_buf;
  tx->gref = xi->vectors.GntTbl_GrantAccess(xi->vectors.context, 0, (ULONG)(MmGetPhysicalAddress(coalesce_buf).QuadPart >> PAGE_SHIFT), FALSE, gref, (ULONG)'XNTX');
  xi->tx_shadows[tx->id].gref = tx->gref;
  tx->offset = 0;
  tx->size = (USHORT)length;
  ASSERT(tx->offset + tx->size <= PAGE_SIZE);
  ASSERT(tx->size);
  return tx;
}
  
/* Called at DISPATCH_LEVEL with tx_lock held */
/*
 * Send one NDIS_PACKET. This may involve multiple entries on TX ring.
 */
static BOOLEAN
XenNet_HWSendPacket(struct xennet_info *xi, PNET_BUFFER nb)
{
  struct netif_tx_request *tx0 = NULL;
  struct netif_tx_request *txN = NULL;
  struct netif_extra_info *ei = NULL;
  //PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;
  ULONG mss = 0;
  uint16_t flags = NETTXF_more_data;
  packet_info_t pi;
  BOOLEAN ndis_lso = FALSE;
  BOOLEAN xen_gso = FALSE;
  ULONG remaining;
  ULONG parse_result;
  ULONG frags = 0;
  BOOLEAN coalesce_required = FALSE;
  PVOID coalesce_buf;
  ULONG coalesce_remaining = 0;
  grant_ref_t gref;
  ULONG tx_length = 0;
  
  FUNCTION_ENTER();

  gref = xi->vectors.GntTbl_GetRef(xi->vectors.context, (ULONG)'XNTX');
  if (gref == INVALID_GRANT_REF)
  {
    KdPrint((__DRIVER_NAME "     out of grefs\n"));
    return FALSE;
  }
  coalesce_buf = NdisAllocateFromNPagedLookasideList(&xi->tx_lookaside_list);
  if (!coalesce_buf)
  {
    xi->vectors.GntTbl_PutRef(xi->vectors.context, gref, (ULONG)'XNTX');
    KdPrint((__DRIVER_NAME "     out of memory\n"));
    return FALSE;
  }
  XenNet_ClearPacketInfo(&pi);
  //NdisQueryPacket(packet, NULL, (PUINT)&pi.mdl_count, &pi.first_buffer, (PUINT)&pi.total_length);
  pi.first_mdl = pi.curr_mdl = nb->CurrentMdl;
  pi.first_mdl_offset = pi.curr_mdl_offset = nb->CurrentMdlOffset;
  pi.total_length = nb->DataLength;
//KdPrint((__DRIVER_NAME "     A first_mdl = %p\n", pi.first_mdl));
KdPrint((__DRIVER_NAME "     A total_length = %d\n", pi.total_length));
KdPrint((__DRIVER_NAME "     B curr_mdl_offset = %p\n", pi.curr_mdl_offset));
  remaining = min(pi.total_length, PAGE_SIZE);
KdPrint((__DRIVER_NAME "     C remaining = %d\n", remaining));
  while (remaining) /* this much gets put in the header */
  {
    ULONG length = XenNet_QueryData(&pi, remaining);
    remaining -= length;
KdPrint((__DRIVER_NAME "     D length = %d, remaining = %d\n", length, remaining));
    XenNet_EatData(&pi, length);
  }
  frags++;
KdPrint((__DRIVER_NAME "     Da\n"));
  if (pi.total_length > PAGE_SIZE) /* these are the frags we care about */
  {
    remaining = pi.total_length - PAGE_SIZE;
KdPrint((__DRIVER_NAME "     E remaining = %d\n", remaining));
    while (remaining)
    {
      ULONG length = XenNet_QueryData(&pi, PAGE_SIZE);
KdPrint((__DRIVER_NAME "     F length = %d\n", length));
      if (length != 0)
      {
        frags++;
        if (frags > LINUX_MAX_SG_ELEMENTS)
          break; /* worst case there could be hundreds of fragments - leave the loop now */
      }
KdPrint((__DRIVER_NAME "     G remaining = %d\n", remaining));
      remaining -= length;
      XenNet_EatData(&pi, length);
    }
  }
KdPrint((__DRIVER_NAME "     H remaining = %d, frags = %d, LINUX_MAX_SG_ELEMENTS = %d\n", remaining, frags, LINUX_MAX_SG_ELEMENTS));
  if (frags > LINUX_MAX_SG_ELEMENTS)
  {
    frags = LINUX_MAX_SG_ELEMENTS;
    coalesce_required = TRUE;
  }

  /* if we have enough space on the ring then we have enough id's so no need to check for that */
  if (xi->tx_ring_free < frags + 1)
  {
    xi->vectors.GntTbl_PutRef(xi->vectors.context, gref, (ULONG)'XNTX');
    NdisFreeToNPagedLookasideList(&xi->tx_lookaside_list, coalesce_buf);
    KdPrint((__DRIVER_NAME "     Full on send - ring full\n"));
    return FALSE;
  }
  parse_result = XenNet_ParsePacketHeader(&pi, coalesce_buf, PAGE_SIZE);
KdPrint((__DRIVER_NAME "     I parse_result = %d\n", parse_result));
  remaining = pi.total_length - pi.header_length;
KdPrint((__DRIVER_NAME "     J total_length = %d, header_length = %d, remaining = %d\n", pi.total_length, pi.header_length, remaining));

#if 0
  if (NDIS_GET_PACKET_PROTOCOL_TYPE(packet) == NDIS_PROTOCOL_ID_TCP_IP)
  {
    csum_info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)&NDIS_PER_PACKET_INFO_FROM_PACKET(
      packet, TcpIpChecksumPacketInfo);
    if (csum_info->Transmit.NdisPacketChecksumV4)
    {
      if (csum_info->Transmit.NdisPacketIpChecksum && !xi->setting_csum.V4Transmit.IpChecksum)
      {
        KdPrint((__DRIVER_NAME "     IpChecksum not enabled\n"));
        //NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_FAILURE);
        //return TRUE;
      }
      if (csum_info->Transmit.NdisPacketTcpChecksum)
      {
        if (xi->setting_csum.V4Transmit.TcpChecksum)
        {
          flags |= NETTXF_csum_blank | NETTXF_data_validated;
        }
        else
        {
          KdPrint((__DRIVER_NAME "     TcpChecksum not enabled\n"));
          //NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_FAILURE);
          //return TRUE;
        }
      }
      else if (csum_info->Transmit.NdisPacketUdpChecksum)
      {
        if (xi->setting_csum.V4Transmit.UdpChecksum)
        {
          flags |= NETTXF_csum_blank | NETTXF_data_validated;
        }
        else
        {
          KdPrint((__DRIVER_NAME "     UdpChecksum not enabled\n"));
          //NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_FAILURE);
          //return TRUE;
        }
      }
    }
    else if (csum_info->Transmit.NdisPacketChecksumV6)
    {
      KdPrint((__DRIVER_NAME "     NdisPacketChecksumV6 not supported\n"));
      //NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_FAILURE);
      //return TRUE;
    }
  }
  
  mss = PtrToUlong(NDIS_PER_PACKET_INFO_FROM_PACKET(packet, TcpLargeSendPacketInfo));

  if (mss && parse_result == PARSE_OK)
  {
    if (NDIS_GET_PACKET_PROTOCOL_TYPE(packet) != NDIS_PROTOCOL_ID_TCP_IP)
    {
      KdPrint((__DRIVER_NAME "     mss specified when packet is not NDIS_PROTOCOL_ID_TCP_IP\n"));
    }
    ndis_lso = TRUE;
    if (mss > xi->setting_max_offload)
    {
      KdPrint((__DRIVER_NAME "     Requested MSS (%d) larger than allowed MSS (%d)\n", mss, xi->setting_max_offload));
      //NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_FAILURE);
      //FUNCTION_EXIT();
      return TRUE;
    }
  }

  if (ndis_lso)
  {    
    flags |= NETTXF_csum_blank | NETTXF_data_validated; /* these may be implied but not specified when lso is used*/
    if (pi.tcp_length >= mss)
    {
      flags |= NETTXF_extra_info;
      xen_gso = TRUE;
    }
    else
    {
      KdPrint((__DRIVER_NAME "     large send specified when tcp_length < mss\n"));
    }
  }
#endif
/*
* See io/netif.h. Must put (A) 1st request, then (B) optional extra_info, then
* (C) rest of requests on the ring. Only (A) has csum flags.
*/

  /* (A) */
  KdPrint((__DRIVER_NAME "     AA\n"));
  KdPrint((__DRIVER_NAME "     AA XenNet_PutCbOnRing %d\n", min(PAGE_SIZE, remaining)));
  tx0 = XenNet_PutCbOnRing(xi, coalesce_buf, pi.header_length, gref);
  ASSERT(tx0); /* this will never happen */
  tx0->flags = flags;
  tx_length += pi.header_length;

  /* even though we haven't reported that we are capable of it, LSO demands that we calculate the IP Header checksum */
  if (ndis_lso)
  {
    XenNet_SumIpHeader(coalesce_buf, pi.ip4_header_length);
  }
  txN = tx0;

  /* (B) */
  KdPrint((__DRIVER_NAME "     BB\n"));
  if (xen_gso)
  {
    ASSERT(flags & NETTXF_extra_info);
    ei = (struct netif_extra_info *)RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
    //KdPrint((__DRIVER_NAME "     pos = %d\n", xi->tx.req_prod_pvt));
    xi->tx.req_prod_pvt++;
    xi->tx_ring_free--;
    ei->type = XEN_NETIF_EXTRA_TYPE_GSO;
    ei->flags = 0;
    ei->u.gso.size = (USHORT)mss;
    ei->u.gso.type = XEN_NETIF_GSO_TYPE_TCPV4;
    ei->u.gso.pad = 0;
    ei->u.gso.features = 0;
  }

  ASSERT(xi->config_sg || !remaining);
  
  /* (C) - only if data is remaining */
  KdPrint((__DRIVER_NAME "     CC\n"));
  coalesce_buf = NULL;
  while (remaining > 0)
  {
    ULONG length;
    PFN_NUMBER pfn;
    
    ASSERT(pi.curr_mdl);
    if (coalesce_required)
    {
      PVOID va;
      if (!coalesce_buf)
      {
        gref = xi->vectors.GntTbl_GetRef(xi->vectors.context, (ULONG)'XNTX');
        if (gref == INVALID_GRANT_REF)
        {
          KdPrint((__DRIVER_NAME "     out of grefs - partial send\n"));
          break;
        }
        coalesce_buf = NdisAllocateFromNPagedLookasideList(&xi->tx_lookaside_list);
        if (!coalesce_buf)
        {
          xi->vectors.GntTbl_PutRef(xi->vectors.context, gref, (ULONG)'XNTX');
          KdPrint((__DRIVER_NAME "     out of memory - partial send\n"));
          break;
        }
        coalesce_remaining = min(PAGE_SIZE, remaining);
      }
      length = XenNet_QueryData(&pi, coalesce_remaining);
      va = NdisBufferVirtualAddressSafe(pi.curr_mdl, LowPagePriority);
      if (!va)
      {
        KdPrint((__DRIVER_NAME "     failed to map buffer va - partial send\n"));
        coalesce_remaining = 0;
        remaining -= min(PAGE_SIZE, remaining);
        NdisFreeToNPagedLookasideList(&xi->tx_lookaside_list, coalesce_buf);
      }
      else
      {
        memcpy((PUCHAR)coalesce_buf + min(PAGE_SIZE, remaining) - coalesce_remaining, (PUCHAR)va + pi.curr_mdl_offset, length);
        coalesce_remaining -= length;
      }
    }
    else
    {
      length = XenNet_QueryData(&pi, PAGE_SIZE);
    }
    if (!length || coalesce_remaining) /* sometimes there are zero length buffers... */
    {
      XenNet_EatData(&pi, length); /* do this so we actually move to the next buffer */
      continue;
    }

    if (coalesce_buf)
    {
      if (remaining)
      {
        KdPrint((__DRIVER_NAME "     CC XenNet_PutCbOnRing %d\n", min(PAGE_SIZE, remaining)));
        txN = XenNet_PutCbOnRing(xi, coalesce_buf, min(PAGE_SIZE, remaining), gref);
        ASSERT(txN);
        coalesce_buf = NULL;
        remaining -= min(PAGE_SIZE, remaining);
        tx_length += min(PAGE_SIZE, remaining);
      }
    }
    else
    {
      ULONG offset;
      
      gref = xi->vectors.GntTbl_GetRef(xi->vectors.context, (ULONG)'XNTX');
      if (gref == INVALID_GRANT_REF)
      {
        KdPrint((__DRIVER_NAME "     out of grefs - partial send\n"));
        break;
      }
      txN = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
      xi->tx.req_prod_pvt++;
      xi->tx_ring_free--;
      txN->id = get_id_from_freelist(xi);
      ASSERT(!xi->tx_shadows[txN->id].cb);
      offset = MmGetMdlByteOffset(pi.curr_mdl) + pi.curr_mdl_offset;
      pfn = MmGetMdlPfnArray(pi.curr_mdl)[offset >> PAGE_SHIFT];
      txN->offset = (USHORT)offset & (PAGE_SIZE - 1);
      txN->gref = xi->vectors.GntTbl_GrantAccess(xi->vectors.context, 0, (ULONG)pfn, FALSE, gref, (ULONG)'XNTX');
      ASSERT(xi->tx_shadows[txN->id].gref == INVALID_GRANT_REF);
      xi->tx_shadows[txN->id].gref = txN->gref;
      //ASSERT(sg->Elements[sg_element].Length > sg_offset);
      txN->size = (USHORT)length;
      ASSERT(txN->offset + txN->size <= PAGE_SIZE);
      ASSERT(txN->size);
      ASSERT(txN->gref != INVALID_GRANT_REF);
      remaining -= length;
      tx_length += length;
    }
    tx0->size = tx0->size + txN->size;
    txN->flags = NETTXF_more_data;
    XenNet_EatData(&pi, length);
  }
  txN->flags &= ~NETTXF_more_data;
  ASSERT(tx0->size == pi.total_length);
  ASSERT(!xi->tx_shadows[txN->id].nb);
  xi->tx_shadows[txN->id].nb = nb;

#if 0
  if (ndis_lso)
  {
    //KdPrint((__DRIVER_NAME "     TcpLargeSendPacketInfo = %d\n", pi.tcp_length));
    NDIS_PER_PACKET_INFO_FROM_PACKET(packet, TcpLargeSendPacketInfo) = UlongToPtr(tx_length - MAX_ETH_HEADER_LENGTH - pi.ip4_header_length - pi.tcp_header_length);
  }
#endif

  xi->stat_tx_ok++;

  //NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
  //FUNCTION_EXIT();
  xi->tx_outstanding++;
  return TRUE;
}

/* Called at DISPATCH_LEVEL with tx_lock held */
static VOID
XenNet_SendQueuedPackets(struct xennet_info *xi)
{
  PLIST_ENTRY nb_entry;
  PNET_BUFFER nb;
  int notify;

  //FUNCTION_ENTER();

  if (xi->device_state->suspend_resume_state_pdo != SR_STATE_RUNNING)
    return;

  nb_entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  /* if empty, the above returns head*, not NULL */
  while (nb_entry != &xi->tx_waiting_pkt_list)
  {
    nb = CONTAINING_RECORD(nb_entry, NET_BUFFER, NB_LIST_ENTRY_FIELD);
    KdPrint((__DRIVER_NAME "     sending %p from %p\n", nb, NB_NBL(nb)));
    
    if (!XenNet_HWSendPacket(xi, nb))
    {
      KdPrint((__DRIVER_NAME "     No room for packet\n"));
      InsertHeadList(&xi->tx_waiting_pkt_list, nb_entry);
      break;
    }
    nb_entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  }

  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xi->tx, notify);
  if (notify)
  {
    xi->vectors.EvtChn_Notify(xi->vectors.context, xi->event_channel);
  }
  //FUNCTION_EXIT();
}

// Called at DISPATCH_LEVEL
VOID
XenNet_TxBufferGC(struct xennet_info *xi, BOOLEAN dont_set_event)
{
  RING_IDX cons, prod;
  LIST_ENTRY nb_head;
  PLIST_ENTRY nb_entry;
  PNET_BUFFER nb;
  ULONG tx_packets = 0;

  FUNCTION_ENTER();

  if (!xi->connected)
    return; /* a delayed DPC could let this come through... just do nothing */
  ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

  KeAcquireSpinLockAtDpcLevel(&xi->tx_lock);

  InitializeListHead(&nb_head);
  if (xi->tx_shutting_down && !xi->tx_outstanding)
  {
    /* there is a chance that our Dpc had been queued just before the shutdown... */
    KeSetEvent(&xi->tx_idle_event, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);
    return;
  }

  do {
    prod = xi->tx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'rsp_prod'. */

    for (cons = xi->tx.rsp_cons; cons != prod; cons++)
    {
      struct netif_tx_response *txrsp;
      tx_shadow_t *shadow;
      
      txrsp = RING_GET_RESPONSE(&xi->tx, cons);
      
      xi->tx_ring_free++;
      
      if (txrsp->status == NETIF_RSP_NULL)
      {
        continue;
      }

      shadow = &xi->tx_shadows[txrsp->id];
      if (shadow->cb)
      {
        NdisFreeToNPagedLookasideList(&xi->tx_lookaside_list, shadow->cb);
        shadow->cb = NULL;
      }
      
      if (shadow->gref != INVALID_GRANT_REF)
      {
        xi->vectors.GntTbl_EndAccess(xi->vectors.context,
          shadow->gref, FALSE, (ULONG)'XNTX');
        shadow->gref = INVALID_GRANT_REF;
      }
      
      if (shadow->nb)
      {
        PLIST_ENTRY nb_entry;
        KdPrint((__DRIVER_NAME "     nb %p complete\n"));
        nb = shadow->nb;
        nb_entry = &NB_LIST_ENTRY(nb);
        InsertTailList(&nb_head, nb_entry);
        shadow->nb = NULL;
      }
      put_id_on_freelist(xi, txrsp->id);
    }

    xi->tx.rsp_cons = prod;
    /* resist the temptation to set the event more than +1... it breaks things */
    /* although I think we could set it to higher if we knew there were more outstanding packets coming soon... */
    if (!dont_set_event)
      xi->tx.sring->rsp_event = prod + 1;
    KeMemoryBarrier();
  } while (prod != xi->tx.sring->rsp_prod);

  /* if queued packets, send them now */
  if (!xi->tx_shutting_down)
    XenNet_SendQueuedPackets(xi);

  KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);

  /* must be done without holding any locks */
  nb_entry = RemoveHeadList(&nb_head);
  /* if empty, the above returns head*, not NULL */
  while (nb_entry != &nb_head)
  {
    PNET_BUFFER_LIST nbl;
    nb = CONTAINING_RECORD(nb_entry, NET_BUFFER, NB_LIST_ENTRY_FIELD);
    nbl = NB_NBL(nb);
    NBL_REF(nbl)--;
    KdPrint((__DRIVER_NAME "     nb %p from %p complete, refcount = %d\n", nb, nbl, NBL_REF(nbl)));
    if (!NBL_REF(nbl))
    {
      nbl->Status = NDIS_STATUS_SUCCESS;
      NdisMSendNetBufferListsComplete(xi->adapter_handle, nbl, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
      KdPrint((__DRIVER_NAME "     NdisMSendNetBufferListsComplete\n"));
    }
    tx_packets++;
    nb_entry = RemoveHeadList(&nb_head);
  }

  /* must be done after we have truly given back all packets */
  KeAcquireSpinLockAtDpcLevel(&xi->tx_lock);
  xi->tx_outstanding -= tx_packets;
  if (!xi->tx_outstanding && xi->tx_shutting_down)
    KeSetEvent(&xi->tx_idle_event, IO_NO_INCREMENT, FALSE);
  KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);

  if (xi->device_state->suspend_resume_state_pdo == SR_STATE_SUSPENDING
    && xi->device_state->suspend_resume_state_fdo != SR_STATE_SUSPENDING
    && xi->tx_id_free == NET_TX_RING_SIZE)
  {
    KdPrint((__DRIVER_NAME "     Setting SR_STATE_SUSPENDING\n"));
    xi->device_state->suspend_resume_state_fdo = SR_STATE_SUSPENDING;
    KdPrint((__DRIVER_NAME "     Notifying event channel %d\n", xi->device_state->pdo_event_channel));
    xi->vectors.EvtChn_Notify(xi->vectors.context, xi->device_state->pdo_event_channel);
  }

  FUNCTION_EXIT();
}

// called at <= DISPATCH_LEVEL
VOID
XenNet_SendNetBufferLists(
  NDIS_HANDLE adapter_context,
  PNET_BUFFER_LIST nb_lists,
  NDIS_PORT_NUMBER port_number,
  ULONG send_flags)
{
  struct xennet_info *xi = adapter_context;
  PLIST_ENTRY nb_entry;
  KIRQL old_irql;
  PNET_BUFFER_LIST curr_nbl;

  UNREFERENCED_PARAMETER(port_number);
  FUNCTION_ENTER();

  if (xi->inactive)
  {
    curr_nbl = nb_lists;
    while(curr_nbl)
    {
      PNET_BUFFER_LIST next_nbl = NET_BUFFER_LIST_NEXT_NBL(curr_nbl);
      NET_BUFFER_LIST_NEXT_NBL(curr_nbl) = NULL;
      KdPrint((__DRIVER_NAME "     NBL %p\n", curr_nbl));
      curr_nbl->Status = NDIS_STATUS_FAILURE;
      NdisMSendNetBufferListsComplete(xi->adapter_handle, curr_nbl, (send_flags & NDIS_SEND_FLAGS_DISPATCH_LEVEL)?NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL:0);
      curr_nbl = next_nbl;
    }
  }

  KeAcquireSpinLock(&xi->tx_lock, &old_irql);
  
  for (curr_nbl = nb_lists; curr_nbl; curr_nbl = NET_BUFFER_LIST_NEXT_NBL(curr_nbl))
  {
    PNET_BUFFER curr_nb;
    NBL_REF(curr_nbl) = 0;
    for (curr_nb = NET_BUFFER_LIST_FIRST_NB(curr_nbl); curr_nb; curr_nb = NET_BUFFER_NEXT_NB(curr_nb))
    {
      NB_NBL(curr_nb) = curr_nbl;
      nb_entry = &NB_LIST_ENTRY(curr_nb);
      InsertTailList(&xi->tx_waiting_pkt_list, nb_entry);
      NBL_REF(curr_nbl)++;
    }
  }

  XenNet_SendQueuedPackets(xi);

  KeReleaseSpinLock(&xi->tx_lock, old_irql);
  
  FUNCTION_EXIT();
}

VOID
XenNet_CancelSend(NDIS_HANDLE adapter_context, PVOID cancel_id)
{
  UNREFERENCED_PARAMETER(adapter_context);
  UNREFERENCED_PARAMETER(cancel_id);
  FUNCTION_ENTER();
#if 0
  struct xennet_info *xi = MiniportAdapterContext;
  KIRQL old_irql;
  PLIST_ENTRY nb_entry;
  PNDIS_PACKET packet;
  PNDIS_PACKET head = NULL, tail = NULL;
  BOOLEAN result;
#endif
  FUNCTION_ENTER();
  
#if 0
  KeAcquireSpinLock(&xi->tx_lock, &old_irql);

  nb_entry = xi->tx_waiting_pkt_list.Flink;
  while (nb_entry != &xi->tx_waiting_pkt_list)
  {
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    entry = entry->Flink;
    if (NDIS_GET_PACKET_CANCEL_ID(packet) == CancelId)
    {
      KdPrint((__DRIVER_NAME "     Found packet to cancel %p\n", packet));
      result = RemoveEntryList((PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)]);
      ASSERT(result);
      *(PNDIS_PACKET *)&packet->MiniportReservedEx[0] = NULL;
      if (head)
        *(PNDIS_PACKET *)&tail->MiniportReservedEx[0] = packet;
      else
        head = packet;
      tail = packet;
    }
  }

  KeReleaseSpinLock(&xi->tx_lock, old_irql);

  while (head)
  {
    packet = (PNDIS_PACKET)head;
    head = *(PNDIS_PACKET *)&packet->MiniportReservedEx[0];
    KdPrint((__DRIVER_NAME "     NdisMSendComplete(%p)\n", packet));
    NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_REQUEST_ABORTED);
  }
#endif
  
  FUNCTION_EXIT();
}

VOID
XenNet_TxResumeStart(xennet_info_t *xi)
{
  UNREFERENCED_PARAMETER(xi);

  FUNCTION_ENTER();
  /* nothing to do here - all packets were already sent */
  FUNCTION_EXIT();
}

VOID
XenNet_TxResumeEnd(xennet_info_t *xi)
{
  KIRQL old_irql;

  FUNCTION_ENTER();

  UNREFERENCED_PARAMETER(xi);

  KeAcquireSpinLock(&xi->tx_lock, &old_irql);
  //XenNet_SendQueuedPackets(xi);
  KeReleaseSpinLock(&xi->tx_lock, old_irql);

  FUNCTION_EXIT();
}

BOOLEAN
XenNet_TxInit(xennet_info_t *xi)
{
  USHORT i;
  UNREFERENCED_PARAMETER(xi);
  
  KeInitializeSpinLock(&xi->tx_lock);
  InitializeListHead(&xi->tx_waiting_pkt_list);

  KeInitializeEvent(&xi->tx_idle_event, SynchronizationEvent, FALSE);
  xi->tx_shutting_down = FALSE;
  xi->tx_outstanding = 0;
  xi->tx_ring_free = NET_TX_RING_SIZE;
  
  NdisInitializeNPagedLookasideList(&xi->tx_lookaside_list, NULL, NULL, 0,
    PAGE_SIZE, XENNET_POOL_TAG, 0);

  xi->tx_id_free = 0;
  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    xi->tx_shadows[i].gref = INVALID_GRANT_REF;
    xi->tx_shadows[i].cb = NULL;
    put_id_on_freelist(xi, i);
  }

  return TRUE;
}

/*
The ring is completely closed down now. We just need to empty anything left
on our freelists and harvest anything left on the rings.
*/

BOOLEAN
XenNet_TxShutdown(xennet_info_t *xi)
{
  //PLIST_ENTRY entry;
  //PNDIS_PACKET packet;
  ////PMDL mdl;
  ////ULONG i;
  //KIRQL OldIrql;
  UNREFERENCED_PARAMETER(xi);

  FUNCTION_ENTER();

#if 0
  KeAcquireSpinLock(&xi->tx_lock, &OldIrql);
  xi->tx_shutting_down = TRUE;
  KeReleaseSpinLock(&xi->tx_lock, OldIrql);

  while (xi->tx_outstanding)
  {
    KdPrint((__DRIVER_NAME "     Waiting for %d remaining packets to be sent\n", xi->tx_outstanding));
    KeWaitForSingleObject(&xi->tx_idle_event, Executive, KernelMode, FALSE, NULL);
  }

#if (NTDDI_VERSION >= NTDDI_WINXP)
  KeFlushQueuedDpcs();
#endif

  /* Free packets in tx queue */
  nb_entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  while (nb_entry != &xi->tx_waiting_pkt_list)
  {
    packet = CONTAINING_RECORD(nb_entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_FAILURE);
    nb_entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  }

  NdisDeleteNPagedLookasideList(&xi->tx_lookaside_list);
#endif

  FUNCTION_EXIT();

  return TRUE;
}