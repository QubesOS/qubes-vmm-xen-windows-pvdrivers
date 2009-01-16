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
  //ASSERT(xi->tx_pkts[id] == NULL);
  tx = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
  tx->gref = get_grant_ref(mdl);
  xi->tx_mdls[id] = mdl;
  tx->id = id;
  tx->offset = 0;
  tx->size = (USHORT)MmGetMdlByteCount(mdl);
  tx->flags = flags;

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
  //UINT total_packet_length;
  ULONG mss = 0;
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
  UINT first_buffer_length; /* not used */
  UINT total_length;
  
  XenNet_ClearPacketInfo(&pi);
  NdisGetFirstBufferFromPacketSafe(packet, &in_mdl, &pi.header, &first_buffer_length, &total_length, NormalPagePriority);
  
  if (!pi.header)
  {
    KdPrint((__DRIVER_NAME "     NdisGetFirstBufferFromPacketSafe failed\n"));
    return FALSE;
  }

  if (!total_length)
  {
    KdPrint((__DRIVER_NAME "     Zero length packet\n"));
    return TRUE; // we don't want to see this packet again...
  }  

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

  if (mss)
  {
    if (NDIS_GET_PACKET_PROTOCOL_TYPE(packet) != NDIS_PROTOCOL_ID_TCP_IP)
    {
      KdPrint((__DRIVER_NAME "     mss specified when packet is not NDIS_PROTOCOL_ID_TCP_IP\n"));
    }
    ndis_lso = TRUE;
    if (mss > xi->setting_max_offload)
    {
      KdPrint((__DRIVER_NAME "     Requested MSS (%d) larger than allowed MSS (%d)\n", mss, xi->setting_max_offload));
      NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_FAILURE);
      return TRUE;
    }
  }

  if (!mss && total_length > xi->config_mtu + XN_HDR_SIZE)
  {
    KdPrint((__DRIVER_NAME "     Packet size (%d) larger than MTU (%d) + header (%d). mss = %d\n", total_length, xi->config_mtu, XN_HDR_SIZE, mss));
    NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_FAILURE);
    return TRUE;
  }
  pages_required = (total_length + PAGE_SIZE - 1) / PAGE_SIZE;

  if (pages_required + !!ndis_lso > (int)free_requests(xi))
  {
    KdPrint((__DRIVER_NAME "     Full on send - required = %d, available = %d\n", pages_required + !!ndis_lso, (int)free_requests(xi)));
    return FALSE;
  }

  for (page_num = 0, in_remaining = 0; page_num < pages_required; page_num++)
  {
    pi.mdls[page_num] = XenFreelist_GetPage(&xi->tx_freelist);
    if (!pi.mdls[page_num])
    {
      KdPrint((__DRIVER_NAME "     Out of buffers on send (fl->page_outstanding = %d)\n", xi->tx_freelist.page_outstanding));
      pages_required = page_num;
      for (page_num = 0; page_num < pages_required; page_num++)
      {
        NdisAdjustBufferLength(pi.mdls[page_num], PAGE_SIZE);
        XenFreelist_PutPage(&xi->tx_freelist, pi.mdls[page_num]);
      }
      return FALSE;
    }
    out_buffer = MmGetMdlVirtualAddress(pi.mdls[page_num]);
    out_remaining = (USHORT)min(PAGE_SIZE, total_length - page_num * PAGE_SIZE);
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
  /* consume any zero length buffers tacked on the end */
  while (in_mdl && MmGetMdlByteCount(in_mdl) == 0)
    in_mdl = in_mdl->Next;
    
  if (in_mdl)
  {
    KdPrint((__DRIVER_NAME "     Something went wrong... analyzing\n"));
    NdisGetFirstBufferFromPacketSafe(packet, &in_mdl, &pi.header, &first_buffer_length, &total_length, NormalPagePriority);
    KdPrint((__DRIVER_NAME "     total_length = %d\n", total_length));
    while (in_mdl)
    {
      KdPrint((__DRIVER_NAME "     in_mdl = %p\n", in_mdl));
      KdPrint((__DRIVER_NAME "     MmGetSystemAddressForMdlSafe(in_mdl) = %p\n", MmGetSystemAddressForMdlSafe(in_mdl, LowPagePriority)));
      KdPrint((__DRIVER_NAME "     MmGetMdlByteCount(in_mdl) = %d\n", MmGetMdlByteCount(in_mdl)));
      in_mdl = in_mdl->Next;
    }
    ASSERT(FALSE);
  }

  if (ndis_lso)
  {
    ULONG parse_result = XenNet_ParsePacketHeader(&pi);
    if (parse_result == PARSE_OK)
    {
      XenNet_SumIpHeader(MmGetSystemAddressForMdlSafe(pi.mdls[0], NormalPagePriority), pi.ip4_header_length);
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
    else
    {
        KdPrint((__DRIVER_NAME "     could not parse packet - no large send offload done\n"));
    }
  }

  /*
   * See io/netif.h. Must put (A) 1st request, then (B) optional extra_info, then
   * (C) rest of requests on the ring. Only (A) has csum flags.
   */

  /* (A) */
  tx = XenNet_PutOnTxRing(xi, pi.mdls[0], flags);
  tx->size = (USHORT)total_length;
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
  tx->flags &= ~NETTXF_more_data;

  if (ndis_lso)
  {
    NDIS_PER_PACKET_INFO_FROM_PACKET(packet, TcpLargeSendPacketInfo) = UlongToPtr(pi.tcp_length);
  }

  xi->stat_tx_ok++;

  NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
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

  //FUNCTION_ENTER();

  entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  /* if empty, the above returns head*, not NULL */
  while (entry != &xi->tx_waiting_pkt_list)
  {
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    //KdPrint((__DRIVER_NAME "     Packet ready to send\n"));
    success = XenNet_HWSendPacket(xi, packet);
    if (success)
      InsertTailList(&xi->tx_sent_pkt_list, entry);
    else
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
  //FUNCTION_EXIT();
}

// Called at <= DISPATCH_LEVEL with tx spinlock _NOT_ held
static VOID
XenNet_ReturnSentPackets(struct xennet_info *xi)
{
  PLIST_ENTRY entry;
  PNDIS_PACKET packets[32];
  int packet_index = 0;
  int i = 0;
  KIRQL old_irql;
  
  //FUNCTION_ENTER();

  old_irql = KeRaiseIrqlToDpcLevel();
  KeAcquireSpinLockAtDpcLevel(&xi->tx_lock);
  entry = RemoveHeadList(&xi->tx_sent_pkt_list);
  
  while (entry != &xi->tx_sent_pkt_list)
  {
    packets[packet_index++] = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    entry = RemoveHeadList(&xi->tx_sent_pkt_list);
    // try to minimize the need to acquire the spinlock repeatedly
    if (packet_index == 32 || entry == &xi->tx_sent_pkt_list)
    {
      KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);
      for (i = 0; i < packet_index; i++)
        NdisMSendComplete(xi->adapter_handle, packets[i], NDIS_GET_PACKET_STATUS(packets[i]));
      if (entry != &xi->tx_sent_pkt_list) /* don't acquire the lock if we have no more packets to SendComplete */
        KeAcquireSpinLockAtDpcLevel(&xi->tx_lock);
      packet_index = 0;
    }
  }
  if (!i) /* i will be == 0 if we didn't SendComplete any packets, and thus we will still have the lock */
    KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);
  KeLowerIrql(old_irql);
  //FUNCTION_EXIT();
}

// Called at DISPATCH_LEVEL
//NDIS_STATUS
//XenNet_TxBufferGC(struct xennet_info *xi)
VOID
XenNet_TxBufferGC(PKDPC dpc, PVOID context, PVOID arg1, PVOID arg2)
{
  struct xennet_info *xi = context;
  RING_IDX cons, prod;
  unsigned short id;

  UNREFERENCED_PARAMETER(dpc);
  UNREFERENCED_PARAMETER(arg1);
  UNREFERENCED_PARAMETER(arg2);

  //FUNCTION_ENTER();

  ASSERT(xi->connected);
  ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

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
        put_no_id_on_freelist(xi);
        continue; // This would be the response to an extra_info packet
      }

      id = txrsp->id;
 
      if (xi->tx_mdls[id])
      {
        NdisAdjustBufferLength(xi->tx_mdls[id], PAGE_SIZE);
        XenFreelist_PutPage(&xi->tx_freelist, xi->tx_mdls[id]);
        xi->tx_mdls[id] = NULL;
      }
      put_id_on_freelist(xi, id);
    }

    xi->tx.rsp_cons = prod;
    xi->tx.sring->rsp_event = prod + (NET_TX_RING_SIZE >> 2);
    KeMemoryBarrier();
  } while (prod != xi->tx.sring->rsp_prod);

  /* if queued packets, send them now */
  XenNet_SendQueuedPackets(xi);

  KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);

  XenNet_ReturnSentPackets(xi);

  //FUNCTION_EXIT();
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

  //FUNCTION_ENTER();

  if (xi->inactive)
  {
    for (i = 0; i < NumberOfPackets; i++)
    {
      NDIS_SET_PACKET_STATUS(PacketArray[i], NDIS_STATUS_FAILURE);
      NdisMSendComplete(xi->adapter_handle, PacketArray[i], NDIS_GET_PACKET_STATUS(PacketArray[i]));
    }
    return;
  }
    
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
  
  XenNet_ReturnSentPackets(xi);

  //FUNCTION_EXIT();
}

VOID
XenNet_TxResumeStart(xennet_info_t *xi)
{
  int i;
  KIRQL old_irql;

  KeAcquireSpinLock(&xi->tx_lock, &old_irql);
  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    if (xi->tx_mdls[i])
    {
      NdisAdjustBufferLength(xi->tx_mdls[i], PAGE_SIZE);
      XenFreelist_PutPage(&xi->tx_freelist, xi->tx_mdls[i]);
      xi->tx_mdls[i] = NULL;
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
  XenNet_ReturnSentPackets(xi);
}

BOOLEAN
XenNet_TxInit(xennet_info_t *xi)
{
  USHORT i;

  KeInitializeSpinLock(&xi->tx_lock);
  KeInitializeDpc(&xi->tx_dpc, XenNet_TxBufferGC, xi);
  /* dpcs are only serialised to a single processor */
  KeSetTargetProcessorDpc(&xi->tx_dpc, 0);
  //KeSetImportanceDpc(&xi->tx_dpc, HighImportance);

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

  FUNCTION_ENTER();

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
    mdl = xi->tx_mdls[i];
    if (mdl)
    {
      NdisAdjustBufferLength(xi->tx_mdls[i], PAGE_SIZE);
      XenFreelist_PutPage(&xi->tx_freelist, xi->tx_mdls[i]);
    }
  }

  XenFreelist_Dispose(&xi->tx_freelist);

  KeReleaseSpinLock(&xi->tx_lock, OldIrql);

  FUNCTION_EXIT();

  return TRUE;
}
