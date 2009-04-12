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

static __inline shared_buffer_t *
get_hb_from_freelist(struct xennet_info *xi)
{
  shared_buffer_t *hb;
  
  //FUNCTION_ENTER();
  if (xi->tx_hb_free == 0)
  {
    //FUNCTION_EXIT();
    return NULL;
  }
  xi->tx_hb_free--;
  //KdPrint((__DRIVER_NAME "     xi->tx_hb_free = %d\n", xi->tx_hb_free));
  //KdPrint((__DRIVER_NAME "     xi->tx_hb_list[xi->tx_hb_free] = %d\n", xi->tx_hb_list[xi->tx_hb_free]));
  hb = &xi->tx_hbs[xi->tx_hb_list[xi->tx_hb_free]];
  //KdPrint((__DRIVER_NAME "     hb = %p\n", hb));
  //FUNCTION_EXIT();
  return hb;
}

static __inline VOID
put_hb_on_freelist(struct xennet_info *xi, shared_buffer_t *hb)
{
  //FUNCTION_ENTER();
  
  //KdPrint((__DRIVER_NAME "     hb = %p\n", hb));
  //KdPrint((__DRIVER_NAME "     xi->tx_hb_free = %d\n", xi->tx_hb_free));
  ASSERT(hb);
  xi->tx_hb_list[xi->tx_hb_free] = hb->id;
  xi->tx_hb_free++;
  //FUNCTION_EXIT();
}

#define SWAP_USHORT(x) (USHORT)((((x & 0xFF) << 8)|((x >> 8) & 0xFF)))

/* Called at DISPATCH_LEVEL with tx_lock held */
/*
 * Send one NDIS_PACKET. This may involve multiple entries on TX ring.
 */
static BOOLEAN
XenNet_HWSendPacket(struct xennet_info *xi, PNDIS_PACKET packet)
{
  struct netif_tx_request *tx0 = NULL;
  struct netif_tx_request *txN = NULL;
  struct netif_extra_info *ei = NULL;
  PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;
  //UINT total_packet_length;
  ULONG mss = 0;
  uint16_t flags = NETTXF_more_data;
  packet_info_t pi;
  BOOLEAN ndis_lso = FALSE;
  BOOLEAN xen_gso = FALSE;
  //ULONG remaining;
  PSCATTER_GATHER_LIST sg;
  ULONG sg_element = 0;
  ULONG sg_offset = 0;
  ULONG parse_result;
  shared_buffer_t *header_buf = NULL;
  ULONG chunks = 0;
  
  //FUNCTION_ENTER();
  
  XenNet_ClearPacketInfo(&pi);
  NdisQueryPacket(packet, NULL, (PUINT)&pi.mdl_count, &pi.first_buffer, (PUINT)&pi.total_length);
  //KdPrint((__DRIVER_NAME "     A - packet = %p, mdl_count = %d, total_length = %d\n", packet, pi.mdl_count, pi.total_length));

  parse_result = XenNet_ParsePacketHeader(&pi);  
  //KdPrint((__DRIVER_NAME "     B\n"));

  if (pi.header && *((PUCHAR)pi.header + 12) != 0x08)
    KdPrint((__DRIVER_NAME "     %02x %02x\n", (int)*((PUCHAR)pi.header + 12), (int)*((PUCHAR)pi.header + 13)));

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
      //NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_FAILURE);
      //FUNCTION_EXIT();
      return TRUE;
    }
  }

  if (pi.mdl_count + !!ndis_lso > xi->tx_ring_free)
  {
    KdPrint((__DRIVER_NAME "     Full on send - required = %d, available = %d\n", pi.mdl_count + !!ndis_lso, xi->tx_ring_free));
    //FUNCTION_EXIT();
    return FALSE;
  }

  sg = (PSCATTER_GATHER_LIST)NDIS_PER_PACKET_INFO_FROM_PACKET(packet, ScatterGatherListPacketInfo);
  ASSERT(sg != NULL);

  if (ndis_lso || (pi.header_length && pi.header_length > sg->Elements[sg_element].Length && pi.header == pi.header_data))
  {
    header_buf = get_hb_from_freelist(xi);
    if (!header_buf)
    {
      KdPrint((__DRIVER_NAME "     Full on send - no free hb's\n"));
      return FALSE;
    }
  }
  
  if (ndis_lso)
  {    
    if (parse_result == PARSE_OK)
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
    else
    {
        KdPrint((__DRIVER_NAME "     could not parse packet - no large send offload done\n"));
    }
  }

/*
* See io/netif.h. Must put (A) 1st request, then (B) optional extra_info, then
* (C) rest of requests on the ring. Only (A) has csum flags.
*/

  //KdPrint((__DRIVER_NAME "     C\n"));
  /* (A) */
// if we coalesced the header then we want to put that on first, otherwise we put on the first sg element
  tx0 = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
  chunks++;
  xi->tx_ring_free--;
  tx0->id = 0xFFFF;
  if (header_buf)
  {
    ULONG remaining = pi.header_length;
    ASSERT(pi.header_length < TX_HEADER_BUFFER_SIZE);
    //KdPrint((__DRIVER_NAME "     D - header_length = %d\n", pi.header_length));
    memcpy(header_buf->virtual, pi.header, pi.header_length);
    /* even though we haven't reported that we are capable of it, LSO demands that we calculate the IP Header checksum */
    if (ndis_lso)
    {
      XenNet_SumIpHeader(header_buf->virtual, pi.ip4_header_length);
    }
    tx0->gref = (grant_ref_t)(header_buf->logical.QuadPart >> PAGE_SHIFT);
    tx0->offset = (USHORT)header_buf->logical.LowPart & (PAGE_SIZE - 1);
    tx0->size = (USHORT)pi.header_length;
    ASSERT(tx0->offset + tx0->size <= PAGE_SIZE);
    ASSERT(tx0->size);
    /* TODO: if the next buffer contains only a small amount of data then put it on too */
    while (remaining)
    {
      //KdPrint((__DRIVER_NAME "     D - remaining = %d\n", remaining));
      //KdPrint((__DRIVER_NAME "     Da - sg_element = %d, sg->Elements[sg_element].Length = %d\n", sg_element, sg->Elements[sg_element].Length));
      if (sg->Elements[sg_element].Length <= remaining)
      {
        remaining -= sg->Elements[sg_element].Length;
        sg_element++;
      }
      else
      {
        sg_offset = remaining;
        remaining = 0;
      }
    }
  }
  else
  {
    //KdPrint((__DRIVER_NAME "     E\n"));
    //KdPrint((__DRIVER_NAME "     Eg - sg_element = %d, sg_offset = %d\n", sg_element, sg_offset));
    //KdPrint((__DRIVER_NAME "     Eh - address = %p, length = %d\n",
    //  sg->Elements[sg_element].Address.LowPart, sg->Elements[sg_element].Length));
    tx0->gref = (grant_ref_t)(sg->Elements[sg_element].Address.QuadPart >> PAGE_SHIFT);
    tx0->offset = (USHORT)sg->Elements[sg_element].Address.LowPart & (PAGE_SIZE - 1);
    tx0->size = (USHORT)sg->Elements[sg_element].Length;
    ASSERT(tx0->size);
    sg_element++;
  }
  tx0->flags = flags;
  txN = tx0;
  xi->tx.req_prod_pvt++;

  /* (B) */
  if (xen_gso)
  {
    //KdPrint((__DRIVER_NAME "     Using extra_info\n"));
    ASSERT(flags & NETTXF_extra_info);
    ei = (struct netif_extra_info *)RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
    chunks++;
    xi->tx_ring_free--;
    ei->type = XEN_NETIF_EXTRA_TYPE_GSO;
    ei->flags = 0;
    ei->u.gso.size = (USHORT)mss;
    ei->u.gso.type = XEN_NETIF_GSO_TYPE_TCPV4;
    ei->u.gso.pad = 0;
    ei->u.gso.features = 0;
    xi->tx.req_prod_pvt++;
  }

  //KdPrint((__DRIVER_NAME "     F\n"));
  /* (C) */
  while (sg_element < sg->NumberOfElements)
  {
    //KdPrint((__DRIVER_NAME "     G - sg_element = %d, sg_offset = %d\n", sg_element, sg_offset));
    //KdPrint((__DRIVER_NAME "     H - address = %p, length = %d\n",
    //  sg->Elements[sg_element].Address.LowPart + sg_offset, sg->Elements[sg_element].Length - sg_offset));
    txN = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
    xi->tx_ring_free--;
    txN->id = 0xFFFF;
    txN->gref = (grant_ref_t)(sg->Elements[sg_element].Address.QuadPart >> PAGE_SHIFT);
    ASSERT((sg->Elements[sg_element].Address.LowPart & (PAGE_SIZE - 1)) + sg_offset <= PAGE_SIZE);
    txN->offset = (USHORT)(sg->Elements[sg_element].Address.LowPart + sg_offset) & (PAGE_SIZE - 1);
    ASSERT(sg->Elements[sg_element].Length > sg_offset);
    txN->size = (USHORT)(sg->Elements[sg_element].Length - sg_offset);
    ASSERT(txN->offset + txN->size <= PAGE_SIZE);
    ASSERT(txN->size);
    tx0->size = tx0->size + txN->size;
    txN->flags = NETTXF_more_data;
    sg_offset = 0;
    sg_element++;
    xi->tx.req_prod_pvt++;
  }
  txN->flags &= ~NETTXF_more_data;
  txN->id = get_id_from_freelist(xi);
//KdPrint((__DRIVER_NAME "     send - id = %d\n", tx0->id));
  //KdPrint((__DRIVER_NAME "     TX: id = %d, hb = %p, xi->tx_shadows[txN->id].hb = %p\n", txN->id, header_buf, xi->tx_shadows[txN->id].hb));
  ASSERT(!xi->tx_shadows[txN->id].hb);
  ASSERT(!xi->tx_shadows[txN->id].packet);
  xi->tx_shadows[txN->id].packet = packet;
  xi->tx_shadows[txN->id].hb = header_buf;

  if (ndis_lso)
  {
    //KdPrint((__DRIVER_NAME "     TcpLargeSendPacketInfo = %d\n", pi.tcp_length));
    NDIS_PER_PACKET_INFO_FROM_PACKET(packet, TcpLargeSendPacketInfo) = UlongToPtr(pi.tcp_length);
  }

  if (chunks > 12)
  {
    KdPrint((__DRIVER_NAME "     chunks = %d\n", chunks));
  }
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
  PLIST_ENTRY entry;
  PNDIS_PACKET packet;
  int notify;

  //FUNCTION_ENTER();

  if (xi->device_state->suspend_resume_state_pdo != SR_STATE_RUNNING)
    return;

  entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  /* if empty, the above returns head*, not NULL */
  while (entry != &xi->tx_waiting_pkt_list)
  {
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    //KdPrint((__DRIVER_NAME "     Packet ready to send\n"));
    if (!XenNet_HWSendPacket(xi, packet))
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

//ULONG packets_outstanding = 0;
// Called at DISPATCH_LEVEL
VOID
XenNet_TxBufferGC(PKDPC dpc, PVOID context, PVOID arg1, PVOID arg2)
{
  struct xennet_info *xi = context;
  RING_IDX cons, prod;
  PNDIS_PACKET head = NULL, tail = NULL;
  PNDIS_PACKET packet;

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
      
      xi->tx_ring_free++;
      
      if (txrsp->status == NETIF_RSP_NULL || txrsp->id == 0xFFFF)
        continue;

      //KdPrint((__DRIVER_NAME "     GC: id = %d, hb = %p\n", txrsp->id, xi->tx_shadows[txrsp->id].hb));
      if (xi->tx_shadows[txrsp->id].hb)
      {
        put_hb_on_freelist(xi, xi->tx_shadows[txrsp->id].hb);
        xi->tx_shadows[txrsp->id].hb = NULL;
      }
      
      if (xi->tx_shadows[txrsp->id].packet)
      {
        packet = xi->tx_shadows[txrsp->id].packet;
        *(PNDIS_PACKET *)&packet->MiniportReservedEx[0] = NULL;
        if (head)
          *(PNDIS_PACKET *)&tail->MiniportReservedEx[0] = packet;
        else
          head = packet;
        tail = packet;
        xi->tx_shadows[txrsp->id].packet = NULL;
      }
      put_id_on_freelist(xi, txrsp->id);
    }

    xi->tx.rsp_cons = prod;
    xi->tx.sring->rsp_event = prod + (NET_TX_RING_SIZE >> 2);
    KeMemoryBarrier();
  } while (prod != xi->tx.sring->rsp_prod);

  /* if queued packets, send them now */
  XenNet_SendQueuedPackets(xi);

  KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);

  while (head)
  {
    packet = (PNDIS_PACKET)head;
    head = *(PNDIS_PACKET *)&packet->MiniportReservedEx[0];
    NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_SUCCESS);
    xi->tx_outstanding--;
    if (!xi->tx_outstanding && xi->tx_shutting_down)
      KeSetEvent(&xi->tx_idle_event, IO_NO_INCREMENT, FALSE);
  }

  if (xi->device_state->suspend_resume_state_pdo == SR_STATE_SUSPENDING
    && xi->device_state->suspend_resume_state_fdo != SR_STATE_SUSPENDING
    && xi->tx_id_free == NET_TX_RING_SIZE)
  {
    KdPrint((__DRIVER_NAME "     Setting SR_STATE_SUSPENDING\n"));
    xi->device_state->suspend_resume_state_fdo = SR_STATE_SUSPENDING;
    KdPrint((__DRIVER_NAME "     Notifying event channel %d\n", xi->device_state->pdo_event_channel));
    xi->vectors.EvtChn_Notify(xi->vectors.context, xi->device_state->pdo_event_channel);
  }

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
      NdisMSendComplete(xi->adapter_handle, PacketArray[i], NDIS_STATUS_FAILURE);
    }
    return;
  }
    
  KeAcquireSpinLock(&xi->tx_lock, &OldIrql);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ " (packets = %d, free_requests = %d)\n", NumberOfPackets, free_requests(xi)));
  for (i = 0; i < NumberOfPackets; i++)
  {
    packet = PacketArray[i];
//packets_outstanding++;
//KdPrint(("+packet = %p\n", packet));
    ASSERT(packet);
    *(ULONG *)&packet->MiniportReservedEx = 0;
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(&xi->tx_waiting_pkt_list, entry);
  }

  XenNet_SendQueuedPackets(xi);

  KeReleaseSpinLock(&xi->tx_lock, OldIrql);
  
  //FUNCTION_EXIT();
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

  KeAcquireSpinLock(&xi->tx_lock, &old_irql);
  XenNet_SendQueuedPackets(xi);
  KeReleaseSpinLock(&xi->tx_lock, old_irql);

  FUNCTION_EXIT();
}

BOOLEAN
XenNet_TxInit(xennet_info_t *xi)
{
  USHORT i, j;

  KeInitializeSpinLock(&xi->tx_lock);
  KeInitializeDpc(&xi->tx_dpc, XenNet_TxBufferGC, xi);
  /* dpcs are only serialised to a single processor */
  KeSetTargetProcessorDpc(&xi->tx_dpc, 0);
  //KeSetImportanceDpc(&xi->tx_dpc, HighImportance);
  InitializeListHead(&xi->tx_waiting_pkt_list);

  KeInitializeEvent(&xi->tx_idle_event, SynchronizationEvent, FALSE);
  xi->tx_shutting_down = FALSE;
  xi->tx_outstanding = 0;
  xi->tx_ring_free = NET_TX_RING_SIZE;

  for (i = 0; i < TX_HEADER_BUFFERS / (PAGE_SIZE / TX_HEADER_BUFFER_SIZE); i++)
  {
    PVOID virtual;
    NDIS_PHYSICAL_ADDRESS logical;
    NdisMAllocateSharedMemory(xi->adapter_handle, PAGE_SIZE, TRUE, &virtual, &logical);
    if (virtual == NULL)
      continue;
    //KdPrint((__DRIVER_NAME "     Allocated SharedMemory at %p\n", virtual));
    for (j = 0; j < PAGE_SIZE / TX_HEADER_BUFFER_SIZE; j++)
    {
      USHORT index = i * (PAGE_SIZE / TX_HEADER_BUFFER_SIZE) + j;
      xi->tx_hbs[index].id = index;
      xi->tx_hbs[index].virtual = (PUCHAR)virtual + j * TX_HEADER_BUFFER_SIZE;
      xi->tx_hbs[index].logical.QuadPart = logical.QuadPart + j * TX_HEADER_BUFFER_SIZE;
      put_hb_on_freelist(xi, &xi->tx_hbs[index]);
    }
  }
  if (i == 0)
    KdPrint((__DRIVER_NAME "     Unable to allocate any SharedMemory buffers\n"));

  xi->tx_id_free = 0;
  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
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
  PLIST_ENTRY entry;
  PNDIS_PACKET packet;
  //PMDL mdl;
  //ULONG i;
  KIRQL OldIrql;
  shared_buffer_t *hb;

  FUNCTION_ENTER();

  ASSERT(!xi->connected);

  KeAcquireSpinLock(&xi->tx_lock, &OldIrql);

  xi->tx_shutting_down = TRUE;

  /* Free packets in tx queue */
  entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  while (entry != &xi->tx_waiting_pkt_list)
  {
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_FAILURE);
    entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  }
  
  KeReleaseSpinLock(&xi->tx_lock, OldIrql);

  while (xi->tx_outstanding)
  {
    KdPrint((__DRIVER_NAME "     Waiting for all packets to be sent\n"));
    KeWaitForSingleObject(&xi->tx_idle_event, Executive, KernelMode, FALSE, NULL);
  }

  KeAcquireSpinLock(&xi->tx_lock, &OldIrql);

  while((hb = get_hb_from_freelist(xi)) != NULL)
  {
    /* only free the actual buffers which were aligned on a page boundary */
    if ((PtrToUlong(hb->virtual) & (PAGE_SIZE - 1)) == 0)
      NdisMFreeSharedMemory(xi->adapter_handle, PAGE_SIZE, TRUE, hb->virtual, hb->logical);
  }

  KeReleaseSpinLock(&xi->tx_lock, OldIrql);

  FUNCTION_EXIT();

  return TRUE;
}
