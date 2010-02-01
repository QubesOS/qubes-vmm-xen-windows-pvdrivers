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

/* Not really necessary but keeps PREfast happy */
static KDEFERRED_ROUTINE XenNet_TxBufferGC;

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
get_cb_from_freelist(struct xennet_info *xi)
{
  shared_buffer_t *cb;
  
  //FUNCTION_ENTER();
  if (xi->tx_cb_free == 0)
  {
    //FUNCTION_EXIT();
    return NULL;
  }
  xi->tx_cb_free--;
  cb = &xi->tx_cbs[xi->tx_cb_list[xi->tx_cb_free]];
  //FUNCTION_EXIT();
  return cb;
}

static __inline VOID
put_cb_on_freelist(struct xennet_info *xi, shared_buffer_t *cb)
{
  //FUNCTION_ENTER();
  
  ASSERT(cb);
  xi->tx_cb_list[xi->tx_cb_free] = cb->id;
  xi->tx_cb_free++;
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
  ULONG mss = 0;
  uint16_t flags = NETTXF_more_data;
  packet_info_t pi;
  BOOLEAN ndis_lso = FALSE;
  BOOLEAN xen_gso = FALSE;
  PSCATTER_GATHER_LIST sg = NULL;
  ULONG sg_element = 0;
  ULONG sg_offset = 0;
  ULONG parse_result;
  shared_buffer_t *coalesce_buf = NULL;
  ULONG chunks = 0;
  
  //FUNCTION_ENTER();
  
  XenNet_ClearPacketInfo(&pi);
  NdisQueryPacket(packet, NULL, (PUINT)&pi.mdl_count, &pi.first_buffer, (PUINT)&pi.total_length);

  if (xi->config_sg)
  {
    parse_result = XenNet_ParsePacketHeader(&pi, NULL, 0);
  }
  else
  {
    coalesce_buf = get_cb_from_freelist(xi);
    if (!coalesce_buf)
    {
      KdPrint((__DRIVER_NAME "     Full on send - no free cb's\n"));
      return FALSE;
    }
    parse_result = XenNet_ParsePacketHeader(&pi, coalesce_buf->virtual, pi.total_length);
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

  if (xi->config_sg)
  {
    sg = (PSCATTER_GATHER_LIST)NDIS_PER_PACKET_INFO_FROM_PACKET(packet, ScatterGatherListPacketInfo);
    ASSERT(sg != NULL);

    if (sg->NumberOfElements > 19)
    {
      KdPrint((__DRIVER_NAME "     sg->NumberOfElements = %d\n", sg->NumberOfElements));
      NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_SUCCESS);
      return TRUE; // we'll pretend we sent the packet here for now...
    }
    if (sg->NumberOfElements + !!ndis_lso > xi->tx_ring_free)
    {
      //KdPrint((__DRIVER_NAME "     Full on send - required = %d, available = %d\n", sg->NumberOfElements + !!ndis_lso, xi->tx_ring_free));
      //FUNCTION_EXIT();
      return FALSE;
    }

    if (ndis_lso || (pi.header_length && pi.header_length > sg->Elements[sg_element].Length && pi.header == pi.header_data))
    {
      coalesce_buf = get_cb_from_freelist(xi);
      if (!coalesce_buf)
      {
        KdPrint((__DRIVER_NAME "     Full on send - no free cb's\n"));
        return FALSE;
      }
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

/*
* See io/netif.h. Must put (A) 1st request, then (B) optional extra_info, then
* (C) rest of requests on the ring. Only (A) has csum flags.
*/

  /* (A) */
  tx0 = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
  xi->tx.req_prod_pvt++;
  chunks++;
  xi->tx_ring_free--;
  tx0->id = get_id_from_freelist(xi);
  ASSERT(xi->tx_shadows[tx0->id].gref == INVALID_GRANT_REF);
// if we coalesced the header then we want to put that on first, otherwise we put on the first sg element
  if (coalesce_buf)
  {
    ULONG remaining = pi.header_length;
    memcpy(coalesce_buf->virtual, pi.header, pi.header_length);
    /* even though we haven't reported that we are capable of it, LSO demands that we calculate the IP Header checksum */
    if (ndis_lso)
    {
      XenNet_SumIpHeader(coalesce_buf->virtual, pi.ip4_header_length);
    }
    ASSERT(!xi->tx_shadows[tx0->id].cb);
    xi->tx_shadows[tx0->id].cb = coalesce_buf;
    tx0->gref = coalesce_buf->gref;
    tx0->offset = coalesce_buf->offset;
    tx0->size = (USHORT)pi.header_length;
    ASSERT(tx0->offset + tx0->size <= PAGE_SIZE);
    ASSERT(tx0->size);
    if (xi->config_sg)
    {
      /* TODO: if the next buffer contains only a small amount of data then put it on too */
      while (remaining)
      {
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
  }
  else
  {
    ASSERT(xi->config_sg);
    tx0->gref = xi->vectors.GntTbl_GrantAccess(xi->vectors.context, 0,
      (ULONG)(sg->Elements[sg_element].Address.QuadPart >> PAGE_SHIFT), FALSE, INVALID_GRANT_REF);
    ASSERT(tx0->gref != INVALID_GRANT_REF);
    xi->tx_shadows[tx0->id].gref = tx0->gref;
    tx0->offset = (USHORT)sg->Elements[sg_element].Address.LowPart & (PAGE_SIZE - 1);
    tx0->size = (USHORT)min(sg->Elements[sg_element].Length, PAGE_SIZE - tx0->offset);
    if (tx0->offset + tx0->size > PAGE_SIZE)
    {
      KdPrint((__DRIVER_NAME "     offset + size = %d\n", tx0->offset + tx0->size));
    }
    ASSERT(tx0->size);
    if (tx0->size != sg->Elements[sg_element].Length)
    {
      sg_offset = tx0->size;
    }
    else
    {
      sg_element++;
    }
  }
  tx0->flags = flags;
  txN = tx0;
  ASSERT(txN->gref != INVALID_GRANT_REF);

  /* (B) */
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

  if (xi->config_sg)
  {
    /* (C) - only if sg otherwise it was all sent on the first buffer */
    while (sg_element < sg->NumberOfElements)
    {
      txN = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
      xi->tx.req_prod_pvt++;
      chunks++;
      xi->tx_ring_free--;
      txN->id = get_id_from_freelist(xi);
      txN->gref = xi->vectors.GntTbl_GrantAccess(xi->vectors.context, 0,
        (ULONG)((sg->Elements[sg_element].Address.QuadPart + sg_offset) >> PAGE_SHIFT), FALSE, INVALID_GRANT_REF);
      ASSERT(txN->gref != INVALID_GRANT_REF);
      ASSERT(xi->tx_shadows[txN->id].gref == INVALID_GRANT_REF);
      xi->tx_shadows[txN->id].gref = txN->gref;
      txN->offset = (USHORT)(sg->Elements[sg_element].Address.LowPart + sg_offset) & (PAGE_SIZE - 1);
      ASSERT(sg->Elements[sg_element].Length > sg_offset);
      txN->size = (USHORT)min(sg->Elements[sg_element].Length - sg_offset, PAGE_SIZE - txN->offset);
      if (txN->offset + txN->size > PAGE_SIZE)
      {
        KdPrint((__DRIVER_NAME "     offset (%d) + size (%d) = %d\n", txN->offset, txN->size, txN->offset + txN->size));
      }
      ASSERT(txN->offset + txN->size <= PAGE_SIZE);
      ASSERT(txN->size);
      tx0->size = tx0->size + txN->size;
      txN->flags = NETTXF_more_data;
      ASSERT(txN->gref != INVALID_GRANT_REF);
      if (txN->size != sg->Elements[sg_element].Length - sg_offset)
      {
        sg_offset += txN->size;
      }
      else
      {
        sg_element++;
        sg_offset = 0;
      }
    }
  }
  txN->flags &= ~NETTXF_more_data;
  ASSERT(tx0->size == pi.total_length);
  ASSERT(!xi->tx_shadows[txN->id].packet);
  xi->tx_shadows[txN->id].packet = packet;

  if (ndis_lso)
  {
    //KdPrint((__DRIVER_NAME "     TcpLargeSendPacketInfo = %d\n", pi.tcp_length));
    NDIS_PER_PACKET_INFO_FROM_PACKET(packet, TcpLargeSendPacketInfo) = UlongToPtr(pi.tcp_length);
  }

  if (chunks > 19)
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
    if (!XenNet_HWSendPacket(xi, packet))
    {
      KdPrint((__DRIVER_NAME "     No room for packet\n"));
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
static VOID
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
        ASSERT(shadow->gref == INVALID_GRANT_REF);
        put_cb_on_freelist(xi, shadow->cb);
        shadow->cb = NULL;
      }
      
      if (shadow->gref != INVALID_GRANT_REF)
      {
        xi->vectors.GntTbl_EndAccess(xi->vectors.context,
          shadow->gref, FALSE);
        shadow->gref = INVALID_GRANT_REF;
      }
      
      if (shadow->packet)
      {
        packet = shadow->packet;
        *(PNDIS_PACKET *)&packet->MiniportReservedEx[0] = NULL;
        if (head)
          *(PNDIS_PACKET *)&tail->MiniportReservedEx[0] = packet;
        else
          head = packet;
        tail = packet;
        shadow->packet = NULL;
      }
      put_id_on_freelist(xi, txrsp->id);
    }

    xi->tx.rsp_cons = prod;
    /* resist the temptation to set the event more than +1... it breaks things */
    xi->tx.sring->rsp_event = prod + 1;
    KeMemoryBarrier();
  } while (prod != xi->tx.sring->rsp_prod);

  /* if queued packets, send them now */
  if (!xi->tx_shutting_down)
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

  for (i = 0; i < NumberOfPackets; i++)
  {
    packet = PacketArray[i];
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
XenNet_CancelSendPackets(
  NDIS_HANDLE MiniportAdapterContext,
  PVOID CancelId)
{
  struct xennet_info *xi = MiniportAdapterContext;
  KIRQL old_irql;
  PLIST_ENTRY entry;
  PNDIS_PACKET packet;
  PNDIS_PACKET head = NULL, tail = NULL;

  FUNCTION_ENTER();

  KeAcquireSpinLock(&xi->tx_lock, &old_irql);

  entry = xi->tx_waiting_pkt_list.Flink;
  while (entry != &xi->tx_waiting_pkt_list)
  {
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    entry = entry->Flink;
    if (NDIS_GET_PACKET_CANCEL_ID(packet) == CancelId)
    {
      RemoveEntryList((PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)]);
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
    NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_REQUEST_ABORTED);
  }
  
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

  KeAcquireSpinLock(&xi->tx_lock, &old_irql);
  XenNet_SendQueuedPackets(xi);
  KeReleaseSpinLock(&xi->tx_lock, old_irql);

  FUNCTION_EXIT();
}

BOOLEAN
XenNet_TxInit(xennet_info_t *xi)
{
  NTSTATUS status;
  USHORT i, j;
  ULONG cb_size;

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
  
  if (xi->config_sg)
  {
    cb_size = TX_HEADER_BUFFER_SIZE;
  }
  else
  {
    cb_size = PAGE_SIZE;
  }

  for (i = 0; i < TX_COALESCE_BUFFERS / (PAGE_SIZE / cb_size); i++)
  {
    PVOID virtual;
    grant_ref_t gref;
    
    status = NdisAllocateMemoryWithTag(&virtual, PAGE_SIZE, XENNET_POOL_TAG);
    if (status != STATUS_SUCCESS)
    {
      break;
    }
    gref = (grant_ref_t)xi->vectors.GntTbl_GrantAccess(xi->vectors.context, 0,
      (ULONG)(MmGetPhysicalAddress(virtual).QuadPart >> PAGE_SHIFT), FALSE, INVALID_GRANT_REF);
    if (gref == INVALID_GRANT_REF)
    {
      NdisFreeMemory(virtual, PAGE_SIZE, 0);
      break;
    }
    
    for (j = 0; j < PAGE_SIZE / cb_size; j++)
    {
      USHORT index = (USHORT)(i * (PAGE_SIZE / cb_size) + j);
      xi->tx_cbs[index].id = index;
      xi->tx_cbs[index].virtual = (PUCHAR)virtual + j * cb_size;
      xi->tx_cbs[index].gref = gref;
      xi->tx_cbs[index].offset = (ULONG_PTR)xi->tx_cbs[index].virtual & (PAGE_SIZE - 1);
      put_cb_on_freelist(xi, &xi->tx_cbs[index]);
    }
  }
  if (i == 0)
    KdPrint((__DRIVER_NAME "     Unable to allocate any SharedMemory buffers\n"));

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
  PLIST_ENTRY entry;
  PNDIS_PACKET packet;
  //PMDL mdl;
  //ULONG i;
  KIRQL OldIrql;
  shared_buffer_t *cb;

  FUNCTION_ENTER();

  KeAcquireSpinLock(&xi->tx_lock, &OldIrql);
  xi->tx_shutting_down = TRUE;
  KeReleaseSpinLock(&xi->tx_lock, OldIrql);

  while (xi->tx_outstanding)
  {
    KdPrint((__DRIVER_NAME "     Waiting for %d remaining packets to be sent\n", xi->tx_outstanding));
    KeWaitForSingleObject(&xi->tx_idle_event, Executive, KernelMode, FALSE, NULL);
  }

  KeRemoveQueueDpc(&xi->tx_dpc);
  KeFlushQueuedDpcs();

  /* Free packets in tx queue */
  entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  while (entry != &xi->tx_waiting_pkt_list)
  {
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_FAILURE);
    entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  }
  
  while((cb = get_cb_from_freelist(xi)) != NULL)
  {
    /* only free the actual buffers which were aligned on a page boundary */
    if ((PtrToUlong(cb->virtual) & (PAGE_SIZE - 1)) == 0)
      NdisFreeMemory(cb->virtual, PAGE_SIZE, 0);
  }

  FUNCTION_EXIT();

  return TRUE;
}
