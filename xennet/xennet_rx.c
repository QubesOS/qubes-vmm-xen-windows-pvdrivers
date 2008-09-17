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

// Called at DISPATCH_LEVEL with rx lock held
static NDIS_STATUS
XenNet_RxBufferAlloc(struct xennet_info *xi)
{
  unsigned short id;
  PMDL mdl;
  ULONG i, notify;
  ULONG batch_target;
  RING_IDX req_prod = xi->rx.req_prod_pvt;
  netif_rx_request_t *req;

//KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  batch_target = xi->rx_target - (req_prod - xi->rx.rsp_cons);

  if (batch_target < (xi->rx_target >> 2))
    return NDIS_STATUS_SUCCESS; /* only refill if we are less than 3/4 full already */

  for (i = 0; i < batch_target; i++)
  {
    if (xi->rx_id_free == 0)
    {
      KdPrint((__DRIVER_NAME "     Added %d out of %d buffers to rx ring (ran out of id's)\n", i, batch_target));
      break;
    }
    mdl = XenFreelist_GetPage(&xi->rx_freelist);
    if (!mdl)
    {
      KdPrint((__DRIVER_NAME "     Added %d out of %d buffers to rx ring (no free pages)\n", i, batch_target));
      break;
    }
    xi->rx_id_free--;

    /* Give to netback */
    id = (USHORT)((req_prod + i) & (NET_RX_RING_SIZE - 1));
    ASSERT(xi->rx_mdls[id] == NULL);
    xi->rx_mdls[id] = mdl;
    req = RING_GET_REQUEST(&xi->rx, req_prod + i);
    req->gref = get_grant_ref(mdl);
    ASSERT(req->gref != INVALID_GRANT_REF);
    req->id = id;
  }

  xi->rx.req_prod_pvt = req_prod + i;
  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xi->rx, notify);
  if (notify)
  {
    xi->vectors.EvtChn_Notify(xi->vectors.context, xi->event_channel);
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NDIS_STATUS_SUCCESS;
}

static PNDIS_PACKET
get_packet_from_freelist(struct xennet_info *xi)
{
  NDIS_STATUS status;
  PNDIS_PACKET packet;

  //ASSERT(!KeTestSpinLock(&xi->rx_lock));

  if (!xi->rx_packet_free)
  {
    NdisAllocatePacket(&status, &packet, xi->packet_pool);
    if (status != NDIS_STATUS_SUCCESS)
      return NULL;
    NDIS_SET_PACKET_HEADER_SIZE(packet, XN_HDR_SIZE);
  }
  else
  {
    xi->rx_packet_free--;
    packet = xi->rx_packet_list[xi->rx_packet_free];
  }
  return packet;
}

static VOID
put_packet_on_freelist(struct xennet_info *xi, PNDIS_PACKET packet)
{
  //ASSERT(!KeTestSpinLock(&xi->rx_lock));

  if (xi->rx_packet_free == NET_RX_RING_SIZE * 2)
  {
    //KdPrint((__DRIVER_NAME "     packet free list full - releasing packet\n"));
    NdisFreePacket(packet);
    return;
  }
  NdisReinitializePacket(packet);
  xi->rx_packet_list[xi->rx_packet_free] = packet;
  xi->rx_packet_free++;
}

static VOID
packet_freelist_dispose(struct xennet_info *xi)
{
  while(xi->rx_packet_free != 0)
  {
    xi->rx_packet_free--;
    NdisFreePacket(xi->rx_packet_list[xi->rx_packet_free]);
  }
}

static PNDIS_PACKET
XenNet_MakePacket(struct xennet_info *xi)
{
  PNDIS_PACKET packet;
  PUCHAR in_buffer;
  PNDIS_BUFFER out_mdl;
  PUCHAR out_buffer;
  USHORT out_offset;
  USHORT out_remaining;
  USHORT length;
  USHORT new_ip4_length;
  //NDIS_STATUS status;
  USHORT i;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  if (!xi->rxpi.split_required)
  {
    packet = get_packet_from_freelist(xi);
    if (packet == NULL)
    {
      /* buffers will be freed in MakePackets */
      return NULL;
    }
    xi->rx_outstanding++;
    for (i = 0; i < xi->rxpi.mdl_count; i++)
      NdisChainBufferAtBack(packet, xi->rxpi.mdls[i]);

    NDIS_PER_PACKET_INFO_FROM_PACKET(packet, TcpLargeSendPacketInfo) = UlongToPtr(xi->rxpi.mss);

    NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
  }
  else
  {
    out_mdl = XenFreelist_GetPage(&xi->rx_freelist);
    if (!out_mdl)
      return NULL;
    packet = get_packet_from_freelist(xi);
    if (packet == NULL)
    {
      XenFreelist_PutPage(&xi->rx_freelist, out_mdl);
      return NULL;
    }
    xi->rx_outstanding++;
    out_buffer = MmGetMdlVirtualAddress(out_mdl);
    out_offset = XN_HDR_SIZE + xi->rxpi.ip4_header_length + xi->rxpi.tcp_header_length;
    out_remaining = min(xi->rxpi.mss, xi->rxpi.tcp_remaining);
    NdisAdjustBufferLength(out_mdl, out_offset + out_remaining);
    memcpy(out_buffer, xi->rxpi.header, out_offset);
    new_ip4_length = out_remaining + xi->rxpi.ip4_header_length + xi->rxpi.tcp_header_length;
    SET_NET_USHORT(&out_buffer[XN_HDR_SIZE + 2], new_ip4_length);
    SET_NET_ULONG(&out_buffer[XN_HDR_SIZE + xi->rxpi.ip4_header_length + 4], xi->rxpi.tcp_seq);
    xi->rxpi.tcp_seq += out_remaining;
    xi->rxpi.tcp_remaining = xi->rxpi.tcp_remaining - out_remaining;
    do 
    {
      ASSERT(xi->rxpi.curr_mdl < xi->rxpi.mdl_count);
      in_buffer = XenNet_GetData(&xi->rxpi, out_remaining, &length);
      memcpy(&out_buffer[out_offset], in_buffer, length);
      out_remaining = out_remaining - length;
      out_offset = out_offset + length;
    } while (out_remaining != 0); // && in_buffer != NULL);
    NdisChainBufferAtBack(packet, out_mdl);
    XenNet_SumIpHeader(out_buffer, xi->rxpi.ip4_header_length);
    NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
  }
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (%p)\n", packet));
  return packet;
}

/*
 Windows appears to insist that the checksum on received packets is correct, and won't
 believe us when we lie about it, which happens when the packet is generated on the
 same bridge in Dom0. Doh!
 This is only for TCP and UDP packets. IP checksums appear to be correct anyways.
*/
static VOID
XenNet_SumPacketData(
  packet_info_t *pi,  
  PNDIS_PACKET packet
)
{
  USHORT i;
  PUCHAR buffer;
  PMDL mdl;
  UINT total_length;
  UINT buffer_length;
  USHORT buffer_offset;
  ULONG csum;
  PUSHORT csum_ptr;
  USHORT remaining;
  USHORT ip4_length;
  
//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  NdisGetFirstBufferFromPacketSafe(packet, &mdl, &buffer, &buffer_length, &total_length, NormalPagePriority);
  ASSERT(mdl);

  ip4_length = GET_NET_PUSHORT(&buffer[XN_HDR_SIZE + 2]);

  if ((USHORT)(ip4_length + XN_HDR_SIZE) != total_length)
  {
    KdPrint((__DRIVER_NAME "     Size Mismatch %d (ip4_length + XN_HDR_SIZE) != %d (total_length)\n", ip4_length + XN_HDR_SIZE, total_length));
  }

  switch (pi->ip_proto)
  {
  case 6:
    csum_ptr = (USHORT *)&buffer[XN_HDR_SIZE + pi->ip4_header_length + 16];
    break;
  case 17:
    csum_ptr = (USHORT *)&buffer[XN_HDR_SIZE + pi->ip4_header_length + 6];
    break;
  default:
    KdPrint((__DRIVER_NAME "     Don't know how to calc sum for IP Proto %d\n", pi->ip_proto));
    return;
  }
    
  *csum_ptr = 0;

  csum = 0;
  csum += GET_NET_PUSHORT(&buffer[XN_HDR_SIZE + 12]) + GET_NET_PUSHORT(&buffer[XN_HDR_SIZE + 14]); // src
  csum += GET_NET_PUSHORT(&buffer[XN_HDR_SIZE + 16]) + GET_NET_PUSHORT(&buffer[XN_HDR_SIZE + 18]); // dst
  csum += ((USHORT)buffer[XN_HDR_SIZE + 9]);

  remaining = ip4_length - pi->ip4_header_length;

  csum += remaining;

  for (buffer_offset = i = XN_HDR_SIZE + pi->ip4_header_length; i < total_length - 1; i += 2, buffer_offset += 2)
  {
    if (buffer_offset == buffer_length - 1) // deal with a buffer ending on an odd byte boundary
    {
      csum += (USHORT)buffer[buffer_offset] << 8;
      NdisGetNextBuffer(mdl, &mdl);
      if (mdl == NULL)
      {
        KdPrint((__DRIVER_NAME "     Ran out of buffers\n"));
        return;
      }
      NdisQueryBufferSafe(mdl, &buffer, &buffer_length, NormalPagePriority);
      csum += ((USHORT)buffer[0]);
      buffer_offset = (USHORT)-1;
    }
    else
    {
      if (buffer_offset == buffer_length)
      {
//        KdPrint((__DRIVER_NAME "     New buffer - aligned...\n"));
        NdisGetNextBuffer(mdl, &mdl);
        if (mdl == NULL)
        {
          KdPrint((__DRIVER_NAME "     Ran out of buffers\n"));
          return;
        }
        NdisQueryBufferSafe(mdl, (PVOID) &buffer, &buffer_length, NormalPagePriority);
        buffer_offset = 0;
      }
      csum += GET_NET_PUSHORT(&buffer[buffer_offset]);
    }
  }
  if (i != total_length) // last odd byte
  {
    csum += ((USHORT)buffer[buffer_offset] << 8);
  }
  while (csum & 0xFFFF0000)
    csum = (csum & 0xFFFF) + (csum >> 16);
  *csum_ptr = (USHORT)~GET_NET_USHORT((USHORT)csum);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static ULONG
XenNet_MakePackets(
  struct xennet_info *xi,
  PLIST_ENTRY rx_packet_list
)
{
  USHORT i;
  ULONG packet_count = 0;
  PNDIS_PACKET packet;
  PLIST_ENTRY entry;
  UCHAR psh;
  PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "(packets = %p, packet_count = %d)\n", packets, *packet_count_p));

  XenNet_ParsePacketHeader(&xi->rxpi);
  switch (xi->rxpi.ip_proto)
  {
  case 6:  // TCP
    if (xi->rxpi.split_required)
      break;
    // fallthrough
  case 17:  // UDP
    packet = XenNet_MakePacket(xi);
    if (packet == NULL)
    {
      KdPrint((__DRIVER_NAME "     Ran out of packets\n"));
      xi->stat_rx_no_buffer++;
      packet_count = 0;
      goto done;
    }
    if (xi->rxpi.csum_blank)
      XenNet_SumPacketData(&xi->rxpi, packet);
    if (xi->rxpi.csum_blank || xi->rxpi.data_validated)
    {
      csum_info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)&NDIS_PER_PACKET_INFO_FROM_PACKET(
        packet, TcpIpChecksumPacketInfo);
      csum_info->Receive.NdisPacketTcpChecksumSucceeded = TRUE;
    }
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(rx_packet_list, entry);
    RtlZeroMemory(&xi->rxpi, sizeof(xi->rxpi));
    return 1;
  default:
    packet = XenNet_MakePacket(xi);
    if (packet == NULL)
    {
      KdPrint((__DRIVER_NAME "     Ran out of packets\n"));
      xi->stat_rx_no_buffer++;
      packet_count = 0;
      goto done;
    }
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(rx_packet_list, entry);
    RtlZeroMemory(&xi->rxpi, sizeof(xi->rxpi));
    return 1;
  }

  xi->rxpi.tcp_remaining = xi->rxpi.tcp_length;
  if (MmGetMdlByteCount(xi->rxpi.mdls[0]) > (ULONG)(XN_HDR_SIZE + xi->rxpi.ip4_header_length + xi->rxpi.tcp_header_length))
    xi->rxpi.curr_mdl_offset = XN_HDR_SIZE + xi->rxpi.ip4_header_length + xi->rxpi.tcp_header_length;
  else
    xi->rxpi.curr_mdl = 1;

  /* we can make certain assumptions here as the following code is only for tcp4 */
  psh = xi->rxpi.header[XN_HDR_SIZE + xi->rxpi.ip4_header_length + 13] & 8;
  while (xi->rxpi.tcp_remaining)
  {
    PUCHAR buffer;
    PMDL mdl;
    UINT total_length;
    UINT buffer_length;
    packet = XenNet_MakePacket(xi);
    if (!packet)
    {
      KdPrint((__DRIVER_NAME "     Ran out of packets\n"));
      xi->stat_rx_no_buffer++;
      break; /* we are out of memory - just drop the packets */
    }
    csum_info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)&NDIS_PER_PACKET_INFO_FROM_PACKET(
      packet, TcpIpChecksumPacketInfo);
    csum_info->Receive.NdisPacketTcpChecksumSucceeded = TRUE;
    if (psh)
    {
      NdisGetFirstBufferFromPacketSafe(packet, &mdl, &buffer, &buffer_length, &total_length, NormalPagePriority);
      if (xi->rxpi.tcp_remaining)
      {
        buffer[XN_HDR_SIZE + xi->rxpi.ip4_header_length + 13] &= ~8;
        KdPrint((__DRIVER_NAME "     Seq %d cleared PSH\n", GET_NET_PULONG(&buffer[XN_HDR_SIZE + xi->rxpi.ip4_header_length + 4])));
      }
      else
      {
        buffer[XN_HDR_SIZE + xi->rxpi.ip4_header_length + 13] |= 8;
        KdPrint((__DRIVER_NAME "     Seq %d set PSH\n", GET_NET_PULONG(&buffer[XN_HDR_SIZE + xi->rxpi.ip4_header_length + 4])));
      }
    }
    XenNet_SumPacketData(&xi->rxpi, packet);
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(rx_packet_list, entry);
    packet_count++;
  }

done:
  for (i = 0; i < xi->rxpi.mdl_count; i++)
  {
    NdisAdjustBufferLength(xi->rxpi.mdls[i], PAGE_SIZE);
    XenFreelist_PutPage(&xi->rx_freelist, xi->rxpi.mdls[i]);
  }
  RtlZeroMemory(&xi->rxpi, sizeof(xi->rxpi));  
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (split)\n"));
  return packet_count;
}

#define MAXIMUM_PACKETS_PER_INDICATE 256

// Called at DISPATCH_LEVEL
NDIS_STATUS
XenNet_RxBufferCheck(struct xennet_info *xi)
{
  RING_IDX cons, prod;
  LIST_ENTRY rx_packet_list;
  PLIST_ENTRY entry;
  PNDIS_PACKET packets[MAXIMUM_PACKETS_PER_INDICATE];
  ULONG packet_count = 0;
  PMDL mdl;
  struct netif_rx_response *rxrsp = NULL;
  struct netif_extra_info *ei;
  USHORT id;
  int more_to_do;
  
//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(xi->connected);

  KeAcquireSpinLockAtDpcLevel(&xi->rx_lock);

  InitializeListHead(&rx_packet_list);

  do {
    prod = xi->rx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'prod'. */

    for (cons = xi->rx.rsp_cons; cons != prod; cons++)
    {
      id = (USHORT)(cons & (NET_RX_RING_SIZE - 1));
      ASSERT(xi->rx_mdls[id]);
      mdl = xi->rx_mdls[id];
      xi->rx_mdls[id] = NULL;
      xi->rx_id_free++;
      if (xi->rxpi.extra_info)
      {
        XenFreelist_PutPage(&xi->rx_freelist, mdl);
        ei = (struct netif_extra_info *)RING_GET_RESPONSE(&xi->rx, cons);
        xi->rxpi.extra_info = (BOOLEAN)!!(ei->flags & XEN_NETIF_EXTRA_FLAG_MORE);
        switch (ei->type)
        {
        case XEN_NETIF_EXTRA_TYPE_GSO:
          switch (ei->u.gso.type)
          {
          case XEN_NETIF_GSO_TYPE_TCPV4:
            xi->rxpi.mss = ei->u.gso.size;
            // TODO - put this assertion somewhere ASSERT(header_len + xi->rxpi.mss <= PAGE_SIZE); // this limits MTU to PAGE_SIZE - XN_HEADER_LEN
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
        rxrsp = RING_GET_RESPONSE(&xi->rx, cons);
        if (rxrsp->status <= 0
          || rxrsp->offset + rxrsp->status > PAGE_SIZE)
        {
          KdPrint((__DRIVER_NAME ": Error: rxrsp offset %d, size %d\n",
            rxrsp->offset, rxrsp->status));
          ASSERT(!xi->rxpi.extra_info);
          XenFreelist_PutPage(&xi->rx_freelist, mdl);
          continue;
        }
        ASSERT(rxrsp->id == id);
        if (!xi->rxpi.more_frags) // handling the packet's 1st buffer
        {
          if (rxrsp->flags & NETRXF_csum_blank)
            xi->rxpi.csum_blank = TRUE;
          if (rxrsp->flags & NETRXF_data_validated)
            xi->rxpi.data_validated = TRUE;
        }
        NdisAdjustBufferLength(mdl, rxrsp->status);
        xi->rxpi.mdls[xi->rxpi.mdl_count++] = mdl;
        xi->rxpi.extra_info = (BOOLEAN)!!(rxrsp->flags & NETRXF_extra_info);
        xi->rxpi.more_frags = (BOOLEAN)!!(rxrsp->flags & NETRXF_more_data);
        xi->rxpi.total_length = xi->rxpi.total_length + rxrsp->status;
      }

      /* Packet done, add it to the list */
      if (!xi->rxpi.more_frags && !xi->rxpi.extra_info)
      {
        packet_count += XenNet_MakePackets(xi, &rx_packet_list);
      }
    }
    xi->rx.rsp_cons = cons;
    RING_FINAL_CHECK_FOR_RESPONSES(&xi->rx, more_to_do);
  } while (more_to_do);

  if (xi->rxpi.more_frags || xi->rxpi.extra_info)
    KdPrint((__DRIVER_NAME "     Partial receive (more_frags = %d, extra_info = %d, total_length = %d, mdl_count = %d)\n", xi->rxpi.more_frags, xi->rxpi.extra_info, xi->rxpi.total_length, xi->rxpi.mdl_count));

  /* Give netback more buffers */
  XenNet_RxBufferAlloc(xi);

  KeReleaseSpinLockFromDpcLevel(&xi->rx_lock);

  entry = RemoveHeadList(&rx_packet_list);
  packet_count = 0;
  while (entry != &rx_packet_list)
  {
    packets[packet_count++] = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    entry = RemoveHeadList(&rx_packet_list);
    if (packet_count == MAXIMUM_PACKETS_PER_INDICATE || entry == &rx_packet_list)
    {
      NdisMIndicateReceivePacket(xi->adapter_handle, packets, packet_count);
      packet_count = 0;
    }
  }
  return NDIS_STATUS_SUCCESS;
}

/* called at DISPATCH_LEVEL */
/* it's okay for return packet to be called while resume_state != RUNNING as the packet will simply be added back to the freelist, the grants will be fixed later */
VOID DDKAPI
XenNet_ReturnPacket(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PNDIS_PACKET Packet
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
  PMDL mdl;
  KeAcquireSpinLockAtDpcLevel(&xi->rx_lock);

  NdisUnchainBufferAtBack(Packet, &mdl);
  while (mdl)
  {
    NdisAdjustBufferLength(mdl, PAGE_SIZE);
    XenFreelist_PutPage(&xi->rx_freelist, mdl);
    NdisUnchainBufferAtBack(Packet, &mdl);
  }

  put_packet_on_freelist(xi, Packet);
  xi->rx_outstanding--;

  KeReleaseSpinLockFromDpcLevel(&xi->rx_lock);
  
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
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

  XenFreelist_Dispose(&xi->rx_freelist);

  ASSERT(!xi->connected);

  for (i = 0; i < NET_RX_RING_SIZE; i++)
  {
    if (!xi->rx_mdls[i])
      continue;

    mdl = xi->rx_mdls[i];
    NdisAdjustBufferLength(mdl, PAGE_SIZE);
    XenFreelist_PutPage(&xi->rx_freelist, mdl);
  }
}

VOID
XenNet_RxResumeStart(xennet_info_t *xi)
{
  int i;
  KIRQL old_irql;

  KeAcquireSpinLock(&xi->rx_lock, &old_irql);
  for (i = 0; i < NET_RX_RING_SIZE; i++)
  {
    if (xi->rx_mdls[i])
    {
      XenFreelist_PutPage(&xi->rx_freelist, xi->rx_mdls[i]);
      xi->rx_mdls[i] = NULL;
    }
  }
  XenFreelist_ResumeStart(&xi->rx_freelist);
  xi->rx_id_free = NET_RX_RING_SIZE;
  xi->rx_outstanding = 0;
  KeReleaseSpinLock(&xi->rx_lock, old_irql);
}

VOID
XenNet_RxResumeEnd(xennet_info_t *xi)
{
  KIRQL old_irql;

  KeAcquireSpinLock(&xi->rx_lock, &old_irql);
  XenFreelist_ResumeEnd(&xi->rx_freelist);
  XenNet_RxBufferAlloc(xi);
  KeReleaseSpinLock(&xi->rx_lock, old_irql);
}

BOOLEAN
XenNet_RxInit(xennet_info_t *xi)
{
  int i;

  FUNCTION_ENTER();

  xi->rx_id_free = NET_RX_RING_SIZE;

  for (i = 0; i < NET_RX_RING_SIZE; i++)
  {
    xi->rx_mdls[i] = NULL;
  }

  xi->rx_outstanding = 0;
  XenFreelist_Init(xi, &xi->rx_freelist, &xi->rx_lock);

  XenNet_RxBufferAlloc(xi);

  FUNCTION_EXIT();

  return TRUE;
}

BOOLEAN
XenNet_RxShutdown(xennet_info_t *xi)
{
  KIRQL OldIrql;

  FUNCTION_ENTER();

  KeAcquireSpinLock(&xi->rx_lock, &OldIrql);

  XenNet_RxBufferFree(xi);

  XenFreelist_Dispose(&xi->rx_freelist);

  packet_freelist_dispose(xi);

  /* free RX resources */

  ASSERT(xi->rx_outstanding == 0);

  KeReleaseSpinLock(&xi->rx_lock, OldIrql);

  FUNCTION_EXIT();

  return TRUE;
}
