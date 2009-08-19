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

static __inline shared_buffer_t *
get_pb_from_freelist(struct xennet_info *xi)
{
  shared_buffer_t *pb;
  
  if (xi->rx_pb_free == 0)
  {
    KdPrint((__DRIVER_NAME "     Out of pb's\n"));    
    return NULL;
  }
  xi->rx_pb_free--;

  pb = &xi->rx_pbs[xi->rx_pb_list[xi->rx_pb_free]];
  pb->ref_count++;
  return pb;
}

static __inline VOID
ref_pb(struct xennet_info *xi, shared_buffer_t *pb)
{
  UNREFERENCED_PARAMETER(xi);
  pb->ref_count++;
  //KdPrint((__DRIVER_NAME "     incremented pb %p ref to %d\n", pb, pb->ref_count));
}

static __inline VOID
put_pb_on_freelist(struct xennet_info *xi, shared_buffer_t *pb)
{
  pb->ref_count--;
  //KdPrint((__DRIVER_NAME "     decremented pb %p ref to %d\n", pb, pb->ref_count));
  if (pb->ref_count == 0)
  {
    //KdPrint((__DRIVER_NAME "     freeing pb %p\n", pb, pb->ref_count));
    NdisAdjustBufferLength(pb->buffer, PAGE_SIZE);
    NDIS_BUFFER_LINKAGE(pb->buffer) = NULL;
    pb->next = NULL;
    xi->rx_pb_list[xi->rx_pb_free] = pb->id;
    xi->rx_pb_free++;
  }
}

// Called at DISPATCH_LEVEL with rx lock held
static NDIS_STATUS
XenNet_FillRing(struct xennet_info *xi)
{
  unsigned short id;
  shared_buffer_t *page_buf;
  ULONG i, notify;
  ULONG batch_target;
  RING_IDX req_prod = xi->rx.req_prod_pvt;
  netif_rx_request_t *req;

  //FUNCTION_ENTER();

  batch_target = xi->rx_target - (req_prod - xi->rx.rsp_cons);

  if (batch_target < (xi->rx_target >> 2))
  {
    //FUNCTION_EXIT();
    return NDIS_STATUS_SUCCESS; /* only refill if we are less than 3/4 full already */
  }

  for (i = 0; i < batch_target; i++)
  {
    page_buf = get_pb_from_freelist(xi);
    if (!page_buf)
    {
      KdPrint((__DRIVER_NAME "     Added %d out of %d buffers to rx ring (no free pages)\n", i, batch_target));
      break;
    }
    xi->rx_id_free--;

    /* Give to netback */
    id = (USHORT)((req_prod + i) & (NET_RX_RING_SIZE - 1));
    ASSERT(xi->rx_ring_pbs[id] == (USHORT)0xFFFF);
    xi->rx_ring_pbs[id] = page_buf->id;
    req = RING_GET_REQUEST(&xi->rx, req_prod + i);
    req->id = id;
    req->gref = (grant_ref_t)(page_buf->logical.QuadPart >> PAGE_SHIFT);
    ASSERT(req->gref != INVALID_GRANT_REF);
  }
  KeMemoryBarrier();
  xi->rx.req_prod_pvt = req_prod + i;
  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xi->rx, notify);
  if (notify)
  {
    xi->vectors.EvtChn_Notify(xi->vectors.context, xi->event_channel);
  }

  //FUNCTION_EXIT();

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
    NdisAllocatePacket(&status, &packet, xi->rx_packet_pool);
    if (status != NDIS_STATUS_SUCCESS)
    {
      KdPrint((__DRIVER_NAME "     cannot allocate packet\n"));
      return NULL;
    }
    NDIS_SET_PACKET_HEADER_SIZE(packet, XN_HDR_SIZE);
    NdisZeroMemory(packet->MiniportReservedEx, sizeof(packet->MiniportReservedEx));
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
  PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;
  //ASSERT(!KeTestSpinLock(&xi->rx_lock));

  if (xi->rx_packet_free == NET_RX_RING_SIZE * 2)
  {
    KdPrint((__DRIVER_NAME "     packet free list full - releasing packet\n"));
    NdisFreePacket(packet);
    return;
  }
  csum_info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)&NDIS_PER_PACKET_INFO_FROM_PACKET(
    packet, TcpIpChecksumPacketInfo);
  csum_info->Value = 0;
  NdisZeroMemory(packet->MiniportReservedEx, sizeof(packet->MiniportReservedEx));
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
  NDIS_STATUS status;
  PNDIS_PACKET packet;
  PNDIS_BUFFER out_buffer;
  USHORT new_ip4_length;
  PUCHAR header_va;
  packet_info_t *pi = &xi->rxpi;

  //FUNCTION_ENTER();

  if (!pi->split_required)
  {
    PNDIS_BUFFER buffer;
    shared_buffer_t *page_buf;
    
    //KdPrint((__DRIVER_NAME "     !split_required\n"));

    packet = get_packet_from_freelist(xi);
    if (packet == NULL)
    {
      /* buffers will be freed in MakePackets */
      KdPrint((__DRIVER_NAME "     No free packets\n"));
      //FUNCTION_EXIT();
      return NULL;
    }
    xi->rx_outstanding++;

    // what if we needed to consolidate the header? maybe should put that on instead of all the buffers...
    *(shared_buffer_t **)&packet->MiniportReservedEx[sizeof(LIST_ENTRY)] = pi->first_pb;
    
    buffer = pi->first_buffer;
    page_buf = pi->first_pb;
    //KdPrint((__DRIVER_NAME "     packet = %p, first_buffer = %p, first_pb = %p\n", packet, buffer, page_buf));
    while (buffer)
    {
      PNDIS_BUFFER next_buffer;
      //KdPrint((__DRIVER_NAME "     buffer = %p\n", buffer));

      NdisGetNextBuffer(buffer, &next_buffer);
      NDIS_BUFFER_LINKAGE(buffer) = NULL;
      NdisChainBufferAtBack(packet, buffer);
      //ref_pb(xi, page_buf);
      
      buffer = next_buffer;
      page_buf = page_buf->next;
    }

    NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
  }
  else
  {
    ULONG out_remaining;
    shared_buffer_t *header_buf;
    
    //KdPrint((__DRIVER_NAME "     split_required\n"));

    packet = get_packet_from_freelist(xi);
    if (packet == NULL)
    {
      //FUNCTION_EXIT();
      return NULL;
    }
    xi->rx_outstanding++;

    //status = NdisAllocateMemoryWithTag((PUCHAR *)&header_buf, sizeof(shared_buffer_t) + pi->header_length, XENNET_POOL_TAG);
    ASSERT(sizeof(shared_buffer_t) + pi->header_length < LOOKASIDE_LIST_ALLOC_SIZE);
    header_buf = NdisAllocateFromNPagedLookasideList(&xi->rx_lookaside_list);
    ASSERT(header_buf); // lazy
    header_va = (PUCHAR)(header_buf + 1);
    NdisZeroMemory(header_buf, sizeof(shared_buffer_t));
    NdisMoveMemory(header_va, pi->header, pi->header_length);

    // TODO: if there are only a few bytes left on the first buffer then add them to the header buffer too

    NdisAllocateBuffer(&status, &out_buffer, xi->rx_buffer_pool, header_va, pi->header_length);
    //KdPrint((__DRIVER_NAME "     about to add buffer with length = %d\n", MmGetMdlByteCount(out_buffer)));
    NdisChainBufferAtBack(packet, out_buffer);
    *(shared_buffer_t **)&packet->MiniportReservedEx[sizeof(LIST_ENTRY)] = header_buf;
    header_buf->next = pi->curr_pb;

    //KdPrint((__DRIVER_NAME "     header_length = %d\n", pi->header_length));
    //KdPrint((__DRIVER_NAME "     curr_mdl_offset = %d\n", pi->curr_mdl_offset));
    //KdPrint((__DRIVER_NAME "     tcp_remaining = %d\n", pi->tcp_remaining));
    
    //KdPrint((__DRIVER_NAME "     tcp_remaining = %d\n", pi->tcp_remaining));
    out_remaining = (USHORT)min(pi->mss, pi->tcp_remaining);
    new_ip4_length = (USHORT)(pi->ip4_header_length + pi->tcp_header_length + out_remaining);
    SET_NET_USHORT(&header_va[XN_HDR_SIZE + 2], new_ip4_length);
    SET_NET_ULONG(&header_va[XN_HDR_SIZE + pi->ip4_header_length + 4], pi->tcp_seq);
    pi->tcp_seq += out_remaining;
    pi->tcp_remaining = (USHORT)(pi->tcp_remaining - out_remaining);
    do 
    {
      ULONG in_buffer_offset;
      ULONG in_buffer_length;
      ULONG out_length;
      //UINT tmp_packet_length;
      //KdPrint((__DRIVER_NAME "     curr_buffer = %p\n", pi->curr_buffer));
      //KdPrint((__DRIVER_NAME "     curr_pb = %p\n", pi->curr_pb));
      //KdPrint((__DRIVER_NAME "     out_remaining = %d\n", out_remaining));
      NdisQueryBufferOffset(pi->curr_buffer, &in_buffer_offset, &in_buffer_length);
      out_length = min(out_remaining, in_buffer_length - pi->curr_mdl_offset);
      //KdPrint((__DRIVER_NAME "     out_length = %d\n", out_length));
      NdisCopyBuffer(&status, &out_buffer, xi->rx_buffer_pool, pi->curr_buffer, pi->curr_mdl_offset, out_length);
      //TODO: check status
      //KdPrint((__DRIVER_NAME "     about to add buffer with length = %d\n", MmGetMdlByteCount(out_buffer)));
      NdisChainBufferAtBack(packet, out_buffer);
      //NdisQueryPacketLength(packet, &tmp_packet_length);
      //KdPrint((__DRIVER_NAME "     current packet length = %d\n", tmp_packet_length));
      ref_pb(xi, pi->curr_pb);
      pi->curr_mdl_offset = (USHORT)(pi->curr_mdl_offset + out_length);
      if (pi->curr_mdl_offset == in_buffer_length)
      {
        NdisGetNextBuffer(pi->curr_buffer, &pi->curr_buffer);
        pi->curr_pb = pi->curr_pb->next;
        pi->curr_mdl_offset = 0;
      }
      out_remaining -= out_length;
    } while (out_remaining != 0);
    XenNet_SumIpHeader(header_va, pi->ip4_header_length);
    NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
  }

  //FUNCTION_EXIT();
  return packet;
}

/*
 Windows appears to insist that the checksum on received packets is correct, and won't
 believe us when we lie about it, which happens when the packet is generated on the
 same bridge in Dom0. Doh!
 This is only for TCP and UDP packets. IP checksums appear to be correct anyways.
*/

static BOOLEAN
XenNet_SumPacketData(
  packet_info_t *pi,
  PNDIS_PACKET packet,
  BOOLEAN set_csum
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
  
  //FUNCTION_ENTER();

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
    //FUNCTION_EXIT();
    return FALSE; // should never happen
  }

  if (set_csum)  
    *csum_ptr = 0;

  csum = 0;
  csum += GET_NET_PUSHORT(&buffer[XN_HDR_SIZE + 12]) + GET_NET_PUSHORT(&buffer[XN_HDR_SIZE + 14]); // src
  csum += GET_NET_PUSHORT(&buffer[XN_HDR_SIZE + 16]) + GET_NET_PUSHORT(&buffer[XN_HDR_SIZE + 18]); // dst
  csum += ((USHORT)buffer[XN_HDR_SIZE + 9]);

  remaining = ip4_length - pi->ip4_header_length;

  csum += remaining;

  for (buffer_offset = i = XN_HDR_SIZE + pi->ip4_header_length; i < total_length - 1; i += 2, buffer_offset += 2)
  {
    /* don't include the checksum field itself in the calculation */
    if ((pi->ip_proto == 6 && i == XN_HDR_SIZE + pi->ip4_header_length + 16) || (pi->ip_proto == 17 && i == XN_HDR_SIZE + pi->ip4_header_length + 6))
      continue;
    if (buffer_offset == buffer_length - 1) // deal with a buffer ending on an odd byte boundary
    {
      csum += (USHORT)buffer[buffer_offset] << 8;
      NdisGetNextBuffer(mdl, &mdl);
      if (mdl == NULL)
      {
        KdPrint((__DRIVER_NAME "     Ran out of buffers\n"));
        return FALSE; // should never happen
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
          return FALSE; // should never happen
        }
        NdisQueryBufferSafe(mdl, (PVOID) &buffer, &buffer_length, NormalPagePriority);
        buffer_offset = 0;
      }
      csum += GET_NET_PUSHORT(&buffer[buffer_offset]);
    }
  }
  if (i != total_length) // last odd byte
  {
    if (buffer_offset >= buffer_length)
    {
      NdisGetNextBuffer(mdl, &mdl);
      if (mdl == NULL)
      {
        KdPrint((__DRIVER_NAME "     Ran out of buffers\n"));
        return FALSE; // should never happen
      }
      NdisQueryBufferSafe(mdl, (PVOID)&buffer, &buffer_length, NormalPagePriority);
      buffer_offset = 0;
    }
    csum += ((USHORT)buffer[buffer_offset] << 8);
  }
  while (csum & 0xFFFF0000)
    csum = (csum & 0xFFFF) + (csum >> 16);
  
  if (set_csum)
    *csum_ptr = (USHORT)~GET_NET_USHORT((USHORT)csum);
  else
  {
    //FUNCTION_EXIT();
    return (BOOLEAN)(*csum_ptr == (USHORT)~GET_NET_USHORT((USHORT)csum));
  }
  //FUNCTION_EXIT();
  return TRUE;
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
  ULONG parse_result;  
  packet_info_t *pi = &xi->rxpi;
  PNDIS_BUFFER buffer;
  shared_buffer_t *page_buf;

  //FUNCTION_ENTER();

  parse_result = XenNet_ParsePacketHeader(pi, NULL, 0);
  
  //KdPrint((__DRIVER_NAME "     ip4_length = %d, tcp_length = %d\n", pi->ip4_length, pi->tcp_length));

  if ((xi->packet_filter & NDIS_PACKET_TYPE_MULTICAST)
    && !(xi->packet_filter & NDIS_PACKET_TYPE_ALL_MULTICAST)
    && (pi->header[0] & 0x01)
    && !(pi->header[0] == 0xFF && pi->header[1] == 0xFF && pi->header[2] == 0xFF
        && pi->header[3] == 0xFF && pi->header[4] == 0xFF && pi->header[5] == 0xFF))
  {
    for (i = 0; i < xi->multicast_list_size; i++)
    {
      if (memcmp(xi->multicast_list[i], pi->header, 6) == 0)
        break;
    }
    if (i == xi->multicast_list_size)
    {
      //KdPrint((__DRIVER_NAME "     Packet not for my MAC address\n"));
      goto done;
    }
  }
  switch (pi->ip_proto)
  {
  case 6:  // TCP
    if (pi->split_required)
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

    if (parse_result == PARSE_OK)
    {
      csum_info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)&NDIS_PER_PACKET_INFO_FROM_PACKET(
        packet, TcpIpChecksumPacketInfo);
      if (pi->csum_blank || pi->data_validated)
      {
        if (xi->setting_csum.V4Receive.TcpChecksum && pi->ip_proto == 6)
        {
          if (!pi->tcp_has_options || xi->setting_csum.V4Receive.TcpOptionsSupported)
          {
            csum_info->Receive.NdisPacketTcpChecksumSucceeded = TRUE;
          }
        } else if (xi->setting_csum.V4Receive.UdpChecksum && pi->ip_proto == 17)
        {
          csum_info->Receive.NdisPacketUdpChecksumSucceeded = TRUE;
        }
        if (pi->csum_blank)
        {
          XenNet_SumPacketData(pi, packet, TRUE);
        }
      }
      else if (xi->config_csum_rx_check)
      {
        if (xi->setting_csum.V4Receive.TcpChecksum && pi->ip_proto == 6)
        {
          if (XenNet_SumPacketData(pi, packet, FALSE))
          {
            csum_info->Receive.NdisPacketTcpChecksumSucceeded = TRUE;
          }
          else
          {
            csum_info->Receive.NdisPacketTcpChecksumFailed = TRUE;
          }
        } else if (xi->setting_csum.V4Receive.UdpChecksum && pi->ip_proto == 17)
        {
          if (XenNet_SumPacketData(pi, packet, FALSE))
          {
            csum_info->Receive.NdisPacketUdpChecksumSucceeded = TRUE;
          }
          else
          {
            csum_info->Receive.NdisPacketUdpChecksumFailed = TRUE;
          }
        }
      }
    }
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[0];
    InsertTailList(rx_packet_list, entry);
    XenNet_ClearPacketInfo(pi);
    //FUNCTION_EXIT();
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
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[0];
    InsertTailList(rx_packet_list, entry);
    XenNet_ClearPacketInfo(pi);
    //FUNCTION_EXIT();
    return 1;
  }

  /* synchronise the pb with the buffer */
  buffer = pi->first_buffer;
  pi->curr_pb = pi->first_pb;
  //KdPrint((__DRIVER_NAME "     first_buffer = %p, curr_buffer = %p, first_pb = %p, curr_pb = %p\n",
  //  pi->first_buffer, pi->curr_buffer, pi->first_pb, pi->curr_pb));
  
  while (pi->curr_pb != NULL && buffer != pi->curr_buffer)
  {
    NdisGetNextBuffer(buffer, &buffer);
    pi->curr_pb = pi->curr_pb->next;
    //KdPrint((__DRIVER_NAME "     buffer = %p, curr_pb = %p\n", buffer, pi->curr_pb));
  }
  
  pi->tcp_remaining = pi->tcp_length;

  /* we can make certain assumptions here as the following code is only for tcp4 */
  psh = pi->header[XN_HDR_SIZE + pi->ip4_header_length + 13] & 8;
  while (pi->tcp_remaining)
  {
    PUCHAR header_va;
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
    if (xi->setting_csum.V4Receive.TcpChecksum)
    {
      csum_info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)&NDIS_PER_PACKET_INFO_FROM_PACKET(
        packet, TcpIpChecksumPacketInfo);
      csum_info->Receive.NdisPacketTcpChecksumSucceeded = TRUE;
    }
    if (psh)
    {
      NdisGetFirstBufferFromPacketSafe(packet, &mdl, &header_va, &buffer_length, &total_length, NormalPagePriority);
      if (pi->tcp_remaining)
        header_va[XN_HDR_SIZE + pi->ip4_header_length + 13] &= ~8;
      else
        header_va[XN_HDR_SIZE + pi->ip4_header_length + 13] |= 8;
    }
    XenNet_SumPacketData(pi, packet, TRUE);
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[0];
    InsertTailList(rx_packet_list, entry);
    packet_count++;
  }

done:
  //buffer = pi->first_buffer;
  page_buf = pi->first_pb;
  while (page_buf)
  {
    //PNDIS_BUFFER next_buffer;
    shared_buffer_t *next_pb;

    //NdisGetNextBuffer(buffer, &next_buffer);
    next_pb = page_buf->next;

    //NdisFreeBuffer(buffer);
    put_pb_on_freelist(xi, page_buf);
    
    //buffer = next_buffer;
    page_buf = next_pb;
  }
  XenNet_ClearPacketInfo(pi);
  //FUNCTION_EXIT();
  return packet_count;
}

static BOOLEAN
XenNet_RxQueueDpcSynchronized(PVOID context)
{
  struct xennet_info *xi = context;

  KeInsertQueueDpc(&xi->rx_dpc, NULL, NULL);
  
  return TRUE;
}

#define MAXIMUM_PACKETS_PER_INDICATE 32
/*
We limit the number of packets per interrupt so that acks get a chance
under high rx load. The DPC is immediately re-scheduled */

#define MAX_PACKETS_PER_INTERRUPT 64

// Called at DISPATCH_LEVEL
static VOID
XenNet_RxBufferCheck(PKDPC dpc, PVOID context, PVOID arg1, PVOID arg2)
{
  struct xennet_info *xi = context;
  RING_IDX cons, prod;
  LIST_ENTRY rx_packet_list;
  PLIST_ENTRY entry;
  PNDIS_PACKET packets[MAXIMUM_PACKETS_PER_INDICATE];
  ULONG packet_count = 0;
  struct netif_rx_response *rxrsp = NULL;
  struct netif_extra_info *ei;
  USHORT id;
  int more_to_do = FALSE;
  packet_info_t *pi = &xi->rxpi;
  //NDIS_STATUS status;
  shared_buffer_t *page_buf;
  PNDIS_BUFFER buffer;

  UNREFERENCED_PARAMETER(dpc);
  UNREFERENCED_PARAMETER(arg1);
  UNREFERENCED_PARAMETER(arg2);

  //FUNCTION_ENTER();

  ASSERT(xi->connected);

  KeAcquireSpinLockAtDpcLevel(&xi->rx_lock);
  
  if (xi->rx_shutting_down)
  {
    /* there is a chance that our Dpc had been queued just before the shutdown... */
    KeReleaseSpinLockFromDpcLevel(&xi->rx_lock);
    return;
  }
  InitializeListHead(&rx_packet_list);

  do {
    prod = xi->rx.sring->rsp_prod;
//KdPrint((__DRIVER_NAME "     prod - cons = %d\n", prod - xi->rx.rsp_cons));    
    KeMemoryBarrier(); /* Ensure we see responses up to 'prod'. */

    for (cons = xi->rx.rsp_cons; cons != prod && packet_count < MAX_PACKETS_PER_INTERRUPT; cons++)
    {
      id = (USHORT)(cons & (NET_RX_RING_SIZE - 1));
      ASSERT(xi->rx_ring_pbs[id] != (USHORT)0xFFFF);
      page_buf = &xi->rx_pbs[xi->rx_ring_pbs[id]];
      xi->rx_ring_pbs[id] = 0xFFFF;
      xi->rx_id_free++;
      //KdPrint((__DRIVER_NAME "     got page_buf %p with id %d from ring at id %d\n", page_buf, page_buf->id, id));
      if (pi->extra_info)
      {
        //KdPrint((__DRIVER_NAME "     processing extra info\n"));
        put_pb_on_freelist(xi, page_buf);
        ei = (struct netif_extra_info *)RING_GET_RESPONSE(&xi->rx, cons);
        pi->extra_info = (BOOLEAN)!!(ei->flags & XEN_NETIF_EXTRA_FLAG_MORE);
        switch (ei->type)
        {
        case XEN_NETIF_EXTRA_TYPE_GSO:
          switch (ei->u.gso.type)
          {
          case XEN_NETIF_GSO_TYPE_TCPV4:
            pi->mss = ei->u.gso.size;
            // TODO - put this assertion somewhere ASSERT(header_len + pi->mss <= PAGE_SIZE); // this limits MTU to PAGE_SIZE - XN_HEADER_LEN
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
          KdPrint((__DRIVER_NAME "     Error: rxrsp offset %d, size %d\n",
            rxrsp->offset, rxrsp->status));
          ASSERT(!pi->extra_info);
          put_pb_on_freelist(xi, page_buf);
          continue;
        }
        ASSERT(!rxrsp->offset);
        ASSERT(rxrsp->id == id);
        if (!pi->more_frags) // handling the packet's 1st buffer
        {
          if (rxrsp->flags & NETRXF_csum_blank)
            pi->csum_blank = TRUE;
          if (rxrsp->flags & NETRXF_data_validated)
            pi->data_validated = TRUE;
        }
        //NdisAllocateBuffer(&status, &buffer, xi->rx_buffer_pool, (PUCHAR)page_buf->virtual + rxrsp->offset, rxrsp->status);
        //KdPrint((__DRIVER_NAME "     buffer = %p, offset = %d, len = %d\n", buffer, rxrsp->offset, rxrsp->status));
        //ASSERT(status == NDIS_STATUS_SUCCESS); // lazy
        buffer = page_buf->buffer;
        NdisAdjustBufferLength(buffer, rxrsp->status);
        if (pi->first_pb)
        {
          //KdPrint((__DRIVER_NAME "     additional buffer\n"));
          pi->curr_pb->next = page_buf;
          pi->curr_pb = page_buf;
          NDIS_BUFFER_LINKAGE(pi->curr_buffer) = buffer;
          pi->curr_buffer = buffer;
        }
        else
        {
          pi->first_pb = page_buf;
          pi->curr_pb = page_buf;
          pi->first_buffer = buffer;
          pi->curr_buffer = buffer;
        }
        pi->mdl_count++;
        pi->extra_info = (BOOLEAN)!!(rxrsp->flags & NETRXF_extra_info);
        pi->more_frags = (BOOLEAN)!!(rxrsp->flags & NETRXF_more_data);
        pi->total_length = pi->total_length + rxrsp->status;
      }

      /* Packet done, add it to the list */
      if (!pi->more_frags && !pi->extra_info)
      {
        packet_count += XenNet_MakePackets(xi, &rx_packet_list);
      }
    }
    xi->rx.rsp_cons = cons;

    if (packet_count >= MAX_PACKETS_PER_INTERRUPT)
      break;

    more_to_do = RING_HAS_UNCONSUMED_RESPONSES(&xi->rx);
    if (!more_to_do)
    {
      xi->rx.sring->rsp_event = xi->rx.rsp_cons + 1;
      mb();
      more_to_do = RING_HAS_UNCONSUMED_RESPONSES(&xi->rx);
    }
  } while (more_to_do);

  if (pi->more_frags || pi->extra_info)
    KdPrint((__DRIVER_NAME "     Partial receive (more_frags = %d, extra_info = %d, total_length = %d, mdl_count = %d)\n", pi->more_frags, pi->extra_info, pi->total_length, pi->mdl_count));

  /* Give netback more buffers */
  XenNet_FillRing(xi);

  if (packet_count >= MAX_PACKETS_PER_INTERRUPT)
  {
    /* fire again immediately */
    xi->vectors.EvtChn_Sync(xi->vectors.context, XenNet_RxQueueDpcSynchronized, xi);
  }

  //KdPrint((__DRIVER_NAME "     packet_count = %d, page_count = %d, avg_page_count = %d, event = %d\n", packet_count, page_count, xi->avg_page_count / 128, event));

  KeReleaseSpinLockFromDpcLevel(&xi->rx_lock);

  entry = RemoveHeadList(&rx_packet_list);
  packet_count = 0;
  while (entry != &rx_packet_list)
  {
    PNDIS_PACKET packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[0]);
    packets[packet_count++] = packet;
    entry = RemoveHeadList(&rx_packet_list);
    if (packet_count == MAXIMUM_PACKETS_PER_INDICATE || entry == &rx_packet_list)
    {
      //KdPrint((__DRIVER_NAME "     Indicating\n"));
      NdisMIndicateReceivePacket(xi->adapter_handle, packets, packet_count);
      packet_count = 0;
    }
  }
  //FUNCTION_EXIT();
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
  PNDIS_BUFFER buffer;
  shared_buffer_t *page_buf = *(shared_buffer_t **)&Packet->MiniportReservedEx[sizeof(LIST_ENTRY)];

  //FUNCTION_ENTER();

  //KdPrint((__DRIVER_NAME "     page_buf = %p\n", page_buf));

  KeAcquireSpinLockAtDpcLevel(&xi->rx_lock);

  NdisUnchainBufferAtFront(Packet, &buffer);
  while (buffer)
  {
    shared_buffer_t *next_buf = page_buf->next;
    if (!page_buf->virtual)
    {
      /* this isn't actually a share_buffer, it is some memory allocated for the header - just free it */
      PUCHAR va;
      UINT len;
      NdisQueryBufferSafe(buffer, &va, &len, NormalPagePriority);
      //KdPrint((__DRIVER_NAME "     freeing header buffer %p\n", va - sizeof(shared_buffer_t)));
      //NdisFreeMemory(va - sizeof(shared_buffer_t), len + sizeof(shared_buffer_t), 0);
      NdisFreeToNPagedLookasideList(&xi->rx_lookaside_list, va - sizeof(shared_buffer_t));
      NdisFreeBuffer(buffer);
    }
    else
    {
      //KdPrint((__DRIVER_NAME "     returning page_buf %p with id %d\n", page_buf, page_buf->id));
      if (buffer != page_buf->buffer)
        NdisFreeBuffer(buffer);
      put_pb_on_freelist(xi, page_buf);
    }
    NdisUnchainBufferAtFront(Packet, &buffer);
    page_buf = next_buf;
  }  

  put_packet_on_freelist(xi, Packet);
  xi->rx_outstanding--;
  
  if (!xi->rx_outstanding && xi->rx_shutting_down)
    KeSetEvent(&xi->packet_returned_event, IO_NO_INCREMENT, FALSE);

  XenNet_FillRing(xi);

  KeReleaseSpinLockFromDpcLevel(&xi->rx_lock);

  //FUNCTION_EXIT();
}

/*
   Free all Rx buffers (on halt, for example) 
   The ring must be stopped at this point.
*/

static VOID
XenNet_PurgeRing(struct xennet_info *xi)
{
  int i;
  for (i = 0; i < NET_RX_RING_SIZE; i++)
  {
    if (xi->rx_ring_pbs[i] != 0xFFFF)
    {
      put_pb_on_freelist(xi, &xi->rx_pbs[xi->rx_ring_pbs[i]]);
      xi->rx_ring_pbs[i] = 0xFFFF;
    }
  }
}

static VOID
XenNet_BufferFree(struct xennet_info *xi)
{
  shared_buffer_t *pb;

  XenNet_PurgeRing(xi);

  while ((pb = get_pb_from_freelist(xi)) != NULL)
  {
    NdisFreeBuffer(pb->buffer);
    NdisMFreeSharedMemory(xi->adapter_handle, PAGE_SIZE, TRUE, pb->virtual, pb->logical);
  }
}

VOID
XenNet_RxResumeStart(xennet_info_t *xi)
{
  KIRQL old_irql;

  FUNCTION_ENTER();

  KeAcquireSpinLock(&xi->rx_lock, &old_irql);
  XenNet_PurgeRing(xi);
  KeReleaseSpinLock(&xi->rx_lock, old_irql);
  
  FUNCTION_EXIT();
}

VOID
XenNet_BufferAlloc(xennet_info_t *xi)
{
  NDIS_STATUS status;
  int i;
  
  xi->rx_id_free = NET_RX_RING_SIZE;
  xi->rx_outstanding = 0;

  for (i = 0; i < NET_RX_RING_SIZE; i++)
  {
    xi->rx_ring_pbs[i] = 0xFFFF;
  }
  
  for (i = 0; i < RX_PAGE_BUFFERS; i++)
  {
    xi->rx_pbs[i].id = (USHORT)i;
    NdisMAllocateSharedMemory(xi->adapter_handle, PAGE_SIZE, TRUE, &xi->rx_pbs[i].virtual, &xi->rx_pbs[i].logical);
    NdisAllocateBuffer(&status, &xi->rx_pbs[i].buffer, xi->rx_buffer_pool, (PUCHAR)xi->rx_pbs[i].virtual, PAGE_SIZE);
    if (status != STATUS_SUCCESS)
      break;
    xi->rx_pbs[i].ref_count = 1; /* when we put it back it will go to zero */
    put_pb_on_freelist(xi, &xi->rx_pbs[i]);
  }
  if (i == 0)
    KdPrint((__DRIVER_NAME "     Unable to allocate any SharedMemory buffers\n"));
}


VOID
XenNet_RxResumeEnd(xennet_info_t *xi)
{
  KIRQL old_irql;

  FUNCTION_ENTER();

  KeAcquireSpinLock(&xi->rx_lock, &old_irql);
  //XenNet_BufferAlloc(xi);
  XenNet_FillRing(xi);
  KeReleaseSpinLock(&xi->rx_lock, old_irql);
  
  FUNCTION_EXIT();
}

BOOLEAN
XenNet_RxInit(xennet_info_t *xi)
{
  NDIS_STATUS status;

  FUNCTION_ENTER();

  xi->rx_shutting_down = FALSE;
  KeInitializeSpinLock(&xi->rx_lock);
  KeInitializeEvent(&xi->packet_returned_event, SynchronizationEvent, FALSE);
  KeInitializeTimer(&xi->rx_timer);
  KeInitializeDpc(&xi->rx_dpc, XenNet_RxBufferCheck, xi);
  KeSetTargetProcessorDpc(&xi->rx_dpc, 0);
  //KeSetImportanceDpc(&xi->rx_dpc, HighImportance);
  //KeInitializeDpc(&xi->rx_timer_dpc, XenNet_RxTimerDpc, xi);

  XenNet_BufferAlloc(xi);
  
  NdisAllocatePacketPool(&status, &xi->rx_packet_pool, NET_RX_RING_SIZE * 4,
    PROTOCOL_RESERVED_SIZE_IN_PACKET);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint(("NdisAllocatePacketPool failed with 0x%x\n", status));
    return FALSE;
  }

  NdisInitializeNPagedLookasideList(&xi->rx_lookaside_list, NULL, NULL, 0, LOOKASIDE_LIST_ALLOC_SIZE, XENNET_POOL_TAG, 0);
  
  XenNet_FillRing(xi);

  FUNCTION_EXIT();

  return TRUE;
}

BOOLEAN
XenNet_RxShutdown(xennet_info_t *xi)
{
  KIRQL old_irql;

  FUNCTION_ENTER();

  KeAcquireSpinLock(&xi->rx_lock, &old_irql);
  xi->rx_shutting_down = TRUE;
  KeReleaseSpinLock(&xi->rx_lock, old_irql);

  if (xi->config_rx_interrupt_moderation)
  {
    KeCancelTimer(&xi->rx_timer);
  }

  KeRemoveQueueDpc(&xi->rx_dpc);
  KeFlushQueuedDpcs();

  while (xi->rx_outstanding)
  {
    KdPrint((__DRIVER_NAME "     Waiting for all packets to be returned\n"));
    KeWaitForSingleObject(&xi->packet_returned_event, Executive, KernelMode, FALSE, NULL);
  }

  //KeAcquireSpinLock(&xi->rx_lock, &old_irql);

  XenNet_BufferFree(xi);

  packet_freelist_dispose(xi);

  NdisFreePacketPool(xi->rx_packet_pool);

  NdisDeleteNPagedLookasideList(&xi->rx_lookaside_list);

  //KeReleaseSpinLock(&xi->rx_lock, old_irql);

  FUNCTION_EXIT();

  return TRUE;
}
