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
#if (NTDDI_VERSION >= NTDDI_WINXP)
static KDEFERRED_ROUTINE XenNet_RxBufferCheck;
#endif

LONG rx_pb_outstanding = 0;

static __inline shared_buffer_t *
get_pb_from_freelist(struct xennet_info *xi)
{
  NDIS_STATUS status;
  shared_buffer_t *pb;
  PVOID ptr_ref;

  if (stack_pop(xi->rx_pb_stack, &ptr_ref))
  {
    pb = ptr_ref;
    pb->ref_count = 1;
    InterlockedDecrement(&xi->rx_pb_free);
    InterlockedIncrement(&rx_pb_outstanding);
    return pb;
  }

  /* don't allocate a new one if we are shutting down */
  if (xi->shutting_down)
    return NULL;
    
  status = NdisAllocateMemoryWithTag(&pb, sizeof(shared_buffer_t), XENNET_POOL_TAG);
  if (status != STATUS_SUCCESS)
  {
    return NULL;
  }
  status = NdisAllocateMemoryWithTag(&pb->virtual, PAGE_SIZE, XENNET_POOL_TAG);
  if (status != STATUS_SUCCESS)
  {
    NdisFreeMemory(pb, sizeof(shared_buffer_t), 0);
    return NULL;
  }
  pb->gref = (grant_ref_t)xi->vectors.GntTbl_GrantAccess(xi->vectors.context, 0,
            (ULONG)(MmGetPhysicalAddress(pb->virtual).QuadPart >> PAGE_SHIFT), FALSE, INVALID_GRANT_REF, (ULONG)'XNRX');
  if (pb->gref == INVALID_GRANT_REF)
  {
    NdisFreeMemory(pb, sizeof(shared_buffer_t), 0);
    NdisFreeMemory(pb->virtual, PAGE_SIZE, 0);
    return NULL;
  }
  pb->offset = (USHORT)(ULONG_PTR)pb->virtual & (PAGE_SIZE - 1);
  NdisAllocateBuffer(&status, &pb->buffer, xi->rx_buffer_pool, (PUCHAR)pb->virtual, PAGE_SIZE);
  if (status != STATUS_SUCCESS)
  {
    xi->vectors.GntTbl_EndAccess(xi->vectors.context,
        pb->gref, FALSE, (ULONG)'XNRX');
    NdisFreeMemory(pb, sizeof(shared_buffer_t), 0);
    NdisFreeMemory(pb->virtual, PAGE_SIZE, 0);
    return NULL;
  }
  InterlockedIncrement(&rx_pb_outstanding);
  pb->ref_count = 1;
  return pb;
}

static __inline VOID
ref_pb(struct xennet_info *xi, shared_buffer_t *pb)
{
  UNREFERENCED_PARAMETER(xi);
  InterlockedIncrement(&pb->ref_count);
}

static __inline VOID
put_pb_on_freelist(struct xennet_info *xi, shared_buffer_t *pb)
{
  if (InterlockedDecrement(&pb->ref_count) == 0)
  {
    NdisAdjustBufferLength(pb->buffer, PAGE_SIZE);
    NDIS_BUFFER_LINKAGE(pb->buffer) = NULL;
    pb->next = NULL;
    stack_push(xi->rx_pb_stack, pb);
    InterlockedIncrement(&xi->rx_pb_free);
    InterlockedDecrement(&rx_pb_outstanding);
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
    ASSERT(xi->rx_ring_pbs[id] == NULL);
    xi->rx_ring_pbs[id] = page_buf;
    req = RING_GET_REQUEST(&xi->rx, req_prod + i);
    req->id = id;
    req->gref = page_buf->gref;
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

LONG total_allocated_packets = 0;
LARGE_INTEGER last_print_time;

/* lock free */
static PNDIS_PACKET
get_packet_from_freelist(struct xennet_info *xi)
{
  NDIS_STATUS status;
  PNDIS_PACKET packet;

  NdisAllocatePacket(&status, &packet, xi->rx_packet_pool);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint((__DRIVER_NAME "     cannot allocate packet\n"));
    return NULL;
  }
  NDIS_SET_PACKET_HEADER_SIZE(packet, XN_HDR_SIZE);
  NdisZeroMemory(packet->MiniportReservedEx, sizeof(packet->MiniportReservedEx));
  InterlockedIncrement(&total_allocated_packets);
  return packet;
}

/* lock free */
static VOID
put_packet_on_freelist(struct xennet_info *xi, PNDIS_PACKET packet)
{
  LARGE_INTEGER current_time;

  UNREFERENCED_PARAMETER(xi);
  
  InterlockedDecrement(&total_allocated_packets);
  NdisFreePacket(packet);
  KeQuerySystemTime(&current_time);
  if ((int)total_allocated_packets < 0 || (current_time.QuadPart - last_print_time.QuadPart) / 10000 > 1000)
  {
    last_print_time.QuadPart = current_time.QuadPart;
    KdPrint(("total_allocated_packets = %d, rx_outstanding = %d, rx_pb_outstanding = %d, rx_pb_free = %d\n", total_allocated_packets, xi->rx_outstanding, rx_pb_outstanding, xi->rx_pb_free));
  }
}

static PNDIS_PACKET
XenNet_MakePacket(struct xennet_info *xi, packet_info_t *pi)
{
  NDIS_STATUS status;
  PNDIS_PACKET packet;
  PNDIS_BUFFER out_buffer;
  USHORT new_ip4_length;
  PUCHAR header_va;
  ULONG out_remaining;
  ULONG tcp_length;
  ULONG header_extra;
  shared_buffer_t *header_buf;

  //FUNCTION_ENTER();
  
  packet = get_packet_from_freelist(xi);
  if (packet == NULL)
  {
    /* buffers will be freed in MakePackets */
    //KdPrint((__DRIVER_NAME "     No free packets\n"));
    //FUNCTION_EXIT();
    return NULL;
  }
  
  header_buf = NdisAllocateFromNPagedLookasideList(&xi->rx_lookaside_list);
  if (!header_buf)
  {
    KdPrint((__DRIVER_NAME "     No free header buffers\n"));
    put_packet_on_freelist(xi, packet);
    return NULL;
  }
  header_va = (PUCHAR)(header_buf + 1);
  NdisZeroMemory(header_buf, sizeof(shared_buffer_t));
  NdisMoveMemory(header_va, pi->header, pi->header_length);
  //KdPrint((__DRIVER_NAME "     header_length = %d, current_lookahead = %d\n", pi->header_length, xi->current_lookahead));
  //KdPrint((__DRIVER_NAME "     ip4_header_length = %d\n", pi->ip4_header_length));
  //KdPrint((__DRIVER_NAME "     tcp_header_length = %d\n", pi->tcp_header_length));
  /* make sure we satisfy the lookahead requirement */
  XenNet_BuildHeader(pi, header_va, max(MIN_LOOKAHEAD_LENGTH, xi->current_lookahead) + MAX_ETH_HEADER_LENGTH);
  header_extra = pi->header_length - (MAX_ETH_HEADER_LENGTH + pi->ip4_header_length + pi->tcp_header_length);
  ASSERT(pi->header_length <= MAX_ETH_HEADER_LENGTH + MAX_LOOKAHEAD_LENGTH);
  NdisAllocateBuffer(&status, &out_buffer, xi->rx_buffer_pool, header_va, pi->header_length);
  if (status != STATUS_SUCCESS)
  {
    KdPrint((__DRIVER_NAME "     No free header buffers\n"));
    NdisFreeToNPagedLookasideList(&xi->rx_lookaside_list, header_buf);
    put_packet_on_freelist(xi, packet);
    return NULL;
  }
  NdisChainBufferAtBack(packet, out_buffer);
  *(shared_buffer_t **)&packet->MiniportReservedEx[0] = header_buf;
  header_buf->next = pi->curr_pb;

  // TODO: if there are only a few bytes left on the first buffer then add them to the header buffer too... maybe

  //KdPrint((__DRIVER_NAME "     split_required = %d\n", pi->split_required));
  //KdPrint((__DRIVER_NAME "     tcp_length = %d, mss = %d\n", pi->tcp_length, pi->mss));
  //KdPrint((__DRIVER_NAME "     total_length = %d\n", pi->total_length));
  //KdPrint((__DRIVER_NAME "     header_length = %d\n", pi->header_length));
  //KdPrint((__DRIVER_NAME "     header_extra = %d\n", header_extra));
  if (pi->split_required)
  {
    tcp_length = (USHORT)min(pi->mss, pi->tcp_remaining);
    new_ip4_length = (USHORT)(pi->ip4_header_length + pi->tcp_header_length + tcp_length);
    //KdPrint((__DRIVER_NAME "     new_ip4_length = %d\n", new_ip4_length));
    //KdPrint((__DRIVER_NAME "     this tcp_length = %d\n", tcp_length));
    SET_NET_USHORT(&header_va[XN_HDR_SIZE + 2], new_ip4_length);
    SET_NET_ULONG(&header_va[XN_HDR_SIZE + pi->ip4_header_length + 4], pi->tcp_seq);
    pi->tcp_seq += tcp_length;
    pi->tcp_remaining = (USHORT)(pi->tcp_remaining - tcp_length);
    /* part of the packet is already present in the header buffer for lookahead */
    out_remaining = tcp_length - header_extra;
  }
  else
  {
    out_remaining = pi->total_length - pi->header_length;
  }
  //KdPrint((__DRIVER_NAME "     before loop - out_remaining = %d\n", out_remaining));
    
  while (out_remaining != 0)
  {
    ULONG in_buffer_offset;
    ULONG in_buffer_length;
    ULONG out_length;
    
    //KdPrint((__DRIVER_NAME "     in loop - out_remaining = %d, curr_buffer = %p, curr_pb = %p\n", out_remaining, pi->curr_buffer, pi->curr_pb));
    if (!pi->curr_buffer || !pi->curr_pb)
    {
      KdPrint((__DRIVER_NAME "     out of buffers for packet\n"));
      // TODO: free some stuff or we'll leak
      return NULL;
    }
    NdisQueryBufferOffset(pi->curr_buffer, &in_buffer_offset, &in_buffer_length);
    out_length = min(out_remaining, in_buffer_length - pi->curr_mdl_offset);
    NdisCopyBuffer(&status, &out_buffer, xi->rx_buffer_pool, pi->curr_buffer, pi->curr_mdl_offset, out_length);
    ASSERT(status == STATUS_SUCCESS); //TODO: properly handle error
    NdisChainBufferAtBack(packet, out_buffer);
    ref_pb(xi, pi->curr_pb);
    pi->curr_mdl_offset = (USHORT)(pi->curr_mdl_offset + out_length);
    if (pi->curr_mdl_offset == in_buffer_length)
    {
      NdisGetNextBuffer(pi->curr_buffer, &pi->curr_buffer);
      pi->curr_pb = pi->curr_pb->next;
      pi->curr_mdl_offset = 0;
    }
    out_remaining -= out_length;
  }
  if (pi->split_required)
  {
    XenNet_SumIpHeader(header_va, pi->ip4_header_length);
  }
  NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
  if (header_extra > 0)
    pi->header_length -= header_extra;
  ASSERT(*(shared_buffer_t **)&packet->MiniportReservedEx[0]);
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
  UINT data_length;
  UINT buffer_length;
  USHORT buffer_offset;
  ULONG csum;
  PUSHORT csum_ptr;
  USHORT remaining;
  USHORT ip4_length;
  BOOLEAN csum_span = TRUE; /* when the USHORT to be checksummed spans a buffer */
  
  //FUNCTION_ENTER();

  NdisGetFirstBufferFromPacketSafe(packet, &mdl, &buffer, &buffer_length, &total_length, NormalPagePriority);
  ASSERT(mdl);

  ip4_length = GET_NET_PUSHORT(&buffer[XN_HDR_SIZE + 2]);
  data_length = ip4_length + XN_HDR_SIZE;
  
  if ((USHORT)data_length > total_length)
  {
    KdPrint((__DRIVER_NAME "     Size Mismatch %d (ip4_length + XN_HDR_SIZE) != %d (total_length)\n", ip4_length + XN_HDR_SIZE, total_length));
    return FALSE;
  }

  switch (pi->ip_proto)
  {
  case 6:
    ASSERT(buffer_length >= (USHORT)(XN_HDR_SIZE + pi->ip4_header_length + 17));
    csum_ptr = (USHORT *)&buffer[XN_HDR_SIZE + pi->ip4_header_length + 16];
    break;
  case 17:
    ASSERT(buffer_length >= (USHORT)(XN_HDR_SIZE + pi->ip4_header_length + 7));
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
  
  csum_span = FALSE;
  buffer_offset = i = XN_HDR_SIZE + pi->ip4_header_length;
  while (i < data_length)
  {
    /* don't include the checksum field itself in the calculation */
    if ((pi->ip_proto == 6 && i == XN_HDR_SIZE + pi->ip4_header_length + 16) || (pi->ip_proto == 17 && i == XN_HDR_SIZE + pi->ip4_header_length + 6))
    {
      /* we know that this always happens in the header buffer so we are guaranteed the full two bytes */
      i += 2;
      buffer_offset += 2;
      continue;
    }
    if (csum_span)
    {
      /* the other half of the next bit */
      ASSERT(buffer_offset == 0);
      csum += (USHORT)buffer[buffer_offset];
      csum_span = FALSE;
      i += 1;
      buffer_offset += 1;
    }
    else if (buffer_offset == buffer_length - 1)
    {
      /* deal with a buffer ending on an odd byte boundary */
      csum += (USHORT)buffer[buffer_offset] << 8;
      csum_span = TRUE;
      i += 1;
      buffer_offset += 1;
    }
    else
    {
      csum += GET_NET_PUSHORT(&buffer[buffer_offset]);
      i += 2;
      buffer_offset += 2;
    }
    if (buffer_offset == buffer_length && i < total_length)
    {
      NdisGetNextBuffer(mdl, &mdl);
      if (mdl == NULL)
      {
        KdPrint((__DRIVER_NAME "     Ran out of buffers\n"));
        return FALSE; // should never happen
      }
      NdisQueryBufferSafe(mdl, &buffer, &buffer_length, NormalPagePriority);
      ASSERT(buffer_length);
      buffer_offset = 0;
    }
  }
      
  while (csum & 0xFFFF0000)
    csum = (csum & 0xFFFF) + (csum >> 16);
  
  if (set_csum)
  {
    *csum_ptr = (USHORT)~GET_NET_USHORT((USHORT)csum);
  }
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
  PLIST_ENTRY rx_packet_list,
  packet_info_t *pi
)
{
  ULONG packet_count = 0;
  PNDIS_PACKET packet;
  PLIST_ENTRY entry;
  UCHAR psh;
  PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;
  ULONG parse_result;  
  //PNDIS_BUFFER buffer;
  shared_buffer_t *page_buf;

  //FUNCTION_ENTER();

  parse_result = XenNet_ParsePacketHeader(pi, NULL, 0);
  
  if (!XenNet_FilterAcceptPacket(xi, pi))
  {
    goto done;
  }

  switch (pi->ip_proto)
  {
  case 6:  // TCP
    if (pi->split_required)
      break;
    // fallthrough
  case 17:  // UDP
    packet = XenNet_MakePacket(xi, pi);
    if (packet == NULL)
    {
      //KdPrint((__DRIVER_NAME "     Ran out of packets\n"));
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
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(rx_packet_list, entry);
    packet_count = 1;
    goto done;
  default:
    packet = XenNet_MakePacket(xi, pi);
    if (packet == NULL)
    {
      //KdPrint((__DRIVER_NAME "     Ran out of packets\n"));
      xi->stat_rx_no_buffer++;
      packet_count = 0;
      goto done;
    }
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(rx_packet_list, entry);
    packet_count = 1;
    goto done;
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
    packet = XenNet_MakePacket(xi, pi);
    if (!packet)
    {
      //KdPrint((__DRIVER_NAME "     Ran out of packets\n"));
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
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(rx_packet_list, entry);
    packet_count++;
  }

done:
  page_buf = pi->first_pb;
  while (page_buf)
  {
    shared_buffer_t *next_pb;

    next_pb = page_buf->next;
    put_pb_on_freelist(xi, page_buf);
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

/* We limit the number of packets per interrupt so that acks get a chance
under high rx load. The DPC is immediately re-scheduled */
/* this isn't actually done right now */
#define MAX_BUFFERS_PER_INTERRUPT 256

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
  ULONG buffer_count = 0;
  struct netif_extra_info *ei;
  USHORT id;
  int more_to_do = FALSE;
  packet_info_t *pi = &xi->rxpi[KeGetCurrentProcessorNumber() & 0xff];
  //NDIS_STATUS status;
  shared_buffer_t *page_buf;
  shared_buffer_t *head_buf = NULL;
  shared_buffer_t *tail_buf = NULL;
  shared_buffer_t *last_buf = NULL;
  BOOLEAN extra_info_flag = FALSE;
  BOOLEAN more_data_flag = FALSE;
  PNDIS_BUFFER buffer;

  UNREFERENCED_PARAMETER(dpc);
  UNREFERENCED_PARAMETER(arg1);
  UNREFERENCED_PARAMETER(arg2);

  //FUNCTION_ENTER();

  if (!xi->connected)
    return; /* a delayed DPC could let this come through... just do nothing */

  InitializeListHead(&rx_packet_list);

  /* get all the buffers off the ring as quickly as possible so the lock is held for a minimum amount of time */

  KeAcquireSpinLockAtDpcLevel(&xi->rx_lock);
  
  if (xi->rx_shutting_down)
  {
    /* there is a chance that our Dpc had been queued just before the shutdown... */
    KeReleaseSpinLockFromDpcLevel(&xi->rx_lock);
    return;
  }

  if (xi->rx_partial_buf)
  {
    head_buf = xi->rx_partial_buf;
    tail_buf = xi->rx_partial_buf;
    while (tail_buf->next)
      tail_buf = tail_buf->next;
    more_data_flag = xi->rx_partial_more_data_flag;
    extra_info_flag = xi->rx_partial_extra_info_flag;
    xi->rx_partial_buf = NULL;
  }

  do {
    prod = xi->rx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'prod'. */

    for (cons = xi->rx.rsp_cons; cons != prod; cons++)
    {
      id = (USHORT)(cons & (NET_RX_RING_SIZE - 1));
      page_buf = xi->rx_ring_pbs[id];
      ASSERT(page_buf);
      xi->rx_ring_pbs[id] = NULL;
      xi->rx_id_free++;
      memcpy(&page_buf->rsp, RING_GET_RESPONSE(&xi->rx, cons), max(sizeof(struct netif_rx_response), sizeof(struct netif_extra_info)));
      if (!extra_info_flag)
      {
        if (page_buf->rsp.status <= 0
          || page_buf->rsp.offset + page_buf->rsp.status > PAGE_SIZE)
        {
          KdPrint((__DRIVER_NAME "     Error: rsp offset %d, size %d\n",
            page_buf->rsp.offset, page_buf->rsp.status));
          ASSERT(!extra_info_flag);
          put_pb_on_freelist(xi, page_buf);
          continue;
        }
      }
      
      if (!head_buf)
      {
        head_buf = page_buf;
        tail_buf = page_buf;
      }
      else
      {
        tail_buf->next = page_buf;
        tail_buf = page_buf;
      }
      page_buf->next = NULL;

      if (extra_info_flag)
      {
        ei = (struct netif_extra_info *)&page_buf->rsp;
        extra_info_flag = ei->flags & XEN_NETIF_EXTRA_FLAG_MORE;
      }
      else
      {
        more_data_flag = (BOOLEAN)(page_buf->rsp.flags & NETRXF_more_data);
        extra_info_flag = (BOOLEAN)(page_buf->rsp.flags & NETRXF_extra_info);
      }
      
      if (!extra_info_flag && !more_data_flag)
        last_buf = page_buf;
      buffer_count++;
    }
    xi->rx.rsp_cons = cons;

    /* Give netback more buffers */
    XenNet_FillRing(xi);

    more_to_do = RING_HAS_UNCONSUMED_RESPONSES(&xi->rx);
    if (!more_to_do)
    {
      xi->rx.sring->rsp_event = xi->rx.rsp_cons + 1;
      KeMemoryBarrier();
      more_to_do = RING_HAS_UNCONSUMED_RESPONSES(&xi->rx);
    }
  } while (more_to_do);
  
  /* anything past last_buf belongs to an incomplete packet... */
  if (last_buf && last_buf->next)
  {
    KdPrint((__DRIVER_NAME "     Partial receive\n"));
    xi->rx_partial_buf = last_buf->next;
    xi->rx_partial_more_data_flag = more_data_flag;
    xi->rx_partial_extra_info_flag = extra_info_flag;
    last_buf->next = NULL;
  }

  KeReleaseSpinLockFromDpcLevel(&xi->rx_lock);

#if 0
do this on a timer or something during packet manufacture
  if (buffer_count >= MAX_BUFFERS_PER_INTERRUPT)
  {
    /* fire again immediately */
    KdPrint((__DRIVER_NAME "     Dpc Duration Exceeded\n"));
    KeInsertQueueDpc(&xi->rx_dpc, NULL, NULL);
    //xi->vectors.EvtChn_Sync(xi->vectors.context, XenNet_RxQueueDpcSynchronized, xi);
  }
#endif

  /* make packets out of the buffers */
  page_buf = head_buf;
  extra_info_flag = FALSE;
  more_data_flag = FALSE;
  while (page_buf)
  {
    shared_buffer_t *next_buf = page_buf->next;

    page_buf->next = NULL;
    if (extra_info_flag)
    {
      //KdPrint((__DRIVER_NAME "     processing extra info\n"));
      ei = (struct netif_extra_info *)&page_buf->rsp;
      extra_info_flag = ei->flags & XEN_NETIF_EXTRA_FLAG_MORE;
      switch (ei->type)
      {
      case XEN_NETIF_EXTRA_TYPE_GSO:
        switch (ei->u.gso.type)
        {
        case XEN_NETIF_GSO_TYPE_TCPV4:
          pi->mss = ei->u.gso.size;
          //KdPrint((__DRIVER_NAME "     mss = %d\n", pi->mss));
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
      put_pb_on_freelist(xi, page_buf);
    }
    else
    {
      ASSERT(!page_buf->rsp.offset);
      if (!more_data_flag) // handling the packet's 1st buffer
      {
        if (page_buf->rsp.flags & NETRXF_csum_blank)
          pi->csum_blank = TRUE;
        if (page_buf->rsp.flags & NETRXF_data_validated)
          pi->data_validated = TRUE;
      }
      buffer = page_buf->buffer;
      NdisAdjustBufferLength(buffer, page_buf->rsp.status);
      //KdPrint((__DRIVER_NAME "     buffer = %p, pb = %p\n", buffer, page_buf));
      if (pi->first_pb)
      {
        ASSERT(pi->curr_pb);
        //KdPrint((__DRIVER_NAME "     additional buffer\n"));
        pi->curr_pb->next = page_buf;
        pi->curr_pb = page_buf;
        ASSERT(pi->curr_buffer);
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
      extra_info_flag = (BOOLEAN)(page_buf->rsp.flags & NETRXF_extra_info);
      more_data_flag = (BOOLEAN)(page_buf->rsp.flags & NETRXF_more_data);
      pi->total_length = pi->total_length + page_buf->rsp.status;
    }

    /* Packet done, add it to the list */
    if (!more_data_flag && !extra_info_flag)
    {
      pi->curr_pb = pi->first_pb;
      pi->curr_buffer = pi->first_buffer;
      XenNet_MakePackets(xi, &rx_packet_list, pi);
    }

    page_buf = next_buf;
  }
  ASSERT(!more_data_flag && !extra_info_flag);
      
  xi->stat_rx_ok += packet_count;

  /* indicate packets to NDIS */
  entry = RemoveHeadList(&rx_packet_list);
  packet_count = 0;
  while (entry != &rx_packet_list)
  {
    PNDIS_PACKET packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    ASSERT(*(shared_buffer_t **)&packet->MiniportReservedEx[0]);

    packets[packet_count++] = packet;
    InterlockedIncrement(&xi->rx_outstanding);
    entry = RemoveHeadList(&rx_packet_list);
    if (packet_count == MAXIMUM_PACKETS_PER_INDICATE || entry == &rx_packet_list)
    {
      NdisMIndicateReceivePacket(xi->adapter_handle, packets, packet_count);
      packet_count = 0;
    }
  }
  //FUNCTION_EXIT();
}

/* called at DISPATCH_LEVEL */
/* it's okay for return packet to be called while resume_state != RUNNING as the packet will simply be added back to the freelist, the grants will be fixed later */
VOID
XenNet_ReturnPacket(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PNDIS_PACKET Packet
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
  PNDIS_BUFFER buffer;
  shared_buffer_t *page_buf = *(shared_buffer_t **)&Packet->MiniportReservedEx[0];

  //FUNCTION_ENTER();

  //KdPrint((__DRIVER_NAME "     page_buf = %p\n", page_buf));

  NdisUnchainBufferAtFront(Packet, &buffer);
  
  while (buffer)
  {
    shared_buffer_t *next_buf;
    ASSERT(page_buf);
    next_buf = page_buf->next;
    if (!page_buf->virtual)
    {
      /* this isn't actually a share_buffer, it is some memory allocated for the header - just free it */
      PUCHAR va;
      UINT len;
      NdisQueryBufferSafe(buffer, &va, &len, NormalPagePriority);
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
  InterlockedDecrement(&xi->rx_outstanding);
  
  if (!xi->rx_outstanding && xi->rx_shutting_down)
    KeSetEvent(&xi->packet_returned_event, IO_NO_INCREMENT, FALSE);

  KeAcquireSpinLockAtDpcLevel(&xi->rx_lock);

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
    if (xi->rx_ring_pbs[i] != NULL)
    {
      put_pb_on_freelist(xi, xi->rx_ring_pbs[i]);
      xi->rx_ring_pbs[i] = NULL;
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
    xi->vectors.GntTbl_EndAccess(xi->vectors.context,
        pb->gref, FALSE, (ULONG)'XNRX');
    NdisFreeMemory(pb->virtual, PAGE_SIZE, 0);
    NdisFreeMemory(pb, sizeof(shared_buffer_t), 0);
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
  //NDIS_STATUS status;
  int i;
  
  xi->rx_id_free = NET_RX_RING_SIZE;
  xi->rx_outstanding = 0;

  for (i = 0; i < NET_RX_RING_SIZE; i++)
  {
    xi->rx_ring_pbs[i] = NULL;
  }
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
  KeSetImportanceDpc(&xi->rx_dpc, HighImportance);
  //KeInitializeDpc(&xi->rx_timer_dpc, XenNet_RxTimerDpc, xi);
  status = NdisAllocateMemoryWithTag((PVOID)&xi->rxpi, sizeof(packet_info_t) * NdisSystemProcessorCount(), XENNET_POOL_TAG);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint(("NdisAllocateMemoryWithTag failed with 0x%x\n", status));
    return FALSE;
  }
  NdisZeroMemory(xi->rxpi, sizeof(packet_info_t) * NdisSystemProcessorCount());

  stack_new(&xi->rx_pb_stack, NET_RX_RING_SIZE * 4);

  XenNet_BufferAlloc(xi);
  
  NdisAllocatePacketPool(&status, &xi->rx_packet_pool, NET_RX_RING_SIZE * 4,
    PROTOCOL_RESERVED_SIZE_IN_PACKET);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint(("NdisAllocatePacketPool failed with 0x%x\n", status));
    return FALSE;
  }

  NdisInitializeNPagedLookasideList(&xi->rx_lookaside_list, NULL, NULL, 0,
    MAX_ETH_HEADER_LENGTH + MAX_LOOKAHEAD_LENGTH + sizeof(shared_buffer_t), XENNET_POOL_TAG, 0);
  
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
#if (NTDDI_VERSION >= NTDDI_WINXP)
  KeFlushQueuedDpcs();
#endif

  while (xi->rx_outstanding)
  {
    KdPrint((__DRIVER_NAME "     Waiting for all packets to be returned\n"));
    KeWaitForSingleObject(&xi->packet_returned_event, Executive, KernelMode, FALSE, NULL);
  }

  //KeAcquireSpinLock(&xi->rx_lock, &old_irql);

  NdisFreeMemory(xi->rxpi, sizeof(packet_info_t) * NdisSystemProcessorCount(), 0);

  XenNet_BufferFree(xi);

  NdisFreePacketPool(xi->rx_packet_pool);

  NdisDeleteNPagedLookasideList(&xi->rx_lookaside_list);

  stack_delete(xi->rx_pb_stack, NULL, NULL);
  //KeReleaseSpinLock(&xi->rx_lock, old_irql);

  FUNCTION_EXIT();

  return TRUE;
}
