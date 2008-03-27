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
    {
      KdPrint((__DRIVER_NAME "     Added %d out of %d buffers to rx ring\n", i, batch_target));
      KdPrint((__DRIVER_NAME "     (rx_outstanding = %d)\n", xi->rx_outstanding));
      break;
    }
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


//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  ProfTime_RxBufferAlloc.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_RxBufferAlloc++;
#endif

  return NDIS_STATUS_SUCCESS;
}

#define __NET_USHORT_BYTE_0(x) ((USHORT)(x & 0xFF))
#define __NET_USHORT_BYTE_1(x) ((USHORT)((PUCHAR)&x)[1] & 0xFF)

#define GET_NET_USHORT(x) ((__NET_USHORT_BYTE_0(x) << 8) | __NET_USHORT_BYTE_1(x))
#define SET_NET_USHORT(y, x) *((USHORT *)&(y)) = ((__NET_USHORT_BYTE_0(x) << 8) | __NET_USHORT_BYTE_1(x))

#define GET_NET_ULONG(x) ((GET_NET_USHORT(x) << 16) | GET_NET_USHORT(((PUCHAR)&x)[2]))
#define SET_NET_ULONG(y, x) *((ULONG *)&(y)) = ((GET_NET_USHORT(x) << 16) | GET_NET_USHORT(((PUCHAR)&x)[2]))

static VOID
XenNet_ParseHeader(
  struct xennet_info *xi
)
{
  UINT header_length;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(xi->rxpi.mdls[0]);
  
  NdisQueryBufferSafe(xi->rxpi.mdls[0], &xi->rxpi.header, &header_length, NormalPagePriority);

  if (header_length < XN_HDR_SIZE + 20 + 20) // minimum size of first buffer is ETH + IP + TCP header
  {
    return;
  }
  
  switch (GET_NET_USHORT(xi->rxpi.header[12])) // L2 protocol field
  {
  case 0x0800:
    xi->rxpi.ip_version = (xi->rxpi.header[XN_HDR_SIZE + 0] & 0xF0) >> 4;
    if (xi->rxpi.ip_version != 4)
    {
      KdPrint((__DRIVER_NAME "     ip_version = %d\n", xi->rxpi.ip_version));
      return;
    }
    xi->rxpi.ip4_header_length = (xi->rxpi.header[XN_HDR_SIZE + 0] & 0x0F) << 2;
    if (header_length < (ULONG)(xi->rxpi.ip4_header_length + 20))
    {
      KdPrint((__DRIVER_NAME "     first packet is only %d long, must be >= %d\n", XN_HDR_SIZE + header_length, (ULONG)(XN_HDR_SIZE + xi->rxpi.ip4_header_length + 20)));
      // we need to do something conclusive here...
      return;
    }
    break;
  default:
//    KdPrint((__DRIVER_NAME "     Not IP\n"));
    return;
  }
  xi->rxpi.ip_proto = xi->rxpi.header[XN_HDR_SIZE + 9];
  switch (xi->rxpi.ip_proto)
  {
  case 6:  // TCP
  case 17: // UDP
    break;
  default:
    return;
  }
  xi->rxpi.ip4_length = GET_NET_USHORT(xi->rxpi.header[XN_HDR_SIZE + 2]);
  xi->rxpi.tcp_header_length = (xi->rxpi.header[XN_HDR_SIZE + xi->rxpi.ip4_header_length + 12] & 0xf0) >> 2;
  xi->rxpi.tcp_length = xi->rxpi.ip4_length - xi->rxpi.ip4_header_length - xi->rxpi.tcp_header_length;
  xi->rxpi.tcp_remaining = xi->rxpi.tcp_length;
  xi->rxpi.tcp_seq = GET_NET_ULONG(xi->rxpi.header[XN_HDR_SIZE + xi->rxpi.ip4_header_length + 4]);
  if (xi->rxpi.mss > 0 && xi->rxpi.tcp_length > xi->rxpi.mss)
    xi->rxpi.split_required = TRUE;
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static VOID
XenNet_SumIpHeader(
  struct xennet_info *xi,  
  PNDIS_PACKET packet
)
{
  PMDL mdl;
  UINT total_length;
  UINT buffer_length;
  PUCHAR buffer;
  ULONG csum = 0;
  USHORT i;

  NdisGetFirstBufferFromPacketSafe(packet, &mdl, &buffer, &buffer_length, &total_length, NormalPagePriority);
  ASSERT(mdl);

  buffer[XN_HDR_SIZE + 10] = 0;
  buffer[XN_HDR_SIZE + 11] = 0;
  for (i = 0; i < xi->rxpi.ip4_header_length; i += 2)
  {
    csum += GET_NET_USHORT(buffer[XN_HDR_SIZE + i]);
  }
  while (csum & 0xFFFF0000)
    csum = (csum & 0xFFFF) + (csum >> 16);
  csum = ~csum;
  SET_NET_USHORT(buffer[XN_HDR_SIZE + 10], csum);
}


/*
 Windows appears to insist that the checksum on received packets is correct, and won't
 believe us when we lie about it, which happens when the packet is generated on the
 same bridge in Dom0. Doh!
 This is only for TCP and UDP packets. IP checksums appear to be correct anyways.
*/
static VOID
XenNet_SumTcpPacket(
  struct xennet_info *xi,  
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

  #if defined(XEN_PROFILE)
  ProfCount_RxPacketsCsumOffload++;
  #endif

  NdisGetFirstBufferFromPacketSafe(packet, &mdl, &buffer, &buffer_length, &total_length, NormalPagePriority);
  ASSERT(mdl);

  ip4_length = GET_NET_USHORT(buffer[XN_HDR_SIZE + 2]);

  if ((USHORT)(ip4_length + XN_HDR_SIZE) != total_length)
  {
    KdPrint((__DRIVER_NAME "     Size Mismatch %d (ip4_length + XN_HDR_SIZE) != %d (total_length)\n", ip4_length + XN_HDR_SIZE, total_length));
  }

  csum_ptr = (USHORT *)&buffer[XN_HDR_SIZE + xi->rxpi.ip4_header_length + 16];
  *csum_ptr = 0;

  csum = 0;
  csum += GET_NET_USHORT(buffer[XN_HDR_SIZE + 12]) + GET_NET_USHORT(buffer[XN_HDR_SIZE + 14]); // seq
  csum += GET_NET_USHORT(buffer[XN_HDR_SIZE + 16]) + GET_NET_USHORT(buffer[XN_HDR_SIZE + 18]); // ack
  csum += ((USHORT)buffer[XN_HDR_SIZE + 9]);

  remaining = ip4_length - xi->rxpi.ip4_header_length;

  csum += remaining;

  for (buffer_offset = i = XN_HDR_SIZE + xi->rxpi.ip4_header_length; i < total_length - 1; i += 2, buffer_offset += 2)
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
//      KdPrint((__DRIVER_NAME "     New buffer - unaligned...\n"));
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
        NdisQueryBufferSafe(mdl, &buffer, &buffer_length, NormalPagePriority);
        buffer_offset = 0;
      }
      csum += GET_NET_USHORT(buffer[buffer_offset]);
//KdPrint((__DRIVER_NAME "     %04X\n", GET_NET_USHORT(buffer[buffer_offset])));
    }
  }
  if (i != total_length) // last odd byte
  {
//KdPrint((__DRIVER_NAME "    *%04X\n", (USHORT)buffer[buffer_offset] << 8));
    csum += ((USHORT)buffer[buffer_offset] << 8);
  }
  while (csum & 0xFFFF0000)
    csum = (csum & 0xFFFF) + (csum >> 16);
  *csum_ptr = (USHORT)~GET_NET_USHORT(csum);

//  KdPrint((__DRIVER_NAME "     csum = %04x\n", *csum_ptr));

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static PUCHAR
XenNet_GetData(
  struct xennet_info *xi,
  USHORT req_length,
  PUSHORT length
)
{
  PNDIS_BUFFER mdl = xi->rxpi.mdls[xi->rxpi.curr_mdl];
  PUCHAR buffer = (PUCHAR)MmGetMdlVirtualAddress(mdl) + xi->rxpi.curr_mdl_offset;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  *length = (USHORT)min(req_length, MmGetMdlByteCount(mdl) - xi->rxpi.curr_mdl_offset);

//  KdPrint((__DRIVER_NAME "     req_length = %d, length = %d\n", req_length, *length));

  xi->rxpi.curr_mdl_offset = xi->rxpi.curr_mdl_offset + *length;
  if (xi->rxpi.curr_mdl_offset == MmGetMdlByteCount(mdl))
  {
    xi->rxpi.curr_mdl++;
    xi->rxpi.curr_mdl_offset = 0;
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return buffer;
}

static PNDIS_PACKET
XenNet_MakePacket(
  struct xennet_info *xi
)
{
  PNDIS_PACKET packet;
  PUCHAR in_buffer;
  PNDIS_BUFFER out_mdl;
  PUCHAR out_buffer;
  USHORT out_offset;
  USHORT out_remaining;
  USHORT length;
  USHORT new_ip4_length;
  NDIS_STATUS status;
  USHORT i;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  NdisAllocatePacket(&status, &packet, xi->packet_pool);
  ASSERT(status == NDIS_STATUS_SUCCESS);
  xi->rx_outstanding++;
  NDIS_SET_PACKET_HEADER_SIZE(packet, XN_HDR_SIZE);

  if (!xi->rxpi.split_required)
  {
    for (i = 0; i < xi->rxpi.mdl_count; i++)
      NdisChainBufferAtBack(packet, xi->rxpi.mdls[i]);
    NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
  }
  else
  {
    out_mdl = get_page_from_freelist(xi);
    out_buffer = MmGetMdlVirtualAddress(out_mdl);
    out_offset = XN_HDR_SIZE + xi->rxpi.ip4_header_length + xi->rxpi.tcp_header_length;
    out_remaining = min(xi->rxpi.mss, xi->rxpi.tcp_remaining);
    NdisAdjustBufferLength(out_mdl, out_offset + out_remaining);
    memcpy(out_buffer, xi->rxpi.header, out_offset);
    new_ip4_length = out_remaining + xi->rxpi.ip4_header_length + xi->rxpi.tcp_header_length;
    SET_NET_USHORT(out_buffer[XN_HDR_SIZE + 2], new_ip4_length);
    SET_NET_ULONG(out_buffer[XN_HDR_SIZE + xi->rxpi.ip4_header_length + 4], xi->rxpi.tcp_seq);
    xi->rxpi.tcp_seq += out_remaining;
    xi->rxpi.tcp_remaining = xi->rxpi.tcp_remaining - out_remaining;
    do 
    {
      ASSERT(xi->rxpi.curr_mdl < xi->rxpi.mdl_count);
      in_buffer = XenNet_GetData(xi, out_remaining, &length);
      memcpy(&out_buffer[out_offset], in_buffer, length);
      out_remaining = out_remaining - length;
      out_offset = out_offset + length;
    } while (out_remaining != 0); // && in_buffer != NULL);
    NdisChainBufferAtBack(packet, out_mdl);
    XenNet_SumIpHeader(xi, packet);
    NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (%p)\n", packet));
  return packet;
}

static VOID
XenNet_MakePackets(
  struct xennet_info *xi,
  PNDIS_PACKET *packets,
  PULONG packet_count_p
)
{
  USHORT i;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "(packets = %p, packet_count = %d)\n", packets, *packet_count_p));

  XenNet_ParseHeader(xi);
  switch (xi->rxpi.ip_proto)
  {
  case 6:  // TCP
    if (xi->rxpi.split_required)
      break;
    // fallthrough
  case 17:  // UDP
    packets[*packet_count_p] = XenNet_MakePacket(xi);
    if (xi->rxpi.csum_calc_required)
      XenNet_SumTcpPacket(xi, packets[*packet_count_p]);
    (*packet_count_p)++;
//    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (TCP/UDP)\n"));
    return;
  default:
    packets[*packet_count_p] = XenNet_MakePacket(xi);
    (*packet_count_p)++;
//    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (Other)\n"));
    return;
  }
//  KdPrint((__DRIVER_NAME "     splitting packet\n"));
  xi->rxpi.tcp_remaining = xi->rxpi.tcp_length;
  if (MmGetMdlByteCount(xi->rxpi.mdls[0]) > (ULONG)(XN_HDR_SIZE + xi->rxpi.ip4_header_length + xi->rxpi.tcp_header_length))
    xi->rxpi.curr_mdl_offset = XN_HDR_SIZE + xi->rxpi.ip4_header_length + xi->rxpi.tcp_header_length;
  else
    xi->rxpi.curr_mdl = 1;

  while (xi->rxpi.tcp_remaining)
  {
//    KdPrint((__DRIVER_NAME "     tcp_remaining = %d\n", xi->rxpi.tcp_remaining));
    packets[*packet_count_p] = XenNet_MakePacket(xi);
    XenNet_SumTcpPacket(xi, packets[*packet_count_p]);
    (*packet_count_p)++;
  }
  ASSERT(xi->rxpi.curr_mdl == xi->rxpi.mdl_count);
//  KdPrint((__DRIVER_NAME "     tcp_remaining = %d\n", xi->rxpi.tcp_remaining));
  // TODO: restore psh status to last packet
  for (i = 0; i < xi->rxpi.mdl_count; i++)
  {
    NdisAdjustBufferLength(xi->rxpi.mdls[i], PAGE_SIZE);
    put_page_on_freelist(xi, xi->rxpi.mdls[i]);
  }
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (split)\n"));
}

// Called at DISPATCH_LEVEL
NDIS_STATUS
XenNet_RxBufferCheck(struct xennet_info *xi)
{
  RING_IDX cons, prod;
  PNDIS_PACKET packets[NET_RX_RING_SIZE];
  ULONG packet_count;
  PMDL mdl;
  int moretodo;
  struct netif_rx_response *rxrsp = NULL;
  struct netif_extra_info *ei;
  USHORT id;
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
  do {
    ASSERT(cycles++ < 256);
    prod = xi->rx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'rp'. */

    for (cons = xi->rx.rsp_cons; cons != prod; cons++)
    {
      ASSERT(cycles++ < 256);
      id = (USHORT)(cons & (NET_RX_RING_SIZE - 1));
      mdl = xi->rx_buffers[id];
      xi->rx_buffers[id] = NULL;
      xi->rx_id_free++;
      if (xi->rxpi.extra_info)
      {
        put_page_on_freelist(xi, mdl);
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
          put_page_on_freelist(xi, mdl);
          continue;
        }
        ASSERT(rxrsp->id == id);
        if (!xi->rxpi.more_frags) // handling the packet's 1st buffer
        {
          
          if (rxrsp->flags & (NETRXF_csum_blank|NETRXF_data_validated) && xi->config_csum)
          {
            //KdPrint((__DRIVER_NAME "     RX csum blank = %d, validated = %d\n", !!(rxrsp->flags & NETRXF_csum_blank), !!(rxrsp->flags & NETRXF_data_validated)));
            if (rxrsp->flags & NETRXF_csum_blank)
              xi->rxpi.csum_calc_required = TRUE;
          }
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
        XenNet_MakePackets(xi, packets, &packet_count);
        RtlZeroMemory(&xi->rxpi, sizeof(xi->rxpi));
      }
    }
    ASSERT(packet_count < NET_RX_RING_SIZE);
    xi->rx.rsp_cons = prod;
    RING_FINAL_CHECK_FOR_RESPONSES(&xi->rx, moretodo);
  } while (moretodo);

  /* Give netback more buffers */
  XenNet_RxBufferAlloc(xi);

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

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (rx_outstanding = %d)\n", xi->rx_outstanding));

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

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ " (%p)\n", Packet));

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

  xi->rx_outstanding--;
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

  xi->rx_outstanding = 0;
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
