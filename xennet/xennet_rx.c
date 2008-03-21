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
      break;
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

//KdPrint((__DRIVER_NAME "     Added %d out of %d buffers to rx ring\n", i, batch_target));

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  ProfTime_RxBufferAlloc.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_RxBufferAlloc++;
#endif

  return NDIS_STATUS_SUCCESS;
}

static VOID
XenNet_SplitRxPacket(
 PNDIS_PACKET *packets,
 PULONG packet_count,
 ULONG total_packet_length
)
{
  ULONG mss = PtrToUlong(NDIS_PER_PACKET_INFO_FROM_PACKET(packets[*packet_count], TcpLargeSendPacketInfo));
  ULONG header_length = 54; //TODO: actually calculate this from the TCP header
  ULONG tcp_length = total_packet_length - header_length;
  ULONG remaining = tcp_length;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  KdPrint((__DRIVER_NAME "     mss = %d\n", mss));

  while (remaining)
  {
    // take the buffers off of the current packet
    KdPrint((__DRIVER_NAME "     Remaining = %d\n", remaining));

    if (remaining > mss)
    {
      // tcp length = mss;
      remaining -= mss;
    }
    else
    {
      // tcp length = remaining
      remaining = 0;
    }
    // do some creative stuff here... clone the header of the previous packet and update the various fields
    // append the remaining data buffers
    // increment the packet count
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return;
}

#define __NET_USHORT_BYTE_0(x) ((USHORT)(x & 0xFF))
#define __NET_USHORT_BYTE_1(x) ((USHORT)((PUCHAR)&x)[1] & 0xFF)
#define NET_USHORT(x) ((__NET_USHORT_BYTE_0(x) << 8) | __NET_USHORT_BYTE_1(x))

static VOID
XenNet_SplitLargePackets(
  PNDIS_PACKET *packets,
  ULONG packet_count,
  PULONG new_packets,
  USHORT ip4_length,
  USHORT ip4_header_length,
  USHORT tcp_header_length
)
{
  PUCHAR header;
  PNDIS_PACKET first_packet;
  PNDIS_PACKET curr_packet;

  new_packets = 0;

  header = buffer;
  remaining = ip4_length - ip4_header_length - tcp_header_length;
  // save psh status of packet
  while (remaining)
  {
    *((PUSHORT)&buffer[XN_HDR_SIZE + 2]) = NET_USHORT(mss);
    tcp_length = min(remaining, mss);
    remaining -= tcp_length;

      // clear psh of old packet

    NdisAllocatePacket(&status, &packets[packet_count + 1], xi->packet_pool);
    ASSERT(status == NDIS_STATUS_SUCCESS);
    NDIS_SET_PACKET_HEADER_SIZE(packets[packet_count + 1], XN_HDR_SIZE);

    new_buffer_mdl = get_page_from_freelist(xi);
    new_buffer = MmGetMdlVirtualAddress(new_buffer_mdl);
    memcpy(new_buffer, buffer, XN_HDR_SIZE + ip4_header_length + tcp_header_length);
    *((PUSHORT)&new_header[XN_HDR_SIZE + 2]) = NET_USHORT(tcp_length);
    // fix tcp sequence of new packet
    new_remaining = tcp_length;
    while (new_remaining > 0)
    {
         
      if (buffer_offset != 0)
      {
        new_buffer = 
        // allocate a new buffer
        // copy remaining data to new buffer
        // set length of current buffer
        // set length of new buffer
      }

// I was up to here...
      NdisUnchainBufferAtBack(packets[packet_count], &mdl);
      NdisChainBufferAtFront(packets[packet_count + 1], mdl);
      NdisChainBufferAtFront(packets[packet_count + 1], new_header_mdl);
      
      
      // copy all buffers to new packet
      packet_count++;
    }
    // restore psh status to last packet
}

/*
 Windows appears to insist that the checksum on received packets is correct, and won't
 believe us when we lie about it, which happens when the packet is generated on the
 same bridge in Dom0. Doh!
 This is only for TCP and UDP packets. IP checksums appear to be correct anyways.
*/
static VOID
XenNet_SumData(
  PNDIS_PACKET packet
)
{
  USHORT i;
  PUCHAR buffer;
  PMDL mdl;
  UINT total_length;
  UINT buffer_length;
  ULONG csum, pre_csum;
  PUSHORT csum_ptr;
  UCHAR ip_version;
  USHORT ip4_header_length;
  USHORT ip4_length;
  USHORT tcp_header_length;
  USHORT tcp_length;
  USHORT buffer_offset;
  USHORT mss;
  PNDIS_PACKET packet;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  mss = PtrToUlong(NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpLargeSendPacketInfo);
  NdisGetFirstBufferFromPacketSafe(packet, &mdl, &buffer, &buffer_length, &total_length, NormalPagePriority);
  if (mdl == NULL)
  {
    KdPrint((__DRIVER_NAME "     Cannot get first buffer\n"));
    return;
  }

  if (buffer_length < XN_HDR_SIZE + 20 + 20) // minimum size of ETH + IP + TCP header
  {
    KdPrint((__DRIVER_NAME "     %d is not enough data for the first buffer\n", buffer_length));
    return;
  }
  
  switch (NET_USHORT(buffer[12])) // L2 protocol field
  {
  case 0x0800:
    ip_version = (buffer[XN_HDR_SIZE + 0] & 0xF0) >> 4;
    if (ip_version != 4)
    {
      KdPrint((__DRIVER_NAME "     ip_version = %d\n", ip_version));
      return;
    }
    ip4_header_length = (buffer[XN_HDR_SIZE + 0] & 0x0F) << 2;
    if (buffer_length < (ULONG)(ip4_header_length + 20))
    {
      KdPrint((__DRIVER_NAME "     first packet is only %d long, must be >= %d\n", XN_HDR_SIZE + buffer_length, (ULONG)(XN_HDR_SIZE + ip4_header_length + 20)));
      return;
    }
    break;
  default:
    KdPrint((__DRIVER_NAME "     Not IP\n"));
    return;
  }
  switch (buffer[XN_HDR_SIZE + 9])
  {
  case 6:  // TCP
  case 17: // UDP
    break;
  default:
    KdPrint((__DRIVER_NAME "     Not TCP or UDP\n"));
    return;
  }
  ip4_length = NET_USHORT(buffer[XN_HDR_SIZE + 2]);
  tcp_header_length = (buffer[XN_HDR_SIZE + ip4_header_length + 12] & 0xf0) >> 2;
  csum_ptr = (USHORT *)&buffer[XN_HDR_SIZE + ip4_header_length + 16];
  *csum_ptr = 0;

KdPrint((__DRIVER_NAME "     buffer_length = %d, total_length = %d, ip4_length = %d, ip4_header_length = %d, tcp_header_length = %d\n", buffer_length, total_length, ip4_length, ip4_header_length, tcp_header_length));

  ASSERT((USHORT)(ip4_length + XN_HDR_SIZE) == total_length);

  remaining = ip4_length - ip4_header_length - tcp_header_length;
  if (mss && remaining > mss)
  {
    ASSERT(mss <= PAGE_SIZE); // maybe fix this one day, but its a good assumption for now
    SplitLargePackets(packets, current_packet, &new_packets);
  }
  
  pre_csum = 0;
  pre_csum += NET_USHORT(buffer[XN_HDR_SIZE + 12]) + NET_USHORT(buffer[XN_HDR_SIZE + 14]);
  pre_csum += NET_USHORT(buffer[XN_HDR_SIZE + 16]) + NET_USHORT(buffer[XN_HDR_SIZE + 18]);
  pre_csum += ((USHORT)buffer[XN_HDR_SIZE + 9]);

  remaining = ip4_length - ip4_header_length;

  while (remaining > 0)
  {
    if (mss == 0)
      tcp_length = remaining;
    else
      tcp_length = min(remaining, mss);
    remaining -= tcp_length;

    csum = pre_csum + tcp_length;
    for (buffer_offset = i = XN_HDR_SIZE + ip4_header_length; i < tcp_length - 1; i += 2, buffer_offset += 2)
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
        KdPrint((__DRIVER_NAME "     New buffer - unaligned...\n"));
        csum += ((USHORT)buffer[0]);
        buffer_offset = -1;
      }
      else
      {
        if (buffer_offset == buffer_length)
        {
          KdPrint((__DRIVER_NAME "     New buffer - aligned...\n"));
          NdisGetNextBuffer(mdl, &mdl);
          if (mdl == NULL)
          {
            KdPrint((__DRIVER_NAME "     Ran out of buffers\n"));
            return;
          }
          NdisQueryBufferSafe(mdl, &buffer, &buffer_length, NormalPagePriority);
          buffer_offset = 0;
        }
        csum += NET_USHORT(buffer[buffer_offset]);
//KdPrint((__DRIVER_NAME "     %04X\n", NET_USHORT(buffer[buffer_offset])));
      }
    }
    if (i != ip4_length) // last odd byte
    {
//KdPrint((__DRIVER_NAME "    *%04X\n", (USHORT)buffer[buffer_offset] << 8));
      csum += ((USHORT)buffer[buffer_offset] << 8);
    }
    while (csum & 0xFFFF0000)
      csum = (csum & 0xFFFF) + (csum >> 16);
    *csum_ptr = (USHORT)~NET_USHORT(csum);

    if (remaining != 0)
    {
      // create a new packet
      // copy the header to a new buffer
      // if we are not at the start of the current buffer, copy the remaining data from the current buffer into a new buffer
      
    }
  
    KdPrint((__DRIVER_NAME "     csum = %04x\n", *csum_ptr));
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
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
  int more_frags = 0;
  NDIS_STATUS status;
  USHORT id;
  PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;
  USHORT total_packet_length = 0;
  BOOLEAN csum_calc_required;
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
  csum_calc_required = FALSE;
  if (xi->rx_current_packet)
  {
    packets[packet_count] = xi->rx_current_packet;
    xi->rx_current_packet = NULL;
    more_frags = NETRXF_more_data;
  }
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
      if (xi->rx_extra_info)
      {
KdPrint((__DRIVER_NAME "     RX extra info packet detected\n"));
        put_page_on_freelist(xi, mdl);
        ei = (struct netif_extra_info *)RING_GET_RESPONSE(&xi->rx, cons);
        xi->rx_extra_info = ei->flags & XEN_NETIF_EXTRA_FLAG_MORE;
        switch (ei->type)
        {
        case XEN_NETIF_EXTRA_TYPE_GSO:
KdPrint((__DRIVER_NAME "     GSO detected - size = %d\n", ei->u.gso.size));
          switch (ei->u.gso.type)
          {
          case XEN_NETIF_GSO_TYPE_TCPV4:
KdPrint((__DRIVER_NAME "     GSO_TYPE_TCPV4 detected\n"));
            NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpLargeSendPacketInfo) = (PVOID)(xen_ulong_t)(ei->u.gso.size);
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
//KdPrint((__DRIVER_NAME "     normal packet detected\n"));
        rxrsp = RING_GET_RESPONSE(&xi->rx, cons);
        if (rxrsp->status <= 0
          || rxrsp->offset + rxrsp->status > PAGE_SIZE)
        {
          KdPrint((__DRIVER_NAME ": Error: rxrsp offset %d, size %d\n",
            rxrsp->offset, rxrsp->status));
          continue;
        }
        ASSERT(rxrsp->id == id);
        if (!more_frags) // handling the packet's 1st buffer
        {
          NdisAllocatePacket(&status, &packets[packet_count], xi->packet_pool);
          ASSERT(status == NDIS_STATUS_SUCCESS);
          NDIS_SET_PACKET_HEADER_SIZE(packets[packet_count], XN_HDR_SIZE);
          NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpLargeSendPacketInfo) = 0;
          total_packet_length = 0;
          if (rxrsp->flags & (NETRXF_csum_blank|NETRXF_data_validated) && xi->config_csum) // and we are enabled for offload...
          {
//KdPrint((__DRIVER_NAME "     RX csum blank = %d, validated = %d\n", !!(rxrsp->flags & NETRXF_csum_blank), !!(rxrsp->flags & NETRXF_data_validated)));
            if (rxrsp->flags & NETRXF_csum_blank)
              csum_calc_required = TRUE;
            csum_info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)&NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpIpChecksumPacketInfo);
            csum_info->Receive.NdisPacketTcpChecksumSucceeded = 1;
            csum_info->Receive.NdisPacketUdpChecksumSucceeded = 0;
            csum_info->Receive.NdisPacketIpChecksumSucceeded = 1;
#if defined(XEN_PROFILE)
            ProfCount_RxPacketsCsumOffload++;
#endif
//KdPrint((__DRIVER_NAME "     RX csum offload TcpFailed = %d, UdpFailed = %d\n", csum_info->Receive.NdisPacketTcpChecksumFailed, csum_info->Receive.NdisPacketUdpChecksumFailed));
          }
        }
        total_packet_length = total_packet_length  + rxrsp->status;
        NdisAdjustBufferLength(mdl, rxrsp->status);
        NdisChainBufferAtBack(packets[packet_count], mdl);
        
        xi->rx_extra_info = rxrsp->flags & NETRXF_extra_info;
        more_frags = rxrsp->flags & NETRXF_more_data;
      }

if (more_frags)
  KdPrint((__DRIVER_NAME "     more frags\n"));
      /* Packet done, add it to the list */
      if (!more_frags && !xi->rx_extra_info)
      {
if (PtrToUlong(NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpLargeSendPacketInfo)))
  KdPrint((__DRIVER_NAME "     total length = %d, mss = %d\n", total_packet_length, PtrToUlong(NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpLargeSendPacketInfo))));
#if defined(XEN_PROFILE)
        ProfCount_RxPacketsTotal++;
#endif
        xi->stat_rx_ok++;
        NDIS_SET_PACKET_STATUS(packets[packet_count], NDIS_STATUS_SUCCESS);

/*
        if (total_packet_length > xi->config_mtu + XN_HDR_SIZE)
        {
          KdPrint((__DRIVER_NAME "     total_packet_length %d, config_mtu = %d\n", total_packet_length, xi->config_mtu));
          XenNet_SplitRxPacket(packets, &packet_count, total_packet_length);
        }
        else */ if (csum_calc_required)
        {
          XenNet_SumData(packets[packet_count]);
          csum_calc_required = FALSE;
        }

        packet_count++;
      }
    }
    xi->rx.rsp_cons = prod;

    RING_FINAL_CHECK_FOR_RESPONSES(&xi->rx, moretodo);
  } while (moretodo);

  /* Give netback more buffers */
  XenNet_RxBufferAlloc(xi);

  if (more_frags)
  {
KdPrint((__DRIVER_NAME "     leftover frags\n"));
    xi->rx_current_packet = packets[packet_count];
  }

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

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

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

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

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

  xi->page_free = 0;
  xi->rx_current_packet = NULL;
  xi->rx_extra_info = 0;
  
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
