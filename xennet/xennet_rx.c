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

#define __NET_USHORT_BYTE_0(x) ((USHORT)(x & 0xFF))
#define __NET_USHORT_BYTE_1(x) ((USHORT)((PUCHAR)&x)[1] & 0xFF)
#define NET_USHORT(x) ((__NET_USHORT_BYTE_0(x) << 8) | __NET_USHORT_BYTE_1(x))

static VOID
XenNet_ParseHeader(
  struct xennet_info *xi
)
{
  USHORT i;
  PUCHAR buffer;
  PMDL mdl;
  UINT total_length;
  UINT buffer_length;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(!xi->rx.mdls[0]);
  
  NdisQueryBuffer(xi->rx.mdls[0], &buffer, &buffer_length);

  if (buffer_length < XN_HDR_SIZE + 20 + 20) // minimum size of first buffer is ETH + IP + TCP header
  {
    KdPrint((__DRIVER_NAME "     %d is not enough data for the first buffer\n", buffer_length));
    return;
  }
  
  switch (NET_USHORT(buffer[12])) // L2 protocol field
  {
  case 0x0800:
    ip_version = (buffer[XN_HDR_SIZE + 0] & 0xF0) >> 4;
    if (xi->rx.ip_version != 4)
    {
      KdPrint((__DRIVER_NAME "     ip_version = %d\n", xi->rx.ip_version));
      return;
    }
    xi->rx.ip4_header_length = (buffer[XN_HDR_SIZE + 0] & 0x0F) << 2;
    if (buffer_length < (ULONG)(xi->rx.ip4_header_length + 20))
    {
      KdPrint((__DRIVER_NAME "     first packet is only %d long, must be >= %d\n", XN_HDR_SIZE + buffer_length, (ULONG)(XN_HDR_SIZE + xi->rx.ip4_header_length + 20)));
      return;
    }
    break;
  default:
    KdPrint((__DRIVER_NAME "     Not IP\n"));
    return;
  }
  xi->rx.ip4_proto = buffer[XN_HDR_SIZE + 9];
  switch (xi->rx.ip4_proto)
  {
  case 6:  // TCP
  case 17: // UDP
    break;
  default:
    KdPrint((__DRIVER_NAME "     Not TCP or UDP\n"));
    return;
  }
  xi->rx.ip4_length = NET_USHORT(buffer[XN_HDR_SIZE + 2]);
  xi->rx.tcp_header_length = (buffer[XN_HDR_SIZE + xi->rx.ip4_header_length + 12] & 0xf0) >> 2;
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
  PNDIS_PACKET packet;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  mss = PtrToUlong(NDIS_PER_PACKET_INFO_FROM_PACKET(packets[packet_count], TcpLargeSendPacketInfo);
  NdisGetFirstBufferFromPacketSafe(packet, &mdl, &buffer, &buffer_length, &total_length, NormalPagePriority);
  ASSERT(mdl);

  csum_ptr = (USHORT *)&buffer[XN_HDR_SIZE + xi->rx.ip4_header_length + 16];
  *csum_ptr = 0;

  ASSERT((USHORT)(ip4_length + XN_HDR_SIZE) == total_length);

  remaining = ip4_length - ip4_header_length - tcp_header_length;
  // TODO: pre-calc a sum of the header...
  pre_csum = 0;
  pre_csum += NET_USHORT(buffer[XN_HDR_SIZE + 12]) + NET_USHORT(buffer[XN_HDR_SIZE + 14]);
  pre_csum += NET_USHORT(buffer[XN_HDR_SIZE + 16]) + NET_USHORT(buffer[XN_HDR_SIZE + 18]);
  pre_csum += ((USHORT)buffer[XN_HDR_SIZE + 9]);

  remaining = ip4_length - ip4_header_length;

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

  KdPrint((__DRIVER_NAME "     csum = %04x\n", *csum_ptr));

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static PUCHAR
XenNet_GetMoreData(
  struct xennet_info xi,
  PUSHORT remaining
)
{
  PNDIS_BUFFER mdl = xi->rx.mdls[mdl_number];
  PUCHAR buffer = MmGetMdlVirtualAddress(mdl) + xi->rx.curr_mdl_offset;
  USHORT length = min(*remaining, MmGetMdlByteCount(mdl) - xi->rx.curr_mdl_offset);

  *remaining -= length;
  xi->rx.curr_mdl_offset += length;
  if (xi->rx.curr_mdl_offset == MmGetMdlByteCount(mdl))
    xi->rx.mdl_number++;
  return buffer;
}


static NDIS_PACKET
XenNet_MakePacket(
  struct xennet_info xi,
  PUCHAR header,
  ULONG mdl_number,
  ULONG buf_offset;
)
{
  PNDIS_PACKET packet;
  PUCHAR in_buffer;
  PNDIS_BUFFER out_mdl;
  PUCHAR out_buffer;
  USHORT out_offset;

  NdisAllocatePacket(&status, &packets[*packet_count], xi->packet_pool);
  ASSERT(status == NDIS_STATUS_SUCCESS);
  NDIS_SET_PACKET_HEADER_SIZE(packets[*packet_count], XN_HDR_SIZE);
  if (header == NULL)
  {
    for (i = 0; i < xi->rx.mdl_count; i++)
      NdisChainBufferAtBack(packet, mdls[i]);
    NDIS_SET_PACKET_STATUS(packet, NDIS_STATUS_SUCCESS);
  }
  else
  {
    out_mdl = get_page_from_freelist(xi);
    out_buffer = out_ptr = MmGetMdlVirtualAddress(out_mdl);
    out_offset = XN_HDR_SIZE + xi->rx.ip4_header_length + xi->rx.tcp_header_length;
    out_remaining = xi->rx.mss;
    memcpy(out_buffer, header, out_offset);
    do 
    {
      in_buffer = XenNet_GetMoreData(xi, &out_remaining, &length);
      memcpy(&out_buffer[out_offset], in_buffer, length);
    } while (out_remaining != 0 && in_buffer != NULL)
    length = xi->rx.mss - out_remaining;
    in_buffer[___ip4_length_offset___] = NET_USHORT(...); // recalc this
    in_buffer[___mss_offset___] = NET_USHORT(length);
    in_buffer[___seq_offset___] = NET_ULONG(in_buffer[___seq_offset___]) + ???
  }
  return packet;
}

static VOID
XenNet_MakePackets(
  struct xennet_info *xi,
  PNDIS_PACKET *packets,
  PULONG packet_count
)
{
  PNDIS_PACKET first_packet;
  PNDIS_PACKET curr_packet;
  PNDIS_BUFFER mdls[MAX_BUFFERS_PER_PACKET];
  ULONG mdl_count = 0;
  ULONG curr_in_mdl_index;
  PNDIS_BUFFER curr_out_mdl;
  ULONG curr_in_offset;
  ULONG curr_out_offset;
  PUCHAR header;
  PUCHAR curr_in_buffer;
  PUCHAR curr_out_buffer;

  ULONG total_in_remaining;
  ULONG buffer_in_remaining;

  XenNet_ParseHeader(xi);
  switch (xi->rx.ip4_proto)
  {
  case 6:  // TCP
    if (xi->rx.split_required)
      break;
    packets[*packet_count] = XenNet_MakePacket(xi);
    if (xi->rx.csum_calc_required)
      XenNet_SumPacket(xi, packets[*packet_count];
    *packet_count++;
    return;
  case 17:  // UDP
    packets[*packet_count] = XenNet_MakePacket(xi);
    if (xi->rx.csum_calc_required)
      XenNet_SumPacket(xi, packets[*packet_count];
    *packet_count++;
    return;
  default:
    packets[*packet_count] = XenNet_MakePacket(xi, ...);
    *packet_count++;
    return;
  }

  while (data left in buffer)
  {
    packets[*packet_count] = XenNet_MakePacket(xi, ...);
    XenNet_SumPacket(xi, packets[*packet_count];
    *packet_count++;
  }
  // TODO: restore psh status to last packet
  for (i = 0; i < mdl_count; i++)
  {
    put_page_on_freelist(xi, mdls[i];
  }
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
  NDIS_STATUS status;
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
      if (xi->rx.extra_info)
      {
        put_page_on_freelist(xi, mdl);
        ei = (struct netif_extra_info *)RING_GET_RESPONSE(&xi->rx, cons);
        xi->rx.extra_info = !!(ei->flags & XEN_NETIF_EXTRA_FLAG_MORE);
        switch (ei->type)
        {
        case XEN_NETIF_EXTRA_TYPE_GSO:
          switch (ei->u.gso.type)
          {
          case XEN_NETIF_GSO_TYPE_TCPV4:
            xi->rx.mss = (PVOID)(xen_ulong_t)(ei->u.gso.size);
            ASSERT(header_len + xi->rx.mss <= PAGE_SIZE); // this limits MTU to PAGE_SIZE - XN_HEADER_LEN
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
        if (!xi->rx.more_frags) // handling the packet's 1st buffer
        {
          
          if (rxrsp->flags & (NETRXF_csum_blank|NETRXF_data_validated) && xi->config_csum) // and we are enabled for offload...
          {
            //KdPrint((__DRIVER_NAME "     RX csum blank = %d, validated = %d\n", !!(rxrsp->flags & NETRXF_csum_blank), !!(rxrsp->flags & NETRXF_data_validated)));
            if (rxrsp->flags & NETRXF_csum_blank)
              xi->rx.csum_calc_required = TRUE;
            #if defined(XEN_PROFILE)
            ProfCount_RxPacketsCsumOffload++;
            #endif
          }
        }
        NdisAdjustBufferLength(mdl, rxrsp->status);
        xi->rx.mdls[mdl_count++] = mdl;
        xi->rx.extra_info = !!(rxrsp->flags & NETRXF_extra_info);
        xi->rx.more_frags = !!(rxrsp->flags & NETRXF_more_data);
        xi->rx.total_length += rxrsp->status;
      }

      /* Packet done, add it to the list */
      if (!xi->rx.more_frags && !xi->rx.extra_info)
      {
        XenNet_MakePackets(xi, packets, &packet_count)
        RtlZeroMemory(xi->rx, sizeof(xi->rx));
        packet_count++;
      }
    }
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
