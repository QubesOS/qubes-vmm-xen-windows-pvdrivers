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
get_tx_id_from_freelist(struct xennet_info *xi)
{
  if (xi->tx_id_free == 0)
    return 0xFFFF;
  xi->tx_id_free--;
  return xi->tx_id_list[xi->tx_id_free];
}

static VOID
put_tx_id_on_freelist(struct xennet_info *xi, USHORT id)
{
  xi->tx_id_list[xi->tx_id_free] = id;
  xi->tx_id_free++;
}

/* Called at DISPATCH_LEVEL with tx_lock held */
static PMDL
XenNet_Linearize(struct xennet_info *xi, PNDIS_PACKET Packet)
{
  PMDL pmdl;
  char *start;
  PNDIS_BUFFER buffer;
  PVOID buff_va;
  UINT buff_len;
  UINT tot_buff_len;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
#endif

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  NdisGetFirstBufferFromPacketSafe(Packet, &buffer, &buff_va, &buff_len,
    &tot_buff_len, NormalPagePriority);
  ASSERT(tot_buff_len <= XN_MAX_PKT_SIZE);

  pmdl = get_page_from_freelist(xi);
  if (!pmdl)
  {
    KdPrint(("Could not allocate MDL for linearization\n"));
    return NULL;
  }

  start = MmGetMdlVirtualAddress(pmdl);

  while (buffer)
  {
    NdisQueryBufferSafe(buffer, &buff_va, &buff_len, NormalPagePriority);
    RtlCopyMemory(start, buff_va, buff_len);
    start += buff_len;
    NdisGetNextBuffer(buffer, &buffer);
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
#if defined(XEN_PROFILE)
  ProfTime_Linearize.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_Linearize++;
#endif

  return pmdl;
}

/* Called at DISPATCH_LEVEL with tx_lock held */

static VOID
XenNet_SendQueuedPackets(struct xennet_info *xi)
{
  PLIST_ENTRY entry;
  PNDIS_PACKET packet;
  struct netif_tx_request *tx;
  unsigned short id;
  int notify;
  PMDL pmdl;
  UINT pkt_size;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
#endif
  PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;

#if defined(XEN_PROFILE)
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  /* if empty, the above returns head*, not NULL */
  while (entry != &xi->tx_waiting_pkt_list)
  {
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);

    NdisQueryPacket(packet, NULL, NULL, NULL, &pkt_size);

    id = get_tx_id_from_freelist(xi);
    if (id == 0xFFFF)
    {
      /* whups, out of space on the ring. requeue and get out */
      InsertHeadList(&xi->tx_waiting_pkt_list, entry);
      break;
    }
    //KdPrint(("sending pkt, len %d\n", pkt_size));
    ASSERT(xi->tx_pkts[id] == NULL);
    xi->tx_pkts[id] = packet;

    pmdl = XenNet_Linearize(xi, packet);
    if (!pmdl)
    {
      KdPrint((__DRIVER_NAME "Couldn't linearize packet!\n"));
      NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_FAILURE);
      break;
    }

    /* NOTE: 
     * We use the UCHAR[3*sizeof(PVOID)] array in each packet's MiniportReservedEx thusly:
     * 0: PMDL to linearized data
     * sizeof(PVOID)+: LIST_ENTRY for placing packet on the waiting pkt list
     */
    *(PMDL *)&packet->MiniportReservedEx = pmdl;

    tx = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
    tx->id = id;
    tx->gref = get_grant_ref(pmdl);
    tx->offset = (uint16_t)MmGetMdlByteOffset(pmdl);
    tx->size = (UINT16)pkt_size;
    
    tx->flags = 0;
#if defined(XEN_PROFILE)
    ProfCount_TxPacketsTotal++;
#endif
    csum_info = (PNDIS_TCP_IP_CHECKSUM_PACKET_INFO)&NDIS_PER_PACKET_INFO_FROM_PACKET(packet, TcpIpChecksumPacketInfo);
    if (csum_info->Transmit.NdisPacketTcpChecksum || csum_info->Transmit.NdisPacketUdpChecksum)
    {
      tx->flags |= NETTXF_csum_blank|NETTXF_data_validated;
#if defined(XEN_PROFILE)
      ProfCount_TxPacketsOffload++;
#endif
    }

    xi->tx.req_prod_pvt++;

    entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  }

  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xi->tx, notify);
  if (notify)
  {
    xi->XenInterface.EvtChn_Notify(xi->XenInterface.InterfaceHeader.Context,
      xi->event_channel);
  }

#if defined(XEN_PROFILE)
  ProfTime_SendQueuedPackets.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_SendQueuedPackets++;
#endif
}

// Called at DISPATCH_LEVEL
NDIS_STATUS
XenNet_TxBufferGC(struct xennet_info *xi)
{
  RING_IDX cons, prod;
  unsigned short id;
  PNDIS_PACKET packet;
  int moretodo;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
#endif

  ASSERT(xi->connected);
  ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  KeAcquireSpinLockAtDpcLevel(&xi->tx_lock);

  do {
    prod = xi->tx.sring->rsp_prod;
    KeMemoryBarrier(); /* Ensure we see responses up to 'rp'. */

    for (cons = xi->tx.rsp_cons; cons != prod; cons++)
    {
      struct netif_tx_response *txrsp;

      txrsp = RING_GET_RESPONSE(&xi->tx, cons);
      if (txrsp->status == NETIF_RSP_NULL)
        continue; // should this happen? what about the page?
      id  = txrsp->id;
      packet = xi->tx_pkts[id];
      xi->tx_pkts[id] = NULL;
      put_tx_id_on_freelist(xi, id);
      put_page_on_freelist(xi, *(PMDL *)packet->MiniportReservedEx);
      NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_SUCCESS);

      InterlockedDecrement(&xi->tx_outstanding);
      xi->stat_tx_ok++;
    }

    xi->tx.rsp_cons = prod;

    RING_FINAL_CHECK_FOR_RESPONSES(&xi->tx, moretodo);
  } while (moretodo);

  /* if queued packets, send them now */
  XenNet_SendQueuedPackets(xi);

  KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

#if defined(XEN_PROFILE)
  ProfTime_TxBufferGC.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_TxBufferGC++;
#endif

  return NDIS_STATUS_SUCCESS;
}

VOID
XenNet_SendPackets(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PPNDIS_PACKET PacketArray,
  IN UINT NumberOfPackets
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
  PNDIS_PACKET curr_packet;
  UINT i;
  PLIST_ENTRY entry;
  KIRQL OldIrql;
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
  KIRQL OldIrql2;
#endif

#if defined(XEN_PROFILE)
  KeRaiseIrql(DISPATCH_LEVEL, &OldIrql2);
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  KeAcquireSpinLock(&xi->tx_lock, &OldIrql);

  //  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  for (i = 0; i < NumberOfPackets; i++)
  {
    curr_packet = PacketArray[i];
    ASSERT(curr_packet);
    entry = (PLIST_ENTRY)&curr_packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(&xi->tx_waiting_pkt_list, entry);
    InterlockedIncrement(&xi->tx_outstanding);
  }

  XenNet_SendQueuedPackets(xi);

  KeReleaseSpinLock(&xi->tx_lock, OldIrql);

#if defined(XEN_PROFILE)
  ProfTime_SendPackets.QuadPart += KeQueryPerformanceCounter(&dummy).QuadPart - tsc.QuadPart;
  ProfCount_SendPackets++;
  KeLowerIrql(OldIrql2);
#endif

#if defined(XEN_PROFILE)
  if ((ProfCount_SendPackets & 1023) == 0)
  {
    KdPrint((__DRIVER_NAME "     ***\n"));
    KdPrint((__DRIVER_NAME "     RxBufferAlloc     Count = %10d, Avg Time = %10ld\n", ProfCount_RxBufferAlloc, (ProfCount_RxBufferAlloc == 0)?0:(ProfTime_RxBufferAlloc.QuadPart / ProfCount_RxBufferAlloc)));
    KdPrint((__DRIVER_NAME "     ReturnPacket      Count = %10d, Avg Time = %10ld\n", ProfCount_ReturnPacket, (ProfCount_ReturnPacket == 0)?0:(ProfTime_ReturnPacket.QuadPart / ProfCount_ReturnPacket)));
    KdPrint((__DRIVER_NAME "     RxBufferCheck     Count = %10d, Avg Time = %10ld\n", ProfCount_RxBufferCheck, (ProfCount_RxBufferCheck == 0)?0:(ProfTime_RxBufferCheck.QuadPart / ProfCount_RxBufferCheck)));
    KdPrint((__DRIVER_NAME "     Linearize         Count = %10d, Avg Time = %10ld\n", ProfCount_Linearize, (ProfCount_Linearize == 0)?0:(ProfTime_Linearize.QuadPart / ProfCount_Linearize)));
    KdPrint((__DRIVER_NAME "     SendPackets       Count = %10d, Avg Time = %10ld\n", ProfCount_SendPackets, (ProfCount_SendPackets == 0)?0:(ProfTime_SendPackets.QuadPart / ProfCount_SendPackets)));
    KdPrint((__DRIVER_NAME "     SendQueuedPackets Count = %10d, Avg Time = %10ld\n", ProfCount_SendQueuedPackets, (ProfCount_SendQueuedPackets == 0)?0:(ProfTime_SendQueuedPackets.QuadPart / ProfCount_SendQueuedPackets)));
    KdPrint((__DRIVER_NAME "     TxBufferGC        Count = %10d, Avg Time = %10ld\n", ProfCount_TxBufferGC, (ProfCount_TxBufferGC == 0)?0:(ProfTime_TxBufferGC.QuadPart / ProfCount_TxBufferGC)));
    KdPrint((__DRIVER_NAME "     RxPackets         Total = %10d, Offload  = %10d\n", ProfCount_RxPacketsTotal, ProfCount_RxPacketsOffload));
    KdPrint((__DRIVER_NAME "     TxPackets         Total = %10d, Offload  = %10d\n", ProfCount_TxPacketsTotal, ProfCount_TxPacketsOffload));
  }
#endif
  //  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static void
XenNet_TxBufferFree(struct xennet_info *xi)
{
  PLIST_ENTRY entry;
  PNDIS_PACKET packet;
  PMDL mdl;
  USHORT i;

  ASSERT(!xi->connected);

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
    packet = xi->tx_pkts[i];
    if (packet == NULL)
      continue;

    mdl = *(PMDL *)packet->MiniportReservedEx;
    put_page_on_freelist(xi, mdl);

    NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_FAILURE);
  }
}

BOOLEAN
XenNet_TxInit(xennet_info_t *xi)
{
  USHORT i;

  xi->tx_mdl = AllocatePage();
  xi->tx_pgs = MmGetMdlVirtualAddress(xi->tx_mdl);
  SHARED_RING_INIT(xi->tx_pgs);
  FRONT_RING_INIT(&xi->tx, xi->tx_pgs, PAGE_SIZE);
  xi->tx_ring_ref = xi->XenInterface.GntTbl_GrantAccess(
    xi->XenInterface.InterfaceHeader.Context, 0,
    *MmGetMdlPfnArray(xi->tx_mdl), FALSE);
  xi->tx_id_free = 0;
  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    xi->tx_pkts[i] = NULL;
    put_tx_id_on_freelist(xi, i);
  }
  return TRUE;
}

BOOLEAN
XenNet_TxShutdown(xennet_info_t *xi)
{
  XenNet_TxBufferFree(xi);
  return TRUE;
}
