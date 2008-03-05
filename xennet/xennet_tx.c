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
  if (xi->tx_id_free == 0)
    return 0xFFFF;
  xi->tx_id_free--;
  return xi->tx_id_list[xi->tx_id_free];
}

static VOID
put_id_on_freelist(struct xennet_info *xi, USHORT id)
{
  xi->tx_id_list[xi->tx_id_free] = id;
  xi->tx_id_free++;
}

static grant_ref_t
get_gref_from_freelist(struct xennet_info *xi)
{
  if (xi->tx_gref_free == 0)
    return 0;
  xi->tx_gref_free--;
  return xi->tx_gref_list[xi->tx_gref_free];
}

static VOID
put_gref_on_freelist(struct xennet_info *xi, grant_ref_t gref)
{
  xi->tx_gref_list[xi->tx_gref_free] = gref;
  xi->tx_gref_free++;
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
#if defined(XEN_PROFILE)
  LARGE_INTEGER tsc, dummy;
#endif
  PNDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;
  ULONG i;
  PSCATTER_GATHER_LIST sg_list;
  UINT total_packet_length;
  USHORT remaining;
  USHORT offset;
  USHORT length;
  ULONGLONG curr_addr;
  ULONG sg_num;
  ULONG pfn;

#if defined(XEN_PROFILE)
  tsc = KeQueryPerformanceCounter(&dummy);
#endif

  entry = RemoveHeadList(&xi->tx_waiting_pkt_list);
  /* if empty, the above returns head*, not NULL */
  while (entry != &xi->tx_waiting_pkt_list)
  {
//KdPrint((__DRIVER_NAME "     Packet ready to send\n"));
    packet = CONTAINING_RECORD(entry, NDIS_PACKET, MiniportReservedEx[sizeof(PVOID)]);
    sg_list = NDIS_PER_PACKET_INFO_FROM_PACKET(packet, ScatterGatherListPacketInfo);

    i = 0;
    sg_num = 0;
    remaining = 0;
    curr_addr = 0;
    id = 0;
    while (sg_num < sg_list->NumberOfElements || remaining > 0)
    {
      if (remaining == 0)
      {
//KdPrint((__DRIVER_NAME "     First Frag in sg...\n"));
        curr_addr = sg_list->Elements[sg_num].Address.QuadPart;
        offset = (USHORT)(sg_list->Elements[sg_num].Address.QuadPart & (PAGE_SIZE - 1));
        remaining = (USHORT)sg_list->Elements[sg_num].Length;
        length = min(remaining, PAGE_SIZE - offset);
        sg_num++;
      }
      else
      {
//KdPrint((__DRIVER_NAME "     Subsequent Frag in sg...\n"));
        offset = 0;
        length = min(remaining, PAGE_SIZE);
      }
      pfn = (ULONG)(curr_addr >> PAGE_SHIFT);
      remaining = remaining - length;
      curr_addr += length;
      if (i++ < *(ULONG *)&packet->MiniportReservedEx)
        continue;
      id = get_id_from_freelist(xi);
      if (id == 0xFFFF)
      {
//KdPrint((__DRIVER_NAME "     But out of space...\n"));
        /* whups, out of space on the ring. requeue and get out */
        InsertHeadList(&xi->tx_waiting_pkt_list, entry);
        break;
      }
      ASSERT(xi->tx_pkts[id] == NULL);
      (*(ULONG *)&packet->MiniportReservedEx)++;
      tx = RING_GET_REQUEST(&xi->tx, xi->tx.req_prod_pvt);
      tx->gref = get_gref_from_freelist(xi);
      ASSERT(tx->gref != 0);
      ASSERT(xi->tx_grefs[id] == 0);
      xi->tx_grefs[id] = tx->gref;
      xi->XenInterface.GntTbl_GrantAccess(
        xi->XenInterface.InterfaceHeader.Context, 0,
        pfn, FALSE, tx->gref);
      tx->id = id;
      tx->offset = offset;
      tx->flags = 0;
      if (i == 1) // we have already incremented i!!!
      {
//KdPrint((__DRIVER_NAME "     First Frag in packet...\n"));
        NdisQueryPacket(packet, NULL, NULL, NULL, &total_packet_length);
        tx->size = (USHORT)total_packet_length;
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
      }
      else
      {
//KdPrint((__DRIVER_NAME "     Subsequent Frag in packet...\n"));
        tx->size = length;
      }
      if (sg_num == sg_list->NumberOfElements && remaining == 0)
      {
//KdPrint((__DRIVER_NAME "     No more frags\n"));
        xi->tx_pkts[id] = packet; /* only set the packet on the last buffer */
      }
      else
      {
//KdPrint((__DRIVER_NAME "     More frags\n"));
        tx->flags |= NETTXF_more_data;
      }
      xi->tx.req_prod_pvt++;
    }
    if (id == 0xFFFF)
      break;
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
      if (packet)
      {
        xi->tx_pkts[id] = NULL;
        /* TODO: check status and indicate appropriately */
        NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_SUCCESS);
      }
      put_gref_on_freelist(xi, xi->tx_grefs[id]);
      xi->tx_grefs[id] = 0;
      put_id_on_freelist(xi, id);

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
  PNDIS_PACKET packet;
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
    packet = PacketArray[i];
    ASSERT(packet);
    *(ULONG *)&packet->MiniportReservedEx = 0;
    entry = (PLIST_ENTRY)&packet->MiniportReservedEx[sizeof(PVOID)];
    InsertTailList(&xi->tx_waiting_pkt_list, entry);
    InterlockedIncrement(&xi->tx_outstanding);
#if defined(XEN_PROFILE)
    ProfCount_PacketsPerSendPackets++;
#endif
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
    KdPrint((__DRIVER_NAME "     Packets per SendPackets = %10d\n", (ProfCount_SendPackets == 0)?0:(ProfCount_PacketsPerSendPackets / ProfCount_SendPackets)));
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
  USHORT i;
  grant_ref_t gref;

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
    if (packet != NULL)
      NdisMSendComplete(xi->adapter_handle, packet, NDIS_STATUS_FAILURE);
    gref = xi->tx_grefs[i];
    if (gref != 0)
      xi->XenInterface.GntTbl_EndAccess(
        xi->XenInterface.InterfaceHeader.Context, gref, TRUE);
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
    *MmGetMdlPfnArray(xi->tx_mdl), FALSE, 0);
  xi->tx_id_free = 0;
  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    xi->tx_pkts[i] = NULL;
    put_id_on_freelist(xi, i);
  }
  xi->tx_gref_free = 0;
  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    xi->tx_grefs[i] = 0;
    put_gref_on_freelist(xi, xi->XenInterface.GntTbl_GetRef(
      xi->XenInterface.InterfaceHeader.Context));
  }
  return TRUE;
}

BOOLEAN
XenNet_TxShutdown(xennet_info_t *xi)
{
  ULONG i;

  XenNet_TxBufferFree(xi);

  /* free TX resources */
  if (xi->XenInterface.GntTbl_EndAccess(
    xi->XenInterface.InterfaceHeader.Context, xi->tx_ring_ref, 0))
  {
    xi->tx_ring_ref = GRANT_INVALID_REF;
    FreePages(xi->tx_mdl);
  }
  /* if EndAccess fails then tx/rx ring pages LEAKED -- it's not safe to reuse
     pages Dom0 still has access to */
  xi->tx_pgs = NULL;

  for (i = 0; i < NET_TX_RING_SIZE; i++)
  {
    xi->XenInterface.GntTbl_PutRef(
      xi->XenInterface.InterfaceHeader.Context, xi->tx_gref_list[i]);
  }

  return TRUE;
}
