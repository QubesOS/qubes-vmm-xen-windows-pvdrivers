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

// Q = Query Mandatory, S = Set Mandatory
NDIS_OID supported_oids[] =
{
  /* general OIDs */
  OID_GEN_SUPPORTED_LIST,        // Q
  OID_GEN_HARDWARE_STATUS,       // Q
  OID_GEN_MEDIA_SUPPORTED,       // Q
  OID_GEN_MEDIA_IN_USE,          // Q
  OID_GEN_MAXIMUM_LOOKAHEAD,     // Q
  OID_GEN_MAXIMUM_FRAME_SIZE,    // Q
  OID_GEN_LINK_SPEED,            // Q
  OID_GEN_TRANSMIT_BUFFER_SPACE, // Q
  OID_GEN_RECEIVE_BUFFER_SPACE,  // Q
  OID_GEN_TRANSMIT_BLOCK_SIZE,   // Q
  OID_GEN_RECEIVE_BLOCK_SIZE,    // Q
  OID_GEN_VENDOR_ID,             // Q
  OID_GEN_VENDOR_DESCRIPTION,    // Q
  OID_GEN_CURRENT_PACKET_FILTER, // QS
  OID_GEN_CURRENT_LOOKAHEAD,     // QS
  OID_GEN_DRIVER_VERSION,        // Q
  OID_GEN_MAXIMUM_TOTAL_SIZE,    // Q
  OID_GEN_PROTOCOL_OPTIONS,      // S
  OID_GEN_MAC_OPTIONS,           // Q
  OID_GEN_MEDIA_CONNECT_STATUS,  // Q
  OID_GEN_MAXIMUM_SEND_PACKETS,  // Q
  /* stats */
  OID_GEN_XMIT_OK,               // Q
  OID_GEN_RCV_OK,                // Q
  OID_GEN_XMIT_ERROR,            // Q
  OID_GEN_RCV_ERROR,             // Q
  OID_GEN_RCV_NO_BUFFER,         // Q
  /* media-specific OIDs */
  OID_802_3_PERMANENT_ADDRESS,
  OID_802_3_CURRENT_ADDRESS,
  OID_802_3_MULTICAST_LIST,
  OID_802_3_MAXIMUM_LIST_SIZE,
  /* tcp offload */
  OID_TCP_TASK_OFFLOAD,
};

/* return 4 or 8 depending on size of buffer */
#define HANDLE_STAT_RETURN \
  {if (InformationBufferLength == 4) { \
    len = 4; *BytesNeeded = 8; \
    } else { \
    len = 8; \
    } }

NDIS_STATUS 
XenNet_QueryInformation(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN NDIS_OID Oid,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength,
  OUT PULONG BytesWritten,
  OUT PULONG BytesNeeded)
{
  struct xennet_info *xi = MiniportAdapterContext;
  UCHAR vendor_desc[] = XN_VENDOR_DESC;
  ULONG64 temp_data;
  PVOID data = &temp_data;
  UINT len = 4;
  BOOLEAN used_temp_buffer = TRUE;
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  PNDIS_TASK_OFFLOAD_HEADER ntoh;
  PNDIS_TASK_OFFLOAD nto;
  PNDIS_TASK_TCP_IP_CHECKSUM nttic;
#ifdef OFFLOAD_LARGE_SEND
  PNDIS_TASK_TCP_LARGE_SEND nttls;
#endif

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  switch(Oid)
  {
    case OID_GEN_SUPPORTED_LIST:
      data = supported_oids;
      len = sizeof(supported_oids);
      break;
    case OID_GEN_HARDWARE_STATUS:
      if (!xi->connected)
        temp_data = NdisHardwareStatusInitializing;
      else
        temp_data = NdisHardwareStatusReady;
      break;
    case OID_GEN_MEDIA_SUPPORTED:
      temp_data = NdisMedium802_3;
      break;
    case OID_GEN_MEDIA_IN_USE:
      temp_data = NdisMedium802_3;
      break;
    case OID_GEN_MAXIMUM_LOOKAHEAD:
      temp_data = XN_DATA_SIZE;
      break;
    case OID_GEN_MAXIMUM_FRAME_SIZE:
      // According to the specs, OID_GEN_MAXIMUM_FRAME_SIZE does not include the header, so
      // it is XN_DATA_SIZE not XN_MAX_PKT_SIZE
      temp_data = XN_DATA_SIZE;
      break;
    case OID_GEN_LINK_SPEED:
      temp_data = 10000000; /* 1Gb */
      break;
    case OID_GEN_TRANSMIT_BUFFER_SPACE:
      /* pkts times sizeof ring, maybe? */
//      temp_data = XN_MAX_PKT_SIZE * NET_TX_RING_SIZE;
      temp_data = PAGE_SIZE * NET_TX_RING_SIZE;
      break;
    case OID_GEN_RECEIVE_BUFFER_SPACE:
      /* pkts times sizeof ring, maybe? */
//      temp_data = XN_MAX_PKT_SIZE * NET_RX_RING_SIZE;
      temp_data = PAGE_SIZE * NET_RX_RING_SIZE;
      break;
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
      temp_data = PAGE_SIZE; //XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_RECEIVE_BLOCK_SIZE:
      temp_data = PAGE_SIZE; //XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_VENDOR_ID:
      temp_data = 0xFFFFFF; // Not guaranteed to be XENSOURCE_MAC_HDR;
      break;
    case OID_GEN_VENDOR_DESCRIPTION:
      data = vendor_desc;
      len = sizeof(vendor_desc);
      break;
    case OID_GEN_CURRENT_PACKET_FILTER:
      temp_data = xi->packet_filter;
      break;
    case OID_GEN_CURRENT_LOOKAHEAD:
      // TODO: we should store this...
      temp_data = XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_DRIVER_VERSION:
      temp_data = (NDIS_MINIPORT_MAJOR_VERSION << 8) | NDIS_MINIPORT_MINOR_VERSION;
      len = 2;
      break;
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
#if !defined(OFFLOAD_LARGE_SEND)
      temp_data = XN_MAX_PKT_SIZE;
#else
      temp_data = MAX_LARGE_SEND_OFFLOAD;
#endif
      break;
    case OID_GEN_MAC_OPTIONS:
      temp_data = NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | 
        NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |
        NDIS_MAC_OPTION_NO_LOOPBACK;
      break;
    case OID_GEN_MEDIA_CONNECT_STATUS:
      if (xi->connected)
        temp_data = NdisMediaStateConnected;
      else
        temp_data = NdisMediaStateDisconnected;
      break;
    case OID_GEN_MAXIMUM_SEND_PACKETS:
      temp_data = XN_MAX_SEND_PKTS;
      break;
    case OID_GEN_XMIT_OK:
      temp_data = xi->stat_tx_ok;
      HANDLE_STAT_RETURN;
      break;
    case OID_GEN_RCV_OK:
      temp_data = xi->stat_rx_ok;
      HANDLE_STAT_RETURN;
      break;
    case OID_GEN_XMIT_ERROR:
      temp_data = xi->stat_tx_error;
      HANDLE_STAT_RETURN;
      break;
    case OID_GEN_RCV_ERROR:
      temp_data = xi->stat_rx_error;
      HANDLE_STAT_RETURN;
      break;
    case OID_GEN_RCV_NO_BUFFER:
      temp_data = xi->stat_rx_no_buffer;
      HANDLE_STAT_RETURN;
      break;
    case OID_802_3_PERMANENT_ADDRESS:
      data = xi->perm_mac_addr;
      len = ETH_ALEN;
      break;
    case OID_802_3_CURRENT_ADDRESS:
      data = xi->curr_mac_addr;
      len = ETH_ALEN;
      break;
    case OID_802_3_MULTICAST_LIST:
      data = NULL;
      len = 0;
    case OID_802_3_MAXIMUM_LIST_SIZE:
      temp_data = 0; /* no mcast support */
      break;
    case OID_TCP_TASK_OFFLOAD:
      KdPrint(("Get OID_TCP_TASK_OFFLOAD\n"));
      /* it's times like this that C really sucks */

      len = sizeof(NDIS_TASK_OFFLOAD_HEADER);

      len += FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer)
        + sizeof(NDIS_TASK_TCP_IP_CHECKSUM);
#ifdef OFFLOAD_LARGE_SEND
      len += FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer)
        + sizeof(NDIS_TASK_TCP_LARGE_SEND);
#endif

      if (len > InformationBufferLength)
      {
          break;
      }

      ntoh = (PNDIS_TASK_OFFLOAD_HEADER)InformationBuffer;
      if (ntoh->Version != NDIS_TASK_OFFLOAD_VERSION
        || ntoh->Size != sizeof(*ntoh)
        || ntoh->EncapsulationFormat.Encapsulation != IEEE_802_3_Encapsulation)
      {
        status = NDIS_STATUS_NOT_SUPPORTED;
        break;
      }
      ntoh->OffsetFirstTask = ntoh->Size;

      /* fill in first nto */
      nto = (PNDIS_TASK_OFFLOAD)((PCHAR)(ntoh) + ntoh->OffsetFirstTask);
      nto->Version = NDIS_TASK_OFFLOAD_VERSION;
      nto->Size = sizeof(NDIS_TASK_OFFLOAD);
      nto->Task = TcpIpChecksumNdisTask;
      nto->TaskBufferLength = sizeof(NDIS_TASK_TCP_IP_CHECKSUM);

      /* fill in checksum offload struct */
      nttic = (PNDIS_TASK_TCP_IP_CHECKSUM)nto->TaskBuffer;
      nttic->V4Transmit.IpChecksum = 0;
      nttic->V4Transmit.IpOptionsSupported = 0;
      nttic->V4Transmit.TcpChecksum = 1;
      nttic->V4Transmit.TcpOptionsSupported = 1;
      nttic->V4Transmit.UdpChecksum = 1;
      nttic->V4Receive.IpChecksum = 0;
      nttic->V4Receive.IpOptionsSupported = 0;
      nttic->V4Receive.TcpChecksum = 1;
      nttic->V4Receive.TcpOptionsSupported = 1;
      nttic->V4Receive.UdpChecksum = 1;
      nttic->V6Transmit.IpOptionsSupported = 0;
      nttic->V6Transmit.TcpOptionsSupported = 0;
      nttic->V6Transmit.TcpChecksum = 0;
      nttic->V6Transmit.UdpChecksum = 0;
      nttic->V6Receive.IpOptionsSupported = 0;
      nttic->V6Receive.TcpOptionsSupported = 0;
      nttic->V6Receive.TcpChecksum = 0;
      nttic->V6Receive.UdpChecksum = 0;

#ifdef OFFLOAD_LARGE_SEND
      /* offset from start of current NTO to start of next NTO */
      nto->OffsetNextTask = FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer)
        + nto->TaskBufferLength;

      /* fill in second nto */
      nto = (PNDIS_TASK_OFFLOAD)((PCHAR)(nto) + nto->OffsetNextTask);
      nto->Version = NDIS_TASK_OFFLOAD_VERSION;
      nto->Size = sizeof(NDIS_TASK_OFFLOAD);
      nto->Task = TcpLargeSendNdisTask;
      nto->TaskBufferLength = sizeof(NDIS_TASK_TCP_LARGE_SEND);

      /* fill in large send struct */
      nttls = (PNDIS_TASK_TCP_LARGE_SEND)nto->TaskBuffer;
      nttls->Version = 0;
      nttls->MaxOffLoadSize = MAX_LARGE_SEND_OFFLOAD;
      nttls->MinSegmentCount = MIN_LARGE_SEND_SEGMENTS;
      nttls->TcpOptions = TRUE;
      nttls->IpOptions = TRUE;
#endif
      nto->OffsetNextTask = 0; /* last one */

      used_temp_buffer = FALSE;
      break;
    default:
      KdPrint(("Get Unknown OID 0x%x\n", Oid));
      status = NDIS_STATUS_NOT_SUPPORTED;
  }

  if (!NT_SUCCESS(status))
  {
  //  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (returned error)\n"));
    return status;
  }

  if (len > InformationBufferLength)
  {
    *BytesNeeded = len;
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (BUFFER_TOO_SHORT)\n"));
    return NDIS_STATUS_BUFFER_TOO_SHORT;
  }

  *BytesWritten = len;
  if (len && used_temp_buffer)
  {
    NdisMoveMemory((PUCHAR)InformationBuffer, data, len);
  }

  //KdPrint(("Got OID 0x%x\n", Oid));
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return status;
}

NDIS_STATUS 
XenNet_SetInformation(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN NDIS_OID Oid,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength,
  OUT PULONG BytesRead,
  OUT PULONG BytesNeeded
  )
{
  NTSTATUS status;
  struct xennet_info *xi = MiniportAdapterContext;
  PULONG64 data = InformationBuffer;
  PNDIS_TASK_OFFLOAD_HEADER ntoh;
  PNDIS_TASK_OFFLOAD nto;
  PNDIS_TASK_TCP_IP_CHECKSUM nttic;
#ifdef OFFLOAD_LARGE_SEND
  PNDIS_TASK_TCP_LARGE_SEND nttls;
#endif
  int offset;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  UNREFERENCED_PARAMETER(MiniportAdapterContext);
  UNREFERENCED_PARAMETER(InformationBufferLength);
  UNREFERENCED_PARAMETER(BytesRead);
  UNREFERENCED_PARAMETER(BytesNeeded);

  switch(Oid)
  {
    case OID_GEN_SUPPORTED_LIST:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_SUPPORTED_LIST\n"));
      break;
    case OID_GEN_HARDWARE_STATUS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_HARDWARE_STATUS\n"));
      break;
    case OID_GEN_MEDIA_SUPPORTED:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MEDIA_SUPPORTED\n"));
      break;
    case OID_GEN_MEDIA_IN_USE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MEDIA_IN_USE\n"));
      break;
    case OID_GEN_MAXIMUM_LOOKAHEAD:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MAXIMUM_LOOKAHEAD\n"));
      break;
    case OID_GEN_MAXIMUM_FRAME_SIZE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MAXIMUM_FRAME_SIZE\n"));
      break;
    case OID_GEN_LINK_SPEED:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_LINK_SPEED\n"));
      break;
    case OID_GEN_TRANSMIT_BUFFER_SPACE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_TRANSMIT_BUFFER_SPACE\n"));
      break;
    case OID_GEN_RECEIVE_BUFFER_SPACE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_RECEIVE_BUFFER_SPACE\n"));
      break;
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_TRANSMIT_BLOCK_SIZE\n"));
      break;
    case OID_GEN_RECEIVE_BLOCK_SIZE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_RECEIVE_BLOCK_SIZE\n"));
      break;
    case OID_GEN_VENDOR_ID:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_VENDOR_ID\n"));
      break;
    case OID_GEN_VENDOR_DESCRIPTION:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_VENDOR_DESCRIPTION\n"));
      break;
    case OID_GEN_CURRENT_PACKET_FILTER:
      KdPrint(("Set OID_GEN_CURRENT_PACKET_FILTER\n"));
      xi->packet_filter = *(ULONG *)data;
      status = NDIS_STATUS_SUCCESS;
      break;
    case OID_GEN_CURRENT_LOOKAHEAD:
      KdPrint(("Set OID_GEN_CURRENT_LOOKAHEAD %d\n", *(int *)data));
      // TODO: We should do this...
      status = NDIS_STATUS_SUCCESS;
      break;
    case OID_GEN_DRIVER_VERSION:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_DRIVER_VERSION\n"));
      break;
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MAXIMUM_TOTAL_SIZE\n"));
      break;
    case OID_GEN_PROTOCOL_OPTIONS:
      KdPrint(("Unsupported set OID_GEN_PROTOCOL_OPTIONS\n"));
      // TODO - actually do this...
      status = NDIS_STATUS_SUCCESS;
      break;
    case OID_GEN_MAC_OPTIONS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MAC_OPTIONS\n"));
      break;
    case OID_GEN_MEDIA_CONNECT_STATUS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MEDIA_CONNECT_STATUS\n"));
      break;
    case OID_GEN_MAXIMUM_SEND_PACKETS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_MAXIMUM_SEND_PACKETS\n"));
      break;
    case OID_GEN_XMIT_OK:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_XMIT_OK\n"));
      break;
    case OID_GEN_RCV_OK:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_RCV_OK\n"));
      break;
    case OID_GEN_XMIT_ERROR:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_XMIT_ERROR\n"));
      break;
    case OID_GEN_RCV_ERROR:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_RCV_ERROR\n"));
      break;
    case OID_GEN_RCV_NO_BUFFER:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_GEN_RCV_NO_BUFFER\n"));
      break;
    case OID_802_3_PERMANENT_ADDRESS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_802_3_PERMANENT_ADDRESS\n"));
      break;
    case OID_802_3_CURRENT_ADDRESS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_802_3_CURRENT_ADDRESS\n"));
      break;
    case OID_802_3_MULTICAST_LIST:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_802_3_MULTICAST_LIST\n"));
      break;
    case OID_802_3_MAXIMUM_LIST_SIZE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_802_3_MAXIMUM_LIST_SIZE\n"));
      break;
    case OID_TCP_TASK_OFFLOAD:
      // Just fake this for now... ultimately we need to manually calc rx checksum if offload is disabled by windows
      status = NDIS_STATUS_SUCCESS;
      KdPrint(("Set OID_TCP_TASK_OFFLOAD\n"));
      // we should disable everything here, then enable what has been set
      ntoh = (PNDIS_TASK_OFFLOAD_HEADER)InformationBuffer;
      *BytesRead = sizeof(NDIS_TASK_OFFLOAD_HEADER);
      offset = ntoh->OffsetFirstTask;
      nto = (PNDIS_TASK_OFFLOAD)ntoh; // not really, just to get the first offset right
      while (offset != 0)
      {
        *BytesRead += FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer);
        nto = (PNDIS_TASK_OFFLOAD)(((PUCHAR)nto) + offset);
        switch (nto->Task)
        {
        case TcpIpChecksumNdisTask:
          *BytesRead += sizeof(NDIS_TASK_TCP_IP_CHECKSUM);
          KdPrint(("TcpIpChecksumNdisTask\n"));
          nttic = (PNDIS_TASK_TCP_IP_CHECKSUM)nto->TaskBuffer;
          KdPrint(("  V4Transmit.IpOptionsSupported  = %d\n", nttic->V4Transmit.IpOptionsSupported));
          KdPrint(("  V4Transmit.TcpOptionsSupported = %d\n", nttic->V4Transmit.TcpOptionsSupported));
          KdPrint(("  V4Transmit.TcpChecksum         = %d\n", nttic->V4Transmit.TcpChecksum));
          KdPrint(("  V4Transmit.UdpChecksum         = %d\n", nttic->V4Transmit.UdpChecksum));
          KdPrint(("  V4Transmit.IpChecksum          = %d\n", nttic->V4Transmit.IpChecksum));
          KdPrint(("  V4Receive.IpOptionsSupported   = %d\n", nttic->V4Receive.IpOptionsSupported));
          KdPrint(("  V4Receive.TcpOptionsSupported  = %d\n", nttic->V4Receive.TcpOptionsSupported));
          KdPrint(("  V4Receive.TcpChecksum          = %d\n", nttic->V4Receive.TcpChecksum));
          KdPrint(("  V4Receive.UdpChecksum          = %d\n", nttic->V4Receive.UdpChecksum));
          KdPrint(("  V4Receive.IpChecksum           = %d\n", nttic->V4Receive.IpChecksum));
          KdPrint(("  V6Transmit.IpOptionsSupported  = %d\n", nttic->V6Transmit.IpOptionsSupported));
          KdPrint(("  V6Transmit.TcpOptionsSupported = %d\n", nttic->V6Transmit.TcpOptionsSupported));
          KdPrint(("  V6Transmit.TcpChecksum         = %d\n", nttic->V6Transmit.TcpChecksum));
          KdPrint(("  V6Transmit.UdpChecksum         = %d\n", nttic->V6Transmit.UdpChecksum));
          KdPrint(("  V6Receive.IpOptionsSupported   = %d\n", nttic->V6Receive.IpOptionsSupported));
          KdPrint(("  V6Receive.TcpOptionsSupported  = %d\n", nttic->V6Receive.TcpOptionsSupported));
          KdPrint(("  V6Receive.TcpChecksum          = %d\n", nttic->V6Receive.TcpChecksum));
          KdPrint(("  V6Receive.UdpChecksum          = %d\n", nttic->V6Receive.UdpChecksum));
          break;
        case TcpLargeSendNdisTask:
          *BytesRead += sizeof(NDIS_TASK_TCP_LARGE_SEND);
          KdPrint(("TcpLargeSendNdisTask\n"));
          nttls = (PNDIS_TASK_TCP_LARGE_SEND)nto->TaskBuffer;
          KdPrint(("  MaxOffLoadSize                 = %d\n", nttls->MaxOffLoadSize));
          KdPrint(("  MinSegmentCount                = %d\n", nttls->MinSegmentCount));
          KdPrint(("  TcpOptions                     = %d\n", nttls->TcpOptions));
          KdPrint(("  IpOptions                      = %d\n", nttls->IpOptions));
          break;
        default:
          KdPrint(("  Unknown Task %d\n", nto->Task));
        }
        offset = nto->OffsetNextTask;
      }
      break;
    default:
      KdPrint(("Set Unknown OID 0x%x\n", Oid));
      status = NDIS_STATUS_NOT_SUPPORTED;
      break;
  }
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return status;
}
