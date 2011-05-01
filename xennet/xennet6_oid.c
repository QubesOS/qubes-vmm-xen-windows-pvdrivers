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

#include "xennet6.h"

/* return 4 or 8 depending on size of buffer */
#define HANDLE_STAT_RETURN \
  {if (InformationBufferLength == 4) { \
    len = 4; *BytesNeeded = 8; \
    } else { \
    len = 8; \
    } }

#define SET_LEN_AND_BREAK_IF_SHORT(_len) do { len = _len; if (len > InformationBufferLength) break; } while(0)
  
static NDIS_STATUS
XenNet_QueryInformation(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN NDIS_OID Oid,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength,
  OUT PUINT BytesWritten,
  OUT PUINT BytesNeeded)
{
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  struct xennet_info *xi = MiniportAdapterContext;
  BOOLEAN used_temp_buffer = TRUE;
  UINT len = 4;
  ULONG64 temp_data;
  PVOID data = &temp_data;
  PNDIS_INTERRUPT_MODERATION_PARAMETERS nimp;
#if 0
  UCHAR vendor_desc[] = XN_VENDOR_DESC;
  PNDIS_TASK_OFFLOAD_HEADER ntoh;
  PNDIS_TASK_OFFLOAD nto;
  PNDIS_TASK_TCP_IP_CHECKSUM nttic;
  PNDIS_TASK_TCP_LARGE_SEND nttls;
  PNDIS_PNP_CAPABILITIES npc;
#endif

  *BytesNeeded = 0;
  *BytesWritten = 0;

// FUNCTION_ENTER()

  switch(Oid)
  {
#if 0
    case OID_GEN_SUPPORTED_LIST:
      data = supported_oids;
      len = sizeof(supported_oids);
      break;
    case OID_GEN_HARDWARE_STATUS:
      if (!xi->connected)
      {
        temp_data = NdisHardwareStatusInitializing;
        FUNCTION_MSG("NdisHardwareStatusInitializing\n");
      }
      else
      {
        temp_data = NdisHardwareStatusReady;
        FUNCTION_MSG("NdisHardwareStatusReady\n");
      }
      break;
    case OID_GEN_MEDIA_SUPPORTED:
      temp_data = NdisMedium802_3;
      break;
    case OID_GEN_MEDIA_IN_USE:
      temp_data = NdisMedium802_3;
      break;
    case OID_GEN_MAXIMUM_LOOKAHEAD:
      temp_data = MAX_LOOKAHEAD_LENGTH; //xi->config_mtu;
      break;
    case OID_GEN_MAXIMUM_FRAME_SIZE:
      temp_data = xi->config_mtu;
      break;
    case OID_GEN_LINK_SPEED:
      temp_data = 10000000; /* 1Gb */
      break;
    case OID_GEN_TRANSMIT_BUFFER_SPACE:
      /* multiply this by some small number as we can queue additional packets */
      temp_data = PAGE_SIZE * NET_TX_RING_SIZE * 4;
      break;
    case OID_GEN_RECEIVE_BUFFER_SPACE:
      temp_data = PAGE_SIZE * NET_RX_RING_SIZE * 2;
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
    case OID_GEN_DRIVER_VERSION:
      temp_data = (NDIS_MINIPORT_MAJOR_VERSION << 8) | NDIS_MINIPORT_MINOR_VERSION;
      len = 2;
      break;
    case OID_GEN_VENDOR_DRIVER_VERSION:
      temp_data = VENDOR_DRIVER_VERSION;
      len = 4;
      break;
    case OID_GEN_MAC_OPTIONS:
      temp_data = NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | 
        NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |
        NDIS_MAC_OPTION_NO_LOOPBACK;
      break;
    case OID_GEN_MEDIA_CONNECT_STATUS:
      if (xi->connected && !xi->inactive)
        temp_data = NdisMediaStateConnected;
      else
        temp_data = NdisMediaStateDisconnected;
      break;
    case OID_GEN_MAXIMUM_SEND_PACKETS:
      /* this is actually ignored for deserialised drivers like us */
      temp_data = 0; //XN_MAX_SEND_PKTS;
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
    case OID_802_3_RCV_ERROR_ALIGNMENT:
    case OID_802_3_XMIT_ONE_COLLISION:
    case OID_802_3_XMIT_MORE_COLLISIONS:
      temp_data = 0;
      HANDLE_STAT_RETURN;
      break;
    case OID_802_3_MAXIMUM_LIST_SIZE:
      temp_data = MULTICAST_LIST_MAX_SIZE;
      break;
    case OID_TCP_TASK_OFFLOAD:
      KdPrint(("Get OID_TCP_TASK_OFFLOAD\n"));
      /* it's times like this that C really sucks */

      len = sizeof(NDIS_TASK_OFFLOAD_HEADER);

      if (xi->config_csum)
      {
        len += FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer)
          + sizeof(NDIS_TASK_TCP_IP_CHECKSUM);
      }

      if (xi->config_gso)
      {
        len += FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer)
          + sizeof(NDIS_TASK_TCP_LARGE_SEND);
      }

      //len += 1024;

      if (len > InformationBufferLength)
      {
          break;
      }

      ntoh = (PNDIS_TASK_OFFLOAD_HEADER)InformationBuffer;
      if (ntoh->Version != NDIS_TASK_OFFLOAD_VERSION
        || ntoh->Size != sizeof(*ntoh)
        || !(
          ntoh->EncapsulationFormat.Encapsulation == IEEE_802_3_Encapsulation
          || (ntoh->EncapsulationFormat.Encapsulation == UNSPECIFIED_Encapsulation
              && ntoh->EncapsulationFormat.EncapsulationHeaderSize == XN_HDR_SIZE)))
      {
        status = NDIS_STATUS_NOT_SUPPORTED;
        break;
      }
      ntoh->OffsetFirstTask = 0; 
      nto = NULL;

      if (xi->config_csum)
      {
        if (ntoh->OffsetFirstTask == 0)
        {
          ntoh->OffsetFirstTask = ntoh->Size;
          nto = (PNDIS_TASK_OFFLOAD)((PCHAR)(ntoh) + ntoh->OffsetFirstTask);
        }
        else
        {
          nto->OffsetNextTask = FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer)
            + nto->TaskBufferLength;
          nto = (PNDIS_TASK_OFFLOAD)((PCHAR)(nto) + nto->OffsetNextTask);
        }
        /* fill in first nto */
        nto->Version = NDIS_TASK_OFFLOAD_VERSION;
        nto->Size = sizeof(NDIS_TASK_OFFLOAD);
        nto->Task = TcpIpChecksumNdisTask;
        nto->TaskBufferLength = sizeof(NDIS_TASK_TCP_IP_CHECKSUM);

        KdPrint(("config_csum enabled\n"));
        KdPrint(("nto = %p\n", nto));
        KdPrint(("nto->Size = %d\n", nto->Size));
        KdPrint(("nto->TaskBufferLength = %d\n", nto->TaskBufferLength));

        /* fill in checksum offload struct */
        nttic = (PNDIS_TASK_TCP_IP_CHECKSUM)nto->TaskBuffer;
        nttic->V4Transmit.IpChecksum = 0;
        nttic->V4Transmit.IpOptionsSupported = 0;
        nttic->V4Transmit.TcpChecksum = 1;
        nttic->V4Transmit.TcpOptionsSupported = 1;
        nttic->V4Transmit.UdpChecksum = 1;
        nttic->V4Receive.IpChecksum = 1;
        nttic->V4Receive.IpOptionsSupported = 1;
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
      }
      if (xi->config_gso)
      {
        if (ntoh->OffsetFirstTask == 0)
        {
          ntoh->OffsetFirstTask = ntoh->Size;
          nto = (PNDIS_TASK_OFFLOAD)((PCHAR)(ntoh) + ntoh->OffsetFirstTask);
        }
        else
        {
          nto->OffsetNextTask = FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer)
            + nto->TaskBufferLength;
          nto = (PNDIS_TASK_OFFLOAD)((PCHAR)(nto) + nto->OffsetNextTask);
        }
  
        /* fill in second nto */
        nto->Version = NDIS_TASK_OFFLOAD_VERSION;
        nto->Size = sizeof(NDIS_TASK_OFFLOAD);
        nto->Task = TcpLargeSendNdisTask;
        nto->TaskBufferLength = sizeof(NDIS_TASK_TCP_LARGE_SEND);

        KdPrint(("config_gso enabled\n"));
        KdPrint(("nto = %p\n", nto));
        KdPrint(("nto->Size = %d\n", nto->Size));
        KdPrint(("nto->TaskBufferLength = %d\n", nto->TaskBufferLength));
  
        /* fill in large send struct */
        nttls = (PNDIS_TASK_TCP_LARGE_SEND)nto->TaskBuffer;
        nttls->Version = 0;
        nttls->MaxOffLoadSize = xi->config_gso;
        nttls->MinSegmentCount = MIN_LARGE_SEND_SEGMENTS;
        nttls->TcpOptions = FALSE; /* linux can't handle this */
        nttls->IpOptions = FALSE; /* linux can't handle this */
        KdPrint(("&(nttls->IpOptions) = %p\n", &(nttls->IpOptions)));        
      }

      if (nto)
        nto->OffsetNextTask = 0; /* last one */

      used_temp_buffer = FALSE;
      break;
    case OID_IP4_OFFLOAD_STATS:
    case OID_IP6_OFFLOAD_STATS:
      /* these are called often so just ignore then quietly */
      status = NDIS_STATUS_NOT_SUPPORTED;
      break;

    case OID_PNP_CAPABILITIES:
      KdPrint(("Get OID_PNP_CAPABILITIES\n"));
      len = sizeof(NDIS_PNP_CAPABILITIES);
      if (len > InformationBufferLength)
        break;
      npc = (PNDIS_PNP_CAPABILITIES)InformationBuffer;
      npc->Flags = 0;
      npc->WakeUpCapabilities.MinMagicPacketWakeUp = NdisDeviceStateUnspecified;
      npc->WakeUpCapabilities.MinPatternWakeUp = NdisDeviceStateUnspecified;
      npc->WakeUpCapabilities.MinLinkChangeWakeUp = NdisDeviceStateUnspecified;
      used_temp_buffer = FALSE;
      break;
    case OID_PNP_QUERY_POWER:
      KdPrint(("Get OID_PNP_CAPABILITIES\n"));
      used_temp_buffer = FALSE;
      break;

#endif
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
      temp_data = xi->config_mtu + XN_HDR_SIZE;
      break;
    case OID_GEN_INTERRUPT_MODERATION:
      SET_LEN_AND_BREAK_IF_SHORT(sizeof(NDIS_INTERRUPT_MODERATION_PARAMETERS));
      nimp = (PNDIS_INTERRUPT_MODERATION_PARAMETERS)InformationBuffer;
      nimp->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
      nimp->Header.Revision = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
      nimp->Header.Size = NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
      nimp->Flags = 0;
      nimp->InterruptModeration = NdisInterruptModerationNotSupported;
      break;
    case OID_GEN_CURRENT_PACKET_FILTER:
      temp_data = xi->packet_filter;
      break;
    case OID_GEN_CURRENT_LOOKAHEAD:
      temp_data = xi->current_lookahead;
      break;
    case OID_802_3_CURRENT_ADDRESS:
      data = xi->curr_mac_addr;
      len = ETH_ALEN;
      break;
    case OID_802_3_PERMANENT_ADDRESS:
      data = xi->perm_mac_addr;
      len = ETH_ALEN;
      break;
    case OID_802_3_MULTICAST_LIST:
      data = xi->multicast_list;
      len = xi->multicast_list_size * 6;
      break;
    case OID_GEN_XMIT_OK:
      temp_data = xi->stat_tx_ok;
      HANDLE_STAT_RETURN;
      break;
    default:
      KdPrint(("Get Unknown OID 0x%x\n", Oid));
    /* silently fail these */
    case OID_GEN_MACHINE_NAME:
    case OID_GEN_SUPPORTED_GUIDS:
      status = NDIS_STATUS_NOT_SUPPORTED;
    break;
  }

  if (!NT_SUCCESS(status))
  {
    //FUNCTION_EXIT_STATUS(status);
    return status;
  }

  if (len > InformationBufferLength)
  {
    *BytesNeeded = len;
    FUNCTION_MSG("(BUFFER_TOO_SHORT %d > %d)\n", len, InformationBufferLength);
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
  IN NDIS_HANDLE adapter_context,
  IN NDIS_OID Oid,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength,
  OUT PUINT BytesRead,
  OUT PUINT BytesNeeded
  )
{
  NTSTATUS status;
  struct xennet_info *xi = adapter_context;
  PULONG64 data = InformationBuffer;
  ULONG i;
  UCHAR *multicast_list;
#if 0
  PNDIS_TASK_OFFLOAD_HEADER ntoh;
  PNDIS_TASK_OFFLOAD nto;
  PNDIS_TASK_TCP_IP_CHECKSUM nttic = NULL;
  PNDIS_TASK_TCP_LARGE_SEND nttls = NULL;
  int offset;
#endif
  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  UNREFERENCED_PARAMETER(BytesRead);
  UNREFERENCED_PARAMETER(BytesNeeded);
  switch(Oid)
  {
#if 0
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
    case OID_802_3_CURRENT_ADDRESS:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_802_3_CURRENT_ADDRESS\n"));
      break;
    case OID_802_3_MULTICAST_LIST:
      KdPrint(("     Set OID_802_3_MULTICAST_LIST\n"));
      KdPrint(("       Length = %d\n", InformationBufferLength));
      KdPrint(("       Entries = %d\n", InformationBufferLength / 6));
      if (InformationBufferLength > MULTICAST_LIST_MAX_SIZE * 6)
      {
        status = NDIS_STATUS_MULTICAST_FULL;
        break;
      }
      
      if (InformationBufferLength % 6 != 0)
      {
        status = NDIS_STATUS_MULTICAST_FULL;
        break;
      }
      multicast_list = InformationBuffer;
      for (i = 0; i < InformationBufferLength / 6; i++)
      {
        if (!(multicast_list[i * 6 + 0] & 0x01))
        {
          KdPrint(("       Address %d (%02x:%02x:%02x:%02x:%02x:%02x) is not a multicast address\n", i,
            (ULONG)multicast_list[i * 6 + 0], (ULONG)multicast_list[i * 6 + 1], 
            (ULONG)multicast_list[i * 6 + 2], (ULONG)multicast_list[i * 6 + 3], 
            (ULONG)multicast_list[i * 6 + 4], (ULONG)multicast_list[i * 6 + 5]));
          /* the docs say that we should return NDIS_STATUS_MULTICAST_FULL if we get an invalid multicast address but I'm not sure if that's the case... */
        }
      }
      memcpy(xi->multicast_list, InformationBuffer, InformationBufferLength);
      xi->multicast_list_size = InformationBufferLength / 6;
      status = NDIS_STATUS_SUCCESS;
      break;
    case OID_802_3_MAXIMUM_LIST_SIZE:
      status = NDIS_STATUS_NOT_SUPPORTED;
      KdPrint(("Unsupported set OID_802_3_MAXIMUM_LIST_SIZE\n"));
      break;
    case OID_TCP_TASK_OFFLOAD:
      status = NDIS_STATUS_SUCCESS;
      KdPrint(("Set OID_TCP_TASK_OFFLOAD\n"));
      // we should disable everything here, then enable what has been set
      ntoh = (PNDIS_TASK_OFFLOAD_HEADER)InformationBuffer;
      if (ntoh->Version != NDIS_TASK_OFFLOAD_VERSION)
      {
        KdPrint(("Invalid version (%d passed but must be %d)\n", ntoh->Version, NDIS_TASK_OFFLOAD_VERSION));
        status = NDIS_STATUS_INVALID_DATA;
        break;
      }
      if (ntoh->Version != NDIS_TASK_OFFLOAD_VERSION || ntoh->Size != sizeof(NDIS_TASK_OFFLOAD_HEADER))
      {
        KdPrint(("Invalid size (%d passed but must be %d)\n", ntoh->Size, sizeof(NDIS_TASK_OFFLOAD_HEADER)));
        status = NDIS_STATUS_INVALID_DATA;
        break;
      }
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
          nttic = (PNDIS_TASK_TCP_IP_CHECKSUM)nto->TaskBuffer;
          KdPrint(("TcpIpChecksumNdisTask\n"));
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
          /* check for stuff we outright don't support */
          if (nttic->V6Transmit.IpOptionsSupported ||
            nttic->V6Transmit.TcpOptionsSupported ||
            nttic->V6Transmit.TcpChecksum ||
            nttic->V6Transmit.UdpChecksum ||
            nttic->V6Receive.IpOptionsSupported ||
            nttic->V6Receive.TcpOptionsSupported ||
            nttic->V6Receive.TcpChecksum ||
            nttic->V6Receive.UdpChecksum)
          {
            KdPrint(("IPv6 offload not supported\n"));
            status = NDIS_STATUS_INVALID_DATA;
            nttic = NULL;
            break;
          }
          if (nttic->V4Transmit.IpOptionsSupported ||
            nttic->V4Transmit.IpChecksum)
          {
            KdPrint(("IPv4 IP Transmit offload not supported\n"));
            status = NDIS_STATUS_INVALID_DATA;
            nttic = NULL;
            break;
          }
          if (nttic->V4Receive.IpOptionsSupported &&
            !nttic->V4Receive.IpChecksum)
          {
            KdPrint(("Invalid combination\n"));
            status = NDIS_STATUS_INVALID_DATA;
            nttic = NULL;
            break;
          }
          if (nttic->V4Transmit.TcpOptionsSupported &&
            !nttic->V4Transmit.TcpChecksum)
          {
            KdPrint(("Invalid combination\n"));
            status = NDIS_STATUS_INVALID_DATA;
            nttic = NULL;
            break;
          }
          if (nttic->V4Receive.TcpOptionsSupported &&
            !nttic->V4Receive.TcpChecksum)
          {
            KdPrint(("Invalid combination\n"));
            status = NDIS_STATUS_INVALID_DATA;
            nttic = NULL;
            break;
          }
          break;
        case TcpLargeSendNdisTask:
          *BytesRead += sizeof(NDIS_TASK_TCP_LARGE_SEND);
          KdPrint(("TcpLargeSendNdisTask\n"));
          nttls = (PNDIS_TASK_TCP_LARGE_SEND)nto->TaskBuffer;
          KdPrint(("  MaxOffLoadSize                 = %d\n", nttls->MaxOffLoadSize));
          KdPrint(("  MinSegmentCount                = %d\n", nttls->MinSegmentCount));
          KdPrint(("  TcpOptions                     = %d\n", nttls->TcpOptions));
          KdPrint(("  IpOptions                      = %d\n", nttls->IpOptions));
          if (nttls->MinSegmentCount != MIN_LARGE_SEND_SEGMENTS)
          {
            KdPrint(("     MinSegmentCount should be %d\n", MIN_LARGE_SEND_SEGMENTS));
            status = NDIS_STATUS_INVALID_DATA;
            nttls = NULL;
            break;
          }
          if (nttls->IpOptions)
          {
            KdPrint(("     IpOptions not supported\n"));
            status = NDIS_STATUS_INVALID_DATA;
            nttls = NULL;
            break;
          }
          if (nttls->TcpOptions)
          {
            KdPrint(("     TcpOptions not supported\n"));
            status = NDIS_STATUS_INVALID_DATA;
            nttls = NULL;
            break;
          }
          break;
        default:
          KdPrint(("     Unknown Task %d\n", nto->Task));
        }
        offset = nto->OffsetNextTask;
      }
      if (nttic != NULL)
        xi->setting_csum = *nttic;
      else
      {
        RtlZeroMemory(&xi->setting_csum, sizeof(NDIS_TASK_TCP_IP_CHECKSUM));
        KdPrint(("     csum offload disabled\n", nto->Task));
      }        
      if (nttls != NULL)
        xi->setting_max_offload = nttls->MaxOffLoadSize;
      else
      {
        xi->setting_max_offload = 0;
        KdPrint(("     LSO disabled\n", nto->Task));
      }
      break;
    case OID_PNP_SET_POWER:
      KdPrint(("     Set OID_PNP_SET_POWER\n"));
      xi->new_power_state = *(PNDIS_DEVICE_POWER_STATE)InformationBuffer;
      IoQueueWorkItem(xi->power_workitem, XenNet_SetPower, DelayedWorkQueue, xi);
      status = NDIS_STATUS_PENDING;
      break;
#endif
    case OID_GEN_CURRENT_PACKET_FILTER:
      KdPrint(("Set OID_GEN_CURRENT_PACKET_FILTER (xi = %p)\n", xi));
      if (*(ULONG *)data & NDIS_PACKET_TYPE_DIRECTED)
        KdPrint(("  NDIS_PACKET_TYPE_DIRECTED\n"));
      if (*(ULONG *)data & NDIS_PACKET_TYPE_MULTICAST)
        KdPrint(("  NDIS_PACKET_TYPE_MULTICAST\n"));
      if (*(ULONG *)data & NDIS_PACKET_TYPE_ALL_MULTICAST)
        KdPrint(("  NDIS_PACKET_TYPE_ALL_MULTICAST\n"));
      if (*(ULONG *)data & NDIS_PACKET_TYPE_BROADCAST)
        KdPrint(("  NDIS_PACKET_TYPE_BROADCAST\n"));
      if (*(ULONG *)data & NDIS_PACKET_TYPE_PROMISCUOUS)
        KdPrint(("  NDIS_PACKET_TYPE_PROMISCUOUS\n"));
      if (*(ULONG *)data & NDIS_PACKET_TYPE_ALL_FUNCTIONAL)
        KdPrint(("  NDIS_PACKET_TYPE_ALL_FUNCTIONAL (not supported)\n"));
      if (*(ULONG *)data & NDIS_PACKET_TYPE_ALL_LOCAL)
        KdPrint(("  NDIS_PACKET_TYPE_ALL_LOCAL (not supported)\n"));  
      if (*(ULONG *)data & NDIS_PACKET_TYPE_FUNCTIONAL)
        KdPrint(("  NDIS_PACKET_TYPE_FUNCTIONAL (not supported)\n"));
      if (*(ULONG *)data & NDIS_PACKET_TYPE_GROUP)
        KdPrint(("  NDIS_PACKET_TYPE_GROUP (not supported)\n"));
      if (*(ULONG *)data & ~SUPPORTED_PACKET_FILTERS)
      {
        status = NDIS_STATUS_NOT_SUPPORTED;
        KdPrint(("  returning NDIS_STATUS_NOT_SUPPORTED\n"));
        break;
      }
      xi->packet_filter = *(ULONG *)data;
      status = NDIS_STATUS_SUCCESS;
      break;
    case OID_802_3_MULTICAST_LIST:
      KdPrint(("     Set OID_802_3_MULTICAST_LIST\n"));
      KdPrint(("       Length = %d\n", InformationBufferLength));
      KdPrint(("       Entries = %d\n", InformationBufferLength / 6));
      if (InformationBufferLength > MULTICAST_LIST_MAX_SIZE * 6)
      {
        status = NDIS_STATUS_MULTICAST_FULL;
        break;
      }
      
      if (InformationBufferLength % 6 != 0)
      {
        status = NDIS_STATUS_MULTICAST_FULL;
        break;
      }
      multicast_list = InformationBuffer;
      for (i = 0; i < InformationBufferLength / 6; i++)
      {
        if (!(multicast_list[i * 6 + 0] & 0x01))
        {
          KdPrint(("       Address %d (%02x:%02x:%02x:%02x:%02x:%02x) is not a multicast address\n", i,
            (ULONG)multicast_list[i * 6 + 0], (ULONG)multicast_list[i * 6 + 1], 
            (ULONG)multicast_list[i * 6 + 2], (ULONG)multicast_list[i * 6 + 3], 
            (ULONG)multicast_list[i * 6 + 4], (ULONG)multicast_list[i * 6 + 5]));
          /* the docs say that we should return NDIS_STATUS_MULTICAST_FULL if we get an invalid multicast address but I'm not sure if that's the case... */
        }
      }
      memcpy(xi->multicast_list, InformationBuffer, InformationBufferLength);
      xi->multicast_list_size = InformationBufferLength / 6;
      status = NDIS_STATUS_SUCCESS;
      break;
    case OID_GEN_CURRENT_LOOKAHEAD:
      xi->current_lookahead = *(ULONG *)data;
      KdPrint(("Set OID_GEN_CURRENT_LOOKAHEAD %d (%p)\n", xi->current_lookahead, xi));
      status = NDIS_STATUS_SUCCESS;
      break;
    default:
      KdPrint(("Set Unknown OID 0x%x\n", Oid));
    case OID_GEN_NETWORK_LAYER_ADDRESSES: /* this could tell us what IP addresses there are for us to send arps after a suspend/resume */
      status = NDIS_STATUS_NOT_SUPPORTED;
      break;
  }
  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return status;
}

#if 0
set 0001021a OID_GEN_MACHINE_NAME
get 00010111 OID_GEN_MAXIMUM_TOTAL_SIZE
get 00010209 OID_GEN_INTERRUPT_MODERATION
set 0001010e OID_GEN_CURRENT_PACKET_FILTER
set 0001010f OID_GEN_CURRENT_LOOKAHEAD
get 00010117 OID_GEN_SUPPORTED_GUIDS

stat 00020101 OID_GEN_XMIT_OK
#endif

NDIS_STATUS
XenNet_OidRequest(NDIS_HANDLE adapter_context, PNDIS_OID_REQUEST oid_request)
{
  NTSTATUS status;
  
  FUNCTION_ENTER();
  switch(oid_request->RequestType)
  {
  case NdisRequestQueryInformation:
    FUNCTION_MSG("RequestType = NdisRequestQueryInformation\n");
    //FUNCTION_MSG("Oid = %08x\n", oid_request->DATA.QUERY_INFORMATION.Oid);
    status = XenNet_QueryInformation(adapter_context,
      oid_request->DATA.QUERY_INFORMATION.Oid,
      oid_request->DATA.QUERY_INFORMATION.InformationBuffer,
      oid_request->DATA.QUERY_INFORMATION.InformationBufferLength,
      &oid_request->DATA.QUERY_INFORMATION.BytesWritten,
      &oid_request->DATA.QUERY_INFORMATION.BytesNeeded);
    break;
  case NdisRequestSetInformation:
    FUNCTION_MSG("RequestType = NdisRequestSetInformation\n");
    //FUNCTION_MSG("Oid = %08x\n", oid_request->DATA.SET_INFORMATION.Oid);
    status = XenNet_SetInformation(adapter_context,
      oid_request->DATA.SET_INFORMATION.Oid,
      oid_request->DATA.SET_INFORMATION.InformationBuffer,
      oid_request->DATA.SET_INFORMATION.InformationBufferLength,
      &oid_request->DATA.SET_INFORMATION.BytesRead,
      &oid_request->DATA.SET_INFORMATION.BytesNeeded);
    break;
  case NdisRequestQueryStatistics:
    FUNCTION_MSG("RequestType = NdisRequestQueryStatistics\n");
    //FUNCTION_MSG("Oid = %08x\n", oid_request->DATA.METHOD_INFORMATION.Oid);
    status = XenNet_QueryInformation(adapter_context,
      oid_request->DATA.QUERY_INFORMATION.Oid,
      oid_request->DATA.QUERY_INFORMATION.InformationBuffer,
      oid_request->DATA.QUERY_INFORMATION.InformationBufferLength,
      &oid_request->DATA.QUERY_INFORMATION.BytesWritten,
      &oid_request->DATA.QUERY_INFORMATION.BytesNeeded);
    break;
  default:
    FUNCTION_MSG("RequestType = NdisRequestQuery%d\n", oid_request->RequestType);
    status = NDIS_STATUS_NOT_SUPPORTED;
    break;
  }
  FUNCTION_EXIT();
  return status;
}

VOID
XenNet_CancelOidRequest(NDIS_HANDLE adapter_context, PVOID request_id)
{
  UNREFERENCED_PARAMETER(adapter_context);
  UNREFERENCED_PARAMETER(request_id);
  FUNCTION_ENTER();
  FUNCTION_EXIT();
}
