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

#define DEF_OID_QUERY(oid, min_length) {oid, #oid, min_length, XenNet_Query##oid, NULL}
#define DEF_OID_QUERYSET(oid, min_length) {oid, #oid, min_length, XenNet_Query##oid, XenNet_Set##oid}
#define DEF_OID_SET(oid, min_length) {oid, #oid, min_length, NULL, XenNet_Set##oid}

#define DEF_OID_QUERY_STAT(oid) DEF_OID_QUERY(##oid, 0) /* has to be 0 so the 4/8 size works */
#define DEF_OID_QUERY_ULONG(oid) DEF_OID_QUERY(##oid, sizeof(ULONG))
#define DEF_OID_QUERYSET_ULONG(oid) DEF_OID_QUERYSET(##oid, sizeof(ULONG))
#define DEF_OID_SET_ULONG(oid) DEF_OID_SET(##oid, sizeof(ULONG))

/*
#define SET_ULONG(value) \
  do { \
    request->DATA.SET_INFORMATION.InformationBufferLength = sizeof(ULONG); \
    *(ULONG *)request->DATA.SET_INFORMATION.InformationBuffer = value; \
  } while (0);
*/
#define DEF_OID_QUERY_ROUTINE(oid, value, length) \
NDIS_STATUS \
XenNet_Query##oid(NDIS_HANDLE context, PNDIS_OID_REQUEST request) \
{ \
  struct xennet_info *xi = context; \
  UNREFERENCED_PARAMETER(xi); \
  if (request->DATA.QUERY_INFORMATION.InformationBufferLength < length) \
  { \
    request->DATA.QUERY_INFORMATION.BytesNeeded = length; \
    return NDIS_STATUS_BUFFER_TOO_SHORT; \
  } \
  request->DATA.QUERY_INFORMATION.BytesWritten = length; \
  NdisMoveMemory(request->DATA.QUERY_INFORMATION.InformationBuffer, value, length); \
  return STATUS_SUCCESS; \
}

#define DEF_OID_QUERY_ULONG_ROUTINE(oid, value) \
NDIS_STATUS \
XenNet_Query##oid(NDIS_HANDLE context, PNDIS_OID_REQUEST request) \
{ \
  struct xennet_info *xi = context; \
  UNREFERENCED_PARAMETER(xi); \
  request->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG); \
  *(ULONG *)request->DATA.QUERY_INFORMATION.InformationBuffer = value; \
  return STATUS_SUCCESS; \
}

#define DEF_OID_QUERY_STAT_ROUTINE(oid, value) \
NDIS_STATUS \
XenNet_Query##oid(NDIS_HANDLE context, PNDIS_OID_REQUEST request) \
{ \
  struct xennet_info *xi = context; \
  UNREFERENCED_PARAMETER(xi); \
  if (request->DATA.QUERY_INFORMATION.InformationBufferLength >= 8) \
  { \
    request->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG64); \
    *(ULONG64 *)request->DATA.QUERY_INFORMATION.InformationBuffer = (value); \
  } \
  else if (request->DATA.QUERY_INFORMATION.InformationBufferLength >= 4) \
  { \
    request->DATA.QUERY_INFORMATION.BytesWritten = sizeof(ULONG); \
    request->DATA.QUERY_INFORMATION.BytesNeeded = sizeof(ULONG64); \
    *(ULONG *)request->DATA.QUERY_INFORMATION.InformationBuffer = (ULONG)(value); \
  } \
  else \
  { \
    request->DATA.QUERY_INFORMATION.BytesNeeded = sizeof(ULONG64); \
    return NDIS_STATUS_BUFFER_TOO_SHORT; \
  } \
  return STATUS_SUCCESS; \
}

DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_MAXIMUM_TOTAL_SIZE, xi->current_mtu_value + XN_HDR_SIZE)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_CURRENT_PACKET_FILTER, xi->packet_filter)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_CURRENT_LOOKAHEAD, xi->current_lookahead)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_TRANSMIT_BUFFER_SPACE, PAGE_SIZE * NET_TX_RING_SIZE * 4)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_RECEIVE_BUFFER_SPACE, PAGE_SIZE * NET_RX_RING_SIZE * 2)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_TRANSMIT_BLOCK_SIZE, PAGE_SIZE)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_RECEIVE_BLOCK_SIZE, PAGE_SIZE)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_MAXIMUM_SEND_PACKETS, 0)
DEF_OID_QUERY_ULONG_ROUTINE(OID_802_3_MAXIMUM_LIST_SIZE, MULTICAST_LIST_MAX_SIZE)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_HARDWARE_STATUS, xi->connected?NdisHardwareStatusReady:NdisHardwareStatusInitializing)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_VENDOR_ID, 0xFFFFFF) // Not guaranteed to be XENSOURCE_MAC_HDR;
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_VENDOR_DRIVER_VERSION, VENDOR_DRIVER_VERSION)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_MEDIA_SUPPORTED, NdisMedium802_3)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_MEDIA_IN_USE, NdisMedium802_3)
DEF_OID_QUERY_ULONG_ROUTINE(OID_GEN_MAXIMUM_LOOKAHEAD, MAX_LOOKAHEAD_LENGTH)

DEF_OID_QUERY_STAT_ROUTINE(OID_GEN_XMIT_OK, xi->stats.ifHCOutUcastPkts + xi->stats.ifHCOutMulticastPkts + xi->stats.ifHCOutBroadcastPkts)
DEF_OID_QUERY_STAT_ROUTINE(OID_GEN_XMIT_ERROR, xi->stats.ifOutErrors)
DEF_OID_QUERY_STAT_ROUTINE(OID_GEN_RCV_OK, xi->stats.ifHCInUcastPkts + xi->stats.ifHCInMulticastPkts + xi->stats.ifHCInBroadcastPkts)
DEF_OID_QUERY_STAT_ROUTINE(OID_GEN_RCV_ERROR, xi->stats.ifInErrors)
DEF_OID_QUERY_STAT_ROUTINE(OID_GEN_RCV_NO_BUFFER, xi->stats.ifInDiscards)
DEF_OID_QUERY_STAT_ROUTINE(OID_802_3_RCV_ERROR_ALIGNMENT, 0)
DEF_OID_QUERY_STAT_ROUTINE(OID_802_3_XMIT_ONE_COLLISION, 0)
DEF_OID_QUERY_STAT_ROUTINE(OID_802_3_XMIT_MORE_COLLISIONS, 0)

DEF_OID_QUERY_ROUTINE(OID_GEN_VENDOR_DESCRIPTION, XN_VENDOR_DESC, sizeof(XN_VENDOR_DESC))

DEF_OID_QUERY_ROUTINE(OID_802_3_PERMANENT_ADDRESS, xi->perm_mac_addr, ETH_ALEN)
DEF_OID_QUERY_ROUTINE(OID_802_3_CURRENT_ADDRESS, xi->curr_mac_addr, ETH_ALEN)

DEF_OID_QUERY_ROUTINE(OID_802_3_MULTICAST_LIST, xi->multicast_list, xi->multicast_list_size * 6)

NDIS_STATUS
XenNet_SetOID_802_3_MULTICAST_LIST(NDIS_HANDLE context, PNDIS_OID_REQUEST request)
{
  struct xennet_info *xi = context;
  UCHAR *multicast_list;
  int i;

  if (request->DATA.SET_INFORMATION.InformationBufferLength > MULTICAST_LIST_MAX_SIZE * 6)
  {
    return NDIS_STATUS_MULTICAST_FULL;
  }
  
  if (request->DATA.SET_INFORMATION.InformationBufferLength % 6 != 0)
  {
    return NDIS_STATUS_MULTICAST_FULL;
  }
  multicast_list = request->DATA.SET_INFORMATION.InformationBuffer;
  for (i = 0; i < (int)request->DATA.SET_INFORMATION.InformationBufferLength / 6; i++)
  {
    if (!(multicast_list[i * 6 + 0] & 0x01))
    {
      FUNCTION_MSG("Address %d (%02x:%02x:%02x:%02x:%02x:%02x) is not a multicast address\n", i,
        (ULONG)multicast_list[i * 6 + 0], (ULONG)multicast_list[i * 6 + 1], 
        (ULONG)multicast_list[i * 6 + 2], (ULONG)multicast_list[i * 6 + 3], 
        (ULONG)multicast_list[i * 6 + 4], (ULONG)multicast_list[i * 6 + 5]);
      /* the docs say that we should return NDIS_STATUS_MULTICAST_FULL if we get an invalid multicast address but I'm not sure if that's the case... */
    }
  }
  memcpy(xi->multicast_list, multicast_list, request->DATA.SET_INFORMATION.InformationBufferLength);
  xi->multicast_list_size = request->DATA.SET_INFORMATION.InformationBufferLength / 6;
  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
XenNet_SetOID_GEN_CURRENT_PACKET_FILTER(NDIS_HANDLE context, PNDIS_OID_REQUEST request)
{
  struct xennet_info *xi = context;
  PULONG data = request->DATA.SET_INFORMATION.InformationBuffer;
  
  request->DATA.SET_INFORMATION.BytesNeeded = sizeof(ULONG64);
  if (*data & NDIS_PACKET_TYPE_DIRECTED)
    FUNCTION_MSG("NDIS_PACKET_TYPE_DIRECTED\n");
  if (*data & NDIS_PACKET_TYPE_MULTICAST)
    FUNCTION_MSG("NDIS_PACKET_TYPE_MULTICAST\n");
  if (*data & NDIS_PACKET_TYPE_ALL_MULTICAST)
    FUNCTION_MSG("NDIS_PACKET_TYPE_ALL_MULTICAST\n");
  if (*data & NDIS_PACKET_TYPE_BROADCAST)
    FUNCTION_MSG("NDIS_PACKET_TYPE_BROADCAST\n");
  if (*data & NDIS_PACKET_TYPE_PROMISCUOUS)
    FUNCTION_MSG("NDIS_PACKET_TYPE_PROMISCUOUS\n");
  if (*data & NDIS_PACKET_TYPE_ALL_FUNCTIONAL)
    FUNCTION_MSG("NDIS_PACKET_TYPE_ALL_FUNCTIONAL (not supported)\n");
  if (*data & NDIS_PACKET_TYPE_ALL_LOCAL)
    FUNCTION_MSG("NDIS_PACKET_TYPE_ALL_LOCAL (not supported)\n");
  if (*data & NDIS_PACKET_TYPE_FUNCTIONAL)
    FUNCTION_MSG("NDIS_PACKET_TYPE_FUNCTIONAL (not supported)\n");
  if (*data & NDIS_PACKET_TYPE_GROUP)
    FUNCTION_MSG("NDIS_PACKET_TYPE_GROUP (not supported)\n");
  if (*data & ~SUPPORTED_PACKET_FILTERS)
  {
    FUNCTION_MSG("returning NDIS_STATUS_NOT_SUPPORTED\n");
    return NDIS_STATUS_NOT_SUPPORTED;
  }
  xi->packet_filter = *(ULONG *)data;
  request->DATA.SET_INFORMATION.BytesRead = sizeof(ULONG);
  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
XenNet_SetOID_GEN_CURRENT_LOOKAHEAD(NDIS_HANDLE context, PNDIS_OID_REQUEST request)
{
  struct xennet_info *xi = context;
  PULONG data = request->DATA.QUERY_INFORMATION.InformationBuffer;
  xi->current_lookahead = *(ULONG *)data;
  FUNCTION_MSG("Set OID_GEN_CURRENT_LOOKAHEAD %d (%p)\n", xi->current_lookahead, xi);
  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
XenNet_SetOID_GEN_LINK_PARAMETERS(NDIS_HANDLE context, PNDIS_OID_REQUEST request)
{
  UNREFERENCED_PARAMETER(context);
  UNREFERENCED_PARAMETER(request);
  return STATUS_NOT_SUPPORTED;
}

NDIS_STATUS
XenNet_QueryOID_GEN_INTERRUPT_MODERATION(NDIS_HANDLE context, PNDIS_OID_REQUEST request)
{
  PNDIS_INTERRUPT_MODERATION_PARAMETERS nimp;
  UNREFERENCED_PARAMETER(context);
  nimp = (PNDIS_INTERRUPT_MODERATION_PARAMETERS)request->DATA.QUERY_INFORMATION.InformationBuffer;
  nimp->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
  nimp->Header.Revision = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
  nimp->Header.Size = NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
  nimp->Flags = 0;
  nimp->InterruptModeration = NdisInterruptModerationNotSupported;
  request->DATA.SET_INFORMATION.BytesRead = sizeof(NDIS_INTERRUPT_MODERATION_PARAMETERS);
  return STATUS_SUCCESS;
}

NDIS_STATUS
XenNet_SetOID_GEN_INTERRUPT_MODERATION(NDIS_HANDLE context, PNDIS_OID_REQUEST request)
{
  UNREFERENCED_PARAMETER(context);
  UNREFERENCED_PARAMETER(request);
  return STATUS_NOT_SUPPORTED;
}

NDIS_STATUS
XenNet_QueryOID_GEN_STATISTICS(NDIS_HANDLE context, PNDIS_OID_REQUEST request)
{
  struct xennet_info *xi = context;

  NdisMoveMemory(request->DATA.QUERY_INFORMATION.InformationBuffer, &xi->stats, sizeof(NDIS_STATISTICS_INFO));
  request->DATA.SET_INFORMATION.BytesRead = sizeof(NDIS_STATISTICS_INFO);
  return STATUS_SUCCESS;
}

NDIS_STATUS
XenNet_SetOID_PNP_SET_POWER(NDIS_HANDLE context, PNDIS_OID_REQUEST request)
{
  UNREFERENCED_PARAMETER(context);
  UNREFERENCED_PARAMETER(request);
  return STATUS_NOT_SUPPORTED;
}

NDIS_STATUS
XenNet_SetOID_GEN_NETWORK_LAYER_ADDRESSES(NDIS_HANDLE context, PNDIS_OID_REQUEST request)
{
  PNETWORK_ADDRESS_LIST nal = request->DATA.QUERY_INFORMATION.InformationBuffer;
  PNETWORK_ADDRESS na;
  PNETWORK_ADDRESS_IP ip;
  int i;
  
  UNREFERENCED_PARAMETER(context);
  FUNCTION_MSG("AddressType = %d\n", nal->AddressType);
  FUNCTION_MSG("AddressCount = %d\n", nal->AddressCount);
  if (nal->AddressCount == 0)
  {
    // remove addresses of AddressType type
  }
  else
  {
    na = nal->Address;
    for (i = 0; i < nal->AddressCount; i++)
    {
      if ((ULONG_PTR)na - (ULONG_PTR)nal + FIELD_OFFSET(NETWORK_ADDRESS, Address) + na->AddressLength > request->DATA.QUERY_INFORMATION.InformationBufferLength)
      {
        FUNCTION_MSG("Out of bounds\n");
        return NDIS_STATUS_INVALID_DATA;
      }
      switch(na->AddressType)
      {
      case NDIS_PROTOCOL_ID_TCP_IP:
        FUNCTION_MSG("Address[%d].Type = NDIS_PROTOCOL_ID_TCP_IP\n", i);
        FUNCTION_MSG("Address[%d].Length = %d\n", i, na->AddressLength);
        if (na->AddressLength != NETWORK_ADDRESS_LENGTH_IP)
        {
          FUNCTION_MSG("Length is invalid\n");
          break;
        }
        ip = (PNETWORK_ADDRESS_IP)na->Address;
        FUNCTION_MSG("Address[%d].in_addr = %d.%d.%d.%d\n", i, ip->in_addr & 0xff, (ip->in_addr >> 8) & 0xff, (ip->in_addr >> 16) & 0xff, (ip->in_addr >> 24) & 0xff);
        break;
      default:
        FUNCTION_MSG("Address[%d].Type = %d\n", i, na->AddressType);
        FUNCTION_MSG("Address[%d].Length = %d\n", i, na->AddressLength);
        break;
      }
      na = (PNETWORK_ADDRESS)((PUCHAR)na + FIELD_OFFSET(NETWORK_ADDRESS, Address) + na->AddressLength);
    }
  }
  
  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
XenNet_SetOID_GEN_MACHINE_NAME(NDIS_HANDLE context, PNDIS_OID_REQUEST request)
{
  UNICODE_STRING name;
  UNREFERENCED_PARAMETER(context);
  
  name.Length = (USHORT)request->DATA.QUERY_INFORMATION.InformationBufferLength;
  name.MaximumLength = (USHORT)request->DATA.QUERY_INFORMATION.InformationBufferLength;
  name.Buffer = request->DATA.QUERY_INFORMATION.InformationBuffer;
  FUNCTION_MSG("name = %wZ\n", &name);
  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
XenNet_SetOID_OFFLOAD_ENCAPSULATION(NDIS_HANDLE context, PNDIS_OID_REQUEST request)
{
  struct xennet_info *xi = context;
  /* mostly assume that NDIS vets the settings for us */
  PNDIS_OFFLOAD_ENCAPSULATION noe = (PNDIS_OFFLOAD_ENCAPSULATION)request->DATA.SET_INFORMATION.InformationBuffer;
  if (noe->IPv4.EncapsulationType != NDIS_ENCAPSULATION_IEEE_802_3)
  {
    FUNCTION_MSG("Unknown Encapsulation Type %d\n", noe->IPv4.EncapsulationType);
    return NDIS_STATUS_NOT_SUPPORTED;
  }
    
  switch(noe->IPv4.Enabled)
  {
  case NDIS_OFFLOAD_SET_ON:
    FUNCTION_MSG(" IPv4.Enabled = NDIS_OFFLOAD_SET_ON\n");
    xi->current_csum_supported = xi->backend_csum_supported && xi->frontend_csum_supported;
    xi->current_gso_value = min(xi->backend_csum_supported, xi->frontend_csum_supported);
    break;
  case NDIS_OFFLOAD_SET_OFF:
    FUNCTION_MSG(" IPv4.Enabled = NDIS_OFFLOAD_SET_OFF\n");
    xi->current_csum_supported = FALSE;
    xi->current_gso_value = 0;
    break;
  case NDIS_OFFLOAD_SET_NO_CHANGE:
    FUNCTION_MSG(" IPv4.Enabled = NDIS_OFFLOAD_NO_CHANGE\n");
    break;
  }
  FUNCTION_MSG(" IPv4.HeaderSize = %d\n", noe->IPv4.HeaderSize);
  FUNCTION_MSG(" IPv6.EncapsulationType = %d\n", noe->IPv6.EncapsulationType);
  switch(noe->IPv6.Enabled)
  {
  case NDIS_OFFLOAD_SET_ON:
    FUNCTION_MSG(" IPv6.Enabled = NDIS_OFFLOAD_SET_ON (this is an error)\n");
    break;
  case NDIS_OFFLOAD_SET_OFF:
    FUNCTION_MSG(" IPv6.Enabled = NDIS_OFFLOAD_SET_OFF\n");
    break;
  case NDIS_OFFLOAD_SET_NO_CHANGE:
    FUNCTION_MSG(" IPv6.Enabled = NDIS_OFFLOAD_NO_CHANGE\n");
    break;
  }
  FUNCTION_MSG(" IPv6.HeaderSize = %d\n", noe->IPv6.HeaderSize);
  return NDIS_STATUS_SUCCESS;
}

struct xennet_oids_t xennet_oids[] = {
  DEF_OID_QUERY_ULONG(OID_GEN_HARDWARE_STATUS),

  DEF_OID_QUERY_ULONG(OID_GEN_TRANSMIT_BUFFER_SPACE),
  DEF_OID_QUERY_ULONG(OID_GEN_RECEIVE_BUFFER_SPACE),
  DEF_OID_QUERY_ULONG(OID_GEN_TRANSMIT_BLOCK_SIZE),
  DEF_OID_QUERY_ULONG(OID_GEN_RECEIVE_BLOCK_SIZE),

  DEF_OID_QUERY_ULONG(OID_GEN_VENDOR_ID),
  DEF_OID_QUERY(OID_GEN_VENDOR_DESCRIPTION, sizeof(XN_VENDOR_DESC)),
  DEF_OID_QUERY_ULONG(OID_GEN_VENDOR_DRIVER_VERSION),

  DEF_OID_QUERYSET_ULONG(OID_GEN_CURRENT_PACKET_FILTER),
  DEF_OID_QUERYSET_ULONG(OID_GEN_CURRENT_LOOKAHEAD),
  //DEF_OID_QUERY(OID_GEN_DRIVER_VERSION),
  DEF_OID_QUERY_ULONG(OID_GEN_MAXIMUM_TOTAL_SIZE),
  DEF_OID_SET(OID_GEN_LINK_PARAMETERS, sizeof(NDIS_LINK_PARAMETERS)),
  DEF_OID_QUERYSET(OID_GEN_INTERRUPT_MODERATION, sizeof(NDIS_INTERRUPT_MODERATION_PARAMETERS)),
  
  DEF_OID_QUERY_ULONG(OID_GEN_MAXIMUM_SEND_PACKETS),

  /* general optional */
  DEF_OID_SET(OID_GEN_NETWORK_LAYER_ADDRESSES, FIELD_OFFSET(NETWORK_ADDRESS_LIST, Address)),
  DEF_OID_SET(OID_GEN_MACHINE_NAME, 0),
  DEF_OID_SET(OID_OFFLOAD_ENCAPSULATION, sizeof(NDIS_OFFLOAD_ENCAPSULATION)),
  //DEF_OID_QUERY(OID_GEN_TRANSPORT_HEADER_OFFSET, sizeof(TRANSPORT_HEADER_OFFSET)),

  /* power */
  //DEF_OID_QUERY(OID_PNP_CAPABILITIES, sizeof(NDIS_PNP_CAPABILITIES)),
  DEF_OID_SET_ULONG(OID_PNP_SET_POWER),
  //DEF_OID_QUERY_ULONG(OID_PNP_QUERY_POWER),
  
  /* stats */
  DEF_OID_QUERY_STAT(OID_GEN_XMIT_OK),
  DEF_OID_QUERY_STAT(OID_GEN_RCV_OK),
  DEF_OID_QUERY_STAT(OID_GEN_XMIT_ERROR),
  DEF_OID_QUERY_STAT(OID_GEN_RCV_ERROR),
  DEF_OID_QUERY_STAT(OID_GEN_RCV_NO_BUFFER),
  DEF_OID_QUERY_STAT(OID_802_3_RCV_ERROR_ALIGNMENT),
  DEF_OID_QUERY_STAT(OID_802_3_XMIT_ONE_COLLISION),
  DEF_OID_QUERY_STAT(OID_802_3_XMIT_MORE_COLLISIONS),
  DEF_OID_QUERY_ULONG(OID_GEN_MEDIA_SUPPORTED),
  DEF_OID_QUERY_ULONG(OID_GEN_MEDIA_IN_USE),
  DEF_OID_QUERY(OID_GEN_STATISTICS, sizeof(NDIS_STATISTICS_INFO)),
  DEF_OID_QUERY_ULONG(OID_GEN_MAXIMUM_LOOKAHEAD),
  /* media-specific */
  DEF_OID_QUERY(OID_802_3_PERMANENT_ADDRESS, 6),
  DEF_OID_QUERY(OID_802_3_CURRENT_ADDRESS, 6),
  DEF_OID_QUERYSET(OID_802_3_MULTICAST_LIST, 0),
  DEF_OID_QUERY_ULONG(OID_802_3_MAXIMUM_LIST_SIZE),
  
#if 0
  /* tcp offload */
  DEF_OID_QUERY(OID_TCP_TASK_OFFLOAD,
  DEF_OID_QUERY(OID_TCP_OFFLOAD_PARAMETERS,
  DEF_OID_QUERY(OID_OFFLOAD_ENCAPSULATION,
#endif

  {0, "", 0, NULL, NULL}
};

static NDIS_OID supported_oids[ARRAY_SIZE(xennet_oids)];

#if 0
/* return 4 or 8 depending on size of buffer */
#define HANDLE_STAT_RETURN \
  {if (InformationBufferLength == 4) { \
    len = 4; *BytesNeeded = 8; \
    } else { \
    len = 8; \
    } }

#define SET_LEN_AND_BREAK_IF_SHORT(_len) if ((len = _len) > InformationBufferLength) break;

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
  UCHAR vendor_desc[] = XN_VENDOR_DESC;
#if 0
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
    case OID_GEN_MEDIA_SUPPORTED:
      temp_data = NdisMedium802_3;
      break;
    case OID_GEN_MEDIA_IN_USE:
      temp_data = NdisMedium802_3;
      break;
    case OID_GEN_MAXIMUM_LOOKAHEAD:
      temp_data = MAX_LOOKAHEAD_LENGTH; //xi->config_mtu_value;
      break;
    case OID_GEN_MAXIMUM_FRAME_SIZE:
      temp_data = xi->config_mtu_value;
      break;
    case OID_GEN_LINK_SPEED:
      temp_data = 10000000; /* 1Gb */
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
      temp_data = xi->current_mtu_value + XN_HDR_SIZE;
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
    case OID_GEN_VENDOR_ID:
      FUNCTION_MSG("OID_GEN_VENDOR_ID InformationBufferLength = %d\n", InformationBufferLength);
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
    case OID_TCP_CONNECTION_OFFLOAD_HARDWARE_CAPABILITIES:
      FUNCTION_MSG("Unhandled OID_TCP_CONNECTION_OFFLOAD_HARDWARE_CAPABILITIES\n");
      break;
    case OID_TCP_CONNECTION_OFFLOAD_CURRENT_CONFIG:
      FUNCTION_MSG("Unhandled OID_TCP_CONNECTION_OFFLOAD_HARDWARE_CAPABILITIES\n");
      break;
    case OID_TCP_OFFLOAD_CURRENT_CONFIG:
      FUNCTION_MSG("Unhandled OID_TCP_OFFLOAD_CURRENT_CONFIG\n");
      break;
    case OID_GEN_MAXIMUM_SEND_PACKETS:
      /* this is actually ignored for deserialised drivers like us */
      temp_data = 0;
      break;
    case OID_GEN_HARDWARE_STATUS:
      if (!xi->connected)
      {
        temp_data = NdisHardwareStatusInitializing;
      }
      else
      {
        temp_data = NdisHardwareStatusReady;
      }
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
    default:
      FUNCTION_MSG("Unhandled get OID_%08x\n", Oid);
    /* silently fail these */
    case OID_GEN_SUPPORTED_GUIDS:
    case OID_IP4_OFFLOAD_STATS:
    case OID_IP6_OFFLOAD_STATS:
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
    FUNCTION_MSG("(BUFFER_TOO_SHORT OID_%08x len = %d > InformationBufferLength %d)\n", Oid, len, InformationBufferLength);
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

static NDIS_STATUS
XenNet_QueryStatistics(
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
  PNDIS_STATISTICS_INFO nsi;
  //PIP_OFFLOAD_STATS ios;
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
#endif
    case OID_GEN_STATISTICS:
      SET_LEN_AND_BREAK_IF_SHORT(sizeof(NDIS_STATISTICS_INFO));
      nsi = (PNDIS_STATISTICS_INFO)InformationBuffer;
      nsi->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
      nsi->Header.Revision = NDIS_STATISTICS_INFO_REVISION_1;
      nsi->Header.Size = NDIS_SIZEOF_STATISTICS_INFO_REVISION_1;
      nsi->SupportedStatistics = 0;
      break;    
    case OID_GEN_XMIT_OK:
      temp_data = xi->stat_tx_ok;
      HANDLE_STAT_RETURN;
      break;
    case OID_GEN_RCV_OK:
      temp_data = xi->stat_rx_ok;
      HANDLE_STAT_RETURN;
      break;
#if 0
    case OID_IP4_OFFLOAD_STATS:
#if 0
      SET_LEN_AND_BREAK_IF_SHORT(sizeof(IP_OFFLOAD_STATS));
      ios = (PIP_OFFLOAD_STATS)InformationBuffer;
      ios->InReceives = 0;
      ios->InOctets = 0;
      ios->InDelivers = 0;
      ios->OutRequests = 0;
      ios->OutOctets = 0;
      ios->InHeaderErrors = 0;
      ios->InTruncatedPackets = 0;
      ios->InDiscards = 0;
      ios->OutDiscards= 0;
      ios->OutNoRoutes = 0;
#endif
      status = NDIS_STATUS_NOT_SUPPORTED;
      break;
    case OID_IP6_OFFLOAD_STATS:
#if 0
      SET_LEN_AND_BREAK_IF_SHORT(sizeof(IP_OFFLOAD_STATS));
      ios = (PIP_OFFLOAD_STATS)InformationBuffer;
      ios->InReceives = 0;
      ios->InOctets = 0;
      ios->InDelivers = 0;
      ios->OutRequests = 0;
      ios->OutOctets = 0;
      ios->InHeaderErrors = 0;
      ios->InTruncatedPackets = 0;
      ios->InDiscards = 0;
      ios->OutDiscards= 0;
      ios->OutNoRoutes = 0;
#endif
      status = NDIS_STATUS_NOT_SUPPORTED;
      break;
#endif
    case OID_TCP_CONNECTION_OFFLOAD_HARDWARE_CAPABILITIES:
      FUNCTION_MSG("Unhandled statistic OID_TCP_CONNECTION_OFFLOAD_HARDWARE_CAPABILITIES\n");
      break;
    case OID_TCP_CONNECTION_OFFLOAD_CURRENT_CONFIG:
      FUNCTION_MSG("Unhandled statistic OID_TCP_CONNECTION_OFFLOAD_HARDWARE_CAPABILITIES\n");
      break;
    case OID_TCP_OFFLOAD_CURRENT_CONFIG:
      FUNCTION_MSG("Unhandled statistic OID_TCP_OFFLOAD_CURRENT_CONFIG\n");
      break;
    default:
      KdPrint(("Unhandled statistics OID_%08x\n", Oid));
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

static NDIS_STATUS
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
  PNDIS_OFFLOAD_ENCAPSULATION noe;
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
      FUNCTION_MSG("Set OID_GEN_CURRENT_LOOKAHEAD %d (%p)\n", xi->current_lookahead, xi);
      status = NDIS_STATUS_SUCCESS;
      break;
    case OID_OFFLOAD_ENCAPSULATION:
      /* mostly assume that NDIS vets the settings for us */
      noe = (PNDIS_OFFLOAD_ENCAPSULATION)InformationBuffer;
      FUNCTION_MSG("Set OID_OFFLOAD_ENCAPSULATION\n");
      if (noe->IPv4.EncapsulationType != NDIS_ENCAPSULATION_IEEE_802_3)
      {
        status = NDIS_STATUS_NOT_SUPPORTED;
        FUNCTION_MSG("Unknown Encapsulation Type %d\n", noe->IPv4.EncapsulationType);
        break;
      }
        
      switch(noe->IPv4.Enabled)
      {
      case NDIS_OFFLOAD_SET_ON:
        FUNCTION_MSG(" IPv4.Enabled = NDIS_OFFLOAD_SET_ON\n");
        xi->current_csum_supported = xi->backend_csum_supported && xi->frontend_csum_supported;
        xi->current_gso_value = min(xi->backend_csum_supported, xi->frontend_csum_supported);
        break;
      case NDIS_OFFLOAD_SET_OFF:
        FUNCTION_MSG(" IPv4.Enabled = NDIS_OFFLOAD_SET_OFF\n");
        xi->current_csum_supported = FALSE;
        xi->current_gso_value = 0;
        break;
      case NDIS_OFFLOAD_SET_NO_CHANGE:
        FUNCTION_MSG(" IPv4.Enabled = NDIS_OFFLOAD_NO_CHANGE\n");
        break;
      }
      FUNCTION_MSG(" IPv4.HeaderSize = %d\n", noe->IPv4.HeaderSize);
      FUNCTION_MSG(" IPv6.EncapsulationType = %d\n", noe->IPv6.EncapsulationType);
      switch(noe->IPv6.Enabled)
      {
      case NDIS_OFFLOAD_SET_ON:
        FUNCTION_MSG(" IPv6.Enabled = NDIS_OFFLOAD_SET_ON (this is an error)\n");
        break;
      case NDIS_OFFLOAD_SET_OFF:
        FUNCTION_MSG(" IPv6.Enabled = NDIS_OFFLOAD_SET_OFF\n");
        break;
      case NDIS_OFFLOAD_SET_NO_CHANGE:
        FUNCTION_MSG(" IPv6.Enabled = NDIS_OFFLOAD_NO_CHANGE\n");
        break;
      }
      FUNCTION_MSG(" IPv6.HeaderSize = %d\n", noe->IPv6.HeaderSize);
      status = NDIS_STATUS_SUCCESS;
      break;
    default:
      FUNCTION_MSG("Unhandled set OID_%08x\n", Oid);
    case OID_GEN_NETWORK_LAYER_ADDRESSES: /* this could tell us what IP addresses there are for us to send arps after a suspend/resume */
    case OID_GEN_MACHINE_NAME:
      status = NDIS_STATUS_NOT_SUPPORTED;
      break;
  }
  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return status;
}
#endif

NDIS_STATUS
XenNet_OidRequest(NDIS_HANDLE adapter_context, PNDIS_OID_REQUEST oid_request)
{
  NTSTATUS status;
  int i;
  NDIS_OID oid;
  MINIPORT_OID_REQUEST *routine;
  
  //FUNCTION_ENTER();
  switch(oid_request->RequestType)
  {
  case NdisRequestQueryInformation:
    FUNCTION_MSG("RequestType = NdisRequestQueryInformation\n");
    //FUNCTION_MSG("Oid = %08x\n", oid_request->DATA.QUERY_INFORMATION.Oid);
    oid = oid_request->DATA.QUERY_INFORMATION.Oid;
    break;
  case NdisRequestSetInformation:
    FUNCTION_MSG("RequestType = NdisRequestSetInformation\n");
    oid = oid_request->DATA.SET_INFORMATION.Oid;
    break;
  case NdisRequestQueryStatistics:
    FUNCTION_MSG("RequestType = NdisRequestQueryStatistics\n");
    oid = oid_request->DATA.QUERY_INFORMATION.Oid;
    break;
  default:
    FUNCTION_MSG("RequestType = NdisRequestQuery%d\n", oid_request->RequestType);
    return NDIS_STATUS_NOT_SUPPORTED;
  }
  for (i = 0; xennet_oids[i].oid && xennet_oids[i].oid != oid; i++);

  if (!xennet_oids[i].oid)
  {
    FUNCTION_MSG("Unsupported OID %08x\n", oid);
    return NDIS_STATUS_NOT_SUPPORTED;
  }
  FUNCTION_MSG("Oid = %s\n", xennet_oids[i].oid_name);
  routine = NULL;
  switch(oid_request->RequestType)
  {
  case NdisRequestQueryInformation:
  case NdisRequestQueryStatistics:
    if (oid_request->DATA.QUERY_INFORMATION.InformationBufferLength < xennet_oids[i].min_length)
    {
      FUNCTION_MSG("InformationBufferLength %d < min_length %d\n", oid_request->DATA.QUERY_INFORMATION.InformationBufferLength < xennet_oids[i].min_length);
      oid_request->DATA.QUERY_INFORMATION.BytesNeeded = xennet_oids[i].min_length;
      return NDIS_STATUS_BUFFER_TOO_SHORT;
    }
    routine =  xennet_oids[i].query_routine;
    break;
  case NdisRequestSetInformation:
    if (oid_request->DATA.SET_INFORMATION.InformationBufferLength < xennet_oids[i].min_length)
    {
      FUNCTION_MSG("InformationBufferLength %d < min_length %d\n", oid_request->DATA.SET_INFORMATION.InformationBufferLength < xennet_oids[i].min_length);
      oid_request->DATA.SET_INFORMATION.BytesNeeded = xennet_oids[i].min_length;
      return NDIS_STATUS_BUFFER_TOO_SHORT;
    }
    routine =  xennet_oids[i].set_routine;
    break;
  }
  if (!routine)
  {
    FUNCTION_MSG("Operation not supported\n");
    return NDIS_STATUS_NOT_SUPPORTED;
  }
  status = routine(adapter_context, oid_request);
  FUNCTION_MSG("status = %08x\n", status);
  
  //FUNCTION_EXIT();
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
