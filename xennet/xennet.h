/*
PV Drivers for Windows Xen HVM Domains
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

#pragma warning(disable: 4201)
#pragma warning(disable: 4214)

#ifdef __MINGW32__
#include <ntddk.h>
#define NDIS50_MINIPORT 1
#include <ndis.h>
#include "../mingw/mingw_extras.h"

#else
#define DDKAPI
#include <ntddk.h>
#include <wdm.h>
#define NDIS_MINIPORT_DRIVER
#if NTDDI_VERSION < NTDDI_WINXP
# define NDIS50_MINIPORT 1
#else
# define NDIS51_MINIPORT 1
#endif
#include <ndis.h>
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#endif


#define VENDOR_DRIVER_VERSION_MAJOR 0
#define VENDOR_DRIVER_VERSION_MINOR 9

#define VENDOR_DRIVER_VERSION (((VENDOR_DRIVER_VERSION_MAJOR) << 16) | (VENDOR_DRIVER_VERSION_MINOR))

#define __DRIVER_NAME "XenNet"

#include <xen_windows.h>
#include <memory.h>
#include <grant_table.h>
#include <event_channel.h>
#include <hvm/params.h>
#include <hvm/hvm_op.h>
#include <xen_public.h>
#include <io/ring.h>
#include <io/netif.h>
#include <io/xenbus.h>
#include <stdlib.h>
#define XENNET_POOL_TAG (ULONG) 'XenN'


/* Xen macros use these, so they need to be redefined to Win equivs */
#define wmb() KeMemoryBarrier()
#define mb() KeMemoryBarrier()

#define GRANT_INVALID_REF 0

#define NAME_SIZE 64

#define ETH_ALEN 6

/*
#define __NET_USHORT_BYTE_0(x) ((USHORT)(x & 0xFF))
#define __NET_USHORT_BYTE_1(x) ((USHORT)((PUCHAR)&x)[1] & 0xFF)

#define GET_NET_USHORT(x) ((__NET_USHORT_BYTE_0(x) << 8) | __NET_USHORT_BYTE_1(x))
#define SET_NET_USHORT(y, x) *((USHORT *)&(y)) = ((__NET_USHORT_BYTE_0(x) << 8) | __NET_USHORT_BYTE_1(x))
*/

static FORCEINLINE USHORT
GET_NET_USHORT(USHORT data)
{
  return (data << 8) | (data >> 8);
}

static FORCEINLINE USHORT
GET_NET_PUSHORT(PVOID pdata)
{
  return (*((PUSHORT)pdata) << 8) | (*((PUSHORT)pdata) >> 8);
}

static FORCEINLINE VOID
SET_NET_USHORT(PVOID ptr, USHORT data)
{
  *((PUSHORT)ptr) = GET_NET_USHORT(data);
}

static FORCEINLINE ULONG
GET_NET_ULONG(ULONG data)
{
  ULONG tmp;
  
  tmp = ((data & 0x00ff00ff) << 8) | ((data & 0xff00ff00) >> 8);
  return (tmp << 16) | (tmp >> 16);
}

static FORCEINLINE ULONG
GET_NET_PULONG(PVOID pdata)
{
  ULONG tmp;
  
  tmp = ((*((PULONG)pdata) & 0x00ff00ff) << 8) | ((*((PULONG)pdata) & 0xff00ff00) >> 8);
  return (tmp << 16) | (tmp >> 16);
}

static FORCEINLINE VOID
SET_NET_ULONG(PVOID ptr, ULONG data)
{
  *((PULONG)ptr) = GET_NET_ULONG(data);
}
/*
#define GET_NET_ULONG(x) ((GET_NET_USHORT(x) << 16) | GET_NET_USHORT(((PUCHAR)&x)[2]))
#define SET_NET_ULONG(y, x) *((ULONG *)&(y)) = ((GET_NET_USHORT(x) << 16) | GET_NET_USHORT(((PUCHAR)&x)[2]))
*/

#define SUPPORTED_PACKET_FILTERS (\
  NDIS_PACKET_TYPE_DIRECTED | \
  NDIS_PACKET_TYPE_MULTICAST | \
  NDIS_PACKET_TYPE_BROADCAST | \
  NDIS_PACKET_TYPE_PROMISCUOUS | \
  NDIS_PACKET_TYPE_ALL_MULTICAST)

/* couldn't get regular xen ring macros to work...*/
#define __NET_RING_SIZE(type, _sz) \
    (__RD32( \
    (_sz - sizeof(struct type##_sring) + sizeof(union type##_sring_entry)) \
    / sizeof(union type##_sring_entry)))

#define NET_TX_RING_SIZE __NET_RING_SIZE(netif_tx, PAGE_SIZE)
#define NET_RX_RING_SIZE __NET_RING_SIZE(netif_rx, PAGE_SIZE)

#pragma warning(disable: 4127) // conditional expression is constant

#define MIN_LARGE_SEND_SEGMENTS 4

/* TODO: crank this up if we support higher mtus? */
#define XN_HDR_SIZE 14
#define XN_MAX_DATA_SIZE 1500
#define XN_MIN_FRAME_SIZE 60
#define XN_MAX_FRAME_SIZE (XN_HDR_SIZE + XN_DATA_SIZE)
/*
#if !defined(OFFLOAD_LARGE_SEND)
  #define XN_MAX_PKT_SIZE (XN_HDR_SIZE + XN_DATA_SIZE)
#else
  #define XN_MAX_PKT_SIZE MAX_LARGE_SEND_OFFLOAD
#endif
*/

#define XN_MAX_SEND_PKTS 16

#define XENSOURCE_MAC_HDR 0x00163E
#define XN_VENDOR_DESC "Xensource"
#define MAX_XENBUS_STR_LEN 128

#define RX_MIN_TARGET 8
#define RX_DFL_MIN_TARGET 256
#define RX_MAX_TARGET min(NET_RX_RING_SIZE, 256)

//#define MAX_BUFFERS_PER_PACKET NET_RX_RING_SIZE

#define MAX_ETH_HEADER_SIZE 14
#define MIN_IP4_HEADER_SIZE 20
#define MAX_IP4_HEADER_SIZE (15 * 4)
#define MIN_TCP_HEADER_SIZE 20
#define MAX_TCP_HEADER_SIZE (15 * 4)
#define MAX_PKT_HEADER_SIZE (MAX_ETH_HEADER_SIZE + MAX_IP_HEADER_SIZE + MAX_TCP_HEADER_SIZE)

typedef struct
{
  PVOID next;
  PHYSICAL_ADDRESS logical;
  PVOID virtual;
  PNDIS_BUFFER buffer;
  USHORT id;
  USHORT ref_count;
} shared_buffer_t;

typedef struct
{
  PNDIS_PACKET packet; /* only set on the last packet */
  shared_buffer_t *hb;
} tx_shadow_t;

typedef struct {
  PNDIS_BUFFER first_buffer;
  PNDIS_BUFFER curr_buffer;
  shared_buffer_t *first_pb;
  shared_buffer_t *curr_pb;
  UCHAR header_data[132]; /* maximum possible size of ETH + IP + TCP/UDP headers */
  ULONG mdl_count;
  USHORT curr_mdl_offset;
  USHORT mss;
  NDIS_TCP_IP_CHECKSUM_PACKET_INFO csum_info;
  BOOLEAN csum_blank;
  BOOLEAN data_validated;
  BOOLEAN split_required;
  UCHAR ip_version;
  PUCHAR header;
  ULONG first_buffer_length;
  ULONG header_length;
  UCHAR ip_proto;
  ULONG total_length;
  USHORT ip4_header_length;
  USHORT ip4_length;
  USHORT tcp_header_length;
  BOOLEAN tcp_has_options;
  USHORT tcp_length;
  USHORT tcp_remaining;
  ULONG tcp_seq;
  BOOLEAN extra_info;
  BOOLEAN more_frags;
} packet_info_t;

#define PAGE_LIST_SIZE (max(NET_RX_RING_SIZE, NET_TX_RING_SIZE) * 4)
#define MULTICAST_LIST_MAX_SIZE 32

struct xennet_info
{
  BOOLEAN inactive;
  
  /* Base device vars */
  PDEVICE_OBJECT pdo;
  PDEVICE_OBJECT fdo;
  PDEVICE_OBJECT lower_do;
  //WDFDEVICE wdf_device;
  WCHAR dev_desc[NAME_SIZE];

  /* NDIS-related vars */
  NDIS_HANDLE adapter_handle;
  NDIS_MINIPORT_INTERRUPT interrupt;
  ULONG packet_filter;
  BOOLEAN connected;
  BOOLEAN shutting_down;
  uint8_t perm_mac_addr[ETH_ALEN];
  uint8_t curr_mac_addr[ETH_ALEN];

  /* Misc. Xen vars */
  XENPCI_VECTORS vectors;
  PXENPCI_DEVICE_STATE device_state;
  evtchn_port_t event_channel;
  ULONG state;
  char backend_path[MAX_XENBUS_STR_LEN];
  ULONG backend_state;
  PVOID config_page;
  UCHAR multicast_list[MULTICAST_LIST_MAX_SIZE][6];
  ULONG multicast_list_size;
  KDPC suspend_dpc;
  PIO_WORKITEM resume_work_item;

  /* tx related - protected by tx_lock */
  KSPIN_LOCK tx_lock;
  LIST_ENTRY tx_waiting_pkt_list;
  struct netif_tx_front_ring tx;
  ULONG tx_ring_free;
  tx_shadow_t tx_shadows[NET_TX_RING_SIZE];
  NDIS_HANDLE tx_buffer_pool;
#define TX_HEADER_BUFFER_SIZE 512
//#define TX_HEADER_BUFFERS (NET_TX_RING_SIZE >> 2)
#define TX_HEADER_BUFFERS (NET_TX_RING_SIZE)
  KEVENT tx_idle_event;
  ULONG tx_outstanding;
  ULONG tx_id_free;
  USHORT tx_id_list[NET_TX_RING_SIZE];
  ULONG tx_hb_free;
  ULONG tx_hb_list[TX_HEADER_BUFFERS];
  shared_buffer_t tx_hbs[TX_HEADER_BUFFERS];
  KDPC tx_dpc;

  /* rx_related - protected by rx_lock */
  KSPIN_LOCK rx_lock;
  struct netif_rx_front_ring rx;
  ULONG rx_id_free;
  packet_info_t rxpi;
  PNDIS_PACKET rx_packet_list[NET_RX_RING_SIZE * 2];
  ULONG rx_packet_free;
  KEVENT packet_returned_event;
  //NDIS_MINIPORT_TIMER rx_timer;
  KDPC rx_dpc;
  KTIMER rx_timer;
  KDPC rx_timer_dpc;
  NDIS_HANDLE rx_packet_pool;
  NDIS_HANDLE rx_buffer_pool;
  ULONG rx_pb_free;
#define RX_PAGE_BUFFERS (NET_RX_RING_SIZE * 2)
  ULONG rx_pb_list[RX_PAGE_BUFFERS];
  shared_buffer_t rx_pbs[RX_PAGE_BUFFERS];
  USHORT rx_ring_pbs[NET_RX_RING_SIZE];
#define LOOKASIDE_LIST_ALLOC_SIZE 256
  NPAGED_LOOKASIDE_LIST rx_lookaside_list;
  /* Receive-ring batched refills. */
  ULONG rx_target;
  ULONG rx_max_target;
  ULONG rx_min_target;

  /* how many packets are in the net stack atm */
  ULONG rx_outstanding;

  /* config vars from registry */
  ULONG config_sg;
  ULONG config_csum;
  ULONG config_csum_rx_check;
  ULONG config_gso;
  ULONG config_mtu;
  ULONG config_rx_interrupt_moderation;

  NDIS_TASK_TCP_IP_CHECKSUM setting_csum;
  ULONG setting_max_offload;

  /* config stuff calculated from the above */
  ULONG config_max_pkt_size;

  /* stats */
  ULONG64 stat_tx_ok;
  ULONG64 stat_rx_ok;
  ULONG64 stat_tx_error;
  ULONG64 stat_rx_error;
  ULONG64 stat_rx_no_buffer;
  
} typedef xennet_info_t;

VOID DDKAPI
XenNet_ReturnPacket(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PNDIS_PACKET Packet
  );

BOOLEAN
XenNet_RxInit(xennet_info_t *xi);

BOOLEAN
XenNet_RxShutdown(xennet_info_t *xi);

VOID
XenNet_RxResumeStart(xennet_info_t *xi);

VOID
XenNet_RxResumeEnd(xennet_info_t *xi);

VOID
XenNet_TxBufferGC(PKDPC dpc, PVOID context, PVOID arg1, PVOID arg2);

VOID
XenNet_TxResumeStart(xennet_info_t *xi);

VOID
XenNet_TxResumeEnd(xennet_info_t *xi);

VOID DDKAPI
XenNet_SendPackets(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PPNDIS_PACKET PacketArray,
  IN UINT NumberOfPackets
  );

BOOLEAN
XenNet_TxInit(xennet_info_t *xi);

BOOLEAN
XenNet_TxShutdown(xennet_info_t *xi);

NDIS_STATUS DDKAPI
XenNet_QueryInformation(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN NDIS_OID Oid,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength,
  OUT PULONG BytesWritten,
  OUT PULONG BytesNeeded);

NDIS_STATUS DDKAPI
XenNet_SetInformation(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN NDIS_OID Oid,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength,
  OUT PULONG BytesRead,
  OUT PULONG BytesNeeded
  );

/* return values */
#define PARSE_OK 0
#define PARSE_TOO_SMALL 1 /* first buffer is too small */
#define PARSE_UNKNOWN_TYPE 2

ULONG
XenNet_ParsePacketHeader(packet_info_t *pi);

VOID
XenNet_SumIpHeader(
  PUCHAR header,
  USHORT ip4_header_length
);

static __forceinline VOID
XenNet_ClearPacketInfo(packet_info_t *pi)
{
#if 1
  #if 0
  RtlZeroMemory(&pi->mdl_count, sizeof(packet_info_t) - FIELD_OFFSET(packet_info_t, mdl_count));
  #else
  RtlZeroMemory(pi, sizeof(packet_info_t));
  #endif
#else
  pi->mdl_count = 0;
  pi->curr_mdl_index = pi->curr_mdl_offset = 0;
  pi->extra_info = pi->more_frags = pi->csum_blank =
    pi->data_validated = pi->split_required = 0;
#endif
}
