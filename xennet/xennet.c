/*
PV Net Driver for Windows Xen HVM Domains
Copyright (C) 2007 James Harper
Copyright (C) 2007 Andrew Grover

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

#include <stdlib.h>
#include <io/xenbus.h>
#include "xennet.h"

#if !defined (NDIS51_MINIPORT)
#error requires NDIS 5.1 compilation environment
#endif

#define GRANT_INVALID_REF	0

#define NET_TX_RING_SIZE __RING_SIZE((struct netif_tx_sring *)0, PAGE_SIZE)
#define NET_RX_RING_SIZE __RING_SIZE((struct netif_rx_sring *)0, PAGE_SIZE)

#pragma warning(disable: 4127)

struct xennet_info
{
  PDEVICE_OBJECT pdo;
  PDEVICE_OBJECT fdo;
  PDEVICE_OBJECT lower_do;
  WDFDEVICE wdf_device;

  WCHAR name[NAME_SIZE];
  NDIS_HANDLE adapter_handle;
  ULONG packet_filter;
  int connected;
  UINT8 perm_mac_addr[ETH_ALEN];
  UINT8 curr_mac_addr[ETH_ALEN];

  char Path[128];
  char BackendPath[128];
  XEN_IFACE_EVTCHN EvtChnInterface;
  XEN_IFACE_XENBUS XenBusInterface;
  XEN_IFACE_XEN XenInterface;
  XEN_IFACE_GNTTBL GntTblInterface;

  struct netif_tx_front_ring tx;
  struct netif_rx_front_ring rx;

  PMDL tx_mdl;
  PMDL rx_mdl;
  struct netif_tx_sring *tx_pgs;
  struct netif_rx_sring *rx_pgs;

  UINT irq;
  evtchn_port_t event_channel;

  grant_ref_t tx_ring_ref;
  grant_ref_t rx_ring_ref;
};

/* need to do typedef so the DECLARE below works */
typedef struct _wdf_device_info
{
  struct xennet_info *xennet_info;
} wdf_device_info;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(wdf_device_info, GetWdfDeviceInfo)

/* This function copied from linux's lib/vsprintf.c, see it for attribution */
static unsigned long
simple_strtoul(const char *cp,char **endp,unsigned int base)
{
  unsigned long result = 0,value;

  if (!base) {
    base = 10;
    if (*cp == '0') {
      base = 8;
      cp++;
      if ((toupper(*cp) == 'X') && isxdigit(cp[1])) {
        cp++;
        base = 16;
      }
    }
  } else if (base == 16) {
    if (cp[0] == '0' && toupper(cp[1]) == 'X')
    cp += 2;
  }
  while (isxdigit(*cp) &&
  (value = isdigit(*cp) ? *cp-'0' : toupper(*cp)-'A'+10) < base) {
    result = result*base + value;
    cp++;
  }
  if (endp)
  *endp = (char *)cp;
  return result;
 }

static PMDL
AllocatePages(int Pages)
{
  PHYSICAL_ADDRESS Min;
  PHYSICAL_ADDRESS Max;
  PHYSICAL_ADDRESS Align;
  PMDL Mdl;

  KdPrint((__DRIVER_NAME " --> Allocate Pages\n"));

  Min.QuadPart = 0;
  Max.QuadPart = 0xFFFFFFFF;
  Align.QuadPart = PAGE_SIZE;

  Mdl = MmAllocatePagesForMdl(Min, Max, Align, Pages * PAGE_SIZE);

  KdPrint((__DRIVER_NAME " <-- Allocate Pages (mdl = %08x)\n", Mdl));

  return Mdl;
}
  
static PMDL
AllocatePage()
{
  return AllocatePages(1);
}

static BOOLEAN
XenNet_Interrupt(
  PKINTERRUPT Interrupt,
  PVOID ServiceContext
  )
{
  // struct xennet_info *xennet_info = ServiceContext;
  // KIRQL KIrql;

  UNREFERENCED_PARAMETER(Interrupt);
  UNREFERENCED_PARAMETER(ServiceContext);

  // KeAcquireSpinLock(&ChildDeviceData->Lock, &KIrql);
  // KdPrint((__DRIVER_NAME " --> Setting Dpc Event\n"));
  // KeSetEvent(&ChildDeviceData->DpcThreadEvent, 1, FALSE);
  // KeReleaseSpinLock(&ChildDeviceData->Lock, KIrql);
  // KdPrint((__DRIVER_NAME " --> Dpc Event Set\n"));

  /* do something */

  return TRUE;
}

static VOID
XenNet_BackEndStateHandler(char *Path, PVOID Data)
{
  struct xennet_info *xi = Data;
  char *Value;
  int be_state;
  char TmpPath[128];
  xenbus_transaction_t xbt = 0;
  int retry = 0;
  char *err;

  xi->XenBusInterface.Read(xi->XenBusInterface.InterfaceHeader.Context,
    XBT_NIL, Path, &Value);
  be_state = atoi(Value);
  ExFreePool(Value);

  switch (be_state)
  {
  case XenbusStateUnknown:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Unknown\n"));  
    break;

  case XenbusStateInitialising:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialising\n"));  
    break;

  case XenbusStateInitWait:
    KdPrint((__DRIVER_NAME "     Backend State Changed to InitWait\n"));  

    xi->event_channel = xi->EvtChnInterface.AllocUnbound(
      xi->EvtChnInterface.InterfaceHeader.Context, 0);  
    xi->EvtChnInterface.Bind(xi->EvtChnInterface.InterfaceHeader.Context,
      xi->event_channel, XenNet_Interrupt, xi);

    /* TODO: must free pages in MDL as well as MDL using MmFreePagesFromMdl and ExFreePool */
    // or, allocate mem and then get mdl, then free mdl
    xi->tx_mdl = AllocatePage();
    xi->tx_pgs = MmMapLockedPagesSpecifyCache(xi->tx_mdl, KernelMode, MmNonCached,
      NULL, FALSE, NormalPagePriority);
    SHARED_RING_INIT(xi->tx_pgs);
    FRONT_RING_INIT(&xi->tx, xi->tx_pgs, PAGE_SIZE);
    xi->tx_ring_ref = xi->GntTblInterface.GrantAccess(
      xi->GntTblInterface.InterfaceHeader.Context, 0,
      *MmGetMdlPfnArray(xi->tx_mdl), FALSE);

    xi->rx_mdl = AllocatePage();
    xi->rx_pgs = MmMapLockedPagesSpecifyCache(xi->rx_mdl, KernelMode, MmNonCached,
      NULL, FALSE, NormalPagePriority);
    SHARED_RING_INIT(xi->rx_pgs);
    FRONT_RING_INIT(&xi->rx, xi->rx_pgs, PAGE_SIZE);
    xi->rx_ring_ref = xi->GntTblInterface.GrantAccess(
      xi->GntTblInterface.InterfaceHeader.Context, 0,
      *MmGetMdlPfnArray(xi->rx_mdl), FALSE);

    xi->XenBusInterface.StartTransaction(xi->XenBusInterface.InterfaceHeader.Context,
      &xbt);

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/tx-ring-ref", xi->Path);
    err = xi->XenBusInterface.Printf(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", xi->tx_ring_ref);
    if (err)
      goto trouble;

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/rx-ring-ref", xi->Path);
    err = xi->XenBusInterface.Printf(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", xi->rx_ring_ref);
    if (err)
      goto trouble;

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/event-channel", xi->Path);
    err = xi->XenBusInterface.Printf(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", xi->event_channel);
    if (err)
      goto trouble;

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/request-rx-copy", xi->Path);
    err = xi->XenBusInterface.Printf(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", 1);
    if (err)
      goto trouble;

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/feature-rx-notify",
      xi->Path);
    err = xi->XenBusInterface.Printf(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", 1);
    if (err)
      goto trouble;

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath),
      "%s/feature-no-csum-offload", xi->Path);
    err = xi->XenBusInterface.Printf(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", 1);
    if (err)
      goto trouble;

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath),
      "%s/feature-sg", xi->Path);
    err = xi->XenBusInterface.Printf(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", 0);
    if (err)
      goto trouble;

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath),
      "%s/feature-gso-tcpv4", xi->Path);
    err = xi->XenBusInterface.Printf(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", 0);
    if (err)
      goto trouble;

    /* commit transaction */
    xi->XenBusInterface.EndTransaction(xi->XenBusInterface.InterfaceHeader.Context,
      xbt, 0, &retry);

    /* TODO: prepare tx and rx rings */

    KdPrint((__DRIVER_NAME "     Set Frontend state to Initialised\n"));
    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->Path);
    xi->XenBusInterface.Printf(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", XenbusStateInitialised);

    /* send fake arp? */

    xi->connected = TRUE;

    break;

  case XenbusStateInitialised:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialised\n"));
    // create the device
    break;

  case XenbusStateConnected:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Connected\n"));  

    /* do more stuff here */

    KdPrint((__DRIVER_NAME "     Set Frontend state to Connected\n"));
    break;

  case XenbusStateClosing:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closing\n"));  
    break;

  case XenbusStateClosed:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closed\n"));  
    break;

  default:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Undefined = %d\n", be_state));
    break;
  }

trouble:
  KdPrint((__DRIVER_NAME __FUNCTION__ ": Should never happen!\n"));
  xi->XenBusInterface.EndTransaction(xi->XenBusInterface.InterfaceHeader.Context,
    xbt, 1, &retry);

}


VOID
XenNet_Halt(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  UNREFERENCED_PARAMETER(MiniportAdapterContext);
}

static NDIS_STATUS
XenNet_Init(
  OUT PNDIS_STATUS OpenErrorStatus,
  OUT PUINT SelectedMediumIndex,
  IN PNDIS_MEDIUM MediumArray,
  IN UINT MediumArraySize,
  IN NDIS_HANDLE MiniportAdapterHandle,
  IN NDIS_HANDLE WrapperConfigurationContext
  )
{
  NDIS_STATUS status;
  UINT i;
  BOOLEAN medium_found = FALSE;
  struct xennet_info *xi = NULL;
  ULONG length;
  WDF_OBJECT_ATTRIBUTES wdf_attrs;
  char *msg;
  char *Value;
  char **vif_devs;
  char TmpPath[128];

  UNREFERENCED_PARAMETER(OpenErrorStatus);
  UNREFERENCED_PARAMETER(WrapperConfigurationContext);

  /* deal with medium stuff */
  for (i = 0; i < MediumArraySize; i++)
  {
    if (MediumArray[i] == NdisMedium802_3)
    {
      medium_found = TRUE;
      break;
    }
  }
  if (!medium_found)
  {
    KdPrint(("NIC_MEDIA_TYPE not in MediumArray\n"));
    return NDIS_STATUS_UNSUPPORTED_MEDIA;
  }
  *SelectedMediumIndex = i;

  /* Alloc memory for adapter private info */
  status = NdisAllocateMemoryWithTag(&xi, sizeof(*xi), XENNET_POOL_TAG);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("NdisAllocateMemoryWithTag failed with 0x%x\n", status));
    status = NDIS_STATUS_RESOURCES;
    goto err;
  }
  RtlZeroMemory(xi, sizeof(*xi));

  /* init xennet_info */
  xi->adapter_handle = MiniportAdapterHandle;
  NdisMGetDeviceProperty(MiniportAdapterHandle, &xi->pdo, &xi->fdo,
    &xi->lower_do, NULL, NULL);

  status = IoGetDeviceProperty(xi->pdo, DevicePropertyDeviceDescription,
    NAME_SIZE, xi->name, &length);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("IoGetDeviceProperty failed with 0x%x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  NdisMSetAttributesEx(xi->adapter_handle, (NDIS_HANDLE) xi,
      0, NDIS_ATTRIBUTE_DESERIALIZE, NdisInterfaceInternal);

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&wdf_attrs, wdf_device_info);

  status = WdfDeviceMiniportCreate(WdfGetDriver(), &wdf_attrs, xi->fdo,
    xi->lower_do, xi->pdo, &xi->wdf_device);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("WdfDeviceMiniportCreate failed with 0x%x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }
  
  GetWdfDeviceInfo(xi->wdf_device)->xennet_info = xi;

  /* get lower (Xen) interfaces */

  status = WdfFdoQueryForInterface(xi->wdf_device, &GUID_XEN_IFACE_EVTCHN,
    (PINTERFACE) &xi->EvtChnInterface, sizeof(XEN_IFACE_EVTCHN), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint(("WdfFdoQueryForInterface (EvtChn) failed with status 0x%08x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  status = WdfFdoQueryForInterface(xi->wdf_device, &GUID_XEN_IFACE_XENBUS,
    (PINTERFACE) &xi->XenBusInterface, sizeof(XEN_IFACE_XENBUS), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint(("WdfFdoQueryForInterface (XenBus) failed with status 0x%08x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

#if 0
  status = WdfFdoQueryForInterface(xi->wdf_device, &GUID_XEN_IFACE_XEN,
    (PINTERFACE) &xi->XenInterface, sizeof(XEN_IFACE_XEN), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint(("WdfFdoQueryForInterface (Xen) failed with status 0x%08x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }
#endif

  status = WdfFdoQueryForInterface(xi->wdf_device, &GUID_XEN_IFACE_GNTTBL,
    (PINTERFACE) &xi->GntTblInterface, sizeof(XEN_IFACE_GNTTBL), 1, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint(("WdfFdoQueryForInterface (GntTbl) failed with status 0x%08x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  msg = xi->XenBusInterface.List(xi->EvtChnInterface.InterfaceHeader.Context,
    XBT_NIL, "device/vif", &vif_devs);
  if (msg)
  {
    KdPrint((__DRIVER_NAME ": " __FUNCTION__ ": List retval is nonzero!\n"));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  for (i = 0; vif_devs[i]; i++)
  {
    if (i > 0)
    {
      KdPrint((__DRIVER_NAME "Can only handle 1 vif so far, ignoring vif %s\n", vif_devs[i]));
      continue;
    }
    RtlStringCbPrintfA(xi->Path, ARRAY_SIZE(xi->Path), "device/vif/%s", vif_devs[i]);

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath),
      "device/vif/%s/state", vif_devs[i]);
    KdPrint(("%s\n", TmpPath));

    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/backend", xi->Path);
    xi->XenBusInterface.Read(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    if (!Value)
    {
      KdPrint((__DRIVER_NAME "    backend Read Failed\n"));
    }
    else
    {
      RtlStringCbCopyA(xi->BackendPath, ARRAY_SIZE(xi->BackendPath), Value);
      KdPrint((__DRIVER_NAME "backend path = %s\n", xi->BackendPath));
    }
    ExFreePool(Value);

    /* Add watch on backend state */
    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->BackendPath);
    xi->XenBusInterface.AddWatch(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, XenNet_BackEndStateHandler, xi);

    /* get mac address */
    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/mac", xi->Path);
    xi->XenBusInterface.Read(xi->XenBusInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    if (!Value)
    {
      KdPrint((__DRIVER_NAME "    mac Read Failed\n"));
    }
    else
    {
      char *s, *e;
      int i;

      s = Value;

      for (i = 0; i < ETH_ALEN; i++) {
        xi->perm_mac_addr[i] = (UINT8)simple_strtoul(s, &e, 16);
        if ((s == e) || (*e != ((i == ETH_ALEN-1) ? '\0' : ':'))) {
          KdPrint((__DRIVER_NAME "Error parsing MAC address\n"));
          ExFreePool(Value);
          ExFreePool(vif_devs);
          status = NDIS_STATUS_FAILURE;
          goto err;
        }
        s = e + 1;
      }
      memcpy(xi->curr_mac_addr, xi->perm_mac_addr, ETH_ALEN);
    }
    ExFreePool(Value);

    //XenVbd_HotPlugHandler(buffer, NULL);
    //ExFreePoolWithTag(bdDevices[i], XENPCI_POOL_TAG);
  }
  ExFreePool(vif_devs);

  return NDIS_STATUS_SUCCESS;

err:
  NdisFreeMemory(xi, 0, 0);
  return status;
}

NDIS_OID supported_oids[] =
{
  OID_GEN_SUPPORTED_LIST,
  OID_GEN_HARDWARE_STATUS,
  OID_GEN_MEDIA_SUPPORTED,
  OID_GEN_MEDIA_IN_USE,
  OID_GEN_MAXIMUM_LOOKAHEAD,
  OID_GEN_MAXIMUM_FRAME_SIZE,
  OID_GEN_LINK_SPEED,
  OID_GEN_TRANSMIT_BUFFER_SPACE,
  OID_GEN_RECEIVE_BUFFER_SPACE,
  OID_GEN_TRANSMIT_BLOCK_SIZE,
  OID_GEN_RECEIVE_BLOCK_SIZE,
  OID_GEN_VENDOR_ID,
  OID_GEN_VENDOR_DESCRIPTION,
  OID_GEN_CURRENT_PACKET_FILTER,
  OID_GEN_CURRENT_LOOKAHEAD,
  OID_GEN_DRIVER_VERSION,
  OID_GEN_MAXIMUM_TOTAL_SIZE,
  OID_GEN_MAC_OPTIONS,
  OID_GEN_MEDIA_CONNECT_STATUS,
  OID_GEN_MAXIMUM_SEND_PACKETS,
  OID_802_3_PERMANENT_ADDRESS,
  OID_802_3_CURRENT_ADDRESS,
  OID_802_3_MULTICAST_LIST,
  OID_802_3_MAXIMUM_LIST_SIZE,
};

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
  ULONG temp_data;
  PVOID data = &temp_data;
  UINT len = sizeof(temp_data);
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;

  switch(Oid)
  {
    case OID_GEN_SUPPORTED_LIST:
      data = supported_oids;
      len = sizeof(supported_oids);
      break;
    case OID_GEN_HARDWARE_STATUS:
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
      temp_data = XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_LINK_SPEED:
      temp_data = 10000000; /* 1Gb */
      break;
    case OID_GEN_TRANSMIT_BUFFER_SPACE:
      /* pkts times sizeof ring, maybe? */
      temp_data = XN_MAX_PKT_SIZE * NET_TX_RING_SIZE;
      break;
    case OID_GEN_RECEIVE_BUFFER_SPACE:
      /* pkts times sizeof ring, maybe? */
      temp_data = XN_MAX_PKT_SIZE * NET_TX_RING_SIZE;
      break;
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
      temp_data = XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_RECEIVE_BLOCK_SIZE:
      temp_data = XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_VENDOR_ID:
      temp_data = XENSOURCE_MAC_HDR;
      break;
    case OID_GEN_VENDOR_DESCRIPTION:
      data = vendor_desc;
      len = sizeof(vendor_desc);
      break;
    case OID_GEN_CURRENT_PACKET_FILTER:
      temp_data = xi->packet_filter;
      break;
    case OID_GEN_CURRENT_LOOKAHEAD:
      temp_data = XN_MAX_PKT_SIZE;
      break;
    case OID_GEN_DRIVER_VERSION:
      temp_data = (NDIS_MAJOR_VER << 8) | NDIS_MINOR_VER;
      len = 2;
      break;
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
      temp_data = XN_MAX_PKT_SIZE;
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
    default:
      KdPrint(("Unknown OID 0x%x\n", Oid));
      status = NDIS_STATUS_NOT_SUPPORTED;
  }

  if (!NT_SUCCESS(status))
  {
    return status;
  }

  if (len > InformationBufferLength)
  {
    *BytesNeeded = len;
    return NDIS_STATUS_BUFFER_TOO_SHORT;
  }

  *BytesWritten = len;
  if (len)
  {
    NdisMoveMemory(InformationBuffer, data, len);
  }

  KdPrint(("Got OID 0x%x\n", Oid));

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
  UNREFERENCED_PARAMETER(MiniportAdapterContext);
  UNREFERENCED_PARAMETER(Oid);
  UNREFERENCED_PARAMETER(InformationBuffer);
  UNREFERENCED_PARAMETER(InformationBufferLength);
  UNREFERENCED_PARAMETER(BytesRead);
  UNREFERENCED_PARAMETER(BytesNeeded);

  KdPrint((__FUNCTION__ " called with OID=0x%x\n", Oid));
  return NDIS_STATUS_SUCCESS;
}

VOID
XenNet_ReturnPacket(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PNDIS_PACKET Packet
  )
{
  UNREFERENCED_PARAMETER(MiniportAdapterContext);
  UNREFERENCED_PARAMETER(Packet);

  KdPrint((__FUNCTION__ " called\n"));
}

VOID
XenNet_SendPackets(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN PPNDIS_PACKET PacketArray,
  IN UINT NumberOfPackets
  )
{
  /* for each packet:
    req_prod_pvt is the next entry in the cmd ring to use
    add pkt to array of saved packets
    fill out tx request for the first part of skb
    add to grant table
    do flags for csum etc
    gso (later)
    inc req_prod_pvt
    frags
    possibly notify
    network_tx)buf_gc
    stop netif if no more room
    */
  struct xennet_info *xi = MiniportAdapterContext;
  PNDIS_PACKET curr_packet;
  UINT i;
  UINT table_entry;

  KdPrint((__FUNCTION__ " called\n"));

  for (i = 0; i < NumberOfPackets; i++)
  {
    curr_packet = PacketArray[i];
    ASSERT(curr_packet);

    table_entry = xi->tx.req_prod_pvt;
  }

}

VOID
XenNet_PnPEventNotify(
  IN NDIS_HANDLE MiniportAdapterContext,
  IN NDIS_DEVICE_PNP_EVENT PnPEvent,
  IN PVOID InformationBuffer,
  IN ULONG InformationBufferLength
  )
{
  UNREFERENCED_PARAMETER(MiniportAdapterContext);
  UNREFERENCED_PARAMETER(PnPEvent);
  UNREFERENCED_PARAMETER(InformationBuffer);
  UNREFERENCED_PARAMETER(InformationBufferLength);

  KdPrint((__FUNCTION__ " called\n"));
}

VOID
XenNet_Shutdown(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  UNREFERENCED_PARAMETER(MiniportAdapterContext);

  KdPrint((__FUNCTION__ " called\n"));
}

NTSTATUS
DriverEntry(
  PDRIVER_OBJECT DriverObject,
  PUNICODE_STRING RegistryPath
  )
{
  NTSTATUS status;
  WDF_DRIVER_CONFIG config;
  NDIS_HANDLE ndis_wrapper_handle;
  NDIS_MINIPORT_CHARACTERISTICS mini_chars;

  RtlZeroMemory(&mini_chars, sizeof(mini_chars));

  WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
  config.DriverInitFlags |= WdfDriverInitNoDispatchOverride;

  status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES,
    &config, WDF_NO_HANDLE);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("WdfDriverCreate failed err = 0x%x\n", status));
    return status;
  }

  NdisMInitializeWrapper(&ndis_wrapper_handle, DriverObject, RegistryPath, NULL);
  if (!ndis_wrapper_handle)
  {
    KdPrint(("NdisMInitializeWrapper failed\n"));
    return NDIS_STATUS_FAILURE;
  }

  /* NDIS 5.1 driver */
  mini_chars.MajorNdisVersion = 5;
  mini_chars.MinorNdisVersion = 1;

  mini_chars.HaltHandler = XenNet_Halt;
  mini_chars.InitializeHandler = XenNet_Init;
  mini_chars.ISRHandler = NULL; // needed if we register interrupt?
  mini_chars.QueryInformationHandler = XenNet_QueryInformation;
  mini_chars.ResetHandler = NULL; //TODO: fill in
  mini_chars.SetInformationHandler = XenNet_SetInformation;
  /* added in v.4 -- use multiple pkts interface */
  mini_chars.ReturnPacketHandler = XenNet_ReturnPacket;
  mini_chars.SendPacketsHandler = XenNet_SendPackets;
  /* added in v.5.1 */
  mini_chars.PnPEventNotifyHandler = XenNet_PnPEventNotify;
  mini_chars.AdapterShutdownHandler = XenNet_Shutdown;

  /* TODO: we don't have hardware, but we have "resources", so do we need to implement fns to handle this? */

  /* set up upper-edge interface */
  status = NdisMRegisterMiniport(ndis_wrapper_handle, &mini_chars, sizeof(mini_chars));
  if (!NT_SUCCESS(status))
  {
    KdPrint(("NdisMRegisterMiniport failed, status = 0x%x\n", status));
    NdisTerminateWrapper(ndis_wrapper_handle, NULL);
    return status;
  }

  return status;
}
