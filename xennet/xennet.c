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

#include <stdlib.h>
#include <io/xenbus.h>
#include "xennet.h"

LARGE_INTEGER ProfTime_TxBufferGC;
LARGE_INTEGER ProfTime_RxBufferAlloc;
LARGE_INTEGER ProfTime_ReturnPacket;
LARGE_INTEGER ProfTime_RxBufferCheck;
LARGE_INTEGER ProfTime_Linearize;
LARGE_INTEGER ProfTime_SendPackets;
LARGE_INTEGER ProfTime_SendQueuedPackets;

int ProfCount_TxBufferGC;
int ProfCount_RxBufferAlloc;
int ProfCount_ReturnPacket;
int ProfCount_RxBufferCheck;
int ProfCount_Linearize;
int ProfCount_SendPackets;
int ProfCount_PacketsPerSendPackets;
int ProfCount_SendQueuedPackets;

int ProfCount_TxPacketsTotal;
int ProfCount_TxPacketsOffload;
int ProfCount_RxPacketsTotal;
int ProfCount_RxPacketsOffload;
int ProfCount_CallsToIndicateReceive;

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

// Called at DISPATCH_LEVEL

static BOOLEAN
XenNet_Interrupt(
  PKINTERRUPT Interrupt,
  PVOID ServiceContext
  )
{
  struct xennet_info *xi = ServiceContext;

  UNREFERENCED_PARAMETER(Interrupt);

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  if (xi->connected)
  {
    XenNet_TxBufferGC(xi);
    XenNet_RxBufferCheck(xi);
  }
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

// Called at <= DISPATCH_LEVEL

static VOID
XenNet_BackEndStateHandler(char *Path, PVOID Data)
{
  struct xennet_info *xi = Data;
  char *Value;
  char *err;
  ULONG new_backend_state;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
//  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  err = xi->XenInterface.XenBus_Read(xi->XenInterface.InterfaceHeader.Context,
    XBT_NIL, Path, &Value);
  if (err)
  {
    KdPrint(("Failed to read %s\n", Path, err));
    return;
  }
  new_backend_state = atoi(Value);
  xi->XenInterface.FreeMem(Value);

  if (xi->backend_state == new_backend_state)
  {
    KdPrint((__DRIVER_NAME "     state unchanged\n"));
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
    return;
  }    

  xi->backend_state = new_backend_state;

  switch (xi->backend_state)
  {
  case XenbusStateUnknown:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Unknown\n"));  
    break;

  case XenbusStateInitialising:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialising\n"));  
    break;

  case XenbusStateInitWait:
    KdPrint((__DRIVER_NAME "     Backend State Changed to InitWait\n"));  
    break;

  case XenbusStateInitialised:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialised\n"));
    break;

  case XenbusStateConnected:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Connected\n"));  
    break;

  case XenbusStateClosing:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closing\n"));  
    break;

  case XenbusStateClosed:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closed\n"));  
    break;

  default:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Undefined = %d\n", xi->backend_state));
    break;
  }

  KeSetEvent(&xi->backend_state_change_event, 1, FALSE);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return;
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
  char *res;
  char *Value;
  char TmpPath[MAX_XENBUS_STR_LEN];
  struct set_params {
    char *name;
    int value;
  } params[] = {
    {"tx-ring-ref", 0},
    {"rx-ring-ref", 0},
    {"event-channel", 0},
    {"request-rx-copy", 1},
    {"feature-rx-notify", 1},
//    {"feature-no-csum-offload", 1},
    {"feature-sg", 1},
    {"feature-gso-tcpv4", 0},
    {NULL, 0},
  };
  int retry = 0;
  char *err;
  xenbus_transaction_t xbt = 0;

  UNREFERENCED_PARAMETER(OpenErrorStatus);
  UNREFERENCED_PARAMETER(WrapperConfigurationContext);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

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
  xi->rx_target     = RX_DFL_MIN_TARGET;
  xi->rx_min_target = RX_DFL_MIN_TARGET;
  xi->rx_max_target = RX_MAX_TARGET;

  xi->state = XenbusStateUnknown;
  xi->backend_state = XenbusStateUnknown;

  KeInitializeSpinLock(&xi->tx_lock);
  KeInitializeSpinLock(&xi->rx_lock);

  InitializeListHead(&xi->tx_waiting_pkt_list);

  NdisAllocatePacketPool(&status, &xi->packet_pool, XN_RX_QUEUE_LEN,
    PROTOCOL_RESERVED_SIZE_IN_PACKET);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint(("NdisAllocatePacketPool failed with 0x%x\n", status));
    status = NDIS_STATUS_RESOURCES;
    goto err;
  }
  NdisSetPacketPoolProtocolId(xi->packet_pool, NDIS_PROTOCOL_ID_TCP_IP);

  NdisAllocateBufferPool(&status, &xi->buffer_pool, XN_RX_QUEUE_LEN);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint(("NdisAllocateBufferPool failed with 0x%x\n", status));
    status = NDIS_STATUS_RESOURCES;
    goto err;
  }

  NdisMGetDeviceProperty(MiniportAdapterHandle, &xi->pdo, &xi->fdo,
    &xi->lower_do, NULL, NULL);
  xi->pdo_data = (PXENPCI_XEN_DEVICE_DATA)xi->pdo->DeviceExtension;

  xi->packet_filter = NDIS_PACKET_TYPE_PROMISCUOUS;

  status = IoGetDeviceProperty(xi->pdo, DevicePropertyDeviceDescription,
    NAME_SIZE, xi->dev_desc, &length);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("IoGetDeviceProperty failed with 0x%x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  NdisMSetAttributesEx(xi->adapter_handle, (NDIS_HANDLE) xi,
    0, (NDIS_ATTRIBUTE_DESERIALIZE | NDIS_ATTRIBUTE_BUS_MASTER),
    NdisInterfaceInternal);

  status = NdisMInitializeScatterGatherDma(xi->adapter_handle, TRUE, XN_MAX_PKT_SIZE);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("NdisMInitializeScatterGatherDma failed with 0x%x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  WDF_OBJECT_ATTRIBUTES_INIT(&wdf_attrs);

  status = WdfDeviceMiniportCreate(WdfGetDriver(), &wdf_attrs, xi->fdo,
    xi->lower_do, xi->pdo, &xi->wdf_device);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("WdfDeviceMiniportCreate failed with 0x%x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  /* get lower (Xen) interfaces */

  status = WdfFdoQueryForInterface(xi->wdf_device, &GUID_XEN_IFACE,
    (PINTERFACE) &xi->XenInterface, sizeof(XEN_IFACE), 2, NULL);
  if(!NT_SUCCESS(status))
  {
    KdPrint(("WdfFdoQueryForInterface failed with status 0x%08x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath),
      "%s/backend", xi->pdo_data->Path);
  res = xi->XenInterface.XenBus_Read(xi->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
  if (res)
  {
    KdPrint((__DRIVER_NAME "    Failed to read backend path\n"));
    xi->XenInterface.FreeMem(res);
    status = NDIS_STATUS_FAILURE;
    goto err;
  }
  RtlStringCbCopyA(xi->backend_path, ARRAY_SIZE(xi->backend_path), Value);
  xi->XenInterface.FreeMem(Value);
  KdPrint((__DRIVER_NAME "backend path = %s\n", xi->backend_path));

  KeInitializeEvent(&xi->backend_state_change_event, SynchronizationEvent, FALSE);  
  KeInitializeEvent(&xi->shutdown_event, SynchronizationEvent, FALSE);  

  /* Add watch on backend state */
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->backend_path);
  xi->XenInterface.XenBus_AddWatch(xi->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, XenNet_BackEndStateHandler, xi);

  /* Tell backend we're coming up */
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(xi->XenInterface.InterfaceHeader.Context,
    XBT_NIL, TmpPath, "%d", XenbusStateInitialising);

  // wait here for signal that we are all set up
  while (xi->backend_state != XenbusStateInitWait)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive, KernelMode, FALSE, NULL);

  xi->event_channel = xi->XenInterface.EvtChn_AllocUnbound(
    xi->XenInterface.InterfaceHeader.Context, 0);
  xi->XenInterface.EvtChn_BindDpc(xi->XenInterface.InterfaceHeader.Context,
    xi->event_channel, XenNet_Interrupt, xi);

  XenNet_TxInit(xi);
  XenNet_RxInit(xi);

  /* fixup array for dynamic values */
  params[0].value = xi->tx_ring_ref;
  params[1].value = xi->rx_ring_ref;
  params[2].value = xi->event_channel;
  xi->XenInterface.XenBus_StartTransaction(
    xi->XenInterface.InterfaceHeader.Context, &xbt);

  for (err = NULL, i = 0; params[i].name; i++)
  {
    RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/%s",
      xi->pdo_data->Path, params[i].name);
    err = xi->XenInterface.XenBus_Printf(xi->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", params[i].value);
    if (err)
    {
      KdPrint(("setting %s failed, err = %s\n", params[i].name, err));
      break;
    }
  }

  xi->XenInterface.XenBus_EndTransaction(xi->XenInterface.InterfaceHeader.Context,
    xbt, 1, &retry);
  if (err)
  {
    status = NDIS_STATUS_FAILURE;
    goto err;
  } 

  xi->connected = TRUE;

  KeMemoryBarrier(); // packets could be received anytime after we set Frontent to Connected

  xi->state = XenbusStateConnected;
  KdPrint((__DRIVER_NAME "     Set Frontend state to Connected\n"));
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(xi->XenInterface.InterfaceHeader.Context,
    XBT_NIL, TmpPath, "%d", xi->state);

  KdPrint((__DRIVER_NAME "     Waiting for backend to connect\n"));

  // wait here for signal that we are all set up
  while (xi->backend_state != XenbusStateConnected)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive, KernelMode, FALSE, NULL);

  KdPrint((__DRIVER_NAME "     Connected\n"));

  /* get mac address */
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/mac", xi->backend_path);
  xi->XenInterface.XenBus_Read(xi->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
  if (!Value)
  {
    KdPrint((__DRIVER_NAME "    mac Read Failed\n"));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }
  else
  {
    char *s, *e;
    s = Value;
    for (i = 0; i < ETH_ALEN; i++) {
      xi->perm_mac_addr[i] = (UINT8)simple_strtoul(s, &e, 16);
      if ((s == e) || (*e != ((i == ETH_ALEN-1) ? '\0' : ':'))) {
        KdPrint((__DRIVER_NAME "Error parsing MAC address\n"));
        xi->XenInterface.FreeMem(Value);
        status = NDIS_STATUS_FAILURE;
        goto err;
      }
      s = e + 1;
    }
    memcpy(xi->curr_mac_addr, xi->perm_mac_addr, ETH_ALEN);
    xi->XenInterface.FreeMem(Value);
  }

  /* send fake arp? */

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NDIS_STATUS_SUCCESS;

err:
  NdisFreeMemory(xi, 0, 0);
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return status;
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

/* Called when machine is shutting down, so just quiesce the HW and be done fast. */
VOID
XenNet_Shutdown(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  struct xennet_info *xi = MiniportAdapterContext;

  /* turn off interrupt */
  xi->XenInterface.EvtChn_Unbind(xi->XenInterface.InterfaceHeader.Context,
    xi->event_channel);

  KdPrint((__FUNCTION__ " called\n"));
}

/* Opposite of XenNet_Init */
VOID
XenNet_Halt(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
  CHAR TmpPath[MAX_XENBUS_STR_LEN];
  PVOID if_cxt = xi->XenInterface.InterfaceHeader.Context;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  // set frontend state to 'closing'
  xi->state = XenbusStateClosing;
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(if_cxt, XBT_NIL, TmpPath, "%d", xi->state);

  // wait for backend to set 'Closing' state

  while (xi->backend_state != XenbusStateClosing)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive,
      KernelMode, FALSE, NULL);

  // set frontend state to 'closed'
  xi->state = XenbusStateClosed;
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(if_cxt, XBT_NIL, TmpPath, "%d", xi->state);

  // wait for backend to set 'Closed' state
  while (xi->backend_state != XenbusStateClosed)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive,
      KernelMode, FALSE, NULL);

  // set frontend state to 'Initialising'
  xi->state = XenbusStateInitialising;
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(if_cxt, XBT_NIL, TmpPath, "%d", xi->state);

  // wait for backend to set 'InitWait' state
  while (xi->backend_state != XenbusStateInitWait)
    KeWaitForSingleObject(&xi->backend_state_change_event, Executive,
      KernelMode, FALSE, NULL);

  // Disables the interrupt
  XenNet_Shutdown(xi);

  xi->connected = FALSE;
  KeMemoryBarrier(); /* make sure everyone sees that we are now shut down */

  // TODO: remove event channel xenbus entry (how?)

  XenNet_TxShutdown(xi);
  XenNet_RxShutdown(xi);

  /* Remove watch on backend state */
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->backend_path);
  xi->XenInterface.XenBus_RemWatch(if_cxt, XBT_NIL, TmpPath,
    XenNet_BackEndStateHandler, xi);

  xi->XenInterface.InterfaceHeader.InterfaceDereference(NULL);

  NdisFreeBufferPool(xi->buffer_pool);
  NdisFreePacketPool(xi->packet_pool);

  NdisFreeMemory(xi, 0, 0); // <= DISPATCH_LEVEL

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

VOID
XenNet_Unload(
  PDRIVER_OBJECT  DriverObject
  )
{
  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  UNREFERENCED_PARAMETER(DriverObject);

  WdfDriverMiniportUnload(WdfGetDriver());
  
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
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


  ProfTime_TxBufferGC.QuadPart = 0;
  ProfTime_RxBufferAlloc.QuadPart = 0;
  ProfTime_ReturnPacket.QuadPart = 0;
  ProfTime_RxBufferCheck.QuadPart = 0;
  ProfTime_Linearize.QuadPart = 0;
  ProfTime_SendPackets.QuadPart = 0;
  ProfTime_SendQueuedPackets.QuadPart = 0;

  ProfCount_TxBufferGC = 0;
  ProfCount_RxBufferAlloc = 0;
  ProfCount_ReturnPacket = 0;
  ProfCount_RxBufferCheck = 0;
  ProfCount_Linearize = 0;
  ProfCount_SendPackets = 0;
  ProfCount_PacketsPerSendPackets = 0;
  ProfCount_SendQueuedPackets = 0;

  ProfCount_TxPacketsTotal = 0;
  ProfCount_TxPacketsOffload = 0;
  ProfCount_RxPacketsTotal = 0;
  ProfCount_RxPacketsOffload = 0;
  ProfCount_CallsToIndicateReceive = 0;

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
  mini_chars.MajorNdisVersion = NDIS_MINIPORT_MAJOR_VERSION;
  mini_chars.MinorNdisVersion = NDIS_MINIPORT_MINOR_VERSION;

  mini_chars.HaltHandler = XenNet_Halt;
  mini_chars.InitializeHandler = XenNet_Init;
  mini_chars.ISRHandler = NULL; // needed if we register interrupt?
  mini_chars.QueryInformationHandler = XenNet_QueryInformation;
  mini_chars.ResetHandler = NULL; //TODO: fill in
  mini_chars.SetInformationHandler = XenNet_SetInformation;
  /* added in v.4 -- use multiple pkts interface */
  mini_chars.ReturnPacketHandler = XenNet_ReturnPacket;
  mini_chars.SendPacketsHandler = XenNet_SendPackets;

#if defined (NDIS51_MINIPORT)
  /* added in v.5.1 */
  mini_chars.PnPEventNotifyHandler = XenNet_PnPEventNotify;
  mini_chars.AdapterShutdownHandler = XenNet_Shutdown;
#else
  // something else here
#endif

  /* set up upper-edge interface */
  status = NdisMRegisterMiniport(ndis_wrapper_handle, &mini_chars, sizeof(mini_chars));
  if (!NT_SUCCESS(status))
  {
    KdPrint(("NdisMRegisterMiniport failed, status = 0x%x\n", status));
    NdisTerminateWrapper(ndis_wrapper_handle, NULL);
    return status;
  }

  NdisMRegisterUnloadHandler(ndis_wrapper_handle, XenNet_Unload);

  return status;
}
