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
LARGE_INTEGER ProfTime_RxBufferCheckTopHalf;
LARGE_INTEGER ProfTime_RxBufferCheckBotHalf;

int ProfCount_TxBufferGC;
int ProfCount_RxBufferAlloc;
int ProfCount_ReturnPacket;
int ProfCount_RxBufferCheck;
int ProfCount_Linearize;
int ProfCount_SendPackets;
int ProfCount_PacketsPerSendPackets;
int ProfCount_SendQueuedPackets;

int ProfCount_TxPacketsTotal;
int ProfCount_TxPacketsCsumOffload;
int ProfCount_TxPacketsLargeOffload;
int ProfCount_RxPacketsTotal;
int ProfCount_RxPacketsCsumOffload;
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

static VOID
XenNet_InterruptIsr(
  PBOOLEAN InterruptRecognized,
  PBOOLEAN QueueMiniportHandleInterrupt,
  NDIS_HANDLE MiniportAdapterContext)
{
  struct xennet_info *xi = MiniportAdapterContext;
  
  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  *QueueMiniportHandleInterrupt = (BOOLEAN)!!xi->connected;
  *InterruptRecognized = FALSE; /* we can't be sure here... */

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static VOID
XenNet_InterruptDpc(NDIS_HANDLE  MiniportAdapterContext)
{
  struct xennet_info *xi = MiniportAdapterContext;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  if (xi->connected)
  {
    XenNet_TxBufferGC(xi);
    XenNet_RxBufferCheck(xi);
  }
  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

// Called at <= DISPATCH_LEVEL

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
  UINT i, j;
  BOOLEAN medium_found = FALSE;
  struct xennet_info *xi = NULL;
  ULONG length;
  PNDIS_RESOURCE_LIST nrl;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR prd;
  KIRQL irq_level;
  ULONG irq_vector;
  UCHAR type;
  PUCHAR ptr;
  PCHAR setting, value;
  
  UNREFERENCED_PARAMETER(OpenErrorStatus);

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
  xi->adapter_handle = MiniportAdapterHandle;
  xi->rx_target     = RX_DFL_MIN_TARGET;
  xi->rx_min_target = RX_DFL_MIN_TARGET;
  xi->rx_max_target = RX_MAX_TARGET;
  NdisMSetAttributesEx(xi->adapter_handle, (NDIS_HANDLE) xi,
    0, NDIS_ATTRIBUTE_DESERIALIZE, // | NDIS_ATTRIBUTE_BUS_MASTER),
    NdisInterfaceInternal);

  NdisMQueryAdapterResources(&status, WrapperConfigurationContext,
    NULL, (PUINT)&length);
  NdisAllocateMemoryWithTag(&nrl, length, XENNET_POOL_TAG);
  NdisMQueryAdapterResources(&status, WrapperConfigurationContext,
    nrl, (PUINT)&length);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint(("Could not get Adapter Resources 0x%x\n", status));
    return NDIS_ERROR_CODE_ADAPTER_NOT_FOUND;
  }
  xi->event_channel = 0;
  xi->config_csum = 1;
  xi->config_sg = 1;
  xi->config_gso = 1;

  for (i = 0; i < nrl->Count; i++)
  {
    prd = &nrl->PartialDescriptors[i];

    switch(prd->Type)
    {
    case CmResourceTypeInterrupt:
      irq_vector = prd->u.Interrupt.Vector;
      irq_level = (KIRQL)prd->u.Interrupt.Level;
      KdPrint((__DRIVER_NAME "     irq_vector = %03x, irq_level = %03x\n", irq_vector, irq_level));
      break;

    case CmResourceTypeMemory:
      NdisMMapIoSpace(&ptr, MiniportAdapterHandle, prd->u.Memory.Start, PAGE_SIZE);
      while((type = GET_XEN_INIT_RSP(&ptr, &setting, &value)) != XEN_INIT_TYPE_END)
      {
        switch(type)
        {
        case XEN_INIT_TYPE_RING: /* frontend ring */
          KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_RING - %s = %p\n", setting, value));
          if (strcmp(setting, "tx-ring-ref") == 0)
          {
            FRONT_RING_INIT(&xi->tx, (netif_tx_sring_t *)value, PAGE_SIZE);
          } else if (strcmp(setting, "rx-ring-ref") == 0)
          {
            FRONT_RING_INIT(&xi->rx, (netif_rx_sring_t *)value, PAGE_SIZE);
          }
          break;
        case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ: /* frontend event channel */
          KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_EVENT_CHANNEL - %s = %d\n", setting, PtrToUlong(value)));
          if (strcmp(setting, "event-channel") == 0)
          {
            xi->event_channel = PtrToUlong(value);
          }
          break;
        case XEN_INIT_TYPE_READ_STRING_BACK:
        case XEN_INIT_TYPE_READ_STRING_FRONT:
          KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = %s\n", setting, value));
          if (strcmp(setting, "mac") == 0)
          {
            char *s, *e;
            s = value;
            for (j = 0; j < ETH_ALEN; j++) {
              xi->perm_mac_addr[j] = (UINT8)simple_strtoul(s, &e, 16);
              if ((s == e) || (*e != ((j == ETH_ALEN-1) ? '\0' : ':'))) {
                KdPrint((__DRIVER_NAME "Error parsing MAC address\n"));
              }
              s = e + 1;
            }
            memcpy(xi->curr_mac_addr, xi->perm_mac_addr, ETH_ALEN);
          }
          break;
        case XEN_INIT_TYPE_VECTORS:
          KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_VECTORS\n"));
          if (((PXENPCI_VECTORS)value)->length != sizeof(XENPCI_VECTORS) ||
            ((PXENPCI_VECTORS)value)->magic != XEN_DATA_MAGIC)
          {
            KdPrint((__DRIVER_NAME "     vectors mismatch (magic = %08x, length = %d)\n",
              ((PXENPCI_VECTORS)value)->magic, ((PXENPCI_VECTORS)value)->length));
            KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
            return NDIS_ERROR_CODE_ADAPTER_NOT_FOUND;
          }
          else
            memcpy(&xi->vectors, value, sizeof(XENPCI_VECTORS));
          break;
        default:
          KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_%d\n", type));
          break;
        }
      }
      break;
    }
  } 

  KeInitializeSpinLock(&xi->rx_lock);

  InitializeListHead(&xi->tx_waiting_pkt_list);

  NdisAllocatePacketPool(&status, &xi->packet_pool, XN_RX_QUEUE_LEN * 8,
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
  xi->packet_filter = NDIS_PACKET_TYPE_PROMISCUOUS;

  status = IoGetDeviceProperty(xi->pdo, DevicePropertyDeviceDescription,
    NAME_SIZE, xi->dev_desc, &length);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("IoGetDeviceProperty failed with 0x%x\n", status));
    status = NDIS_STATUS_FAILURE;
    goto err;
  }

  KeInitializeEvent(&xi->shutdown_event, SynchronizationEvent, FALSE);  

  XenNet_TxInit(xi);
  XenNet_RxInit(xi);

  xi->connected = TRUE;

  KeMemoryBarrier(); // packets could be received anytime after we set Frontent to Connected

  status = NdisMRegisterInterrupt(&xi->interrupt, MiniportAdapterHandle, irq_vector, irq_level,
    TRUE, TRUE, NdisInterruptLatched);
  /* send fake arp? */
  if (!NT_SUCCESS(status))
  {
    KdPrint(("NdisMRegisterInterrupt failed with 0x%x\n", status));
    //status = NDIS_STATUS_FAILURE;
    //goto err;
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return NDIS_STATUS_SUCCESS;

err:
  NdisFreeMemory(xi, 0, 0);
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ " (error path)\n"));
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
  UNREFERENCED_PARAMETER(MiniportAdapterContext);

  KdPrint((__FUNCTION__ " called\n"));
}

/* Opposite of XenNet_Init */
VOID
XenNet_Halt(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
//  CHAR TmpPath[MAX_XENBUS_STR_LEN];
//  PVOID if_cxt = xi->XenInterface.InterfaceHeader.Context;
//  LARGE_INTEGER timeout;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

#if 0
  // set frontend state to 'closing'
  xi->state = XenbusStateClosing;
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(if_cxt, XBT_NIL, TmpPath, "%d", xi->state);

  // wait for backend to set 'Closing' state

  while (xi->backend_state != XenbusStateClosing)
  {
    timeout.QuadPart = -5 * 1000 * 1000 * 100; // 5 seconds
    if (KeWaitForSingleObject(&xi->backend_state_change_event, Executive, KernelMode, FALSE, &timeout) != STATUS_SUCCESS)
      KdPrint((__DRIVER_NAME "     Still Waiting for Closing...\n"));
  }

  // set frontend state to 'closed'
  xi->state = XenbusStateClosed;
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(if_cxt, XBT_NIL, TmpPath, "%d", xi->state);

  // wait for backend to set 'Closed' state
  while (xi->backend_state != XenbusStateClosed)
  {
    timeout.QuadPart = -5 * 1000 * 1000 * 100; // 5 seconds
    if (KeWaitForSingleObject(&xi->backend_state_change_event, Executive, KernelMode, FALSE, &timeout) != STATUS_SUCCESS)
      KdPrint((__DRIVER_NAME "     Still Waiting for Closed...\n"));
  }

  // set frontend state to 'Initialising'
  xi->state = XenbusStateInitialising;
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->pdo_data->Path);
  xi->XenInterface.XenBus_Printf(if_cxt, XBT_NIL, TmpPath, "%d", xi->state);

  // wait for backend to set 'InitWait' state
  while (xi->backend_state != XenbusStateInitWait)
  {
    timeout.QuadPart = -5 * 1000 * 1000 * 100; // 5 seconds
    if (KeWaitForSingleObject(&xi->backend_state_change_event, Executive, KernelMode, FALSE, &timeout) != STATUS_SUCCESS)
      KdPrint((__DRIVER_NAME "     Still Waiting for InitWait...\n"));
  }
#endif
  // Disables the interrupt
  XenNet_Shutdown(xi);

  xi->connected = FALSE;
  KeMemoryBarrier(); /* make sure everyone sees that we are now shut down */

  // TODO: remove event channel xenbus entry (how?)

  XenNet_TxShutdown(xi);
  XenNet_RxShutdown(xi);

#if 0

  /* Remove watch on backend state */
  RtlStringCbPrintfA(TmpPath, ARRAY_SIZE(TmpPath), "%s/state", xi->backend_path);
  xi->XenInterface.XenBus_RemWatch(if_cxt, XBT_NIL, TmpPath,
    XenNet_BackEndStateHandler, xi);

#endif

  NdisFreeBufferPool(xi->buffer_pool);
  NdisFreePacketPool(xi->packet_pool);

  NdisFreeMemory(xi, 0, 0); // <= DISPATCH_LEVEL

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static PDRIVER_DISPATCH XenNet_Pnp_Original;

static NTSTATUS
XenNet_Pnp(PDEVICE_OBJECT device_object, PIRP irp)
{
  PIO_STACK_LOCATION stack;
  NTSTATUS status;
  PCM_RESOURCE_LIST old_crl, new_crl;
  PCM_PARTIAL_RESOURCE_LIST prl;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR prd;
  ULONG old_length, new_length;
  PMDL mdl;
  PUCHAR start, ptr;
  //NDIS_STRING config_param_name;
  //PNDIS_CONFIGURATION_PARAMETER config_param;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stack = IoGetCurrentIrpStackLocation(irp);

  // check if the Irp is meant for us... maybe the stack->DeviceObject field?
  
  switch (stack->MinorFunction)
  {
  case IRP_MN_START_DEVICE:
  
#if 0
  NdisOpenConfiguration(&status, &config_handle, WrapperConfigurationContext);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Could not open config in registry (%08x)\n", status));
    goto err;
  }

  NdisInitUnicodeString(&config_param_name, L"ScatterGather");
  NdisReadConfiguration(&status, &config_param, config_handle, &config_param_name, NdisParameterInteger);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Could not read ScatterGather value (%08x)\n", status));
    xi->config_sg = 1;
  }
  else
  {
    KdPrint(("ScatterGather = %d\n", config_param->ParameterData.IntegerData));
    xi->config_sg = config_param->ParameterData.IntegerData;
  }
  
  NdisInitUnicodeString(&config_param_name, L"LargeSendOffload");
  NdisReadConfiguration(&status, &config_param, config_handle, &config_param_name, NdisParameterInteger);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Could not read LargeSendOffload value (%08x)\n", status));
    xi->config_gso = 0;
  }
  else
  {
    KdPrint(("LargeSendOffload = %d\n", config_param->ParameterData.IntegerData));
    xi->config_gso = config_param->ParameterData.IntegerData;
    if (xi->config_gso > 61440)
    {
      xi->config_gso = 61440;
      KdPrint(("(clipped to %d)\n", xi->config_gso));
    }
  }

  NdisInitUnicodeString(&config_param_name, L"ChecksumOffload");
  NdisReadConfiguration(&status, &config_param, config_handle, &config_param_name, NdisParameterInteger);
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Could not read ChecksumOffload value (%08x)\n", status));
    xi->config_csum = 1;
  }
  else
  {
    KdPrint(("ChecksumOffload = %d\n", config_param->ParameterData.IntegerData));
    xi->config_csum = config_param->ParameterData.IntegerData;
  }

  NdisInitUnicodeString(&config_param_name, L"MTU");
  NdisReadConfiguration(&status, &config_param, config_handle, &config_param_name, NdisParameterInteger);  
  if (!NT_SUCCESS(status))
  {
    KdPrint(("Could not read MTU value (%08x)\n", status));
    xi->config_mtu = 1500;
  }
  else
  {
    KdPrint(("MTU = %d\n", config_param->ParameterData.IntegerData));
    xi->config_mtu = config_param->ParameterData.IntegerData;
  }

  xi->config_max_pkt_size = max(xi->config_mtu + XN_HDR_SIZE, xi->config_gso + XN_HDR_SIZE);
  
  NdisCloseConfiguration(config_handle);
#endif

    KdPrint((__DRIVER_NAME "     IRP_MN_START_DEVICE - DeviceObject = %p\n", stack->DeviceObject));
    old_crl = stack->Parameters.StartDevice.AllocatedResourcesTranslated;
    if (old_crl != NULL)
    {
      mdl = AllocatePage();
      old_length = FIELD_OFFSET(CM_RESOURCE_LIST, List) + 
        FIELD_OFFSET(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList) +
        FIELD_OFFSET(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors) +
        sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * old_crl->List[0].PartialResourceList.Count;
      new_length = old_length + sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * 1;
      new_crl = ExAllocatePoolWithTag(PagedPool, new_length, XENNET_POOL_TAG);
      memcpy(new_crl, old_crl, old_length);
      prl = &new_crl->List[0].PartialResourceList;
      prd = &prl->PartialDescriptors[prl->Count++];
      prd->Type = CmResourceTypeMemory;
      prd->ShareDisposition = CmResourceShareDeviceExclusive;
      prd->Flags = CM_RESOURCE_MEMORY_READ_WRITE|CM_RESOURCE_MEMORY_PREFETCHABLE|CM_RESOURCE_MEMORY_CACHEABLE;
      prd->u.Memory.Start.QuadPart = MmGetMdlPfnArray(mdl)[0] << PAGE_SHIFT;
      prd->u.Memory.Length = PAGE_SIZE;
      KdPrint((__DRIVER_NAME "     Start = %08x, Length = %d\n", prd->u.Memory.Start.LowPart, prd->u.Memory.Length));
      ptr = start = MmGetMdlVirtualAddress(mdl);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_RING, "tx-ring-ref", NULL);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_RING, "rx-ring-ref", NULL);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_EVENT_CHANNEL_IRQ, "event-channel", NULL);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_BACK, "mac", NULL);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_WRITE_STRING, "feature-no-csum-offload", "0");
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_WRITE_STRING, "feature-sg", "1");
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_WRITE_STRING, "feature-gso-tcpv4", "1");
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_WRITE_STRING, "request-rx-copy", "1");
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_WRITE_STRING, "feature-rx-notify", "1");
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_VECTORS, NULL, NULL);
      ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_END, NULL, NULL);
      
      stack->Parameters.StartDevice.AllocatedResourcesTranslated = new_crl;

      old_crl = stack->Parameters.StartDevice.AllocatedResources;
      new_crl = ExAllocatePoolWithTag(PagedPool, new_length, XENNET_POOL_TAG);
      memcpy(new_crl, old_crl, old_length);
      prl = &new_crl->List[0].PartialResourceList;
      prd = &prl->PartialDescriptors[prl->Count++];
      prd->Type = CmResourceTypeMemory;
      prd->ShareDisposition = CmResourceShareDeviceExclusive;
      prd->Flags = CM_RESOURCE_MEMORY_READ_WRITE|CM_RESOURCE_MEMORY_PREFETCHABLE|CM_RESOURCE_MEMORY_CACHEABLE;
      prd->u.Memory.Start.QuadPart = MmGetMdlPfnArray(mdl)[0] << PAGE_SHIFT;
      prd->u.Memory.Length = PAGE_SIZE;
      stack->Parameters.StartDevice.AllocatedResources = new_crl;
      IoCopyCurrentIrpStackLocationToNext(irp);
    }
    else
    {
      KdPrint((__DRIVER_NAME "     AllocatedResource == NULL\n"));
    }
    status = XenNet_Pnp_Original(device_object, irp);
    break;
  default:
    status = XenNet_Pnp_Original(device_object, irp);
    break;
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

NTSTATUS
DriverEntry(
  PDRIVER_OBJECT DriverObject,
  PUNICODE_STRING RegistryPath
  )
{
  NTSTATUS status;
  NDIS_HANDLE ndis_wrapper_handle;
  NDIS_MINIPORT_CHARACTERISTICS mini_chars;

  ProfTime_TxBufferGC.QuadPart = 0;
  ProfTime_RxBufferAlloc.QuadPart = 0;
  ProfTime_ReturnPacket.QuadPart = 0;
  ProfTime_RxBufferCheck.QuadPart = 0;
  ProfTime_RxBufferCheckTopHalf.QuadPart = 0;
  ProfTime_RxBufferCheckBotHalf.QuadPart = 0;
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
  ProfCount_TxPacketsCsumOffload = 0;
  ProfCount_TxPacketsLargeOffload = 0;
  ProfCount_RxPacketsTotal = 0;
  ProfCount_RxPacketsCsumOffload = 0;
  ProfCount_CallsToIndicateReceive = 0;

  RtlZeroMemory(&mini_chars, sizeof(mini_chars));

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
  mini_chars.ISRHandler = XenNet_InterruptIsr;
  mini_chars.HandleInterruptHandler = XenNet_InterruptDpc;
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

  /* this is a bit naughty... */
  XenNet_Pnp_Original = DriverObject->MajorFunction[IRP_MJ_PNP];
  DriverObject->MajorFunction[IRP_MJ_PNP] = XenNet_Pnp;

  return status;
}
