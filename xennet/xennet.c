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

/* ----- BEGIN Other people's code --------- */
/* from linux/include/linux/ctype.h, used under GPLv2 */
#define _U      0x01    /* upper */
#define _L      0x02    /* lower */
#define _D      0x04    /* digit */
#define _C      0x08    /* cntrl */
#define _P      0x10    /* punct */
#define _S      0x20    /* white space (space/lf/tab) */
#define _X      0x40    /* hex digit */
#define _SP     0x80    /* hard space (0x20) */

/* from linux/include/lib/ctype.c, used under GPLv2 */
unsigned char _ctype[] = {
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 0-7 */
_C,_C|_S,_C|_S,_C|_S,_C|_S,_C|_S,_C,_C,         /* 8-15 */
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 16-23 */
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 24-31 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,                    /* 32-39 */
_P,_P,_P,_P,_P,_P,_P,_P,                        /* 40-47 */
_D,_D,_D,_D,_D,_D,_D,_D,                        /* 48-55 */
_D,_D,_P,_P,_P,_P,_P,_P,                        /* 56-63 */
_P,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U,      /* 64-71 */
_U,_U,_U,_U,_U,_U,_U,_U,                        /* 72-79 */
_U,_U,_U,_U,_U,_U,_U,_U,                        /* 80-87 */
_U,_U,_U,_P,_P,_P,_P,_P,                        /* 88-95 */
_P,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L,      /* 96-103 */
_L,_L,_L,_L,_L,_L,_L,_L,                        /* 104-111 */
_L,_L,_L,_L,_L,_L,_L,_L,                        /* 112-119 */
_L,_L,_L,_P,_P,_P,_P,_C,                        /* 120-127 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                /* 128-143 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                /* 144-159 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,   /* 160-175 */
_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,       /* 176-191 */
_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,       /* 192-207 */
_U,_U,_U,_U,_U,_U,_U,_P,_U,_U,_U,_U,_U,_U,_U,_L,       /* 208-223 */
_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,       /* 224-239 */
_L,_L,_L,_L,_L,_L,_L,_P,_L,_L,_L,_L,_L,_L,_L,_L};      /* 240-255 */

/* from linux/include/linux/ctype.h, used under GPLv2 */
#define __ismask(x) (_ctype[(int)(unsigned char)(x)])

#define isalnum(c)      ((__ismask(c)&(_U|_L|_D)) != 0)
#define isalpha(c)      ((__ismask(c)&(_U|_L)) != 0)
#define iscntrl(c)      ((__ismask(c)&(_C)) != 0)
#define isdigit(c)      ((__ismask(c)&(_D)) != 0)
#define isgraph(c)      ((__ismask(c)&(_P|_U|_L|_D)) != 0)
#define islower(c)      ((__ismask(c)&(_L)) != 0)
#define isprint(c)      ((__ismask(c)&(_P|_U|_L|_D|_SP)) != 0)
#define ispunct(c)      ((__ismask(c)&(_P)) != 0)
#define isspace(c)      ((__ismask(c)&(_S)) != 0)
#define isupper(c)      ((__ismask(c)&(_U)) != 0)
#define isxdigit(c)     ((__ismask(c)&(_D|_X)) != 0)

#define TOLOWER(x) ((x) | 0x20)

/* from linux/lib/vsprintf.c, used under GPLv2 */
/* Copyright (C) 1991, 1992  Linus Torvalds
 * Wirzenius wrote this portably, Torvalds fucked it up :-)
 */
/**
 * simple_strtoul - convert a string to an unsigned long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base)
{
  unsigned long result = 0,value;

  if (!base) {
    base = 10;
    if (*cp == '0') {
      base = 8;
      cp++;
      if ((TOLOWER(*cp) == 'x') && isxdigit(cp[1])) {
        cp++;
        base = 16;
      }
    }
  } else if (base == 16) {
    if (cp[0] == '0' && TOLOWER(cp[1]) == 'x')
      cp += 2;
  }
  while (isxdigit(*cp) &&
    (value = isdigit(*cp) ? *cp-'0' : TOLOWER(*cp)-'a'+10) < base) {
    result = result*base + value;
    cp++;
  }
  if (endp)
    *endp = (char *)cp;
  return result;
}
/* end vsprintf.c code */
/* ----- END Other people's code --------- */

// Called at DISPATCH_LEVEL

static DDKAPI VOID
XenNet_InterruptIsr(
  PBOOLEAN InterruptRecognized,
  PBOOLEAN QueueMiniportHandleInterrupt,
  NDIS_HANDLE MiniportAdapterContext)
{
  struct xennet_info *xi = MiniportAdapterContext;
  
  //FUNCTION_ENTER();

  *QueueMiniportHandleInterrupt = (BOOLEAN)!!xi->connected;
  *InterruptRecognized = FALSE; /* we can't be sure here... */

  //FUNCTION_EXIT();
}

static DDKAPI VOID
XenNet_InterruptDpc(NDIS_HANDLE  MiniportAdapterContext)
{
  struct xennet_info *xi = MiniportAdapterContext;

  if (xi->device_state->resume_state != RESUME_STATE_RUNNING)
  {
    KdPrint((__DRIVER_NAME " --- " __FUNCTION__ " device_state event\n"));
    // there should be a better way to synchronise with rx and tx...
    KeAcquireSpinLockAtDpcLevel(&xi->rx_lock);
    KeReleaseSpinLockFromDpcLevel(&xi->rx_lock);
    KeAcquireSpinLockAtDpcLevel(&xi->tx_lock);
    KeReleaseSpinLockFromDpcLevel(&xi->tx_lock);
    xi->device_state->resume_state_ack = xi->device_state->resume_state;
    return;
  }

  //FUNCTION_ENTER();
  if (xi->connected)
  {
    XenNet_TxBufferGC(xi);
    XenNet_RxBufferCheck(xi);
  }
  //FUNCTION_EXIT();
}

static NDIS_STATUS
XenNet_ConnectBackend(struct xennet_info *xi)
{
  PUCHAR ptr;
  UCHAR type;
  PCHAR setting, value;
  UINT i;

  ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

  ptr = xi->config_page;
  while((type = GET_XEN_INIT_RSP(&ptr, (PVOID)&setting, (PVOID)&value)) != XEN_INIT_TYPE_END)
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
        for (i = 0; i < ETH_ALEN; i++) {
          xi->perm_mac_addr[i] = (uint8_t)simple_strtoul(s, &e, 16);
          if ((s == e) || (*e != ((i == ETH_ALEN-1) ? '\0' : ':'))) {
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
        FUNCTION_ERROR_EXIT();
        return NDIS_STATUS_ADAPTER_NOT_FOUND;
      }
      else
        memcpy(&xi->vectors, value, sizeof(XENPCI_VECTORS));
      break;
    case XEN_INIT_TYPE_STATE_PTR:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_DEVICE_STATE - %p\n", PtrToUlong(value)));
      xi->device_state = (PXENPCI_DEVICE_STATE)value;
      break;
    default:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_%d\n", type));
      break;
    }
  }
  return NDIS_STATUS_SUCCESS;
}

static DDKAPI VOID
XenNet_Resume(PDEVICE_OBJECT device_object, PVOID context)
{
  struct xennet_info *xi = context;
  
  UNREFERENCED_PARAMETER(device_object);
  
  XenNet_RxResumeStart(xi);
  XenNet_TxResumeStart(xi);
  XenNet_ConnectBackend(xi);
  xi->device_state->resume_state = RESUME_STATE_RUNNING;
  XenNet_RxResumeEnd(xi);
  XenNet_TxResumeEnd(xi);
  NdisMSetPeriodicTimer(&xi->resume_timer, 100);
}

static DDKAPI VOID 
XenResumeCheck_Timer(
 PVOID SystemSpecific1,
 PVOID FunctionContext,
 PVOID SystemSpecific2,
 PVOID SystemSpecific3
)
{
  struct xennet_info *xi = FunctionContext;
  PIO_WORKITEM work_item;
  BOOLEAN timer_cancelled;
 
  UNREFERENCED_PARAMETER(SystemSpecific1);
  UNREFERENCED_PARAMETER(SystemSpecific2);
  UNREFERENCED_PARAMETER(SystemSpecific3);
 
  if (xi->device_state->resume_state == RESUME_STATE_FRONTEND_RESUME)
  {
    NdisMCancelTimer(&xi->resume_timer, &timer_cancelled);
  	work_item = IoAllocateWorkItem(xi->fdo);
  	IoQueueWorkItem(work_item, XenNet_Resume, DelayedWorkQueue, xi);
  }
}

// Called at <= DISPATCH_LEVEL
static DDKAPI NDIS_STATUS
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
  BOOLEAN medium_found = FALSE;
  struct xennet_info *xi = NULL;
  ULONG nrl_length;
  PNDIS_RESOURCE_LIST nrl;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR prd;
  KIRQL irq_level = 0;
  ULONG irq_vector = 0;
  NDIS_HANDLE config_handle;
  NDIS_STRING config_param_name;
  PNDIS_CONFIGURATION_PARAMETER config_param;
  ULONG i;
  PUCHAR ptr;
  UCHAR type;
  PCHAR setting, value;
  ULONG length;
  CHAR buf[128];
  
  UNREFERENCED_PARAMETER(OpenErrorStatus);

  FUNCTION_ENTER();

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
  status = NdisAllocateMemoryWithTag((PVOID)&xi, sizeof(*xi), XENNET_POOL_TAG);
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

  nrl_length = 0;
  NdisMQueryAdapterResources(&status, WrapperConfigurationContext,
    NULL, (PUINT)&nrl_length);
  KdPrint((__DRIVER_NAME "     nrl_length = %d\n", nrl_length));
  status = NdisAllocateMemoryWithTag((PVOID)&nrl, nrl_length, XENNET_POOL_TAG);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint((__DRIVER_NAME "     Could not get allocate memory for Adapter Resources 0x%x\n", status));
    return NDIS_STATUS_RESOURCES;
  }
  NdisMQueryAdapterResources(&status, WrapperConfigurationContext,
    nrl, (PUINT)&nrl_length);
  if (status != NDIS_STATUS_SUCCESS)
  {
    KdPrint((__DRIVER_NAME "     Could not get Adapter Resources 0x%x\n", status));
    return NDIS_STATUS_RESOURCES;
  }
  xi->event_channel = 0;
  xi->config_csum = 1;
  xi->config_sg = 1;
  xi->config_gso = 61440;
  xi->config_page = NULL;
  
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
      status = NdisMMapIoSpace(&xi->config_page, MiniportAdapterHandle, prd->u.Memory.Start, prd->u.Memory.Length);
      if (!NT_SUCCESS(status))
      {
        KdPrint(("NdisMMapIoSpace failed with 0x%x\n", status));
        NdisFreeMemory(nrl, nrl_length, 0);
        return NDIS_STATUS_RESOURCES;
      }
      break;
    }
  }
  NdisFreeMemory(nrl, nrl_length, 0);
  if (!xi->config_page)
  {
    KdPrint(("No config page given\n"));
    return NDIS_STATUS_RESOURCES;
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

  ptr = xi->config_page;
  while((type = GET_XEN_INIT_RSP(&ptr, (PVOID)&setting, (PVOID)&value)) != XEN_INIT_TYPE_END)
  {
    switch(type)
    {
    case XEN_INIT_TYPE_VECTORS:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_VECTORS\n"));
      if (((PXENPCI_VECTORS)value)->length != sizeof(XENPCI_VECTORS) ||
        ((PXENPCI_VECTORS)value)->magic != XEN_DATA_MAGIC)
      {
        KdPrint((__DRIVER_NAME "     vectors mismatch (magic = %08x, length = %d)\n",
          ((PXENPCI_VECTORS)value)->magic, ((PXENPCI_VECTORS)value)->length));
        FUNCTION_ERROR_EXIT();
        return NDIS_STATUS_FAILURE;
      }
      else
        memcpy(&xi->vectors, value, sizeof(XENPCI_VECTORS));
      break;
    case XEN_INIT_TYPE_STATE_PTR:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_DEVICE_STATE - %p\n", PtrToUlong(value)));
      xi->device_state = (PXENPCI_DEVICE_STATE)value;
      break;
    default:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_%d\n", type));
      break;
    }
  }
  
  // now build config page
  
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
    xi->config_csum = !!config_param->ParameterData.IntegerData;
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

  ptr = xi->config_page;
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_RUN, NULL, NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_RING, "tx-ring-ref", NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_RING, "rx-ring-ref", NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_EVENT_CHANNEL_IRQ, "event-channel", NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_BACK, "mac", NULL);
  RtlStringCbPrintfA(buf, ARRAY_SIZE(buf), "%d", !xi->config_csum);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_WRITE_STRING, "feature-no-csum-offload", buf);
  RtlStringCbPrintfA(buf, ARRAY_SIZE(buf), "%d", (int)xi->config_sg);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_WRITE_STRING, "feature-sg", buf);
  RtlStringCbPrintfA(buf, ARRAY_SIZE(buf), "%d", !!xi->config_gso);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_WRITE_STRING, "feature-gso-tcpv4", buf);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_WRITE_STRING, "request-rx-copy", "1");
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_WRITE_STRING, "feature-rx-notify", "1");
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_END, NULL, NULL);
  
  status = xi->vectors.XenPci_XenConfigDevice(xi->vectors.context);
  // check return value

  status = XenNet_ConnectBackend(xi);
  
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

  NdisMInitializeTimer(&xi->resume_timer, xi->adapter_handle, XenResumeCheck_Timer, xi);
  NdisMSetPeriodicTimer(&xi->resume_timer, 100);

  FUNCTION_EXIT();

  return NDIS_STATUS_SUCCESS;

err:
  NdisFreeMemory(xi, 0, 0);
  FUNCTION_ERROR_EXIT();
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

  FUNCTION_CALLED();
}

/* Called when machine is shutting down, so just quiesce the HW and be done fast. */
VOID DDKAPI
XenNet_Shutdown(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  struct xennet_info *xi = MiniportAdapterContext;

  FUNCTION_CALLED();

  NdisMDeregisterInterrupt(&xi->interrupt);
}

/* Opposite of XenNet_Init */
VOID DDKAPI
XenNet_Halt(
  IN NDIS_HANDLE MiniportAdapterContext
  )
{
  struct xennet_info *xi = MiniportAdapterContext;
//  CHAR TmpPath[MAX_XENBUS_STR_LEN];
//  PVOID if_cxt = xi->XenInterface.InterfaceHeader.Context;
//  LARGE_INTEGER timeout;

  FUNCTION_ENTER();
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  // Disables the interrupt
  XenNet_Shutdown(xi);

  xi->vectors.XenPci_XenShutdownDevice(xi->vectors.context);

  xi->connected = FALSE;
  KeMemoryBarrier(); /* make sure everyone sees that we are now shut down */

  // TODO: remove event channel xenbus entry (how?)

  XenNet_TxShutdown(xi);
  XenNet_RxShutdown(xi);

  NdisFreeBufferPool(xi->buffer_pool);
  NdisFreePacketPool(xi->packet_pool);

  NdisFreeMemory(xi, 0, 0); // <= DISPATCH_LEVEL

  FUNCTION_EXIT();
}

NTSTATUS DDKAPI
DriverEntry(
  PDRIVER_OBJECT DriverObject,
  PUNICODE_STRING RegistryPath
  )
{
  NTSTATUS status;
  NDIS_HANDLE ndis_wrapper_handle;
  NDIS_MINIPORT_CHARACTERISTICS mini_chars;

  FUNCTION_ENTER();

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

  FUNCTION_EXIT();

  return status;
}
