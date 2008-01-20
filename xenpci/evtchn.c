/*
PV Drivers for Windows Xen HVM Domains
Copyright (C) 2007 James Harper

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

#include "xenpci.h"

static VOID
EvtChn_DpcBounce(WDFDPC Dpc)
{
  ev_action_t *Action;

  Action = GetEvtChnDeviceData(Dpc)->Action;
  Action->ServiceRoutine(NULL, Action->ServiceContext);
}

BOOLEAN
EvtChn_Interrupt(WDFINTERRUPT Interrupt, ULONG MessageID)
{
  int cpu = KeGetCurrentProcessorNumber();
  vcpu_info_t *vcpu_info;
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(WdfInterruptGetDevice(Interrupt));
  shared_info_t *shared_info_area = xpdd->shared_info_area;
  unsigned long evt_words, evt_word;
  unsigned long evt_bit;
  unsigned long port;
  ev_action_t *ev_action;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ " (cpu = %d)\n", cpu));

  UNREFERENCED_PARAMETER(MessageID);

  vcpu_info = &shared_info_area->vcpu_info[cpu];

  vcpu_info->evtchn_upcall_pending = 0;

  evt_words = _InterlockedExchange((volatile LONG *)&vcpu_info->evtchn_pending_sel, 0);
  
  while (_BitScanForward(&evt_word, evt_words))
  {
    evt_words &= ~(1 << evt_word);
    while (_BitScanForward(&evt_bit, shared_info_area->evtchn_pending[evt_word] & ~shared_info_area->evtchn_mask[evt_word]))
    {
      port = (evt_word << 5) + evt_bit;
      ev_action = &xpdd->ev_actions[port];
      if (ev_action->ServiceRoutine == NULL)
      {
        KdPrint((__DRIVER_NAME "     Unhandled Event!!!\n"));
      }
      else
      {
        if (ev_action->DpcFlag)
        {
//          KdPrint((__DRIVER_NAME " --- Scheduling Dpc\n"));
          WdfDpcEnqueue(ev_action->Dpc);
        }
        else
        {
          ev_action->ServiceRoutine(NULL, ev_action->ServiceContext);
        }
      }
      _interlockedbittestandreset((volatile LONG *)&shared_info_area->evtchn_pending[0], port);
    }
  }

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return FALSE; // This needs to be FALSE so it can fall through to the scsiport ISR.
}

NTSTATUS
EvtChn_Bind(PVOID Context, evtchn_port_t Port, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext)
{
  WDFDEVICE Device = Context;
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);

  KdPrint((__DRIVER_NAME " --> EvtChn_Bind (ServiceRoutine = %08X, ServiceContext = %08x)\n", ServiceRoutine, ServiceContext));

  if(xpdd->ev_actions[Port].ServiceRoutine != NULL)
  {
    xpdd->ev_actions[Port].ServiceRoutine = NULL;
    KeMemoryBarrier(); // make sure we don't call the old Service Routine with the new data...
    KdPrint((__DRIVER_NAME " Handler for port %d already registered, replacing\n", Port));
  }

  xpdd->ev_actions[Port].DpcFlag = FALSE;
  xpdd->ev_actions[Port].ServiceContext = ServiceContext;
  KeMemoryBarrier();
  xpdd->ev_actions[Port].ServiceRoutine = ServiceRoutine;

  EvtChn_Unmask(Device, Port);

  KdPrint((__DRIVER_NAME " <-- EvtChn_Bind\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
EvtChn_BindDpc(PVOID Context, evtchn_port_t Port, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext)
{
  WDFDEVICE Device = Context;
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
  WDF_DPC_CONFIG DpcConfig;
  WDF_OBJECT_ATTRIBUTES DpcObjectAttributes;

  KdPrint((__DRIVER_NAME " --> EvtChn_BindDpc\n"));

  if(xpdd->ev_actions[Port].ServiceRoutine != NULL)
  {
    KdPrint((__DRIVER_NAME " Handler for port %d already registered, replacing\n", Port));
    xpdd->ev_actions[Port].ServiceRoutine = NULL;
    KeMemoryBarrier(); // make sure we don't call the old Service Routine with the new data...
  }

  xpdd->ev_actions[Port].ServiceContext = ServiceContext;
  xpdd->ev_actions[Port].DpcFlag = TRUE;

  WDF_DPC_CONFIG_INIT(&DpcConfig, EvtChn_DpcBounce);
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&DpcObjectAttributes, EVTCHN_DEVICE_DATA);
  DpcObjectAttributes.ParentObject = Device;
  WdfDpcCreate(&DpcConfig, &DpcObjectAttributes, &xpdd->ev_actions[Port].Dpc);
  GetEvtChnDeviceData(xpdd->ev_actions[Port].Dpc)->Action = &xpdd->ev_actions[Port];

  KeMemoryBarrier(); // make sure that the new service routine is only called once the context is set up
  xpdd->ev_actions[Port].ServiceRoutine = ServiceRoutine;

  EvtChn_Unmask(Device, Port);

  KdPrint((__DRIVER_NAME " <-- EvtChn_BindDpc\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
EvtChn_Unbind(PVOID Context, evtchn_port_t Port)
{
  WDFDEVICE Device = Context;
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);

  EvtChn_Mask(Context, Port);
  xpdd->ev_actions[Port].ServiceRoutine = NULL;
  KeMemoryBarrier();
  xpdd->ev_actions[Port].ServiceContext = NULL;

  if (xpdd->ev_actions[Port].DpcFlag)
    WdfDpcCancel(xpdd->ev_actions[Port].Dpc, TRUE);
  
  //KdPrint((__DRIVER_NAME " <-- EvtChn_UnBind\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
EvtChn_Mask(PVOID Context, evtchn_port_t Port)
{
  WDFDEVICE Device = Context;
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
  //KdPrint((__DRIVER_NAME " --> EvtChn_Mask\n"));

  _interlockedbittestandset(
    (volatile LONG *)&xpdd->shared_info_area->evtchn_mask[0], Port);

  //KdPrint((__DRIVER_NAME " <-- EvtChn_Mask\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
EvtChn_Unmask(PVOID Context, evtchn_port_t Port)
{
  WDFDEVICE Device = Context;
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
  //KdPrint((__DRIVER_NAME " --> EvtChn_Unmask\n"));

  _interlockedbittestandreset(
    (volatile LONG *)&xpdd->shared_info_area->evtchn_mask[0], Port);
  // should we kick off pending interrupts here too???

  //KdPrint((__DRIVER_NAME " <-- EvtChn_Unmask\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
EvtChn_Notify(PVOID Context, evtchn_port_t Port)
{
  struct evtchn_send send;

  //KdPrint((__DRIVER_NAME " --> EvtChn_Notify\n"));

  send.port = Port;

  (void)HYPERVISOR_event_channel_op(Context, EVTCHNOP_send, &send);

  //KdPrint((__DRIVER_NAME " <-- EvtChn_Notify\n"));

  return STATUS_SUCCESS;
}

evtchn_port_t
EvtChn_AllocUnbound(PVOID Context, domid_t Domain)
{
  evtchn_alloc_unbound_t op;

  //KdPrint((__DRIVER_NAME " --> AllocUnbound\n"));

  op.dom = DOMID_SELF;
  op.remote_dom = Domain;
  HYPERVISOR_event_channel_op(Context, EVTCHNOP_alloc_unbound, &op);

  //KdPrint((__DRIVER_NAME " <-- AllocUnbound\n"));

  return op.port;
}

evtchn_port_t
EvtChn_GetXenStorePort(WDFDEVICE Device)
{
  evtchn_port_t Port;  

  //KdPrint((__DRIVER_NAME " --> EvtChn_GetStorePort\n"));

  Port = (evtchn_port_t)hvm_get_parameter(Device, HVM_PARAM_STORE_EVTCHN);

  //KdPrint((__DRIVER_NAME " <-- EvtChn_GetStorePort\n"));

  return Port;
}

PVOID
EvtChn_GetXenStoreRingAddr(WDFDEVICE Device)
{
  PHYSICAL_ADDRESS pa_xen_store_interface;
  PVOID xen_store_interface;

  ULONG xen_store_mfn;

  //KdPrint((__DRIVER_NAME " --> EvtChn_GetRingAddr\n"));

  xen_store_mfn = (ULONG)hvm_get_parameter(Device, HVM_PARAM_STORE_PFN);

  pa_xen_store_interface.QuadPart = xen_store_mfn << PAGE_SHIFT;
  xen_store_interface = MmMapIoSpace(pa_xen_store_interface, PAGE_SIZE, MmNonCached);

  //KdPrint((__DRIVER_NAME " xen_store_mfn = %08x\n", xen_store_mfn));
  //KdPrint((__DRIVER_NAME " xen_store_evtchn = %08x\n", xen_store_evtchn));
  //KdPrint((__DRIVER_NAME " xen_store_interface = %08x\n", xen_store_interface));

  //KeInitializeEvent(&xenbus_waitevent, NotificationEvent, FALSE);

  //KdPrint((__DRIVER_NAME " <-- EvtChn_GetRingAddr\n"));

  return xen_store_interface;
}

NTSTATUS
EvtChn_Init(WDFDEVICE Device)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
  int i;

  for (i = 0; i < NR_EVENTS; i++)
  {
    EvtChn_Mask(Device, i);
    xpdd->ev_actions[i].ServiceRoutine = NULL;
    xpdd->ev_actions[i].ServiceContext = NULL;
    xpdd->ev_actions[i].Count = 0;
  }

  for (i = 0; i < 8; i++)
  {
    xpdd->shared_info_area->evtchn_pending[i] = 0;
  }

  for (i = 0; i < MAX_VIRT_CPUS; i++)
  {
    xpdd->shared_info_area->vcpu_info[i].evtchn_upcall_pending = 0;
    xpdd->shared_info_area->vcpu_info[i].evtchn_pending_sel = 0;
  }

  return STATUS_SUCCESS;
}
