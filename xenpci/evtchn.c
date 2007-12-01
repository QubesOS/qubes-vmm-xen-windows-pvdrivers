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
#include "hypercall.h"

#define NR_EVENTS 1024

typedef struct _ev_action_t {
  PKSERVICE_ROUTINE ServiceRoutine;
  PVOID ServiceContext;
  ULONG Count;
} ev_action_t;

static ev_action_t ev_actions[NR_EVENTS];

static unsigned long bound_ports[NR_EVENTS/(8*sizeof(unsigned long))];

BOOLEAN
EvtChn_Interrupt(WDFINTERRUPT Interrupt, ULONG MessageID)
{
  int cpu = 0;
  vcpu_info_t *vcpu_info;
//  int i;
  unsigned long evt_words, evt_word;
  unsigned long evt_bit;
  unsigned long port;
  ev_action_t *ev_action;

  UNREFERENCED_PARAMETER(Interrupt);
  UNREFERENCED_PARAMETER(MessageID);

  //KdPrint((__DRIVER_NAME "     I+\n"));
  //KdPrint((__DRIVER_NAME " --> XenPCI_ISR\n"));

  vcpu_info = &shared_info_area->vcpu_info[cpu];

  vcpu_info->evtchn_upcall_pending = 0;

  evt_words = _InterlockedExchange((volatile LONG *)&vcpu_info->evtchn_pending_sel, 0);
  
  while (_BitScanForward(&evt_word, evt_words))
  {
    evt_words &= ~(1 << evt_word);
    while (_BitScanForward(&evt_bit, shared_info_area->evtchn_pending[evt_word] & ~shared_info_area->evtchn_mask[evt_word]))
    {
      port = (evt_word << 5) + evt_bit;
      ev_action = &ev_actions[port];
      if (ev_action->ServiceRoutine == NULL)
      {
        KdPrint((__DRIVER_NAME "     Unhandled Event!!!\n"));
      }
      else
      {
        //KdPrint((__DRIVER_NAME "     Calling Handler for port %d\n", port));
        ev_action->ServiceRoutine(NULL, ev_action->ServiceContext);
      }
      _interlockedbittestandreset((volatile LONG *)&shared_info_area->evtchn_pending[0], port);
    }
  }

  //KdPrint((__DRIVER_NAME " <-- XenPCI_ISR\n"));

  //KdPrint((__DRIVER_NAME "     I-\n"));

  return TRUE;
}

evtchn_port_t
EvtChn_AllocUnbound(domid_t Domain)
{
  evtchn_alloc_unbound_t op;

  //KdPrint((__DRIVER_NAME " --> AllocUnbound\n"));

  op.dom = DOMID_SELF;
  op.remote_dom = Domain;
  HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);

  //KdPrint((__DRIVER_NAME " <-- AllocUnbound\n"));

  return op.port;
}


NTSTATUS
EvtChn_Bind(evtchn_port_t Port, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext)
{
  KdPrint((__DRIVER_NAME " --> EvtChn_Bind\n"));

  if(ev_actions[Port].ServiceRoutine != NULL)
  {
    KdPrint((__DRIVER_NAME " Handler for port %d already registered, replacing\n", Port));
  }

  ev_actions[Port].ServiceContext = ServiceContext;
  KeMemoryBarrier();
  ev_actions[Port].ServiceRoutine = ServiceRoutine;

  EvtChn_Unmask(Port);

  KdPrint((__DRIVER_NAME " <-- EvtChn_Bind\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
EvtChn_Unbind(evtchn_port_t Port)
{
  //KdPrint((__DRIVER_NAME " --> EvtChn_UnBind\n"));

  EvtChn_Mask(Port);
  ev_actions[Port].ServiceContext = NULL;
  ev_actions[Port].ServiceRoutine = NULL;

  //KdPrint((__DRIVER_NAME " <-- EvtChn_UnBind\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
EvtChn_Mask(evtchn_port_t Port)
{
  //KdPrint((__DRIVER_NAME " --> EvtChn_Mask\n"));

  _interlockedbittestandset((volatile LONG *)&shared_info_area->evtchn_mask[0], Port);

  //KdPrint((__DRIVER_NAME " <-- EvtChn_Mask\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
EvtChn_Unmask(evtchn_port_t Port)
{
  //KdPrint((__DRIVER_NAME " --> EvtChn_Unmask\n"));

  _interlockedbittestandreset((volatile LONG *)&shared_info_area->evtchn_mask[0], Port);
  // should we kick off pending interrupts here too???

  //KdPrint((__DRIVER_NAME " <-- EvtChn_Unmask\n"));

  return STATUS_SUCCESS;
}

NTSTATUS
EvtChn_Notify(evtchn_port_t Port)
{
  struct evtchn_send send;

  //KdPrint((__DRIVER_NAME " --> EvtChn_Notify\n"));

  send.port = Port;

  (void)HYPERVISOR_event_channel_op(EVTCHNOP_send, &send);

  //KdPrint((__DRIVER_NAME " <-- EvtChn_Notify\n"));

  return STATUS_SUCCESS;
}


evtchn_port_t
EvtChn_GetXenStorePort()
{
  evtchn_port_t Port;  

  //KdPrint((__DRIVER_NAME " --> EvtChn_GetStorePort\n"));

  Port = (evtchn_port_t)hvm_get_parameter(HVM_PARAM_STORE_EVTCHN);

  //KdPrint((__DRIVER_NAME " <-- EvtChn_GetStorePort\n"));

  return Port;
}

PVOID
EvtChn_GetXenStoreRingAddr()
{
  PHYSICAL_ADDRESS pa_xen_store_interface;
  PVOID xen_store_interface;

  ULONG xen_store_mfn;

  //KdPrint((__DRIVER_NAME " --> EvtChn_GetRingAddr\n"));

  xen_store_mfn = (ULONG)hvm_get_parameter(HVM_PARAM_STORE_PFN);

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
EvtChn_Init()
{
  int i;

  for (i = 0; i < NR_EVENTS; i++)
  {
    EvtChn_Mask(i);
    ev_actions[i].ServiceRoutine = NULL;
    ev_actions[i].ServiceContext = NULL;
    ev_actions[i].Count = 0;
  }

  for (i = 0; i < 8; i++) {
    shared_info_area->evtchn_pending[i] = 0;
  }
  shared_info_area->vcpu_info[0].evtchn_upcall_pending = 0;
  shared_info_area->vcpu_info[0].evtchn_pending_sel = 0;

  return STATUS_SUCCESS;
}

static ev_action_t ev_actions[NR_EVENTS];
