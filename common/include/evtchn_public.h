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

DEFINE_GUID( GUID_XEN_IFACE_EVTCHN, 0xD2D20756, 0xDE69, 0x4447, 0x8A, 0x7D, 0x98, 0x37, 0x19, 0x7D, 0x61, 0x66);
//{D2D20756-DE69-4447-8A7D-9837197D6166}

typedef evtchn_port_t
(*PXEN_EVTCHN_ALLOCUNBOUND)(domid_t Domain);

typedef NTSTATUS
(*PXEN_EVTCHN_BIND)(evtchn_port_t Port, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext);

typedef NTSTATUS
(*PXEN_EVTCHN_UNBIND)(evtchn_port_t Port);

typedef NTSTATUS
(*PXEN_EVTCHN_MASK)(evtchn_port_t Port);

typedef NTSTATUS
(*PXEN_EVTCHN_UNMASK)(evtchn_port_t Port);

typedef NTSTATUS
(*PXEN_EVTCHN_NOTIFY)(evtchn_port_t Port);

typedef struct _XENBUS_IFACE_EVTCHN {
  INTERFACE InterfaceHeader;

  PXEN_EVTCHN_BIND Bind;
  PXEN_EVTCHN_BIND BindDpc;
  PXEN_EVTCHN_UNBIND Unbind;
  PXEN_EVTCHN_MASK Mask;
  PXEN_EVTCHN_UNMASK Unmask;
  PXEN_EVTCHN_NOTIFY Notify;
  PXEN_EVTCHN_ALLOCUNBOUND AllocUnbound;

} XEN_IFACE_EVTCHN, *PXEN_IFACE_EVTCHN;
