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

#if !defined(_XENPCI_H_)
#define _XENPCI_H_

#define __attribute__(arg) /* empty */
#define EISCONN 127

#include <ntddk.h>
#include <wdm.h>
#include <wdf.h>
#include <initguid.h>
#include <wdmguid.h>
#include <errno.h>

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#include <xen_windows.h>
#include <memory.h>
#include <grant_table.h>
#include <event_channel.h>
#include <hvm/params.h>
#include <hvm/hvm_op.h>

#include <evtchn_public.h>
#include <xenbus_public.h>
#include <xen_public.h>
#include <gnttbl_public.h>

//{C828ABE9-14CA-4445-BAA6-82C2376C6518}
DEFINE_GUID( GUID_XENPCI_DEVCLASS, 0xC828ABE9, 0x14CA, 0x4445, 0xBA, 0xA6, 0x82, 0xC2, 0x37, 0x6C, 0x65, 0x18);

#define __DRIVER_NAME "XenPCI"
#define XENPCI_POOL_TAG (ULONG) 'XenP'
//#define XENPCI_FDO_INSTANCE_SIGNATURE (ULONG) 'XENP'

#define NR_RESERVED_ENTRIES 8
#define NR_GRANT_FRAMES 4
#define NR_GRANT_ENTRIES (NR_GRANT_FRAMES * PAGE_SIZE / sizeof(grant_entry_t))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef struct _XENPCI_IDENTIFICATION_DESCRIPTION
{
  WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER Header;
  UNICODE_STRING DeviceType;
  char Path[128];
} XENPCI_IDENTIFICATION_DESCRIPTION, *PXENPCI_IDENTIFICATION_DESCRIPTION;

typedef struct _ev_action_t {
  PKSERVICE_ROUTINE ServiceRoutine;
  PVOID ServiceContext;
  BOOLEAN DpcFlag;
  WDFDPC Dpc;
  ULONG Count;
} ev_action_t;

typedef struct {
  ev_action_t *Action;
} EVTCHN_DEVICE_DATA, *PEVTCHN_DEVICE_DATA;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(EVTCHN_DEVICE_DATA, GetEvtChnDeviceData);

typedef struct _XENBUS_WATCH_RING
{
  char Path[128];
  char Token[10];
} XENBUS_WATCH_RING;

typedef struct _XENBUS_REQ_INFO
{
  int In_Use:1;
  KEVENT WaitEvent;
  void *Reply;
} XENBUS_REQ_INFO;

typedef struct _XENBUS_WATCH_ENTRY {
  char Path[128];
  PXENBUS_WATCH_CALLBACK ServiceRoutine;
  PVOID ServiceContext;
  int Count;
  int Active;
} XENBUS_WATCH_ENTRY, *PXENBUS_WATCH_ENTRY;

#define NR_EVENTS 1024
#define WATCH_RING_SIZE 128
#define NR_XB_REQS 32
#define MAX_WATCH_ENTRIES 128

// TODO: tidy up & organize this struct
typedef struct {

  WDFDEVICE Device;
  BOOLEAN XenBus_ShuttingDown;

  WDFINTERRUPT XenInterrupt;
  ULONG irqNumber;

  shared_info_t *shared_info_area;

  PHYSICAL_ADDRESS platform_mmio_addr;
  ULONG platform_mmio_orig_len;
  ULONG platform_mmio_len;
  ULONG platform_mmio_alloc;

  char *hypercall_stubs;

  evtchn_port_t xen_store_evtchn;

  grant_entry_t *gnttab_table;
  PHYSICAL_ADDRESS gnttab_table_physical;
  grant_ref_t gnttab_list[NR_GRANT_ENTRIES];

  ev_action_t ev_actions[NR_EVENTS];
  unsigned long bound_ports[NR_EVENTS/(8*sizeof(unsigned long))];

  HANDLE XenBus_ReadThreadHandle;
  KEVENT XenBus_ReadThreadEvent;
  HANDLE XenBus_WatchThreadHandle;
  KEVENT XenBus_WatchThreadEvent;

  XENBUS_WATCH_RING XenBus_WatchRing[WATCH_RING_SIZE];
  int XenBus_WatchRingReadIndex;
  int XenBus_WatchRingWriteIndex;

  struct xenstore_domain_interface *xen_store_interface;

  XENBUS_REQ_INFO req_info[NR_XB_REQS];
  int nr_live_reqs;
  XENBUS_WATCH_ENTRY XenBus_WatchEntries[MAX_WATCH_ENTRIES];

} XENPCI_DEVICE_DATA, *PXENPCI_DEVICE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(XENPCI_DEVICE_DATA, GetDeviceData);

typedef unsigned long xenbus_transaction_t;
typedef uint32_t XENSTORE_RING_IDX;

#define XBT_NIL ((xenbus_transaction_t)0)

char *
XenBus_Read(PVOID Context, xenbus_transaction_t xbt, const char *path, char **value);
char *
XenBus_Write(PVOID Context, xenbus_transaction_t xbt, const char *path, const char *value);
char *
XenBus_Printf(PVOID Context, xenbus_transaction_t xbt, const char *path, const char *fmt, ...);
char *
XenBus_StartTransaction(PVOID Context, xenbus_transaction_t *xbt);
char *
XenBus_EndTransaction(PVOID Context, xenbus_transaction_t t, int abort, int *retry);
char *
XenBus_List(PVOID Context, xenbus_transaction_t xbt, const char *prefix, char ***contents);
NTSTATUS
XenBus_Init(WDFDEVICE Device);
NTSTATUS
XenBus_Close(WDFDEVICE Device);
NTSTATUS
XenBus_Start(WDFDEVICE Device);
NTSTATUS
XenBus_Stop(WDFDEVICE Device);
char *
XenBus_AddWatch(PVOID Context, xenbus_transaction_t xbt, const char *Path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext);
char *
XenBus_RemWatch(PVOID Context, xenbus_transaction_t xbt, const char *Path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext);
VOID
XenBus_ThreadProc(PVOID StartContext);

PHYSICAL_ADDRESS
XenPCI_AllocMMIO(WDFDEVICE Device, ULONG len);

NTSTATUS
EvtChn_Init(WDFDEVICE Device);
BOOLEAN
EvtChn_Interrupt(WDFINTERRUPT Interrupt, ULONG MessageID);
VOID
EvtChn_InterruptDpc(WDFINTERRUPT Interrupt, WDFOBJECT AssociatedObject);
NTSTATUS
EvtChn_Mask(PVOID Context, evtchn_port_t Port);
NTSTATUS
EvtChn_Unmask(PVOID Context, evtchn_port_t Port);
NTSTATUS
EvtChn_Bind(PVOID Context, evtchn_port_t Port, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext);
NTSTATUS
EvtChn_BindDpc(PVOID Context, evtchn_port_t Port, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext);
NTSTATUS
EvtChn_Unbind(PVOID Context, evtchn_port_t Port);
NTSTATUS
EvtChn_Notify(PVOID Context, evtchn_port_t Port);
evtchn_port_t
EvtChn_AllocUnbound(PVOID Context, domid_t Domain);
evtchn_port_t
EvtChn_GetXenStorePort(WDFDEVICE Device);
PVOID
EvtChn_GetXenStoreRingAddr(WDFDEVICE Device);

VOID
GntTbl_Init(WDFDEVICE Device);
grant_ref_t
GntTbl_GrantAccess(WDFDEVICE Device, domid_t domid, unsigned long frame, int readonly);
BOOLEAN
GntTbl_EndAccess(WDFDEVICE Device, grant_ref_t ref);

#endif
