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

#ifdef __MINGW32__
#include "../mingw/mingw_extras.h"
#else
#define DDKAPI
#include <wdm.h>
//#include <wdf.h>
#include <initguid.h>
#include <wdmguid.h>
#include <errno.h>
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#endif

#define __DRIVER_NAME "XenPCI"

#include <xen_windows.h>
#include <memory.h>
#include <grant_table.h>
#include <event_channel.h>
#include <hvm/params.h>
#include <hvm/hvm_op.h>
#include <sched.h>
#include <io/xenbus.h>

#include <xen_public.h>

//{C828ABE9-14CA-4445-BAA6-82C2376C6518}
DEFINE_GUID( GUID_XENPCI_DEVCLASS, 0xC828ABE9, 0x14CA, 0x4445, 0xBA, 0xA6, 0x82, 0xC2, 0x37, 0x6C, 0x65, 0x18);

#define XENPCI_POOL_TAG (ULONG) 'XenP'

#define NR_RESERVED_ENTRIES 8
#define NR_GRANT_FRAMES 32
#define NR_GRANT_ENTRIES (NR_GRANT_FRAMES * PAGE_SIZE / sizeof(grant_entry_t))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define EVT_ACTION_TYPE_EMPTY  0
#define EVT_ACTION_TYPE_NORMAL 1
#define EVT_ACTION_TYPE_DPC    2
#define EVT_ACTION_TYPE_IRQ    3

typedef struct _ev_action_t {
  PKSERVICE_ROUTINE ServiceRoutine;
  PVOID ServiceContext;
  ULONG type; /* EVT_ACTION_TYPE_* */
  KDPC Dpc;
  ULONG vector;
  ULONG Count;
  PVOID xpdd;
} ev_action_t;

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
  int RemovePending;
  int Running;
  KEVENT CompleteEvent;
} XENBUS_WATCH_ENTRY, *PXENBUS_WATCH_ENTRY;

#define NR_EVENTS 1024
#define WATCH_RING_SIZE 128
#define NR_XB_REQS 32
#define MAX_WATCH_ENTRIES 128

#define CHILD_STATE_EMPTY 0
#define CHILD_STATE_DELETED 1
#define CHILD_STATE_ADDED 2

// TODO: tidy up & organize this struct

typedef enum {
    Unknown = 0,
    NotStarted,
    Started,
    StopPending,
    Stopped,
    RemovePending,
    SurpriseRemovePending,
    Removed
} DEVICE_PNP_STATE;

typedef struct
{
  PDEVICE_OBJECT fdo;
  PDEVICE_OBJECT pdo;
  PDEVICE_OBJECT lower_do;
  
  DEVICE_PNP_STATE current_pnp_state;
  DEVICE_PNP_STATE previous_pnp_state;
  DEVICE_POWER_STATE device_power_state;
  SYSTEM_POWER_STATE system_power_state;
  
  ULONG device_usage_paging;
  ULONG device_usage_dump;
  ULONG device_usage_hibernation;
} XENPCI_COMMON, *PXENPCI_COMMON;

static __inline void INIT_PNP_STATE(PXENPCI_COMMON common)
{
  common->current_pnp_state = NotStarted;
  common->previous_pnp_state = NotStarted;
}

static __inline void SET_PNP_STATE(PXENPCI_COMMON common, DEVICE_PNP_STATE state)
{
  common->previous_pnp_state = common->current_pnp_state;
  common->current_pnp_state = state;
}

static __inline void REVERT_PNP_STATE(PXENPCI_COMMON common)
{
  common->current_pnp_state = common->previous_pnp_state;
}

#define SHUTDOWN_RING_SIZE 128

#define SUSPEND_STATE_NONE      0 /* no suspend in progress */
#define SUSPEND_STATE_SCHEDULED 1 /* suspend scheduled */
#define SUSPEND_STATE_HIGH_IRQL 2 /* all processors are at high IRQL and spinning */
#define SUSPEND_STATE_RESUMING  3

typedef struct {  
  XENPCI_COMMON common;
  
  BOOLEAN XenBus_ShuttingDown;

  PKINTERRUPT interrupt;
  ULONG irq_number;
  ULONG irq_vector;
  KIRQL irq_level;
  KAFFINITY irq_affinity;

  PHYSICAL_ADDRESS shared_info_area_unmapped;
  shared_info_t *shared_info_area;

  PHYSICAL_ADDRESS platform_mmio_addr;
  ULONG platform_mmio_orig_len;
  ULONG platform_mmio_len;
  ULONG platform_mmio_alloc;
  USHORT platform_mmio_flags;

  char *hypercall_stubs;

  evtchn_port_t xen_store_evtchn;

  grant_entry_t *gnttab_table;
  PHYSICAL_ADDRESS gnttab_table_physical;
  grant_ref_t *gnttab_list;
  /* this is the maximum number of grant frames we have memory allocated for */
  /* after a resume it may not be the actual number of grant frames we have though */
  ULONG max_grant_frames;

  ev_action_t ev_actions[NR_EVENTS];
//  unsigned long bound_ports[NR_EVENTS/(8*sizeof(unsigned long))];

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

  KSPIN_LOCK WatchLock;
  KSPIN_LOCK grant_lock;

  //KGUARDED_MUTEX WatchHandlerMutex;

  LIST_ENTRY child_list;
  
  int suspend_state;
  
  UNICODE_STRING interface_name;
  BOOLEAN interface_open;
  
  KSPIN_LOCK shutdown_ring_lock;
  CHAR shutdown_ring[SHUTDOWN_RING_SIZE];
  ULONG shutdown_prod;
  ULONG shutdown_cons;
  ULONG shutdown_start; /* the start of the most recent message on the ring */
  PIRP shutdown_irp;
} XENPCI_DEVICE_DATA, *PXENPCI_DEVICE_DATA;

typedef struct {  
  XENPCI_COMMON common;
  PDEVICE_OBJECT bus_pdo;
  PDEVICE_OBJECT bus_fdo;
  BOOLEAN eject_requested;
  BOOLEAN reported_missing;
  char path[128];
  char device[128];
  ULONG index;
  ULONG irq_vector;
  KIRQL irq_level;
  char backend_path[128];
  //PVOID xenbus_request;
  KEVENT backend_state_event;
  ULONG backend_state;
  PHYSICAL_ADDRESS config_page_phys;
  ULONG config_page_length;
  PUCHAR requested_resources_start;
  PUCHAR requested_resources_ptr;
  PUCHAR assigned_resources_start;
  PUCHAR assigned_resources_ptr;
  XENPCI_DEVICE_STATE device_state;
} XENPCI_PDO_DEVICE_DATA, *PXENPCI_PDO_DEVICE_DATA;

typedef struct
{
  LIST_ENTRY entry;
  int state;
  PXENPCI_PDO_DEVICE_DATA context;
} XEN_CHILD, *PXEN_CHILD;

#ifdef __GNUC__
#define SWINT(x) if (intno == x) { asm ("int $"#x";"); return;}
#else
#define SWINT(x) if (intno == x) { __asm { int x } return; }
#endif

#if defined(_X86_)
static __inline VOID
sw_interrupt(UCHAR intno)
{
  //KdPrint((__DRIVER_NAME "     Calling interrupt %02X\n", intno));
  SWINT(0x10) SWINT(0x11) SWINT(0x12) SWINT(0x13) SWINT(0x14) SWINT(0x15) SWINT(0x16) SWINT(0x17)
  SWINT(0x18) SWINT(0x19) SWINT(0x1A) SWINT(0x1B) SWINT(0x1C) SWINT(0x1D) SWINT(0x1E) SWINT(0x1F)
  SWINT(0x20) SWINT(0x21) SWINT(0x22) SWINT(0x23) SWINT(0x24) SWINT(0x25) SWINT(0x26) SWINT(0x27)
  SWINT(0x28) SWINT(0x29) SWINT(0x2A) SWINT(0x2B) SWINT(0x2C) SWINT(0x2D) SWINT(0x2E) SWINT(0x2F)
  SWINT(0x30) SWINT(0x31) SWINT(0x32) SWINT(0x33) SWINT(0x34) SWINT(0x35) SWINT(0x36) SWINT(0x37)
  SWINT(0x38) SWINT(0x39) SWINT(0x3A) SWINT(0x3B) SWINT(0x3C) SWINT(0x3D) SWINT(0x3E) SWINT(0x3F)
  SWINT(0x40) SWINT(0x41) SWINT(0x42) SWINT(0x43) SWINT(0x44) SWINT(0x45) SWINT(0x46) SWINT(0x47)
  SWINT(0x48) SWINT(0x49) SWINT(0x4A) SWINT(0x4B) SWINT(0x4C) SWINT(0x4D) SWINT(0x4E) SWINT(0x4F)
  SWINT(0x50) SWINT(0x51) SWINT(0x52) SWINT(0x53) SWINT(0x54) SWINT(0x55) SWINT(0x56) SWINT(0x57)
  SWINT(0x58) SWINT(0x59) SWINT(0x5A) SWINT(0x5B) SWINT(0x5C) SWINT(0x5D) SWINT(0x5E) SWINT(0x5F)
  SWINT(0x60) SWINT(0x61) SWINT(0x62) SWINT(0x63) SWINT(0x64) SWINT(0x65) SWINT(0x66) SWINT(0x67)
  SWINT(0x68) SWINT(0x69) SWINT(0x6A) SWINT(0x6B) SWINT(0x6C) SWINT(0x6D) SWINT(0x6E) SWINT(0x6F)
  SWINT(0x70) SWINT(0x71) SWINT(0x72) SWINT(0x73) SWINT(0x74) SWINT(0x75) SWINT(0x76) SWINT(0x77)
  SWINT(0x78) SWINT(0x79) SWINT(0x7A) SWINT(0x7B) SWINT(0x7C) SWINT(0x7D) SWINT(0x7E) SWINT(0x7F)
  SWINT(0x80) SWINT(0x81) SWINT(0x82) SWINT(0x83) SWINT(0x84) SWINT(0x85) SWINT(0x86) SWINT(0x87)
  SWINT(0x88) SWINT(0x89) SWINT(0x8A) SWINT(0x8B) SWINT(0x8C) SWINT(0x8D) SWINT(0x8E) SWINT(0x8F)
  SWINT(0x90) SWINT(0x91) SWINT(0x92) SWINT(0x93) SWINT(0x94) SWINT(0x95) SWINT(0x96) SWINT(0x97)
  SWINT(0x98) SWINT(0x99) SWINT(0x9A) SWINT(0x9B) SWINT(0x9C) SWINT(0x9D) SWINT(0x9E) SWINT(0x9F)
  SWINT(0xA0) SWINT(0xA1) SWINT(0xA2) SWINT(0xA3) SWINT(0xA4) SWINT(0xA5) SWINT(0xA6) SWINT(0xA7)
  SWINT(0xA8) SWINT(0xA9) SWINT(0xAA) SWINT(0xAB) SWINT(0xAC) SWINT(0xAD) SWINT(0xAE) SWINT(0xAF)
  SWINT(0xB0) SWINT(0xB1) SWINT(0xB2) SWINT(0xB3) SWINT(0xB4) SWINT(0xB5) SWINT(0xB6) SWINT(0xB7)
  SWINT(0xB8) SWINT(0xB9) SWINT(0xBA) SWINT(0xBB) SWINT(0xBC) SWINT(0xBD) SWINT(0xBE) SWINT(0xBF)
  SWINT(0xC0) SWINT(0xC1) SWINT(0xC2) SWINT(0xC3) SWINT(0xC4) SWINT(0xC5) SWINT(0xC6) SWINT(0xC7)
  SWINT(0xC8) SWINT(0xC9) SWINT(0xCA) SWINT(0xCB) SWINT(0xCC) SWINT(0xCD) SWINT(0xCE) SWINT(0xCF)
  SWINT(0xD0) SWINT(0xD1) SWINT(0xD2) SWINT(0xD3) SWINT(0xD4) SWINT(0xD5) SWINT(0xD6) SWINT(0xD7)
  SWINT(0xD8) SWINT(0xD9) SWINT(0xDA) SWINT(0xDB) SWINT(0xDC) SWINT(0xDD) SWINT(0xDE) SWINT(0xDF)
  SWINT(0xE0) SWINT(0xE1) SWINT(0xE2) SWINT(0xE3) SWINT(0xE4) SWINT(0xE5) SWINT(0xE6) SWINT(0xE7)
  SWINT(0xE8) SWINT(0xE9) SWINT(0xEA) SWINT(0xEB) SWINT(0xEC) SWINT(0xED) SWINT(0xEE) SWINT(0xEF)
  SWINT(0xF0) SWINT(0xF1) SWINT(0xF2) SWINT(0xF3) SWINT(0xF4) SWINT(0xF5) SWINT(0xF6) SWINT(0xF7)
  SWINT(0xF8) SWINT(0xF9) SWINT(0xFA) SWINT(0xFB) SWINT(0xFC) SWINT(0xFD) SWINT(0xFE) SWINT(0xFF)

  /* not found */
  KdPrint((__DRIVER_NAME "     interrupt %02X not set up. Blame James.\n", intno));
  KeBugCheckEx(('X' << 16)|('E' << 8)|('N'), 0x00000002, (ULONG)intno, 0x00000000, 0x00000000);
}
#else
VOID _sw_interrupt(UCHAR);

static __inline VOID
sw_interrupt(UCHAR intno)
{
  _sw_interrupt(intno);
}
#endif

  
#include "hypercall.h"

#define XBT_NIL ((xenbus_transaction_t)0)

static __inline VOID
XenPci_FreeMem(PVOID Ptr)
{
  ExFreePoolWithTag(Ptr, XENPCI_POOL_TAG);
}

NTSTATUS
hvm_get_stubs(PXENPCI_DEVICE_DATA xpdd);
NTSTATUS
hvm_free_stubs(PXENPCI_DEVICE_DATA xpdd);

NTSTATUS
XenPci_Power_Fdo(PDEVICE_OBJECT device_object, PIRP irp);
NTSTATUS
XenPci_Dummy_Fdo(PDEVICE_OBJECT device_object, PIRP irp);
NTSTATUS
XenPci_Pnp_Fdo(PDEVICE_OBJECT device_object, PIRP irp);
NTSTATUS
XenPci_Irp_Create_Fdo(PDEVICE_OBJECT device_object, PIRP irp);
NTSTATUS
XenPci_Irp_Close_Fdo(PDEVICE_OBJECT device_object, PIRP irp);
NTSTATUS
XenPci_Irp_Read_Fdo(PDEVICE_OBJECT device_object, PIRP irp);
NTSTATUS
XenPci_Irp_Cleanup_Fdo(PDEVICE_OBJECT device_object, PIRP irp);

NTSTATUS
XenPci_Power_Pdo(PDEVICE_OBJECT device_object, PIRP irp);
//NTSTATUS
//XenPci_Dummy_Pdo(PDEVICE_OBJECT device_object, PIRP irp);
NTSTATUS
XenPci_Pnp_Pdo(PDEVICE_OBJECT device_object, PIRP irp);
NTSTATUS
XenPci_Irp_Create_Pdo(PDEVICE_OBJECT device_object, PIRP irp);
NTSTATUS
XenPci_Irp_Close_Pdo(PDEVICE_OBJECT device_object, PIRP irp);
NTSTATUS
XenPci_Irp_Read_Pdo(PDEVICE_OBJECT device_object, PIRP irp);
NTSTATUS
XenPci_Irp_Cleanup_Pdo(PDEVICE_OBJECT device_object, PIRP irp);

NTSTATUS
XenPci_Resume(PDEVICE_OBJECT device_object);

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
char *
XenBus_AddWatch(PVOID Context, xenbus_transaction_t xbt, const char *Path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext);
char *
XenBus_RemWatch(PVOID Context, xenbus_transaction_t xbt, const char *Path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext);
//VOID
//XenBus_ThreadProc(PVOID StartContext);
NTSTATUS
XenBus_Init(PXENPCI_DEVICE_DATA xpdd);
NTSTATUS
XenBus_Close(PXENPCI_DEVICE_DATA xpdd);
NTSTATUS
XenBus_Start(PXENPCI_DEVICE_DATA xpdd);
NTSTATUS
XenBus_Stop(PXENPCI_DEVICE_DATA xpdd);
VOID
XenBus_Resume(PXENPCI_DEVICE_DATA xpdd);

PHYSICAL_ADDRESS
XenPci_AllocMMIO(PXENPCI_DEVICE_DATA xpdd, ULONG len);

NTSTATUS
EvtChn_Init(PXENPCI_DEVICE_DATA xpdd);
NTSTATUS
EvtChn_ConnectInterrupt(PXENPCI_DEVICE_DATA xpdd);
/*
VOID
EvtChn_Resume(PXENPCI_DEVICE_DATA xpdd);
*/
NTSTATUS
EvtChn_Shutdown(PXENPCI_DEVICE_DATA xpdd);

NTSTATUS
EvtChn_Mask(PVOID Context, evtchn_port_t Port);
NTSTATUS
EvtChn_Unmask(PVOID Context, evtchn_port_t Port);
NTSTATUS
EvtChn_Bind(PVOID Context, evtchn_port_t Port, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext);
NTSTATUS
EvtChn_BindDpc(PVOID Context, evtchn_port_t Port, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext);
NTSTATUS
EvtChn_BindIrq(PVOID Context, evtchn_port_t Port, ULONG vector);
NTSTATUS
EvtChn_Unbind(PVOID Context, evtchn_port_t Port);
NTSTATUS
EvtChn_Notify(PVOID Context, evtchn_port_t Port);
evtchn_port_t
EvtChn_AllocUnbound(PVOID Context, domid_t Domain);

VOID
GntTbl_Init(PXENPCI_DEVICE_DATA xpdd);
VOID
GntTbl_InitMap(PXENPCI_DEVICE_DATA xpdd);
grant_ref_t
GntTbl_GrantAccess(PVOID Context, domid_t domid, uint32_t, int readonly, grant_ref_t ref);
BOOLEAN
GntTbl_EndAccess(PVOID Context, grant_ref_t ref, BOOLEAN keepref);
VOID
GntTbl_PutRef(PVOID Context, grant_ref_t ref);
grant_ref_t
GntTbl_GetRef(PVOID Context);
int 
GntTbl_Map(PVOID Context, unsigned int start_idx, unsigned int end_idx);
#endif
