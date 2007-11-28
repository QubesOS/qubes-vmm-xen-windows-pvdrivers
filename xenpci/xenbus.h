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

#if !defined(_XENBUS_H_)
#define _XENBUS_H_

#include <ntddk.h>
#include <wdm.h>
#include <wdf.h>
#include <initguid.h>

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#define __XEN_INTERFACE_VERSION__ 0x00030205
#define __i386__
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef SHORT int16_t;
typedef USHORT uint16_t;
typedef LONG int32_t;
typedef ULONG uint32_t;
typedef ULONGLONG uint64_t;
typedef unsigned long pgentry_t;

#define _PAGE_PRESENT  0x001UL
#define _PAGE_RW       0x002UL
#define _PAGE_USER     0x004UL
#define _PAGE_PWT      0x008UL
#define _PAGE_PCD      0x010UL
#define _PAGE_ACCESSED 0x020UL
#define _PAGE_DIRTY    0x040UL
#define _PAGE_PAT      0x080UL
#define _PAGE_PSE      0x080UL
#define _PAGE_GLOBAL   0x100UL

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)

#include <xen.h>
#include <event_channel.h>
#include <hvm/params.h>
#include <hvm/hvm_op.h>
#include <evtchn_public.h>
#include <evtchn_store_public.h>

//{C828ABE9-14CA-4445-BAA6-82C2376C6518}
DEFINE_GUID( GUID_XENBUS_DEVCLASS, 0xC828ABE9, 0x14CA, 0x4445, 0xBA, 0xA6, 0x82, 0xC2, 0x37, 0x6C, 0x65, 0x18);

#define __DRIVER_NAME "XenBus"
#define XENBUS_POOL_TAG (ULONG) 'XenP'

#define NR_RESERVED_ENTRIES 8
#define NR_GRANT_FRAMES 4
#define NR_GRANT_ENTRIES (NR_GRANT_FRAMES * PAGE_SIZE / sizeof(grant_entry_t))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef struct _XENBUS_IDENTIFICATION_DESCRIPTION
{
  WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER Header;
  UNICODE_STRING DeviceType;
  ULONG DeviceIndex;
} XENBUS_IDENTIFICATION_DESCRIPTION, *PXENBUS_IDENTIFICATION_DESCRIPTION;


typedef struct {
  WDFQUEUE          IoDefaultQueue;
  WDFINTERRUPT      Interrupt;
  PULONG            IoBaseAddress;
  ULONG             IoRange;
} XENBUS_DEVICE_DATA, *PXENBUS_DEVICE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(XENBUS_DEVICE_DATA, GetDeviceData);


void
grant_table_init();

typedef unsigned long xenbus_transaction_t;
typedef uint32_t XENSTORE_RING_IDX;

/*
enum xsd_sockmsg_type
{
    XS_DEBUG,
    XS_DIRECTORY,
    XS_READ,
    XS_GET_PERMS,
    XS_WATCH,
    XS_UNWATCH,
    XS_TRANSACTION_START,
    XS_TRANSACTION_END,
    XS_INTRODUCE,
    XS_RELEASE,
    XS_GET_DOMAIN_PATH,
    XS_WRITE,
    XS_MKDIR,
    XS_RM,
    XS_SET_PERMS,
    XS_WATCH_EVENT,
    XS_ERROR,
    XS_IS_DOMAIN_INTRODUCED,
    XS_RESUME
};

struct xsd_sockmsg
{
    uint32_t type;  /* XS_??? */
    uint32_t req_id;/* Request identifier, echoed in daemon's response.  */
    uint32_t tx_id; /* Transaction id (0 if not related to a transaction). */
    uint32_t len;   /* Length of data following this. */

    /* Generally followed by nul-terminated string(s). */
};
*/

#define XBT_NIL ((xenbus_transaction_t)0)
char *
XenBus_Read(PVOID Context, xenbus_transaction_t xbt, const char *path, char **value);
char *
XenBus_Write(PVOID Context, xenbus_transaction_t xbt, const char *path, const char *value);
char *
XenBus_StartTransaction(PVOID Context, xenbus_transaction_t *xbt);
char *
XenBus_EndTransaction(PVOID Context, xenbus_transaction_t t, int abort, int *retry);


char *
xenbus_watch_path(xenbus_transaction_t xbt, const char *path);
void
wait_for_watch(void);
char *
xenbus_wait_for_value(const char*,const char*);

char *
xenbus_rm(xenbus_transaction_t xbt, const char *path);
char *
xenbus_ls(xenbus_transaction_t xbt, const char *prefix, char ***contents);
char *
xenbus_get_perms(xenbus_transaction_t xbt, const char *path, char **value);
char *
xenbus_set_perms(xenbus_transaction_t xbt, const char *path, domid_t dom, char perm);
char *
xenbus_transaction_start(xenbus_transaction_t *xbt);
char *
xenbus_transaction_end(xenbus_transaction_t, int abort, int *retry);
int
xenbus_read_integer(char *path);
void
xenbus_irq();

NTSTATUS
XenBus_Init();
NTSTATUS
XenBus_Close();

PVOID
map_frames(PULONG f, ULONG n);

//extern XEN_IFACE_EVTCHN EvtchnInterface;
//extern XEN_IFACE_EVTCHN_STORE EvtchnStoreInterface;


/*
void
do_ls_test(const char *pre);
*/

void
XenBus_ThreadProc(PVOID StartContext);

#endif