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

#if !defined(_XEN_PUBLIC_H_)
#define _XEN_PUBLIC_H_

//{5C568AC5-9DDF-4FA5-A94A-39D67077819C}
DEFINE_GUID(GUID_XEN_IFACE, 0x5C568AC5, 0x9DDF, 0x4FA5, 0xA9, 0x4A, 0x39, 0xD6, 0x70, 0x77, 0x81, 0x9C);

//{CD433FE7-954F-4D51-BE29-D8A38DFA1108}
DEFINE_GUID(GUID_XENHIDE_IFACE, 0xCD433FE7, 0x954F, 0x4D51, 0xBE, 0x29, 0xD8, 0xA3, 0x8D, 0xFA, 0x11, 0x08);

typedef PHYSICAL_ADDRESS
(*PXEN_ALLOCMMIO)(PVOID Context, ULONG Length);

typedef void
(*PXEN_FREEMEM)(PVOID Ptr);

typedef NTSTATUS
(*PXEN_EVTCHN_BIND)(PVOID Context, evtchn_port_t Port, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext);

typedef NTSTATUS
(*PXEN_EVTCHN_UNBIND)(PVOID Context, evtchn_port_t Port);

typedef NTSTATUS
(*PXEN_EVTCHN_MASK)(PVOID Context, evtchn_port_t Port);

typedef NTSTATUS
(*PXEN_EVTCHN_UNMASK)(PVOID Context, evtchn_port_t Port);

typedef NTSTATUS
(*PXEN_EVTCHN_NOTIFY)(PVOID Context, evtchn_port_t Port);

typedef evtchn_port_t
(*PXEN_EVTCHN_ALLOCUNBOUND)(PVOID Context, domid_t Domain);

typedef grant_ref_t
(*PXEN_GNTTBL_GRANTACCESS)(PVOID Context, domid_t domid, uint32_t frame, int readonly, grant_ref_t ref);

typedef BOOLEAN
(*PXEN_GNTTBL_ENDACCESS)(PVOID Context, grant_ref_t ref, BOOLEAN keepref);

typedef VOID
(*PXEN_GNTTBL_PUTREF)(PVOID Context, grant_ref_t ref);

typedef grant_ref_t
(*PXEN_GNTTBL_GETREF)(PVOID Context);


typedef VOID
(*PXENBUS_WATCH_CALLBACK)(char *Path, PVOID ServiceContext);

typedef char *
(*PXEN_XENBUS_READ)(PVOID Context, xenbus_transaction_t xbt, const char *path, char **value);

typedef char *
(*PXEN_XENBUS_WRITE)(PVOID Context, xenbus_transaction_t xbt, const char *path, const char *value);

typedef char *
(*PXEN_XENBUS_PRINTF)(PVOID Context, xenbus_transaction_t xbt, const char *path, const char *fmt, ...);

typedef char *
(*PXEN_XENBUS_STARTTRANSACTION)(PVOID Context, xenbus_transaction_t *xbt);

typedef char *
(*PXEN_XENBUS_ENDTRANSACTION)(PVOID Context, xenbus_transaction_t t, int abort, int *retry);

typedef char *
(*PXEN_XENBUS_LIST)(PVOID Context, xenbus_transaction_t xbt, const char *prefix, char ***contents);

typedef char *
(*PXEN_XENBUS_ADDWATCH)(PVOID Context, xenbus_transaction_t xbt, const char *Path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext);

typedef char *
(*PXEN_XENBUS_REMWATCH)(PVOID Context, xenbus_transaction_t xbt, const char *Path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext);

#if 0
typedef struct _XEN_IFACE {
  INTERFACE InterfaceHeader;

  PXEN_ALLOCMMIO AllocMMIO;
  PXEN_FREEMEM FreeMem;

  PXEN_EVTCHN_BIND EvtChn_Bind;
  PXEN_EVTCHN_UNBIND EvtChn_Unbind;
  PXEN_EVTCHN_MASK EvtChn_Mask;
  PXEN_EVTCHN_UNMASK EvtChn_Unmask;
  PXEN_EVTCHN_NOTIFY EvtChn_Notify;
  PXEN_EVTCHN_ALLOCUNBOUND EvtChn_AllocUnbound;
  PXEN_EVTCHN_BIND EvtChn_BindDpc;

  PXEN_GNTTBL_GETREF GntTbl_GetRef;
  PXEN_GNTTBL_PUTREF GntTbl_PutRef;
  PXEN_GNTTBL_GRANTACCESS GntTbl_GrantAccess;
  PXEN_GNTTBL_ENDACCESS GntTbl_EndAccess;

  PXEN_XENBUS_READ XenBus_Read;
  PXEN_XENBUS_WRITE XenBus_Write;
  PXEN_XENBUS_PRINTF XenBus_Printf;
  PXEN_XENBUS_STARTTRANSACTION XenBus_StartTransaction;
  PXEN_XENBUS_ENDTRANSACTION XenBus_EndTransaction;
  PXEN_XENBUS_LIST XenBus_List;
  PXEN_XENBUS_ADDWATCH XenBus_AddWatch;
  PXEN_XENBUS_REMWATCH XenBus_RemWatch;
} XEN_IFACE, *PXEN_IFACE;

typedef struct _XENPCI_IDENTIFICATION_DESCRIPTION
{
  WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER Header;
  char DeviceType[128]; //UNICODE_STRING DeviceType;
  char Path[128];
  ULONG DeviceIndex;
} XENPCI_IDENTIFICATION_DESCRIPTION, *PXENPCI_IDENTIFICATION_DESCRIPTION;
#endif


#define XEN_DATA_MAGIC 0x12345678

typedef struct {
  ULONG magic;
  USHORT length;

  PVOID context;
  PXEN_EVTCHN_BIND EvtChn_Bind;
  PXEN_EVTCHN_BIND EvtChn_BindDpc;
  PXEN_EVTCHN_UNBIND EvtChn_Unbind;
  PXEN_EVTCHN_MASK EvtChn_Mask;
  PXEN_EVTCHN_UNMASK EvtChn_Unmask;
  PXEN_EVTCHN_NOTIFY EvtChn_Notify;
  PXEN_GNTTBL_GETREF GntTbl_GetRef;
  PXEN_GNTTBL_PUTREF GntTbl_PutRef;
  PXEN_GNTTBL_GRANTACCESS GntTbl_GrantAccess;
  PXEN_GNTTBL_ENDACCESS GntTbl_EndAccess;
} XENPCI_VECTORS, *PXENPCI_VECTORS;


#define XEN_INIT_TYPE_END               0
#define XEN_INIT_TYPE_WRITE_STRING      1
#define XEN_INIT_TYPE_RING              2
#define XEN_INIT_TYPE_EVENT_CHANNEL     3
#define XEN_INIT_TYPE_EVENT_CHANNEL_IRQ 4
#define XEN_INIT_TYPE_READ_STRING_FRONT 5
#define XEN_INIT_TYPE_READ_STRING_BACK  6
#define XEN_INIT_TYPE_VECTORS           7
#define XEN_INIT_TYPE_GRANT_ENTRIES     8

static __inline VOID
__ADD_XEN_INIT_UCHAR(PUCHAR *ptr, UCHAR val)
{
//  KdPrint((__DRIVER_NAME "     ADD_XEN_INIT_UCHAR *ptr = %p, val = %d\n", *ptr, val));
  *(PUCHAR)(*ptr) = val;
  *ptr += sizeof(UCHAR);
}

static __inline VOID
__ADD_XEN_INIT_USHORT(PUCHAR *ptr, USHORT val)
{
//  KdPrint((__DRIVER_NAME "     ADD_XEN_INIT_USHORT *ptr = %p, val = %d\n", *ptr, val));
  *(PUSHORT)(*ptr) = val;
  *ptr += sizeof(USHORT);
}

static __inline VOID
__ADD_XEN_INIT_ULONG(PUCHAR *ptr, ULONG val)
{
//  KdPrint((__DRIVER_NAME "     ADD_XEN_INIT_ULONG *ptr = %p, val = %d\n", *ptr, val));
  *(PULONG)(*ptr) = val;
  *ptr += sizeof(ULONG);
}

static __inline VOID
__ADD_XEN_INIT_PTR(PUCHAR *ptr, PVOID val)
{
//  KdPrint((__DRIVER_NAME "     ADD_XEN_INIT_PTR *ptr = %p, val = %p\n", *ptr, val));
  *(PVOID *)(*ptr) = val;
  *ptr += sizeof(PVOID);
}

static __inline VOID
__ADD_XEN_INIT_STRING(PUCHAR *ptr, PCHAR val)
{
//  KdPrint((__DRIVER_NAME "     ADD_XEN_INIT_STRING *ptr = %p, val = %s\n", *ptr, val));
  RtlStringCbCopyA((PCHAR)*ptr, PAGE_SIZE - (PtrToUlong(*ptr) & (PAGE_SIZE - 1)), val);
  *ptr += strlen(val) + 1;
}

static __inline UCHAR
__GET_XEN_INIT_UCHAR(PUCHAR *ptr)
{
  UCHAR retval;
  retval = **ptr;
//  KdPrint((__DRIVER_NAME "     GET_XEN_INIT_UCHAR *ptr = %p, retval = %d\n", *ptr, retval));
  *ptr += sizeof(UCHAR);
  return retval;
}

static __inline USHORT
__GET_XEN_INIT_USHORT(PUCHAR *ptr)
{
  USHORT retval;
  retval = *(PUSHORT)*ptr;
//  KdPrint((__DRIVER_NAME "     GET_XEN_INIT_USHORT *ptr = %p, retval = %d\n", *ptr, retval));
  *ptr += sizeof(USHORT);
  return retval;
}

static __inline ULONG
__GET_XEN_INIT_ULONG(PUCHAR *ptr)
{
  ULONG retval;
  retval = *(PLONG)*ptr;
//  KdPrint((__DRIVER_NAME "     GET_XEN_INIT_ULONG *ptr = %p, retval = %d\n", *ptr, retval));
  *ptr += sizeof(ULONG);
  return retval;
}

static __inline PCHAR
__GET_XEN_INIT_STRING(PUCHAR *ptr)
{
  PCHAR retval;
  retval = (PCHAR)*ptr;
//  KdPrint((__DRIVER_NAME "     GET_XEN_INIT_STRING *ptr = %p, retval = %s\n", *ptr, retval));
  *ptr += strlen((PCHAR)*ptr) + 1;
  return retval;
}

static __inline PVOID
__GET_XEN_INIT_PTR(PUCHAR *ptr)
{
  PVOID retval;
  retval = *(PVOID *)(*ptr);
//  KdPrint((__DRIVER_NAME "     GET_XEN_INIT_PTR *ptr = %p, retval = %p\n", *ptr, retval));
  *ptr += sizeof(PVOID);
  return retval;
}

static __inline VOID
ADD_XEN_INIT_REQ(PUCHAR *ptr, UCHAR type, PVOID p1, PVOID p2)
{
  __ADD_XEN_INIT_UCHAR(ptr, type);
  switch (type)
  {
  case XEN_INIT_TYPE_END:
  case XEN_INIT_TYPE_VECTORS:
    break;
  case XEN_INIT_TYPE_WRITE_STRING:
    __ADD_XEN_INIT_STRING(ptr, p1);
    __ADD_XEN_INIT_STRING(ptr, p2);
    break;
  case XEN_INIT_TYPE_RING:
  case XEN_INIT_TYPE_EVENT_CHANNEL:
  case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ:
  case XEN_INIT_TYPE_READ_STRING_FRONT:
  case XEN_INIT_TYPE_READ_STRING_BACK:
    __ADD_XEN_INIT_STRING(ptr, p1);
    break;
  case XEN_INIT_TYPE_GRANT_ENTRIES:
    __ADD_XEN_INIT_ULONG(ptr, PtrToUlong(p1));
    break;
  }
}

static __inline UCHAR
GET_XEN_INIT_REQ(PUCHAR *ptr, PVOID *p1, PVOID *p2)
{
  UCHAR retval;

  retval = __GET_XEN_INIT_UCHAR(ptr);
  switch (retval)
  {
  case XEN_INIT_TYPE_END:
  case XEN_INIT_TYPE_VECTORS:
    *p1 = NULL;
    *p2 = NULL;
    break;
  case XEN_INIT_TYPE_WRITE_STRING:
    *p1 = __GET_XEN_INIT_STRING(ptr);
    *p2 = __GET_XEN_INIT_STRING(ptr);
    break;
  case XEN_INIT_TYPE_RING:
  case XEN_INIT_TYPE_EVENT_CHANNEL:
  case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ:
  case XEN_INIT_TYPE_READ_STRING_FRONT:
  case XEN_INIT_TYPE_READ_STRING_BACK:
    *p1 = __GET_XEN_INIT_STRING(ptr);
    *p2 = NULL;
    break;
  case XEN_INIT_TYPE_GRANT_ENTRIES:
    *p1 = UlongToPtr(__GET_XEN_INIT_ULONG(ptr));
    break;
  }
  return retval;
}

static __inline VOID
ADD_XEN_INIT_RSP(PUCHAR *ptr, UCHAR type, PVOID p1, PVOID p2)
{
  __ADD_XEN_INIT_UCHAR(ptr, type);
  switch (type)
  {
  case XEN_INIT_TYPE_END:
  case XEN_INIT_TYPE_WRITE_STRING: /* this shouldn't happen */
    break;
  case XEN_INIT_TYPE_RING:
    __ADD_XEN_INIT_STRING(ptr, p1);
    __ADD_XEN_INIT_PTR(ptr, p2);
    break;
  case XEN_INIT_TYPE_EVENT_CHANNEL:
  case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ:
    __ADD_XEN_INIT_STRING(ptr, p1);
    __ADD_XEN_INIT_ULONG(ptr, PtrToUlong(p2));
    break;
  case XEN_INIT_TYPE_READ_STRING_FRONT:
  case XEN_INIT_TYPE_READ_STRING_BACK:
    __ADD_XEN_INIT_STRING(ptr, p1);
    __ADD_XEN_INIT_STRING(ptr, p2);
    break;
  case XEN_INIT_TYPE_VECTORS:
    //__ADD_XEN_INIT_ULONG(ptr, PtrToUlong(p1));
    memcpy(*ptr, p2, sizeof(XENPCI_VECTORS));
    *ptr += sizeof(XENPCI_VECTORS);
    break;
  case XEN_INIT_TYPE_GRANT_ENTRIES:
    __ADD_XEN_INIT_ULONG(ptr, PtrToUlong(p1));
    memcpy(*ptr, p2, PtrToUlong(p1) * sizeof(grant_entry_t));
    *ptr += PtrToUlong(p1) * sizeof(grant_entry_t);
    break;
  }
}

static __inline UCHAR
GET_XEN_INIT_RSP(PUCHAR *ptr, PVOID *p1, PVOID *p2)
{
  UCHAR retval;

  retval = __GET_XEN_INIT_UCHAR(ptr);
  switch (retval)
  {
  case XEN_INIT_TYPE_END:
    *p1 = NULL;
    *p2 = NULL;
    break;
  case XEN_INIT_TYPE_WRITE_STRING:
    // this shouldn't happen - no response here
    break;
  case XEN_INIT_TYPE_RING:
    *p1 = __GET_XEN_INIT_STRING(ptr);
    *p2 = __GET_XEN_INIT_PTR(ptr);
    break;
  case XEN_INIT_TYPE_EVENT_CHANNEL:
  case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ:
    *p1 = __GET_XEN_INIT_STRING(ptr);
    *p2 = UlongToPtr(__GET_XEN_INIT_ULONG(ptr));
    break;
  case XEN_INIT_TYPE_READ_STRING_FRONT:
    *p1 = __GET_XEN_INIT_STRING(ptr);
    *p2 = __GET_XEN_INIT_STRING(ptr);
    break;
  case XEN_INIT_TYPE_READ_STRING_BACK:
    *p1 = __GET_XEN_INIT_STRING(ptr);
    *p2 = __GET_XEN_INIT_STRING(ptr);
    break;
  case XEN_INIT_TYPE_VECTORS:
    *p1 = NULL;
    *p2 = *ptr;
    *ptr += ((PXENPCI_VECTORS)*p2)->length;
    break;
  case XEN_INIT_TYPE_GRANT_ENTRIES:
    *p1 = UlongToPtr(__GET_XEN_INIT_ULONG(ptr));
    *p2 = *ptr;
    *ptr += PtrToUlong(*p1) * sizeof(grant_entry_t);
    break;
  }
  return retval;
}

#endif
