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

#if !defined(_XENBUS_PUBLIC_H_)
#define _XENBUS_PUBLIC_H_

DEFINE_GUID( GUID_XEN_IFACE_XENBUS, 0x9CA4D816, 0x0E5E, 0x4f9a, 0x8F, 0x59, 0x94, 0x4C, 0xED, 0x82, 0x78, 0x11);
//{9CA4D816-0E5E-4f9a-8F59-944CED827811}

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

typedef struct _XEN_IFACE_XENBUS {
  INTERFACE InterfaceHeader;

  PXEN_XENBUS_READ Read;
  PXEN_XENBUS_WRITE Write;
  PXEN_XENBUS_PRINTF Printf;
  PXEN_XENBUS_STARTTRANSACTION StartTransaction;
  PXEN_XENBUS_ENDTRANSACTION EndTransaction;
  PXEN_XENBUS_LIST List;
  PXEN_XENBUS_ADDWATCH AddWatch;
  PXEN_XENBUS_REMWATCH RemWatch;
} XEN_IFACE_XENBUS, *PXEN_IFACE_XENBUS;

#endif