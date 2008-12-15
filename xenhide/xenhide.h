/*PV Drivers for Windows Xen HVM Domains
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

#if !defined(_XENHIDE_H_)
#define _XENHIDE_H_

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <initguid.h>
#include <wdmguid.h>
#include <errno.h>

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#define __DRIVER_NAME "XenHide"

#include <xen_windows.h>
#include <xen_guids.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define XENHIDE_POOL_TAG (ULONG) 'XHID'

//{CD433FE7-954F-4D51-BE29-D8A38DFA1108}
//DEFINE_GUID(GUID_XENHIDE_IFACE, 0xCD433FE7, 0x954F, 0x4D51, 0xBE, 0x29, 0xD8, 0xA3, 0x8D, 0xFA, 0x11, 0x08);

#define XENHIDE_TYPE_NONE 0
#define XENHIDE_TYPE_DEVICE 1
#define XENHIDE_TYPE_PCI_BUS 2

typedef struct {
  PDEVICE_OBJECT filter_do;
  PDEVICE_OBJECT pdo;
  PDEVICE_OBJECT lower_do;
  IO_REMOVE_LOCK RemoveLock;
  USHORT hide_type;
} XENHIDE_DEVICE_DATA, *PXENHIDE_DEVICE_DATA;

#endif
