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

#if !defined(_XENHIDE_H_)
#define _XENHIDE_H_

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

#define __DRIVER_NAME "XenHide"

#include <xen_windows.h>

#include <memory.h>
#include <grant_table.h>
#include <event_channel.h>
#include <hvm/params.h>
#include <hvm/hvm_op.h>

//{C828ABE9-14CA-4445-BAA6-82C2376C6518}
//DEFINE_GUID( GUID_XENPCI_DEVCLASS, 0xC828ABE9, 0x14CA, 0x4445, 0xBA, 0xA6, 0x82, 0xC2, 0x37, 0x6C, 0x65, 0x18);

#define XENHIDE_POOL_TAG (ULONG) 'XenH'
//#define XENHIDE_FDO_INSTANCE_SIGNATURE (ULONG) 'XENP'

#define NR_RESERVED_ENTRIES 8
#define NR_GRANT_FRAMES 4
#define NR_GRANT_ENTRIES (NR_GRANT_FRAMES * PAGE_SIZE / sizeof(grant_entry_t))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

extern char *hypercall_stubs;

typedef struct _XENHIDE_IDENTIFICATION_DESCRIPTION
{
  WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER Header;
  UNICODE_STRING DeviceType;
//  ULONG DeviceIndex;
  char Path[128];
} XENHIDE_IDENTIFICATION_DESCRIPTION, *PXENHIDE_IDENTIFICATION_DESCRIPTION;


typedef struct {
  WDFQUEUE          IoDefaultQueue;

  // Resources
  //WDFINTERRUPT      Interrupt;
  //PULONG            PhysAddress;

  //ULONG platform_mmio_addr;
  //ULONG platform_mmio_len;
  //ULONG platform_mmio_alloc;

  //ULONG shared_info_frame;
  //char *hypercall_stubs;

  //PULONG            IoBaseAddress;
  //ULONG             IoRange;

  // Grant Table stuff

  //grant_entry_t *gnttab_table;
  //grant_ref_t gnttab_list[NR_GRANT_ENTRIES];

} XENHIDE_DEVICE_DATA, *PXENHIDE_DEVICE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(XENHIDE_DEVICE_DATA, GetDeviceData);

typedef unsigned long xenbus_transaction_t;
typedef uint32_t XENSTORE_RING_IDX;

#define XBT_NIL ((xenbus_transaction_t)0)

#endif
