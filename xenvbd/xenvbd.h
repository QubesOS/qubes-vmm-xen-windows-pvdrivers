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

#if !defined(_XENVBD_H_)
#define _XENVBD_H_

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <initguid.h>
#include <ntdddisk.h>
#include <srb.h>

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#define __DRIVER_NAME "XenVbd"

#include <xen_windows.h>
#include <memory.h>
#include <grant_table.h>
#include <event_channel.h>
#include <hvm/params.h>
#include <hvm/hvm_op.h>
#include <xen_public.h>
#include <io/ring.h>
#include <io/blkif.h>

#define XENVBD_POOL_TAG (ULONG) 'XVBD'

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BLK_RING_SIZE __RING_SIZE((blkif_sring_t *)0, PAGE_SIZE)
#define BLK_OTHER_RING_SIZE __RING_SIZE((blkif_other_sring_t *)0, PAGE_SIZE)

#if defined(__x86_64__)
#pragma pack(push, 4)
#endif
struct blkif_other_request {
  uint8_t operation;
  uint8_t nr_segments;
  blkif_vdev_t handle;
  uint64_t id;
  blkif_sector_t sector_number;
  struct blkif_request_segment seg[BLKIF_MAX_SEGMENTS_PER_REQUEST];
};
struct blkif_other_response {
  uint64_t id;
  uint8_t operation;
  int16_t status;
};
#if defined(__x86_64__)
#pragma pack(pop)
#endif

typedef struct blkif_other_request blkif_other_request_t;
typedef struct blkif_other_response blkif_other_response_t;
DEFINE_RING_TYPES(blkif_other, struct blkif_other_request, struct blkif_other_response);

typedef struct {
  blkif_request_t req;
  PSCSI_REQUEST_BLOCK Srb;
/*
  PMDL Mdl;
  VOID *Buf;
*/
} blkif_shadow_t;

#define SHADOW_ENTRIES 32
#define GRANT_ENTRIES 128

typedef enum {
  XENVBD_DEVICETYPE_UNKNOWN,
  XENVBD_DEVICETYPE_DISK,
  XENVBD_DEVICETYPE_CDROM,
  XENVBD_DEVICETYPE_CONTROLLER // Not yet used
} XENVBD_DEVICETYPE;

struct
{
  blkif_shadow_t shadows[SHADOW_ENTRIES];
  USHORT shadow_free_list[SHADOW_ENTRIES];
  USHORT shadow_free;

  grant_entry_t grants[GRANT_ENTRIES];
  USHORT grant_free_list[GRANT_ENTRIES];
  USHORT grant_free;

  evtchn_port_t event_channel;
  union {
    blkif_front_ring_t ring;
    blkif_other_front_ring_t other_ring;
  };
  int ring_detect_state;
  BOOLEAN use_other;
  blkif_response_t tmp_rep;
  XENVBD_DEVICETYPE device_type;
  DISK_GEOMETRY Geometry;
  ULONG bytes_per_sector;
  ULONGLONG total_sectors;
  XENPCI_VECTORS vectors;
} typedef XENVBD_DEVICE_DATA, *PXENVBD_DEVICE_DATA;

VOID
XenVbd_FillInitCallbacks(PHW_INITIALIZATION_DATA HwInitializationData);

#endif