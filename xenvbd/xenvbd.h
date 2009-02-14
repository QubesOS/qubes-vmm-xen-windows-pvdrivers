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

#ifdef __MINGW32__
#include <ntddk.h>
#include "../mingw/mingw_extras.h"

#else
#define DDKAPI

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <initguid.h>
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#endif

#include <ntdddisk.h>
#include <srb.h>

#define __DRIVER_NAME "XenVbd"

#include <xen_windows.h>
#include <memory.h>
//#include <grant_table.h>
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
  PSCSI_REQUEST_BLOCK srb;
} blkif_shadow_t;

#define MAX_SHADOW_ENTRIES 64
#define SHADOW_ENTRIES min(MAX_SHADOW_ENTRIES, min(BLK_RING_SIZE, BLK_OTHER_RING_SIZE))

typedef enum {
  XENVBD_DEVICETYPE_UNKNOWN,
  XENVBD_DEVICETYPE_DISK,
  XENVBD_DEVICETYPE_CDROM,
  XENVBD_DEVICETYPE_CONTROLLER // Not yet used
} XENVBD_DEVICETYPE;

typedef enum {
  XENVBD_DEVICEMODE_UNKNOWN,
  XENVBD_DEVICEMODE_READ,
  XENVBD_DEVICEMODE_WRITE
} XENVBD_DEVICEMODE;

struct
{
  BOOLEAN inactive;
  
  blkif_shadow_t shadows[MAX_SHADOW_ENTRIES];
  USHORT shadow_free_list[MAX_SHADOW_ENTRIES];
  USHORT shadow_free;
  USHORT shadow_min_free;

  PUCHAR device_base;

  blkif_sring_t *sring;
  evtchn_port_t event_channel;
  ULONG *event_channel_ptr;
  union {
    blkif_front_ring_t ring;
    blkif_other_front_ring_t other_ring;
  };
  int ring_detect_state;
  BOOLEAN use_other;
  BOOLEAN cached_use_other;
  UCHAR last_sense_key;
  UCHAR last_additional_sense_code;
  blkif_response_t tmp_rep;
  XENVBD_DEVICETYPE device_type;
  XENVBD_DEVICEMODE device_mode;
  DISK_GEOMETRY Geometry;
  ULONG bytes_per_sector;
  ULONGLONG total_sectors;
  XENPCI_VECTORS vectors;
  PXENPCI_DEVICE_STATE device_state;
  PSCSI_REQUEST_BLOCK pending_srb;
  grant_ref_t dump_grant_ref;
/*  
  ULONGLONG interrupts;
  ULONGLONG aligned_requests;
  ULONGLONG aligned_bytes;
  ULONGLONG unaligned_requests;
  ULONGLONG unaligned_bytes;
*/
} typedef XENVBD_DEVICE_DATA, *PXENVBD_DEVICE_DATA;

#endif

