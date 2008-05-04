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
  PMDL Mdl;
  VOID *Buf;
} blkif_shadow_t;

//#include "scsidata.h"


#define SCSI_BUSES 4
#define SCSI_TARGETS_PER_BUS 16

typedef enum {
  XENVBD_DEVICETYPE_UNKNOWN,
  XENVBD_DEVICETYPE_DISK,
  XENVBD_DEVICETYPE_CDROM,
  XENVBD_DEVICETYPE_CONTROLLER // Not yet used
} XENVBD_DEVICETYPE;

struct
{
  int Present;
  int Running;
  BOOLEAN PendingInterrupt;
  PVOID DeviceData; // how can we create a forward definition for this???
  evtchn_port_t EventChannel;
  blkif_shadow_t *shadow;
  uint64_t shadow_free;
  ULONG RingBufPFN;
  int BackendState;
  int FrontendState;
  char Path[128];
  int DeviceIndex;
  char BackendPath[128];
  union {
    blkif_front_ring_t Ring;
    blkif_other_front_ring_t OtherRing;
  };
  int ring_detect_state;
  BOOLEAN use_other;
  blkif_response_t tmp_rep;
  XENVBD_DEVICETYPE DeviceType;
  DISK_GEOMETRY Geometry;
  ULONG BytesPerSector;
  ULONGLONG TotalSectors; 
} typedef XENVBD_TARGET_DATA, *PXENVBD_TARGET_DATA;

struct
{
  XENVBD_TARGET_DATA TargetData[SCSI_TARGETS_PER_BUS];
} typedef XENVBD_BUS_DATA, *PXENVBD_BUS_DATA;

struct
{
//  PXENPCI_XEN_DEVICE_DATA XenDeviceData;
  XENVBD_BUS_DATA BusData[SCSI_BUSES];

  KSPIN_LOCK Lock;

  int BusChangePending;

  LONG EnumeratedDevices;
  int TotalInitialDevices;

  PVOID DeviceExtension;
} typedef XENVBD_DEVICE_DATA, *PXENVBD_DEVICE_DATA;

struct
{
  PXENVBD_DEVICE_DATA XenVbdDeviceData;  
} typedef XENVBD_DEVICE_EXTENSION, *PXENVBD_DEVICE_EXTENSION;

#endif
