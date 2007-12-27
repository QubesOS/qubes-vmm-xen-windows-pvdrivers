#if !defined(_XENVBD_H_)
#define _XENVBD_H_

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <wdf.h>
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
  BOOLEAN PendingInterrupt;
  PVOID DeviceData; // how can we create a forward definition for this???
  evtchn_port_t EventChannel;
  //blkif_sring_t *SharedRing;
  blkif_shadow_t *shadow;
  uint64_t shadow_free;
  ULONG RingBufPFN;
  int BackendState;
  int FrontendState;
  char Path[128];
  int DeviceIndex;
  char BackendPath[128];
  blkif_front_ring_t Ring;
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
  PXENPCI_XEN_DEVICE_DATA XenDeviceData;
  XENVBD_BUS_DATA BusData[SCSI_BUSES];

  KSPIN_LOCK Lock;

  int BusChangePending;

  int EnumeratedDevices;
  KEVENT WaitDevicesEvent;

} typedef XENVBD_DEVICE_DATA, *PXENVBD_DEVICE_DATA;

#endif
