#if !defined(_XENVBDDEV_H_)
#define _XENVBDDEV_H_

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <wdf.h>
#include <initguid.h>
#include <ntdddisk.h>
#include <srb.h>

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#include <xen_windows.h>
#include <memory.h>
#include <grant_table.h>
#include <event_channel.h>
#include <hvm/params.h>
#include <hvm/hvm_op.h>
#include <evtchn_public.h>
#include <xenbus_public.h>
#include <gnttbl_public.h>
#include <io/ring.h>
#include <io/blkif.h>
#define __DRIVER_NAME "XenVbdDev"
#define XENVBDDEV_POOL_TAG (ULONG) 'XVBD'

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BLK_RING_SIZE __RING_SIZE((blkif_sring_t *)0, PAGE_SIZE)

typedef struct {
  blkif_request_t req;
  PSCSI_REQUEST_BLOCK Srb;
  PMDL Mdl;
  VOID *Buf;
} blkif_shadow_t;

#include "scsidata.h"

struct
{
  PXENVBDDEV_SCSI_DATA ScsiData;

  PEPROCESS Process;

  KSPIN_LOCK Lock;

  blkif_shadow_t *shadow;
  uint64_t shadow_free;

  int FastPathUsed;
  int SlowPathUsed;
} typedef XENVBDDEV_DEVICE_DATA, *PXENVBDDEV_DEVICE_DATA;

/*
struct {
  LIST_ENTRY Entry;
//  KSPIN_LOCK Lock;
//  WDFQUEUE IoDefaultQueue;
  WDFDEVICE Device;
  char Path[128];
  char BackendPath[128];
  ULONG DeviceIndex;
  evtchn_port_t EventChannel;
  //blkif_sring_t *SharedRing;
  ULONG RingBufPFN;
  int BackendState;
  int FrontendState;
  blkif_front_ring_t Ring;
  blkif_shadow_t *shadow;
  uint64_t shadow_free;

  LIST_ENTRY IrpListHead;
  KSPIN_LOCK IrpListLock;

  WDFDPC Dpc;

//  ULONG BytesPerSector;
//  ULONGLONG TotalSectors;
  DISK_GEOMETRY Geometry;
  XENVBD_DEVICETYPE DeviceType;

  int IrpAddedToList;
  int IrpRemovedFromList;
  int IrpAddedToRing;
  int IrpAddedToRingAtLastNotify;
  int IrpAddedToRingAtLastInterrupt;
  int IrpAddedToRingAtLastDpc;
  int IrpRemovedFromRing;
  int IrpCompleted;

  int FastPathUsed;
  int SlowPathUsed;

} typedef XENVBD_CHILD_DEVICE_DATA, *PXENVBD_CHILD_DEVICE_DATA, **PPXENVBD_CHILD_DEVICE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(PXENVBD_CHILD_DEVICE_DATA, GetChildDeviceData);

typedef struct _XENVBD_DEVICE_IDENTIFICATION_DESCRIPTION
{
  WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER Header;
  PXENVBD_CHILD_DEVICE_DATA DeviceData;
} XENVBD_DEVICE_IDENTIFICATION_DESCRIPTION, *PXENVBD_DEVICE_IDENTIFICATION_DESCRIPTION;
*/

#endif
