#if !defined(_XENBUS_H_)
#define _XENBUS_H_

#include <ntddk.h>
#include <wdm.h>
#include <wdf.h>
#include <initguid.h>
#include <ntdddisk.h>

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
#include <io/ring.h>
#include <io/blkif.h>
#define __DRIVER_NAME "XenVbd"
#define XENVBD_POOL_TAG (ULONG) 'XenP'

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BLK_RING_SIZE __RING_SIZE((blkif_sring_t *)0, PAGE_SIZE)

typedef struct {
  blkif_request_t req;
  //int Id;
  PIRP Irp;
  PMDL Mdl;
  VOID *Buf;
  //int nr_segments;
  //unsigned long gref[BLKIF_MAX_SEGMENTS_PER_REQUEST];
} blkif_shadow_t;

typedef struct {
  LIST_ENTRY Entry;
  PIRP Irp;
} XenVbd_ListEntry;

/*
typedef struct _XENVBD_QUEUE_DATA {
    XENVBD_CHILD_DEVICE_DATA DeviceData;
} XENVBD_QUEUE_DATA, *PXENVBD_QUEUE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(XENVBD_QUEUE_DATA, GetQueueData)
*/

//typedef unsigned long xenbus_transaction_t;
//typedef uint32_t XENSTORE_RING_IDX;

extern XEN_IFACE_EVTCHN EvtChnInterface;
extern XEN_IFACE_XENBUS XenBusInterface;

typedef enum {
  XENVBD_DEVICETYPE_UNKNOWN,
  XENVBD_DEVICETYPE_DISK,
  XENVBD_DEVICETYPE_CDROM
} XENVBD_DEVICETYPE;

typedef struct _XENVBD_CHILD_DEVICE_DATA {
  LIST_ENTRY Entry;
  KSPIN_LOCK Lock;
  WDFQUEUE IoDefaultQueue;
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

  ULONG BytesPerSector;
  ULONGLONG TotalSectors;
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

} XENVBD_CHILD_DEVICE_DATA, *PXENVBD_CHILD_DEVICE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(PXENVBD_CHILD_DEVICE_DATA, GetChildDeviceData);

typedef struct _XENVBD_DEVICE_IDENTIFICATION_DESCRIPTION
{
  WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER Header;
  PXENVBD_CHILD_DEVICE_DATA DeviceData;
  //ULONG DeviceIndex;
  //char Path[128];
} XENVBD_DEVICE_IDENTIFICATION_DESCRIPTION, *PXENVBD_DEVICE_IDENTIFICATION_DESCRIPTION;

#endif
