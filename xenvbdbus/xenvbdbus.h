#if !defined(_XENVBDBUS_H_)
#define _XENVBDBUS_H_

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
#include <gnttbl_public.h>
#include <xenbus_public.h>
#include <io/ring.h>
#include <io/blkif.h>
#define __DRIVER_NAME "XenVbdBus"
#define XENVBDBUS_POOL_TAG (ULONG) 'XVBD'

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BLK_RING_SIZE __RING_SIZE((blkif_sring_t *)0, PAGE_SIZE)

extern XEN_IFACE_EVTCHN EvtChnInterface;
extern XEN_IFACE_XENBUS XenBusInterface;

#include "..\xenvbddev\scsidata.h"

struct
{
  LIST_ENTRY Entry;
  char Path[128];
  char BackendPath[128];
  ULONG DeviceIndex;
  evtchn_port_t EventChannel;
  PMDL SharedRingMDL;
//  ULONG BytesPerSector;
//  ULONGLONG TotalSectors;
  PMDL ScsiDeviceDataMdl;
  PXENVBDDEV_SCSI_DATA ScsiDeviceData;
/*
  KSPIN_LOCK Lock;
  WDFQUEUE IoDefaultQueue;
  WDFDEVICE Device;
*/

//  int TmpCount;
/*
  int BackendState;
  int FrontendState;
*/
  
/*
  blkif_shadow_t *shadow;
  uint64_t shadow_free;

  LIST_ENTRY IrpListHead;
  KSPIN_LOCK IrpListLock;

  WDFDPC Dpc;
*/
/*
  DISK_GEOMETRY Geometry;
*/
/*
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
*/
} typedef XENVBDBUS_CHILD_DEVICE_DATA, *PXENVBDBUS_CHILD_DEVICE_DATA, **PPXENVBDBUS_CHILD_DEVICE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(PXENVBDBUS_CHILD_DEVICE_DATA, GetChildDeviceData);

typedef struct _XENVBDBUS_DEVICE_IDENTIFICATION_DESCRIPTION
{
  WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER Header;
  PXENVBDBUS_CHILD_DEVICE_DATA DeviceData;
  //ULONG DeviceIndex;
  //char Path[128];
} XENVBDBUS_DEVICE_IDENTIFICATION_DESCRIPTION, *PXENVBDBUS_DEVICE_IDENTIFICATION_DESCRIPTION;

#endif
