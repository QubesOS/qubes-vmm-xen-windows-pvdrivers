#if !defined(_XENSCSI_H_)
#define _XENSCSI_H_

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <wdf.h>
#include <initguid.h>
#include <ntdddisk.h>
#include <srb.h>

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#define __DRIVER_NAME "XenSCSI"

#include <xen_windows.h>
#include <memory.h>
#include <grant_table.h>
#include <event_channel.h>
#include <hvm/params.h>
#include <hvm/hvm_op.h>
#include <xen_public.h>
#include <io/ring.h>
#include <io/vscsiif.h>

typedef struct vscsiif_request vscsiif_request_t;
typedef struct vscsiif_response vscsiif_response_t;

#define XENSCSI_POOL_TAG (ULONG) 'XSCS'

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define VSCSIIF_RING_SIZE __RING_SIZE((vscsiif_sring_t *)0, PAGE_SIZE)

typedef struct {
  vscsiif_request_t req;
  PSCSI_REQUEST_BLOCK Srb;
  PMDL Mdl;
  VOID *Buf;
} vscsiif_shadow_t;

//#include "scsidata.h"

#define SCSI_BUSES 4
#define SCSI_TARGETS_PER_BUS 16

struct
{
  int Present;
  BOOLEAN PendingInterrupt;
  PVOID DeviceData; // how can we create a forward definition for this???
  evtchn_port_t EventChannel;
  vscsiif_shadow_t *shadow;
  uint16_t shadow_free;
  ULONG RingBufPFN;
  int BackendState;
  int FrontendState;
  char Path[128];
  int DeviceIndex;
  char BackendPath[128];
  vscsiif_front_ring_t Ring;
  int ring_detect_state;
  int host;
  int channel;
  int id;
  int lun;
} typedef XENSCSI_TARGET_DATA, *PXENSCSI_TARGET_DATA;

struct
{
  XENSCSI_TARGET_DATA TargetData[SCSI_TARGETS_PER_BUS];
} typedef XENSCSI_BUS_DATA, *PXENSCSI_BUS_DATA;

struct
{
  PXENPCI_XEN_DEVICE_DATA XenDeviceData;
  XENSCSI_BUS_DATA BusData[SCSI_BUSES];

  KSPIN_LOCK Lock;

  int BusChangePending;

  LONG EnumeratedDevices;
  int TotalInitialDevices;
} typedef XENSCSI_DEVICE_DATA, *PXENSCSI_DEVICE_DATA;

enum dma_data_direction {
        DMA_BIDIRECTIONAL = 0,
        DMA_TO_DEVICE = 1,
        DMA_FROM_DEVICE = 2,
        DMA_NONE = 3,
};

#endif
