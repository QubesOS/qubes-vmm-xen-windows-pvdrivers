#if !defined(_XENENUM_H_)
#define _XENENUM_H_

#include <ntddk.h>
#include <wdm.h>
#include <wdf.h>
#include <initguid.h>
#include <ntdddisk.h>

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#define __DRIVER_NAME "XenEnum"
#include <xen_windows.h>
#include <memory.h>
#include <grant_table.h>
#include <event_channel.h>
#include <hvm/params.h>
#include <hvm/hvm_op.h>
#include <xen_public.h>
#include <io/ring.h>
#include <io/blkif.h>
#define XENENUM_POOL_TAG (ULONG) 'XENM'

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BLK_RING_SIZE __RING_SIZE((blkif_sring_t *)0, PAGE_SIZE)

/*
struct
{
  LIST_ENTRY Entry;
  char Path[128];
  char BackendPath[128];
  ULONG DeviceIndex;
} typedef XENENUM_CHILD_DEVICE_DATA, *PXENENUM_CHILD_DEVICE_DATA, **PPXENENUM_CHILD_DEVICE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(PXENENUM_CHILD_DEVICE_DATA, GetChildDeviceData);

typedef struct _XENENUM_DEVICE_IDENTIFICATION_DESCRIPTION
{
  WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER Header;
  UNICODE_STRING DeviceType;
  ULONG DeviceIndex;
  char Path[128];
} XENENUM_DEVICE_IDENTIFICATION_DESCRIPTION, *PXENENUM_DEVICE_IDENTIFICATION_DESCRIPTION;
*/

#endif
