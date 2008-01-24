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

#endif
