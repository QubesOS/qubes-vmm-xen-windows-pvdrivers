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

#include "xenpci.h"

VOID
GntTbl_PutRef(PVOID Context, grant_ref_t ref)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  KIRQL OldIrql = PASSIVE_LEVEL;

  if (xpdd->suspend_state != SUSPEND_STATE_HIGH_IRQL)
  {
    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
    KeAcquireSpinLock(&xpdd->grant_lock, &OldIrql);
  }
  xpdd->gnttab_list[ref] = xpdd->gnttab_list[0];
  xpdd->gnttab_list[0]  = ref;
  if (xpdd->suspend_state != SUSPEND_STATE_HIGH_IRQL)
  {
    KeReleaseSpinLock(&xpdd->grant_lock, OldIrql);
  }
}

grant_ref_t
GntTbl_GetRef(PVOID Context)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  unsigned int ref;
  KIRQL OldIrql = PASSIVE_LEVEL;
  
  UNREFERENCED_PARAMETER(OldIrql);

  if (xpdd->suspend_state != SUSPEND_STATE_HIGH_IRQL)
  {
    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
    KeAcquireSpinLock(&xpdd->grant_lock, &OldIrql);
  }
  ref = xpdd->gnttab_list[0];
  xpdd->gnttab_list[0] = xpdd->gnttab_list[ref];
  if (xpdd->suspend_state != SUSPEND_STATE_HIGH_IRQL)
  {
    KeReleaseSpinLock(&xpdd->grant_lock, OldIrql);
  }

  return ref;
}

int 
GntTbl_Map(PVOID Context, unsigned int start_idx, unsigned int end_idx)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  struct xen_add_to_physmap xatp;
  unsigned int i = end_idx;

  /* Loop backwards, so that the first hypercall has the largest index,  ensuring that the table will grow only once.  */
  do {
    xatp.domid = DOMID_SELF;
    xatp.idx = i;
    xatp.space = XENMAPSPACE_grant_table;
    xatp.gpfn = (xen_pfn_t)(xpdd->gnttab_table_physical.QuadPart >> PAGE_SHIFT) + i;
    if (HYPERVISOR_memory_op(xpdd, XENMEM_add_to_physmap, &xatp))
    {
      KdPrint((__DRIVER_NAME "     ***ERROR MAPPING FRAME***\n"));
    }
  } while (i-- > start_idx);

  return 0;
}

grant_ref_t
GntTbl_GrantAccess(
  PVOID Context,
  domid_t domid,
  uint32_t frame, // xen api limits pfn to 32bit, so no guests over 8TB
  int readonly,
  grant_ref_t ref)
{
  PXENPCI_DEVICE_DATA xpdd = Context;

  //KdPrint((__DRIVER_NAME " --> GntTbl_GrantAccess\n"));

  //KdPrint((__DRIVER_NAME "     Granting access to frame %08x\n", frame));

  if (ref == 0)
    ref = GntTbl_GetRef(Context);
  xpdd->gnttab_table[ref].frame = frame;
  xpdd->gnttab_table[ref].domid = domid;

  if (xpdd->gnttab_table[ref].flags)
    KdPrint((__DRIVER_NAME "     WARNING: Attempting to re-use grant entry that is already in use!\n"));

  KeMemoryBarrier();
  readonly *= GTF_readonly;
  xpdd->gnttab_table[ref].flags = GTF_permit_access | (uint16_t)readonly;

  //KdPrint((__DRIVER_NAME " <-- GntTbl_GrantAccess (ref = %d)\n", ref));

  return ref;
}

#ifdef __MINGW32__
/* from linux/include/asm-i386/cmpxchg.h */
static inline short InterlockedCompareExchange16(
  short volatile *dest,
  short exch,
  short comp)
{
  unsigned long prev;

  __asm__ __volatile__("lock;"
    "cmpxchgw %w1,%2"
    : "=a"(prev)
    : "r"(exch), "m"(*(dest)), "0"(comp)
    : "memory");

  KdPrint((__FUNC__ " Check that I work as expected!\n"));

  return prev;
}
#endif

BOOLEAN
GntTbl_EndAccess(
  PVOID Context,
  grant_ref_t ref,
  BOOLEAN keepref)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  unsigned short flags, nflags;

  //KdPrint((__DRIVER_NAME " --> GntTbl_EndAccess\n"));

  nflags = xpdd->gnttab_table[ref].flags;
  do {
    if ((flags = nflags) & (GTF_reading|GTF_writing))
    {
      KdPrint((__DRIVER_NAME "WARNING: g.e. still in use!\n"));
      return FALSE;
    }
  } while ((nflags = InterlockedCompareExchange16(
    (volatile SHORT *)&xpdd->gnttab_table[ref].flags, 0, flags)) != flags);

  if (!keepref)
    GntTbl_PutRef(Context, ref);
  //KdPrint((__DRIVER_NAME " <-- GntTbl_EndAccess\n"));
  return TRUE;
}

static unsigned int 
GntTbl_QueryMaxFrames(PXENPCI_DEVICE_DATA xpdd)
{
  struct gnttab_query_size query;
  int rc;

  query.dom = DOMID_SELF;

  rc = HYPERVISOR_grant_table_op(xpdd,GNTTABOP_query_size, &query, 1);
  if ((rc < 0) || (query.status != GNTST_okay))
  {
    KdPrint((__DRIVER_NAME "     ***CANNOT QUERY MAX GRANT FRAME***\n"));
    return 4; /* Legacy max supported number of frames */
  }
  return query.max_nr_frames;
}

VOID
GntTbl_InitMap(PXENPCI_DEVICE_DATA xpdd)
{
  int i;
  ULONG grant_frames;
  int grant_entries;
  //KdPrint((__DRIVER_NAME " --> GntTbl_Init\n"));

  grant_frames = GntTbl_QueryMaxFrames(xpdd);
  grant_entries = min(NR_GRANT_ENTRIES, (grant_frames * PAGE_SIZE / sizeof(grant_entry_t)));
  KdPrint((__DRIVER_NAME "     grant_entries : %d\n", grant_entries));

  if (xpdd->gnttab_list)
  {
    if (grant_frames > xpdd->max_grant_frames)
    {
      /* this won't actually work as it will be called at HIGH_IRQL and the free and unmap functions won't work... */
      ExFreePoolWithTag(xpdd->gnttab_list, XENPCI_POOL_TAG);
      MmUnmapIoSpace(xpdd->gnttab_table, PAGE_SIZE * xpdd->max_grant_frames);
      xpdd->gnttab_list = NULL;
    }
  }
  
  if (!xpdd->gnttab_list)
  {  
    xpdd->gnttab_list = ExAllocatePoolWithTag(NonPagedPool, sizeof(grant_ref_t) * grant_entries, XENPCI_POOL_TAG);
    xpdd->gnttab_table_physical = XenPci_AllocMMIO(xpdd,
      PAGE_SIZE * grant_frames);
    xpdd->gnttab_table = MmMapIoSpace(xpdd->gnttab_table_physical,
      PAGE_SIZE * grant_frames, MmNonCached);
    if (!xpdd->gnttab_table)
    {
      KdPrint((__DRIVER_NAME "     Error Mapping Grant Table Shared Memory\n"));
      // this should be a show stopper...
      return;
    }
    xpdd->max_grant_frames = grant_frames;
  }
  RtlZeroMemory(xpdd->gnttab_list, sizeof(grant_ref_t) * grant_entries);
  for (i = NR_RESERVED_ENTRIES; i < grant_entries; i++)
    GntTbl_PutRef(xpdd, i);
  
  GntTbl_Map(xpdd, 0, grant_frames - 1);
}

VOID
GntTbl_Init(PXENPCI_DEVICE_DATA xpdd)
{
  //KdPrint((__DRIVER_NAME " --> GntTbl_Init\n"));
  
  KeInitializeSpinLock(&xpdd->grant_lock);
  GntTbl_InitMap(xpdd);
  
  //KdPrint((__DRIVER_NAME " <-- GntTbl_Init table mapped at %p\n", gnttab_table));
}
