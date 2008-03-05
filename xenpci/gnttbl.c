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
GntTbl_PutRef(WDFDEVICE Device, grant_ref_t ref)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
  KIRQL OldIrql;

  KeAcquireSpinLock(&xpdd->grant_lock, &OldIrql);
  xpdd->gnttab_list[ref] = xpdd->gnttab_list[0];
  xpdd->gnttab_list[0]  = ref;
  KeReleaseSpinLock(&xpdd->grant_lock, OldIrql);
}

grant_ref_t
GntTbl_GetRef(WDFDEVICE Device)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
  unsigned int ref;
  KIRQL OldIrql;

  KeAcquireSpinLock(&xpdd->grant_lock, &OldIrql);
  ref = xpdd->gnttab_list[0];
  xpdd->gnttab_list[0] = xpdd->gnttab_list[ref];
  KeReleaseSpinLock(&xpdd->grant_lock, OldIrql);

  return ref;
}

static int 
GntTbl_Map(WDFDEVICE Device, unsigned int start_idx, unsigned int end_idx)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
  struct xen_add_to_physmap xatp;
  unsigned int i = end_idx;

  //KdPrint((__DRIVER_NAME " --> GntTbl_Init\n"));
  /* Loop backwards, so that the first hypercall has the largest index,
   * ensuring that the table will grow only once.
   */
  do {
    xatp.domid = DOMID_SELF;
    xatp.idx = i;
    xatp.space = XENMAPSPACE_grant_table;
    xatp.gpfn = (xen_pfn_t)(xpdd->gnttab_table_physical.QuadPart >> PAGE_SHIFT) + i;
    if (HYPERVISOR_memory_op(Device, XENMEM_add_to_physmap, &xatp))
    {
      KdPrint((__DRIVER_NAME "     ***ERROR MAPPING FRAME***\n"));
    }
  } while (i-- > start_idx);

  return 0;
}

VOID
GntTbl_Init(WDFDEVICE Device)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
  int i;

  //KdPrint((__DRIVER_NAME " --> GntTbl_Init\n"));

  
  KeInitializeSpinLock(&xpdd->grant_lock);

  for (i = NR_RESERVED_ENTRIES; i < NR_GRANT_ENTRIES; i++)
    GntTbl_PutRef(Device, i);

  xpdd->gnttab_table_physical = XenPCI_AllocMMIO(Device,
    PAGE_SIZE * NR_GRANT_FRAMES);
  xpdd->gnttab_table = MmMapIoSpace(xpdd->gnttab_table_physical,
    PAGE_SIZE * NR_GRANT_FRAMES, MmNonCached);
  if (!xpdd->gnttab_table)
  {
    KdPrint((__DRIVER_NAME "     Error Mapping Grant Table Shared Memory\n"));
    return;
  }
  GntTbl_Map(Device, 0, NR_GRANT_FRAMES - 1);

  //KdPrint((__DRIVER_NAME " <-- GntTbl_Init table mapped at %p\n", gnttab_table));
}

grant_ref_t
GntTbl_GrantAccess(
  WDFDEVICE Device,
  domid_t domid,
  uint32_t frame,
  int readonly,
  grant_ref_t ref)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);

  //KdPrint((__DRIVER_NAME " --> GntTbl_GrantAccess\n"));

  //KdPrint((__DRIVER_NAME "     Granting access to frame %08x\n", frame));

  if (ref == 0)
    ref = GntTbl_GetRef(Device);
  xpdd->gnttab_table[ref].frame = frame;
  xpdd->gnttab_table[ref].domid = domid;
  KeMemoryBarrier();
  readonly *= GTF_readonly;
  xpdd->gnttab_table[ref].flags = GTF_permit_access | (uint16_t)readonly;

  //KdPrint((__DRIVER_NAME " <-- GntTbl_GrantAccess (ref = %d)\n", ref));

  return ref;
}

BOOLEAN
GntTbl_EndAccess(
  WDFDEVICE Device,
  grant_ref_t ref,
  BOOLEAN keepref)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
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
    GntTbl_PutRef(Device, ref);
  //KdPrint((__DRIVER_NAME " <-- GntTbl_EndAccess\n"));
  return TRUE;
}
