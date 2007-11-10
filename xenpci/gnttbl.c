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
#include <hypercall.h>

static grant_entry_t *gnttab_table;
static PHYSICAL_ADDRESS gnttab_table_physical;
static grant_ref_t gnttab_list[NR_GRANT_ENTRIES];

static void
put_free_entry(grant_ref_t ref)
{
    gnttab_list[ref] = gnttab_list[0];
    gnttab_list[0]  = ref;

}

static grant_ref_t
get_free_entry()
{
    unsigned int ref = gnttab_list[0];
    gnttab_list[0] = gnttab_list[ref];
    return ref;
}

/*
struct grant_entry {
    uint16_t flags;
    domid_t  domid;
    uint32_t frame;
};
typedef struct grant_entry grant_entry_t;
*/

static int 
GntTab_Map(unsigned int start_idx, unsigned int end_idx)
{
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
    xatp.gpfn = (xen_pfn_t)(gnttab_table_physical.QuadPart >> PAGE_SHIFT) + i;
    if (HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp))
    {
      KdPrint((__DRIVER_NAME "     ***ERROR MAPPING FRAME***\n"));
    }
  } while (i-- > start_idx);

  return 0;
}

VOID
GntTbl_Init()
{
  int i;

  //KdPrint((__DRIVER_NAME " --> GntTbl_Init\n"));

  for (i = NR_RESERVED_ENTRIES; i < NR_GRANT_ENTRIES; i++)
    put_free_entry(i);

  gnttab_table_physical = XenPCI_AllocMMIO(PAGE_SIZE * NR_GRANT_FRAMES);
  gnttab_table = MmMapIoSpace(gnttab_table_physical, PAGE_SIZE * NR_GRANT_FRAMES, MmNonCached);
  if (gnttab_table == NULL)
  {
    KdPrint((__DRIVER_NAME "     Error Mapping Grant Table Shared Memory\n"));
    return;
  }
  GntTab_Map(0, NR_GRANT_FRAMES - 1);

  //KdPrint((__DRIVER_NAME " <-- GntTbl_Init table mapped at %p\n", gnttab_table));
}

grant_ref_t
GntTbl_GrantAccess(domid_t domid, unsigned long frame, int readonly)
{
  grant_ref_t ref;

  //KdPrint((__DRIVER_NAME " --> GntTbl_GrantAccess\n"));

  ref = get_free_entry();
  gnttab_table[ref].frame = frame;
  gnttab_table[ref].domid = domid;
  //_WriteBarrier();
  KeMemoryBarrier();
  readonly *= GTF_readonly;
  gnttab_table[ref].flags = GTF_permit_access | (uint16_t)readonly;

  //KdPrint((__DRIVER_NAME " <-- GntTbl_GrantAccess (ref = %d)\n", ref));

  return ref;
}

BOOLEAN
GntTbl_EndAccess(grant_ref_t ref)
{
  unsigned short flags, nflags;

  //KdPrint((__DRIVER_NAME " --> GntTbl_EndAccess\n"));

  nflags = gnttab_table[ref].flags;
  do {
    if ((flags = nflags) & (GTF_reading|GTF_writing))
    {
      KdPrint((__DRIVER_NAME "WARNING: g.e. still in use!\n"));
      return FALSE;
    }
  } while ((nflags = InterlockedCompareExchange16((volatile SHORT *)&gnttab_table[ref].flags, flags, 0)) != flags);

  put_free_entry(ref);
  //KdPrint((__DRIVER_NAME " <-- GntTbl_EndAccess\n"));
  return TRUE;
}
