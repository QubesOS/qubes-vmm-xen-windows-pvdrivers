#include "xenpci.h"
#include <hypercall.h>

static pgentry_t *demand_map_pgt;
static void *demand_map_area_start;

PVOID
map_frames(PULONG f, ULONG n)
{
  unsigned long x;
  unsigned long y = 0;
  mmu_update_t mmu_updates[16];
  int rc;
 
  for (x = 0; x <= 1024 - n; x += y + 1) {
    for (y = 0; y < n; y++)
      if (demand_map_pgt[x+y] & _PAGE_PRESENT)
        break;
    if (y == n)
      break;
  }
  if (y != n) {
      KdPrint((__DRIVER_NAME " Failed to map %ld frames!\n", n));
      return NULL;
  }

  for (y = 0; y < n; y++) {
    //mmu_updates[y].ptr = virt_to_mach(&demand_map_pgt[x + y]);
    mmu_updates[y].ptr = MmGetPhysicalAddress(&demand_map_pgt[x + y]).QuadPart;
    mmu_updates[y].val = (f[y] << PAGE_SHIFT) | L1_PROT;
  }

  rc = HYPERVISOR_mmu_update(mmu_updates, n, NULL, DOMID_SELF);
  if (rc < 0) {
    KdPrint((__DRIVER_NAME " Map %ld failed: %d.\n", n, rc));
    return NULL;
  } else {
    return (PVOID)(ULONG)((ULONG)demand_map_area_start + x * PAGE_SIZE);
  }
}
