#include "xenpci.h"

/* must be called at <= DISPATCH_LEVEL if hypercall_stubs == NULL */

NTSTATUS
hvm_get_stubs(PXENPCI_DEVICE_DATA xpdd)
{
  DWORD32 cpuid_output[4];
  char xensig[13];
  ULONG i;
  ULONG pages;
  ULONG msr;  

  __cpuid(cpuid_output, 0x40000000);
  *(ULONG*)(xensig + 0) = cpuid_output[1];
  *(ULONG*)(xensig + 4) = cpuid_output[2];
  *(ULONG*)(xensig + 8) = cpuid_output[3];
  xensig[12] = '\0';
  KdPrint((__DRIVER_NAME "     Xen Signature = %s, EAX = 0x%08x\n", xensig, cpuid_output[0]));

  __cpuid(cpuid_output, 0x40000002);
  pages = cpuid_output[0];
  msr = cpuid_output[1];

  if (!xpdd->hypercall_stubs)
  {
    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
    xpdd->hypercall_stubs = ExAllocatePoolWithTag(NonPagedPool, pages * PAGE_SIZE, XENPCI_POOL_TAG);
  }
  KdPrint((__DRIVER_NAME "     Hypercall area at %p\n", xpdd->hypercall_stubs));

  if (!xpdd->hypercall_stubs)
    return 1;
  for (i = 0; i < pages; i++) {
    ULONGLONG pfn;
    pfn = (MmGetPhysicalAddress(xpdd->hypercall_stubs + i * PAGE_SIZE).QuadPart >> PAGE_SHIFT);
    KdPrint((__DRIVER_NAME "     pfn = %16lX\n", pfn));
    __writemsr(msr, (pfn << PAGE_SHIFT) + i);
  }
  return STATUS_SUCCESS;
}

NTSTATUS
hvm_free_stubs(PXENPCI_DEVICE_DATA xpdd)
{
  ExFreePoolWithTag(xpdd->hypercall_stubs, XENPCI_POOL_TAG);

  return STATUS_SUCCESS;
}
