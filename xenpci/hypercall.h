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

#if defined(_X86_)
  #if defined(__MINGW32__)
    #include "hypercall_x86_mingw.h"
  #else
    #include "hypercall_x86.h"
  #endif
#else
  #if defined(_AMD64_)
    #include "hypercall_amd64.h"
  #endif
#endif

static NTSTATUS
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
  KdPrint((__DRIVER_NAME " Xen Signature = %s, EAX = 0x%08x\n", xensig, cpuid_output[0]));

  __cpuid(cpuid_output, 0x40000002);
  pages = cpuid_output[0];
  msr = cpuid_output[1];
  //KdPrint((__DRIVER_NAME " Hypercall area is %u pages.\n", pages));

  xpdd->hypercall_stubs = ExAllocatePoolWithTag(NonPagedPool, pages * PAGE_SIZE, XENPCI_POOL_TAG);
  KdPrint((__DRIVER_NAME " Hypercall area at %p\n", xpdd->hypercall_stubs));

  if (!xpdd->hypercall_stubs)
    return 1;
  for (i = 0; i < pages; i++) {
    ULONGLONG pfn;
    pfn = (MmGetPhysicalAddress(xpdd->hypercall_stubs + i * PAGE_SIZE).QuadPart >> PAGE_SHIFT);
    KdPrint((__DRIVER_NAME " pfn = %16lX\n", pfn));
    __writemsr(msr, (pfn << PAGE_SHIFT) + i);
  }
  return STATUS_SUCCESS;
}

static NTSTATUS
hvm_free_stubs(PXENPCI_DEVICE_DATA xpdd)
{
  ExFreePoolWithTag(xpdd->hypercall_stubs, XENPCI_POOL_TAG);

  return STATUS_SUCCESS;
}

static __inline ULONGLONG
hvm_get_parameter(PXENPCI_DEVICE_DATA xpdd, int hvm_param)
{
  struct xen_hvm_param a;
  int retval;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  a.domid = DOMID_SELF;
  a.index = hvm_param;
  //a.value = via;
  retval = HYPERVISOR_hvm_op(xpdd, HVMOP_get_param, &a);
  KdPrint((__DRIVER_NAME " HYPERVISOR_hvm_op retval = %d\n", retval));
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return a.value;
}

static __inline ULONGLONG
hvm_set_parameter(PXENPCI_DEVICE_DATA xpdd, int hvm_param, ULONGLONG value)
{
  struct xen_hvm_param a;
  int retval;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  a.domid = DOMID_SELF;
  a.index = hvm_param;
  a.value = value;
  //a.value = via;
  retval = HYPERVISOR_hvm_op(xpdd, HVMOP_set_param, &a);
  KdPrint((__DRIVER_NAME " HYPERVISOR_hvm_op retval = %d\n", retval));
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return retval;
}

static __inline int
hvm_shutdown(PXENPCI_DEVICE_DATA xpdd, unsigned int reason)
{
  struct sched_shutdown ss;
  int retval;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  ss.reason = reason;
  retval = HYPERVISOR_sched_op(xpdd, SCHEDOP_shutdown, &ss);
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return retval;
}
