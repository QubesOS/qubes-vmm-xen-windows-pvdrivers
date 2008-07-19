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

static __inline ULONGLONG
hvm_get_parameter(PXENPCI_DEVICE_DATA xpdd, int hvm_param)
{
  struct xen_hvm_param a;
  int retval;

  FUNCTION_ENTER();
  a.domid = DOMID_SELF;
  a.index = hvm_param;
  //a.value = via;
  retval = HYPERVISOR_hvm_op(xpdd, HVMOP_get_param, &a);
  KdPrint((__DRIVER_NAME " HYPERVISOR_hvm_op retval = %d\n", retval));
  FUNCTION_EXIT();
  return a.value;
}

static __inline ULONGLONG
hvm_set_parameter(PXENPCI_DEVICE_DATA xpdd, int hvm_param, ULONGLONG value)
{
  struct xen_hvm_param a;
  int retval;

  FUNCTION_ENTER();
  a.domid = DOMID_SELF;
  a.index = hvm_param;
  a.value = value;
  //a.value = via;
  retval = HYPERVISOR_hvm_op(xpdd, HVMOP_set_param, &a);
  KdPrint((__DRIVER_NAME " HYPERVISOR_hvm_op retval = %d\n", retval));
  FUNCTION_EXIT();
  return retval;
}

static __inline int
hvm_shutdown(PXENPCI_DEVICE_DATA xpdd, unsigned int reason)
{
  struct sched_shutdown ss;
  int retval;

  FUNCTION_ENTER();
  ss.reason = reason;
  retval = HYPERVISOR_sched_op(xpdd, SCHEDOP_shutdown, &ss);
  FUNCTION_EXIT();
  return retval;
}

static __inline VOID
HYPERVISOR_yield(PXENPCI_DEVICE_DATA xpdd)
{
  HYPERVISOR_sched_op(xpdd, SCHEDOP_yield, NULL);
}
