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

char *hypercall_stubs;

static __inline int
HYPERVISOR_memory_op(int cmd, void *arg)
{
  long __res;
  __asm {
    mov ebx, cmd
    mov ecx, arg
    mov eax, hypercall_stubs
    add eax, (__HYPERVISOR_memory_op * 32)
    call eax
    mov [__res], eax
  }
  return __res;
}

static __inline int
HYPERVISOR_xen_version(int cmd, void *arg)
{
  long __res;
  __asm {
    mov ebx, cmd
    mov ecx, arg
    mov eax, hypercall_stubs
    add eax, (__HYPERVISOR_xen_version * 32)
    call eax
    mov [__res], eax
  }
  return __res;
}

static __inline int
HYPERVISOR_grant_table_op(int cmd, void *uop, unsigned int count)
{
  long __res;
  __asm {
    mov ebx, cmd
    mov ecx, uop
    mov edx, count
    mov eax, hypercall_stubs
    add eax, (__HYPERVISOR_grant_table_op * 32)
    call eax
    mov [__res], eax
  }
  return __res;
}

static __inline int
HYPERVISOR_mmu_update(mmu_update_t *req, int count, int *success_count, domid_t domid)
{
  long __res;
  long _domid = (long)domid;
  __asm {
    mov ebx, req
    mov ecx, count
    mov edx, success_count
    mov edi, _domid
    mov eax, hypercall_stubs
    add eax, (__HYPERVISOR_mmu_update * 32)
    call eax
    mov [__res], eax
  }
  return __res;
}

static __inline int
HYPERVISOR_console_io(int cmd, int count, char *string)
{
  long __res;
  __asm {
    mov ebx, cmd
    mov ecx, count
    mov edx, string
    mov eax, hypercall_stubs
    add eax, (__HYPERVISOR_console_io * 32)
    call eax
    mov [__res], eax
  }
  return __res;
}

static __inline int
HYPERVISOR_hvm_op(int op, struct xen_hvm_param *arg)
{
  long __res;
  __asm {
    mov ebx, op
    mov ecx, arg
    mov eax, hypercall_stubs
    add eax, (__HYPERVISOR_hvm_op * 32)
    call eax
    mov [__res], eax
  }
  return __res;
}

static __inline int
HYPERVISOR_event_channel_op(int cmd, void *op)
{
  long __res;
  __asm {
    mov ebx, cmd
    mov ecx, op
    mov eax, hypercall_stubs
    add eax, (__HYPERVISOR_event_channel_op * 32)
    call eax
    mov [__res], eax
  }
  return __res;
}

static __inline ULONGLONG
hvm_get_parameter(int hvm_param)
{
  struct xen_hvm_param a;
  int retval;

  KdPrint((__DRIVER_NAME " --> hvm_get_parameter\n"));
  a.domid = DOMID_SELF;
  a.index = hvm_param;
  //a.value = via;
  retval = HYPERVISOR_hvm_op(HVMOP_get_param, &a);
  KdPrint((__DRIVER_NAME " hvm_get_parameter retval = %d\n", retval));
  KdPrint((__DRIVER_NAME " <-- hvm_get_parameter\n"));
  return a.value;
}
