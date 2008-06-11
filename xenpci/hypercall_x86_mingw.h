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

#define __STR(x) #x
#define STR(x) __STR(x)

#define HYPERCALL_STR(name)					\
	"mov $xpdd->hypercall_stubs,%%eax; "				\
	"add $("STR(__HYPERVISOR_##name)" * 32),%%eax; "	\
	"call *%%eax"

#define _hypercall2(type, name, a1, a2)                         \
({                                                              \
        long __res, __ign1, __ign2;                             \
        asm volatile (                                          \
                HYPERCALL_STR(name)                             \
                : "=a" (__res), "=b" (__ign1), "=c" (__ign2)    \
                : "1" ((long)(a1)), "2" ((long)(a2))            \
                : "memory" );                                   \
        (type)__res;                                            \
})

#define _hypercall3(type, name, a1, a2, a3)			\
({								\
	long __res, __ign1, __ign2, __ign3;			\
	asm volatile (						\
		HYPERCALL_STR(name)				\
		: "=a" (__res), "=b" (__ign1), "=c" (__ign2), 	\
		"=d" (__ign3)					\
		: "1" ((long)(a1)), "2" ((long)(a2)),		\
		"3" ((long)(a3))				\
		: "memory" );					\
	(type)__res;						\
})

#define _hypercall4(type, name, a1, a2, a3, a4)			\
({								\
	long __res, __ign1, __ign2, __ign3, __ign4;		\
	asm volatile (						\
		HYPERCALL_STR(name)				\
		: "=a" (__res), "=b" (__ign1), "=c" (__ign2),	\
		"=d" (__ign3), "=S" (__ign4)			\
		: "1" ((long)(a1)), "2" ((long)(a2)),		\
		"3" ((long)(a3)), "4" ((long)(a4))		\
		: "memory" );					\
	(type)__res;						\
})

static inline void cpuid(int op, unsigned int *eax, unsigned int *ebx,
                         unsigned int *ecx, unsigned int *edx)
{
  __asm__("cpuid"
          : "=a" (*eax),
            "=b" (*ebx),
            "=c" (*ecx),
            "=d" (*edx)
          : "0" (op));
}

static __inline void __cpuid(uint32_t output[4], uint32_t op)
{
  cpuid(op, &output[0], &output[1], &output[2], &output[3]);
}

static __inline void __writemsr(uint32_t msr, uint64_t value)
{
  uint32_t hi, lo;
  hi = value >> 32;
  lo = value & 0xFFFFFFFF;

  __asm__ __volatile__("wrmsr" \
                       : /* no outputs */ \
                       : "c" (msr), "a" (lo), "d" (hi));
}

static __inline int
HYPERVISOR_memory_op(PXENPCI_DEVICE_DATA xpdd, int cmd, void *arg)
{
  return _hypercall2(int, memory_op, cmd, arg);
}

static __inline int
HYPERVISOR_sched_op(PXENPCI_DEVICE_DATA xpdd, int cmd, void *arg)
{
  return _hypercall2(int, sched_op, cmd, arg);
}

static __inline int
HYPERVISOR_xen_version(PXENPCI_DEVICE_DATA xpdd, int cmd, void *arg)
{
  return _hypercall2(int, xen_version, cmd, arg);
}

static __inline int
HYPERVISOR_grant_table_op(PXENPCI_DEVICE_DATA xpdd, int cmd, void *uop, unsigned int count)
{
	return _hypercall3(int, grant_table_op, cmd, uop, count);
}

static __inline int
HYPERVISOR_mmu_update(PXENPCI_DEVICE_DATA xpdd, mmu_update_t *req, int count, int *success_count, domid_t domid)
{
	return _hypercall4(int, mmu_update, req, count, success_count, domid);
}

static __inline int
HYPERVISOR_console_io(PXENPCI_DEVICE_DATA xpdd, int cmd, int count, char *string)
{
	return _hypercall3(int, console_io, cmd, count, string);
}

static __inline int
HYPERVISOR_hvm_op(PXENPCI_DEVICE_DATA xpdd, int op, struct xen_hvm_param *arg)
{
  return _hypercall2(unsigned long, hvm_op, op, arg);
}

static __inline int
HYPERVISOR_event_channel_op(PXENPCI_DEVICE_DATA xpdd, int cmd, void *arg)
{
	return _hypercall2(int, event_channel_op, cmd, arg);
}

