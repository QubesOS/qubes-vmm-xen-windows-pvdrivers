#if !defined(_XEN_WINDOWS_H_)
#define _XEN_WINDOWS_H_

#pragma warning( disable : 4201 ) // nonstandard extension used : nameless struct/union
#pragma warning( disable : 4214 ) // nonstandard extension used : bit field types other than int

#define __XEN_INTERFACE_VERSION__ 0x00030205
#if defined(_AMD64_)
  #define __x86_64__
#elif defined(_IA64_)
  #define __ia64__
#elif defined(_X86_)
  #define __i386__
#else
  #error Unknown architecture
#endif
typedef INT8 int8_t;
typedef UINT8 uint8_t;
typedef INT16 int16_t;
typedef UINT16 uint16_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;

#include <xen.h>

#define _PAGE_PRESENT  0x001UL
#define _PAGE_RW       0x002UL
#define _PAGE_USER     0x004UL
#define _PAGE_PWT      0x008UL
#define _PAGE_PCD      0x010UL
#define _PAGE_ACCESSED 0x020UL
#define _PAGE_DIRTY    0x040UL
#define _PAGE_PAT      0x080UL
#define _PAGE_PSE      0x080UL
#define _PAGE_GLOBAL   0x100UL

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef unsigned long xenbus_transaction_t;
typedef uint32_t XENSTORE_RING_IDX;

#define XBT_NIL ((xenbus_transaction_t)0)

#define SPLITSTRING_POOL_TAG (ULONG) 'SSPT'

#define wmb() KeMemoryBarrier()
#define mb() KeMemoryBarrier()

static char **
SplitString(char *String, char Split, int MaxParts, int *Count)
{
  char **RetVal;
  char *first;
  char *last;

  //KdPrint((__DRIVER_NAME "     a\n"));

  *Count = 0;

  RetVal = ExAllocatePoolWithTag(NonPagedPool, (MaxParts + 1) * sizeof(char *), SPLITSTRING_POOL_TAG);
  last = String;
  do
  {
    if (*Count == MaxParts)
      break;
    //KdPrint((__DRIVER_NAME "     b - count = %d\n", *Count));
    first = last;
    for (last = first; *last != '\0' && *last != Split; last++);
    RetVal[*Count] = ExAllocatePoolWithTag(NonPagedPool, last - first + 1, SPLITSTRING_POOL_TAG);
    //KdPrint((__DRIVER_NAME "     c - count = %d\n", *Count));
    strncpy(RetVal[*Count], first, last - first);
    RetVal[*Count][last - first] = 0;
    //KdPrint((__DRIVER_NAME "     d - count = %d\n", *Count));
    (*Count)++;
    //KdPrint((__DRIVER_NAME "     e - count = %d\n", *Count));
    if (*last == Split)
      last++;
  } while (*last != 0);
  //KdPrint((__DRIVER_NAME "     f - count = %d\n", *Count));
  RetVal[*Count] = NULL;
  return RetVal;
}

static VOID
FreeSplitString(char **Bits, int Count)
{
  int i;

  for (i = 0; i < Count; i++)
    ExFreePoolWithTag(Bits[i], SPLITSTRING_POOL_TAG);
  ExFreePoolWithTag(Bits, SPLITSTRING_POOL_TAG);
}

#define ALLOCATE_PAGES_POOL_TAG (ULONG) 'APPT'

static PMDL
AllocatePagesExtra(int Pages, int ExtraSize)
{
  PMDL Mdl;
  PVOID Buf;

  Buf = ExAllocatePoolWithTag(NonPagedPool, Pages * PAGE_SIZE, ALLOCATE_PAGES_POOL_TAG);
  if (Buf == NULL)
  {
    KdPrint((__DRIVER_NAME "     AllocatePages Failed at ExAllocatePoolWithTag\n"));
    return NULL;
  }
//  KdPrint((__DRIVER_NAME " --- AllocatePages IRQL = %d, Buf = %p\n", KeGetCurrentIrql(), Buf));
  Mdl = ExAllocatePoolWithTag(NonPagedPool, MmSizeOfMdl(Buf, Pages * PAGE_SIZE) + ExtraSize, ALLOCATE_PAGES_POOL_TAG);
  //Mdl = IoAllocateMdl(Buf, Pages * PAGE_SIZE, FALSE, FALSE, NULL);
  if (Mdl == NULL)
  {
    // free the memory here
    KdPrint((__DRIVER_NAME "     AllocatePages Failed at IoAllocateMdl\n"));
    return NULL;
  }
  
  MmInitializeMdl(Mdl, Buf, Pages * PAGE_SIZE);
  MmBuildMdlForNonPagedPool(Mdl);
  
  return Mdl;
}

static PMDL
AllocatePages(int Pages)
{
  return AllocatePagesExtra(Pages, 0);
}

static PMDL
AllocatePage()
{
  return AllocatePagesExtra(1, 0);
}

static VOID
FreePages(PMDL Mdl)
{
  PVOID Buf = MmGetMdlVirtualAddress(Mdl);
//  KdPrint((__DRIVER_NAME " --- FreePages IRQL = %d, Buf = %p\n", KeGetCurrentIrql(), Buf));
//  IoFreeMdl(Mdl);
  ExFreePoolWithTag(Mdl, ALLOCATE_PAGES_POOL_TAG);
  ExFreePoolWithTag(Buf, ALLOCATE_PAGES_POOL_TAG);
}

#endif
