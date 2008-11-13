#if !defined(_XEN_WINDOWS_H_)
#define _XEN_WINDOWS_H_

#pragma warning( disable : 4201 ) // nonstandard extension used : nameless struct/union
#pragma warning( disable : 4214 ) // nonstandard extension used : bit field types other than int

#define __XEN_INTERFACE_VERSION__ 0x00030205
#if defined(_AMD64_)
  #define __x86_64__
#elif defined(_IA64_)
  #define __ia64__
#elif defined(__MINGW32__)
  /* __i386__ already defined */
#elif defined(_X86_)
  #define __i386__
#else
  #error Unknown architecture
#endif

#ifdef __MINGW32__
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#else
typedef INT8 int8_t;
typedef UINT8 uint8_t;
typedef INT16 int16_t;
typedef UINT16 uint16_t;
typedef INT32 int32_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
#endif

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

#define XBT_NIL ((xenbus_transaction_t)0)

#define SPLITSTRING_POOL_TAG (ULONG) 'SSPT'

#define wmb() KeMemoryBarrier()
#define mb() KeMemoryBarrier()
#define FUNCTION_ENTER()       XenDbgPrint(__DRIVER_NAME " --> %s\n", __FUNCTION__)
#define FUNCTION_EXIT()        XenDbgPrint(__DRIVER_NAME " <-- %s\n", __FUNCTION__)
#define FUNCTION_EXIT_STATUS(_status) XenDbgPrint(__DRIVER_NAME " <-- %s, status = %08x\n", __FUNCTION__, _status)
#define FUNCTION_ERROR_EXIT()  XenDbgPrint(__DRIVER_NAME " <-- %s (error path)\n", __FUNCTION__)
#define FUNCTION_CALLED()      XenDbgPrint(__DRIVER_NAME " %s called (line %d)\n", __FUNCTION__, __LINE__)
#ifdef __MINGW32__
#define FUNCTION_MSG(_x) _FUNCTION_MSG _x
#define _FUNCTION_MSG(format, args...) XenDbgPrint(__DRIVER_NAME " %s called: " format, __FUNCTION__, ##args)
#else
#define FUNCTION_MSG(format, ...)     XenDbgPrint(__DRIVER_NAME "     " format, __VA_ARGS__);
#endif

static __inline char **
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

static __inline VOID
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

static __inline PMDL
AllocatePages(int Pages)
{
  return AllocatePagesExtra(Pages, 0);
}

static __inline PMDL
AllocatePage()
{
  return AllocatePagesExtra(1, 0);
}

static __inline PMDL
AllocateUncachedPage()
{
  PMDL mdl;
  PVOID buf;

  buf = MmAllocateNonCachedMemory(PAGE_SIZE);
  mdl = IoAllocateMdl(buf, PAGE_SIZE, FALSE, FALSE, NULL);
  MmBuildMdlForNonPagedPool(mdl);

  return mdl;
}  

static __inline VOID
FreeUncachedPage(PMDL mdl)
{
  PVOID buf = MmGetMdlVirtualAddress(mdl);

  IoFreeMdl(mdl);
  MmFreeNonCachedMemory(buf, PAGE_SIZE);
}

static __inline VOID
FreePages(PMDL Mdl)
{
  PVOID Buf = MmGetMdlVirtualAddress(Mdl);
//  KdPrint((__DRIVER_NAME " --- FreePages IRQL = %d, Buf = %p\n", KeGetCurrentIrql(), Buf));
//  IoFreeMdl(Mdl);
  ExFreePoolWithTag(Mdl, ALLOCATE_PAGES_POOL_TAG);
  ExFreePoolWithTag(Buf, ALLOCATE_PAGES_POOL_TAG);
}

//#define XEN_IOPORT_DEBUG_PORT_BASE 0x10

static XenDbgPrint(PCHAR format, ...)
{
  CHAR buf[512];
  va_list ap;
#ifdef XEN_IOPORT_DEBUG_PORT_BASE
  ULONG i;
  BOOLEAN flag;
  int cpu;
  KIRQL old_irql = 0;
#endif
  
  va_start(ap, format);
  RtlStringCbVPrintfA(buf, ARRAY_SIZE(buf), format, ap);
  va_end(ap);
  DbgPrint(buf);
#ifdef XEN_IOPORT_DEBUG_PORT_BASE
  flag = (KeGetCurrentIrql() < HIGH_LEVEL);
  if (flag)
  {
    KeRaiseIrql(HIGH_LEVEL, &old_irql);
  }
  cpu = KeGetCurrentProcessorNumber() & 0x0F;
  for (i = 0; i < strlen(buf); i++)
  {
    WRITE_PORT_UCHAR((PUCHAR)XEN_IOPORT_DEBUG_PORT_BASE + cpu, buf[i]);
  }
  if (flag)
  {
    KeLowerIrql(old_irql);
  }
#endif
}

#ifdef KdPrint
  #undef KdPrint
#endif
#define KdPrint(_x_) XenDbgPrint _x_

#endif
