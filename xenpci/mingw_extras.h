#include <stdio.h>
#include <stdlib.h>

#define KeMemoryBarrier() asm("mfence;")
/* mingw-runtime 3.13 is buggy #1 */
#undef KeGetCurrentProcessorNumber
#define KeGetCurrentProcessorNumber() \
  ((ULONG)KeGetCurrentKPCR()->Number)

/* mingw-runtime 3.13 is buggy #2 */
#undef KeRaiseIrql
#undef KeLowerIrql

NTOSAPI
VOID
DDKAPI
KeRaiseIrql(IN KIRQL new_irql, OUT PKIRQL old_irql);

NTOSAPI
VOID
DDKAPI
KeLowerIrql(IN KIRQL irql);

extern NTOSAPI CCHAR KeNumberProcessors;

#define RtlStringCbCopyA(dst, dst_len, src) strncpy(dst, src, dst_len)
#define RtlStringCbPrintfA(args...) snprintf(args)
#define RtlStringCbVPrintfA(args...) vsnprintf(args)

/* windows wchar 2 bytes, Linux's is 4! */
typedef unsigned short win_wchar_t;

NTSTATUS
RtlStringCbPrintfW(
  win_wchar_t *dest_str,
  size_t dest_size,
  win_wchar_t *format,
  ...);
