#include <stdio.h>

/* windows wchar 2 bytes, Linux's is 4! */
typedef unsigned short win_wchar_t;

NTSTATUS
RtlStringCbPrintfW(
  win_wchar_t *dest_str,
  size_t dest_size,
  win_wchar_t *format,
  ...);

/* stuff needed for xennet */
#include <ndis.h>

//#define GCCNOANON u.s2.

