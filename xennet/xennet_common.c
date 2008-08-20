/*
PV Net Driver for Windows Xen HVM Domains
Copyright (C) 2007 James Harper
Copyright (C) 2007 Andrew Grover <andy.grover@oracle.com>

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

#include "xennet.h"

ULONG
XenNet_ParsePacketHeader(
  packet_info_t *pi
)
{
  UINT header_length;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(pi->mdls[0]);
  
  NdisQueryBufferSafe(pi->mdls[0], (PVOID) &pi->header, &header_length, NormalPagePriority);

// what about if the buffer isn't completely on one page???
  if (ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(pi->mdls[0]), header_length) != 1)
    KdPrint((__DRIVER_NAME "     header crosses a page!\n"));


  if (header_length < XN_HDR_SIZE + 20 + 20) // minimum size of first buffer is ETH + IP + TCP header
  {
    return PARSE_TOO_SMALL;
  }
  
  switch (GET_NET_USHORT(pi->header[12])) // L2 protocol field
  {
  case 0x0800:
    pi->ip_version = (pi->header[XN_HDR_SIZE + 0] & 0xF0) >> 4;
    if (pi->ip_version != 4)
    {
      KdPrint((__DRIVER_NAME "     ip_version = %d\n", pi->ip_version));
      return PARSE_UNKNOWN_TYPE;
    }
    pi->ip4_header_length = (pi->header[XN_HDR_SIZE + 0] & 0x0F) << 2;
    if (header_length < (ULONG)(pi->ip4_header_length + 20))
    {
      KdPrint((__DRIVER_NAME "     first buffer is only %d bytes long, must be >= %d (1)\n", XN_HDR_SIZE + header_length, (ULONG)(XN_HDR_SIZE + pi->ip4_header_length + 20)));
      // we need to do something conclusive here...
      return PARSE_TOO_SMALL;
    }
    break;
  default:
//    KdPrint((__DRIVER_NAME "     Not IP\n"));
    return PARSE_UNKNOWN_TYPE;
  }
  pi->ip_proto = pi->header[XN_HDR_SIZE + 9];
  switch (pi->ip_proto)
  {
  case 6:  // TCP
  case 17: // UDP
    break;
  default:
    return PARSE_UNKNOWN_TYPE;
  }
  pi->ip4_length = GET_NET_USHORT(pi->header[XN_HDR_SIZE + 2]);
  pi->tcp_header_length = (pi->header[XN_HDR_SIZE + pi->ip4_header_length + 12] & 0xf0) >> 2;

  if (header_length < (ULONG)(pi->ip4_header_length + pi->tcp_header_length))
  {
    KdPrint((__DRIVER_NAME "     first buffer is only %d bytes long, must be >= %d (2)\n", XN_HDR_SIZE + header_length, (ULONG)(XN_HDR_SIZE + pi->ip4_header_length + pi->tcp_header_length)));
    return PARSE_TOO_SMALL;
  }

  pi->tcp_length = pi->ip4_length - pi->ip4_header_length - pi->tcp_header_length;
  pi->tcp_remaining = pi->tcp_length;
  pi->tcp_seq = GET_NET_ULONG(pi->header[XN_HDR_SIZE + pi->ip4_header_length + 4]);
  if (pi->mss > 0 && pi->tcp_length > pi->mss)
    pi->split_required = TRUE;
//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return PARSE_OK;
}

VOID
XenNet_SumIpHeader(
  PUCHAR header,
  USHORT ip4_header_length
)
{
  ULONG csum = 0;
  USHORT i;

  ASSERT(ip4_header_length > 12);
  ASSERT(!(ip4_header_length & 1));

  header[XN_HDR_SIZE + 10] = 0;
  header[XN_HDR_SIZE + 11] = 0;
  for (i = 0; i < ip4_header_length; i += 2)
  {
    csum += GET_NET_USHORT(header[XN_HDR_SIZE + i]);
  }
  while (csum & 0xFFFF0000)
    csum = (csum & 0xFFFF) + (csum >> 16);
  csum = ~csum;
  SET_NET_USHORT(header[XN_HDR_SIZE + 10], csum);
}

PUCHAR
XenNet_GetData(
  packet_info_t *pi,
  USHORT req_length,
  PUSHORT length
)
{
  PNDIS_BUFFER mdl = pi->mdls[pi->curr_mdl];
  PUCHAR buffer = (PUCHAR)MmGetMdlVirtualAddress(mdl) + pi->curr_mdl_offset;

  //FUNCTION_ENTER();

  *length = (USHORT)min(req_length, MmGetMdlByteCount(mdl) - pi->curr_mdl_offset);

  //FUNCTION_MSG(("req_length = %d, length = %d\n", req_length, *length));

  pi->curr_mdl_offset = pi->curr_mdl_offset + *length;
  if (pi->curr_mdl_offset == MmGetMdlByteCount(mdl))
  {
    pi->curr_mdl++;
    pi->curr_mdl_offset = 0;
  }

  //FUNCTION_EXIT();

  return buffer;
}

/* Called at DISPATCH LEVEL */
static VOID DDKAPI
XenFreelist_Timer(
  PVOID SystemSpecific1,
  PVOID FunctionContext,
  PVOID SystemSpecific2,
  PVOID SystemSpecific3
)
{
  freelist_t *fl = (freelist_t *)FunctionContext;
  PMDL mdl;
  int i;

  UNREFERENCED_PARAMETER(SystemSpecific1);
  UNREFERENCED_PARAMETER(SystemSpecific2);
  UNREFERENCED_PARAMETER(SystemSpecific3);

  if (fl->xi->device_state->resume_state != RESUME_STATE_RUNNING && !fl->grants_resumed)
    return;

  KeAcquireSpinLockAtDpcLevel(fl->lock);

  //FUNCTION_MSG((" --- timer - page_free_lowest = %d\n", fl->page_free_lowest));

  if (fl->page_free_lowest > fl->page_free_target) // lots of potential for tuning here
  {
    for (i = 0; i < (int)min(16, fl->page_free_lowest - fl->page_free_target); i++)
    {
      mdl = XenFreelist_GetPage(fl);
      if (!mdl)
        break;
      fl->xi->vectors.GntTbl_EndAccess(fl->xi->vectors.context,
        *(grant_ref_t *)(((UCHAR *)mdl) + MmSizeOfMdl(0, PAGE_SIZE)), 0);
      FreePages(mdl);
    }
    //FUNCTION_MSG((__DRIVER_NAME " --- timer - freed %d pages\n", i));
  }

  fl->page_free_lowest = fl->page_free;

  KeReleaseSpinLockFromDpcLevel(fl->lock);
}

VOID
XenFreelist_Init(struct xennet_info *xi, freelist_t *fl, PKSPIN_LOCK lock)
{
  fl->xi = xi;
  fl->lock = lock;
  fl->page_free = 0;
  fl->page_free_lowest = 0;
  fl->page_free_target = 16; /* tune this */
  fl->grants_resumed = FALSE;
  NdisMInitializeTimer(&fl->timer, fl->xi->adapter_handle, XenFreelist_Timer, fl);
  NdisMSetPeriodicTimer(&fl->timer, 1000);
}

PMDL
XenFreelist_GetPage(freelist_t *fl)
{
  PMDL mdl;
  PFN_NUMBER pfn;
  grant_ref_t gref;

  //ASSERT(!KeTestSpinLock(fl->lock));

  if (fl->page_free == 0)
  {
    mdl = AllocatePagesExtra(1, sizeof(grant_ref_t));
    if (!mdl)
      return NULL;
    pfn = *MmGetMdlPfnArray(mdl);
    gref = fl->xi->vectors.GntTbl_GrantAccess(
      fl->xi->vectors.context, 0,
      (uint32_t)pfn, FALSE, INVALID_GRANT_REF);
    if (gref == INVALID_GRANT_REF)
      KdPrint((__DRIVER_NAME "     No more grefs\n"));
    *(grant_ref_t *)(((UCHAR *)mdl) + MmSizeOfMdl(0, PAGE_SIZE)) = gref;
    /* we really should check if our grant was successful... */
  }
  else
  {
    fl->page_free--;
    if (fl->page_free < fl->page_free_lowest)
      fl->page_free_lowest = fl->page_free;
    mdl = fl->page_list[fl->page_free];
  }

  return mdl;
}

VOID
XenFreelist_PutPage(freelist_t *fl, PMDL mdl)
{
  //ASSERT(!KeTestSpinLock(fl->lock));

  ASSERT(NdisBufferLength(mdl) == PAGE_SIZE);

  if (fl->page_free == PAGE_LIST_SIZE)
  {
    /* our page list is full. free the buffer instead. This will be a bit sucky performancewise... */
    fl->xi->vectors.GntTbl_EndAccess(fl->xi->vectors.context,
      *(grant_ref_t *)(((UCHAR *)mdl) + MmSizeOfMdl(0, PAGE_SIZE)), FALSE);
    FreePages(mdl);
  }
  else
  {
    fl->page_list[fl->page_free] = mdl;
    fl->page_free++;
  }
}

VOID
XenFreelist_Dispose(freelist_t *fl)
{
  PMDL mdl;
  BOOLEAN TimerCancelled;

  NdisMCancelTimer(&fl->timer, &TimerCancelled);

  while(fl->page_free != 0)
  {
    fl->page_free--;
    mdl = fl->page_list[fl->page_free];
    fl->xi->vectors.GntTbl_EndAccess(fl->xi->vectors.context,
      *(grant_ref_t *)(((UCHAR *)mdl) + MmSizeOfMdl(0, PAGE_SIZE)), 0);
    FreePages(mdl);
  }
}

static VOID
XenFreelist_ReGrantMdl(freelist_t *fl, PMDL mdl)
{
  PFN_NUMBER pfn;
  pfn = *MmGetMdlPfnArray(mdl);
  *(grant_ref_t *)(((UCHAR *)mdl) + MmSizeOfMdl(0, PAGE_SIZE)) = fl->xi->vectors.GntTbl_GrantAccess(
    fl->xi->vectors.context, 0,
    (uint32_t)pfn, FALSE, INVALID_GRANT_REF);
}

/* re-grant all the pages, as the grant table was wiped on resume */
VOID
XenFreelist_ResumeStart(freelist_t *fl)
{
  ULONG i;
  
  for (i = 0; i < fl->page_free; i++)
  {
    XenFreelist_ReGrantMdl(fl, fl->page_list[i]);
  }
  fl->grants_resumed = TRUE;
}

VOID
XenFreelist_ResumeEnd(freelist_t *fl)
{
  fl->grants_resumed = FALSE;
}
