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

#define INITGUID
#include "xenvbd.h"
#include <io/blkif.h>
#include <scsi.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <stdlib.h>
#include <xen_public.h>
#include <io/xenbus.h>
#include <io/protocols.h>

#pragma warning(disable: 4127)

#ifdef ALLOC_PRAGMA
DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text (INIT, DriverEntry)
#endif

#if defined(__x86_64__)
  #define GET_PAGE_ALIGNED(ptr) ((PVOID)(((ULONGLONG)ptr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)))
#else
  #define GET_PAGE_ALIGNED(ptr) UlongToPtr((PtrToUlong(ptr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#endif

static BOOLEAN dump_mode = FALSE;

ULONGLONG parse_numeric_string(PCHAR string)
{
  ULONGLONG val = 0;
  while (*string != 0)
  {
    val = val * 10 + (*string - '0');
    string++;
  }
  return val;
}

static blkif_shadow_t *
get_shadow_from_freelist(PXENVBD_DEVICE_DATA xvdd)
{
  if (xvdd->shadow_free == 0)
  {
    KdPrint((__DRIVER_NAME "     No more shadow entries\n"));    
    return NULL;
  }
  xvdd->shadow_free--;
  if (xvdd->shadow_free < xvdd->shadow_min_free)
    xvdd->shadow_min_free = xvdd->shadow_free;
  return &xvdd->shadows[xvdd->shadow_free_list[xvdd->shadow_free]];
}

static VOID
put_shadow_on_freelist(PXENVBD_DEVICE_DATA xvdd, blkif_shadow_t *shadow)
{
  xvdd->shadow_free_list[xvdd->shadow_free] = (USHORT)shadow->req.id;
  shadow->srb = NULL;
  xvdd->shadow_free++;
}

static grant_ref_t
get_grant_from_freelist(PXENVBD_DEVICE_DATA xvdd)
{
  if (xvdd->grant_free == 0)
  {
    KdPrint((__DRIVER_NAME "     No more grant refs\n"));    
    return (grant_ref_t)0x0FFFFFFF;
  }
  xvdd->grant_free--;
  return xvdd->grant_free_list[xvdd->grant_free];
}

static VOID
put_grant_on_freelist(PXENVBD_DEVICE_DATA xvdd, grant_ref_t grant)
{
  xvdd->grant_free_list[xvdd->grant_free] = grant;
  xvdd->grant_free++;
}

static blkif_response_t *
XenVbd_GetResponse(PXENVBD_DEVICE_DATA xvdd, int i)
{
  blkif_other_response_t *rep;
  if (!xvdd->use_other)
    return RING_GET_RESPONSE(&xvdd->ring, i);
  rep = RING_GET_RESPONSE(&xvdd->other_ring, i);
  xvdd->tmp_rep.id = rep->id;
  xvdd->tmp_rep.operation = rep->operation;
  xvdd->tmp_rep.status = rep->status;
  return &xvdd->tmp_rep;
}

static VOID
XenVbd_PutRequest(PXENVBD_DEVICE_DATA xvdd, blkif_request_t *req)
{
  blkif_other_request_t *other_req;

  //KdPrint((__DRIVER_NAME "     ring.sring->rsp_prod = %d\n", xvdd->ring.sring->rsp_prod));
  //KdPrint((__DRIVER_NAME "     ring.sring->rsp_event = %d\n", xvdd->ring.sring->rsp_event));
  //KdPrint((__DRIVER_NAME "     ring.rsp_cons = %d\n", xvdd->ring.rsp_cons));
  //KdPrint((__DRIVER_NAME "     ring.req_prod_pvt = %d\n", xvdd->ring.req_prod_pvt));
  if (!xvdd->use_other)
  {
    *RING_GET_REQUEST(&xvdd->ring, xvdd->ring.req_prod_pvt) = *req;
  }
  else
  {  
    other_req = RING_GET_REQUEST(&xvdd->other_ring, xvdd->ring.req_prod_pvt);
    other_req->operation = req->operation;
    other_req->nr_segments = req->nr_segments;
    other_req->handle = req->handle;
    other_req->id = req->id;
    other_req->sector_number = req->sector_number;
    memcpy(other_req->seg, req->seg, sizeof(struct blkif_request_segment) * req->nr_segments);
  }
  xvdd->ring.req_prod_pvt++;
  //KdPrint((__DRIVER_NAME "     ring.sring->rsp_prod = %d\n", xvdd->ring.sring->rsp_prod));
  //KdPrint((__DRIVER_NAME "     ring.sring->rsp_event = %d\n", xvdd->ring.sring->rsp_event));
  //KdPrint((__DRIVER_NAME "     ring.rsp_cons = %d\n", xvdd->ring.rsp_cons));
  //KdPrint((__DRIVER_NAME "     ring.req_prod_pvt = %d\n", xvdd->ring.req_prod_pvt));
}

static ULONG
XenVbd_InitFromConfig(PXENVBD_DEVICE_DATA xvdd)
{
  ULONG i;
  PUCHAR ptr;
  USHORT type;
  PCHAR setting, value;
  ULONG qemu_protocol_version = 0;

  xvdd->device_type = XENVBD_DEVICETYPE_UNKNOWN;
  xvdd->sring = NULL;
  xvdd->event_channel = 0;

  xvdd->inactive = TRUE;  
  ptr = xvdd->device_base;
  while((type = GET_XEN_INIT_RSP(&ptr, (PVOID) &setting, (PVOID) &value)) != XEN_INIT_TYPE_END)
  {
    switch(type)
    {
    case XEN_INIT_TYPE_RING: /* frontend ring */
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_RING - %s = %p\n", setting, value));
      if (strcmp(setting, "ring-ref") == 0)
      {
        xvdd->sring = (blkif_sring_t *)value;
        FRONT_RING_INIT(&xvdd->ring, xvdd->sring, PAGE_SIZE);
        /* this bit is for when we have to take over an existing ring on a crash dump */
        xvdd->ring.req_prod_pvt = xvdd->sring->req_prod;
        xvdd->ring.rsp_cons = xvdd->ring.req_prod_pvt;
      }
      break;
    case XEN_INIT_TYPE_EVENT_CHANNEL: /* frontend event channel */
    case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ: /* frontend event channel */
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_EVENT_CHANNEL - %s = %d\n", setting, PtrToUlong(value)));
      if (strcmp(setting, "event-channel") == 0)
      {
        /* cheat here - save the state of the ring in the topmost bits of the event-channel */
        xvdd->event_channel_ptr = (ULONG *)(((PCHAR)ptr) - sizeof(ULONG));
        xvdd->event_channel = PtrToUlong(value) & 0x3FFFFFFF;
        if (PtrToUlong(value) & 0x80000000)
        {
          xvdd->cached_use_other = (BOOLEAN)!!(PtrToUlong(value) & 0x40000000);
          KdPrint((__DRIVER_NAME "     cached_use_other = %d\n", xvdd->cached_use_other));
        }
      }
      break;
    case XEN_INIT_TYPE_READ_STRING_BACK:
    case XEN_INIT_TYPE_READ_STRING_FRONT:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = %s\n", setting, value));
      if (strcmp(setting, "sectors") == 0)
        xvdd->total_sectors = parse_numeric_string(value);
      else if (strcmp(setting, "sector-size") == 0)
        xvdd->bytes_per_sector = (ULONG)parse_numeric_string(value);
      else if (strcmp(setting, "device-type") == 0)
      {
        if (strcmp(value, "disk") == 0)
        {
          KdPrint((__DRIVER_NAME "     device-type = Disk\n"));    
          xvdd->device_type = XENVBD_DEVICETYPE_DISK;
        }
        else if (strcmp(value, "cdrom") == 0)
        {
          KdPrint((__DRIVER_NAME "     device-type = CDROM\n"));    
          xvdd->device_type = XENVBD_DEVICETYPE_CDROM;
        }
        else
        {
          KdPrint((__DRIVER_NAME "     device-type = %s (This probably won't work!)\n", value));
          xvdd->device_type = XENVBD_DEVICETYPE_UNKNOWN;
        }
      }
      else if (strcmp(setting, "mode") == 0)
      {
        if (strncmp(value, "r", 1) == 0)
        {
          KdPrint((__DRIVER_NAME "     mode = r\n"));    
          xvdd->device_mode = XENVBD_DEVICEMODE_READ;
        }
        else if (strncmp(value, "w", 1) == 0)
        {
          KdPrint((__DRIVER_NAME "     mode = w\n"));    
          xvdd->device_mode = XENVBD_DEVICEMODE_WRITE;
        }
        else
        {
          KdPrint((__DRIVER_NAME "     mode = unknown\n"));
          xvdd->device_mode = XENVBD_DEVICEMODE_UNKNOWN;
        }
      }
      break;
    case XEN_INIT_TYPE_VECTORS:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_VECTORS\n"));
      if (((PXENPCI_VECTORS)value)->length != sizeof(XENPCI_VECTORS) ||
        ((PXENPCI_VECTORS)value)->magic != XEN_DATA_MAGIC)
      {
        KdPrint((__DRIVER_NAME "     vectors mismatch (magic = %08x, length = %d)\n",
          ((PXENPCI_VECTORS)value)->magic, ((PXENPCI_VECTORS)value)->length));
        KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
        return SP_RETURN_BAD_CONFIG;
      }
      else
        memcpy(&xvdd->vectors, value, sizeof(XENPCI_VECTORS));
      break;
    case XEN_INIT_TYPE_GRANT_ENTRIES:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_GRANT_ENTRIES - %d\n", PtrToUlong(setting)));
      xvdd->grant_entries = (USHORT)PtrToUlong(setting);
      if (dump_mode)
      {
        /* check each grant entry first to make sure it isn't in use already */
        grant_ref_t *gref = (grant_ref_t *)value;
        xvdd->grant_free = 0;
        for (i = 0; i < xvdd->grant_entries; i++)
        {
          if (xvdd->vectors.GntTbl_EndAccess(xvdd->vectors.context, *gref, TRUE))
          {
            put_grant_on_freelist(xvdd, *gref);
          }
          gref++;
        }
      }
      else
      {
        memcpy(&xvdd->grant_free_list, value, sizeof(grant_ref_t) * xvdd->grant_entries);
        xvdd->grant_free = xvdd->grant_entries;
      }
      break;
    case XEN_INIT_TYPE_STATE_PTR:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_DEVICE_STATE - %p\n", PtrToUlong(value)));
      xvdd->device_state = (PXENPCI_DEVICE_STATE)value;
      break;
    case XEN_INIT_TYPE_ACTIVE:
      xvdd->inactive = FALSE;
      break;
    case XEN_INIT_TYPE_QEMU_PROTOCOL_VERSION:
      qemu_protocol_version = PtrToUlong(value);
    default:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_%d\n", type));
      break;
    }
  }
  if (xvdd->device_type == XENVBD_DEVICETYPE_UNKNOWN
    || xvdd->sring == NULL
    || xvdd->event_channel == 0
    || xvdd->total_sectors == 0
    || xvdd->bytes_per_sector == 0)
  {
    KdPrint((__DRIVER_NAME "     Missing settings\n"));
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
    return SP_RETURN_BAD_CONFIG;
  }
  if (!xvdd->inactive && xvdd->device_type == XENVBD_DEVICETYPE_CDROM && qemu_protocol_version > 0)
  {
    xvdd->inactive = TRUE;
  }
  
  if (xvdd->inactive)
    KdPrint((__DRIVER_NAME "     Device is inactive\n"));
  
  if (xvdd->device_type == XENVBD_DEVICETYPE_CDROM)
  {
    /* CD/DVD drives must have bytes_per_sector = 2048. */
    xvdd->bytes_per_sector = 2048;
  }

  /* for some reason total_sectors is measured in 512 byte sectors always, so correct this to be in bytes_per_sectors */
#ifdef __MINGW32__
  /* mingw can't divide, so shift instead (assumes bps is ^2 and at least 512) */
  {
    ULONG num_512_byte_sectors = xvdd->bytes_per_sector / 512;
    ULONG index;

    bit_scan_forward(&index, num_512_byte_sectors);
    xvdd->total_sectors <<= index-1;
  }
#else
  xvdd->total_sectors /= xvdd->bytes_per_sector / 512;
#endif


  xvdd->shadow_free = 0;
  memset(xvdd->shadows, 0, sizeof(blkif_shadow_t) * SHADOW_ENTRIES);
  for (i = 0; i < SHADOW_ENTRIES; i++)
  {
    xvdd->shadows[i].req.id = i;
    put_shadow_on_freelist(xvdd, &xvdd->shadows[i]);
  }
  
  return SP_RETURN_FOUND;
}

ULONG stat_interrupts = 0;
ULONG stat_interrupts_for_me = 0;
ULONG stat_reads = 0;
ULONG stat_writes = 0;
ULONG stat_unaligned_le_4096 = 0;
ULONG stat_unaligned_le_8192 = 0;
ULONG stat_unaligned_le_16384 = 0;
ULONG stat_unaligned_le_32768 = 0;
ULONG stat_unaligned_le_65536 = 0;
ULONG stat_unaligned_gt_65536 = 0;
ULONG stat_no_shadows = 0;
ULONG stat_no_grants = 0;
ULONG stat_outstanding_requests = 0;

static VOID
XenVbd_DumpStats()
{
  KdPrint((__DRIVER_NAME "     stat_interrupts = %d\n", stat_interrupts));
  KdPrint((__DRIVER_NAME "     stat_interrupts_for_me = %d\n", stat_interrupts_for_me));
  KdPrint((__DRIVER_NAME "     stat_reads = %d\n", stat_reads));
  KdPrint((__DRIVER_NAME "     stat_writes = %d\n", stat_writes));
  KdPrint((__DRIVER_NAME "     stat_unaligned_le_4096 = %d\n", stat_unaligned_le_4096));
  KdPrint((__DRIVER_NAME "     stat_unaligned_le_8192 = %d\n", stat_unaligned_le_8192));
  KdPrint((__DRIVER_NAME "     stat_unaligned_le_16384 = %d\n", stat_unaligned_le_16384));
  KdPrint((__DRIVER_NAME "     stat_unaligned_le_32768 = %d\n", stat_unaligned_le_32768));
  KdPrint((__DRIVER_NAME "     stat_unaligned_le_65536 = %d\n", stat_unaligned_le_65536));
  KdPrint((__DRIVER_NAME "     stat_unaligned_gt_65536 = %d\n", stat_unaligned_gt_65536));
  KdPrint((__DRIVER_NAME "     stat_no_shadows = %d\n", stat_no_shadows));
  KdPrint((__DRIVER_NAME "     stat_no_grants = %d\n", stat_no_grants));
  KdPrint((__DRIVER_NAME "     stat_outstanding_requests = %d\n", stat_outstanding_requests));
}

static __inline ULONG
decode_cdb_length(PSCSI_REQUEST_BLOCK srb)
{
  switch (srb->Cdb[0])
  {
  case SCSIOP_READ:
  case SCSIOP_WRITE:
    return (srb->Cdb[7] << 8) | srb->Cdb[8];
  case SCSIOP_READ16:
  case SCSIOP_WRITE16:
    return (srb->Cdb[10] << 24) | (srb->Cdb[11] << 16) | (srb->Cdb[12] << 8) | srb->Cdb[13];    
  default:
    return 0;
  }
}

static __inline ULONGLONG
decode_cdb_sector(PSCSI_REQUEST_BLOCK srb)
{
  ULONGLONG sector;
  
  switch (srb->Cdb[0])
  {
  case SCSIOP_READ:
  case SCSIOP_WRITE:
    sector = (srb->Cdb[2] << 24) | (srb->Cdb[3] << 16) | (srb->Cdb[4] << 8) | srb->Cdb[5];
    break;
  case SCSIOP_READ16:
  case SCSIOP_WRITE16:
    sector = ((ULONGLONG)srb->Cdb[2] << 56) | ((ULONGLONG)srb->Cdb[3] << 48)
           | ((ULONGLONG)srb->Cdb[4] << 40) | ((ULONGLONG)srb->Cdb[5] << 32)
           | ((ULONGLONG)srb->Cdb[6] << 24) | ((ULONGLONG)srb->Cdb[7] << 16)
           | ((ULONGLONG)srb->Cdb[8] << 8) | ((ULONGLONG)srb->Cdb[9]);
    //KdPrint((__DRIVER_NAME "     sector_number = %d (high) %d (low)\n", (ULONG)(sector >> 32), (ULONG)sector));
    break;
  default:
    sector = 0;
    break;
  }
  return sector;
}

static __inline BOOLEAN
decode_cdb_is_read(PSCSI_REQUEST_BLOCK srb)
{
  switch (srb->Cdb[0])
  {
  case SCSIOP_READ:
  case SCSIOP_READ16:
    return TRUE;
  case SCSIOP_WRITE:
  case SCSIOP_WRITE16:
    return FALSE;
  default:
    return FALSE;
  }
}

static VOID
XenVbd_PutSrbOnRing(PXENVBD_DEVICE_DATA xvdd, PSCSI_REQUEST_BLOCK srb, ULONG srb_offset)
{
  ULONG block_count, transfer_length;
  blkif_shadow_t *shadow;
  PHYSICAL_ADDRESS physical_address;
  ULONG pfn;
  ULONG remaining, offset, length;
  PUCHAR ptr;
  int notify;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  //ASSERT(!(srb_offset == 0 && xvdd->split_request_in_progress));
  block_count = decode_cdb_length(srb);;
  block_count *= xvdd->bytes_per_sector / 512;
  if (PtrToUlong(srb->DataBuffer) & 511) /* use SrbExtension intead of DataBuffer if DataBuffer is not aligned to sector size */
  {
    ptr = GET_PAGE_ALIGNED(srb->SrbExtension);
    transfer_length = min(block_count * 512 - srb_offset, UNALIGNED_DOUBLE_BUFFER_SIZE);
  }
  else
  {
    ptr = srb->DataBuffer;
    transfer_length = block_count * 512;
  }

  if (xvdd->grant_free <= ADDRESS_AND_SIZE_TO_SPAN_PAGES(ptr, transfer_length))
  {
    ASSERT(!xvdd->pending_srb);
    //KdPrint((__DRIVER_NAME "     No enough grants - deferring\n"));
    xvdd->pending_srb = srb;
    stat_no_grants++;
    return;
  }

  if (!srb_offset)
  {
    if (PtrToUlong(srb->DataBuffer) & 511)
    {
      if (block_count * 512 <= 4096)
        stat_unaligned_le_4096++;
      else if (block_count * 512 <= 8192)
        stat_unaligned_le_8192++;
      else if (block_count * 512 <= 16384)
        stat_unaligned_le_16384++;
      else if (block_count * 512 <= 32768)
        stat_unaligned_le_32768++;
      else if (block_count * 512 <= 65536)
        stat_unaligned_le_65536++;
      else
        stat_unaligned_gt_65536++;
    }
    if (decode_cdb_is_read(srb))
      stat_reads++;
    else
      stat_writes++;
    stat_outstanding_requests++;
  }
  
  shadow = get_shadow_from_freelist(xvdd);
  ASSERT(shadow);
  shadow->req.sector_number = decode_cdb_sector(srb);
  shadow->req.sector_number *= xvdd->bytes_per_sector / 512;
  shadow->req.handle = 0;
  shadow->req.operation = decode_cdb_is_read(srb)?BLKIF_OP_READ:BLKIF_OP_WRITE;
  shadow->req.nr_segments = 0;
  shadow->offset = srb_offset;
  shadow->length = transfer_length;
  shadow->srb = srb;

  //KdPrint((__DRIVER_NAME "     sector_number = %d, block_count = %d\n", (ULONG)shadow->req.sector_number, block_count));
  //KdPrint((__DRIVER_NAME "     SrbExtension = %p\n", srb->SrbExtension));
  //KdPrint((__DRIVER_NAME "     DataBuffer   = %p\n", srb->DataBuffer));

  if (PtrToUlong(srb->DataBuffer) & 511) /* use SrbExtension intead of DataBuffer if DataBuffer is not aligned to sector size */
  {
    shadow->req.sector_number += srb_offset / 512; //xvdd->bytes_per_sector;
    //KdPrint((__DRIVER_NAME "     Using unaligned buffer - DataBuffer = %p, SrbExtension = %p, total length = %d, offset = %d, length = %d, sector = %d\n", srb->DataBuffer, srb->SrbExtension, block_count * 512, shadow->offset, shadow->length, (ULONG)shadow->req.sector_number));
    if (!decode_cdb_is_read(srb))
    {
      memcpy(ptr, ((PUCHAR)srb->DataBuffer) + srb_offset, shadow->length);
    }
  }
  else
  {
    ptr = srb->DataBuffer;
  }
  //KdPrint((__DRIVER_NAME "     sector_number = %d\n", (ULONG)shadow->req.sector_number));
  //KdPrint((__DRIVER_NAME "     handle = %d\n", shadow->req.handle));
  //KdPrint((__DRIVER_NAME "     operation = %d\n", shadow->req.operation));
    
  remaining = shadow->length;  
  while (remaining > 0)
  {
    physical_address = MmGetPhysicalAddress(ptr);
    pfn = (ULONG)(physical_address.QuadPart >> PAGE_SHIFT);
    shadow->req.seg[shadow->req.nr_segments].gref = get_grant_from_freelist(xvdd);
    ASSERT(shadow->req.seg[shadow->req.nr_segments].gref != INVALID_GRANT_REF);
    xvdd->vectors.GntTbl_GrantAccess(xvdd->vectors.context, 0, pfn, 0, shadow->req.seg[shadow->req.nr_segments].gref);
    offset = (ULONG)(physical_address.QuadPart & (PAGE_SIZE - 1));
    ASSERT((offset & 511) == 0);
    length = min(PAGE_SIZE - offset, remaining);
    shadow->req.seg[shadow->req.nr_segments].first_sect = (UCHAR)(offset >> 9);
    shadow->req.seg[shadow->req.nr_segments].last_sect = (UCHAR)(((offset + length) >> 9) - 1);
    remaining -= length;
    ptr += length;
    //KdPrint((__DRIVER_NAME "     seg[%d].gref = %d\n", shadow->req.nr_segments, shadow->req.seg[shadow->req.nr_segments].gref));
    //KdPrint((__DRIVER_NAME "     seg[%d].first_sect = %d\n", shadow->req.nr_segments, shadow->req.seg[shadow->req.nr_segments].first_sect));
    //KdPrint((__DRIVER_NAME "     seg[%d].last_sect = %d\n", shadow->req.nr_segments, shadow->req.seg[shadow->req.nr_segments].last_sect));
    shadow->req.nr_segments++;
  }
  //KdPrint((__DRIVER_NAME "     nr_segments = %d\n", shadow->req.nr_segments));

  XenVbd_PutRequest(xvdd, &shadow->req);

  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xvdd->ring, notify);
  if (notify)
  {
    //KdPrint((__DRIVER_NAME "     Notifying\n"));
    xvdd->vectors.EvtChn_Notify(xvdd->vectors.context, xvdd->event_channel);
  }

  if (!xvdd->shadow_free)
    stat_no_shadows++;
  if (xvdd->shadow_free && srb_offset == 0)
    ScsiPortNotification(NextLuRequest, xvdd, 0, 0, 0);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

typedef struct {
  PSCSI_REQUEST_BLOCK srb;
  ULONG offset;
} mini_shadow_t;

static VOID
XenVbd_Resume(PVOID DeviceExtension)
{
  PXENVBD_DEVICE_DATA xvdd = (PXENVBD_DEVICE_DATA)DeviceExtension;
  ULONG i;
  mini_shadow_t shadows[MAX_SHADOW_ENTRIES];
  ULONG shadow_count;

  FUNCTION_ENTER();
  KdPrint((__DRIVER_NAME "     found device in resume state\n"));
  //FRONT_RING_INIT(&xvdd->ring, xvdd->sring, PAGE_SIZE); what was this for???
  // re-submit srb's
  
  shadow_count = 0;
  for (i = 0; i < SHADOW_ENTRIES; i++)
  {
    if (xvdd->shadows[i].srb)
    {
      shadows[shadow_count].srb = xvdd->shadows[i].srb;
      shadows[shadow_count].offset = xvdd->shadows[i].offset;
      shadow_count++;
      xvdd->shadows[i].srb = NULL;
    }      
  }
KdPrint((__DRIVER_NAME "     About to call InitFromConfig\n"));
  XenVbd_InitFromConfig(xvdd);
KdPrint((__DRIVER_NAME "     Back from InitFromConfig\n"));
  
  for (i = 0; i < shadow_count; i++)
  {
KdPrint((__DRIVER_NAME "     Putting on Shadow entry\n"));
    XenVbd_PutSrbOnRing(xvdd, shadows[i].srb, shadows[i].offset);
  }
KdPrint((__DRIVER_NAME "     Shadows are back on the ring\n"));
  
  xvdd->device_state->resume_state = RESUME_STATE_RUNNING;

KdPrint((__DRIVER_NAME "     resume_state set to RESUME_STATE_RUNNING\n"));
  
  if (i == 0)
  {
    /* no requests, so we might need to tell scsiport that we can accept a new one if we deferred one earlier */
KdPrint((__DRIVER_NAME "     No shadows - notifying to get things started again\n"));
    ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
  }
  FUNCTION_EXIT();
}

static ULONG DDKAPI
XenVbd_HwScsiFindAdapter(PVOID DeviceExtension, PVOID HwContext, PVOID BusInformation, PCHAR ArgumentString, PPORT_CONFIGURATION_INFORMATION ConfigInfo, PBOOLEAN Again)
{
//  PACCESS_RANGE AccessRange;
  PXENVBD_DEVICE_DATA xvdd = (PXENVBD_DEVICE_DATA)DeviceExtension;
  ULONG status;
//  PXENPCI_XEN_DEVICE_DATA XenDeviceData;
  PACCESS_RANGE access_range;

  UNREFERENCED_PARAMETER(HwContext);
  UNREFERENCED_PARAMETER(BusInformation);
  UNREFERENCED_PARAMETER(ArgumentString);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));  
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  *Again = FALSE;

  KdPrint((__DRIVER_NAME "     BusInterruptLevel = %d\n", ConfigInfo->BusInterruptLevel));
  KdPrint((__DRIVER_NAME "     BusInterruptVector = %03x\n", ConfigInfo->BusInterruptVector));

  KdPrint((__DRIVER_NAME "     NumberOfAccessRanges = %d\n", ConfigInfo->NumberOfAccessRanges));    
  if (ConfigInfo->NumberOfAccessRanges != 1 && ConfigInfo->NumberOfAccessRanges != 2)
  {
    return SP_RETURN_BAD_CONFIG;
  }

  access_range = &((*(ConfigInfo->AccessRanges))[0]);
  KdPrint((__DRIVER_NAME "     RangeStart = %08x, RangeLength = %08x\n",
    access_range->RangeStart.LowPart, access_range->RangeLength));
  xvdd->device_base = ScsiPortGetDeviceBase(
    DeviceExtension,
    ConfigInfo->AdapterInterfaceType,
    ConfigInfo->SystemIoBusNumber,
    access_range->RangeStart,
    access_range->RangeLength,
    !access_range->RangeInMemory);
  if (!xvdd->device_base)
  {
    KdPrint((__DRIVER_NAME "     Invalid config\n"));
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));  
    return SP_RETURN_BAD_CONFIG;
  }
  
  status = XenVbd_InitFromConfig(xvdd);
  if (status != SP_RETURN_FOUND)
    return status;
  
  ConfigInfo->MaximumTransferLength = BLKIF_MAX_SEGMENTS_PER_REQUEST * PAGE_SIZE;
  ConfigInfo->NumberOfPhysicalBreaks = 0; //BLKIF_MAX_SEGMENTS_PER_REQUEST - 1;
  ConfigInfo->ScatterGather = TRUE;
  ConfigInfo->AlignmentMask = 0;
  ConfigInfo->NumberOfBuses = 1;
  ConfigInfo->InitiatorBusId[0] = 1;
  ConfigInfo->MaximumNumberOfLogicalUnits = 1;
  ConfigInfo->MaximumNumberOfTargets = 2;
  ConfigInfo->BufferAccessScsiPortControlled = TRUE;
  if (ConfigInfo->Dma64BitAddresses == SCSI_DMA64_SYSTEM_SUPPORTED)
  {
    ConfigInfo->Master = TRUE;
    ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;
    KdPrint((__DRIVER_NAME "     Dma64BitAddresses supported\n"));
  }
  else
  {
    ConfigInfo->Master = FALSE;
    KdPrint((__DRIVER_NAME "     Dma64BitAddresses not supported\n"));
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));  

  return SP_RETURN_FOUND;
}

static BOOLEAN DDKAPI
XenVbd_HwScsiInitialize(PVOID DeviceExtension)
{
  PXENVBD_DEVICE_DATA xvdd = (PXENVBD_DEVICE_DATA)DeviceExtension;
  blkif_request_t *req;
  int i;
  int notify;
  
  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  if (!dump_mode)
  {
    req = RING_GET_REQUEST(&xvdd->ring, xvdd->ring.req_prod_pvt);
    req->operation = 0xff;
    req->nr_segments = 0;
    for (i = 0; i < BLKIF_MAX_SEGMENTS_PER_REQUEST; i++)
    {
      req->seg[i].gref = 0; //0xffffffff;
      req->seg[i].first_sect = 0; //0xff;
      req->seg[i].last_sect = 0; //0xff;
    }
    xvdd->ring.req_prod_pvt++;

    req = RING_GET_REQUEST(&xvdd->ring, xvdd->ring.req_prod_pvt);
    req->operation = 0xff;
    req->nr_segments = 0;
    for (i = 0; i < BLKIF_MAX_SEGMENTS_PER_REQUEST; i++)
    {
      req->seg[i].gref = 0; //0xffffffff;
      req->seg[i].first_sect = 0; //0xff;
      req->seg[i].last_sect = 0; //0xff;
    }
    xvdd->ring.req_prod_pvt++;

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xvdd->ring, notify);
    if (notify)
      xvdd->vectors.EvtChn_Notify(xvdd->vectors.context, xvdd->event_channel);
    xvdd->ring_detect_state = 0;
  }
  else
  {
    if (xvdd->cached_use_other)
    {
      xvdd->ring.nr_ents = BLK_OTHER_RING_SIZE;
      xvdd->use_other = TRUE;
    }
    xvdd->ring_detect_state = 2;
  }
  
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

static ULONG
XenVbd_FillModePage(PXENVBD_DEVICE_DATA xvdd, PSCSI_REQUEST_BLOCK srb)
{
  PMODE_PARAMETER_HEADER parameter_header;
  PMODE_PARAMETER_BLOCK param_block;
  PMODE_FORMAT_PAGE format_page;
  ULONG offset;
  UCHAR buffer[256];
  BOOLEAN valid_page = FALSE;
  BOOLEAN cdb_llbaa;
  BOOLEAN cdb_dbd;
  UCHAR cdb_page_code;
  USHORT cdb_allocation_length;

  UNREFERENCED_PARAMETER(xvdd);

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  
  //cdb = (PCDB)srb->Cdb;
  switch (srb->Cdb[0])
  {
  case SCSIOP_MODE_SENSE:
    cdb_llbaa = FALSE;
    cdb_dbd = (BOOLEAN)!!(srb->Cdb[1] & 8);
    cdb_page_code = srb->Cdb[2] & 0x3f;
    cdb_allocation_length = srb->Cdb[4];
    KdPrint((__DRIVER_NAME "     SCSIOP_MODE_SENSE llbaa = %d, dbd = %d, page_code = %d, allocation_length = %d\n",
      cdb_llbaa, cdb_dbd, cdb_page_code, cdb_allocation_length));
    break;
  case SCSIOP_MODE_SENSE10:
    cdb_llbaa = (BOOLEAN)!!(srb->Cdb[1] & 16);
    cdb_dbd = (BOOLEAN)!!(srb->Cdb[1] & 8);
    cdb_page_code = srb->Cdb[2] & 0x3f;
    cdb_allocation_length = (srb->Cdb[7] << 8) | srb->Cdb[8];
    KdPrint((__DRIVER_NAME "     SCSIOP_MODE_SENSE10 llbaa = %d, dbd = %d, page_code = %d, allocation_length = %d\n",
      cdb_llbaa, cdb_dbd, cdb_page_code, cdb_allocation_length));
    break;
  default:
    KdPrint((__DRIVER_NAME "     SCSIOP_MODE_SENSE_WTF (%02x)\n", (ULONG)srb->Cdb[0]));
    return FALSE;
  }
  offset = 0;
  RtlZeroMemory(srb->DataBuffer, srb->DataTransferLength);
  RtlZeroMemory(buffer, ARRAY_SIZE(buffer));

  parameter_header = (PMODE_PARAMETER_HEADER)&buffer[offset];
  parameter_header->MediumType = 0;
  parameter_header->DeviceSpecificParameter = 0;
  parameter_header->BlockDescriptorLength = 0;
  offset += sizeof(MODE_PARAMETER_HEADER);
  
  if (xvdd->device_mode == XENVBD_DEVICEMODE_READ)
  {
    KdPrint((__DRIVER_NAME " Mode sense to a read only disk.\n"));
    parameter_header->DeviceSpecificParameter|=MODE_DSP_WRITE_PROTECT; 
  }
  
  if (!cdb_dbd)
  {
    parameter_header->BlockDescriptorLength += sizeof(MODE_PARAMETER_BLOCK);
    param_block = (PMODE_PARAMETER_BLOCK)&buffer[offset];
    if (xvdd->device_type == XENVBD_DEVICETYPE_DISK)
    {
      if (xvdd->total_sectors >> 32) 
      {
        param_block->DensityCode = 0xff;
        param_block->NumberOfBlocks[0] = 0xff;
        param_block->NumberOfBlocks[1] = 0xff;
        param_block->NumberOfBlocks[2] = 0xff;
      }
      else
      {
        param_block->DensityCode = (UCHAR)((xvdd->total_sectors >> 24) & 0xff);
        param_block->NumberOfBlocks[0] = (UCHAR)((xvdd->total_sectors >> 16) & 0xff);
        param_block->NumberOfBlocks[1] = (UCHAR)((xvdd->total_sectors >> 8) & 0xff);
        param_block->NumberOfBlocks[2] = (UCHAR)((xvdd->total_sectors >> 0) & 0xff);
      }
      param_block->BlockLength[0] = (UCHAR)((xvdd->bytes_per_sector >> 16) & 0xff);
      param_block->BlockLength[1] = (UCHAR)((xvdd->bytes_per_sector >> 8) & 0xff);
      param_block->BlockLength[2] = (UCHAR)((xvdd->bytes_per_sector >> 0) & 0xff);
    }
    offset += sizeof(MODE_PARAMETER_BLOCK);
  }
  if (xvdd->device_type == XENVBD_DEVICETYPE_DISK && (cdb_page_code == MODE_PAGE_FORMAT_DEVICE || cdb_page_code == MODE_SENSE_RETURN_ALL))
  {
    valid_page = TRUE;
    format_page = (PMODE_FORMAT_PAGE)&buffer[offset];
    format_page->PageCode = MODE_PAGE_FORMAT_DEVICE;
    format_page->PageLength = sizeof(MODE_FORMAT_PAGE) - FIELD_OFFSET(MODE_FORMAT_PAGE, PageLength);
    /* 256 sectors per track */
    format_page->SectorsPerTrack[0] = 0x01;
    format_page->SectorsPerTrack[1] = 0x00;
    /* xxx bytes per sector */
    format_page->BytesPerPhysicalSector[0] = (UCHAR)(xvdd->bytes_per_sector >> 8);
    format_page->BytesPerPhysicalSector[1] = (UCHAR)(xvdd->bytes_per_sector & 0xff);
    format_page->HardSectorFormating = TRUE;
    format_page->SoftSectorFormating = TRUE;
    offset += sizeof(MODE_FORMAT_PAGE);
  }
  parameter_header->ModeDataLength = (UCHAR)(offset - 1);
  if (!valid_page && cdb_page_code != MODE_SENSE_RETURN_ALL)
  {
    srb->SrbStatus = SRB_STATUS_ERROR;
  }
  else if(offset < srb->DataTransferLength)
    srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
  else
    srb->SrbStatus = SRB_STATUS_SUCCESS;
  srb->DataTransferLength = min(srb->DataTransferLength, offset);
  srb->ScsiStatus = 0;
  memcpy(srb->DataBuffer, buffer, srb->DataTransferLength);
  
  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

static VOID
XenVbd_MakeSense(PXENVBD_DEVICE_DATA xvdd, PSCSI_REQUEST_BLOCK srb, UCHAR sense_key, UCHAR additional_sense_code)
{
  PSENSE_DATA sd = srb->SenseInfoBuffer;
 
  UNREFERENCED_PARAMETER(xvdd);
  
  if (!srb->SenseInfoBuffer)
    return;
  
  sd->ErrorCode = 0x70;
  sd->Valid = 1;
  sd->SenseKey = sense_key;
  sd->AdditionalSenseLength = sizeof(SENSE_DATA) - FIELD_OFFSET(SENSE_DATA, AdditionalSenseLength);
  sd->AdditionalSenseCode = additional_sense_code;
  return;
}

static VOID
XenVbd_MakeAutoSense(PXENVBD_DEVICE_DATA xvdd, PSCSI_REQUEST_BLOCK srb)
{
  if (srb->SrbStatus == SRB_STATUS_SUCCESS || srb->SrbFlags & SRB_FLAGS_DISABLE_AUTOSENSE)
    return;
  XenVbd_MakeSense(xvdd, srb, xvdd->last_sense_key, xvdd->last_additional_sense_code);
  srb->SrbStatus |= SRB_STATUS_AUTOSENSE_VALID;
}

static BOOLEAN DDKAPI
XenVbd_HwScsiInterrupt(PVOID DeviceExtension)
{
  PXENVBD_DEVICE_DATA xvdd = (PXENVBD_DEVICE_DATA)DeviceExtension;
  PSCSI_REQUEST_BLOCK srb;
  RING_IDX i, rp;
  int j;
  blkif_response_t *rep;
  int block_count;
  int more_to_do = TRUE;
  blkif_shadow_t *shadow;
  ULONG offset;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stat_interrupts++;
  /* in dump mode I think we get called on a timer, not by an actual IRQ */
  if (!dump_mode && !xvdd->vectors.EvtChn_AckEvent(xvdd->vectors.context, xvdd->event_channel))
    return FALSE; /* interrupt was not for us */
  stat_interrupts_for_me++;
  if (xvdd->device_state->resume_state != xvdd->device_state->resume_state_ack)
  {
    FUNCTION_ENTER();
    switch (xvdd->device_state->resume_state)
    {
      case RESUME_STATE_SUSPENDING:
        KdPrint((__DRIVER_NAME "     New state SUSPENDING\n"));
        break;
      case RESUME_STATE_FRONTEND_RESUME:
        KdPrint((__DRIVER_NAME "     New state RESUME_STATE_FRONTEND_RESUME\n"));
        XenVbd_Resume(xvdd);
        break;
      default:
        KdPrint((__DRIVER_NAME "     New state %d\n", xvdd->device_state->resume_state));
        break;
    }
    xvdd->device_state->resume_state_ack = xvdd->device_state->resume_state;
    KeMemoryBarrier();
    FUNCTION_EXIT();
  }

  if (xvdd->device_state->resume_state != RESUME_STATE_RUNNING)
  {
    return FALSE;
  }

  if (!dump_mode && !(stat_interrupts_for_me & 0xFFFF))
    XenVbd_DumpStats();
    
  while (more_to_do)
  {
    rp = xvdd->ring.sring->rsp_prod;
    KeMemoryBarrier();
    for (i = xvdd->ring.rsp_cons; i < rp; i++)
    {
      rep = XenVbd_GetResponse(xvdd, i);
/*
* This code is to automatically detect if the backend is using the same
* bit width or a different bit width to us. Later versions of Xen do this
* via a xenstore value, but not all. That 0x0fffffff (notice
* that the msb is not actually set, so we don't have any problems with
* sign extending) is to signify the last entry on the right, which is
* different under 32 and 64 bits, and that is why we set it up there.

* To do the detection, we put two initial entries on the ring, with an op
* of 0xff (which is invalid). The first entry is mostly okay, but the
* second will be grossly misaligned if the backend bit width is different,
* and we detect this and switch frontend structures.
*/
      switch (xvdd->ring_detect_state)
      {
      case 0:
        KdPrint((__DRIVER_NAME "     ring_detect_state = %d, operation = %x, id = %lx, status = %d\n", xvdd->ring_detect_state, rep->operation, rep->id, rep->status));
        xvdd->ring_detect_state = 1;
        break;
      case 1:
        KdPrint((__DRIVER_NAME "     ring_detect_state = %d, operation = %x, id = %lx, status = %d\n", xvdd->ring_detect_state, rep->operation, rep->id, rep->status));
        *xvdd->event_channel_ptr |= 0x80000000;
        if (rep->operation != 0xff)
        {
          xvdd->ring.nr_ents = BLK_OTHER_RING_SIZE;
          xvdd->use_other = TRUE;
          *xvdd->event_channel_ptr |= 0x40000000;
        }
        xvdd->ring_detect_state = 2;
        ScsiPortNotification(NextRequest, DeviceExtension);
        break;
      case 2:
        //KdPrint((__DRIVER_NAME "     ring_detect_state = %d, operation = %x, id = %lx, status = %d\n", xvdd->ring_detect_state, rep->operation, rep->id, rep->status));
        shadow = &xvdd->shadows[rep->id];
        srb = shadow->srb;
        ASSERT(srb != NULL);
        block_count = decode_cdb_length(srb);
        block_count *= xvdd->bytes_per_sector / 512;
        if (rep->status == BLKIF_RSP_OKAY)
          srb->SrbStatus = SRB_STATUS_SUCCESS;
        else
        {
          KdPrint((__DRIVER_NAME "     Xen Operation returned error\n"));
          if (decode_cdb_is_read(srb))
            KdPrint((__DRIVER_NAME "     Operation = Read\n"));
          else
            KdPrint((__DRIVER_NAME "     Operation = Write\n"));
          KdPrint((__DRIVER_NAME "     Sector = %08X, Count = %d\n", (ULONG)shadow->req.sector_number, block_count));
          srb->SrbStatus = SRB_STATUS_ERROR;
          srb->ScsiStatus = 0x02;
          xvdd->last_sense_key = SCSI_SENSE_MEDIUM_ERROR;
          xvdd->last_additional_sense_code = SCSI_ADSENSE_NO_SENSE;
          XenVbd_MakeAutoSense(xvdd, srb);
        }
        for (j = 0; j < shadow->req.nr_segments; j++)
        {
#if DBG
          BOOLEAN result = 
#endif
              xvdd->vectors.GntTbl_EndAccess(xvdd->vectors.context, shadow->req.seg[j].gref, TRUE);
#if DBG
          ASSERT(result);
#endif
          put_grant_on_freelist(xvdd, shadow->req.seg[j].gref);
        }

        if (PtrToUlong(srb->DataBuffer) & 511) /* use SrbExtension intead of DataBuffer if DataBuffer is not aligned to sector size */
        {
          if (decode_cdb_is_read(srb))
            memcpy(((PUCHAR)srb->DataBuffer) + shadow->offset, GET_PAGE_ALIGNED(srb->SrbExtension), shadow->length);
          offset = shadow->offset + shadow->length;
          put_shadow_on_freelist(xvdd, shadow);
          if (offset == (ULONG)block_count * 512)
          {
            ScsiPortNotification(RequestComplete, xvdd, srb);
            stat_outstanding_requests--;
            ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
          }
          else
          {
            XenVbd_PutSrbOnRing(xvdd, srb, offset);
          }
        }
        else
        {
          put_shadow_on_freelist(xvdd, shadow);
          ScsiPortNotification(RequestComplete, xvdd, srb);
          stat_outstanding_requests--;
          if (xvdd->pending_srb)
          {
            srb = xvdd->pending_srb;
            xvdd->pending_srb = NULL;
            XenVbd_PutSrbOnRing(xvdd, srb, 0);
          }
          else
            ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
        }
        break;
      }
    }

    xvdd->ring.rsp_cons = i;
    if (i != xvdd->ring.req_prod_pvt)
    {
      RING_FINAL_CHECK_FOR_RESPONSES(&xvdd->ring, more_to_do);
    }
    else
    {
      xvdd->ring.sring->rsp_event = i + 1;
      more_to_do = FALSE;
    }
  }

  //KdPrint((__DRIVER_NAME "     ring.sring->rsp_prod = %d\n", xvdd->ring.sring->rsp_prod));
  //KdPrint((__DRIVER_NAME "     ring.sring->rsp_event = %d\n", xvdd->ring.sring->rsp_event));
  //KdPrint((__DRIVER_NAME "     ring.rsp_cons = %d\n", xvdd->ring.rsp_cons));
  //KdPrint((__DRIVER_NAME "     ring.req_prod_pvt = %d\n", xvdd->ring.req_prod_pvt));

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return FALSE; /* always fall through to the next ISR... */
}

static BOOLEAN DDKAPI
XenVbd_HwScsiStartIo(PVOID DeviceExtension, PSCSI_REQUEST_BLOCK Srb)
{
  PUCHAR DataBuffer;
  PCDB cdb;
  PXENVBD_DEVICE_DATA xvdd = DeviceExtension;

  //KdPrint((__DRIVER_NAME " --> HwScsiStartIo PathId = %d, TargetId = %d, Lun = %d\n", Srb->PathId, Srb->TargetId, Srb->Lun));

  if (xvdd->inactive)
  {
    Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension);
    return TRUE;
  }
  
  // If we haven't enumerated all the devices yet then just defer the request
  if (xvdd->ring_detect_state < 2)
  {
    Srb->SrbStatus = SRB_STATUS_BUSY;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    KdPrint((__DRIVER_NAME " --- HwScsiStartIo (Still figuring out ring)\n"));
    return TRUE;
  }

  if (xvdd->device_state->resume_state != RESUME_STATE_RUNNING)
  {
    KdPrint((__DRIVER_NAME " --> HwScsiStartIo (Resuming)\n"));
    Srb->SrbStatus = SRB_STATUS_BUSY;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    KdPrint((__DRIVER_NAME " <-- HwScsiStartIo (Resuming)\n"));
    return TRUE;
  }

  if (Srb->PathId != 0 || Srb->TargetId != 0)
  {
    Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension);
    KdPrint((__DRIVER_NAME " --- HwScsiStartIo (Out of bounds)\n"));
    return TRUE;
  }

  switch (Srb->Function)
  {
  case SRB_FUNCTION_EXECUTE_SCSI:
    cdb = (PCDB)Srb->Cdb;
//    KdPrint((__DRIVER_NAME "     SRB_FUNCTION_EXECUTE_SCSI\n"));

    switch(cdb->CDB6GENERIC.OperationCode)
    {
    case SCSIOP_TEST_UNIT_READY:
      //KdPrint((__DRIVER_NAME "     Command = TEST_UNIT_READY\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      Srb->ScsiStatus = 0;
      break;
    case SCSIOP_INQUIRY:
//      KdPrint((__DRIVER_NAME "     Command = INQUIRY\n"));
//      KdPrint((__DRIVER_NAME "     (LUN = %d, EVPD = %d, Page Code = %02X)\n", Srb->Cdb[1] >> 5, Srb->Cdb[1] & 1, Srb->Cdb[2]));
//      KdPrint((__DRIVER_NAME "     (Length = %d)\n", Srb->DataTransferLength));
//      KdPrint((__DRIVER_NAME "     (Srb->Databuffer = %08x)\n", Srb->DataBuffer));
      DataBuffer = Srb->DataBuffer;
      RtlZeroMemory(DataBuffer, Srb->DataTransferLength);
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      switch (xvdd->device_type)
      {
      case XENVBD_DEVICETYPE_DISK:
        if ((Srb->Cdb[1] & 1) == 0)
        {
          PINQUIRYDATA id = (PINQUIRYDATA)DataBuffer;
          id->DeviceType = DIRECT_ACCESS_DEVICE;
          id->Versions = 3;
          id->ResponseDataFormat = 0;
          id->AdditionalLength = FIELD_OFFSET(INQUIRYDATA, VendorSpecific) - FIELD_OFFSET(INQUIRYDATA, AdditionalLength);
          id->CommandQueue = 1;
          memcpy(id->VendorId, "XEN     ", 8); // vendor id
          memcpy(id->ProductId, "PV DISK         ", 16); // product id
          memcpy(id->ProductRevisionLevel, "0000", 4); // product revision level
        }
        else
        {
          switch (Srb->Cdb[2])
          {
          case 0x00:
            DataBuffer[0] = DIRECT_ACCESS_DEVICE;
            DataBuffer[1] = 0x00;
            DataBuffer[2] = 0x00;
            DataBuffer[3] = 2;
            DataBuffer[4] = 0x00;
            DataBuffer[5] = 0x80;
            break;
          case 0x80:
            DataBuffer[0] = DIRECT_ACCESS_DEVICE;
            DataBuffer[1] = 0x80;
            DataBuffer[2] = 0x00;
            DataBuffer[3] = 8;
            memset(&DataBuffer[4], ' ', 8);
            break;
          default:
            //KdPrint((__DRIVER_NAME "     Unknown Page %02x requested\n", Srb->Cdb[2]));
            Srb->SrbStatus = SRB_STATUS_ERROR;
            break;
          }
        }
        break;
      case XENVBD_DEVICETYPE_CDROM:
        if ((Srb->Cdb[1] & 1) == 0)
        {
          PINQUIRYDATA id = (PINQUIRYDATA)DataBuffer;
          id->DeviceType = READ_ONLY_DIRECT_ACCESS_DEVICE;
          id->RemovableMedia = 1;
          id->Versions = 3;
          id->ResponseDataFormat = 0;
          id->AdditionalLength = FIELD_OFFSET(INQUIRYDATA, VendorSpecific) - FIELD_OFFSET(INQUIRYDATA, AdditionalLength);
          id->CommandQueue = 1;
          memcpy(id->VendorId, "XEN     ", 8); // vendor id
          memcpy(id->ProductId, "PV CDROM        ", 16); // product id
          memcpy(id->ProductRevisionLevel, "0000", 4); // product revision level
        }
        else
        {
          switch (Srb->Cdb[2])
          {
          case 0x00:
            DataBuffer[0] = READ_ONLY_DIRECT_ACCESS_DEVICE;
            DataBuffer[1] = 0x00;
            DataBuffer[2] = 0x00;
            DataBuffer[3] = 2;
            DataBuffer[4] = 0x00;
            DataBuffer[5] = 0x80;
            break;
          case 0x80:
            DataBuffer[0] = READ_ONLY_DIRECT_ACCESS_DEVICE;
            DataBuffer[1] = 0x80;
            DataBuffer[2] = 0x00;
            DataBuffer[3] = 8;
            DataBuffer[4] = 0x31;
            DataBuffer[5] = 0x32;
            DataBuffer[6] = 0x33;
            DataBuffer[7] = 0x34;
            DataBuffer[8] = 0x35;
            DataBuffer[9] = 0x36;
            DataBuffer[10] = 0x37;
            DataBuffer[11] = 0x38;
            break;
          default:
            //KdPrint((__DRIVER_NAME "     Unknown Page %02x requested\n", Srb->Cdb[2]));
            Srb->SrbStatus = SRB_STATUS_ERROR;
            break;
          }
        }
        break;
      default:
        //KdPrint((__DRIVER_NAME "     Unknown DeviceType %02x requested\n", xvdd->device_type));
        Srb->SrbStatus = SRB_STATUS_ERROR;
        break;
      }
      break;
    case SCSIOP_READ_CAPACITY:
      //KdPrint((__DRIVER_NAME "     Command = READ_CAPACITY\n"));
      //KdPrint((__DRIVER_NAME "       LUN = %d, RelAdr = %d\n", Srb->Cdb[1] >> 4, Srb->Cdb[1] & 1));
      //KdPrint((__DRIVER_NAME "       LBA = %02x%02x%02x%02x\n", Srb->Cdb[2], Srb->Cdb[3], Srb->Cdb[4], Srb->Cdb[5]));
      //KdPrint((__DRIVER_NAME "       PMI = %d\n", Srb->Cdb[8] & 1));
      DataBuffer = Srb->DataBuffer;
      RtlZeroMemory(DataBuffer, Srb->DataTransferLength);
      if ((xvdd->total_sectors - 1) >> 32)
      {
        DataBuffer[0] = 0xff;
        DataBuffer[1] = 0xff;
        DataBuffer[2] = 0xff;
        DataBuffer[3] = 0xff;
      }
      else
      {
        DataBuffer[0] = (unsigned char)((xvdd->total_sectors - 1) >> 24) & 0xff;
        DataBuffer[1] = (unsigned char)((xvdd->total_sectors - 1) >> 16) & 0xff;
        DataBuffer[2] = (unsigned char)((xvdd->total_sectors - 1) >> 8) & 0xff;
        DataBuffer[3] = (unsigned char)((xvdd->total_sectors - 1) >> 0) & 0xff;
      }
      DataBuffer[4] = (unsigned char)(xvdd->bytes_per_sector >> 24) & 0xff;
      DataBuffer[5] = (unsigned char)(xvdd->bytes_per_sector >> 16) & 0xff;
      DataBuffer[6] = (unsigned char)(xvdd->bytes_per_sector >> 8) & 0xff;
      DataBuffer[7] = (unsigned char)(xvdd->bytes_per_sector >> 0) & 0xff;
      Srb->ScsiStatus = 0;
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;
    case SCSIOP_READ_CAPACITY16:
      //KdPrint((__DRIVER_NAME "     Command = READ_CAPACITY\n"));
      //KdPrint((__DRIVER_NAME "       LUN = %d, RelAdr = %d\n", Srb->Cdb[1] >> 4, Srb->Cdb[1] & 1));
      //KdPrint((__DRIVER_NAME "       LBA = %02x%02x%02x%02x\n", Srb->Cdb[2], Srb->Cdb[3], Srb->Cdb[4], Srb->Cdb[5]));
      //KdPrint((__DRIVER_NAME "       PMI = %d\n", Srb->Cdb[8] & 1));
      DataBuffer = Srb->DataBuffer;
      RtlZeroMemory(DataBuffer, Srb->DataTransferLength);
      DataBuffer[0] = (unsigned char)((xvdd->total_sectors - 1) >> 56) & 0xff;
      DataBuffer[1] = (unsigned char)((xvdd->total_sectors - 1) >> 48) & 0xff;
      DataBuffer[2] = (unsigned char)((xvdd->total_sectors - 1) >> 40) & 0xff;
      DataBuffer[3] = (unsigned char)((xvdd->total_sectors - 1) >> 32) & 0xff;
      DataBuffer[4] = (unsigned char)((xvdd->total_sectors - 1) >> 24) & 0xff;
      DataBuffer[5] = (unsigned char)((xvdd->total_sectors - 1) >> 16) & 0xff;
      DataBuffer[6] = (unsigned char)((xvdd->total_sectors - 1) >> 8) & 0xff;
      DataBuffer[7] = (unsigned char)((xvdd->total_sectors - 1) >> 0) & 0xff;
      DataBuffer[8] = (unsigned char)(xvdd->bytes_per_sector >> 24) & 0xff;
      DataBuffer[9] = (unsigned char)(xvdd->bytes_per_sector >> 16) & 0xff;
      DataBuffer[10] = (unsigned char)(xvdd->bytes_per_sector >> 8) & 0xff;
      DataBuffer[11] = (unsigned char)(xvdd->bytes_per_sector >> 0) & 0xff;
      Srb->ScsiStatus = 0;
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;
    case SCSIOP_MODE_SENSE:
    case SCSIOP_MODE_SENSE10:
//      KdPrint((__DRIVER_NAME "     Command = MODE_SENSE (DBD = %d, PC = %d, Page Code = %02x)\n", Srb->Cdb[1] & 0x08, Srb->Cdb[2] & 0xC0, Srb->Cdb[2] & 0x3F));
      XenVbd_FillModePage(xvdd, Srb);
      break;
    case SCSIOP_READ:
    case SCSIOP_READ16:
    case SCSIOP_WRITE:
    case SCSIOP_WRITE16:
//      KdPrint((__DRIVER_NAME "     Command = READ/WRITE\n"));
      XenVbd_PutSrbOnRing(xvdd, Srb, 0);
      break;
    case SCSIOP_VERIFY:
      // Should we do more here?
//      KdPrint((__DRIVER_NAME "     Command = VERIFY\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;
    case SCSIOP_REPORT_LUNS:
//      KdPrint((__DRIVER_NAME "     Command = REPORT_LUNS\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;;
      break;
    case SCSIOP_REQUEST_SENSE:
//      KdPrint((__DRIVER_NAME "     Command = REQUEST_SENSE\n"));
      XenVbd_MakeSense(xvdd, Srb, xvdd->last_sense_key, xvdd->last_additional_sense_code);
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;      
    case SCSIOP_READ_TOC:
      DataBuffer = Srb->DataBuffer;
//      DataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, HighPagePriority);
/*
#define READ_TOC_FORMAT_TOC         0x00
#define READ_TOC_FORMAT_SESSION     0x01
#define READ_TOC_FORMAT_FULL_TOC    0x02
#define READ_TOC_FORMAT_PMA         0x03
#define READ_TOC_FORMAT_ATIP        0x04
*/
//      KdPrint((__DRIVER_NAME "     Command = READ_TOC\n"));
//      KdPrint((__DRIVER_NAME "     Msf = %d\n", cdb->READ_TOC.Msf));
//      KdPrint((__DRIVER_NAME "     LogicalUnitNumber = %d\n", cdb->READ_TOC.LogicalUnitNumber));
//      KdPrint((__DRIVER_NAME "     Format2 = %d\n", cdb->READ_TOC.Format2));
//      KdPrint((__DRIVER_NAME "     StartingTrack = %d\n", cdb->READ_TOC.StartingTrack));
//      KdPrint((__DRIVER_NAME "     AllocationLength = %d\n", (cdb->READ_TOC.AllocationLength[0] << 8) | cdb->READ_TOC.AllocationLength[1]));
//      KdPrint((__DRIVER_NAME "     Control = %d\n", cdb->READ_TOC.Control));
//      KdPrint((__DRIVER_NAME "     Format = %d\n", cdb->READ_TOC.Format));
      switch (cdb->READ_TOC.Format2)
      {
      case READ_TOC_FORMAT_TOC:
        DataBuffer[0] = 0; // length MSB
        DataBuffer[1] = 10; // length LSB
        DataBuffer[2] = 1; // First Track
        DataBuffer[3] = 1; // Last Track
        DataBuffer[4] = 0; // Reserved
        DataBuffer[5] = 0x14; // current position data + uninterrupted data
        DataBuffer[6] = 1; // last complete track
        DataBuffer[7] = 0; // reserved
        DataBuffer[8] = 0; // MSB Block
        DataBuffer[9] = 0;
        DataBuffer[10] = 0;
        DataBuffer[11] = 0; // LSB Block
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
      case READ_TOC_FORMAT_SESSION:
      case READ_TOC_FORMAT_FULL_TOC:
      case READ_TOC_FORMAT_PMA:
      case READ_TOC_FORMAT_ATIP:
        Srb->SrbStatus = SRB_STATUS_ERROR;
        break;
      }
      break;
    case SCSIOP_START_STOP_UNIT:
//      KdPrint((__DRIVER_NAME "     Command = SCSIOP_START_STOP_UNIT\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;
    case SCSIOP_RESERVE_UNIT:
//      KdPrint((__DRIVER_NAME "     Command = SCSIOP_RESERVE_UNIT\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;
    case SCSIOP_RELEASE_UNIT:
//      KdPrint((__DRIVER_NAME "     Command = SCSIOP_RELEASE_UNIT\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;
    default:
      KdPrint((__DRIVER_NAME "     Unhandled EXECUTE_SCSI Command = %02X\n", Srb->Cdb[0]));
      Srb->SrbStatus = SRB_STATUS_ERROR;
      break;
    }
    if (Srb->SrbStatus == SRB_STATUS_ERROR)
    {
      //KdPrint((__DRIVER_NAME "     EXECUTE_SCSI Command = %02X returned error %02x\n", Srb->Cdb[0], xvdd->last_sense_key));
      if (xvdd->last_sense_key == SCSI_SENSE_NO_SENSE)
      {
        xvdd->last_sense_key = SCSI_SENSE_ILLEGAL_REQUEST;
        xvdd->last_additional_sense_code = SCSI_ADSENSE_INVALID_CDB;
      }
      Srb->ScsiStatus = 0x02;
      XenVbd_MakeAutoSense(xvdd, Srb);
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
    }
    else if (Srb->SrbStatus != SRB_STATUS_PENDING)
    {
      xvdd->last_sense_key = SCSI_SENSE_NO_SENSE;
      xvdd->last_additional_sense_code = SCSI_ADSENSE_NO_SENSE;
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
    }
    break;
  case SRB_FUNCTION_IO_CONTROL:
    //KdPrint((__DRIVER_NAME "     SRB_FUNCTION_IO_CONTROL\n"));
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
    break;
  case SRB_FUNCTION_FLUSH:
    //KdPrint((__DRIVER_NAME "     SRB_FUNCTION_FLUSH\n"));
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unhandled Srb->Function = %08X\n", Srb->Function));
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
    break;
  }

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return TRUE;
}

static BOOLEAN DDKAPI
XenVbd_HwScsiResetBus(PVOID DeviceExtension, ULONG PathId)
{
  PXENVBD_DEVICE_DATA xvdd = DeviceExtension;

  UNREFERENCED_PARAMETER(DeviceExtension);
  UNREFERENCED_PARAMETER(PathId);

  KdPrint((__DRIVER_NAME " --> HwScsiResetBus\n"));

  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));
  if (xvdd->ring_detect_state == 2 && xvdd->device_state->resume_state == RESUME_STATE_RUNNING)
  {
    ScsiPortNotification(NextRequest, DeviceExtension);
  }

  KdPrint((__DRIVER_NAME " <-- HwScsiResetBus\n"));


  return TRUE;
}

static BOOLEAN DDKAPI
XenVbd_HwScsiAdapterState(PVOID DeviceExtension, PVOID Context, BOOLEAN SaveState)
{
  UNREFERENCED_PARAMETER(DeviceExtension);
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(SaveState);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

static SCSI_ADAPTER_CONTROL_STATUS DDKAPI
XenVbd_HwScsiAdapterControl(PVOID DeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters)
{
  SCSI_ADAPTER_CONTROL_STATUS Status = ScsiAdapterControlSuccess;
  PSCSI_SUPPORTED_CONTROL_TYPE_LIST SupportedControlTypeList;
  //KIRQL OldIrql;

  UNREFERENCED_PARAMETER(DeviceExtension);

  KdPrint((__DRIVER_NAME " --> HwScsiAdapterControl\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  switch (ControlType)
  {
  case ScsiQuerySupportedControlTypes:
    SupportedControlTypeList = (PSCSI_SUPPORTED_CONTROL_TYPE_LIST)Parameters;
    KdPrint((__DRIVER_NAME "     ScsiQuerySupportedControlTypes (Max = %d)\n", SupportedControlTypeList->MaxControlType));
    SupportedControlTypeList->SupportedTypeList[ScsiQuerySupportedControlTypes] = TRUE;
    SupportedControlTypeList->SupportedTypeList[ScsiStopAdapter] = TRUE;
    SupportedControlTypeList->SupportedTypeList[ScsiRestartAdapter] = TRUE;
    break;
  case ScsiStopAdapter:
    KdPrint((__DRIVER_NAME "     ScsiStopAdapter\n"));
    /* I don't think we actually have to do anything here... xenpci cleans up all the xenbus stuff for us */
    break;
  case ScsiRestartAdapter:
    KdPrint((__DRIVER_NAME "     ScsiRestartAdapter\n"));
    break;
  case ScsiSetBootConfig:
    KdPrint((__DRIVER_NAME "     ScsiSetBootConfig\n"));
    break;
  case ScsiSetRunningConfig:
    KdPrint((__DRIVER_NAME "     ScsiSetRunningConfig\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     UNKNOWN\n"));
    break;
  }

  KdPrint((__DRIVER_NAME " <-- HwScsiAdapterControl\n"));

  return Status;
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  ULONG status;
  HW_INITIALIZATION_DATA HwInitializationData;
  PVOID driver_extension;
  PUCHAR ptr;

  FUNCTION_ENTER();
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));
  KdPrint((__DRIVER_NAME "     DriverObject = %p\n", DriverObject));

  IoAllocateDriverObjectExtension(DriverObject, UlongToPtr(XEN_INIT_DRIVER_EXTENSION_MAGIC), PAGE_SIZE, &driver_extension);
  ptr = driver_extension;
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_RUN, NULL, NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_RING, "ring-ref", NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_EVENT_CHANNEL_IRQ, "event-channel", NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_FRONT, "device-type", NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_BACK, "mode", NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_BACK, "sectors", NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_BACK, "sector-size", NULL);
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_GRANT_ENTRIES, NULL, UlongToPtr(144));
  ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_END, NULL, NULL);       

  /* RegistryPath == NULL when we are invoked as a crash dump driver */
  if (!RegistryPath)
  {
    dump_mode = TRUE;
  }
  RtlZeroMemory(&HwInitializationData, sizeof(HW_INITIALIZATION_DATA));

  HwInitializationData.HwInitializationDataSize = sizeof(HW_INITIALIZATION_DATA);
  HwInitializationData.AdapterInterfaceType = Internal;
  HwInitializationData.DeviceExtensionSize = sizeof(XENVBD_DEVICE_DATA);
  HwInitializationData.SpecificLuExtensionSize = 0;
  /* SrbExtension is not always aligned to a page boundary, so we add PAGE_SIZE-1 to it to make sure we have at least UNALIGNED_DOUBLE_BUFFER_SIZE bytes of page aligned memory */
  HwInitializationData.SrbExtensionSize = UNALIGNED_DOUBLE_BUFFER_SIZE + PAGE_SIZE - 1;
  HwInitializationData.NumberOfAccessRanges = 1;
  HwInitializationData.MapBuffers = TRUE;
  HwInitializationData.NeedPhysicalAddresses = FALSE;
  HwInitializationData.TaggedQueuing = FALSE;
  HwInitializationData.AutoRequestSense = TRUE;
  HwInitializationData.MultipleRequestPerLu = TRUE;
  HwInitializationData.ReceiveEvent = FALSE;
  HwInitializationData.VendorIdLength = 0;
  HwInitializationData.VendorId = NULL;
  HwInitializationData.DeviceIdLength = 0;
  HwInitializationData.DeviceId = NULL;

  HwInitializationData.HwInitialize = XenVbd_HwScsiInitialize;
  HwInitializationData.HwStartIo = XenVbd_HwScsiStartIo;
  HwInitializationData.HwInterrupt = XenVbd_HwScsiInterrupt;
  HwInitializationData.HwFindAdapter = XenVbd_HwScsiFindAdapter;
  HwInitializationData.HwResetBus = XenVbd_HwScsiResetBus;
  HwInitializationData.HwDmaStarted = NULL;
  HwInitializationData.HwAdapterState = XenVbd_HwScsiAdapterState;
  HwInitializationData.HwAdapterControl = XenVbd_HwScsiAdapterControl;

  status = ScsiPortInitialize(DriverObject, RegistryPath, &HwInitializationData, NULL);
  
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME " ScsiPortInitialize failed with status 0x%08x\n", status));
  }

  FUNCTION_EXIT();

  return status;
}

