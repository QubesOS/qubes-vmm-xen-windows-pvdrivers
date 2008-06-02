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

#if defined(__x86_64__)
  #define GET_PAGE_ALIGNED(ptr) ((PVOID)(((ULONGLONG)ptr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)))
#else
  #define GET_PAGE_ALIGNED(ptr) UlongToPtr((PtrToUlong(ptr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#endif

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
XenVbd_HwScsiTimer(PVOID DeviceExtension)
{
  PXENVBD_DEVICE_DATA xvdd = (PXENVBD_DEVICE_DATA)DeviceExtension;

  KdPrint((__DRIVER_NAME "     shadow_min_free = %d\n", xvdd->shadow_min_free));
  xvdd->shadow_min_free = xvdd->shadow_free;
  ScsiPortNotification(RequestTimerCall, DeviceExtension, XenVbd_HwScsiTimer, 1 * 1000 * 1000);
}

static ULONG
XenVbd_HwScsiFindAdapter(PVOID DeviceExtension, PVOID HwContext, PVOID BusInformation, PCHAR ArgumentString, PPORT_CONFIGURATION_INFORMATION ConfigInfo, PBOOLEAN Again)
{
  ULONG i;
//  PACCESS_RANGE AccessRange;
  PXENVBD_DEVICE_DATA xvdd = (PXENVBD_DEVICE_DATA)DeviceExtension;
//  ULONG status;
//  PXENPCI_XEN_DEVICE_DATA XenDeviceData;
  PACCESS_RANGE access_range;
  PUCHAR ptr;
  USHORT type;
  PCHAR setting, value;
  blkif_sring_t *sring;

  UNREFERENCED_PARAMETER(HwContext);
  UNREFERENCED_PARAMETER(BusInformation);
  UNREFERENCED_PARAMETER(ArgumentString);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));  
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  *Again = FALSE;

  KdPrint((__DRIVER_NAME "     BusInterruptLevel = %d\n", ConfigInfo->BusInterruptLevel));
  KdPrint((__DRIVER_NAME "     BusInterruptVector = %03x\n", ConfigInfo->BusInterruptVector));

  if (ConfigInfo->NumberOfAccessRanges != 1)
  {
    KdPrint((__DRIVER_NAME "     NumberOfAccessRanges = %d\n", ConfigInfo->NumberOfAccessRanges));    
    return SP_RETURN_BAD_CONFIG;
  }

  access_range = &((*(ConfigInfo->AccessRanges))[0]);

  KdPrint((__DRIVER_NAME "     RangeStart = %08x, RangeLength = %08x\n",
    access_range->RangeStart.LowPart, access_range->RangeLength));

  ptr = ScsiPortGetDeviceBase(
    DeviceExtension,
    ConfigInfo->AdapterInterfaceType,
    ConfigInfo->SystemIoBusNumber,
    access_range->RangeStart,
    access_range->RangeLength,
    !access_range->RangeInMemory);
  //ptr = MmMapIoSpace(access_range->RangeStart, access_range->RangeLength, MmCached);
  if (ptr == NULL)
  {
    KdPrint((__DRIVER_NAME "     Unable to map range\n"));
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));  
    return SP_RETURN_BAD_CONFIG;
  }

  xvdd->device_type = XENVBD_DEVICETYPE_UNKNOWN;
  sring = NULL;
  xvdd->event_channel = 0;
  while((type = GET_XEN_INIT_RSP(&ptr, &setting, &value)) != XEN_INIT_TYPE_END)
  {
    switch(type)
    {
    case XEN_INIT_TYPE_RING: /* frontend ring */
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_RING - %s = %p\n", setting, value));
      if (strcmp(setting, "ring-ref") == 0)
      {
        sring = (blkif_sring_t *)value;
        FRONT_RING_INIT(&xvdd->ring, sring, PAGE_SIZE);
        /* this bit is for when we have to take over an existing ring on a bug check */
        xvdd->ring.req_prod_pvt = sring->req_prod;
        xvdd->ring.rsp_cons = sring->rsp_prod;
      }
      break;
    case XEN_INIT_TYPE_EVENT_CHANNEL: /* frontend event channel */
    case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ: /* frontend event channel */
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_EVENT_CHANNEL - %s = %d\n", setting, PtrToUlong(value)));
      if (strcmp(setting, "event-channel") == 0)
      {
        xvdd->event_channel = PtrToUlong(value);
      }
      break;
    case XEN_INIT_TYPE_READ_STRING_BACK:
    case XEN_INIT_TYPE_READ_STRING_FRONT:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = %s\n", setting, value));
      if (strcmp(setting, "sectors") == 0)
        xvdd->total_sectors = atoi(value);
      else if (strcmp(setting, "sector-size") == 0)
        xvdd->bytes_per_sector = atoi(value);
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
      if (PtrToUlong(setting) != GRANT_ENTRIES)
      {
        KdPrint((__DRIVER_NAME "     grant entries mismatch\n"));
        KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
        return SP_RETURN_BAD_CONFIG;
      }
      else
      {
        memcpy(&xvdd->grant_free_list, value, sizeof(ULONG) * PtrToUlong(setting));
        xvdd->grant_free = GRANT_ENTRIES;
      }
      break;
    default:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_%d\n", type));
      break;
    }
  }
  if (xvdd->device_type == XENVBD_DEVICETYPE_UNKNOWN
    || sring == NULL
    || xvdd->event_channel == 0)
  {
    KdPrint((__DRIVER_NAME "     Missing settings\n"));
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
    return SP_RETURN_BAD_CONFIG;
  }
  ConfigInfo->MaximumTransferLength = BLKIF_MAX_SEGMENTS_PER_REQUEST * PAGE_SIZE;
  ConfigInfo->NumberOfPhysicalBreaks = BLKIF_MAX_SEGMENTS_PER_REQUEST - 1;
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

  xvdd->ring_detect_state = 0;

  xvdd->shadow_free = 0;
  memset(xvdd->shadows, 0, sizeof(blkif_shadow_t) * SHADOW_ENTRIES);
  for (i = 0; i < SHADOW_ENTRIES; i++)
  {
    xvdd->shadows[i].req.id = i;
    put_shadow_on_freelist(xvdd, &xvdd->shadows[i]);
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));  

  return SP_RETURN_FOUND;
}

static BOOLEAN
XenVbd_HwScsiInitialize(PVOID DeviceExtension)
{
  PXENVBD_DEVICE_DATA xvdd = (PXENVBD_DEVICE_DATA)DeviceExtension;
  blkif_request_t *req;
  int i;
  int notify;
  
  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  req = RING_GET_REQUEST(&xvdd->ring, xvdd->ring.req_prod_pvt);
  req->operation = 0xff;
  req->nr_segments = 0;
  for (i = 0; i < req->nr_segments; i++)
  {
    req->seg[i].gref = 0xffffffff;
    req->seg[i].first_sect = 0xff;
    req->seg[i].last_sect = 0xff;
  }
  xvdd->ring.req_prod_pvt++;

  req = RING_GET_REQUEST(&xvdd->ring, xvdd->ring.req_prod_pvt);
  req->operation = 0xff;
  req->nr_segments = 0;
  for (i = 0; i < req->nr_segments; i++)
  {
    req->seg[i].gref = 0xffffffff;
    req->seg[i].first_sect = 0xff;
    req->seg[i].last_sect = 0xff;
  }
  xvdd->ring.req_prod_pvt++;

  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xvdd->ring, notify);
  if (notify)
    xvdd->vectors.EvtChn_Notify(xvdd->vectors.context, xvdd->event_channel);

  xvdd->shadow_min_free = xvdd->shadow_free;
  ScsiPortNotification(RequestTimerCall, DeviceExtension, XenVbd_HwScsiTimer, 1 * 1000 * 1000);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

static VOID
XenVbd_PutRequest(PXENVBD_DEVICE_DATA xvdd, blkif_request_t *req)
{
  blkif_other_request_t *other_req;

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

// can use SRB_STATUS_BUSY to push the SRB back to windows...

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  ASSERT(!xvdd->pending_srb);
  
  block_count = (srb->Cdb[7] << 8) | srb->Cdb[8];
  if (PtrToUlong(srb->DataBuffer) & 511) /* use SrbExtension intead of DataBuffer if DataBuffer is not aligned to sector size */
  {
    ptr = GET_PAGE_ALIGNED(srb->SrbExtension);
    transfer_length = min(block_count * xvdd->bytes_per_sector - srb_offset, UNALIGNED_DOUBLE_BUFFER_SIZE);
  }
  else
  {
    ptr = srb->DataBuffer;
    transfer_length = block_count * xvdd->bytes_per_sector;
  }
  if (xvdd->grant_free <= ADDRESS_AND_SIZE_TO_SPAN_PAGES(ptr, transfer_length))
  {
    xvdd->pending_srb = srb;
    return;
  }
  
  shadow = get_shadow_from_freelist(xvdd);
  ASSERT(shadow);
  shadow->req.sector_number = (srb->Cdb[2] << 24) | (srb->Cdb[3] << 16) | (srb->Cdb[4] << 8) | srb->Cdb[5];
  shadow->req.handle = 0;
  shadow->req.operation = (srb->Cdb[0] == SCSIOP_READ)?BLKIF_OP_READ:BLKIF_OP_WRITE;
  shadow->req.nr_segments = 0;
  shadow->offset = srb_offset;
  shadow->length = transfer_length;
  shadow->srb = srb;

  //KdPrint((__DRIVER_NAME "     sector_number = %d, block_count = %d\n", (ULONG)shadow->req.sector_number, block_count));
  //KdPrint((__DRIVER_NAME "     SrbExtension = %p\n", srb->SrbExtension));
  //KdPrint((__DRIVER_NAME "     DataBuffer   = %p\n", srb->DataBuffer));

  if (PtrToUlong(srb->DataBuffer) & 511) /* use SrbExtension intead of DataBuffer if DataBuffer is not aligned to sector size */
  {
    shadow->req.sector_number += srb_offset / xvdd->bytes_per_sector;
    KdPrint((__DRIVER_NAME "     Using unaligned buffer - DataBuffer = %p, SrbExtension = %p, total length = %d, offset = %d, length = %d, sector = %d\n", srb->DataBuffer, srb->SrbExtension, block_count * xvdd->bytes_per_sector, shadow->offset, shadow->length, shadow->req.sector_number));
    if (srb->Cdb[0] == SCSIOP_WRITE)
      memcpy(ptr, ((PUCHAR)srb->DataBuffer) + srb_offset, shadow->length);
  }
  else
  {
    ptr = srb->DataBuffer;
  }

  remaining = shadow->length;  
  while (remaining > 0)
  {
    physical_address = MmGetPhysicalAddress(ptr);
    pfn = (ULONG)(physical_address.QuadPart >> PAGE_SHIFT);
    shadow->req.seg[shadow->req.nr_segments].gref = get_grant_from_freelist(xvdd);
    ASSERT(shadow->req.seg[shadow->req.nr_segments].gref);
    xvdd->vectors.GntTbl_GrantAccess(xvdd->vectors.context, 0, pfn, 0, shadow->req.seg[shadow->req.nr_segments].gref);
    offset = (ULONG)(physical_address.QuadPart & (PAGE_SIZE - 1));
    ASSERT((offset & 511) == 0);
    length = min(PAGE_SIZE - offset, remaining);
    shadow->req.seg[shadow->req.nr_segments].first_sect = (UCHAR)(offset >> 9);
    shadow->req.seg[shadow->req.nr_segments].last_sect = (UCHAR)(((offset + length) >> 9) - 1);
    remaining -= length;
    ptr += length;
    shadow->req.nr_segments++;
  }
    
  XenVbd_PutRequest(xvdd, &shadow->req);

  RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xvdd->ring, notify);
  if (notify)
    xvdd->vectors.EvtChn_Notify(xvdd->vectors.context, xvdd->event_channel);

  /* we don't want another srb if we had to double buffer this one, it will put things out of order */
  if (xvdd->shadow_free && srb_offset + shadow->length == block_count * xvdd->bytes_per_sector )
  {
    ScsiPortNotification(NextLuRequest, xvdd, 0, 0, 0);
  }

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static ULONG
XenVbd_FillModePage(PXENVBD_DEVICE_DATA xvdd, PSCSI_REQUEST_BLOCK srb)
{
  PCDB cdb;
  PMODE_PARAMETER_HEADER parameter_header;
  UCHAR page_code;
  ULONG offset;
  UCHAR buffer[256];

  UNREFERENCED_PARAMETER(xvdd);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  
  cdb = (PCDB)srb->Cdb;
  page_code = cdb->MODE_SENSE.PageCode;
  offset = 0;
  RtlZeroMemory(srb->DataBuffer, srb->DataTransferLength);
  RtlZeroMemory(buffer, ARRAY_SIZE(buffer));

  parameter_header = (PMODE_PARAMETER_HEADER)&buffer[offset];
  parameter_header->MediumType = 0;
  parameter_header->DeviceSpecificParameter = 0;
  parameter_header->BlockDescriptorLength = 0;
  offset += sizeof(MODE_PARAMETER_HEADER);
  parameter_header->ModeDataLength = (UCHAR)(offset - 4);
  srb->DataTransferLength = min(srb->DataTransferLength, offset);
  memcpy(srb->DataBuffer, buffer, srb->DataTransferLength);
  KdPrint((__DRIVER_NAME "     DataTransferLength = %d\n", srb->DataTransferLength));
  KdPrint((__DRIVER_NAME "     ModeDataLength = %d\n", parameter_header->ModeDataLength));
  if (offset != srb->DataTransferLength)
    srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
  else
    srb->SrbStatus = SRB_STATUS_SUCCESS;
  srb->ScsiStatus = 0;
  
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

static VOID
XenVbd_MakeSense(PXENVBD_DEVICE_DATA xvdd, PSCSI_REQUEST_BLOCK srb, BOOLEAN sense_key)
{
  PSENSE_DATA sd = srb->SenseInfoBuffer;
 
  UNREFERENCED_PARAMETER(xvdd);
  
  if (!srb->SenseInfoBuffer)
    return;
  
  sd->ErrorCode = 0x70;
  sd->Valid = 1;
  sd->SenseKey = sense_key;
  sd->AdditionalSenseLength = sizeof(SENSE_DATA) - FIELD_OFFSET(SENSE_DATA, AdditionalSenseLength);
  return;
}

static VOID
XenVbd_MakeAutoSense(PXENVBD_DEVICE_DATA xvdd, PSCSI_REQUEST_BLOCK srb)
{
  if (srb->SrbStatus == SRB_STATUS_SUCCESS || srb->SrbFlags & SRB_FLAGS_DISABLE_AUTOSENSE)
    return;
  XenVbd_MakeSense(xvdd, srb, xvdd->last_sense_key);
  srb->SrbStatus |= SRB_STATUS_AUTOSENSE_VALID;
}

static BOOLEAN
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

  while (more_to_do)
  {
    rp = xvdd->ring.sring->rsp_prod;
    KeMemoryBarrier();
    for (i = xvdd->ring.rsp_cons; i != rp; i++)
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
        if (rep->operation != 0xff)
        {
          xvdd->ring.nr_ents = BLK_OTHER_RING_SIZE;
          xvdd->use_other = TRUE;
        }
        xvdd->ring_detect_state = 2;
        ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
        break;
      case 2:
        shadow = &xvdd->shadows[rep->id];
        srb = shadow->srb;
        ASSERT(srb != NULL);
        block_count = (srb->Cdb[7] << 8) | srb->Cdb[8];

        if (rep->status == BLKIF_RSP_OKAY)
          srb->SrbStatus = SRB_STATUS_SUCCESS;
        else
        {
          KdPrint((__DRIVER_NAME "     Xen Operation returned error\n"));
          if (srb->Cdb[0] == SCSIOP_READ)
            KdPrint((__DRIVER_NAME "     Operation = Read\n"));
          else
            KdPrint((__DRIVER_NAME "     Operation = Write\n"));     
          KdPrint((__DRIVER_NAME "     Sector = %08X, Count = %d\n", shadow->req.sector_number, block_count));
          srb->SrbStatus = SRB_STATUS_ERROR;
          srb->ScsiStatus = 0x02;
          xvdd->last_sense_key = SCSI_SENSE_MEDIUM_ERROR;
          XenVbd_MakeAutoSense(xvdd, srb);
        }
        for (j = 0; j < shadow->req.nr_segments; j++)
        {
          xvdd->vectors.GntTbl_EndAccess(xvdd->vectors.context, shadow->req.seg[j].gref, TRUE);
          put_grant_on_freelist(xvdd, shadow->req.seg[j].gref);
        }

        if (PtrToUlong(srb->DataBuffer) & 511) /* use SrbExtension intead of DataBuffer if DataBuffer is not aligned to sector size */
        {
          if (srb->Cdb[0] == SCSIOP_READ)
          {
            memcpy(((PUCHAR)srb->DataBuffer) + shadow->offset, srb->SrbExtension, shadow->length);
            //KdPrint((__DRIVER_NAME "     (RD) memcpy(%p, %p, %d)\n", ((PUCHAR)srb->DataBuffer) + shadow->offset, srb->SrbExtension, shadow->length));
          }
          //KdPrint((__DRIVER_NAME "     (Get) id = %d, DataBuffer = %p, SrbExtension = %p, total length = %d, offset = %d, length = %d\n", (ULONG)shadow->req.id, srb->DataBuffer, srb->SrbExtension, block_count * xvdd->bytes_per_sector, shadow->offset, shadow->length));
          offset = shadow->offset + shadow->length;
          put_shadow_on_freelist(xvdd, shadow);
          if (offset == block_count * xvdd->bytes_per_sector)
          {
            ScsiPortNotification(RequestComplete, xvdd, srb);
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
          if (xvdd->pending_srb)
          {
            srb = xvdd->pending_srb;
            xvdd->pending_srb = NULL;
            XenVbd_PutSrbOnRing(xvdd, srb, 0);
          }
          else
            ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
        }
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

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  
  return FALSE; /* we just don't know... */
}

static BOOLEAN
XenVbd_HwScsiStartIo(PVOID DeviceExtension, PSCSI_REQUEST_BLOCK Srb)
{
  PUCHAR DataBuffer;
  PCDB cdb;
  PXENVBD_DEVICE_DATA xvdd = DeviceExtension;

  //KdPrint((__DRIVER_NAME " --> HwScsiStartIo PathId = %d, TargetId = %d, Lun = %d\n", Srb->PathId, Srb->TargetId, Srb->Lun));

  // If we haven't enumerated all the devices yet then just defer the request
  if (xvdd->ring_detect_state < 2)
  {
    Srb->SrbStatus = SRB_STATUS_BUSY;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    KdPrint((__DRIVER_NAME " --- HwScsiStartIo (Still figuring out ring)\n"));
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
//      KdPrint((__DRIVER_NAME "     Command = TEST_UNIT_READY\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      Srb->ScsiStatus = 0;
      break;
    case SCSIOP_INQUIRY:
      KdPrint((__DRIVER_NAME "     Command = INQUIRY\n"));
      KdPrint((__DRIVER_NAME "     (LUN = %d, EVPD = %d, Page Code = %02X)\n", Srb->Cdb[1] >> 5, Srb->Cdb[1] & 1, Srb->Cdb[2]));
      KdPrint((__DRIVER_NAME "     (Length = %d)\n", Srb->DataTransferLength));
      KdPrint((__DRIVER_NAME "     (Srb->Databuffer = %08x)\n", Srb->DataBuffer));
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
            KdPrint((__DRIVER_NAME "     Unknown Page %02x requested\n", Srb->Cdb[2]));
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
            KdPrint((__DRIVER_NAME "     Unknown Page %02x requested\n", Srb->Cdb[2]));
            Srb->SrbStatus = SRB_STATUS_ERROR;
            break;
          }
        }
        break;
      default:
        KdPrint((__DRIVER_NAME "     Unknown DeviceType %02x requested\n", xvdd->device_type));
        Srb->SrbStatus = SRB_STATUS_ERROR;
        break;
      }
      break;
    case SCSIOP_READ_CAPACITY:
      //KdPrint((__DRIVER_NAME "     Command = READ_CAPACITY\n"));
      DataBuffer = Srb->DataBuffer;
      RtlZeroMemory(DataBuffer, Srb->DataTransferLength);
      DataBuffer[0] = (unsigned char)((xvdd->total_sectors - 1) >> 24) & 0xff;
      DataBuffer[1] = (unsigned char)((xvdd->total_sectors - 1) >> 16) & 0xff;
      DataBuffer[2] = (unsigned char)((xvdd->total_sectors - 1) >> 8) & 0xff;
      DataBuffer[3] = (unsigned char)((xvdd->total_sectors - 1) >> 0) & 0xff;
      DataBuffer[4] = (unsigned char)(xvdd->bytes_per_sector >> 24) & 0xff;
      DataBuffer[5] = (unsigned char)(xvdd->bytes_per_sector >> 16) & 0xff;
      DataBuffer[6] = (unsigned char)(xvdd->bytes_per_sector >> 8) & 0xff;
      DataBuffer[7] = (unsigned char)(xvdd->bytes_per_sector >> 0) & 0xff;
      Srb->ScsiStatus = 0;
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;
    case SCSIOP_MODE_SENSE:
      KdPrint((__DRIVER_NAME "     Command = MODE_SENSE (DBD = %d, PC = %d, Page Code = %02x)\n", Srb->Cdb[1] & 0x10, Srb->Cdb[2] & 0xC0, Srb->Cdb[2] & 0x3F));
      KdPrint((__DRIVER_NAME "     Length = %d\n", Srb->DataTransferLength));
      XenVbd_FillModePage(xvdd, Srb);
      break;
    case SCSIOP_WRITE:
    case SCSIOP_READ:
      //KdPrint((__DRIVER_NAME "     Command = READ/WRITE\n"));
      XenVbd_PutSrbOnRing(xvdd, Srb, 0);
      break;
    case SCSIOP_VERIFY:
      // Should we do more here?
      KdPrint((__DRIVER_NAME "     Command = VERIFY\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;
    case SCSIOP_REPORT_LUNS:
      KdPrint((__DRIVER_NAME "     Command = REPORT_LUNS\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;;
      break;
    case SCSIOP_REQUEST_SENSE:
      XenVbd_MakeSense(xvdd, Srb, xvdd->last_sense_key);
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
      KdPrint((__DRIVER_NAME "     Command = READ_TOC\n"));
      KdPrint((__DRIVER_NAME "     Msf = %d\n", cdb->READ_TOC.Msf));
      KdPrint((__DRIVER_NAME "     LogicalUnitNumber = %d\n", cdb->READ_TOC.LogicalUnitNumber));
      KdPrint((__DRIVER_NAME "     Format2 = %d\n", cdb->READ_TOC.Format2));
      KdPrint((__DRIVER_NAME "     StartingTrack = %d\n", cdb->READ_TOC.StartingTrack));
      KdPrint((__DRIVER_NAME "     AllocationLength = %d\n", (cdb->READ_TOC.AllocationLength[0] << 8) | cdb->READ_TOC.AllocationLength[1]));
      KdPrint((__DRIVER_NAME "     Control = %d\n", cdb->READ_TOC.Control));
      KdPrint((__DRIVER_NAME "     Format = %d\n", cdb->READ_TOC.Format));
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
      KdPrint((__DRIVER_NAME "     Command = SCSIOP_START_STOP_UNIT\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;
    case SCSIOP_RESERVE_UNIT:
      KdPrint((__DRIVER_NAME "     Command = SCSIOP_RESERVE_UNIT\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;
    case SCSIOP_RELEASE_UNIT:
      KdPrint((__DRIVER_NAME "     Command = SCSIOP_RELEASE_UNIT\n"));
      Srb->SrbStatus = SRB_STATUS_SUCCESS;
      break;
    default:
      KdPrint((__DRIVER_NAME "     Unhandled EXECUTE_SCSI Command = %02X\n", Srb->Cdb[0]));
      Srb->SrbStatus = SRB_STATUS_ERROR;
      break;
    }
    if (Srb->SrbStatus == SRB_STATUS_ERROR)
    {
      if (xvdd->last_sense_key == SCSI_SENSE_NO_SENSE)
        xvdd->last_sense_key = SCSI_SENSE_ILLEGAL_REQUEST;
      Srb->ScsiStatus = 0x02;
      XenVbd_MakeAutoSense(xvdd, Srb);
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
    }
    else if (Srb->SrbStatus != SRB_STATUS_PENDING)
    {
      xvdd->last_sense_key = SCSI_SENSE_NO_SENSE;
      ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
      ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
    }
    break;
  case SRB_FUNCTION_IO_CONTROL:
    KdPrint((__DRIVER_NAME "     SRB_FUNCTION_IO_CONTROL\n"));
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextLuRequest, DeviceExtension, 0, 0, 0);
    break;
  case SRB_FUNCTION_FLUSH:
    KdPrint((__DRIVER_NAME "     SRB_FUNCTION_FLUSH\n"));
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

static BOOLEAN
XenVbd_HwScsiResetBus(PVOID DeviceExtension, ULONG PathId)
{
  UNREFERENCED_PARAMETER(DeviceExtension);
  UNREFERENCED_PARAMETER(PathId);

  KdPrint((__DRIVER_NAME " --> HwScsiResetBus\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  KdPrint((__DRIVER_NAME " <-- HwScsiResetBus\n"));

  return TRUE;
}

static BOOLEAN
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

static SCSI_ADAPTER_CONTROL_STATUS
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

VOID
XenVbd_FillInitCallbacks(PHW_INITIALIZATION_DATA HwInitializationData)
{
  KdPrint((__DRIVER_NAME " --> "__FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  HwInitializationData->HwInitialize = XenVbd_HwScsiInitialize;
  HwInitializationData->HwStartIo = XenVbd_HwScsiStartIo;
  HwInitializationData->HwInterrupt = XenVbd_HwScsiInterrupt;
  HwInitializationData->HwFindAdapter = XenVbd_HwScsiFindAdapter;
  HwInitializationData->HwResetBus = XenVbd_HwScsiResetBus;
  HwInitializationData->HwDmaStarted = NULL;
  HwInitializationData->HwAdapterState = XenVbd_HwScsiAdapterState;
  HwInitializationData->HwAdapterControl = XenVbd_HwScsiAdapterControl;

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}
