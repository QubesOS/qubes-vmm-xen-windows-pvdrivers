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

#include "xenscsi.h"
#include <scsi.h>
#include <ntddscsi.h>
#include <ntdddisk.h>
#include <stdlib.h>
#include <xen_public.h>
#include <io/xenbus.h>
#include <io/protocols.h>

#pragma warning(disable: 4127)

static vscsiif_shadow_t *
get_shadow_from_freelist(PXENSCSI_DEVICE_DATA xsdd)
{
  if (xsdd->shadow_free == 0)
  {
    KdPrint((__DRIVER_NAME "     No more shadow entries\n"));    
    return NULL;
  }
  xsdd->shadow_free--;
  return &xsdd->shadows[xsdd->shadow_free_list[xsdd->shadow_free]];
}

static VOID
put_shadow_on_freelist(PXENSCSI_DEVICE_DATA xsdd, vscsiif_shadow_t *shadow)
{
  xsdd->shadow_free_list[xsdd->shadow_free] = (USHORT)shadow->req.rqid;
  shadow->Srb = NULL;
  xsdd->shadow_free++;
}

static grant_ref_t
get_grant_from_freelist(PXENSCSI_DEVICE_DATA xsdd)
{
  if (xsdd->grant_free == 0)
  {
    KdPrint((__DRIVER_NAME "     No more grant refs\n"));    
    return (grant_ref_t)0x0FFFFFFF;
  }
  xsdd->grant_free--;
  return xsdd->grant_free_list[xsdd->grant_free];
}

static VOID
put_grant_on_freelist(PXENSCSI_DEVICE_DATA xsdd, grant_ref_t grant)
{
  xsdd->grant_free_list[xsdd->grant_free] = grant;
  xsdd->grant_free++;
}

static BOOLEAN
XenScsi_HwScsiInterrupt(PVOID DeviceExtension)
{
  PXENSCSI_DEVICE_DATA xsdd = (PXENSCSI_DEVICE_DATA)DeviceExtension;
  PSCSI_REQUEST_BLOCK Srb;
  RING_IDX i, rp;
  int j;
  vscsiif_response_t *rep;
  int more_to_do = TRUE;
  vscsiif_shadow_t *shadow;
  ULONG remaining;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  while (more_to_do)
  {
    rp = xsdd->ring.sring->rsp_prod;
    KeMemoryBarrier();
    for (i = xsdd->ring.rsp_cons; i != rp; i++)
    {
      rep = RING_GET_RESPONSE(&xsdd->ring, i);
      shadow = &xsdd->shadows[rep->rqid];
      KdPrint((__DRIVER_NAME "     Operation complete - result = 0x%08x\n", rep->rslt));
      Srb = shadow->Srb;
      Srb->ScsiStatus = (UCHAR)rep->rslt;
      if (rep->sense_len > 0 && Srb->SenseInfoBuffer != NULL)
      {
        memcpy(Srb->SenseInfoBuffer, rep->sense_buffer, min(Srb->SenseInfoBufferLength, rep->sense_len));
      }
      if (!rep->rslt)
      {
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
      }
      else
      {
        KdPrint((__DRIVER_NAME "     Xen Operation returned error (result = 0x%08x)\n", rep->rslt));
        Srb->SrbStatus = SRB_STATUS_ERROR;
        if (rep->sense_len > 0 && !(Srb->SrbFlags & SRB_FLAGS_DISABLE_AUTOSENSE) && Srb->SenseInfoBuffer != NULL)
        {
          Srb->SrbStatus |= SRB_STATUS_AUTOSENSE_VALID;
        }
      }
      remaining = Srb->DataTransferLength;
      for (j = 0; remaining != 0; j++)
      {
        xsdd->vectors.GntTbl_EndAccess(xsdd->vectors.context, shadow->req.seg[j].gref, TRUE);
        put_grant_on_freelist(xsdd, shadow->req.seg[j].gref);
        shadow->req.seg[j].gref = 0;
        remaining -= shadow->req.seg[j].length;
      }
      put_shadow_on_freelist(xsdd, shadow);
      ScsiPortNotification(RequestComplete, xsdd, Srb);
      ScsiPortNotification(NextRequest, xsdd);
    }

    xsdd->ring.rsp_cons = i;
    if (i != xsdd->ring.req_prod_pvt)
    {
      RING_FINAL_CHECK_FOR_RESPONSES(&xsdd->ring, more_to_do);
    }
    else
    {
      xsdd->ring.sring->rsp_event = i + 1;
      more_to_do = FALSE;
    }
  }

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  
  return FALSE; /* we just don't know... */
}

static VOID
XenScsi_ParseBackendDevice(PXENSCSI_DEVICE_DATA xsdd, PCHAR value)
{
  int i = 0;
  int j = 0;
  BOOLEAN scanning = TRUE;

  while (scanning)
  {
    if (value[i] == 0)
      scanning = FALSE;
    if (value[i] == ':' || value[i] == 0)
    {
       value[i] = 0;
       xsdd->host = xsdd->channel;
       xsdd->channel = xsdd->id;
       xsdd->id = xsdd->lun;
       xsdd->lun = atoi(&value[j]);
       j = i + 1;
    }
    i++;
  }
  KdPrint((__DRIVER_NAME "     host = %d, channel = %d, id = %d, lun = %d\n",
    xsdd->host, xsdd->channel, xsdd->id, xsdd->lun));  
}

static ULONG
XenScsi_HwScsiFindAdapter(PVOID DeviceExtension, PVOID HwContext, PVOID BusInformation, PCHAR ArgumentString, PPORT_CONFIGURATION_INFORMATION ConfigInfo, PBOOLEAN Again)
{
  ULONG i;
//  PACCESS_RANGE AccessRange;
  PXENSCSI_DEVICE_DATA xsdd = (PXENSCSI_DEVICE_DATA)DeviceExtension;
//  ULONG status;
//  PXENPCI_XEN_DEVICE_DATA XenDeviceData;
  PACCESS_RANGE access_range;
  PUCHAR ptr;
  USHORT type;
  PCHAR setting, value;
  vscsiif_sring_t *sring;

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

  sring = NULL;
  xsdd->event_channel = 0;
  while((type = GET_XEN_INIT_RSP(&ptr, &setting, &value)) != XEN_INIT_TYPE_END)
  {
    switch(type)
    {
    case XEN_INIT_TYPE_RING: /* frontend ring */
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_RING - %s = %p\n", setting, value));
      if (strcmp(setting, "ring-ref") == 0)
      {
        sring = (vscsiif_sring_t *)value;
        FRONT_RING_INIT(&xsdd->ring, sring, PAGE_SIZE);
      }
      break;
    case XEN_INIT_TYPE_EVENT_CHANNEL: /* frontend event channel */
    case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ: /* frontend event channel */
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_EVENT_CHANNEL - %s = %d\n", setting, PtrToUlong(value)));
      if (strcmp(setting, "event-channel") == 0)
      {
        xsdd->event_channel = PtrToUlong(value);
      }
      break;
    case XEN_INIT_TYPE_READ_STRING_BACK:
    case XEN_INIT_TYPE_READ_STRING_FRONT:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = %s\n", setting, value));
      if (strcmp(setting, "b-dev") == 0)
      {
        XenScsi_ParseBackendDevice(xsdd, value);
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
        memcpy(&xsdd->vectors, value, sizeof(XENPCI_VECTORS));
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
        memcpy(&xsdd->grant_free_list, value, sizeof(ULONG) * PtrToUlong(setting));
        xsdd->grant_free = GRANT_ENTRIES;
      }
      break;
    default:
      KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_%d\n", type));
      break;
    }
  }
#if 0
  if (xsdd->device_type == XENSCSI_DEVICETYPE_UNKNOWN
    || sring == NULL
    || xsdd->event_channel == 0)
  {
    KdPrint((__DRIVER_NAME "     Missing settings\n"));
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
    return SP_RETURN_BAD_CONFIG;
  }
#endif
  ConfigInfo->MaximumTransferLength = VSCSIIF_SG_TABLESIZE * PAGE_SIZE;
  ConfigInfo->NumberOfPhysicalBreaks = VSCSIIF_SG_TABLESIZE - 1;
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

  xsdd->shadow_free = 0;
  memset(xsdd->shadows, 0, sizeof(vscsiif_shadow_t) * SHADOW_ENTRIES);
  for (i = 0; i < SHADOW_ENTRIES; i++)
  {
    xsdd->shadows[i].req.rqid = (USHORT)i;
    put_shadow_on_freelist(xsdd, &xsdd->shadows[i]);
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));  

  return SP_RETURN_FOUND;
}

static BOOLEAN
XenScsi_HwScsiInitialize(PVOID DeviceExtension)
{
  //PXENSCSI_DEVICE_DATA xsdd = (PXENSCSI_DEVICE_DATA)DeviceExtension;
  
  UNREFERENCED_PARAMETER(DeviceExtension);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return TRUE;
}

static VOID
XenScsi_PutSrbOnRing(PXENSCSI_DEVICE_DATA xsdd, PSCSI_REQUEST_BLOCK Srb)
{
  PUCHAR ptr;
  PHYSICAL_ADDRESS physical_address;
  PFN_NUMBER pfn;
  //int i;
  vscsiif_shadow_t *shadow;
  int remaining;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  shadow = get_shadow_from_freelist(xsdd);
  ASSERT(shadow);
  shadow->Srb = Srb;
  shadow->req.cmd = VSCSIIF_CMND_SCSI;
  memset(shadow->req.cmnd, 0, VSCSIIF_MAX_COMMAND_SIZE);
  memcpy(shadow->req.cmnd, Srb->Cdb, Srb->CdbLength);
  shadow->req.cmd_len = Srb->CdbLength;
  shadow->req.id = (USHORT)xsdd->id;
  shadow->req.lun = (USHORT)xsdd->lun;
  shadow->req.channel = (USHORT)xsdd->channel;
  if (Srb->DataTransferLength && (Srb->SrbFlags & SRB_FLAGS_DATA_IN) && (Srb->SrbFlags & SRB_FLAGS_DATA_OUT))
  {
    KdPrint((__DRIVER_NAME "     Cmd = %02x, Length = %d, DMA_BIDIRECTIONAL\n", Srb->Cdb[0], Srb->DataTransferLength));
    shadow->req.sc_data_direction = DMA_BIDIRECTIONAL;
  }
  else if (Srb->DataTransferLength && (Srb->SrbFlags & SRB_FLAGS_DATA_IN))
  {
    KdPrint((__DRIVER_NAME "     Cmd = %02x, Length = %d, DMA_FROM_DEVICE\n", Srb->Cdb[0], Srb->DataTransferLength));
    shadow->req.sc_data_direction = DMA_FROM_DEVICE;
  }
  else if (Srb->DataTransferLength && (Srb->SrbFlags & SRB_FLAGS_DATA_OUT))
  {
    KdPrint((__DRIVER_NAME "     Cmd = %02x, Length = %d, DMA_TO_DEVICE\n", Srb->Cdb[0], Srb->DataTransferLength));
    shadow->req.sc_data_direction = DMA_TO_DEVICE;
  }
  else
  {
    KdPrint((__DRIVER_NAME "     Cmd = %02x, Length = %d, DMA_NONE\n", Srb->Cdb[0], Srb->DataTransferLength));
    shadow->req.sc_data_direction = DMA_NONE;
  }
  //shadow->req.use_sg = (UINT8)((Srb->DataTransferLength + PAGE_SIZE - 1) >> PAGE_SHIFT);
  shadow->req.request_bufflen = Srb->DataTransferLength;

  remaining = Srb->DataTransferLength;
  shadow->req.seg[0].offset = 0;
  shadow->req.seg[0].length = 0;

  ptr = Srb->DataBuffer;

  for (shadow->req.use_sg = 0; remaining != 0; shadow->req.use_sg++)
  {
    physical_address = MmGetPhysicalAddress(ptr);
    pfn = (ULONG)(physical_address.QuadPart >> PAGE_SHIFT);
    shadow->req.seg[shadow->req.use_sg].gref = get_grant_from_freelist(xsdd);
    ASSERT(shadow->req.seg[shadow->req.use_sg].gref);
    xsdd->vectors.GntTbl_GrantAccess(xsdd->vectors.context, 0, (ULONG)pfn, 0, shadow->req.seg[shadow->req.use_sg].gref);
    shadow->req.seg[shadow->req.use_sg].offset = (USHORT)(physical_address.LowPart & (PAGE_SIZE - 1));
    shadow->req.seg[shadow->req.use_sg].length = (USHORT)min(PAGE_SIZE - shadow->req.seg[shadow->req.use_sg].offset, remaining);
    remaining -= shadow->req.seg[shadow->req.use_sg].length;
    ptr += shadow->req.seg[shadow->req.use_sg].length;
    //KdPrint((__DRIVER_NAME "     Page = %d, Offset = %d, Length = %d, Remaining = %d\n", shadow->req.use_sg, shadow->req.seg[shadow->req.use_sg].offset, shadow->req.seg[shadow->req.use_sg].length, remaining));
  }
  *RING_GET_REQUEST(&xsdd->ring, xsdd->ring.req_prod_pvt) = shadow->req;
  xsdd->ring.req_prod_pvt++;

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static BOOLEAN
XenScsi_HwScsiStartIo(PVOID DeviceExtension, PSCSI_REQUEST_BLOCK Srb)
{
  PXENSCSI_DEVICE_DATA xsdd = DeviceExtension;
  int notify;

  //KdPrint((__DRIVER_NAME " --> HwScsiStartIo PathId = %d, TargetId = %d, Lun = %d\n", Srb->PathId, Srb->TargetId, Srb->Lun));

//  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  if (Srb->PathId != 0 || Srb->TargetId != 0)
  {
    Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    KdPrint((__DRIVER_NAME " --- HwScsiStartIo (Out of bounds)\n"));
    return TRUE;
  }

  switch (Srb->Function)
  {
  case SRB_FUNCTION_EXECUTE_SCSI:
    XenScsi_PutSrbOnRing(xsdd, Srb);
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&xsdd->ring, notify);
    if (notify)
      xsdd->vectors.EvtChn_Notify(xsdd->vectors.context, xsdd->event_channel);
    if (!xsdd->shadow_free)
      ScsiPortNotification(NextRequest, DeviceExtension);
    break;
  case SRB_FUNCTION_IO_CONTROL:
    KdPrint((__DRIVER_NAME "     SRB_FUNCTION_IO_CONTROL\n"));
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    break;
  case SRB_FUNCTION_FLUSH:
    KdPrint((__DRIVER_NAME "     SRB_FUNCTION_FLUSH\n"));
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unhandled Srb->Function = %08X\n", Srb->Function));
    Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    ScsiPortNotification(RequestComplete, DeviceExtension, Srb);
    ScsiPortNotification(NextRequest, DeviceExtension, NULL);
    break;
  }

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return TRUE;
}

static BOOLEAN
XenScsi_HwScsiResetBus(PVOID DeviceExtension, ULONG PathId)
{
  UNREFERENCED_PARAMETER(DeviceExtension);
  UNREFERENCED_PARAMETER(PathId);


  KdPrint((__DRIVER_NAME " --> HwScsiResetBus\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  KdPrint((__DRIVER_NAME " <-- HwScsiResetBus\n"));

  return TRUE;
}

static BOOLEAN
XenScsi_HwScsiAdapterState(PVOID DeviceExtension, PVOID Context, BOOLEAN SaveState)
{
  UNREFERENCED_PARAMETER(DeviceExtension);
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(SaveState);

  KdPrint((__DRIVER_NAME " --> HwScsiAdapterState\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  KdPrint((__DRIVER_NAME " <-- HwScsiAdapterState\n"));

  return TRUE;
}

static SCSI_ADAPTER_CONTROL_STATUS
XenScsi_HwScsiAdapterControl(PVOID DeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters)
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
    break;
  case ScsiStopAdapter:
    KdPrint((__DRIVER_NAME "     ScsiStopAdapter\n"));
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
XenScsi_FillInitCallbacks(PHW_INITIALIZATION_DATA HwInitializationData)
{
  KdPrint((__DRIVER_NAME " --> "__FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  HwInitializationData->HwInitialize = XenScsi_HwScsiInitialize;
  HwInitializationData->HwStartIo = XenScsi_HwScsiStartIo;
  HwInitializationData->HwInterrupt = XenScsi_HwScsiInterrupt;
  HwInitializationData->HwFindAdapter = XenScsi_HwScsiFindAdapter;
  HwInitializationData->HwResetBus = XenScsi_HwScsiResetBus;
  HwInitializationData->HwAdapterState = XenScsi_HwScsiAdapterState;
  HwInitializationData->HwAdapterControl = XenScsi_HwScsiAdapterControl;

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}
