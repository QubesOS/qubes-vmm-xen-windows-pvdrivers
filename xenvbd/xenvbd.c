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

DRIVER_INITIALIZE DriverEntry;

static ULONG
XenVbd_HwScsiFindAdapter(PVOID DeviceExtension, PVOID HwContext, PVOID BusInformation, PCHAR ArgumentString, PPORT_CONFIGURATION_INFORMATION ConfigInfo, PBOOLEAN Again);
static BOOLEAN
XenVbd_HwScsiInitialize(PVOID DeviceExtension);
static BOOLEAN
XenVbd_HwScsiStartIo(PVOID DeviceExtension, PSCSI_REQUEST_BLOCK Srb);
static BOOLEAN
XenVbd_HwScsiInterrupt(PVOID DeviceExtension);
static BOOLEAN
XenVbd_HwScsiResetBus(PVOID DeviceExtension, ULONG PathId);
static BOOLEAN
XenVbd_HwScsiAdapterState(PVOID DeviceExtension, PVOID Context, BOOLEAN SaveState);
static SCSI_ADAPTER_CONTROL_STATUS
XenVbd_HwScsiAdapterControl(PVOID DeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#endif

static PDRIVER_DISPATCH XenVbd_Pnp_Original;

static NTSTATUS
XenVbd_Pnp(PDEVICE_OBJECT device_object, PIRP irp)
{
  PIO_STACK_LOCATION stack;
  NTSTATUS status;
  PCM_RESOURCE_LIST old_crl, new_crl;
  PCM_PARTIAL_RESOURCE_LIST prl;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR prd;
  ULONG old_length, new_length;
  PMDL mdl;
  PUCHAR start, ptr;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stack = IoGetCurrentIrpStackLocation(irp);

  switch (stack->MinorFunction)
  {
  case IRP_MN_START_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_START_DEVICE\n"));
    mdl = AllocatePage();
    old_crl = stack->Parameters.StartDevice.AllocatedResourcesTranslated;
    old_length = FIELD_OFFSET(CM_RESOURCE_LIST, List) + 
      FIELD_OFFSET(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList) +
      FIELD_OFFSET(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors) +
      sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * old_crl->List[0].PartialResourceList.Count;
    new_length = old_length + sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * 1;
    new_crl = ExAllocatePoolWithTag(PagedPool, new_length, XENVBD_POOL_TAG);
    memcpy(new_crl, old_crl, old_length);
    prl = &new_crl->List[0].PartialResourceList;
    prd = &prl->PartialDescriptors[prl->Count++];
    prd->Type = CmResourceTypeMemory;
    prd->ShareDisposition = CmResourceShareDeviceExclusive;
    prd->Flags = CM_RESOURCE_MEMORY_READ_WRITE|CM_RESOURCE_MEMORY_PREFETCHABLE|CM_RESOURCE_MEMORY_CACHEABLE;
    prd->u.Memory.Start.QuadPart = MmGetMdlPfnArray(mdl)[0] << PAGE_SHIFT;
    prd->u.Memory.Length = PAGE_SIZE;
    KdPrint((__DRIVER_NAME "     Start = %08x, Length = %d\n", prd->u.Memory.Start.LowPart, prd->u.Memory.Length));
    ptr = start = MmGetMdlVirtualAddress(mdl);
    ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_RING, "ring-ref", NULL);
    ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_EVENT_CHANNEL_IRQ, "event-channel", NULL);
    ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_FRONT, "device-type", NULL);
    ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_BACK, "sectors", NULL);
    ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_READ_STRING_BACK, "sector-size", NULL);
    ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_VECTORS, NULL, NULL);
    ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_GRANT_ENTRIES, UlongToPtr(GRANT_ENTRIES), NULL);
    ADD_XEN_INIT_REQ(&ptr, XEN_INIT_TYPE_END, NULL, NULL);
    
    stack->Parameters.StartDevice.AllocatedResourcesTranslated = new_crl;

    old_crl = stack->Parameters.StartDevice.AllocatedResources;
    new_crl = ExAllocatePoolWithTag(PagedPool, new_length, XENVBD_POOL_TAG);
    memcpy(new_crl, old_crl, old_length);
    prl = &new_crl->List[0].PartialResourceList;
    prd = &prl->PartialDescriptors[prl->Count++];
    prd->Type = CmResourceTypeMemory;
    prd->ShareDisposition = CmResourceShareDeviceExclusive;
    prd->Flags = CM_RESOURCE_MEMORY_READ_WRITE|CM_RESOURCE_MEMORY_PREFETCHABLE|CM_RESOURCE_MEMORY_CACHEABLE;
    prd->u.Memory.Start.QuadPart = MmGetMdlPfnArray(mdl)[0] << PAGE_SHIFT;
    prd->u.Memory.Length = PAGE_SIZE;
    stack->Parameters.StartDevice.AllocatedResources = new_crl;

    IoCopyCurrentIrpStackLocationToNext(irp);
    status = XenVbd_Pnp_Original(device_object, irp);

    break;

  case IRP_MN_QUERY_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_STOP_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_STOP_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_CANCEL_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_STOP_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_QUERY_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_REMOVE_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_REMOVE_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_CANCEL_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_REMOVE_DEVICE\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  case IRP_MN_SURPRISE_REMOVAL:
    KdPrint((__DRIVER_NAME "     IRP_MN_SURPRISE_REMOVAL\n"));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;

  default:
    KdPrint((__DRIVER_NAME "     Unknown Minor = %d\n", stack->MinorFunction));
    status = XenVbd_Pnp_Original(device_object, irp);
    break;
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  ULONG Status;
  HW_INITIALIZATION_DATA HwInitializationData;

  KdPrint((__DRIVER_NAME " --> "__FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  RtlZeroMemory(&HwInitializationData, sizeof(HW_INITIALIZATION_DATA));

  HwInitializationData.HwInitializationDataSize = sizeof(HW_INITIALIZATION_DATA);
  HwInitializationData.AdapterInterfaceType = Internal;
  HwInitializationData.HwDmaStarted = NULL;
  HwInitializationData.DeviceExtensionSize = sizeof(XENVBD_DEVICE_DATA);
  HwInitializationData.SpecificLuExtensionSize = 0;
  HwInitializationData.SrbExtensionSize = 0;
  HwInitializationData.NumberOfAccessRanges = 1;
  HwInitializationData.MapBuffers = TRUE;
  HwInitializationData.NeedPhysicalAddresses = FALSE;
  HwInitializationData.TaggedQueuing = TRUE;
  HwInitializationData.AutoRequestSense = FALSE;
  HwInitializationData.MultipleRequestPerLu = TRUE;
  HwInitializationData.ReceiveEvent = FALSE;
  HwInitializationData.VendorIdLength = 0;
  HwInitializationData.VendorId = NULL;
  HwInitializationData.DeviceIdLength = 0;
  HwInitializationData.DeviceId = NULL;

  XenVbd_FillInitCallbacks(&HwInitializationData);

  Status = ScsiPortInitialize(DriverObject, RegistryPath, &HwInitializationData, NULL);
  
  /* this is a bit naughty... */
  XenVbd_Pnp_Original = DriverObject->MajorFunction[IRP_MJ_PNP];
  DriverObject->MajorFunction[IRP_MJ_PNP] = XenVbd_Pnp;

  if(!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME " ScsiPortInitialize failed with status 0x%08x\n", Status));
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return Status;
}
#if 0
static __inline uint64_t
GET_ID_FROM_FREELIST(PXENVBD_DEVICE_DATA device_data)
{
  uint64_t free;
  free = device_data->shadow_free;
  device_data->shadow_free = device_data->shadow[free].req.id;
  device_data->shadow[free].req.id = 0x0fffffee; /* debug */
  return free;
}
#endif

#if 0
static VOID
XenVbd_BackEndStateHandler(char *Path, PVOID Data)
{
  PXENVBD_DEVICE_DATA device_data;
  char TmpPath[128];
  char *Value;
  int NewState;
  PMDL Mdl;
  grant_ref_t ref;
  blkif_sring_t *SharedRing;
  ULONG PFN;
  ULONG i, j;
  blkif_request_t *req;
  int notify;

  KdPrint((__DRIVER_NAME " --> BackEndStateHandler\n"));
  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));

  device_data = (PXENVBD_TARGET_DATA)Data;

  DeviceData->XenDeviceData->XenInterface.XenBus_Read(
    DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
    XBT_NIL, Path, &Value);

  NewState = atoi(Value);
  switch (NewState)
  {
  case XenbusStateUnknown:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Unknown\n"));  
    break;

  case XenbusStateInitialising:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialising\n"));  
    break;

  case XenbusStateInitWait:
    KdPrint((__DRIVER_NAME "     Backend State Changed to InitWait\n"));  

    TargetData->EventChannel = DeviceData->XenDeviceData->XenInterface.EvtChn_AllocUnbound(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context, 0);
    DeviceData->XenDeviceData->XenInterface.EvtChn_Bind(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      TargetData->EventChannel, XenVbd_Interrupt, TargetData);
    Mdl = AllocatePage();
    PFN = (ULONG)*MmGetMdlPfnArray(Mdl);
    SharedRing = (blkif_sring_t *)MmGetMdlVirtualAddress(Mdl);
    RtlZeroMemory(SharedRing, PAGE_SIZE);
    SHARED_RING_INIT(SharedRing);
    FRONT_RING_INIT(&TargetData->Ring, SharedRing, PAGE_SIZE);
    ref = DeviceData->XenDeviceData->XenInterface.GntTbl_GrantAccess(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      0, PFN, FALSE, 0);
    ASSERT((signed short)ref >= 0);
    TargetData->ring_detect_state = 0;
    TargetData->shadow = ExAllocatePoolWithTag(NonPagedPool, sizeof(blkif_shadow_t) * max(BLK_RING_SIZE, BLK_OTHER_RING_SIZE), XENVBD_POOL_TAG);

    memset(TargetData->shadow, 0, sizeof(blkif_shadow_t) * max(BLK_RING_SIZE, BLK_OTHER_RING_SIZE));
    for (i = 0; i < max(BLK_RING_SIZE, BLK_OTHER_RING_SIZE); i++)
    {
      TargetData->shadow[i].req.id = i + 1;
      TargetData->shadow[i].Mdl = AllocatePages(BLKIF_MAX_SEGMENTS_PER_REQUEST); // stupid that we have to do this!
      TargetData->shadow[i].Buf = MmGetMdlVirtualAddress(TargetData->shadow[i].Mdl);
      for (j = 0; j < BLKIF_MAX_SEGMENTS_PER_REQUEST; j++)
      {
        TargetData->shadow[i].req.seg[j].gref = DeviceData->XenDeviceData->XenInterface.GntTbl_GrantAccess(
          DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
          0, (ULONG)MmGetMdlPfnArray(TargetData->shadow[i].Mdl)[j], FALSE, 0);
        ASSERT((signed short)TargetData->shadow[i].req.seg[j].gref >= 0);
      }
    }
    TargetData->shadow_free = 0;

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/protocol");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%s", XEN_IO_PROTO_ABI_NATIVE);

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/ring-ref");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", ref);

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/event-channel");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, "%d", TargetData->EventChannel);

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/state");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context, 
      XBT_NIL, TmpPath, "%d", XenbusStateInitialised);

/*
    KdPrint((__DRIVER_NAME "     sizeof(blkif_request) = %d\n", sizeof(struct blkif_request)));
    KdPrint((__DRIVER_NAME "     sizeof(blkif_request_segment) = %d\n", sizeof(struct blkif_request_segment)));
    KdPrint((__DRIVER_NAME "     sizeof(blkif_response) = %d\n", sizeof(struct blkif_response)));
    KdPrint((__DRIVER_NAME "     operation = %d\n", (int)((char *)(&req.operation) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     nr_segments = %d\n", (int)((char *)(&req.nr_segments) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     handle = %d\n", (int)((char *)(&req.handle) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     id = %d\n", (int)((char *)(&req.id) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     sector_number = %d\n", (int)((char *)(&req.sector_number) - (char *)(&req))));
    KdPrint((__DRIVER_NAME "     seg = %d\n", (int)((char *)(&req.seg) - (char *)(&req))));

    KdPrint((__DRIVER_NAME "     id = %d\n", (int)((char *)(&rep.id) - (char *)(&rep))));
    KdPrint((__DRIVER_NAME "     operation = %d\n", (int)((char *)(&rep.operation) - (char *)(&rep))));
    KdPrint((__DRIVER_NAME "     status = %d\n", (int)((char *)(&rep.status) - (char *)(&rep))));

    KdPrint((__DRIVER_NAME "     sizeof(union blkif_sring_entry) = %d\n", sizeof(union blkif_sring_entry)));
    KdPrint((__DRIVER_NAME "     %d\n", (int)((char *)(&entries[1]) - (char *)(&entries[0]))));
*/
    KdPrint((__DRIVER_NAME "     Set Frontend state to Initialised\n"));
    break;

  case XenbusStateInitialised:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialised\n"));
    break;

  case XenbusStateConnected:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Connected\n"));  

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/device-type");
    DeviceData->XenDeviceData->XenInterface.XenBus_Read(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    if (strcmp(Value, "disk") == 0)
    {
      KdPrint((__DRIVER_NAME "     DeviceType = Disk\n"));    
      TargetData->DeviceType = XENVBD_DEVICETYPE_DISK;
    }
    else if (strcmp(Value, "cdrom") == 0)
    {
      KdPrint((__DRIVER_NAME "     DeviceType = CDROM\n"));    
      TargetData->DeviceType = XENVBD_DEVICETYPE_CDROM;
    }
    else
    {
      KdPrint((__DRIVER_NAME "     DeviceType = %s (This probably won't work!)\n", Value));
      TargetData->DeviceType = XENVBD_DEVICETYPE_UNKNOWN;
    }

    RtlStringCbCopyA(TmpPath, 128, TargetData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/type"); // should probably check that this is 'phy' or 'file' or at least not ''
    DeviceData->XenDeviceData->XenInterface.XenBus_Read(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    KdPrint((__DRIVER_NAME "     Backend Type = %s\n", Value));
    ExFreePool(Value);

    RtlStringCbCopyA(TmpPath, 128, TargetData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/mode"); // should store this...
    DeviceData->XenDeviceData->XenInterface.XenBus_Read(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    KdPrint((__DRIVER_NAME "     Backend Mode = %s\n", Value));
    ExFreePool(Value);

    RtlStringCbCopyA(TmpPath, 128, TargetData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/sector-size");
    DeviceData->XenDeviceData->XenInterface.XenBus_Read(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    // should complain if Value == NULL
    TargetData->BytesPerSector = atoi(Value);

    KdPrint((__DRIVER_NAME "     BytesPerSector = %d\n", TargetData->BytesPerSector));    

    RtlStringCbCopyA(TmpPath, 128, TargetData->BackendPath);
    RtlStringCbCatA(TmpPath, 128, "/sectors");
    DeviceData->XenDeviceData->XenInterface.XenBus_Read(
      DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
      XBT_NIL, TmpPath, &Value);
    // should complain if Value == NULL
    TargetData->TotalSectors = (ULONGLONG)atol(Value);

    KdPrint((__DRIVER_NAME "     TotalSectors = %d\n", TargetData->TotalSectors));    

    // should probably use the partition table (if one exists) here for the sectorspertrack and trackspercylinder values
    TargetData->Geometry.MediaType = FixedMedia;
    TargetData->Geometry.BytesPerSector = TargetData->BytesPerSector;
    TargetData->Geometry.SectorsPerTrack = 63;
    TargetData->Geometry.TracksPerCylinder = 255;
    TargetData->Geometry.Cylinders.QuadPart = TargetData->TotalSectors / TargetData->Geometry.SectorsPerTrack / TargetData->Geometry.TracksPerCylinder;
    KdPrint((__DRIVER_NAME "     Geometry C/H/S = %d/%d/%d\n", TargetData->Geometry.Cylinders.LowPart, TargetData->Geometry.TracksPerCylinder, TargetData->Geometry.SectorsPerTrack));

    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/state");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context, XBT_NIL, TmpPath, "%d", XenbusStateConnected);

    KdPrint((__DRIVER_NAME "     Set Frontend state to Connected\n"));

    TargetData->Running = 1;
    KeMemoryBarrier();
    
    req = RING_GET_REQUEST(&TargetData->Ring, TargetData->Ring.req_prod_pvt);
    req->operation = 0xff;
    req->nr_segments = 0;
    for (i = 0; i < req->nr_segments; i++)
    {
      req->seg[i].gref = 0xffffffff;
      req->seg[i].first_sect = 0xff;
      req->seg[i].last_sect = 0xff;
    }
    TargetData->Ring.req_prod_pvt++;

    req = RING_GET_REQUEST(&TargetData->Ring, TargetData->Ring.req_prod_pvt);
    req->operation = 0xff;
    req->nr_segments = 0;
    for (i = 0; i < req->nr_segments; i++)
    {
      req->seg[i].gref = 0xffffffff;
      req->seg[i].first_sect = 0xff;
      req->seg[i].last_sect = 0xff;
    }
    TargetData->Ring.req_prod_pvt++;

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&TargetData->Ring, notify);
    if (notify)
      DeviceData->XenDeviceData->XenInterface.EvtChn_Notify(
        DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context,
        TargetData->EventChannel);

    InterlockedIncrement(&DeviceData->EnumeratedDevices);
    KdPrint((__DRIVER_NAME "     Added a device\n"));  

// now ask windows to rescan the scsi bus...
//    DeviceData->BusChangePending = 1;
    break;

  case XenbusStateClosing:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closing\n"));  
    // this behaviour is only to properly close down to then restart in the case of a dump
    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/state");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context, XBT_NIL, TmpPath, "%d", XenbusStateClosed);
    KdPrint((__DRIVER_NAME "     Set Frontend state to Closed\n"));
    break;

  case XenbusStateClosed:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closed\n"));  
    // this behaviour is only to properly close down to then restart in the case of a dump
    RtlStringCbCopyA(TmpPath, 128, TargetData->Path);
    RtlStringCbCatA(TmpPath, 128, "/state");
    DeviceData->XenDeviceData->XenInterface.XenBus_Printf(DeviceData->XenDeviceData->XenInterface.InterfaceHeader.Context, XBT_NIL, TmpPath, "%d", XenbusStateInitialising);
    KdPrint((__DRIVER_NAME "     Set Frontend state to Initialising\n"));
    break;

  default:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Undefined = %d\n", NewState));
    break;
  }

  KdPrint((__DRIVER_NAME " <-- BackEndStateHandler\n"));
}

#endif
