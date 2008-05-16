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

#include "xenpci.h"
#include <stdlib.h>
#include <io/ring.h>

#pragma warning(disable : 4200) // zero-sized array
#pragma warning(disable: 4127) // conditional expression is constant

NTSTATUS
XenPci_Power_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  POWER_STATE_TYPE power_type;
  POWER_STATE power_state;
  //PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  //PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;

  UNREFERENCED_PARAMETER(device_object);
  
  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stack = IoGetCurrentIrpStackLocation(irp);
  power_type = stack->Parameters.Power.Type;
  power_state = stack->Parameters.Power.State;
  
  switch (stack->MinorFunction)
  {
  case IRP_MN_POWER_SEQUENCE:
    KdPrint((__DRIVER_NAME "     IRP_MN_POWER_SEQUENCE\n"));
    status = STATUS_NOT_SUPPORTED;
    break;
  case IRP_MN_QUERY_POWER:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_POWER\n"));
    status = STATUS_SUCCESS;
    break;
  case IRP_MN_SET_POWER:
    KdPrint((__DRIVER_NAME "     IRP_MN_SET_POWER\n"));
    switch (power_type) {
    case DevicePowerState:
      PoSetPowerState(device_object, power_type, power_state);
      status = STATUS_SUCCESS;
      break;
    case SystemPowerState:
      status = STATUS_SUCCESS;
      break;
    default:
      status = STATUS_NOT_SUPPORTED;
      break;
    }    
    break;
  case IRP_MN_WAIT_WAKE:
    KdPrint((__DRIVER_NAME "     IRP_MN_WAIT_WAKE\n"));
    status = STATUS_NOT_SUPPORTED;
    break;
  default:
    //KdPrint((__DRIVER_NAME "     Unknown IRP_MN_%d\n", stack->MinorFunction));
    status = STATUS_NOT_SUPPORTED;
    break;
  }
  if (status != STATUS_NOT_SUPPORTED) {
    irp->IoStatus.Status = status;
  }

  PoStartNextPowerIrp(irp);
  status = irp->IoStatus.Status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  
  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return status;
}

static VOID
XenPci_BackEndStateHandler(char *Path, PVOID Context)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  char *value;
  char *err;
  ULONG new_backend_state;
  char path[128];

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  /* check that path == device/id/state */
  RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->path);
  err = XenBus_Read(xpdd, XBT_NIL, Path, &value);
  if (err)
  {
    KdPrint(("Failed to read %s\n", path, err));
    return;
  }
  new_backend_state = atoi(value);
  XenPci_FreeMem(value);

  if (xppdd->backend_state == new_backend_state)
  {
    KdPrint((__DRIVER_NAME "     state unchanged\n"));
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
    return;
  }    

  xppdd->backend_state = new_backend_state;

  switch (xppdd->backend_state)
  {
  case XenbusStateUnknown:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Unknown\n"));  
    break;

  case XenbusStateInitialising:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialising\n"));  
    break;

  case XenbusStateInitWait:
    KdPrint((__DRIVER_NAME "     Backend State Changed to InitWait\n"));  
    break;

  case XenbusStateInitialised:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialised\n"));
    break;

  case XenbusStateConnected:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Connected\n"));  
    break;

  case XenbusStateClosing:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closing\n"));  
    /* check our current PNP statue - this may be a surprise removal... */
    break;

  case XenbusStateClosed:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closed\n"));  
    break;

  default:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Undefined = %d\n", xppdd->backend_state));
    break;
  }

  KeSetEvent(&xppdd->backend_state_event, 1, FALSE);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return;
}

struct dummy_sring {
    RING_IDX req_prod, req_event;
    RING_IDX rsp_prod, rsp_event;
    uint8_t  pad[48];
};

static NTSTATUS
XenPci_Pnp_StartDevice(PDEVICE_OBJECT device_object, PIRP irp)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  PIO_STACK_LOCATION stack;
  PCM_PARTIAL_RESOURCE_LIST res_list;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR res_descriptor;
  ULONG i;
  char path[128];
  PCHAR setting, value;
  PCHAR res;
  PMDL mdl;
  PVOID address;
  grant_ref_t gref;
  evtchn_port_t event_channel;
  UCHAR type;
  PUCHAR in_ptr = NULL, in_start = NULL;
  PUCHAR out_ptr, out_start = NULL;
  XENPCI_VECTORS vectors;
  LARGE_INTEGER timeout;

  UNREFERENCED_PARAMETER(device_object);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stack = IoGetCurrentIrpStackLocation(irp);

  /* Get backend path */
  RtlStringCbPrintfA(path, ARRAY_SIZE(path),
    "%s/backend", xppdd->path);
  res = XenBus_Read(xpdd, XBT_NIL, path, &value);
  if (res)
  {
    KdPrint((__DRIVER_NAME "    Failed to read backend path\n"));
    XenPci_FreeMem(res);
  }
  RtlStringCbCopyA(xppdd->backend_path, ARRAY_SIZE(xppdd->backend_path), value);
  XenPci_FreeMem(value);

  /* Add watch on backend state */
  RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
  XenBus_AddWatch(xpdd, XBT_NIL, path, XenPci_BackEndStateHandler, xppdd);

  /* Tell backend we're coming up */
  RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->path);
  XenBus_Printf(xpdd, XBT_NIL, path, "%d", XenbusStateInitialising);

  // wait here for signal that we are all set up - we should probably add a timeout to make sure we don't hang forever
  while (xppdd->backend_state != XenbusStateInitWait)
  {
    timeout.QuadPart = -5 * 1000 * 1000 * 100; // 5 seconds
    if (KeWaitForSingleObject(&xppdd->backend_state_event, Executive, KernelMode, FALSE, &timeout) != STATUS_SUCCESS)
      KdPrint((__DRIVER_NAME "     Still Waiting for InitWait...\n"));
  }

  res_list = &stack->Parameters.StartDevice.AllocatedResources->List[0].PartialResourceList;
  for (i = 0; i < res_list->Count; i++)
  {
    res_descriptor = &res_list->PartialDescriptors[i];
    switch (res_descriptor->Type)
    {
    case CmResourceTypeInterrupt:
      KdPrint((__DRIVER_NAME "     irq_number = %d\n", res_descriptor->u.Interrupt.Vector));
      KdPrint((__DRIVER_NAME "     irq_level = %03x\n", res_descriptor->u.Interrupt.Level));
      break;
    }
  }

  res_list = &stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList;
  for (i = 0; i < res_list->Count; i++)
  {
    res_descriptor = &res_list->PartialDescriptors[i];
    switch (res_descriptor->Type) {
    case CmResourceTypeInterrupt:
      KdPrint((__DRIVER_NAME "     CmResourceTypeInterrupt\n"));
      KdPrint((__DRIVER_NAME "     irq_vector = %03x\n", res_descriptor->u.Interrupt.Vector));
      KdPrint((__DRIVER_NAME "     irq_level = %d\n", res_descriptor->u.Interrupt.Level));
      xppdd->irq_vector = res_descriptor->u.Interrupt.Vector;
      xppdd->irq_level = (KIRQL)res_descriptor->u.Interrupt.Level;
      break;
    case CmResourceTypeMemory:
      KdPrint((__DRIVER_NAME "     CmResourceTypeMemory\n"));
      KdPrint((__DRIVER_NAME "     Start = %08x, Length = %d\n", res_descriptor->u.Memory.Start.LowPart, res_descriptor->u.Memory.Length));
      out_ptr = out_start = MmMapIoSpace(res_descriptor->u.Memory.Start, res_descriptor->u.Memory.Length, MmNonCached);
      in_ptr = in_start = ExAllocatePoolWithTag(PagedPool, res_descriptor->u.Memory.Length, XENPCI_POOL_TAG);
      memcpy(in_ptr, out_ptr, res_descriptor->u.Memory.Length);
      
      while((type = GET_XEN_INIT_REQ(&in_ptr, &setting, &value)) != XEN_INIT_TYPE_END)
      {
        switch (type)
        {
        case XEN_INIT_TYPE_WRITE_STRING: /* frontend setting = value */
          KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_WRITE_STRING - %s = %s\n", setting, value));
          RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->path, setting);
          XenBus_Printf(xpdd, XBT_NIL, path, "%s", value);
          break;
        case XEN_INIT_TYPE_RING: /* frontend ring */
          /* we only allocate and do the SHARED_RING_INIT here */
          mdl = AllocatePage();
          address = MmGetMdlVirtualAddress(mdl);
          KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_RING - %s = %p\n", setting, address));
          SHARED_RING_INIT((struct dummy_sring *)address);
          gref = GntTbl_GrantAccess(xpdd, 0, *MmGetMdlPfnArray(mdl), FALSE, 0);
          RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->path, setting);
          XenBus_Printf(xpdd, XBT_NIL, path, "%d", gref);
          ADD_XEN_INIT_RSP(&out_ptr, type, setting, address);
          break;
        case XEN_INIT_TYPE_EVENT_CHANNEL: /* frontend event channel */
        case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ: /* frontend event channel bound to irq */
          event_channel = EvtChn_AllocUnbound(xpdd, 0);
          KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_EVENT_CHANNEL - %s = %d\n", setting, event_channel));
          RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->path, setting);
          XenBus_Printf(xpdd, XBT_NIL, path, "%d", event_channel);
          ADD_XEN_INIT_RSP(&out_ptr, type, setting, UlongToPtr(event_channel));
          if (type == XEN_INIT_TYPE_EVENT_CHANNEL_IRQ)
            EvtChn_BindIrq(xpdd, event_channel, xppdd->irq_vector);
          break;
        }
      }
    }
  }

  /* We are all ready to go */
  RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->path);
  XenBus_Printf(xpdd, XBT_NIL, path, "%d", XenbusStateConnected);

  // wait here for signal that we are all set up - we should probably add a timeout to make sure we don't hang forever
  while (xppdd->backend_state != XenbusStateConnected)
  {
    timeout.QuadPart = -5 * 1000 * 1000 * 100; // 5 seconds
    if (KeWaitForSingleObject(&xppdd->backend_state_event, Executive, KernelMode, FALSE, &timeout) != STATUS_SUCCESS)
      KdPrint((__DRIVER_NAME "     Still Waiting for Connected...\n"));
  }

  res_list = &stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList;
  for (i = 0; i < res_list->Count; i++)
  {
    res_descriptor = &res_list->PartialDescriptors[i];
    switch (res_descriptor->Type) {
    case CmResourceTypeMemory:
      in_ptr = in_start;
      while((type = GET_XEN_INIT_REQ(&in_ptr, &setting, &value)) != XEN_INIT_TYPE_END)
      {
        switch(type)
        {
        case XEN_INIT_TYPE_READ_STRING_BACK:
        case XEN_INIT_TYPE_READ_STRING_FRONT:
          if (type == XEN_INIT_TYPE_READ_STRING_FRONT)
            RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->path, setting);
          else
            RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->backend_path, setting);
          res = XenBus_Read(xpdd, XBT_NIL, path, &value);
          if (res)
          {
            KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = <failed>\n", setting));
            XenPci_FreeMem(res);
            ADD_XEN_INIT_RSP(&out_ptr, type, setting, NULL);
          }
          else
          {
            KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = %s\n", setting, value));
            ADD_XEN_INIT_RSP(&out_ptr, type, setting, value);
            XenPci_FreeMem(value);
          }
          break;
        case XEN_INIT_TYPE_VECTORS:
          KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_VECTORS\n"));
          vectors.magic = XEN_DATA_MAGIC;
          vectors.length = sizeof(XENPCI_VECTORS);
          vectors.context = xpdd;
          vectors.EvtChn_Bind = EvtChn_Bind;
          vectors.EvtChn_BindDpc = EvtChn_BindDpc;
          vectors.EvtChn_Unbind = EvtChn_Unbind;
          vectors.EvtChn_Mask = EvtChn_Mask;
          vectors.EvtChn_Unmask = EvtChn_Unmask;
          vectors.EvtChn_Notify = EvtChn_Notify;
          vectors.GntTbl_GetRef = GntTbl_GetRef;
          vectors.GntTbl_PutRef = GntTbl_PutRef;
          vectors.GntTbl_GrantAccess = GntTbl_GrantAccess;
          vectors.GntTbl_EndAccess = GntTbl_EndAccess;
          ADD_XEN_INIT_RSP(&out_ptr, type, NULL, &vectors);
          break;
        case XEN_INIT_TYPE_GRANT_ENTRIES:
          KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_GRANT_ENTRIES - %d\n", PtrToUlong(setting)));
          __ADD_XEN_INIT_UCHAR(&out_ptr, type);
          __ADD_XEN_INIT_ULONG(&out_ptr, PtrToUlong(setting));
          for (i = 0; i < PtrToUlong(setting); i++)
            __ADD_XEN_INIT_ULONG(&out_ptr, GntTbl_GetRef(xpdd));
          break;
        }
      }
      ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_END, NULL, NULL);
      MmUnmapIoSpace(out_start, res_descriptor->u.Memory.Length);
      ExFreePoolWithTag(in_start, XENPCI_POOL_TAG);
    }
  }
  
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_QueryResourceRequirements(PDEVICE_OBJECT device_object, PIRP irp)
{
  //PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  //PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  PIO_RESOURCE_REQUIREMENTS_LIST irrl;
  PIO_RESOURCE_DESCRIPTOR ird;
  ULONG length;
  
  UNREFERENCED_PARAMETER(device_object);
  
  length = FIELD_OFFSET(IO_RESOURCE_REQUIREMENTS_LIST, List) +
    FIELD_OFFSET(IO_RESOURCE_LIST, Descriptors) +
    sizeof(IO_RESOURCE_DESCRIPTOR) * 3;
  irrl = ExAllocatePoolWithTag(PagedPool,
    length,
    XENPCI_POOL_TAG);
  
  irrl->ListSize = length;
  irrl->InterfaceType = Internal;
  irrl->BusNumber = 0;
  irrl->SlotNumber = 0;
  irrl->AlternativeLists = 1;
  irrl->List[0].Version = 1;
  irrl->List[0].Revision = 1;
  irrl->List[0].Count = 0;

  ird = &irrl->List[0].Descriptors[irrl->List[0].Count++];
  ird->Option = 0;
  ird->Type = CmResourceTypeInterrupt;
  ird->ShareDisposition = CmResourceShareShared; //CmResourceShareDeviceExclusive;
  ird->Flags = CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
  ird->u.Interrupt.MinimumVector = 1;
  ird->u.Interrupt.MaximumVector = 6;

  ird = &irrl->List[0].Descriptors[irrl->List[0].Count++];
  ird->Option = IO_RESOURCE_ALTERNATIVE;
  ird->Type = CmResourceTypeInterrupt;
  ird->ShareDisposition = CmResourceShareShared; //CmResourceShareDeviceExclusive;
  ird->Flags = CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
  ird->u.Interrupt.MinimumVector = 10;
  ird->u.Interrupt.MaximumVector = 14;

  irp->IoStatus.Information = (ULONG_PTR)irrl;
  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_Pnp_QueryTargetRelations(PDEVICE_OBJECT device_object, PIRP irp)
{
  PDEVICE_RELATIONS dr;
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  
  dr = (PDEVICE_RELATIONS)ExAllocatePoolWithTag (PagedPool, sizeof(DEVICE_RELATIONS), XENPCI_POOL_TAG);
  dr->Count = 1;
  dr->Objects[0] = xppdd->common.pdo;
  ObReferenceObject(xppdd->common.pdo);
  irp->IoStatus.Information = (ULONG_PTR)dr;
  
  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_Pnp_QueryCapabilities(PDEVICE_OBJECT device_object, PIRP irp)
{
  PIO_STACK_LOCATION stack;
  PDEVICE_CAPABILITIES dc;

  UNREFERENCED_PARAMETER(device_object);
  
  stack = IoGetCurrentIrpStackLocation(irp);
  dc = stack->Parameters.DeviceCapabilities.Capabilities;
  dc->LockSupported = FALSE;
  dc->EjectSupported = FALSE;
  dc->Removable = FALSE;
  dc->DockDevice = FALSE;
  dc->UniqueID = FALSE;
  dc->SilentInstall = FALSE;
  dc->RawDeviceOK = FALSE;
  dc->SurpriseRemovalOK = FALSE;
  dc->HardwareDisabled = FALSE;
  dc->NoDisplayInUI = FALSE;
  dc->DeviceWake = PowerDeviceUnspecified;
  dc->D1Latency = 0;
  dc->D2Latency = 0;
  dc->D3Latency = 0;
  /* we are really supposed to get the DeviceState entries from the parent... */
  dc->DeviceState[PowerSystemWorking] = PowerDeviceD0;
  dc->DeviceState[PowerSystemSleeping1] = PowerDeviceUnspecified;
  dc->DeviceState[PowerSystemSleeping2] = PowerDeviceUnspecified;
  dc->DeviceState[PowerSystemSleeping3] = PowerDeviceUnspecified;
  dc->DeviceState[PowerSystemHibernate] = PowerDeviceD3;
  dc->DeviceState[PowerSystemShutdown] = PowerDeviceD3;
  return STATUS_SUCCESS;
}

NTSTATUS
XenPci_Pnp_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  LPWSTR buffer;
  WCHAR widebuf[256];
  unsigned int i;
  PPNP_BUS_INFORMATION pbi;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stack = IoGetCurrentIrpStackLocation(irp);

  switch (stack->MinorFunction)
  {
  case IRP_MN_START_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_START_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    status = XenPci_Pnp_StartDevice(device_object, irp);
    break;
    
  case IRP_MN_QUERY_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_STOP_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_STOP_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_CANCEL_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_STOP_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_QUERY_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_REMOVE_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_REMOVE_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_CANCEL_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_REMOVE_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_SURPRISE_REMOVAL:
    KdPrint((__DRIVER_NAME "     IRP_MN_SURPRISE_REMOVAL (status = %08x)\n", irp->IoStatus.Status));
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_DEVICE_USAGE_NOTIFICATION:
    KdPrint((__DRIVER_NAME "     IRP_MN_DEVICE_USAGE_NOTIFICATION (status = %08x)\n", irp->IoStatus.Status));
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_QUERY_ID:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_ID (status = %08x)\n", irp->IoStatus.Status));
    switch (stack->Parameters.QueryId.IdType)
    {
    case BusQueryDeviceID: /* REG_SZ */
      KdPrint((__DRIVER_NAME "     BusQueryDeviceID\n"));
      buffer = ExAllocatePoolWithTag(PagedPool, 512, XENPCI_POOL_TAG);
      for (i = 0; i < strlen(xppdd->device); i++)
        widebuf[i] = xppdd->device[i];
      widebuf[i] = 0;
      RtlStringCbPrintfW(buffer, 512, L"Xen\\%ws", widebuf);
      KdPrint((__DRIVER_NAME "     %ls\n", buffer));
      irp->IoStatus.Information = (ULONG_PTR)buffer;
      status = STATUS_SUCCESS;
      break;
    case BusQueryHardwareIDs: /* REG_MULTI_SZ */
      KdPrint((__DRIVER_NAME "     BusQueryHardwareIDs\n"));
      buffer = ExAllocatePoolWithTag(PagedPool, 512, XENPCI_POOL_TAG);
      for (i = 0; i < strlen(xppdd->device); i++)
        widebuf[i] = xppdd->device[i];
      widebuf[i] = 0;
      RtlStringCbPrintfW(buffer, 512, L"Xen\\%ws", widebuf);
      for (i = 0; buffer[i] != 0; i++);
      buffer[i + 1] = 0;      
//      for (i = 0; i < 256; i++)
//        KdPrint((__DRIVER_NAME "     %04X: %04X %wc\n", i, buffer[i], buffer[i]));
      KdPrint((__DRIVER_NAME "     %ls\n", buffer));
      irp->IoStatus.Information = (ULONG_PTR)buffer;
      status = STATUS_SUCCESS;
      break;
    case BusQueryCompatibleIDs: /* REG_MULTI_SZ */
      KdPrint((__DRIVER_NAME "     BusQueryCompatibleIDs\n"));
      buffer = ExAllocatePoolWithTag(PagedPool, 512, XENPCI_POOL_TAG);
      for (i = 0; i < strlen(xppdd->device); i++)
        widebuf[i] = xppdd->device[i];
      widebuf[i] = 0;
      RtlStringCbPrintfW(buffer, 512, L"Xen\\%ws", widebuf);
      for (i = 0; buffer[i] != 0; i++);
      buffer[i + 1] = 0;
      KdPrint((__DRIVER_NAME "     %ls\n", buffer));
      irp->IoStatus.Information = (ULONG_PTR)buffer;
      status = STATUS_SUCCESS;
      break;
    case BusQueryInstanceID: /* REG_SZ */
      KdPrint((__DRIVER_NAME "     BusQueryInstanceID\n"));
      buffer = ExAllocatePoolWithTag(PagedPool, 512, XENPCI_POOL_TAG);
      RtlStringCbPrintfW(buffer, 512, L"%02d", xppdd->index);
      KdPrint((__DRIVER_NAME "     %ls\n", buffer));
      irp->IoStatus.Information = (ULONG_PTR)buffer;
      status = STATUS_SUCCESS;
      break;
    default:
      KdPrint((__DRIVER_NAME "     Unhandled IdType = %d\n", stack->Parameters.QueryId.IdType));
      irp->IoStatus.Information = 0;
      status = STATUS_NOT_SUPPORTED;
      break;
    }
    break;
    
  case IRP_MN_QUERY_DEVICE_TEXT:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_DEVICE_TEXT (status = %08x)\n", irp->IoStatus.Status));
    switch (stack->Parameters.QueryDeviceText.DeviceTextType)
    {
    case DeviceTextDescription:
      KdPrint((__DRIVER_NAME "     DeviceTextDescription\n"));
      buffer = ExAllocatePoolWithTag(PagedPool, 512, XENPCI_POOL_TAG);
      for (i = 0; i < strlen(xppdd->device); i++)
        widebuf[i] = xppdd->device[i];
      widebuf[i] = 0;
      RtlStringCbPrintfW(buffer, 512, L"Xen %ws device #%d", widebuf, xppdd->index);
      KdPrint((__DRIVER_NAME "     %ls\n", buffer));
      irp->IoStatus.Information = (ULONG_PTR)buffer;
      status = STATUS_SUCCESS;
      break;
    case DeviceTextLocationInformation:
      KdPrint((__DRIVER_NAME "     DeviceTextLocationInformation\n"));
      buffer = ExAllocatePoolWithTag(PagedPool, 512, XENPCI_POOL_TAG);
      RtlStringCbPrintfW(buffer, 512, L"Xen Bus");
      KdPrint((__DRIVER_NAME "     %ls\n", buffer));
      irp->IoStatus.Information = (ULONG_PTR)buffer;
      status = STATUS_SUCCESS;
      break;
    default:
      KdPrint((__DRIVER_NAME "     Unhandled IdType = %d\n", stack->Parameters.QueryDeviceText.DeviceTextType));
      irp->IoStatus.Information = 0;
      status = STATUS_NOT_SUPPORTED;
      break;
    }
    break;
    
  case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_RESOURCE_REQUIREMENTS (status = %08x)\n", irp->IoStatus.Status));
    status = XenPci_QueryResourceRequirements(device_object, irp);
    break;

  case IRP_MN_QUERY_CAPABILITIES:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_CAPABILITIES (status = %08x)\n", irp->IoStatus.Status));
    status = XenPci_Pnp_QueryCapabilities(device_object, irp);
    break;

  case IRP_MN_QUERY_BUS_INFORMATION:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_BUS_INFORMATION (status = %08x)\n", irp->IoStatus.Status));
    pbi = (PPNP_BUS_INFORMATION)ExAllocatePoolWithTag(PagedPool, sizeof(PNP_BUS_INFORMATION), XENPCI_POOL_TAG);
    pbi->BusTypeGuid = GUID_BUS_TYPE_XEN;
    pbi->LegacyBusType = Internal;
    pbi->BusNumber = 0;
    irp->IoStatus.Information = (ULONG_PTR)pbi;
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_QUERY_RESOURCES:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_RESOURCES (status = %08x)\n", irp->IoStatus.Status));
    status = irp->IoStatus.Status;
    #if 0
    crl = (PCM_RESOURCE_LIST)ExAllocatePoolWithTag(PagedPool, sizeof(CM_RESOURCE_LIST) - sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR), XENPCI_POOL_TAG);
    crl->Count = 1;
    crl->List[0].InterfaceType = Internal;
    crl->List[0].BusNumber = 0;
    crl->List[0].PartialResourceList.Version = 0;
    crl->List[0].PartialResourceList.Revision = 0;
    crl->List[0].PartialResourceList.Count = 0;
    irp->IoStatus.Information = (ULONG_PTR)crl;
    status = STATUS_SUCCESS;
    #endif
    break;
    
  case IRP_MN_QUERY_PNP_DEVICE_STATE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_PNP_DEVICE_STATE (status = %08x)\n", irp->IoStatus.Status));
    irp->IoStatus.Information = 0;
    status = STATUS_SUCCESS;
    break;
  
  case IRP_MN_QUERY_DEVICE_RELATIONS:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_DEVICE_RELATIONS (status = %08x)\n", irp->IoStatus.Status));
    switch (stack->Parameters.QueryDeviceRelations.Type)
    {
    case TargetDeviceRelation:
      KdPrint((__DRIVER_NAME "     BusRelations\n"));
      status = XenPci_Pnp_QueryTargetRelations(device_object, irp);
      break;  
    default:
      status = irp->IoStatus.Status;
      break;
    }
    break;
        
  default:
    KdPrint((__DRIVER_NAME "     Unhandled Minor = %d, Status = %08x\n", stack->MinorFunction, irp->IoStatus.Status));
    status = irp->IoStatus.Status;
    break;
  }

  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

NTSTATUS
XenPci_Irp_Create_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  PXENPCI_DEVICE_DATA xpdd;
  NTSTATUS status;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  status = IoCallDriver(xpdd->common.lower_do, irp);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

NTSTATUS
XenPci_Irp_Close_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  PXENPCI_DEVICE_DATA xpdd;
  NTSTATUS status;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  status = IoCallDriver(xpdd->common.lower_do, irp);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

NTSTATUS
XenPci_Irp_Read_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  PXENPCI_DEVICE_DATA xpdd;
  NTSTATUS status;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  status = IoCallDriver(xpdd->common.lower_do, irp);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

NTSTATUS
XenPci_Irp_Cleanup_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;

  UNREFERENCED_PARAMETER(device_object);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  
  status = STATUS_SUCCESS;
  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}
