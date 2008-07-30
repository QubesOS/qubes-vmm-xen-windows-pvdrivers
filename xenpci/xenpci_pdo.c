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
    //KdPrint((__DRIVER_NAME "     IRP_MN_POWER_SEQUENCE\n"));
    status = STATUS_NOT_SUPPORTED;
    break;
  case IRP_MN_QUERY_POWER:
    //KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_POWER\n"));
    status = STATUS_SUCCESS;
    break;
  case IRP_MN_SET_POWER:
    //KdPrint((__DRIVER_NAME "     IRP_MN_SET_POWER\n"));
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
    //KdPrint((__DRIVER_NAME "     IRP_MN_WAIT_WAKE\n"));
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

/*
Called at PASSIVE_LEVEL(?)
Called during restore
*/

static ULONG
XenPci_ReadBackendState(PXENPCI_PDO_DEVICE_DATA xppdd)
{
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  char path[128];
  char *value;
  char *err;
  ULONG backend_state;
  
  RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
  err = XenBus_Read(xpdd, XBT_NIL, path, &value);
  if (err)
  {
    XenPci_FreeMem(err);
    return XenbusStateUnknown;
  }
  else
  {
    backend_state = atoi(value);
    XenPci_FreeMem(value);
    return backend_state;
  }
}

static VOID
XenPci_BackEndStateHandler(char *path, PVOID context)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  ULONG new_backend_state;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  /* check that path == device/id/state */
  //RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->path);
  new_backend_state = XenPci_ReadBackendState(xppdd);
  if (new_backend_state == XenbusStateUnknown)
  {
    if (xpdd->suspend_state != SUSPEND_STATE_NONE)
      return;
    KdPrint(("Failed to read %s, assuming closed\n", path));
    new_backend_state = XenbusStateClosed;
  }

  if (xppdd->backend_state == new_backend_state)
  {
    KdPrint((__DRIVER_NAME "     state unchanged\n"));
    //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
    return;
  }

  xppdd->backend_state = new_backend_state;

  switch (xppdd->backend_state)
  {
  case XenbusStateUnknown:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Unknown (%s)\n", path));  
    break;

  case XenbusStateInitialising:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialising (%s)\n", path));  
    break;

  case XenbusStateInitWait:
    KdPrint((__DRIVER_NAME "     Backend State Changed to InitWait (%s)\n", path));  
    break;

  case XenbusStateInitialised:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Initialised (%s)\n", path));  
    break;

  case XenbusStateConnected:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Connected (%s)\n", path));    
    break;

  case XenbusStateClosing:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closing (%s)\n", path));  
    if (xpdd->suspend_state == SUSPEND_STATE_NONE)
    {
      if (xppdd->common.device_usage_paging
        || xppdd->common.device_usage_dump
        || xppdd->common.device_usage_hibernation)
      {
        KdPrint((__DRIVER_NAME "     Not closing device because it is in use\n"));
        /* in use by page file, dump file, or hiber file - can't close */
        /* we should probably re-check if the device usage changes in the future */
      }
      else
      {
        if (xppdd->common.current_pnp_state == Started)
        {
          KdPrint((__DRIVER_NAME "     Sending RequestDeviceEject\n"));
          xppdd->eject_requested = TRUE;
          IoRequestDeviceEject(xppdd->common.pdo);
        }
        else
        {
          KdPrint((__DRIVER_NAME "     Not closing device because it is not started\n"));
        }
      }
    }
    break;

  case XenbusStateClosed:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closed (%s)\n", path));  
    break;

  default:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Undefined = %d (%s)\n", xppdd->backend_state, path));
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

/*
Called at PASSIVE_LEVEL
Called during restore
*/
static NTSTATUS
XenPci_ChangeFrontendState(PXENPCI_PDO_DEVICE_DATA xppdd, ULONG frontend_state_set, ULONG backend_state_response, ULONG maximum_wait_ms)
{
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  LARGE_INTEGER timeout;
  ULONG remaining;
  ULONG thiswait;
  char path[128];
  
  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  /* Tell backend we're going down */
  //strcpy(path, xppdd->path);
  RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->path);
  XenBus_Printf(xpdd, XBT_NIL, path, "%d", frontend_state_set);

  remaining = maximum_wait_ms;

  while (xppdd->backend_state != backend_state_response)
  {
    thiswait = min((LONG)remaining, 1000); // 1 second or remaining time, whichever is less
    timeout.QuadPart = (LONGLONG)-1 * thiswait * 1000 * 10;
    if (KeWaitForSingleObject(&xppdd->backend_state_event, Executive, KernelMode, FALSE, &timeout) == STATUS_TIMEOUT)
    {
      remaining -= thiswait;
      if (remaining == 0)
      {
        KdPrint((__DRIVER_NAME "     Timed out waiting for %d!\n", backend_state_response));
        return STATUS_UNSUCCESSFUL;
      }
      KdPrint((__DRIVER_NAME "     Still waiting for %d (currently %d)...\n", backend_state_response, xppdd->backend_state));
    }
  }
  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  return STATUS_SUCCESS;
}

static VOID
DUMP_CURRENT_PNP_STATE(PXENPCI_PDO_DEVICE_DATA xppdd)
{
  switch (xppdd->common.current_pnp_state)
  {
  case Unknown:
    KdPrint((__DRIVER_NAME "     pnp_state = Unknown\n"));
    break;
  case NotStarted:
    KdPrint((__DRIVER_NAME "     pnp_state = NotStarted\n"));
    break;
  case Started:
    KdPrint((__DRIVER_NAME "     pnp_state = Started\n"));
    break;
  case StopPending:
    KdPrint((__DRIVER_NAME "     pnp_state = StopPending\n"));
    break;
  case Stopped:
    KdPrint((__DRIVER_NAME "     pnp_state = Stopped\n"));
    break;
  case RemovePending:
    KdPrint((__DRIVER_NAME "     pnp_state = RemovePending\n"));
    break;
  case SurpriseRemovePending:
    KdPrint((__DRIVER_NAME "     pnp_state = SurpriseRemovePending\n"));
    break;
  case Removed:
    KdPrint((__DRIVER_NAME "     pnp_state = Removed\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     pnp_state = ???\n"));
    break;
  }
}

static NTSTATUS
XenPci_EvtChn_Bind(PVOID Context, evtchn_port_t Port, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return EvtChn_Bind(xpdd, Port, ServiceRoutine, ServiceContext);
}

static NTSTATUS
XenPci_EvtChn_BindDpc(PVOID Context, evtchn_port_t Port, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return EvtChn_BindDpc(xpdd, Port, ServiceRoutine, ServiceContext);
}

static NTSTATUS
XenPci_EvtChn_Unbind(PVOID Context, evtchn_port_t Port)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return EvtChn_Unbind(xpdd, Port);
}

static NTSTATUS
XenPci_EvtChn_Mask(PVOID Context, evtchn_port_t Port)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return EvtChn_Mask(xpdd, Port);
}

static NTSTATUS
XenPci_EvtChn_Unmask(PVOID Context, evtchn_port_t Port)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return EvtChn_Unmask(xpdd, Port);
}

static NTSTATUS
XenPci_EvtChn_Notify(PVOID Context, evtchn_port_t Port)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return EvtChn_Notify(xpdd, Port);
}

static grant_ref_t
XenPci_GntTbl_GrantAccess(PVOID Context, domid_t domid, uint32_t frame, int readonly, grant_ref_t ref)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return GntTbl_GrantAccess(xpdd, domid, frame, readonly, ref);
}

static BOOLEAN
XenPci_GntTbl_EndAccess(PVOID Context, grant_ref_t ref, BOOLEAN keepref)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return GntTbl_EndAccess(xpdd, ref, keepref);
}

static VOID
XenPci_GntTbl_PutRef(PVOID Context, grant_ref_t ref)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  GntTbl_PutRef(xpdd, ref);
}

static grant_ref_t
XenPci_GntTbl_GetRef(PVOID Context)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return GntTbl_GetRef(xpdd);
}

static NTSTATUS
XenPci_XenShutdownDevice(PVOID Context)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  PUCHAR in_ptr;
  ULONG i;
  UCHAR type;
  PVOID setting;
  PVOID value;

  FUNCTION_ENTER();

  if (xppdd->backend_state == XenbusStateConnected)
  {
    XenPci_ChangeFrontendState(xppdd, XenbusStateClosing, XenbusStateClosing, 30000);
    if (xppdd->backend_state == XenbusStateClosing)
      XenPci_ChangeFrontendState(xppdd, XenbusStateClosed, XenbusStateClosed, 30000);
    if (xppdd->backend_state == XenbusStateClosed)
      XenPci_ChangeFrontendState(xppdd, XenbusStateInitialising, XenbusStateInitWait, 30000);
  }
  else
  {
    if (xppdd->backend_state == XenbusStateClosing)
      XenPci_ChangeFrontendState(xppdd, XenbusStateClosed, XenbusStateClosed, 30000);
  }

  if (xppdd->assigned_resources_start != NULL)
  {
    ADD_XEN_INIT_RSP(&xppdd->assigned_resources_ptr, XEN_INIT_TYPE_END, NULL, NULL);
    in_ptr = xppdd->assigned_resources_start;
    while((type = GET_XEN_INIT_RSP(&in_ptr, &setting, &value)) != XEN_INIT_TYPE_END)
    {
      switch (type)
      {
      case XEN_INIT_TYPE_RING: /* frontend ring */
        FreePages(value);
        break;
      case XEN_INIT_TYPE_EVENT_CHANNEL: /* frontend event channel */
        // don't know how to do this yet...
        break;
      case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ: /* frontend event channel bound to irq */
        EvtChn_Unbind(xpdd, PtrToUlong(value));
        EvtChn_Close(xpdd, PtrToUlong(value));
        break;
      case XEN_INIT_TYPE_GRANT_ENTRIES:
        for (i = 0; i < PtrToUlong(setting); i++)
          GntTbl_EndAccess(xpdd, ((grant_ref_t *)value)[i], FALSE);
        break;
      }
    }
    ExFreePoolWithTag(xppdd->assigned_resources_start, XENPCI_POOL_TAG);
    xppdd->assigned_resources_start = NULL;
  }

  FUNCTION_EXIT();

  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_XenConfigDevice(PVOID context);

static NTSTATUS
XenPci_XenConfigDeviceSpecifyBuffers(PVOID context, PUCHAR src, PUCHAR dst)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  NTSTATUS status = STATUS_SUCCESS;
  ULONG i;
  char path[128];
  PCHAR setting, value;
  PCHAR res;
  PVOID address;
  UCHAR type;
  PUCHAR in_ptr; //, in_start;
  PUCHAR out_ptr; //, out_start;
  XENPCI_VECTORS vectors;
  ULONG event_channel;
  BOOLEAN run = FALSE;
  PMDL ring;
  grant_ref_t gref;
  BOOLEAN done_xenbus_init = FALSE;
 
  FUNCTION_ENTER();

  in_ptr = src;
  out_ptr = dst;
  
  // always add vectors
  vectors.magic = XEN_DATA_MAGIC;
  vectors.length = sizeof(XENPCI_VECTORS);
  vectors.context = xppdd;
  vectors.EvtChn_Bind = XenPci_EvtChn_Bind;
  vectors.EvtChn_BindDpc = XenPci_EvtChn_BindDpc;
  vectors.EvtChn_Unbind = XenPci_EvtChn_Unbind;
  vectors.EvtChn_Mask = XenPci_EvtChn_Mask;
  vectors.EvtChn_Unmask = XenPci_EvtChn_Unmask;
  vectors.EvtChn_Notify = XenPci_EvtChn_Notify;
  vectors.GntTbl_GetRef = XenPci_GntTbl_GetRef;
  vectors.GntTbl_PutRef = XenPci_GntTbl_PutRef;
  vectors.GntTbl_GrantAccess = XenPci_GntTbl_GrantAccess;
  vectors.GntTbl_EndAccess = XenPci_GntTbl_EndAccess;
  vectors.XenPci_XenConfigDevice = XenPci_XenConfigDevice;
  vectors.XenPci_XenShutdownDevice = XenPci_XenShutdownDevice;
  ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_VECTORS, NULL, &vectors);
  ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_STATE_PTR, NULL, &xppdd->device_state);

  // first pass, possibly before state == Connected
  while((type = GET_XEN_INIT_REQ(&in_ptr, (PVOID)&setting, (PVOID)&value)) != XEN_INIT_TYPE_END)
  {
  
    if (!done_xenbus_init)
    {
      if (XenPci_ChangeFrontendState(xppdd, XenbusStateInitialising, XenbusStateInitWait, 30000) != STATUS_SUCCESS)
      {
        status = STATUS_UNSUCCESSFUL;
        goto error;
      }
      done_xenbus_init = TRUE;
    }
    
    ADD_XEN_INIT_REQ(&xppdd->requested_resources_ptr, type, setting, value);

    switch (type)
    {
    case XEN_INIT_TYPE_RUN:
      run = TRUE;
    case XEN_INIT_TYPE_WRITE_STRING: /* frontend setting = value */
      //KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_WRITE_STRING - %s = %s\n", setting, value));
      RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->path, setting);
      XenBus_Printf(xpdd, XBT_NIL, path, "%s", value);
      break;
    case XEN_INIT_TYPE_RING: /* frontend ring */
      /* we only allocate and do the SHARED_RING_INIT here */
      if ((ring = AllocatePage()) != 0)
      {
        address = MmGetMdlVirtualAddress(ring);
        //KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_RING - %s = %p\n", setting, address));
        SHARED_RING_INIT((struct dummy_sring *)address);
        if ((gref = GntTbl_GrantAccess(
          xpdd, 0, (ULONG)*MmGetMdlPfnArray(ring), FALSE, 0)) != 0)
        {
          RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->path, setting);
          XenBus_Printf(xpdd, XBT_NIL, path, "%d", gref);
          ADD_XEN_INIT_RSP(&out_ptr, type, setting, address);
          ADD_XEN_INIT_RSP(&xppdd->assigned_resources_ptr, type, setting, ring);
          // add the grant entry too so it gets freed automatically
          __ADD_XEN_INIT_UCHAR(&xppdd->assigned_resources_ptr, XEN_INIT_TYPE_GRANT_ENTRIES);
          __ADD_XEN_INIT_ULONG(&xppdd->assigned_resources_ptr, 1);
          __ADD_XEN_INIT_ULONG(&xppdd->assigned_resources_ptr, gref);
        }
        else
        {
          FreePages(ring);
          status = STATUS_UNSUCCESSFUL;
          goto error;
        }
      }
      else
      {
        status = STATUS_UNSUCCESSFUL;
        goto error;
      }
      break;
    case XEN_INIT_TYPE_EVENT_CHANNEL: /* frontend event channel */
    case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ: /* frontend event channel bound to irq */
      if ((event_channel = EvtChn_AllocUnbound(xpdd, 0)) != 0)
      {
        //KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_EVENT_CHANNEL - %s = %d\n", setting, event_channel));
        RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->path, setting);
        XenBus_Printf(xpdd, XBT_NIL, path, "%d", event_channel);
        ADD_XEN_INIT_RSP(&out_ptr, type, setting, UlongToPtr(event_channel));
        ADD_XEN_INIT_RSP(&xppdd->assigned_resources_ptr, type, setting, UlongToPtr(event_channel));
        if (type == XEN_INIT_TYPE_EVENT_CHANNEL_IRQ)
          EvtChn_BindIrq(xpdd, event_channel, xppdd->irq_vector);
      }
      else
      {
        status = STATUS_UNSUCCESSFUL;
        goto error;
      }
      break;
    }
  }
  if (!NT_SUCCESS(status))
  {
    goto error;
  }
  if (run)
  {
    if (XenPci_ChangeFrontendState(xppdd, XenbusStateConnected, XenbusStateConnected, 30000) != STATUS_SUCCESS)
    {
      status = STATUS_UNSUCCESSFUL;
      goto error;
    }
  }

  // second pass, possibly after state == Connected
  in_ptr = src;
  while((type = GET_XEN_INIT_REQ(&in_ptr, (PVOID)&setting, (PVOID)&value)) != XEN_INIT_TYPE_END)
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
        //KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = <failed>\n", setting));
        XenPci_FreeMem(res);
        ADD_XEN_INIT_RSP(&out_ptr, type, setting, NULL);
      }
      else
      {
        //KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = %s\n", setting, value));
        ADD_XEN_INIT_RSP(&out_ptr, type, setting, value);
        XenPci_FreeMem(value);
      }
      break;
    case XEN_INIT_TYPE_VECTORS:
      // this is always done so ignore the request
      break;
    case XEN_INIT_TYPE_GRANT_ENTRIES:
      //KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_GRANT_ENTRIES - %d\n", PtrToUlong(value)));
      __ADD_XEN_INIT_UCHAR(&out_ptr, type);
      __ADD_XEN_INIT_UCHAR(&xppdd->assigned_resources_ptr, type);
      __ADD_XEN_INIT_ULONG(&out_ptr, PtrToUlong(value));
      __ADD_XEN_INIT_ULONG(&xppdd->assigned_resources_ptr, PtrToUlong(value));
      for (i = 0; i < PtrToUlong(value); i++)
      {
        __ADD_XEN_INIT_ULONG(&out_ptr, GntTbl_GetRef(xpdd));
        __ADD_XEN_INIT_ULONG(&xppdd->assigned_resources_ptr, GntTbl_GetRef(xpdd));
      }
      break;
    }
  }
  ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_END, NULL, NULL);
  
error:
  FUNCTION_EXIT_STATUS(status);

  return status;
}

static NTSTATUS
XenPci_XenConfigDevice(PVOID context)
{
  NTSTATUS status;
  PUCHAR src, dst;
  PXENPCI_PDO_DEVICE_DATA xppdd = context;  

  src = ExAllocatePoolWithTag(NonPagedPool, xppdd->config_page_length, XENPCI_POOL_TAG);
  dst = MmMapIoSpace(xppdd->config_page_phys, xppdd->config_page_length, MmNonCached);
  memcpy(src, dst, xppdd->config_page_length);
  
  status = XenPci_XenConfigDeviceSpecifyBuffers(xppdd, src, dst);

  MmUnmapIoSpace(dst, xppdd->config_page_length);
  ExFreePoolWithTag(src, XENPCI_POOL_TAG);
  
  return status;
}

static NTSTATUS
XenPci_GetBackendAndAddWatch(PDEVICE_OBJECT device_object)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  char path[128];
  PCHAR res;
  PCHAR value;

  /* Get backend path */
  RtlStringCbPrintfA(path, ARRAY_SIZE(path),
    "%s/backend", xppdd->path);
  res = XenBus_Read(xpdd, XBT_NIL, path, &value);
  if (res)
  {
    KdPrint((__DRIVER_NAME "    Failed to read backend path\n"));
    XenPci_FreeMem(res);
    return STATUS_UNSUCCESSFUL;
  }
  RtlStringCbCopyA(xppdd->backend_path, ARRAY_SIZE(xppdd->backend_path), value);
  XenPci_FreeMem(value);

  /* Add watch on backend state */
  RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
  XenBus_AddWatch(xpdd, XBT_NIL, path, XenPci_BackEndStateHandler, xppdd);
  
  return STATUS_SUCCESS;
}

NTSTATUS
XenPci_Pdo_Resume(PDEVICE_OBJECT device_object)
{
  NTSTATUS status;
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  //PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  //PUCHAR in_ptr;
  //UCHAR type;
  //PVOID setting;
  //PVOID value;
  //CHAR path[256];
  //PVOID address;
  ULONG old_backend_state;
  PUCHAR src, dst;

  FUNCTION_ENTER();

  old_backend_state = xppdd->backend_state;

  //if (xppdd->common.current_pnp_state == Started && old_backend_state == XenbusStateClosed)
  if (xppdd->restart_on_resume)
  {  
    status = XenPci_GetBackendAndAddWatch(device_object);
  
    if (XenPci_ChangeFrontendState(xppdd, XenbusStateInitialising, XenbusStateInitWait, 30000) != STATUS_SUCCESS)
    {
      KdPrint((__DRIVER_NAME "     Failed to change frontend state to Initialising\n"));
      // this is probably an unrecoverable situation...
      FUNCTION_ERROR_EXIT();
      return STATUS_UNSUCCESSFUL;
    }
    if (xppdd->assigned_resources_ptr)
    {
      // reset things - feed the 'requested resources' back in
      ADD_XEN_INIT_REQ(&xppdd->requested_resources_ptr, XEN_INIT_TYPE_END, NULL, NULL);
      src = xppdd->requested_resources_start;
      xppdd->requested_resources_ptr = xppdd->requested_resources_start = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);;
      xppdd->assigned_resources_ptr = xppdd->assigned_resources_start;
      
      dst = MmMapIoSpace(xppdd->config_page_phys, xppdd->config_page_length, MmNonCached);
      
      status = XenPci_XenConfigDeviceSpecifyBuffers(xppdd, src, dst);

      MmUnmapIoSpace(dst, xppdd->config_page_length);
      ExFreePoolWithTag(src, XENPCI_POOL_TAG);
    }
    if (XenPci_ChangeFrontendState(xppdd, XenbusStateConnected, XenbusStateConnected, 30000) != STATUS_SUCCESS)
    {
      // this is definitely an unrecoverable situation...
      KdPrint((__DRIVER_NAME "     Failed to change frontend state to connected\n"));
      FUNCTION_ERROR_EXIT();
      return STATUS_UNSUCCESSFUL;
    }
  }
  else
  {
    KdPrint((__DRIVER_NAME "     Not resuming - current_pnp_state = %d, old_backend_state = %d\n", xppdd->common.current_pnp_state, old_backend_state));
  }
  KeMemoryBarrier();
  xppdd->device_state.resume_state = RESUME_STATE_FRONTEND_RESUME;

  FUNCTION_EXIT();

  return STATUS_SUCCESS;
} 

/* called at PASSIVE_LEVEL */
NTSTATUS
XenPci_Pdo_Suspend(PDEVICE_OBJECT device_object)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  LARGE_INTEGER wait_time;
  char path[128];
  PUCHAR in_ptr;
  UCHAR type;
  PVOID setting;
  PVOID value;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ " (%s)\n", xppdd->path));

  if (xppdd->backend_state == XenbusStateConnected)
  {
    xppdd->restart_on_resume = TRUE;
    xppdd->device_state.resume_state_ack = RESUME_STATE_RUNNING;
    KeMemoryBarrier();
    xppdd->device_state.resume_state = RESUME_STATE_SUSPENDING;
    KeMemoryBarrier();
    KdPrint((__DRIVER_NAME "     Calling interrupt\n"));
    sw_interrupt((UCHAR)xppdd->irq_vector);
    KdPrint((__DRIVER_NAME "     Back from interrupt call\n"));
    while(xppdd->device_state.resume_state_ack != RESUME_STATE_SUSPENDING)
    {
      KdPrint((__DRIVER_NAME "     Starting delay - resume_state = %d, resume_state_ack = %d\n", xppdd->device_state.resume_state, xppdd->device_state.resume_state_ack));
      wait_time.QuadPart = 100 * (-1 * 10 * 1000);
      KeDelayExecutionThread(KernelMode, FALSE, &wait_time);
      KdPrint((__DRIVER_NAME "     Done with delay\n"));
    }
    KdPrint((__DRIVER_NAME "     resume_state acknowledged\n"));

    XenPci_ChangeFrontendState(xppdd, XenbusStateClosing, XenbusStateClosing, 30000);
    XenPci_ChangeFrontendState(xppdd, XenbusStateClosed, XenbusStateClosed, 30000);
    XenPci_ChangeFrontendState(xppdd, XenbusStateInitialising, XenbusStateInitWait, 30000);

    if (xppdd->assigned_resources_start != NULL)
    {
      in_ptr = xppdd->assigned_resources_ptr;
      ADD_XEN_INIT_RSP(&in_ptr, XEN_INIT_TYPE_END, NULL, NULL);
      in_ptr = xppdd->assigned_resources_start;
      while((type = GET_XEN_INIT_RSP(&in_ptr, &setting, &value)) != XEN_INIT_TYPE_END)
      {
        switch (type)
        {
        case XEN_INIT_TYPE_EVENT_CHANNEL: /* frontend event channel */
        case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ: /* frontend event channel bound to irq */
          EvtChn_Close(xpdd, PtrToUlong(value));
          break;
        }
      }
    }

    RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
    XenBus_RemWatch(xpdd, XBT_NIL, path, XenPci_BackEndStateHandler, xppdd);  
  }
  else
  {
    xppdd->restart_on_resume = FALSE;
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
  
  return status;
}

static NTSTATUS
XenPci_Pnp_StartDevice(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  PIO_STACK_LOCATION stack;
  PCM_PARTIAL_RESOURCE_LIST prl;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR prd;
  ULONG i;
  char path[128];
 
  FUNCTION_ENTER();

  DUMP_CURRENT_PNP_STATE(xppdd);
  
  stack = IoGetCurrentIrpStackLocation(irp);

  status = XenPci_GetBackendAndAddWatch(device_object);
  if (!NT_SUCCESS(status)) {
    FUNCTION_ERROR_EXIT();
    return status;
  }

  prl = &stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList;
  for (i = 0; i < prl->Count; i++)
  {
    prd = & prl->PartialDescriptors[i];
    switch (prd->Type)
    {
    case CmResourceTypeInterrupt:
      KdPrint((__DRIVER_NAME "     CmResourceTypeInterrupt\n"));
      KdPrint((__DRIVER_NAME "     irq_vector = %02x\n", prd->u.Interrupt.Vector));
      KdPrint((__DRIVER_NAME "     irq_level = %d\n", prd->u.Interrupt.Level));
      xppdd->irq_vector = prd->u.Interrupt.Vector;
      xppdd->irq_level = (KIRQL)prd->u.Interrupt.Level;
      break;
    case CmResourceTypeMemory:
      KdPrint((__DRIVER_NAME "     CmResourceTypeMemory\n"));
      KdPrint((__DRIVER_NAME "     Start = %08x, Length = %d\n", prd->u.Memory.Start.LowPart, prd->u.Memory.Length));
      xppdd->config_page_phys = prd->u.Memory.Start;
      xppdd->config_page_length = prd->u.Memory.Length;
      xppdd->requested_resources_start = xppdd->requested_resources_ptr = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);
      xppdd->assigned_resources_start = xppdd->assigned_resources_ptr = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);
      
      status = XenPci_XenConfigDevice(xppdd);
      if (!NT_SUCCESS(status))
      {
        RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
        XenBus_RemWatch(xpdd, XBT_NIL, path, XenPci_BackEndStateHandler, xppdd);
        FUNCTION_ERROR_EXIT();
        return status;
      }
    }
  }
  SET_PNP_STATE(&xppdd->common, Started);
  
  FUNCTION_EXIT();

  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_Pnp_RemoveDevice(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_PDO_DEVICE_DATA xppdd = device_object->DeviceExtension;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  char path[128];

  UNREFERENCED_PARAMETER(irp);

  FUNCTION_ENTER();

  DUMP_CURRENT_PNP_STATE(xppdd);

  if (xppdd->common.current_pnp_state != Removed)
  {
    status = XenPci_XenShutdownDevice(xppdd);
    /* Remove watch on backend state */
    RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
    XenBus_RemWatch(xpdd, XBT_NIL, path, XenPci_BackEndStateHandler, xppdd);
    SET_PNP_STATE(&xppdd->common, Removed);
    IoInvalidateDeviceRelations(xppdd->bus_pdo, BusRelations);
  }
  if (xppdd->reported_missing)
  {
    IoDeleteDevice(xppdd->common.pdo);
  }
  
  FUNCTION_EXIT_STATUS(status);

  return status;
}

static NTSTATUS
XenPci_QueryResourceRequirements(PDEVICE_OBJECT device_object, PIRP irp)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  PIO_RESOURCE_REQUIREMENTS_LIST irrl;
  PIO_RESOURCE_DESCRIPTOR ird;
  ULONG length;
  //ULONG available_interrupts[] = {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}; //{3, 4, 5, 10, 11, 14};
  ULONG available_interrupts[] = {
    //62, 61, 60, 59, 58, 57, 56,
    //55, 54, 53, 52, 51, 50, 49, 48,
    47, 46, 45, 44, 43, 42, 41, 40,
    39, 38, 37, 36, 35, 34, 33, 32,
    31, 30, 29, 28, 27, 26, 25, 24,
    23, 22, 21, 20, 19, 18, 17, 16,
    //15, 14, 13, 12, 11, 10, 8,
    //7, 6, 5, 4, 3, 1
  };
  int i;

  UNREFERENCED_PARAMETER(device_object);

  length = FIELD_OFFSET(IO_RESOURCE_REQUIREMENTS_LIST, List) +
    FIELD_OFFSET(IO_RESOURCE_LIST, Descriptors) +
    sizeof(IO_RESOURCE_DESCRIPTOR) * ARRAY_SIZE(available_interrupts);
  irrl = ExAllocatePoolWithTag(NonPagedPool,
    length,
    XENPCI_POOL_TAG);
  
  irrl->ListSize = length;
  irrl->InterfaceType = PCIBus;
  irrl->BusNumber = 0;
  irrl->SlotNumber = 0;
  irrl->AlternativeLists = 1;
  irrl->List[0].Version = 1;
  irrl->List[0].Revision = 1;
  irrl->List[0].Count = 0;

  for (i = 0; i < ARRAY_SIZE(available_interrupts); i++)
  {
    if (i == (int)xpdd->irq_number)
      continue;
    ird = &irrl->List[0].Descriptors[irrl->List[0].Count++];
    ird->Option = i?IO_RESOURCE_ALTERNATIVE:0;
    ird->Type = CmResourceTypeInterrupt;
    if (available_interrupts[i] >= 16)
    {
      ird->Option |= IO_RESOURCE_PREFERRED;
      ird->ShareDisposition = CmResourceShareDeviceExclusive;
    }
    else
      ird->ShareDisposition = CmResourceShareShared;
    ird->Flags = CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
    ird->u.Interrupt.MinimumVector = available_interrupts[i];
    ird->u.Interrupt.MaximumVector = available_interrupts[i];
  }
  
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
  dc->EjectSupported = TRUE;
  dc->Removable = TRUE;
  dc->DockDevice = FALSE;
  dc->UniqueID = FALSE;
  dc->SilentInstall = TRUE; //FALSE;
  dc->RawDeviceOK = FALSE;
  dc->SurpriseRemovalOK = TRUE;
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
  ULONG *usage_type;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stack = IoGetCurrentIrpStackLocation(irp);

  switch (stack->MinorFunction)
  {
  case IRP_MN_START_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_START_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    status = XenPci_Pnp_StartDevice(device_object, irp);
    break;
    
  case IRP_MN_QUERY_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_STOP_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    SET_PNP_STATE(&xppdd->common, StopPending);
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_STOP_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    SET_PNP_STATE(&xppdd->common, Stopped);
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_CANCEL_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_STOP_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    REVERT_PNP_STATE(&xppdd->common);
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_QUERY_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_REMOVE_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    if (xppdd->eject_requested)
    {
      SET_PNP_STATE(&xppdd->common, RemovePending);
      status = STATUS_SUCCESS;
    }
    else
    {
      status = STATUS_UNSUCCESSFUL;
    }
    break;

  case IRP_MN_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_REMOVE_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    status = XenPci_Pnp_RemoveDevice(device_object, irp);
    break;

  case IRP_MN_CANCEL_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_REMOVE_DEVICE (status = %08x)\n", irp->IoStatus.Status));
    REVERT_PNP_STATE(&xppdd->common);
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_SURPRISE_REMOVAL:
    KdPrint((__DRIVER_NAME "     IRP_MN_SURPRISE_REMOVAL (status = %08x)\n", irp->IoStatus.Status));
    SET_PNP_STATE(&xppdd->common, SurpriseRemovePending);
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_DEVICE_USAGE_NOTIFICATION:
    KdPrint((__DRIVER_NAME "     IRP_MN_DEVICE_USAGE_NOTIFICATION (status = %08x)\n", irp->IoStatus.Status));
    
    usage_type = NULL;
    switch (stack->Parameters.UsageNotification.Type)
    {
    case DeviceUsageTypePaging:
      KdPrint((__DRIVER_NAME "     type = DeviceUsageTypePaging\n"));
      usage_type = &xppdd->common.device_usage_paging;
      break;
    case DeviceUsageTypeDumpFile:
      KdPrint((__DRIVER_NAME "     type = DeviceUsageTypeDumpFile\n"));
      usage_type = &xppdd->common.device_usage_dump;
      break;
    case DeviceUsageTypeHibernation:
      KdPrint((__DRIVER_NAME "     type = DeviceUsageTypeHibernation\n"));
      usage_type = &xppdd->common.device_usage_hibernation;
      break;
    default:
      KdPrint((__DRIVER_NAME " Unknown usage type %x\n",
        stack->Parameters.UsageNotification.Type));
      break;
    }
    KdPrint((__DRIVER_NAME "     inpath = %d\n", stack->Parameters.UsageNotification.InPath));
    if (usage_type)
    {
      if (stack->Parameters.UsageNotification.InPath)
        (*usage_type)++;
      else
        (*usage_type)--;
    }        
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

  case IRP_MN_EJECT:
    KdPrint((__DRIVER_NAME "     IRP_MN_EJECT\n"));
    status = STATUS_SUCCESS;
    break;
      
  default:
    //KdPrint((__DRIVER_NAME "     Unhandled Minor = %d, Status = %08x\n", stack->MinorFunction, irp->IoStatus.Status));
    status = irp->IoStatus.Status;
    break;
  }

  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

NTSTATUS
XenPci_Irp_Create_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  status = irp->IoStatus.Status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  FUNCTION_EXIT();

  return status;
}

NTSTATUS
XenPci_Irp_Close_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  status = irp->IoStatus.Status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  FUNCTION_EXIT();

  return status;
}

NTSTATUS
XenPci_Irp_Read_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  status = irp->IoStatus.Status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  FUNCTION_EXIT();

  return status;
}

NTSTATUS
XenPci_Irp_Cleanup_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();
  
  status = irp->IoStatus.Status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  
  FUNCTION_EXIT();

  return status;
}
