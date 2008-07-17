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
//#include <wdmsec.h>
#include <stdlib.h>

#define SYSRQ_PATH "control/sysrq"
#define SHUTDOWN_PATH "control/shutdown"
#define BALLOON_PATH "memory/target"

#if 0
static VOID
XenBus_BalloonHandler(char *Path, PVOID Data);
#endif

/*
static VOID
XenPCI_XenBusWatchHandler(char *Path, PVOID Data);
*/

#pragma warning(disable : 4200) // zero-sized array

//CM_PARTIAL_RESOURCE_DESCRIPTOR InterruptRaw;
//CM_PARTIAL_RESOURCE_DESCRIPTOR InterruptTranslated;

NTSTATUS
XenPci_Power_Fdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  POWER_STATE_TYPE power_type;
  POWER_STATE power_state;
  PXENPCI_DEVICE_DATA xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  //PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;

  UNREFERENCED_PARAMETER(device_object);
  
  FUNCTION_ENTER();

  stack = IoGetCurrentIrpStackLocation(irp);
  power_type = stack->Parameters.Power.Type;
  power_state = stack->Parameters.Power.State;

  switch (stack->MinorFunction)
  {
  case IRP_MN_POWER_SEQUENCE:
    KdPrint((__DRIVER_NAME "     IRP_MN_POWER_SEQUENCE\n"));
    break;
  case IRP_MN_QUERY_POWER:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_POWER\n"));
    break;
  case IRP_MN_SET_POWER:
    KdPrint((__DRIVER_NAME "     IRP_MN_SET_POWER\n"));
    switch (power_type) {
    case DevicePowerState:
      KdPrint((__DRIVER_NAME "     DevicePowerState\n"));
      break;
    case SystemPowerState:
      KdPrint((__DRIVER_NAME "     SystemPowerState\n"));
      break;
    default:
      break;
    }    
    break;
  case IRP_MN_WAIT_WAKE:
    break;
  }
  PoStartNextPowerIrp(irp);
  IoSkipCurrentIrpStackLocation(irp);
  status =  PoCallDriver (xpdd->common.lower_do, irp);
  
  FUNCTION_EXIT();

  return status;
}

NTSTATUS
XenPci_Dummy_Fdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PXENPCI_DEVICE_DATA xpdd;

  FUNCTION_ENTER();

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  stack = IoGetCurrentIrpStackLocation(irp);
  IoSkipCurrentIrpStackLocation(irp);
  status = IoCallDriver(xpdd->common.lower_do, irp);

  FUNCTION_EXIT();

  return status;
}

/*
 * Alloc MMIO from the device's MMIO region. There is no corresponding free() fn
 */
PHYSICAL_ADDRESS
XenPci_AllocMMIO(PXENPCI_DEVICE_DATA xpdd, ULONG len)
{
  PHYSICAL_ADDRESS addr;

  len = (len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

  addr = xpdd->platform_mmio_addr;
  addr.QuadPart += xpdd->platform_mmio_alloc;
  xpdd->platform_mmio_alloc += len;

  ASSERT(xpdd->platform_mmio_alloc <= xpdd->platform_mmio_len);

  return addr;
}

static NTSTATUS
XenPci_Init(PXENPCI_DEVICE_DATA xpdd)
{
  struct xen_add_to_physmap xatp;
  int ret;

  FUNCTION_ENTER();

  hvm_get_stubs(xpdd);

  if (!xpdd->shared_info_area_unmapped.QuadPart)
  {
    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
    /* this should be safe as this part will never be called on resume where IRQL == HIGH_LEVEL */
    xpdd->shared_info_area_unmapped = XenPci_AllocMMIO(xpdd, PAGE_SIZE);
    xpdd->shared_info_area = MmMapIoSpace(xpdd->shared_info_area_unmapped,
      PAGE_SIZE, MmNonCached);
  }
  KdPrint((__DRIVER_NAME " shared_info_area_unmapped.QuadPart = %lx\n", xpdd->shared_info_area_unmapped.QuadPart));
  xatp.domid = DOMID_SELF;
  xatp.idx = 0;
  xatp.space = XENMAPSPACE_shared_info;
  xatp.gpfn = (xen_pfn_t)(xpdd->shared_info_area_unmapped.QuadPart >> PAGE_SHIFT);
  KdPrint((__DRIVER_NAME " gpfn = %d\n", xatp.gpfn));
  ret = HYPERVISOR_memory_op(xpdd, XENMEM_add_to_physmap, &xatp);
  KdPrint((__DRIVER_NAME " hypervisor memory op ret = %d\n", ret));

  FUNCTION_EXIT();

  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_Pnp_IoCompletion(PDEVICE_OBJECT device_object, PIRP irp, PVOID context)
{
  PKEVENT event = (PKEVENT)context;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  if (irp->PendingReturned)
  {
    KeSetEvent(event, IO_NO_INCREMENT, FALSE);
  }

  FUNCTION_EXIT();

  return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
XenPci_QueueWorkItem(PDEVICE_OBJECT device_object, PIO_WORKITEM_ROUTINE routine, PVOID context)
{
  PIO_WORKITEM work_item;
  NTSTATUS status = STATUS_SUCCESS;

	work_item = IoAllocateWorkItem(device_object);
	IoQueueWorkItem(work_item, routine, DelayedWorkQueue, context);
	
  return status;
}

static NTSTATUS
XenPci_SendAndWaitForIrp(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_DEVICE_DATA xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  KEVENT event;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  KeInitializeEvent(&event, NotificationEvent, FALSE);

  IoCopyCurrentIrpStackLocationToNext(irp);
  IoSetCompletionRoutine(irp, XenPci_Pnp_IoCompletion, &event, TRUE, TRUE, TRUE);

  status = IoCallDriver(xpdd->common.lower_do, irp);

  if (status == STATUS_PENDING)
  {
    KdPrint((__DRIVER_NAME "     waiting ...\n"));
    KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
    KdPrint((__DRIVER_NAME "     ... done\n"));
    status = irp->IoStatus.Status;
  }

  FUNCTION_EXIT();

  return status;
}

static NTSTATUS
XenPci_ProcessShutdownIrp(PXENPCI_DEVICE_DATA xpdd)
{
  PIO_STACK_LOCATION stack;
  NTSTATUS status;
  PIRP irp;
  KIRQL old_irql;
  ULONG length;

  FUNCTION_ENTER();

  KeAcquireSpinLock(&xpdd->shutdown_ring_lock, &old_irql);
  if (xpdd->shutdown_irp)
  {
    irp = xpdd->shutdown_irp;
    stack = IoGetCurrentIrpStackLocation(irp);
    KdPrint((__DRIVER_NAME "     stack = %p\n", stack));
    KdPrint((__DRIVER_NAME "     length = %d, buffer = %p\n", stack->Parameters.Read.Length, irp->AssociatedIrp.SystemBuffer));
    length = min(xpdd->shutdown_prod - xpdd->shutdown_cons, stack->Parameters.Read.Length);
    KdPrint((__DRIVER_NAME "     length = %d\n", length));
    if (length > 0)
    {
      memcpy(irp->AssociatedIrp.SystemBuffer, &xpdd->shutdown_ring[xpdd->shutdown_cons & (SHUTDOWN_RING_SIZE - 1)], length);
      xpdd->shutdown_cons += length;
      if (xpdd->shutdown_cons > SHUTDOWN_RING_SIZE)
      {
        xpdd->shutdown_cons -= SHUTDOWN_RING_SIZE;
        xpdd->shutdown_prod -= SHUTDOWN_RING_SIZE;
        xpdd->shutdown_start -= SHUTDOWN_RING_SIZE;
      }
      xpdd->shutdown_irp = NULL;
      KeReleaseSpinLock(&xpdd->shutdown_ring_lock, old_irql);
      status = STATUS_SUCCESS;    
      irp->IoStatus.Status = status;
      irp->IoStatus.Information = length;
      IoSetCancelRoutine(irp, NULL);
      IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
    else
    {
      KeReleaseSpinLock(&xpdd->shutdown_ring_lock, old_irql);
      KdPrint((__DRIVER_NAME "     nothing to read... pending\n"));
      IoMarkIrpPending(irp);
      status = STATUS_PENDING;
    }
  }
  else
  {
    KdPrint((__DRIVER_NAME "     no pending irp\n"));
    KeReleaseSpinLock(&xpdd->shutdown_ring_lock, old_irql);
    status = STATUS_SUCCESS;
  }  

  FUNCTION_EXIT();

  return status;
}

static VOID
XenBus_ShutdownIoCancel(PDEVICE_OBJECT device_object, PIRP irp)
{
  PXENPCI_DEVICE_DATA xpdd;
  KIRQL old_irql;

  FUNCTION_ENTER();

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  IoReleaseCancelSpinLock(irp->CancelIrql);
  KeAcquireSpinLock(&xpdd->shutdown_ring_lock, &old_irql);
  if (irp == xpdd->shutdown_irp)
  {
    KdPrint((__DRIVER_NAME "     Not the current irp???\n"));
    xpdd->shutdown_irp = NULL;
  }
  irp->IoStatus.Status = STATUS_CANCELLED;
  irp->IoStatus.Information = 0;
  KeReleaseSpinLock(&xpdd->shutdown_ring_lock, old_irql);
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  FUNCTION_EXIT();
}

struct {
  volatile ULONG do_spin;
  volatile LONG nr_spinning;
  KEVENT stopped_spinning_event;
} typedef SUSPEND_INFO, *PSUSPEND_INFO;

/* runs at PASSIVE_LEVEL */
static DDKAPI VOID
XenPci_CompleteResume(PDEVICE_OBJECT device_object, PVOID context)
{
  PSUSPEND_INFO suspend_info = context;
  PXENPCI_DEVICE_DATA xpdd;
  PXEN_CHILD child;

  UNREFERENCED_PARAMETER(context);
  FUNCTION_ENTER();

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;

  while (suspend_info->nr_spinning != 0)
  {
    KdPrint((__DRIVER_NAME "     %d processors are still spinning\n", suspend_info->nr_spinning));
    KeWaitForSingleObject(&suspend_info->stopped_spinning_event, Executive, KernelMode, FALSE, NULL);
  }
  KdPrint((__DRIVER_NAME "     all other processors have stopped spinning\n"));

  /* this has to be done at PASSIVE_LEVEL */
  EvtChn_ConnectInterrupt(xpdd);

  XenBus_Resume(xpdd);

  for (child = (PXEN_CHILD)xpdd->child_list.Flink; child != (PXEN_CHILD)&xpdd->child_list; child = (PXEN_CHILD)child->entry.Flink)
  {
    XenPci_Resume(child->context->common.pdo);
    child->context->device_state.resume_state = RESUME_STATE_FRONTEND_RESUME;
    // how can we signal children that they are ready to restart again?
    // maybe we can fake an interrupt?
  }

  xpdd->suspend_state = SUSPEND_STATE_NONE;

  FUNCTION_EXIT();
}

/* Called at DISPATCH_LEVEL */
static DDKAPI VOID
XenPci_Suspend(
  PRKDPC Dpc,
  PVOID Context,
  PVOID SystemArgument1,
  PVOID SystemArgument2)
{
  PXENPCI_DEVICE_DATA xpdd = Context;
  PSUSPEND_INFO suspend_info = SystemArgument1;
  ULONG ActiveProcessorCount;
  KIRQL old_irql;
  int cancelled;
  PIO_WORKITEM work_item;
  PXEN_CHILD child;
  //PUCHAR gnttbl_backup[PAGE_SIZE * NR_GRANT_FRAMES];

  UNREFERENCED_PARAMETER(Dpc);
  UNREFERENCED_PARAMETER(SystemArgument2);

  FUNCTION_ENTER();
  FUNCTION_MSG(("(CPU = %d)\n", KeGetCurrentProcessorNumber()));

  if (KeGetCurrentProcessorNumber() != 0)
  {
    KeRaiseIrql(HIGH_LEVEL, &old_irql);
    KdPrint((__DRIVER_NAME "     spinning...\n"));
    InterlockedIncrement(&suspend_info->nr_spinning);
    KeMemoryBarrier();
    while(suspend_info->do_spin)
    {
      KeStallExecutionProcessor(1);
      KeMemoryBarrier();
      /* can't call HYPERVISOR_yield() here as the stubs will be reset and we will crash */
    }
    KeMemoryBarrier();
    InterlockedDecrement(&suspend_info->nr_spinning);    
    KdPrint((__DRIVER_NAME "     ...done spinning\n"));
    FUNCTION_MSG(("(CPU = %d)\n", KeGetCurrentProcessorNumber()));
    KeLowerIrql(old_irql);
    KeSetEvent(&suspend_info->stopped_spinning_event, IO_NO_INCREMENT, FALSE);
    FUNCTION_EXIT();
    return;
  }
  ActiveProcessorCount = (ULONG)KeNumberProcessors;

  KeRaiseIrql(HIGH_LEVEL, &old_irql);
  
  KdPrint((__DRIVER_NAME "     waiting for all other processors to spin\n"));
  while (suspend_info->nr_spinning < (LONG)ActiveProcessorCount - 1)
  {
      HYPERVISOR_yield(xpdd);
      KeMemoryBarrier();
  }
  KdPrint((__DRIVER_NAME "     all other processors are spinning\n"));

  xpdd->suspend_state = SUSPEND_STATE_HIGH_IRQL;
  KeMemoryBarrier();
  
  KdPrint((__DRIVER_NAME "     calling suspend\n"));
  cancelled = hvm_shutdown(Context, SHUTDOWN_suspend);
  KdPrint((__DRIVER_NAME "     back from suspend, cancelled = %d\n", cancelled));

  XenPci_Init(xpdd);
  
  GntTbl_InitMap(Context);

  /* this enables interrupts again too */  
  EvtChn_Init(xpdd);

  for (child = (PXEN_CHILD)xpdd->child_list.Flink; child != (PXEN_CHILD)&xpdd->child_list; child = (PXEN_CHILD)child->entry.Flink)
  {
    child->context->device_state.resume_state = RESUME_STATE_BACKEND_RESUME;
  }

  KeLowerIrql(old_irql);
  xpdd->suspend_state = SUSPEND_STATE_RESUMING;
  KeMemoryBarrier();
  
  KdPrint((__DRIVER_NAME "     waiting for all other processors to stop spinning\n"));
  suspend_info->do_spin = 0;
  KeMemoryBarrier();

	work_item = IoAllocateWorkItem(xpdd->common.fdo);
	IoQueueWorkItem(work_item, XenPci_CompleteResume, DelayedWorkQueue, suspend_info);
  
  FUNCTION_EXIT();
}

/* Called at PASSIVE_LEVEL */
static VOID DDKAPI
XenPci_BeginSuspend(PDEVICE_OBJECT device_object, PVOID context)
{
  //KAFFINITY ActiveProcessorMask = 0; // this is for Vista+
  PXENPCI_DEVICE_DATA xpdd = device_object->DeviceExtension;
  ULONG ActiveProcessorCount;
  ULONG i;
  PSUSPEND_INFO suspend_info;
  PKDPC Dpc;
  KIRQL OldIrql;

  UNREFERENCED_PARAMETER(context);
  FUNCTION_ENTER();

  if (xpdd->suspend_state == SUSPEND_STATE_NONE)
  {
    XenBus_StopThreads(xpdd);
    xpdd->suspend_state = SUSPEND_STATE_SCHEDULED;
    suspend_info = ExAllocatePoolWithTag(NonPagedPool, sizeof(SUSPEND_INFO), XENPCI_POOL_TAG);
    RtlZeroMemory(suspend_info, sizeof(SUSPEND_INFO));
    KeInitializeEvent(&suspend_info->stopped_spinning_event, SynchronizationEvent, FALSE);
    suspend_info->do_spin = 1;

    for (i = 0; i < MAX_VIRT_CPUS; i++)
    {
      xpdd->shared_info_area->vcpu_info[i].evtchn_upcall_mask = 1;
    }
    KeMemoryBarrier();
    EvtChn_Shutdown(xpdd);

    //ActiveProcessorCount = KeQueryActiveProcessorCount(&ActiveProcessorMask); // this is for Vista+
    ActiveProcessorCount = (ULONG)KeNumberProcessors;
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    for (i = 0; i < ActiveProcessorCount; i++)
    {
      Dpc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KDPC), XENPCI_POOL_TAG);
      KeInitializeDpc(Dpc, XenPci_Suspend, xpdd);
      KeSetTargetProcessorDpc(Dpc, (CCHAR)i);
      KeInsertQueueDpc(Dpc, suspend_info, NULL);
    }
    KeLowerIrql(OldIrql);
  }
  FUNCTION_EXIT();
}

static void
XenPci_ShutdownHandler(char *path, PVOID context)
{
  PXENPCI_DEVICE_DATA xpdd = (PXENPCI_DEVICE_DATA)context;
  char *res;
  char *value;
  KIRQL old_irql;
  PIO_WORKITEM work_item;

  UNREFERENCED_PARAMETER(path);

  FUNCTION_ENTER();

  res = XenBus_Read(xpdd, XBT_NIL, SHUTDOWN_PATH, &value);
  if (res)
  {
    KdPrint(("Error reading shutdown path - %s\n", res));
    XenPci_FreeMem(res);
    return;
  }

  KdPrint((__DRIVER_NAME "     Shutdown value = %s\n", value));

  if (strlen(value) != 0)
  {
    if (strcmp(value, "suspend") == 0)
    {
      KdPrint((__DRIVER_NAME "     Suspend detected\n"));
      /* we have to queue this as a work item as we stop the xenbus thread, which we are currently running in! */
    	work_item = IoAllocateWorkItem(xpdd->common.fdo);
      IoQueueWorkItem(work_item, XenPci_BeginSuspend, DelayedWorkQueue, NULL);
      //XenPci_BeginSuspend(xpdd);
    }
    else
    {
      KeAcquireSpinLock(&xpdd->shutdown_ring_lock, &old_irql);
      if (xpdd->shutdown_start >= xpdd->shutdown_cons)
        xpdd->shutdown_prod = xpdd->shutdown_start;
      else
        xpdd->shutdown_start = xpdd->shutdown_prod;
      memcpy(&xpdd->shutdown_ring[xpdd->shutdown_prod], value, strlen(value));
      xpdd->shutdown_prod += (ULONG)strlen(value);
      xpdd->shutdown_ring[xpdd->shutdown_prod++] = '\r';
      xpdd->shutdown_ring[xpdd->shutdown_prod++] = '\n';
      KeReleaseSpinLock(&xpdd->shutdown_ring_lock, old_irql);
      XenPci_ProcessShutdownIrp(xpdd);
    }
  }

  //XenPci_FreeMem(value);

  FUNCTION_EXIT();
}

static VOID
XenPci_SysrqHandler(char *path, PVOID context)
{
  PXENPCI_DEVICE_DATA xpdd = context;
  char *value;
  char letter;
  char *res;

  UNREFERENCED_PARAMETER(path);

  FUNCTION_ENTER();

  XenBus_Read(xpdd, XBT_NIL, SYSRQ_PATH, &value);

  KdPrint((__DRIVER_NAME "     SysRq Value = %s\n", value));

  if (value != NULL && strlen(value) != 0)
  {
    letter = *value;
    res = XenBus_Write(xpdd, XBT_NIL, SYSRQ_PATH, "");
    if (res)
    {
      KdPrint(("Error writing sysrq path\n"));
      XenPci_FreeMem(res);
      return;
    }
  }
  else
  {
    letter = 0;
  }

  if (value != NULL)
  {
    XenPci_FreeMem(value);
  }

  switch (letter)
  {
  case 'B':
    KeBugCheckEx(('X' << 16)|('E' << 8)|('N'), 0x00000001, 0x00000000, 0x00000000, 0x00000000);
    break;
  default:
    KdPrint(("     Unhandled sysrq letter %c\n", letter));
    break;
  }

  FUNCTION_EXIT();
}

static VOID
XenPci_DeviceWatchHandler(char *path, PVOID context)
{
  char **bits;
  int count;
  char *err;
  char *value;
  PXENPCI_DEVICE_DATA xpdd = context;

//  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

//  KdPrint((__DRIVER_NAME "     path = %s\n", path));
  bits = SplitString(path, '/', 4, &count);
//  KdPrint((__DRIVER_NAME "     count = %d\n", count));

  if (count == 3)
  {
    err = XenBus_Read(xpdd, XBT_NIL, path, &value);
    if (err)
    {
      /* obviously path no longer exists, in which case the removal is being taken care of elsewhere and we shouldn't invalidate now */
      XenPci_FreeMem(err);
    }
    else
    {
      XenPci_FreeMem(value);
      /* we probably have to be a bit smarter here and do nothing if xenpci isn't running yet */
      KdPrint((__DRIVER_NAME "     Invalidating Device Relations\n"));
      IoInvalidateDeviceRelations(xpdd->common.pdo, BusRelations);
    }
  }
  FreeSplitString(bits, count);

//  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static DDKAPI VOID
XenPci_Pnp_StartDeviceCallback(PDEVICE_OBJECT device_object, PVOID context)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_DEVICE_DATA xpdd = device_object->DeviceExtension;
  PIRP irp = context;
  char *response;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  
  XenPci_Init(xpdd);

  GntTbl_Init(xpdd);

  EvtChn_Init(xpdd);
  EvtChn_ConnectInterrupt(xpdd);

  XenBus_Init(xpdd);

  response = XenBus_AddWatch(xpdd, XBT_NIL, SYSRQ_PATH, XenPci_SysrqHandler, xpdd);
  KdPrint((__DRIVER_NAME "     sysrqwatch response = '%s'\n", response)); 
  
  response = XenBus_AddWatch(xpdd, XBT_NIL, SHUTDOWN_PATH, XenPci_ShutdownHandler, xpdd);
  KdPrint((__DRIVER_NAME "     shutdown watch response = '%s'\n", response)); 

  response = XenBus_AddWatch(xpdd, XBT_NIL, "device", XenPci_DeviceWatchHandler, xpdd);
  KdPrint((__DRIVER_NAME "     device watch response = '%s'\n", response)); 

#if 0
  response = XenBus_AddWatch(xpdd, XBT_NIL, BALLOON_PATH, XenPci_BalloonHandler, Device);
  KdPrint((__DRIVER_NAME "     balloon watch response = '%s'\n", response)); 
#endif

  status = IoSetDeviceInterfaceState(&xpdd->interface_name, TRUE);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     IoSetDeviceInterfaceState failed with status 0x%08x\n", status));
  }

  irp->IoStatus.Status = status;
  
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));
}

static NTSTATUS
XenPci_Pnp_StartDevice(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_DEVICE_DATA xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  PIO_STACK_LOCATION stack;
  PCM_PARTIAL_RESOURCE_LIST res_list;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR res_descriptor;
  ULONG i;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  stack = IoGetCurrentIrpStackLocation(irp);

  IoMarkIrpPending(irp);

  status = XenPci_SendAndWaitForIrp(device_object, irp);

  res_list = &stack->Parameters.StartDevice.AllocatedResources->List[0].PartialResourceList;
  
  for (i = 0; i < res_list->Count; i++)
  {
    res_descriptor = &res_list->PartialDescriptors[i];
    switch (res_descriptor->Type)
    {
    case CmResourceTypeInterrupt:
      KdPrint((__DRIVER_NAME "     irq_number = %03x\n", res_descriptor->u.Interrupt.Vector));
      xpdd->irq_number = res_descriptor->u.Interrupt.Vector;
      //memcpy(&InterruptRaw, res_descriptor, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
      break;
    }
  }

  res_list = &stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList;
  
  for (i = 0; i < res_list->Count; i++)
  {
    res_descriptor = &res_list->PartialDescriptors[i];
    switch (res_descriptor->Type) {
    case CmResourceTypePort:
      break;
    case CmResourceTypeMemory:
      KdPrint((__DRIVER_NAME "     Memory mapped CSR:(%x:%x) Length:(%d)\n", res_descriptor->u.Memory.Start.LowPart, res_descriptor->u.Memory.Start.HighPart, res_descriptor->u.Memory.Length));
      KdPrint((__DRIVER_NAME "     Memory flags = %04X\n", res_descriptor->Flags));
      xpdd->platform_mmio_addr = res_descriptor->u.Memory.Start;
      xpdd->platform_mmio_len = res_descriptor->u.Memory.Length;
      xpdd->platform_mmio_alloc = 0;
      xpdd->platform_mmio_flags = res_descriptor->Flags;
      break;
    case CmResourceTypeInterrupt:
      KdPrint((__DRIVER_NAME "     irq_vector = %03x\n", res_descriptor->u.Interrupt.Vector));
      KdPrint((__DRIVER_NAME "     irq_level = %03x\n", res_descriptor->u.Interrupt.Level));
	    xpdd->irq_level = (KIRQL)res_descriptor->u.Interrupt.Level;
  	  xpdd->irq_vector = res_descriptor->u.Interrupt.Vector;
	    xpdd->irq_affinity = res_descriptor->u.Interrupt.Affinity;
      //memcpy(&InterruptTranslated, res_descriptor, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
      break;
    case CmResourceTypeDevicePrivate:
      KdPrint((__DRIVER_NAME "     Private Data: 0x%02x 0x%02x 0x%02x\n", res_descriptor->u.DevicePrivate.Data[0], res_descriptor->u.DevicePrivate.Data[1], res_descriptor->u.DevicePrivate.Data[2] ));
      break;
    default:
      KdPrint((__DRIVER_NAME "     Unhandled resource type (0x%x)\n", res_descriptor->Type));
      break;
    }
  }

  XenPci_QueueWorkItem(device_object, XenPci_Pnp_StartDeviceCallback, irp);

  FUNCTION_EXIT();
  
  return STATUS_PENDING;
}

static NTSTATUS
XenPci_Pnp_StopDevice(PDEVICE_OBJECT device_object, PIRP irp, PVOID context)
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(device_object);
  UNREFERENCED_PARAMETER(context);

  FUNCTION_ENTER();

  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  FUNCTION_EXIT();

  return irp->IoStatus.Status;
}

static NTSTATUS
XenPci_Pnp_QueryStopRemoveDevice(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_DEVICE_DATA xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  if (xpdd->common.device_usage_paging
    || xpdd->common.device_usage_dump
    || xpdd->common.device_usage_hibernation)
  {
    /* We are in the paging or hibernation path - can't remove */
    status = irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
  }
  else
  {
    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(xpdd->common.lower_do, irp);
  }
  
  FUNCTION_EXIT();

  return status;
}

static NTSTATUS
XenPci_Pnp_RemoveDevice(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_DEVICE_DATA xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  irp->IoStatus.Status = STATUS_SUCCESS;
  IoSkipCurrentIrpStackLocation(irp);
  status = IoCallDriver(xpdd->common.lower_do, irp);
  IoDetachDevice(xpdd->common.lower_do);

  FUNCTION_EXIT();

  return status;
}

static DDKAPI VOID
XenPci_Pnp_QueryBusRelationsCallback(PDEVICE_OBJECT device_object, PVOID context)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_DEVICE_DATA xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  PXENPCI_PDO_DEVICE_DATA xppdd;
  PIRP irp = context;
  int device_count = 0;
  PDEVICE_RELATIONS dev_relations;
  PXEN_CHILD child, old_child;
  //char *response;
  char *msg;
  char **devices;
  char **instances;
  int i, j;
  CHAR path[128];
  PDEVICE_OBJECT pdo;
  
  FUNCTION_ENTER();

  msg = XenBus_List(xpdd, XBT_NIL, "device", &devices);
  if (!msg)
  {
    for (child = (PXEN_CHILD)xpdd->child_list.Flink; child != (PXEN_CHILD)&xpdd->child_list; child = (PXEN_CHILD)child->entry.Flink)
    {
      if (child->state == CHILD_STATE_DELETED)
        KdPrint((__DRIVER_NAME "     Found deleted child - this shouldn't happen\n" ));
      child->state = CHILD_STATE_DELETED;
    }

    for (i = 0; devices[i]; i++)
    {
      RtlStringCbPrintfA(path, ARRAY_SIZE(path), "device/%s", devices[i]);
      msg = XenBus_List(xpdd, XBT_NIL, path, &instances);
      if (!msg)
      {
        for (j = 0; instances[j]; j++)
        {
          RtlStringCbPrintfA(path, ARRAY_SIZE(path), "device/%s/%s", devices[i], instances[j]);
        
          for (child = (PXEN_CHILD)xpdd->child_list.Flink; child != (PXEN_CHILD)&xpdd->child_list; child = (PXEN_CHILD)child->entry.Flink)
          {
            if (strcmp(child->context->path, path) == 0)
            {
              KdPrint((__DRIVER_NAME "     Existing device %s\n", path));
              ASSERT(child->state == CHILD_STATE_DELETED);
              child->state = CHILD_STATE_ADDED;
              device_count++;
              break;
            }
          }
        
          if (child == (PXEN_CHILD)&xpdd->child_list)
          {
            KdPrint((__DRIVER_NAME "     New device %s\n", path));
            child = ExAllocatePoolWithTag(NonPagedPool, sizeof(XEN_CHILD), XENPCI_POOL_TAG);
            child->state = CHILD_STATE_ADDED;
            status = IoCreateDevice(
              xpdd->common.fdo->DriverObject,
              sizeof(XENPCI_PDO_DEVICE_DATA),
              NULL,
              FILE_DEVICE_UNKNOWN,
              FILE_AUTOGENERATED_DEVICE_NAME | FILE_DEVICE_SECURE_OPEN,
              FALSE,
              &pdo);
            if (!NT_SUCCESS(status))
              KdPrint((__DRIVER_NAME "     IoCreateDevice status = %08X\n", status));
            RtlZeroMemory(pdo->DeviceExtension, sizeof(XENPCI_PDO_DEVICE_DATA));
            child->context = xppdd = pdo->DeviceExtension;
            xppdd->common.fdo = NULL;
            xppdd->common.pdo = pdo;
            ObReferenceObject(pdo);
            xppdd->common.lower_do = NULL;
            INIT_PNP_STATE(&xppdd->common);
            xppdd->common.device_usage_paging = 0;
            xppdd->common.device_usage_dump = 0;
            xppdd->common.device_usage_hibernation = 0;
            xppdd->bus_fdo = xpdd->common.fdo;
            xppdd->bus_pdo = xpdd->common.pdo;
            RtlStringCbCopyA(xppdd->path, ARRAY_SIZE(xppdd->path), path);
            RtlStringCbCopyA(xppdd->device, ARRAY_SIZE(xppdd->device), devices[i]);
            xppdd->index = atoi(instances[j]);
            KeInitializeEvent(&xppdd->backend_state_event, SynchronizationEvent, FALSE);
            xppdd->backend_state = XenbusStateUnknown;
            xppdd->backend_path[0] = '\0';
            InsertTailList(&xpdd->child_list, (PLIST_ENTRY)child);
            device_count++;
          }
          XenPci_FreeMem(instances[j]);
        }
        XenPci_FreeMem(instances);
      }
      XenPci_FreeMem(devices[i]);
    }
    XenPci_FreeMem(devices);
    dev_relations = ExAllocatePoolWithTag(NonPagedPool, sizeof(DEVICE_RELATIONS) + sizeof(PDEVICE_OBJECT) * (device_count - 1), XENPCI_POOL_TAG);
    for (child = (PXEN_CHILD)xpdd->child_list.Flink, device_count = 0; child != (PXEN_CHILD)&xpdd->child_list; child = (PXEN_CHILD)child->entry.Flink)
    {
      if (child->state == CHILD_STATE_ADDED)
      {
        ObReferenceObject(child->context->common.pdo);
        dev_relations->Objects[device_count++] = child->context->common.pdo;
      }
    }
    dev_relations->Count = device_count;

    child = (PXEN_CHILD)xpdd->child_list.Flink;
    while (child != (PXEN_CHILD)&xpdd->child_list)
    {
      if (child->state == CHILD_STATE_DELETED)
      {
        KdPrint((__DRIVER_NAME "     Removing deleted child from device list\n" ));
        old_child = child;
        child = (PXEN_CHILD)child->entry.Flink;
        RemoveEntryList((PLIST_ENTRY)old_child);
        xppdd = old_child->context;
        xppdd->reported_missing = TRUE;
        ObDereferenceObject(xppdd->common.pdo);
        ExFreePoolWithTag(old_child, XENPCI_POOL_TAG);
      }
      else
        child = (PXEN_CHILD)child->entry.Flink;
    }
    
    status = STATUS_SUCCESS;
  }
  else
  {
    /* this should probably fail in an even worse way - a failure here means we failed to do an ls in xenbus so something is really really wrong */
    device_count = 0;
    dev_relations = ExAllocatePoolWithTag(NonPagedPool, sizeof(DEVICE_RELATIONS) + sizeof(PDEVICE_OBJECT) * (device_count - 1), XENPCI_POOL_TAG);
    dev_relations->Count = device_count;
  }

  irp->IoStatus.Status = status;
  irp->IoStatus.Information = (ULONG_PTR)dev_relations;

  IoCompleteRequest (irp, IO_NO_INCREMENT);

  FUNCTION_EXIT();
}

static NTSTATUS
XenPci_Pnp_QueryBusRelations(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  IoMarkIrpPending(irp);

  status = XenPci_SendAndWaitForIrp(device_object, irp);

  XenPci_QueueWorkItem(device_object, XenPci_Pnp_QueryBusRelationsCallback, irp);

  FUNCTION_EXIT();

  return STATUS_PENDING;
}

static DDKAPI VOID
XenPci_Pnp_FilterResourceRequirementsCallback(PDEVICE_OBJECT device_object, PVOID context)
{
  NTSTATUS status = STATUS_SUCCESS;
  //PXENPCI_DEVICE_DATA xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  PIRP irp = context;
  PIO_RESOURCE_REQUIREMENTS_LIST irrl;
  ULONG irl;
  ULONG ird;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();
  FUNCTION_MSG(("IoStatus.status = %08X\n", irp->IoStatus.Status));
  
  irrl = (PIO_RESOURCE_REQUIREMENTS_LIST)irp->IoStatus.Information;
  for (irl = 0; irl < irrl->AlternativeLists; irl++)
  {
    for (ird = 0; ird < irrl->List[irl].Count; ird++)
    {
      if (irrl->List[irl].Descriptors[ird].Type == CmResourceTypeMemory)
      {
        irrl->List[irl].Descriptors[ird].ShareDisposition = CmResourceShareShared;
      }
    }
  }
  irp->IoStatus.Status = status;
  IoCompleteRequest (irp, IO_NO_INCREMENT);
  
  FUNCTION_EXIT();
}

static NTSTATUS
XenPci_Pnp_FilterResourceRequirements(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  IoMarkIrpPending(irp);

  status = XenPci_SendAndWaitForIrp(device_object, irp);

  XenPci_QueueWorkItem(device_object, XenPci_Pnp_FilterResourceRequirementsCallback, irp);

  FUNCTION_EXIT();

  return STATUS_PENDING;
}

static NTSTATUS
XenPci_Pnp_DeviceUsageNotification(PDEVICE_OBJECT device_object, PIRP irp, PVOID context)
{
  NTSTATUS status;
  PXENPCI_DEVICE_DATA xpdd;
  PIO_STACK_LOCATION stack;
  
  UNREFERENCED_PARAMETER(context);

  FUNCTION_ENTER();

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  stack = IoGetCurrentIrpStackLocation(irp);
  status = irp->IoStatus.Status;

  /* fail if we are in a stop or remove pending state */  
  if (!NT_SUCCESS(irp->IoStatus.Status))
  {
    switch (stack->Parameters.UsageNotification.Type)
    {
    case DeviceUsageTypePaging:
      if (stack->Parameters.UsageNotification.InPath)
        xpdd->common.device_usage_paging--;
      else
        xpdd->common.device_usage_paging++;      
      break;
    case DeviceUsageTypeDumpFile:
      if (stack->Parameters.UsageNotification.InPath)
        xpdd->common.device_usage_dump--;
      else
        xpdd->common.device_usage_dump++;      
      break;
    case DeviceUsageTypeHibernation:
      if (stack->Parameters.UsageNotification.InPath)
        xpdd->common.device_usage_hibernation--;
      else
        xpdd->common.device_usage_hibernation++;      
      break;
    default:
      KdPrint((__DRIVER_NAME " Unknown usage type %x\n",
        stack->Parameters.UsageNotification.Type));
      break;
    }
    if (xpdd->common.device_usage_paging
      || xpdd->common.device_usage_dump
      || xpdd->common.device_usage_hibernation)
    {
      xpdd->common.fdo->Flags &= ~DO_POWER_PAGABLE;
    }
    IoInvalidateDeviceState(xpdd->common.pdo);
  }
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  FUNCTION_EXIT();
  
  return status;
}


NTSTATUS
XenPci_Pnp_Fdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PXENPCI_DEVICE_DATA xpdd;

  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;

  stack = IoGetCurrentIrpStackLocation(irp);

  switch (stack->MinorFunction)
  {
  case IRP_MN_START_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_START_DEVICE\n"));
    return XenPci_Pnp_StartDevice(device_object, irp);

  case IRP_MN_QUERY_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_STOP_DEVICE\n"));
    status = XenPci_Pnp_QueryStopRemoveDevice(device_object, irp);
    if (NT_SUCCESS(status))
      SET_PNP_STATE(&xpdd->common, RemovePending);
    return status;

  case IRP_MN_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_STOP_DEVICE\n"));
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, XenPci_Pnp_StopDevice, NULL, TRUE, TRUE, TRUE);
    break;

  case IRP_MN_CANCEL_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_STOP_DEVICE\n"));
    IoSkipCurrentIrpStackLocation(irp);
    REVERT_PNP_STATE(&xpdd->common);
    irp->IoStatus.Status = STATUS_SUCCESS;
    break;

  case IRP_MN_QUERY_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_REMOVE_DEVICE\n"));
    status = XenPci_Pnp_QueryStopRemoveDevice(device_object, irp);
    if (NT_SUCCESS(status))
      SET_PNP_STATE(&xpdd->common, RemovePending);
    return status;

  case IRP_MN_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_REMOVE_DEVICE\n"));
    return XenPci_Pnp_RemoveDevice(device_object, irp);
    break;

  case IRP_MN_CANCEL_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_REMOVE_DEVICE\n"));
    IoSkipCurrentIrpStackLocation(irp);
    REVERT_PNP_STATE(&xpdd->common);
    irp->IoStatus.Status = STATUS_SUCCESS;
    break;

  case IRP_MN_SURPRISE_REMOVAL:
    KdPrint((__DRIVER_NAME "     IRP_MN_SURPRISE_REMOVAL\n"));
    IoSkipCurrentIrpStackLocation(irp);
    irp->IoStatus.Status = STATUS_SUCCESS;
    break;

  case IRP_MN_DEVICE_USAGE_NOTIFICATION:
    KdPrint((__DRIVER_NAME "     IRP_MN_DEVICE_USAGE_NOTIFICATION\n"));
    switch (stack->Parameters.UsageNotification.Type)
    {
    case DeviceUsageTypePaging:
      KdPrint((__DRIVER_NAME "     type = DeviceUsageTypePaging = %d\n", stack->Parameters.UsageNotification.InPath));
      if (stack->Parameters.UsageNotification.InPath)
        xpdd->common.device_usage_paging++;
      else
        xpdd->common.device_usage_paging--;      
      irp->IoStatus.Status = STATUS_SUCCESS;
      break;
    case DeviceUsageTypeDumpFile:
      KdPrint((__DRIVER_NAME "     type = DeviceUsageTypeDumpFile = %d\n", stack->Parameters.UsageNotification.InPath));
      if (stack->Parameters.UsageNotification.InPath)
        xpdd->common.device_usage_dump++;
      else
        xpdd->common.device_usage_dump--;      
      irp->IoStatus.Status = STATUS_SUCCESS;
      break;
    case DeviceUsageTypeHibernation:
      KdPrint((__DRIVER_NAME "     type = DeviceUsageTypeHibernation = %d\n", stack->Parameters.UsageNotification.InPath));
      if (stack->Parameters.UsageNotification.InPath)
        xpdd->common.device_usage_hibernation++;
      else
        xpdd->common.device_usage_hibernation--;      
      irp->IoStatus.Status = STATUS_SUCCESS;
      break;
    default:
      KdPrint((__DRIVER_NAME "     type = unsupported (%d)\n", stack->Parameters.UsageNotification.Type));      
      irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
      IoCompleteRequest(irp, IO_NO_INCREMENT);
      return STATUS_NOT_SUPPORTED;
    }
    if (!xpdd->common.device_usage_paging
      && !xpdd->common.device_usage_dump
      && !xpdd->common.device_usage_hibernation)
    {
      xpdd->common.fdo->Flags |= DO_POWER_PAGABLE;
    }
    IoInvalidateDeviceState(xpdd->common.pdo);
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, XenPci_Pnp_DeviceUsageNotification, NULL, TRUE, TRUE, TRUE);
    break;

  case IRP_MN_QUERY_DEVICE_RELATIONS:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_DEVICE_RELATIONS\n"));
    switch (stack->Parameters.QueryDeviceRelations.Type)
    {
    case BusRelations:
      KdPrint((__DRIVER_NAME "     BusRelations\n"));
      return XenPci_Pnp_QueryBusRelations(device_object, irp);
      break;  
    default:
      IoSkipCurrentIrpStackLocation(irp);
      break;  
    }
    break;

  case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
    KdPrint((__DRIVER_NAME "     IRP_MN_FILTER_RESOURCE_REQUIREMENTS\n"));
    return XenPci_Pnp_FilterResourceRequirements(device_object, irp);

  case IRP_MN_QUERY_PNP_DEVICE_STATE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_PNP_DEVICE_STATE\n"));
    irp->IoStatus.Status = STATUS_SUCCESS;
    if (xpdd->common.device_usage_paging
      || xpdd->common.device_usage_dump
      || xpdd->common.device_usage_hibernation)
    {
      irp->IoStatus.Information |= PNP_DEVICE_NOT_DISABLEABLE;
    }
    IoSkipCurrentIrpStackLocation(irp);
    break;
    
  default:
    //KdPrint((__DRIVER_NAME "     Unhandled Minor = %d\n", stack->MinorFunction));
    IoSkipCurrentIrpStackLocation(irp);
    break;
  }

  status = IoCallDriver(xpdd->common.lower_do, irp);

  //KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

NTSTATUS
XenPci_Irp_Create_Fdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  PXENPCI_DEVICE_DATA xpdd;
  NTSTATUS status;

  FUNCTION_ENTER();

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  status = STATUS_SUCCESS;    
  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  FUNCTION_EXIT();

  return status;
}

NTSTATUS
XenPci_Irp_Close_Fdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  PXENPCI_DEVICE_DATA xpdd;
  NTSTATUS status;

  FUNCTION_ENTER();

  // wait until pending irp's 
  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  status = STATUS_SUCCESS;    
  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  FUNCTION_EXIT();

  return status;
}

NTSTATUS
XenPci_Irp_Read_Fdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  PXENPCI_DEVICE_DATA xpdd;
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  KIRQL old_irql;

  FUNCTION_ENTER();

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  stack = IoGetCurrentIrpStackLocation(irp);
  if (stack->Parameters.Read.Length == 0)
  {
    irp->IoStatus.Information = 0;
    status = STATUS_SUCCESS;    
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
  }
  else 
  {
    KdPrint((__DRIVER_NAME "     stack = %p\n", stack));
    KdPrint((__DRIVER_NAME "     length = %d, buffer = %p\n", stack->Parameters.Read.Length, irp->AssociatedIrp.SystemBuffer));
    
    KeAcquireSpinLock(&xpdd->shutdown_ring_lock, &old_irql);
    xpdd->shutdown_irp = irp;
    IoSetCancelRoutine(irp, XenBus_ShutdownIoCancel);
    KeReleaseSpinLock(&xpdd->shutdown_ring_lock, old_irql);
    status = XenPci_ProcessShutdownIrp(xpdd);
  }

  FUNCTION_EXIT();

  return status;
}


NTSTATUS
XenPci_Irp_Cleanup_Fdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();
  
  status = STATUS_SUCCESS;
  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  
  FUNCTION_EXIT();

  return status;
}

#if 0
static VOID
XenPci_BalloonHandler(char *Path, PVOID Data)
{
  WDFDEVICE Device = Data;
  char *value;
  xenbus_transaction_t xbt;
  int retry;

  UNREFERENCED_PARAMETER(Path);

  KdPrint((__DRIVER_NAME " --> XenBus_BalloonHandler\n"));

  XenBus_StartTransaction(Device, &xbt);

  XenBus_Read(Device, XBT_NIL, BALLOON_PATH, &value);

  KdPrint((__DRIVER_NAME "     Balloon Value = %s\n", value));

  // use the memory_op(unsigned int op, void *arg) hypercall to adjust this
  // use XENMEM_increase_reservation and XENMEM_decrease_reservation

  XenBus_EndTransaction(Device, xbt, 0, &retry);

  XenPci_FreeMem(value);

  KdPrint((__DRIVER_NAME " <-- XenBus_BalloonHandler\n"));
}
#endif
