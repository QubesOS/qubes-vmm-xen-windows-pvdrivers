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

#define SYSRQ_PATH "control/sysrq"
#define SHUTDOWN_PATH "control/shutdown"
#define BALLOON_PATH "memory/target"

#if 0
static NTSTATUS
XenPCI_PrepareHardware(WDFDEVICE hDevice, WDFCMRESLIST Resources, WDFCMRESLIST ResourcesTranslated);
static NTSTATUS
XenPCI_ReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated);
static NTSTATUS
XenPCI_D0Entry(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState);
static NTSTATUS
XenPCI_D0EntryPostInterruptsEnabled(WDFDEVICE  Device, WDF_POWER_DEVICE_STATE PreviousState);
static NTSTATUS
XenPCI_D0Exit(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState);
static NTSTATUS
XenPCI_D0ExitPreInterruptsDisabled(WDFDEVICE  Device, WDF_POWER_DEVICE_STATE TargetState);
static VOID
XenPCI_IoDefault(WDFQUEUE Queue, WDFREQUEST Request);
static VOID 
XenPCI_IoRead(WDFQUEUE Queue, WDFREQUEST Request, size_t Length);
static NTSTATUS
XenPCI_InterruptEnable(WDFINTERRUPT Interrupt, WDFDEVICE AssociatedDevice);
static NTSTATUS
XenPCI_InterruptDisable(WDFINTERRUPT Interrupt, WDFDEVICE AssociatedDevice);
static NTSTATUS
XenPCI_ChildListCreateDevice(WDFCHILDLIST ChildList, PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription, PWDFDEVICE_INIT ChildInit);
static NTSTATUS
XenPCI_DeviceResourceRequirementsQuery(WDFDEVICE Device, WDFIORESREQLIST IoResourceRequirementsList);
static NTSTATUS
XenPCI_FilterRemoveResourceRequirements(WDFDEVICE Device, WDFIORESREQLIST IoResourceRequirementsList);
static NTSTATUS
XenPCI_FilterAddResourceRequirements(WDFDEVICE Device, WDFIORESREQLIST RequirementsList);
static NTSTATUS
XenPCI_RemoveAddedResources(WDFDEVICE Device, WDFCMRESLIST ResourcesRaw, WDFCMRESLIST ResourcesTranslated);
#endif

static VOID
XenBus_SysrqHandler(char *Path, PVOID Data);
static VOID
XenBus_ShutdownHandler(char *Path, PVOID Data);
static VOID
XenBus_BalloonHandler(char *Path, PVOID Data);
/*
static VOID
XenPCI_XenBusWatchHandler(char *Path, PVOID Data);
*/

/* Global (driver-wide) variables */
static BOOLEAN AutoEnumerate;
static LIST_ENTRY ShutdownMsgList;

#pragma warning(disable : 4200) // zero-sized array

typedef struct {
  LIST_ENTRY ListEntry;
  ULONG Ptr;
//  ULONG Len;
  CHAR Buf[0];
} SHUTDOWN_MSG_ENTRY, *PSHUTDOWN_MSG_ENTRY;

static KSPIN_LOCK ShutdownMsgLock;

CM_PARTIAL_RESOURCE_DESCRIPTOR InterruptRaw;
CM_PARTIAL_RESOURCE_DESCRIPTOR InterruptTranslated;

NTSTATUS
XenPci_Power_Fdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PXENPCI_DEVICE_DATA xpdd;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  stack = IoGetCurrentIrpStackLocation(irp);
  IoSkipCurrentIrpStackLocation(irp);
  status = PoCallDriver(xpdd->common.lower_do, irp);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return status;
}

NTSTATUS
XenPci_Dummy_Fdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PXENPCI_DEVICE_DATA xpdd;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  stack = IoGetCurrentIrpStackLocation(irp);
  IoSkipCurrentIrpStackLocation(irp);
  status = IoCallDriver(xpdd->common.lower_do, irp);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return status;
}

/*
 * Many XEN_IFACE functions allocate memory. Clients must use this to free it.
 * (Xenbus_Read, XenBus_List, XenBus_AddWatch, XenBus_RemWatch)
 */
static void
XenPCI_FreeMem(PVOID Ptr)
{
  ExFreePoolWithTag(Ptr, XENPCI_POOL_TAG);
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
  PHYSICAL_ADDRESS shared_info_area_unmapped;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  hvm_get_stubs(xpdd);

  shared_info_area_unmapped = XenPci_AllocMMIO(xpdd, PAGE_SIZE);
  KdPrint((__DRIVER_NAME " shared_info_area_unmapped.QuadPart = %lx\n", shared_info_area_unmapped.QuadPart));
  xatp.domid = DOMID_SELF;
  xatp.idx = 0;
  xatp.space = XENMAPSPACE_shared_info;
  xatp.gpfn = (xen_pfn_t)(shared_info_area_unmapped.QuadPart >> PAGE_SHIFT);
  KdPrint((__DRIVER_NAME " gpfn = %d\n", xatp.gpfn));
  ret = HYPERVISOR_memory_op(xpdd, XENMEM_add_to_physmap, &xatp);
  KdPrint((__DRIVER_NAME " hypervisor memory op ret = %d\n", ret));
  xpdd->shared_info_area = MmMapIoSpace(shared_info_area_unmapped,
    PAGE_SIZE, MmCached);
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return STATUS_SUCCESS;
}

#if 0
WDFQUEUE ReadQueue;
#endif

static NTSTATUS
XenPci_Pnp_IoCompletion(PDEVICE_OBJECT device_object, PIRP irp, PVOID context)
{
  PKEVENT event = (PKEVENT)context;

  UNREFERENCED_PARAMETER(device_object);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  if (irp->PendingReturned)
  {
    KeSetEvent(event, IO_NO_INCREMENT, FALSE);
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

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

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

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

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

static VOID
XenPci_Pnp_StartDeviceCallback(PDEVICE_OBJECT device_object, PVOID context)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_DEVICE_DATA xpdd = device_object->DeviceExtension;
  PIRP irp = context;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  
  XenPci_Init(xpdd);

  GntTbl_Init(xpdd);

  EvtChn_Init(xpdd);

  XenBus_Init(xpdd);

  irp->IoStatus.Status = status;
  
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));
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

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  stack = IoGetCurrentIrpStackLocation(irp);

  IoMarkIrpPending(irp);

  status = XenPci_SendAndWaitForIrp(device_object, irp);

  /* I think we want to start a work item here to do this... */

  res_list = &stack->Parameters.StartDevice.AllocatedResources->List[0].PartialResourceList;
  
  for (i = 0; i < res_list->Count; i++)
  {
    res_descriptor = &res_list->PartialDescriptors[i];
    switch (res_descriptor->Type)
    {
    case CmResourceTypeInterrupt:
      xpdd->irq_number = res_descriptor->u.Interrupt.Vector;
      memcpy(&InterruptRaw, res_descriptor, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
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
      xpdd->platform_mmio_addr = res_descriptor->u.Memory.Start;
      xpdd->platform_mmio_len = res_descriptor->u.Memory.Length;
      xpdd->platform_mmio_alloc = 0;
      break;
    case CmResourceTypeInterrupt:
	  xpdd->irq_level = (KIRQL)res_descriptor->u.Interrupt.Level;
	  xpdd->irq_vector = res_descriptor->u.Interrupt.Vector;
	  xpdd->irq_affinity = res_descriptor->u.Interrupt.Affinity;
      memcpy(&InterruptTranslated, res_descriptor, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
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

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));
  
  return STATUS_PENDING;
}

static NTSTATUS
XenPci_Pnp_StopDevice(PDEVICE_OBJECT device_object, PIRP irp, PVOID context)
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(device_object);
  UNREFERENCED_PARAMETER(context);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return irp->IoStatus.Status;
}

static NTSTATUS
XenPci_Pnp_QueryRemoveDevice(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_DEVICE_DATA xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;

  UNREFERENCED_PARAMETER(device_object);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  if (FALSE)
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

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

static NTSTATUS
XenPci_Pnp_RemoveDevice(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PXENPCI_DEVICE_DATA xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;

  UNREFERENCED_PARAMETER(device_object);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  irp->IoStatus.Status = STATUS_SUCCESS;
  IoSkipCurrentIrpStackLocation(irp);
  status = IoCallDriver(xpdd->common.lower_do, irp);
  IoDetachDevice(xpdd->common.lower_do);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

#if 0
static VOID
XenPci_XenBusWatchHandler(PVOID context, char *path)
{
  NTSTATUS status;
  char **bits;
  int count;
  int i;
//  WDFDEVICE Device = Data;
//  WDFCHILDLIST ChildList;
//  WDF_CHILD_LIST_ITERATOR ChildIterator;
//  WDFDEVICE ChildDevice;
//  PXENPCI_XEN_DEVICE_DATA ChildDeviceData;
//  XENPCI_IDENTIFICATION_DESCRIPTION description;
  PXEN_CHILD child = NULL;
  PXENPCI_DEVICE_DATA xpdd = context;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
  KeAcquireGuardedMutex(&xpdd->WatchHandlerMutex);
#endif

  KdPrint((__DRIVER_NAME "     path = %s\n", path));
  bits = SplitString(path, '/', 3, &count);
  KdPrint((__DRIVER_NAME "     Count = %s\n", count));
  
  ASSERT(count >= 2);
  
  for (i = 0; i < 16; i++)
  {
    if (xpdd->child_devices[i].pdo != NULL && strncmp(xpdd->child_devices[i].path, path, strlen(xpdd->child_devices[i].path)) == 0 && path[strlen(xpdd->child_devices[i].path] == '/')
    {
	  child = &xpdd->child_devices[i];
	  break;
	}
  }
  
  if (child == NULL && count >= 2)
    IoInvalidateDeviceRelations(xpdd->common.fdo, BusRelations);
  else if (count > 2)
  {
    // forward on to the child
  }
  
#if 0
  ChildDeviceData = NULL;
  WDF_CHILD_LIST_ITERATOR_INIT(&ChildIterator, WdfRetrievePresentChildren);
  WdfChildListBeginIteration(ChildList, &ChildIterator);
  while (NT_SUCCESS(WdfChildListRetrieveNextDevice(ChildList, &ChildIterator, &ChildDevice, NULL)))
  {
    ChildDeviceData = GetXenDeviceData(ChildDevice);
    if (!ChildDeviceData)
    {
      KdPrint(("     No child device data, should never happen\n"));
      continue;
    }
    if (strncmp(ChildDeviceData->Path, Path, strlen(ChildDeviceData->Path)) == 0 && Path[strlen(ChildDeviceData->Path)] == '/')
    {
      if (Count == 3 && ChildDeviceData->WatchHandler != NULL)
        ChildDeviceData->WatchHandler(Path, ChildDeviceData->WatchContext);
      break;
    }
    ChildDeviceData = NULL;
  }
  WdfChildListEndIteration(ChildList, &ChildIterator);
  if (Count >= 2 && ChildDeviceData == NULL)
  {
    RtlZeroMemory(&description, sizeof(description));
    WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(&description.Header, sizeof(description));
    strncpy(description.Path, Path, 128);
    strncpy(description.DeviceType, Bits[1], 128);
    KdPrint((__DRIVER_NAME "     Adding child for %s\n", description.DeviceType));
    status = WdfChildListAddOrUpdateChildDescriptionAsPresent(ChildList, &description.Header, NULL);
  }
  FreeSplitString(Bits, Count);

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
  KeReleaseGuardedMutex(&xpdd->WatchHandlerMutex);
#endif

#endif

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}
#endif

static VOID
XenPci_Pnp_QueryBusRelationsCallback(PDEVICE_OBJECT device_object, PVOID context)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_DEVICE_DATA xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;
  PIRP irp = context;
  int devices = 0;
  PDEVICE_RELATIONS dev_relations;
  PXEN_CHILD child;
  //char *response;
  char *msgTypes;
  char **Types;
  int i;
  //CHAR buffer[128];
  PDEVICE_OBJECT pdo;
  
  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  msgTypes = XenBus_List(xpdd, XBT_NIL, "device", &Types);
  if (!msgTypes)
  {
    for (child = (PXEN_CHILD)xpdd->child_list.Flink; child != (PXEN_CHILD)&xpdd->child_list; child = (PXEN_CHILD)child->entry.Flink)
    {
      if (child->state == CHILD_STATE_DELETED)
        KdPrint((__DRIVER_NAME "     Found deleted child - this shouldn't happen\n" ));
      child->state = CHILD_STATE_DELETED;
    }

    for (i = 0; Types[i]; i++)
    {
      //RtlStringCbPrintfA(buffer, ARRAY_SIZE(buffer), "device/%s", Types[i]);

      for (child = (PXEN_CHILD)xpdd->child_list.Flink; child != (PXEN_CHILD)&xpdd->child_list; child = (PXEN_CHILD)child->entry.Flink)
      {
        if (strcmp(child->context->path, Types[i]) == 0)
        {
          KdPrint((__DRIVER_NAME "     Existing device %s\n", Types[i]));
          ASSERT(child->state != CHILD_STATE_DELETED);
          child->state = CHILD_STATE_ADDED;
          devices++;
          break;
        }
      }
      if (child == (PXEN_CHILD)&xpdd->child_list)
      {
        KdPrint((__DRIVER_NAME "     New device %s\n", Types[i]));
        child = ExAllocatePoolWithTag(NonPagedPool, sizeof(XEN_CHILD), XENPCI_POOL_TAG);
        child->state = CHILD_STATE_ADDED;
        status = IoCreateDevice(xpdd->common.fdo->DriverObject, sizeof(XENPCI_COMMON), NULL, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pdo);
        if (!NT_SUCCESS(status))
          KdPrint((__DRIVER_NAME "     IoCreateDevice status = %08X\n", status));
        child->context = (PXENPCI_PDO_DEVICE_DATA)pdo->DeviceExtension;
        child->context->common.fdo = NULL;
        child->context->common.pdo = pdo;
        child->context->common.lower_do = NULL;
        strcpy(child->context->path, Types[i]);
        child->context->index = 0;
        InsertTailList(&xpdd->child_list, (PLIST_ENTRY)child);
        devices++;
      }
      ExFreePoolWithTag(Types[i], XENPCI_POOL_TAG);
    }
    dev_relations = ExAllocatePoolWithTag(NonPagedPool, sizeof(DEVICE_RELATIONS) + sizeof(PDEVICE_OBJECT) * (devices - 1), XENPCI_POOL_TAG);
    for (child = (PXEN_CHILD)xpdd->child_list.Flink, devices = 0; child != (PXEN_CHILD)&xpdd->child_list; child = (PXEN_CHILD)child->entry.Flink)
    {
      if (child->state == CHILD_STATE_ADDED)
        dev_relations->Objects[devices++] = child->context->common.pdo;
    }
    dev_relations->Count = devices;

    status = STATUS_SUCCESS;
  }
  else
  {
    devices = 0;
    dev_relations = ExAllocatePoolWithTag(NonPagedPool, sizeof(DEVICE_RELATIONS) + sizeof(PDEVICE_OBJECT) * (devices - 1), XENPCI_POOL_TAG);
    dev_relations->Count = devices;
  }

  XenPCI_FreeMem(Types);

  irp->IoStatus.Status = status;
  irp->IoStatus.Information = (ULONG_PTR)dev_relations;

  IoCompleteRequest (irp, IO_NO_INCREMENT);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));
}

static NTSTATUS
XenPci_Pnp_QueryBusRelations(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;

  UNREFERENCED_PARAMETER(device_object);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  IoMarkIrpPending(irp);

  status = XenPci_SendAndWaitForIrp(device_object, irp);

  XenPci_QueueWorkItem(device_object, XenPci_Pnp_QueryBusRelationsCallback, irp);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return STATUS_PENDING;
}

NTSTATUS
XenPci_Pnp_Fdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  PIO_STACK_LOCATION stack;
  NTSTATUS status;
  PXENPCI_DEVICE_DATA xpdd;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  xpdd = (PXENPCI_DEVICE_DATA)device_object->DeviceExtension;

  stack = IoGetCurrentIrpStackLocation(irp);

  switch (stack->MinorFunction)
  {
  case IRP_MN_START_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_START_DEVICE\n"));
    return XenPci_Pnp_StartDevice(device_object, irp);

  case IRP_MN_QUERY_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_STOP_DEVICE\n"));
    IoSkipCurrentIrpStackLocation(irp);
    irp->IoStatus.Status = STATUS_SUCCESS;
    break;

  case IRP_MN_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_STOP_DEVICE\n"));
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, XenPci_Pnp_StopDevice, NULL, TRUE, TRUE, TRUE);
    break;

  case IRP_MN_CANCEL_STOP_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_STOP_DEVICE\n"));
    IoSkipCurrentIrpStackLocation(irp);
    irp->IoStatus.Status = STATUS_SUCCESS;
    break;

  case IRP_MN_QUERY_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_REMOVE_DEVICE\n"));
    return XenPci_Pnp_QueryRemoveDevice(device_object, irp);

  case IRP_MN_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_REMOVE_DEVICE\n"));
    return XenPci_Pnp_QueryRemoveDevice(device_object, irp);
    break;

  case IRP_MN_CANCEL_REMOVE_DEVICE:
    KdPrint((__DRIVER_NAME "     IRP_MN_CANCEL_REMOVE_DEVICE\n"));
    IoSkipCurrentIrpStackLocation(irp);
    irp->IoStatus.Status = STATUS_SUCCESS;
    break;

  case IRP_MN_SURPRISE_REMOVAL:
    KdPrint((__DRIVER_NAME "     IRP_MN_SURPRISE_REMOVAL\n"));
    IoSkipCurrentIrpStackLocation(irp);
    irp->IoStatus.Status = STATUS_SUCCESS;
    break;

  case IRP_MN_DEVICE_USAGE_NOTIFICATION:
    KdPrint((__DRIVER_NAME "     IRP_MN_DEVICE_USAGE_NOTIFICATION\n"));
    IoSkipCurrentIrpStackLocation(irp);
    irp->IoStatus.Status = STATUS_SUCCESS;
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

  default:
    KdPrint((__DRIVER_NAME "     Unhandled Minor = %d\n", stack->MinorFunction));
    IoSkipCurrentIrpStackLocation(irp);
    break;
  }

  status = IoCallDriver(xpdd->common.lower_do, irp);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__"\n"));

  return status;
}

#if 0

static NTSTATUS
XenPCI_D0Entry(
    IN WDFDEVICE  Device,
    IN WDF_POWER_DEVICE_STATE PreviousState
    )
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(PreviousState);

  KdPrint((__DRIVER_NAME " --> EvtDeviceD0Entry\n"));

  KdPrint((__DRIVER_NAME " <-- EvtDeviceD0Entry\n"));

  return status;
}

static NTSTATUS
XenPCI_D0EntryPostInterruptsEnabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)
{
  NTSTATUS status = STATUS_SUCCESS;
  //OBJECT_ATTRIBUTES oa;
  char *response;
  char *msgTypes;
  char **Types;
  int i;
  char buffer[128];
  WDFCHILDLIST ChildList;

  UNREFERENCED_PARAMETER(PreviousState);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  XenBus_Start(Device);

  response = XenBus_AddWatch(Device, XBT_NIL, SYSRQ_PATH, XenBus_SysrqHandler, Device);
  KdPrint((__DRIVER_NAME "     sysrqwatch response = '%s'\n", response)); 
  
  response = XenBus_AddWatch(Device, XBT_NIL, SHUTDOWN_PATH, XenBus_ShutdownHandler, Device);
  KdPrint((__DRIVER_NAME "     shutdown watch response = '%s'\n", response)); 

  response = XenBus_AddWatch(Device, XBT_NIL, BALLOON_PATH, XenBus_BalloonHandler, Device);
  KdPrint((__DRIVER_NAME "     shutdown watch response = '%s'\n", response)); 

  response = XenBus_AddWatch(Device, XBT_NIL, "device", XenPCI_XenBusWatchHandler, Device);
  KdPrint((__DRIVER_NAME "     device watch response = '%s'\n", response)); 

  ChildList = WdfFdoGetDefaultChildList(Device);

  WdfChildListBeginScan(ChildList);
  msgTypes = XenBus_List(Device, XBT_NIL, "device", &Types);
  if (!msgTypes) {
    for (i = 0; Types[i]; i++)
    {
      RtlStringCbPrintfA(buffer, ARRAY_SIZE(buffer), "device/%s", Types[i]);
      XenPCI_XenBusWatchHandler(buffer, Device);
      ExFreePoolWithTag(Types[i], XENPCI_POOL_TAG);
    }
  }
  WdfChildListEndScan(ChildList);

  XenPCI_FreeMem(Types);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return status;
}

static NTSTATUS
XenPCI_D0ExitPreInterruptsDisabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState)
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(TargetState);

  KdPrint((__DRIVER_NAME " --> D0ExitPreInterruptsDisabled\n"));

  XenBus_Stop(Device);

  KdPrint((__DRIVER_NAME " <-- D0ExitPreInterruptsDisabled\n"));

  return status;
}

static NTSTATUS
XenPCI_D0Exit(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState)
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(Device);
  UNREFERENCED_PARAMETER(TargetState);

  KdPrint((__DRIVER_NAME " --> DeviceD0Exit\n"));

  XenBus_Close(Device);

  KdPrint((__DRIVER_NAME " <-- DeviceD0Exit\n"));

  return status;
}

static VOID 
XenPCI_IoDefault(
    IN WDFQUEUE  Queue,
    IN WDFREQUEST  Request
    )
{
  UNREFERENCED_PARAMETER(Queue);

  KdPrint((__DRIVER_NAME " --> EvtDeviceIoDefault\n"));

  WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);

  KdPrint((__DRIVER_NAME " <-- EvtDeviceIoDefault\n"));
}

static VOID 
XenPCI_IoRead(WDFQUEUE Queue, WDFREQUEST Request, size_t Length)
{
  PSHUTDOWN_MSG_ENTRY Entry;
  size_t Remaining;
  size_t CopyLen;
  PCHAR Buffer;
  size_t BufLen;
  KIRQL OldIrql;

  UNREFERENCED_PARAMETER(Queue);
  UNREFERENCED_PARAMETER(Length);

  KdPrint((__DRIVER_NAME " --> IoRead\n"));

  WdfRequestRetrieveOutputBuffer(Request, 1, &Buffer, &BufLen);

  KeAcquireSpinLock(&ShutdownMsgLock, &OldIrql);

  Entry = (PSHUTDOWN_MSG_ENTRY)RemoveHeadList(&ShutdownMsgList);

  if ((PLIST_ENTRY)Entry == &ShutdownMsgList)
  {
    KdPrint((__DRIVER_NAME " <-- IoRead (Nothing in queue... xenpci is now broken)\n"));
    return;
  }

  Remaining = strlen(Entry->Buf + Entry->Ptr);
  CopyLen = min(Remaining, BufLen);

  memcpy(Buffer, Entry->Buf + Entry->Ptr, CopyLen);

  if (Entry->Buf[Entry->Ptr] == 0)
  {
    KdPrint((__DRIVER_NAME "     All done... stopping queue\n"));
    if (IsListEmpty(&ShutdownMsgList))
      WdfIoQueueStop(ReadQueue, NULL, NULL);
  }
  else
  {    
    KdPrint((__DRIVER_NAME "     More to do...\n"));
    Entry->Ptr += (ULONG)CopyLen;
    InsertHeadList(&ShutdownMsgList, &Entry->ListEntry);
  }

  KeReleaseSpinLock(&ShutdownMsgLock, OldIrql);

  WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, CopyLen);

  KdPrint((__DRIVER_NAME " <-- IoRead\n"));
}


static NTSTATUS
XenPCI_InterruptEnable(WDFINTERRUPT Interrupt, WDFDEVICE AssociatedDevice)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(AssociatedDevice);

  UNREFERENCED_PARAMETER(Interrupt);

  KdPrint((__DRIVER_NAME " --> EvtInterruptEnable\n"));

  xpdd->shared_info_area->vcpu_info[0].evtchn_upcall_mask = 0;

  KdPrint((__DRIVER_NAME " <-- EvtInterruptEnable\n"));

  return STATUS_SUCCESS;
}

static NTSTATUS
XenPCI_InterruptDisable(WDFINTERRUPT Interrupt, WDFDEVICE AssociatedDevice)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(AssociatedDevice);

  UNREFERENCED_PARAMETER(Interrupt);

  //KdPrint((__DRIVER_NAME " --> EvtInterruptDisable\n"));

  xpdd->shared_info_area->vcpu_info[0].evtchn_upcall_mask = 1;
  // should we kick off any pending interrupts here?

  //KdPrint((__DRIVER_NAME " <-- EvtInterruptDisable\n"));

  return STATUS_SUCCESS;
}

static NTSTATUS
XenPCI_ChildListCreateDevice(
  WDFCHILDLIST ChildList,
  PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription,
  PWDFDEVICE_INIT ChildInit)
{
  NTSTATUS status;
  WDFDEVICE ChildDevice = NULL;
  PXENPCI_IDENTIFICATION_DESCRIPTION XenIdentificationDesc;
  DECLARE_UNICODE_STRING_SIZE(buffer, 20);
  WDF_OBJECT_ATTRIBUTES PdoAttributes;
  DECLARE_CONST_UNICODE_STRING(DeviceLocation, L"Xen Bus");
  WDF_QUERY_INTERFACE_CONFIG  qiConfig;
  PXENPCI_XEN_DEVICE_DATA ChildDeviceData = NULL;
  UNICODE_STRING DeviceType;
  ANSI_STRING AnsiBuf;

  UNREFERENCED_PARAMETER(ChildList);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  XenIdentificationDesc = CONTAINING_RECORD(IdentificationDescription, XENPCI_IDENTIFICATION_DESCRIPTION, Header);

  RtlInitAnsiString(&AnsiBuf, XenIdentificationDesc->DeviceType);
  RtlAnsiStringToUnicodeString(&DeviceType, &AnsiBuf, TRUE);

  KdPrint((__DRIVER_NAME "     Type = %s\n", XenIdentificationDesc->DeviceType));

  //DeviceInit = WdfPdoInitAllocate(Device);
  WdfDeviceInitSetDeviceType(ChildInit, FILE_DEVICE_CONTROLLER);

  status = RtlUnicodeStringPrintf(&buffer, L"Xen\\%wZ\0", &DeviceType);
  status = WdfPdoInitAssignDeviceID(ChildInit, &buffer);
  status = WdfPdoInitAddHardwareID(ChildInit, &buffer);
  status = WdfPdoInitAddCompatibleID(ChildInit, &buffer);

  status = RtlUnicodeStringPrintf(&buffer, L"%02d", 0);
  status = WdfPdoInitAssignInstanceID(ChildInit, &buffer);

  status = RtlUnicodeStringPrintf(&buffer, L"%wZ", &DeviceType);
  status = WdfPdoInitAddDeviceText(ChildInit, &buffer, &DeviceLocation, 0x409);

  WdfPdoInitSetDefaultLocale(ChildInit, 0x409);
  
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&PdoAttributes, XENPCI_XEN_DEVICE_DATA);

//  WDF_PDO_EVENT_CALLBACKS_INIT(&PdoCallbacks);
//  PdoCallbacks.EvtDeviceResourceRequirementsQuery = XenPCI_DeviceResourceRequirementsQuery;
//  WdfPdoInitSetEventCallbacks(ChildInit, &PdoCallbacks);

  status = WdfDeviceCreate(&ChildInit, &PdoAttributes, &ChildDevice);
  if (!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreate status = %08X\n", status));
  }

  WdfDeviceSetSpecialFileSupport(ChildDevice, WdfSpecialFilePaging, TRUE);
  WdfDeviceSetSpecialFileSupport(ChildDevice, WdfSpecialFileHibernation, TRUE);
  WdfDeviceSetSpecialFileSupport(ChildDevice, WdfSpecialFileDump, TRUE);

  ChildDeviceData = GetXenDeviceData(ChildDevice);
  ChildDeviceData->Magic = XEN_DATA_MAGIC;
  ChildDeviceData->AutoEnumerate = AutoEnumerate;
  ChildDeviceData->WatchHandler = NULL;
  strncpy(ChildDeviceData->Path, XenIdentificationDesc->Path, 128);
  ChildDeviceData->DeviceIndex = XenIdentificationDesc->DeviceIndex;
  memcpy(&ChildDeviceData->InterruptRaw, &InterruptRaw, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
  memcpy(&ChildDeviceData->InterruptTranslated, &InterruptTranslated, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
  
  ChildDeviceData->XenInterface.InterfaceHeader.Size = sizeof(ChildDeviceData->XenInterface);
  ChildDeviceData->XenInterface.InterfaceHeader.Version = 2;
  ChildDeviceData->XenInterface.InterfaceHeader.Context = WdfPdoGetParent(ChildDevice);
  ChildDeviceData->XenInterface.InterfaceHeader.InterfaceReference = WdfDeviceInterfaceReferenceNoOp;
  ChildDeviceData->XenInterface.InterfaceHeader.InterfaceDereference = WdfDeviceInterfaceDereferenceNoOp;

  ChildDeviceData->XenInterface.AllocMMIO = XenPci_AllocMMIO;
  ChildDeviceData->XenInterface.FreeMem = XenPCI_FreeMem;

  ChildDeviceData->XenInterface.EvtChn_Bind = EvtChn_Bind;
  ChildDeviceData->XenInterface.EvtChn_Unbind = EvtChn_Unbind;
  ChildDeviceData->XenInterface.EvtChn_Mask = EvtChn_Mask;
  ChildDeviceData->XenInterface.EvtChn_Unmask = EvtChn_Unmask;
  ChildDeviceData->XenInterface.EvtChn_Notify = EvtChn_Notify;
  ChildDeviceData->XenInterface.EvtChn_AllocUnbound = EvtChn_AllocUnbound;
  ChildDeviceData->XenInterface.EvtChn_BindDpc = EvtChn_BindDpc;

  ChildDeviceData->XenInterface.GntTbl_GetRef = GntTbl_GetRef;
  ChildDeviceData->XenInterface.GntTbl_PutRef = GntTbl_PutRef;
  ChildDeviceData->XenInterface.GntTbl_GrantAccess = GntTbl_GrantAccess;
  ChildDeviceData->XenInterface.GntTbl_EndAccess = GntTbl_EndAccess;

  ChildDeviceData->XenInterface.XenBus_Read = XenBus_Read;
  ChildDeviceData->XenInterface.XenBus_Write = XenBus_Write;
  ChildDeviceData->XenInterface.XenBus_Printf = XenBus_Printf;
  ChildDeviceData->XenInterface.XenBus_StartTransaction = XenBus_StartTransaction;
  ChildDeviceData->XenInterface.XenBus_EndTransaction = XenBus_EndTransaction;
  ChildDeviceData->XenInterface.XenBus_List = XenBus_List;
  ChildDeviceData->XenInterface.XenBus_AddWatch = XenBus_AddWatch;
  ChildDeviceData->XenInterface.XenBus_RemWatch = XenBus_RemWatch;

  WDF_QUERY_INTERFACE_CONFIG_INIT(&qiConfig, (PINTERFACE)&ChildDeviceData->XenInterface, &GUID_XEN_IFACE, NULL);
  status = WdfDeviceAddQueryInterface(ChildDevice, &qiConfig);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));

  return status;
}

struct {
  ULONG do_spin;
  ULONG nr_spinning;
} typedef SUSPEND_INFO, *PSUSPEND_INFO;

static VOID
XenPci_Suspend(
 PRKDPC Dpc,
 PVOID Context,
 PVOID SystemArgument1,
 PVOID SystemArgument2)
{
  WDFDEVICE Device = Context;
//  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
  PSUSPEND_INFO suspend_info = SystemArgument1;
  ULONG ActiveProcessorCount;
  KIRQL OldIrql;
  int cancelled;

  UNREFERENCED_PARAMETER(Dpc);
  UNREFERENCED_PARAMETER(SystemArgument2);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ " (CPU = %d)\n", KeGetCurrentProcessorNumber()));
  KdPrint((__DRIVER_NAME "     Device = %p\n", Device));

  if (KeGetCurrentProcessorNumber() != 0)
  {
    KdPrint((__DRIVER_NAME "     spinning...\n"));
    InterlockedIncrement((volatile LONG *)&suspend_info->nr_spinning);
    KeMemoryBarrier();
    while(suspend_info->do_spin)
    {
      /* we should be able to wait more nicely than this... */
    }
    KeMemoryBarrier();
    InterlockedDecrement((volatile LONG *)&suspend_info->nr_spinning);    
    KdPrint((__DRIVER_NAME "     ...done spinning\n"));
    KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n", KeGetCurrentProcessorNumber()));
    return;
  }
  ActiveProcessorCount = (ULONG)KeNumberProcessors;

  KdPrint((__DRIVER_NAME "     waiting for all other processors to spin\n"));
  while (suspend_info->nr_spinning < ActiveProcessorCount - 1)
  {
      /* we should be able to wait more nicely than this... */
  }
  KdPrint((__DRIVER_NAME "     all other processors are spinning\n"));

  KeRaiseIrql(HIGH_LEVEL, &OldIrql);
  KdPrint((__DRIVER_NAME "     calling suspend\n"));
  cancelled = HYPERVISOR_shutdown(Device, SHUTDOWN_suspend);
  KdPrint((__DRIVER_NAME "     back from suspend, cancelled = %d\n", cancelled));
  KeLowerIrql(OldIrql);

  KdPrint((__DRIVER_NAME "     waiting for all other processors to stop spinning\n"));
  suspend_info->do_spin = 0;
  while (suspend_info->nr_spinning != 0)
  {
      /* we should be able to wait more nicely than this... */
  }
  KdPrint((__DRIVER_NAME "     all other processors have stopped spinning\n"));

  // TODO: Enable xenbus
  // TODO: Enable our IRQ

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n", KeGetCurrentProcessorNumber()));
}

static VOID
XenPci_BeginSuspend(WDFDEVICE Device)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
//  KAFFINITY ActiveProcessorMask = 0;
  ULONG ActiveProcessorCount;
  ULONG i;
  PSUSPEND_INFO suspend_info;
  PKDPC Dpc;
  KIRQL OldIrql;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     Device = %p\n", Device));

  if (!xpdd->suspending)
  {
    xpdd->suspending = 1;
    suspend_info = ExAllocatePoolWithTag(NonPagedPool, sizeof(SUSPEND_INFO), XENPCI_POOL_TAG);
    suspend_info->do_spin = 1;
    RtlZeroMemory(suspend_info, sizeof(SUSPEND_INFO));
    // TODO: Disable xenbus
    // TODO: Disable our IRQ
    //ActiveProcessorCount = KeQueryActiveProcessorCount(&ActiveProcessorMask);
    ActiveProcessorCount = (ULONG)KeNumberProcessors;
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    for (i = 0; i < ActiveProcessorCount; i++)
    {
      Dpc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KDPC), XENPCI_POOL_TAG);
      KeInitializeDpc(Dpc, XenPci_Suspend, Device);
      KeSetTargetProcessorDpc(Dpc, (CCHAR)i);
      KeInsertQueueDpc(Dpc, suspend_info, NULL);
    }
    KeLowerIrql(OldIrql);
  }
  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static void
XenBus_ShutdownHandler(char *Path, PVOID Data)
{
  WDFDEVICE Device = Data;  
  char *res;
  char *Value;
  xenbus_transaction_t xbt;
  int retry;
  PSHUTDOWN_MSG_ENTRY Entry;

  UNREFERENCED_PARAMETER(Path);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  KdPrint((__DRIVER_NAME "     Device = %p\n", Device));

  res = XenBus_StartTransaction(Device, &xbt);
  if (res)
  {
    KdPrint(("Error starting transaction\n"));
    XenPCI_FreeMem(res);
    return;
  }

  res = XenBus_Read(Device, XBT_NIL, SHUTDOWN_PATH, &Value);
  if (res)
  {
    KdPrint(("Error reading shutdown path\n"));
    XenPCI_FreeMem(res);
    XenBus_EndTransaction(Device, xbt, 1, &retry);
    return;
  }

  if (Value != NULL && strlen(Value) != 0)
  {
    res = XenBus_Write(Device, XBT_NIL, SHUTDOWN_PATH, "");
    if (res)
    {
      KdPrint(("Error writing shutdown path\n"));
      XenPCI_FreeMem(res);
      // end trans?
      return;
    }
  } 

  if (Value != NULL)
  {
    KdPrint((__DRIVER_NAME "     Shutdown Value = %s\n", Value));
    KdPrint((__DRIVER_NAME "     strlen(...) = %d\n", strlen(Value)));
  }
  else
  {
    KdPrint((__DRIVER_NAME "     Shutdown Value = <null>\n"));
  }

  res = XenBus_EndTransaction(Device, xbt, 0, &retry);
  if (res)
  {
    KdPrint(("Error ending transaction\n"));
    XenPCI_FreeMem(res);
    return;
  }

  if (Value != NULL && strlen(Value) != 0)
  {
    if (strcmp(Value, "suspend") == 0)
    {
      KdPrint((__DRIVER_NAME "     Suspend detected\n"));
      XenPci_BeginSuspend(Device);
    }
    else
    {
      Entry = (PSHUTDOWN_MSG_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(SHUTDOWN_MSG_ENTRY) + strlen(Value) + 1 + 1, XENPCI_POOL_TAG);
      Entry->Ptr = 0;
      RtlStringCbPrintfA(Entry->Buf, sizeof(SHUTDOWN_MSG_ENTRY) + strlen(Value) + 1 + 1, "%s\n", Value);
      InsertTailList(&ShutdownMsgList, &Entry->ListEntry);
      WdfIoQueueStart(ReadQueue);
    }
  }

  XenPCI_FreeMem(Value);

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static VOID
XenBus_BalloonHandler(char *Path, PVOID Data)
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

  XenPCI_FreeMem(value);

  KdPrint((__DRIVER_NAME " <-- XenBus_BalloonHandler\n"));
}

static VOID
XenBus_SysrqHandler(char *Path, PVOID Data)
{
  WDFDEVICE Device = Data;
  char *Value;
  xenbus_transaction_t xbt;
  int retry;
  char letter;
  char *res;

  UNREFERENCED_PARAMETER(Path);

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

  XenBus_StartTransaction(Device, &xbt);

  XenBus_Read(Device, XBT_NIL, SYSRQ_PATH, &Value);

  KdPrint((__DRIVER_NAME "     SysRq Value = %s\n", Value));

  if (Value != NULL && strlen(Value) != 0)
  {
    letter = *Value;
    res = XenBus_Write(Device, XBT_NIL, SYSRQ_PATH, "");
    if (res)
    {
      KdPrint(("Error writing sysrq path\n"));
      XenPCI_FreeMem(res);
      XenBus_EndTransaction(Device, xbt, 0, &retry);
      return;
    }
  }
  else
  {
    letter = 0;
  }

  XenBus_EndTransaction(Device, xbt, 0, &retry);

  if (Value != NULL)
  {
    XenPCI_FreeMem(Value);
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

  KdPrint((__DRIVER_NAME " <-- " __FUNCTION__ "\n"));
}

static NTSTATUS
XenPCI_DeviceResourceRequirementsQuery(WDFDEVICE Device, WDFIORESREQLIST IoResourceRequirementsList)
{
  NTSTATUS  status;
  WDFIORESLIST resourceList;
  IO_RESOURCE_DESCRIPTOR descriptor;
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);

  //KdPrint((__DRIVER_NAME " --> DeviceResourceRequirementsQuery\n"));

  status = WdfIoResourceListCreate(IoResourceRequirementsList, WDF_NO_OBJECT_ATTRIBUTES, &resourceList);
  if (!NT_SUCCESS(status))
    return status;

  RtlZeroMemory(&descriptor, sizeof(descriptor));

  descriptor.Option = 0;
  descriptor.Type = CmResourceTypeMemory;
  descriptor.ShareDisposition = CmResourceShareShared; //CmResourceShareDeviceExclusive;
  descriptor.Flags = CM_RESOURCE_MEMORY_READ_WRITE;
  descriptor.u.Memory.Length = PAGE_SIZE;
  descriptor.u.Memory.Alignment = PAGE_SIZE;
  descriptor.u.Memory.MinimumAddress.QuadPart
    = xpdd->platform_mmio_addr.QuadPart + PAGE_SIZE;
  descriptor.u.Memory.MaximumAddress.QuadPart
    = xpdd->platform_mmio_addr.QuadPart + xpdd->platform_mmio_len - 1;

  //KdPrint((__DRIVER_NAME "     MinimumAddress = %08x, MaximumAddress = %08X\n", descriptor.u.Memory.MinimumAddress.LowPart, descriptor.u.Memory.MaximumAddress.LowPart));

  status = WdfIoResourceListAppendDescriptor(resourceList, &descriptor);
  if (!NT_SUCCESS(status))
    return status;

  status = WdfIoResourceRequirementsListAppendIoResList(IoResourceRequirementsList, resourceList);
  if (!NT_SUCCESS(status))
    return status;

  //KdPrint((__DRIVER_NAME " <-- DeviceResourceRequirementsQuery\n"));

  return status;
}
#endif