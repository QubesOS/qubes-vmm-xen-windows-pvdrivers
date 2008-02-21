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

DRIVER_INITIALIZE DriverEntry;
static NTSTATUS
XenPCI_AddDevice(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit);
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

static VOID
XenBus_SysrqHandler(char *Path, PVOID Data);
static VOID
XenBus_ShutdownHandler(char *Path, PVOID Data);
static VOID
XenBus_BalloonHandler(char *Path, PVOID Data);
static VOID
XenPCI_XenBusWatchHandler(char *Path, PVOID Data);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, XenPCI_AddDevice)
#endif

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
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  WDF_DRIVER_CONFIG config;
  NTSTATUS status;

  KdPrint((__DRIVER_NAME " --> DriverEntry\n"));

  InitializeListHead(&ShutdownMsgList);
  KeInitializeSpinLock(&ShutdownMsgLock);

  WDF_DRIVER_CONFIG_INIT(&config, XenPCI_AddDevice);
  status = WdfDriverCreate(
                      DriverObject,
                      RegistryPath,
                      WDF_NO_OBJECT_ATTRIBUTES,
                      &config,
                      WDF_NO_HANDLE);
  if(!NT_SUCCESS(status))
  {
    KdPrint((__DRIVER_NAME " WdfDriverCreate failed with status 0x%08x\n", status));
  }

  KdPrint((__DRIVER_NAME " <-- DriverEntry\n"));

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

static NTSTATUS
get_hypercall_stubs(WDFDEVICE Device)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
  DWORD32 cpuid_output[4];
  char xensig[13];
  ULONG i;
  ULONG pages;
  ULONG msr;  

  __cpuid(cpuid_output, 0x40000000);
  *(ULONG*)(xensig + 0) = cpuid_output[1];
  *(ULONG*)(xensig + 4) = cpuid_output[2];
  *(ULONG*)(xensig + 8) = cpuid_output[3];
  xensig[12] = '\0';
  KdPrint((__DRIVER_NAME " Xen Signature = %s, EAX = 0x%08x\n", xensig, cpuid_output[0]));

  __cpuid(cpuid_output, 0x40000002);
  pages = cpuid_output[0];
  msr = cpuid_output[1];
  //KdPrint((__DRIVER_NAME " Hypercall area is %u pages.\n", pages));

  xpdd->hypercall_stubs = ExAllocatePoolWithTag(NonPagedPool, pages * PAGE_SIZE, XENPCI_POOL_TAG);
  KdPrint((__DRIVER_NAME " Hypercall area at %p\n", xpdd->hypercall_stubs));

  if (!xpdd->hypercall_stubs)
    return 1;
  for (i = 0; i < pages; i++) {
    ULONGLONG pfn;
    pfn = (MmGetPhysicalAddress(xpdd->hypercall_stubs + i * PAGE_SIZE).QuadPart >> PAGE_SHIFT);
    KdPrint((__DRIVER_NAME " pfn = %16lX\n", pfn));
    __writemsr(msr, (pfn << PAGE_SHIFT) + i);
  }
  return STATUS_SUCCESS;
}

static NTSTATUS
free_hypercall_stubs(WDFDEVICE Device)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);

  ExFreePoolWithTag(xpdd->hypercall_stubs, XENPCI_POOL_TAG);

  return STATUS_SUCCESS;
}

/*
 * Alloc MMIO from the device's MMIO region. There is no corresponding free() fn
 */
PHYSICAL_ADDRESS
XenPCI_AllocMMIO(WDFDEVICE Device, ULONG len)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);

  PHYSICAL_ADDRESS addr;

  len = (len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

  addr = xpdd->platform_mmio_addr;
  addr.QuadPart += xpdd->platform_mmio_alloc;
  xpdd->platform_mmio_alloc += len;

  ASSERT(xpdd->platform_mmio_alloc <= xpdd->platform_mmio_len);

  return addr;
}

static int
init_xen_info(WDFDEVICE Device)
{
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
  struct xen_add_to_physmap xatp;
  int ret;
  PHYSICAL_ADDRESS shared_info_area_unmapped;

  shared_info_area_unmapped = XenPCI_AllocMMIO(Device, PAGE_SIZE);
  KdPrint((__DRIVER_NAME " shared_info_area_unmapped.QuadPart = %lx\n", shared_info_area_unmapped.QuadPart));
  xatp.domid = DOMID_SELF;
  xatp.idx = 0;
  xatp.space = XENMAPSPACE_shared_info;
  xatp.gpfn = (xen_pfn_t)(shared_info_area_unmapped.QuadPart >> PAGE_SHIFT);
  KdPrint((__DRIVER_NAME " gpfn = %d\n", xatp.gpfn));
  ret = HYPERVISOR_memory_op(Device, XENMEM_add_to_physmap, &xatp);
  KdPrint((__DRIVER_NAME " hypervisor memory op ret = %d\n", ret));
  xpdd->shared_info_area = MmMapIoSpace(shared_info_area_unmapped,
    PAGE_SIZE, MmCached);
  return 0;
} 

static int
set_callback_irq(WDFDEVICE Device, ULONGLONG irq)
{
  struct xen_hvm_param a;
  int retval;

  KdPrint((__DRIVER_NAME " --> set_callback_irq\n"));
  a.domid = DOMID_SELF;
  a.index = HVM_PARAM_CALLBACK_IRQ;
  a.value = irq;
  retval = HYPERVISOR_hvm_op(Device, HVMOP_set_param, &a);
  KdPrint((__DRIVER_NAME " HYPERVISOR_hvm_op retval = %d\n", retval));
  KdPrint((__DRIVER_NAME " <-- set_callback_irq\n"));
  return retval;
}

WDFQUEUE ReadQueue;

static NTSTATUS
XenPCI_AddDevice(
    IN WDFDRIVER Driver,
    IN PWDFDEVICE_INIT DeviceInit
    )
{
  NTSTATUS Status;
  WDF_CHILD_LIST_CONFIG config;
  WDF_OBJECT_ATTRIBUTES attributes;
  WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
  WDF_IO_QUEUE_CONFIG IoQConfig;
  WDF_INTERRUPT_CONFIG InterruptConfig;
  PNP_BUS_INFORMATION busInfo;
  DECLARE_CONST_UNICODE_STRING(DeviceName, L"\\Device\\XenShutdown");
  DECLARE_CONST_UNICODE_STRING(SymbolicName, L"\\DosDevices\\XenShutdown");
  WDFDEVICE Device;
  PXENPCI_DEVICE_DATA xpdd;
  PWSTR InterfaceList;

  UNREFERENCED_PARAMETER(Driver);

  KdPrint((__DRIVER_NAME " --> DeviceAdd\n"));

  WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);
  WDF_CHILD_LIST_CONFIG_INIT(&config, sizeof(XENPCI_IDENTIFICATION_DESCRIPTION), XenPCI_ChildListCreateDevice);
  WdfFdoInitSetDefaultChildListConfig(DeviceInit, &config, WDF_NO_OBJECT_ATTRIBUTES);

  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
  pnpPowerCallbacks.EvtDevicePrepareHardware = XenPCI_PrepareHardware;
  pnpPowerCallbacks.EvtDeviceReleaseHardware = XenPCI_ReleaseHardware;
  pnpPowerCallbacks.EvtDeviceD0Entry = XenPCI_D0Entry;
  pnpPowerCallbacks.EvtDeviceD0EntryPostInterruptsEnabled
    = XenPCI_D0EntryPostInterruptsEnabled;
  pnpPowerCallbacks.EvtDeviceD0ExitPreInterruptsDisabled
    = XenPCI_D0ExitPreInterruptsDisabled;
  pnpPowerCallbacks.EvtDeviceD0Exit = XenPCI_D0Exit;
  WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

  WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);

  Status = WdfDeviceInitAssignName(DeviceInit, &DeviceName);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceInitAssignName failed 0x%08x\n", Status));
    return Status;
  }

  /*initialize storage for the device context*/
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, XENPCI_DEVICE_DATA);

  /*create a device instance.*/
  Status = WdfDeviceCreate(&DeviceInit, &attributes, &Device);  
  if(!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreate failed with Status 0x%08x\n", Status));
    return Status;
  }
  xpdd = GetDeviceData(Device);
  xpdd->Device = Device;

  WdfDeviceSetSpecialFileSupport(Device, WdfSpecialFilePaging, TRUE);
  WdfDeviceSetSpecialFileSupport(Device, WdfSpecialFileHibernation, TRUE);
  WdfDeviceSetSpecialFileSupport(Device, WdfSpecialFileDump, TRUE);

  Status = IoGetDeviceInterfaces(&GUID_XENHIDE_IFACE, NULL, 0, &InterfaceList);
  if (!NT_SUCCESS(Status) || InterfaceList == NULL || *InterfaceList == 0)
  {
    AutoEnumerate = FALSE;
    KdPrint((__DRIVER_NAME "     XenHide not loaded or GPLPV not specified\n", Status));
  }
  else
  {
    AutoEnumerate = TRUE;
    KdPrint((__DRIVER_NAME "     XenHide loaded and GPLPV specified\n", Status));
  }

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
  KeInitializeGuardedMutex(&xpdd->WatchHandlerMutex);
#endif
  busInfo.BusTypeGuid = GUID_XENPCI_DEVCLASS;
  busInfo.LegacyBusType = Internal;
  busInfo.BusNumber = 0;

  WdfDeviceSetBusInformationForChildren(Device, &busInfo);

  WDF_INTERRUPT_CONFIG_INIT(&InterruptConfig, EvtChn_Interrupt, NULL);
  InterruptConfig.EvtInterruptEnable = XenPCI_InterruptEnable;
  InterruptConfig.EvtInterruptDisable = XenPCI_InterruptDisable;
  Status = WdfInterruptCreate(Device, &InterruptConfig, WDF_NO_OBJECT_ATTRIBUTES, &xpdd->XenInterrupt);
  if (!NT_SUCCESS (Status))
  {
    KdPrint((__DRIVER_NAME "     WdfInterruptCreate failed 0x%08x\n", Status));
    return Status;
  }

  Status = WdfDeviceCreateDeviceInterface(Device, (LPGUID)&GUID_XEN_IFACE, NULL);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreateDeviceInterface failed 0x%08x\n", Status));
    return Status;
  }
  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&IoQConfig, WdfIoQueueDispatchSequential);
  IoQConfig.EvtIoDefault = XenPCI_IoDefault;

  Status = WdfIoQueueCreate(Device, &IoQConfig, WDF_NO_OBJECT_ATTRIBUTES, NULL);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfIoQueueCreate failed 0x%08x\n", Status));
    return Status;
  }

  WDF_IO_QUEUE_CONFIG_INIT(&IoQConfig, WdfIoQueueDispatchSequential);
  IoQConfig.EvtIoRead = XenPCI_IoRead;

  Status = WdfIoQueueCreate(Device, &IoQConfig, WDF_NO_OBJECT_ATTRIBUTES, &ReadQueue);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfIoQueueCreate (ReadQueue) failed 0x%08x\n", Status));
    return Status;
  }

  WdfIoQueueStopSynchronously(ReadQueue);
  WdfDeviceConfigureRequestDispatching(Device, ReadQueue, WdfRequestTypeRead);

  Status = WdfDeviceCreateSymbolicLink(Device, &SymbolicName);
  if (!NT_SUCCESS(Status))
  {
    KdPrint((__DRIVER_NAME "     WdfDeviceCreateSymbolicLink failed 0x%08x\n", Status));
    return Status;
  }

  KdPrint((__DRIVER_NAME " <-- DeviceAdd\n"));
  return Status;
}

static NTSTATUS
XenPCI_PrepareHardware(
  IN WDFDEVICE    Device,
  IN WDFCMRESLIST ResourceList,
  IN WDFCMRESLIST ResourceListTranslated)
{
  NTSTATUS status = STATUS_SUCCESS;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR descriptor;
  ULONG i;
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);

  KdPrint((__DRIVER_NAME " --> EvtDevicePrepareHardware\n"));

  for (i = 0; i < WdfCmResourceListGetCount(ResourceList); i++)
  {
    descriptor = WdfCmResourceListGetDescriptor(ResourceList, i);
    if(!descriptor)
      continue;
    switch (descriptor->Type)
    {
    case CmResourceTypeInterrupt:
      xpdd->irqNumber = descriptor->u.Interrupt.Vector;
      break;
    }
  }

  //KdPrint((__DRIVER_NAME " GSI = %d\n", irqNumber));

  //KdPrint((__DRIVER_NAME " ResourceListTranslated\n"));
  for (i = 0; i < WdfCmResourceListGetCount(ResourceListTranslated); i++)
  {
    descriptor = WdfCmResourceListGetDescriptor(ResourceListTranslated, i);
    if(!descriptor)
    {
      KdPrint((__DRIVER_NAME " --> EvtDevicePrepareHardware (No descriptor)\n"));
      return STATUS_DEVICE_CONFIGURATION_ERROR;
    }
    switch (descriptor->Type) {
    case CmResourceTypePort:
      //KdPrint((__DRIVER_NAME "     I/O mapped CSR: (%x) Length: (%d)\n", descriptor->u.Port.Start.LowPart, descriptor->u.Port.Length));
      break;
    case CmResourceTypeMemory:
      KdPrint((__DRIVER_NAME "     Memory mapped CSR:(%x:%x) Length:(%d)\n", descriptor->u.Memory.Start.LowPart, descriptor->u.Memory.Start.HighPart, descriptor->u.Memory.Length));
      xpdd->platform_mmio_addr = descriptor->u.Memory.Start;
      xpdd->platform_mmio_len = descriptor->u.Memory.Length;
      xpdd->platform_mmio_alloc = 0;
      break;
    case CmResourceTypeInterrupt:
      //KdPrint((__DRIVER_NAME "     Interrupt level: 0x%0x, Vector: 0x%0x\n", descriptor->u.Interrupt.Level, descriptor->u.Interrupt.Vector));
      memcpy(&InterruptRaw, WdfCmResourceListGetDescriptor(ResourceList, i), sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
      memcpy(&InterruptTranslated, WdfCmResourceListGetDescriptor(ResourceListTranslated, i), sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
      break;
    case CmResourceTypeDevicePrivate:
      //KdPrint((__DRIVER_NAME "     Private Data: 0x%02x 0x%02x 0x%02x\n", descriptor->u.DevicePrivate.Data[0], descriptor->u.DevicePrivate.Data[1], descriptor->u.DevicePrivate.Data[2] ));
      break;
    default:
      //KdPrint((__DRIVER_NAME "     Unhandled resource type (0x%x)\n", descriptor->Type));
      break;
    }
  }

  get_hypercall_stubs(Device);

  if (init_xen_info(Device))
    return STATUS_ACCESS_DENIED;

  GntTbl_Init(Device);

  EvtChn_Init(Device);

  set_callback_irq(Device, xpdd->irqNumber);

  XenBus_Init(Device);

  //KdPrint((__DRIVER_NAME " upcall_pending = %d\n", shared_info_area->vcpu_info[0].evtchn_upcall_pending));

  xpdd->shared_info_area->vcpu_info[0].evtchn_upcall_mask = 0;

  //xen_reboot_init();

  KdPrint((__DRIVER_NAME " <-- EvtDevicePrepareHardware\n"));

  return status;
}

static NTSTATUS
XenPCI_ReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)
{
  UNREFERENCED_PARAMETER(ResourcesTranslated);

  free_hypercall_stubs(Device);

  return STATUS_SUCCESS;
}

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
  ChildDeviceData->XenInterface.InterfaceHeader.Version = 1;
  ChildDeviceData->XenInterface.InterfaceHeader.Context = WdfPdoGetParent(ChildDevice);
  ChildDeviceData->XenInterface.InterfaceHeader.InterfaceReference = WdfDeviceInterfaceReferenceNoOp;
  ChildDeviceData->XenInterface.InterfaceHeader.InterfaceDereference = WdfDeviceInterfaceDereferenceNoOp;

  ChildDeviceData->XenInterface.AllocMMIO = XenPCI_AllocMMIO;
  ChildDeviceData->XenInterface.FreeMem = XenPCI_FreeMem;

  ChildDeviceData->XenInterface.EvtChn_Bind = EvtChn_Bind;
  ChildDeviceData->XenInterface.EvtChn_Unbind = EvtChn_Unbind;
  ChildDeviceData->XenInterface.EvtChn_Mask = EvtChn_Mask;
  ChildDeviceData->XenInterface.EvtChn_Unmask = EvtChn_Unmask;
  ChildDeviceData->XenInterface.EvtChn_Notify = EvtChn_Notify;
  ChildDeviceData->XenInterface.EvtChn_AllocUnbound = EvtChn_AllocUnbound;
  ChildDeviceData->XenInterface.EvtChn_BindDpc = EvtChn_BindDpc;

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

VOID
XenPCI_XenBusWatchHandler(char *Path, PVOID Data)
{
  NTSTATUS status;
  char **Bits;
  int Count;
  WDFDEVICE Device = Data;
  WDFCHILDLIST ChildList;
  WDF_CHILD_LIST_ITERATOR ChildIterator;
  WDFDEVICE ChildDevice;
  PXENPCI_XEN_DEVICE_DATA ChildDeviceData;
  XENPCI_IDENTIFICATION_DESCRIPTION description;
#if (NTDDI_VERSION >= NTDDI_WS03SP1)
  PXENPCI_DEVICE_DATA xpdd = GetDeviceData(Device);
#endif

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));

#if (NTDDI_VERSION >= NTDDI_WS03SP1)
  KeAcquireGuardedMutex(&xpdd->WatchHandlerMutex);
#endif

  KdPrint((__DRIVER_NAME "     Path = %s\n", Path));

  ChildList = WdfFdoGetDefaultChildList(Device);

  Bits = SplitString(Path, '/', 3, &Count);

  KdPrint((__DRIVER_NAME "     Count = %s\n", Count));

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

  KdPrint((__DRIVER_NAME " --> XenBus_ShutdownHandler\n"));

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
    Entry = (PSHUTDOWN_MSG_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(SHUTDOWN_MSG_ENTRY) + strlen(Value) + 1 + 1, XENPCI_POOL_TAG);
    Entry->Ptr = 0;
    RtlStringCbPrintfA(Entry->Buf, sizeof(SHUTDOWN_MSG_ENTRY) + strlen(Value) + 1 + 1, "%s\n", Value);
    InsertTailList(&ShutdownMsgList, &Entry->ListEntry);
    WdfIoQueueStart(ReadQueue);
  }

  XenPCI_FreeMem(Value);

  KdPrint((__DRIVER_NAME " <-- XenBus_ShutdownHandler\n"));
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

