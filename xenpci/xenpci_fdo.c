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
#include <aux_klib.h>

#define SYSRQ_PATH "control/sysrq"
#define SHUTDOWN_PATH "control/shutdown"
#define BALLOON_PATH "memory/target"

static VOID
XenPci_MapHalThenPatchKernel(PXENPCI_DEVICE_DATA xpdd)
{
  NTSTATUS status;
  PAUX_MODULE_EXTENDED_INFO amei;
  ULONG module_info_buffer_size;
  ULONG i;
   
  FUNCTION_ENTER();

  status = AuxKlibInitialize();
  amei = NULL;
  /* buffer size could change between requesting and allocating - need to loop until we are successful */
  while ((status = AuxKlibQueryModuleInformation(&module_info_buffer_size, sizeof(AUX_MODULE_EXTENDED_INFO), amei)) == STATUS_BUFFER_TOO_SMALL || amei == NULL)
  {
    if (amei != NULL)
      ExFreePoolWithTag(amei, XENPCI_POOL_TAG);
    amei = ExAllocatePoolWithTag(NonPagedPool, module_info_buffer_size, XENPCI_POOL_TAG);
  }
  
  KdPrint((__DRIVER_NAME "     AuxKlibQueryModuleInformation = %d\n", status));
  for (i = 0; i < module_info_buffer_size / sizeof(AUX_MODULE_EXTENDED_INFO); i++)
  {
    if (strcmp((PCHAR)amei[i].FullPathName + amei[i].FileNameOffset, "hal.dll") == 0)
    {
      KdPrint((__DRIVER_NAME "     hal.dll found at %p - %p\n", 
        amei[i].BasicInfo.ImageBase,
        ((PUCHAR)amei[i].BasicInfo.ImageBase) + amei[i].ImageSize));
      XenPci_PatchKernel(xpdd, amei[i].BasicInfo.ImageBase, amei[i].ImageSize);
    }
  }
  ExFreePoolWithTag(amei, XENPCI_POOL_TAG);
  FUNCTION_EXIT();
}

#if 0
PMDL
XenPCI_AllocMMIO(WDFDEVICE device, ULONG len)
{
  PMDL mdl = ExAllocatePoolWithTag(NonPagedPool, MmSizeOfMdl(0, len), XENPCI_POOL_TAG);
  PVOID va = MmAllocateMappingAddress(len, XENPCI_POOL_TAG);
  
  for (i = 0; i < ADDRESS_AND_SIZE_TO_SPAN_PAGES(0, len);
  
}
#endif

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

extern ULONG tpr_patch_requested;

NTSTATUS
XenPci_EvtDeviceQueryRemove(WDFDEVICE device)
{
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(device);
  NTSTATUS status;
  
  FUNCTION_ENTER();
  if (xpdd->removable)
    status = STATUS_SUCCESS;
  else
    status = STATUS_UNSUCCESSFUL;
  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPci_Init(PXENPCI_DEVICE_DATA xpdd)
{
  struct xen_add_to_physmap xatp;
  int ret;

  FUNCTION_ENTER();

  hvm_get_stubs(xpdd);

  if (!xpdd->shared_info_area)
  {
    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
    /* this should be safe as this part will never be called on resume where IRQL == HIGH_LEVEL */
    xpdd->shared_info_area_unmapped = XenPci_AllocMMIO(xpdd, PAGE_SIZE);
    xpdd->shared_info_area = MmMapIoSpace(xpdd->shared_info_area_unmapped,
      PAGE_SIZE, MmNonCached);
  }
  KdPrint((__DRIVER_NAME "     shared_info_area_unmapped.QuadPart = %lx\n", xpdd->shared_info_area_unmapped.QuadPart));
  xatp.domid = DOMID_SELF;
  xatp.idx = 0;
  xatp.space = XENMAPSPACE_shared_info;
  xatp.gpfn = (xen_pfn_t)(xpdd->shared_info_area_unmapped.QuadPart >> PAGE_SHIFT);
  KdPrint((__DRIVER_NAME "     gpfn = %x\n", xatp.gpfn));
  ret = HYPERVISOR_memory_op(xpdd, XENMEM_add_to_physmap, &xatp);
  KdPrint((__DRIVER_NAME "     hypervisor memory op (XENMAPSPACE_shared_info) ret = %d\n", ret));
  
  FUNCTION_EXIT();

  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_Resume(PXENPCI_DEVICE_DATA xpdd)
{
  return XenPci_Init(xpdd);
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
  case 0:
    break;
  case 'B': /* cause a bug check */
    KeBugCheckEx(('X' << 16)|('E' << 8)|('N'), 0x00000001, 0x00000000, 0x00000000, 0x00000000);
    break;
  default:
    KdPrint(("     Unhandled sysrq letter %c\n", letter));
    break;
  }

  FUNCTION_EXIT();
}

#if 0
static VOID
XenPci_PrintPendingInterrupts()
{
  PULONG bitmap = (PULONG)0xFFFE0200;
  int i;
  int j;
  ULONG value;
  
  for (i = 0; i < 8; i++)
  {
    value = bitmap[(7 - i) * 4];
    if (value)
    {
      for (j = 0; j < 32; j++)
      {
        if ((value >> j) & 1)
          KdPrint(("     Interrupt pending on pin %d\n", ((7 - i) << 5) | j));
      }
    }
  }
}
#endif

#define BALLOON_UNIT_PAGES (BALLOON_UNITS >> PAGE_SHIFT)

static VOID
XenPci_BalloonThreadProc(PVOID StartContext)
{
  PXENPCI_DEVICE_DATA xpdd = StartContext;
  ULONG new_target = xpdd->current_memory;
  LARGE_INTEGER timeout;
  PLARGE_INTEGER ptimeout;
  PMDL head = NULL;
  // use the memory_op(unsigned int op, void *arg) hypercall to adjust memory
  // use XENMEM_increase_reservation and XENMEM_decrease_reservation

  FUNCTION_ENTER();

  for(;;)
  {
    if (xpdd->current_memory != new_target)
    {
      timeout.QuadPart = (LONGLONG)-1 * 1000 * 1000 * 10;
      ptimeout = &timeout;
    }
    else
    {
      ptimeout = NULL;
    }
    KeWaitForSingleObject(&xpdd->balloon_event, Executive, KernelMode, FALSE, ptimeout);
//TODO: initiate shutdown here
    KdPrint((__DRIVER_NAME "     Got balloon event, current = %d, target = %d\n", xpdd->current_memory, xpdd->target_memory));
    /* not really worried about races here, but cache target so we only read it once */
    new_target = xpdd->target_memory;
    // perform some sanity checks on target_memory
    // make sure target <= initial
    // make sure target > some % of initial
    
    if (xpdd->current_memory == new_target)
    {
      KdPrint((__DRIVER_NAME "     No change to memory\n"));
      continue;
    }
    else if (xpdd->current_memory < new_target)
    {
      PMDL mdl;      
      KdPrint((__DRIVER_NAME "     Trying to take %d MB from Xen\n", new_target - xpdd->current_memory));
      while ((mdl = head) != NULL && xpdd->current_memory < new_target)
      {
        head = mdl->Next;
        mdl->Next = NULL;
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
        xpdd->current_memory++;
      }
    }
    else
    {
      KdPrint((__DRIVER_NAME "     Trying to give %d MB to Xen\n", xpdd->current_memory - new_target));
      while (xpdd->current_memory > new_target)
      {
        PHYSICAL_ADDRESS alloc_low;
        PHYSICAL_ADDRESS alloc_high;
        PHYSICAL_ADDRESS alloc_skip;
        PMDL mdl;
        alloc_low.QuadPart = 0;
        alloc_high.QuadPart = 0xFFFFFFFFFFFFFFFFULL;
        alloc_skip.QuadPart = 0;
        mdl = MmAllocatePagesForMdl(alloc_low, alloc_high, alloc_skip, BALLOON_UNITS);
        if (!mdl)
        {
          KdPrint((__DRIVER_NAME "     Allocation failed - try again in 1 second\n"));
          break;
        }
        else
        {
          if (head)
          {
            mdl->Next = head;
            head = mdl;
          }
          else
          {
            head = mdl;
          }
          xpdd->current_memory--;
        }
      }
    }
  }
  //FUNCTION_EXIT();
}

static VOID
XenPci_BalloonHandler(char *Path, PVOID Data)
{
  WDFDEVICE device = Data;
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(device);
  char *value;
  xenbus_transaction_t xbt;
  int retry;

  UNREFERENCED_PARAMETER(Path);

  FUNCTION_ENTER();

  XenBus_StartTransaction(xpdd, &xbt);

  XenBus_Read(xpdd, XBT_NIL, BALLOON_PATH, &value);
  
  if (value == NULL)
  {
    KdPrint((__DRIVER_NAME "     Failed to read value\n"));
    XenBus_EndTransaction(xpdd, xbt, 0, &retry);
    FUNCTION_EXIT();
    return;
  }

  if (atoi(value) > 0)
    xpdd->target_memory = atoi(value) >> 10; /* convert to MB */

  KdPrint((__DRIVER_NAME "     target memory value = %d (%s)\n", xpdd->target_memory, value));

  XenBus_EndTransaction(xpdd, xbt, 0, &retry);

  XenPci_FreeMem(value);

  KeSetEvent(&xpdd->balloon_event, IO_NO_INCREMENT, FALSE);
  
  // start a thread to allocate memory up to the required amount

  FUNCTION_EXIT();
}

static VOID
XenPci_Suspend0(PVOID context)
{
  PXENPCI_DEVICE_DATA xpdd = context;
  ULONG cancelled;
  
  FUNCTION_ENTER();

  GntTbl_Suspend(xpdd);
  
  cancelled = hvm_shutdown(xpdd, SHUTDOWN_suspend);
  KdPrint((__DRIVER_NAME "     back from suspend, cancelled = %d\n", cancelled));

  if (qemu_filtered_by_qemu)
  {
    XenPci_HideQemuDevices();
    ASSERT(qemu_filtered_by_qemu);
  }

  XenPci_Resume(xpdd);
  GntTbl_Resume(xpdd);
  EvtChn_Resume(xpdd); /* this enables interrupts again too */

  FUNCTION_EXIT();
}

static VOID
XenPci_SuspendN(PVOID context)
{
  UNREFERENCED_PARAMETER(context);
  
  FUNCTION_ENTER();
  KdPrint((__DRIVER_NAME "     doing nothing on cpu N\n"));
  FUNCTION_EXIT();
}

/* Called at PASSIVE_LEVEL */
static VOID DDKAPI
XenPci_SuspendResume(WDFWORKITEM workitem)
{
  NTSTATUS status;
  //KAFFINITY ActiveProcessorMask = 0; // this is for Vista+
  WDFDEVICE device = WdfWorkItemGetParentObject(workitem);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(device);
  WDFCHILDLIST child_list = WdfFdoGetDefaultChildList(device);
  WDF_CHILD_LIST_ITERATOR child_iterator;
  WDFDEVICE child_device;

  FUNCTION_ENTER();

  if (xpdd->suspend_state == SUSPEND_STATE_NONE)
  {
    xpdd->suspend_state = SUSPEND_STATE_SCHEDULED;
    KeMemoryBarrier();

    WDF_CHILD_LIST_ITERATOR_INIT(&child_iterator, WdfRetrievePresentChildren);
    WdfChildListBeginIteration(child_list, &child_iterator);
    while ((status = WdfChildListRetrieveNextDevice(child_list, &child_iterator, &child_device, NULL)) == STATUS_SUCCESS)
    {
      KdPrint((__DRIVER_NAME "     Suspending child\n"));
      XenPci_Pdo_Suspend(child_device);
    }
    KdPrint((__DRIVER_NAME "     WdfChildListRetrieveNextDevice = %08x, STATUS_NO_MORE_ENTRIES = %08x\n", status, STATUS_NO_MORE_ENTRIES));
    WdfChildListEndIteration(child_list, &child_iterator);

    XenBus_Suspend(xpdd);
    EvtChn_Suspend(xpdd);
    XenPci_HighSync(XenPci_Suspend0, XenPci_SuspendN, xpdd);

    xpdd->suspend_state = SUSPEND_STATE_RESUMING;
    XenBus_Resume(xpdd);

    WdfChildListBeginIteration(child_list, &child_iterator);
    while ((status = WdfChildListRetrieveNextDevice(child_list, &child_iterator, &child_device, NULL)) == STATUS_SUCCESS)
    {
      KdPrint((__DRIVER_NAME "     Resuming child\n"));
      XenPci_Pdo_Resume(child_device);
    }
    KdPrint((__DRIVER_NAME "     WdfChildListRetrieveNextDevice = %08x, STATUS_NO_MORE_ENTRIES = %08x\n", status, STATUS_NO_MORE_ENTRIES));
    WdfChildListEndIteration(child_list, &child_iterator);

    xpdd->suspend_state = SUSPEND_STATE_NONE;
  }
  FUNCTION_EXIT();
}

static void
XenPci_ShutdownHandler(char *path, PVOID context)
{
  NTSTATUS status;
  WDFDEVICE device = context;
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(device);
  char *res;
  char *value;
  //KIRQL old_irql;
  WDF_OBJECT_ATTRIBUTES attributes;
  WDF_WORKITEM_CONFIG workitem_config;
  WDFWORKITEM workitem;

  UNREFERENCED_PARAMETER(path);

  FUNCTION_ENTER();

  res = XenBus_Read(xpdd, XBT_NIL, SHUTDOWN_PATH, &value);
  if (res)
  {
    KdPrint(("Error reading shutdown path - %s\n", res));
    XenPci_FreeMem(res);
    FUNCTION_EXIT();
    return;
  }

  KdPrint((__DRIVER_NAME "     Shutdown value = %s\n", value));

  if (strlen(value) && strcmp(value, "suspend") == 0)
  {
    {
      KdPrint((__DRIVER_NAME "     Suspend detected\n"));
      /* we have to queue this as a work item as we stop the xenbus thread, which we are currently running in! */
      WDF_WORKITEM_CONFIG_INIT(&workitem_config, XenPci_SuspendResume);
      WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
      attributes.ParentObject = device;
      status = WdfWorkItemCreate(&workitem_config, &attributes, &workitem);
      // TODO: check status here
      WdfWorkItemEnqueue(workitem);
    }
  }

  XenPci_FreeMem(value);

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

  //FUNCTION_ENTER();

  bits = SplitString(path, '/', 4, &count);
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
      KdPrint((__DRIVER_NAME "     Rescanning child list\n"));
      XenPci_EvtChildListScanForChildren(xpdd->child_list);
    }
  }
  FreeSplitString(bits, count);

  //FUNCTION_EXIT();
}

NTSTATUS
XenPci_EvtDevicePrepareHardware (WDFDEVICE device, WDFCMRESLIST resources_raw, WDFCMRESLIST resources_translated)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(device);
  PCM_PARTIAL_RESOURCE_DESCRIPTOR raw_descriptor, translated_descriptor;
  ULONG i;

  FUNCTION_ENTER();
  
  ASSERT(WdfCmResourceListGetCount(resources_raw) == WdfCmResourceListGetCount(resources_translated));
  
  for (i = 0; i < WdfCmResourceListGetCount(resources_raw); i++)
  {
    raw_descriptor = WdfCmResourceListGetDescriptor(resources_raw, i);
    translated_descriptor = WdfCmResourceListGetDescriptor(resources_translated, i);
    switch (raw_descriptor->Type) {
    case CmResourceTypePort:
      KdPrint((__DRIVER_NAME "     IoPort Address(%x) Length: %d\n", translated_descriptor->u.Port.Start.LowPart, translated_descriptor->u.Port.Length));
      xpdd->platform_ioport_addr = translated_descriptor->u.Port.Start.LowPart;
      xpdd->platform_ioport_len = translated_descriptor->u.Port.Length;
      break;
    case CmResourceTypeMemory:
      KdPrint((__DRIVER_NAME "     Memory mapped CSR:(%x:%x) Length:(%d)\n", translated_descriptor->u.Memory.Start.LowPart, translated_descriptor->u.Memory.Start.HighPart, translated_descriptor->u.Memory.Length));
      KdPrint((__DRIVER_NAME "     Memory flags = %04X\n", translated_descriptor->Flags));
#if 0      
      mmio_freelist_free = 0;
      for (j = 0; j < translated_descriptor->u.Memory.Length >> PAGE_SHIFT; j++)
        put_mmio_on_freelist((xpdd->platform_mmio_addr >> PAGE_SHIFT) + j);
#endif
      xpdd->platform_mmio_addr = translated_descriptor->u.Memory.Start;
      xpdd->platform_mmio_len = translated_descriptor->u.Memory.Length;
      xpdd->platform_mmio_flags = translated_descriptor->Flags;
      break;
    case CmResourceTypeInterrupt:
	    xpdd->irq_level = (KIRQL)translated_descriptor->u.Interrupt.Level;
  	  xpdd->irq_vector = translated_descriptor->u.Interrupt.Vector;
	    xpdd->irq_affinity = translated_descriptor->u.Interrupt.Affinity;
      xpdd->irq_mode = (translated_descriptor->Flags & CM_RESOURCE_INTERRUPT_LATCHED)?Latched:LevelSensitive;
      xpdd->irq_number = raw_descriptor->u.Interrupt.Vector;      
      KdPrint((__DRIVER_NAME "     irq_number = %03x\n", raw_descriptor->u.Interrupt.Vector));
      KdPrint((__DRIVER_NAME "     irq_vector = %03x\n", translated_descriptor->u.Interrupt.Vector));
      KdPrint((__DRIVER_NAME "     irq_level = %03x\n", translated_descriptor->u.Interrupt.Level));
      KdPrint((__DRIVER_NAME "     irq_mode = %s\n", (xpdd->irq_mode == Latched)?"Latched":"LevelSensitive"));
      switch(translated_descriptor->ShareDisposition)
      {
      case CmResourceShareDeviceExclusive:
        KdPrint((__DRIVER_NAME "     ShareDisposition = CmResourceShareDeviceExclusive\n"));
        break;
      case CmResourceShareDriverExclusive:
        KdPrint((__DRIVER_NAME "     ShareDisposition = CmResourceShareDriverExclusive\n"));
        break;
      case CmResourceShareShared:
        KdPrint((__DRIVER_NAME "     ShareDisposition = CmResourceShareShared\n"));
        break;
      default:
        KdPrint((__DRIVER_NAME "     ShareDisposition = %d\n", translated_descriptor->ShareDisposition));
        break;
      }
      break;
    case CmResourceTypeDevicePrivate:
      KdPrint((__DRIVER_NAME "     Private Data: 0x%02x 0x%02x 0x%02x\n", translated_descriptor->u.DevicePrivate.Data[0], translated_descriptor->u.DevicePrivate.Data[1], translated_descriptor->u.DevicePrivate.Data[2]));
      break;
    default:
      KdPrint((__DRIVER_NAME "     Unhandled resource type (0x%x)\n", translated_descriptor->Type));
      break;
    }
  }

  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenPci_EvtDeviceD0Entry(WDFDEVICE device, WDF_POWER_DEVICE_STATE previous_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(device);

  FUNCTION_ENTER();

  xpdd->hibernated = FALSE;

  switch (previous_state)
  {
  case WdfPowerDeviceD0:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD1:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD2:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD2\n"));
    break;
  case WdfPowerDeviceD3:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3\n"));
    break;
  case WdfPowerDeviceD3Final:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3Final\n"));
    break;
  case WdfPowerDevicePrepareForHibernation:
    KdPrint((__DRIVER_NAME "     WdfPowerDevicePrepareForHibernation\n"));
    break;  
  default:
    KdPrint((__DRIVER_NAME "     Unknown WdfPowerDevice state %d\n", previous_state));
    break;  
  }

  if (previous_state == WdfPowerDevicePrepareForHibernation && qemu_filtered_by_qemu)
  {
    XenPci_HideQemuDevices();
    ASSERT(qemu_filtered_by_qemu);
  } 
  
  XenPci_Init(xpdd);
  if (tpr_patch_requested && !xpdd->tpr_patched)
  {
    XenPci_MapHalThenPatchKernel(xpdd);
    xpdd->tpr_patched = TRUE;
  }
  if (previous_state == WdfPowerDevicePrepareForHibernation)
  {
    GntTbl_Resume(xpdd);
  }
  else
  {
    GntTbl_Init(xpdd);
  }
  EvtChn_Init(xpdd);

  FUNCTION_EXIT();

  return status;
}

NTSTATUS
XenPci_EvtDeviceD0EntryPostInterruptsEnabled(WDFDEVICE device, WDF_POWER_DEVICE_STATE previous_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(device);
  PCHAR response;
  char *value;
  domid_t domid = DOMID_SELF;
  ULONG ret;
  xen_ulong_t *max_ram_page;

  UNREFERENCED_PARAMETER(previous_state);

  FUNCTION_ENTER();
  
  XenBus_Init(xpdd);

  response = XenBus_AddWatch(xpdd, XBT_NIL, SYSRQ_PATH, XenPci_SysrqHandler, xpdd);
  
  response = XenBus_AddWatch(xpdd, XBT_NIL, SHUTDOWN_PATH, XenPci_ShutdownHandler, device);

  response = XenBus_AddWatch(xpdd, XBT_NIL, "device", XenPci_DeviceWatchHandler, xpdd);

  ret = HYPERVISOR_memory_op(xpdd, XENMEM_current_reservation, &domid);
  KdPrint((__DRIVER_NAME "     XENMEM_current_reservation = %d\n", ret));
  ret = HYPERVISOR_memory_op(xpdd, XENMEM_maximum_reservation, &domid);
  KdPrint((__DRIVER_NAME "     XENMEM_maximum_reservation = %d\n", ret));
  ret = HYPERVISOR_memory_op(xpdd, XENMEM_maximum_ram_page, &max_ram_page);
  KdPrint((__DRIVER_NAME "     XENMEM_maximum_ram_page = %d\n", ret));

  if (!xpdd->initial_memory)
  {
    XenBus_Read(xpdd, XBT_NIL, BALLOON_PATH, &value);
    if (atoi(value) > 0)
    {
      xpdd->initial_memory = atoi(value) >> 10; /* convert to MB */
      xpdd->current_memory = xpdd->initial_memory;
      xpdd->target_memory = xpdd->initial_memory;
    }
    KdPrint((__DRIVER_NAME "     Initial Memory Value = %d (%s)\n", xpdd->initial_memory, value));
    KeInitializeEvent(&xpdd->balloon_event, SynchronizationEvent, FALSE);
    status = PsCreateSystemThread(&xpdd->balloon_thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, XenPci_BalloonThreadProc, xpdd);
    if (!NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     Could not start balloon thread\n"));
      //return status;
    }    
  }
  response = XenBus_AddWatch(xpdd, XBT_NIL, BALLOON_PATH, XenPci_BalloonHandler, device);

  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenPci_EvtDeviceD0ExitPreInterruptsDisabled(WDFDEVICE device, WDF_POWER_DEVICE_STATE target_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  
  UNREFERENCED_PARAMETER(device);
  
  FUNCTION_ENTER();
  
  switch (target_state)
  {
  case WdfPowerDeviceD0:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD1:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD2:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD2\n"));
    break;
  case WdfPowerDeviceD3:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3\n"));
    break;
  case WdfPowerDeviceD3Final:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3Final\n"));
    break;
  case WdfPowerDevicePrepareForHibernation:
    KdPrint((__DRIVER_NAME "     WdfPowerDevicePrepareForHibernation\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unknown WdfPowerDevice state %d\n", target_state));
    break;  
  }
  
  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenPci_EvtDeviceD0Exit(WDFDEVICE device, WDF_POWER_DEVICE_STATE target_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(device);
  
  FUNCTION_ENTER();

  switch (target_state)
  {
  case WdfPowerDeviceD0:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD1:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD1\n"));
    break;
  case WdfPowerDeviceD2:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD2\n"));
    break;
  case WdfPowerDeviceD3:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3\n"));
    break;
  case WdfPowerDeviceD3Final:
    KdPrint((__DRIVER_NAME "     WdfPowerDeviceD3Final\n"));
    break;
  case WdfPowerDevicePrepareForHibernation:
    KdPrint((__DRIVER_NAME "     WdfPowerDevicePrepareForHibernation\n"));
    xpdd->hibernated = TRUE;
    break;  
  default:
    KdPrint((__DRIVER_NAME "     Unknown WdfPowerDevice state %d\n", target_state));
    break;  
  }
  
  if (target_state == WdfPowerDevicePrepareForHibernation)
  {
    GntTbl_Suspend(xpdd);
  }

  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenPci_EvtDeviceReleaseHardware(WDFDEVICE device, WDFCMRESLIST resources_translated)
{
  NTSTATUS status = STATUS_SUCCESS;
  
  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(resources_translated);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  
  return status;
}

VOID
XenPci_EvtChildListScanForChildren(WDFCHILDLIST child_list)
{
  NTSTATUS status;
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(WdfChildListGetDevice(child_list));
  char *msg;
  char **devices;
  char **instances;
  ULONG i, j;
  CHAR path[128];
  XENPCI_PDO_IDENTIFICATION_DESCRIPTION child_description;
  
  FUNCTION_ENTER();

  WdfChildListBeginScan(child_list);

  msg = XenBus_List(xpdd, XBT_NIL, "device", &devices);
  if (!msg)
  {
    for (i = 0; devices[i]; i++)
    {
      RtlStringCbPrintfA(path, ARRAY_SIZE(path), "device/%s", devices[i]);
      
      for (j = 0; j < WdfCollectionGetCount(xpdd->veto_devices); j++)
      {
        WDFOBJECT ws = WdfCollectionGetItem(xpdd->veto_devices, j);
        UNICODE_STRING val;
        ANSI_STRING s;
        WdfStringGetUnicodeString(ws, &val);
        RtlUnicodeStringToAnsiString(&s, &val, TRUE);
        if (!strcmp(devices[i], s.Buffer))
        {
          RtlFreeAnsiString(&s);
          break;
        }
        RtlFreeAnsiString(&s);
      }
      if (j < WdfCollectionGetCount(xpdd->veto_devices))
      {
        XenPci_FreeMem(devices[i]);
        continue;
      }
    
      msg = XenBus_List(xpdd, XBT_NIL, path, &instances);
      if (!msg)
      {
        for (j = 0; instances[j]; j++)
        {
          /* the device comparison is done as a memory compare so zero-ing the structure is important */
          RtlZeroMemory(&child_description, sizeof(child_description));
          WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(&child_description.header, sizeof(child_description));
          RtlStringCbPrintfA(path, ARRAY_SIZE(path), "device/%s/%s", devices[i], instances[j]);
          RtlStringCbCopyA(child_description.path, ARRAY_SIZE(child_description.path), path);
          RtlStringCbCopyA(child_description.device, ARRAY_SIZE(child_description.device), devices[i]);
          child_description.index = atoi(instances[j]);
          status = WdfChildListAddOrUpdateChildDescriptionAsPresent(child_list, &child_description.header, NULL);
          if (!NT_SUCCESS(status))
          {
            KdPrint((__DRIVER_NAME "     WdfChildListAddOrUpdateChildDescriptionAsPresent failed with status 0x%08x\n", status));
          }
          XenPci_FreeMem(instances[j]);
        }
        XenPci_FreeMem(instances);
      }
      else
      {
        // wtf do we do here???
        KdPrint((__DRIVER_NAME "     Failed to list %s tree\n", devices[i]));
      }
      XenPci_FreeMem(devices[i]);
    }
    XenPci_FreeMem(devices);
  }
  else
  {
    // wtf do we do here???
    KdPrint((__DRIVER_NAME "     Failed to list device tree\n"));
  }

  WdfChildListEndScan(child_list);
  
  FUNCTION_EXIT();
}
