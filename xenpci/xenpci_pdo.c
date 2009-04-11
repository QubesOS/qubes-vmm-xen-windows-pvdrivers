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

#define MAP_TYPE_VIRTUAL  1
#define MAP_TYPE_MDL      2
#define MAP_TYPE_REMAPPED 3

typedef struct {
  ULONG map_type;
  PVOID aligned_buffer;
  PVOID unaligned_buffer;
  ULONG copy_length;
} sg_extra_t;

typedef struct {
  ULONG map_type;
  PVOID aligned_buffer;
  PVOID unaligned_buffer;
  ULONG copy_length;
  PHYSICAL_ADDRESS logical;
} map_register_t;

typedef struct {
  PDEVICE_OBJECT device_object;
  ULONG total_map_registers;
  ULONG count;
  map_register_t regs[1];
} map_register_base_t;  

static BOOLEAN
XenPci_BIS_TranslateBusAddress(PVOID context, PHYSICAL_ADDRESS bus_address, ULONG length, PULONG address_space, PPHYSICAL_ADDRESS translated_address)
{
  UNREFERENCED_PARAMETER(context);
  UNREFERENCED_PARAMETER(length);
  /* actually this isn't right - should look up the gref for the physical address and work backwards from that */
  FUNCTION_ENTER();
  if (*address_space != 0)
  {
    KdPrint((__DRIVER_NAME "      Cannot map I/O space\n"));
    FUNCTION_EXIT();
    return FALSE;
  }
  *translated_address = bus_address;
  FUNCTION_EXIT();
  return TRUE;
}

static VOID
XenPci_DOP_PutDmaAdapter(PDMA_ADAPTER dma_adapter)
{
  xen_dma_adapter_t *xen_dma_adapter = (xen_dma_adapter_t *)dma_adapter;
  
  FUNCTION_ENTER();

  if (xen_dma_adapter->dma_extension)
    ObDereferenceObject(xen_dma_adapter->dma_extension_driver);
  ExFreePoolWithTag(xen_dma_adapter->adapter_object.DmaHeader.DmaOperations, XENPCI_POOL_TAG);
  ExFreePoolWithTag(xen_dma_adapter, XENPCI_POOL_TAG);
  
  FUNCTION_EXIT();

  return;
}

static PVOID
XenPci_DOP_AllocateCommonBuffer(
  PDMA_ADAPTER DmaAdapter,
  ULONG Length,
  PPHYSICAL_ADDRESS LogicalAddress,
  BOOLEAN CacheEnabled
)
{
  xen_dma_adapter_t *xen_dma_adapter = (xen_dma_adapter_t *)DmaAdapter;
  PXENPCI_DEVICE_DATA xpdd;
  PVOID buffer;
  PFN_NUMBER pfn;
  grant_ref_t gref;
  
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(CacheEnabled);
  
  //FUNCTION_ENTER();

  xpdd = GetXpdd(xen_dma_adapter->xppdd->wdf_device_bus_fdo);

  //KdPrint((__DRIVER_NAME "     Length = %d\n", Length));
  
  buffer = ExAllocatePoolWithTag(NonPagedPool, Length, XENPCI_POOL_TAG);
  ASSERT(buffer); /* lazy */

  pfn = (PFN_NUMBER)(MmGetPhysicalAddress(buffer).QuadPart >> PAGE_SHIFT);
  ASSERT(pfn); /* lazy */
  //KdPrint((__DRIVER_NAME "     A Requesting Grant Ref\n"));
  gref = (grant_ref_t)GntTbl_GrantAccess(xpdd, 0, (ULONG)pfn, FALSE, INVALID_GRANT_REF);
  //KdPrint((__DRIVER_NAME "     A Got Grant Ref %d\n", gref));
  ASSERT(gref); /* lazy */
  LogicalAddress->QuadPart = (gref << PAGE_SHIFT) | (PtrToUlong(buffer) & (PAGE_SIZE - 1));
  
  //FUNCTION_EXIT();
  return buffer;
}

static VOID
XenPci_DOP_FreeCommonBuffer(
  PDMA_ADAPTER dma_adapter,
  ULONG length,
  PHYSICAL_ADDRESS logical_address,
  PVOID virtual_address,
  BOOLEAN cache_enabled
)
{
  xen_dma_adapter_t *xen_dma_adapter = (xen_dma_adapter_t *)dma_adapter;
  PXENPCI_DEVICE_DATA xpdd;
  grant_ref_t gref;

  UNREFERENCED_PARAMETER(dma_adapter);
  UNREFERENCED_PARAMETER(length);
  UNREFERENCED_PARAMETER(cache_enabled);

//  FUNCTION_ENTER();

  xpdd = GetXpdd(xen_dma_adapter->xppdd->wdf_device_bus_fdo);
  gref = (grant_ref_t)(logical_address.QuadPart >> PAGE_SHIFT);
  //KdPrint((__DRIVER_NAME "     F Releasing Grant Ref %d\n", gref));
  GntTbl_EndAccess(xpdd, gref, FALSE);
  //KdPrint((__DRIVER_NAME "     F Released Grant Ref\n"));
  ExFreePoolWithTag(virtual_address, XENPCI_POOL_TAG);

//  FUNCTION_EXIT();
}

static NTSTATUS
XenPci_DOP_AllocateAdapterChannel(
    IN PDMA_ADAPTER dma_adapter,
    IN PDEVICE_OBJECT device_object,
    IN ULONG NumberOfMapRegisters,
    IN PDRIVER_CONTROL ExecutionRoutine,
    IN PVOID Context
    )
{
  //xen_dma_adapter_t *xen_dma_adapter = (xen_dma_adapter_t *)dma_adapter;
  //PXENPCI_DEVICE_DATA xpdd = GetXpdd(xen_dma_adapter->xppdd->wdf_device_bus_fdo);
  IO_ALLOCATION_ACTION action;
  map_register_base_t *map_register_base;
  
  UNREFERENCED_PARAMETER(dma_adapter);
  
  //FUNCTION_ENTER();

  map_register_base = ExAllocatePoolWithTag(NonPagedPool, 
    FIELD_OFFSET(map_register_base_t, regs) + NumberOfMapRegisters * sizeof(map_register_t), XENPCI_POOL_TAG);
  if (!map_register_base)
  {
    KdPrint((__DRIVER_NAME "     Cannot allocate memory for map_register_base\n"));
    //FUNCTION_EXIT();
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  /* we should also allocate a single page of memory here for remap purposes as once we allocate the map registers there is no failure allowed */
  map_register_base->device_object = device_object;
  map_register_base->total_map_registers = NumberOfMapRegisters;
  map_register_base->count = 0;
  
  action = ExecutionRoutine(device_object, device_object->CurrentIrp, map_register_base, Context);
  
  switch (action)
  {
  case KeepObject:
    KdPrint((__DRIVER_NAME "     KeepObject\n"));
    ASSERT(FALSE);
    break;
  case DeallocateObject:
    KdPrint((__DRIVER_NAME "     DeallocateObject\n"));
    ASSERT(FALSE);
    break;
  case DeallocateObjectKeepRegisters:
    //KdPrint((__DRIVER_NAME "     DeallocateObjectKeepRegisters\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unknown action %d\n", action));
    ASSERT(FALSE);
    break;
  }
  //FUNCTION_EXIT();
  return STATUS_SUCCESS;
}

static BOOLEAN
XenPci_DOP_FlushAdapterBuffers(
  PDMA_ADAPTER dma_adapter,
  PMDL mdl,
  PVOID MapRegisterBase,
  PVOID CurrentVa,
  ULONG Length,
  BOOLEAN write_to_device)
{
  //xen_dma_adapter_t *xen_dma_adapter = (xen_dma_adapter_t *)dma_adapter;
  //PXENPCI_DEVICE_DATA xpdd = GetXpdd(xen_dma_adapter->xppdd->wdf_device_bus_fdo);
  map_register_base_t *map_register_base = MapRegisterBase;
  map_register_t *map_register;
  ULONG i;
  
  UNREFERENCED_PARAMETER(dma_adapter);
  UNREFERENCED_PARAMETER(mdl);
  UNREFERENCED_PARAMETER(CurrentVa);
  UNREFERENCED_PARAMETER(Length);

  //FUNCTION_ENTER();
  
  for (i = 0; i < map_register_base->count; i++)
  {
    map_register = &map_register_base->regs[i];
    if (map_register->map_type == MAP_TYPE_REMAPPED && !write_to_device)
      memcpy(map_register->unaligned_buffer, map_register->aligned_buffer, map_register->copy_length);
  }
  //FUNCTION_EXIT();
  
  return TRUE;
}

static VOID
XenPci_DOP_FreeAdapterChannel(
    IN PDMA_ADAPTER  DmaAdapter
    )
{
  UNREFERENCED_PARAMETER(DmaAdapter);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
}

static VOID
XenPci_DOP_FreeMapRegisters(
  PDMA_ADAPTER dma_adapter,
  PVOID MapRegisterBase,
  ULONG NumberOfMapRegisters)
{
  xen_dma_adapter_t *xen_dma_adapter = (xen_dma_adapter_t *)dma_adapter;
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xen_dma_adapter->xppdd->wdf_device_bus_fdo);
  map_register_base_t *map_register_base = MapRegisterBase;
  map_register_t *map_register;
  ULONG i;
  grant_ref_t gref;

  //FUNCTION_ENTER();
  ASSERT(map_register_base->total_map_registers == NumberOfMapRegisters);

  for (i = 0; i < map_register_base->count; i++)
  {
    map_register = &map_register_base->regs[i];
    switch (map_register->map_type)
    {
    case MAP_TYPE_REMAPPED:
      gref = (grant_ref_t)(map_register->logical.QuadPart >> PAGE_SHIFT);
      //KdPrint((__DRIVER_NAME "     D Releasing Grant Ref %d\n", gref));
      GntTbl_EndAccess(xpdd, gref, FALSE);
      //KdPrint((__DRIVER_NAME "     D Released Grant Ref\n"));
      ExFreePoolWithTag(map_register->aligned_buffer, XENPCI_POOL_TAG);
      break;
    case MAP_TYPE_MDL:
      gref = (grant_ref_t)(map_register->logical.QuadPart >> PAGE_SHIFT);
      //KdPrint((__DRIVER_NAME "     E Releasing Grant Ref %d\n", gref));
      GntTbl_EndAccess(xpdd, gref, FALSE);
      //KdPrint((__DRIVER_NAME "     E Released Grant Ref\n"));
      break;
    case MAP_TYPE_VIRTUAL:
      break;
    }
  }
  ExFreePoolWithTag(map_register_base, XENPCI_POOL_TAG);

  //FUNCTION_EXIT();
}

static PHYSICAL_ADDRESS
XenPci_DOP_MapTransfer(
    PDMA_ADAPTER dma_adapter,
    PMDL mdl,
    PVOID MapRegisterBase,
    PVOID CurrentVa,
    PULONG Length,
    BOOLEAN WriteToDevice)
{
  xen_dma_adapter_t *xen_dma_adapter = (xen_dma_adapter_t *)dma_adapter;
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xen_dma_adapter->xppdd->wdf_device_bus_fdo);
  map_register_base_t *map_register_base = MapRegisterBase;
  map_register_t *map_register = &map_register_base->regs[map_register_base->count];
  PDEVICE_OBJECT device_object = map_register_base->device_object;
  ULONG page_offset;
  PFN_NUMBER pfn;
  grant_ref_t gref;
  PUCHAR ptr;
  ULONG mdl_offset;
  ULONG pfn_index;

  //FUNCTION_ENTER();

  //KdPrint((__DRIVER_NAME "     Mdl = %p, MapRegisterBase = %p, MdlVa = %p, CurrentVa = %p, Length = %d\n",
  //  mdl, MapRegisterBase, MmGetMdlVirtualAddress(mdl), CurrentVa, *Length));

  ASSERT(mdl);
  ASSERT(map_register_base->count < map_register_base->total_map_registers);
  
  if (xen_dma_adapter->dma_extension)
  {
    if (xen_dma_adapter->dma_extension->need_virtual_address(device_object->CurrentIrp))
    {
      map_register->map_type = MAP_TYPE_VIRTUAL;
    }
    else
    {
      ULONG alignment = xen_dma_adapter->dma_extension->get_alignment(device_object->CurrentIrp);
      if ((MmGetMdlByteOffset(mdl) & (alignment - 1)) || (MmGetMdlByteCount(mdl) & (alignment - 1)))
      {
        map_register->map_type = MAP_TYPE_REMAPPED;
      }
      else
      {
        map_register->map_type = MAP_TYPE_MDL;
      }
    }
  }
  else
  {
    map_register->map_type = MAP_TYPE_MDL;
  }

  switch (map_register->map_type)
  {
  case MAP_TYPE_MDL:
    //KdPrint((__DRIVER_NAME "     MAP_TYPE_MDL\n"));
    mdl_offset = (ULONG)((ULONGLONG)CurrentVa - (ULONGLONG)MmGetMdlVirtualAddress(mdl));
    page_offset = PtrToUlong(CurrentVa) & (PAGE_SIZE - 1);
    *Length = min(*Length, PAGE_SIZE - page_offset);
    pfn_index = (ULONG)(((ULONGLONG)CurrentVa >> PAGE_SHIFT) - ((ULONGLONG)MmGetMdlVirtualAddress(mdl) >> PAGE_SHIFT));
    //KdPrint((__DRIVER_NAME "     mdl_offset = %d, page_offset = %d, length = %d, pfn_index = %d\n",
    //  mdl_offset, page_offset, *Length, pfn_index));
    pfn = MmGetMdlPfnArray(mdl)[pfn_index];
    //KdPrint((__DRIVER_NAME "     B Requesting Grant Ref\n"));
    gref = (grant_ref_t)GntTbl_GrantAccess(xpdd, 0, (ULONG)pfn, FALSE, INVALID_GRANT_REF);
    //KdPrint((__DRIVER_NAME "     B Got Grant Ref %d\n", gref));
    map_register->logical.QuadPart = (LONGLONG)(gref << PAGE_SHIFT) | page_offset;
    map_register_base->count++;
    break;
  case MAP_TYPE_REMAPPED:
    //KdPrint((__DRIVER_NAME "     MAP_TYPE_REMAPPED (MapTransfer)\n"));
    //KdPrint((__DRIVER_NAME "     Mdl = %p, MapRegisterBase = %p, MdlVa = %p, CurrentVa = %p, Length = %d\n",
    //  mdl, MapRegisterBase, MmGetMdlVirtualAddress(mdl), CurrentVa, *Length));
    mdl_offset = (ULONG)((ULONGLONG)CurrentVa - (ULONGLONG)MmGetMdlVirtualAddress(mdl));
    *Length = min(*Length, PAGE_SIZE);
    map_register->aligned_buffer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);
    ASSERT(map_register->aligned_buffer);
    map_register->unaligned_buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    ASSERT(map_register->unaligned_buffer); /* lazy */
    map_register->unaligned_buffer = (PUCHAR)map_register->unaligned_buffer + mdl_offset;
    map_register->copy_length = *Length;
    if (WriteToDevice)
      memcpy(map_register->aligned_buffer, map_register->unaligned_buffer, map_register->copy_length);
    pfn = (PFN_NUMBER)(MmGetPhysicalAddress(map_register->aligned_buffer).QuadPart >> PAGE_SHIFT);
    //KdPrint((__DRIVER_NAME "     C Requesting Grant Ref\n"));
    gref = (grant_ref_t)GntTbl_GrantAccess(xpdd, 0, (ULONG)pfn, FALSE, INVALID_GRANT_REF);
    //KdPrint((__DRIVER_NAME "     C Got Grant Ref %d\n", gref));
    map_register->logical.QuadPart = (LONGLONG)(gref << PAGE_SHIFT);
    map_register_base->count++;
    break;
  case MAP_TYPE_VIRTUAL:
    //KdPrint((__DRIVER_NAME "     MAP_TYPE_VIRTUAL\n"));
    ptr = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    ASSERT(ptr); /* lazy */
    map_register->logical.QuadPart = (ULONGLONG)ptr;
    map_register_base->count++;
    break;
  default:
    ASSERT(FALSE);
    break;
  }
  
  //KdPrint((__DRIVER_NAME "     logical = %08x:%08x\n", map_register->logical.HighPart, map_register->logical.LowPart));
  //FUNCTION_EXIT();
  return map_register->logical;
}

static ULONG
XenPci_DOP_GetDmaAlignment(
  PDMA_ADAPTER DmaAdapter)
{
  UNREFERENCED_PARAMETER(DmaAdapter);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return 0;
}

static ULONG
XenPci_DOP_ReadDmaCounter(
  PDMA_ADAPTER DmaAdapter)
{
  UNREFERENCED_PARAMETER(DmaAdapter);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return 0;
}

static NTSTATUS
XenPci_DOP_GetScatterGatherList(
  PDMA_ADAPTER DmaAdapter,
  PDEVICE_OBJECT DeviceObject,
  PMDL Mdl,
  PVOID CurrentVa,
  ULONG Length,
  PDRIVER_LIST_CONTROL ExecutionRoutine,
  PVOID Context,
  BOOLEAN WriteToDevice)
{
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Mdl);
  UNREFERENCED_PARAMETER(CurrentVa);
  UNREFERENCED_PARAMETER(Length);
  UNREFERENCED_PARAMETER(ExecutionRoutine);
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(WriteToDevice);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return STATUS_UNSUCCESSFUL;
}

static VOID
XenPci_DOP_PutScatterGatherList(
    IN PDMA_ADAPTER DmaAdapter,
    IN PSCATTER_GATHER_LIST ScatterGather,
    IN BOOLEAN WriteToDevice
    )
{
  xen_dma_adapter_t *xen_dma_adapter;
  PXENPCI_DEVICE_DATA xpdd;
  ULONG i;
  sg_extra_t *sg_extra;

  UNREFERENCED_PARAMETER(WriteToDevice);
  
  //FUNCTION_ENTER();

  xen_dma_adapter = (xen_dma_adapter_t *)DmaAdapter;
  xpdd = GetXpdd(xen_dma_adapter->xppdd->wdf_device_bus_fdo);
  
  sg_extra = (sg_extra_t *)((PUCHAR)ScatterGather + FIELD_OFFSET(SCATTER_GATHER_LIST, Elements) +
    (sizeof(SCATTER_GATHER_ELEMENT)) * ScatterGather->NumberOfElements);

  switch (sg_extra->map_type)
  {
  case MAP_TYPE_REMAPPED:
    for (i = 0; i < ScatterGather->NumberOfElements; i++)
    {
      grant_ref_t gref;
      gref = (grant_ref_t)(ScatterGather->Elements[i].Address.QuadPart >> PAGE_SHIFT);
      GntTbl_EndAccess(xpdd, gref, FALSE);
      ScatterGather->Elements[i].Address.QuadPart = -1;
    }
    if (!WriteToDevice)
      memcpy(sg_extra->unaligned_buffer, sg_extra->aligned_buffer, sg_extra->copy_length);
    ExFreePoolWithTag(sg_extra->aligned_buffer, XENPCI_POOL_TAG);
    break;
  case MAP_TYPE_MDL:
    for (i = 0; i < ScatterGather->NumberOfElements; i++)
    {
      grant_ref_t gref;
      gref = (grant_ref_t)(ScatterGather->Elements[i].Address.QuadPart >> PAGE_SHIFT);
      GntTbl_EndAccess(xpdd, gref, FALSE);
      ScatterGather->Elements[i].Address.QuadPart = -1;
    }
    break;
  case MAP_TYPE_VIRTUAL:
    break;
  }
  //FUNCTION_EXIT();
}

static NTSTATUS
XenPci_DOP_CalculateScatterGatherList(
  PDMA_ADAPTER DmaAdapter,
  PMDL Mdl,
  PVOID CurrentVa,
  ULONG Length,
  PULONG ScatterGatherListSize,
  PULONG NumberOfMapRegisters
  )
{
  ULONG elements;
  PMDL curr_mdl;
  
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(Mdl);
  
  FUNCTION_ENTER();
  
  KdPrint((__DRIVER_NAME "     Mdl = %p\n", Mdl));
  KdPrint((__DRIVER_NAME "     CurrentVa = %p\n", CurrentVa));
  KdPrint((__DRIVER_NAME "     Length = %d\n", Length));
  if (Mdl)
  {
    for (curr_mdl = Mdl, elements = 0; curr_mdl; curr_mdl = curr_mdl->Next)
      elements += ADDRESS_AND_SIZE_TO_SPAN_PAGES(CurrentVa, Length);
  }
  else
  {
    elements = ADDRESS_AND_SIZE_TO_SPAN_PAGES(0, Length) + 1;
  }
  
  *ScatterGatherListSize = FIELD_OFFSET(SCATTER_GATHER_LIST, Elements)
    + sizeof(SCATTER_GATHER_ELEMENT) * elements
    + sizeof(sg_extra_t);
  if (NumberOfMapRegisters)
    *NumberOfMapRegisters = 1;

  KdPrint((__DRIVER_NAME "     ScatterGatherListSize = %d\n", *ScatterGatherListSize));

  FUNCTION_EXIT();
  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_DOP_BuildScatterGatherList(
  IN PDMA_ADAPTER DmaAdapter,
  IN PDEVICE_OBJECT DeviceObject,
  IN PMDL Mdl,
  IN PVOID CurrentVa,
  IN ULONG Length,
  IN PDRIVER_LIST_CONTROL ExecutionRoutine,
  IN PVOID Context,
  IN BOOLEAN WriteToDevice,
  IN PVOID ScatterGatherBuffer,
  IN ULONG ScatterGatherBufferLength)
{
  ULONG i;
  PSCATTER_GATHER_LIST sglist = ScatterGatherBuffer;
  PUCHAR ptr;
  ULONG remaining = Length;
  ULONG total_remaining;
  xen_dma_adapter_t *xen_dma_adapter;
  PXENPCI_DEVICE_DATA xpdd;
  sg_extra_t *sg_extra;
  PMDL curr_mdl;
  ULONG map_type;
  ULONG sg_element;
  ULONG offset;
  PFN_NUMBER pfn;
  grant_ref_t gref;
  //PUCHAR StartVa;
  
  //FUNCTION_ENTER();
  
  if (!ScatterGatherBuffer)
  {
    KdPrint((__DRIVER_NAME "     NULL ScatterGatherBuffer\n"));
    return STATUS_INVALID_PARAMETER;
  }
  ASSERT(MmGetMdlVirtualAddress(Mdl) == CurrentVa);

  xen_dma_adapter = (xen_dma_adapter_t *)DmaAdapter;
  xpdd = GetXpdd(xen_dma_adapter->xppdd->wdf_device_bus_fdo);

  ASSERT(Mdl);
  
  if (xen_dma_adapter->dma_extension)
  {
    if (xen_dma_adapter->dma_extension->need_virtual_address(DeviceObject->CurrentIrp))
    {
      ASSERT(!Mdl->Next); /* can only virtual a single buffer */
      map_type = MAP_TYPE_VIRTUAL;
      sglist->NumberOfElements = 1;
    }
    else
    {
      ULONG alignment = xen_dma_adapter->dma_extension->get_alignment(DeviceObject->CurrentIrp);
      if ((MmGetMdlByteOffset(Mdl) & (alignment - 1)) || (MmGetMdlByteCount(Mdl) & (alignment - 1)))
      {
        ASSERT(!Mdl->Next); /* can only remap a single buffer for now - will need to check all Mdl's in the future */
        map_type = MAP_TYPE_REMAPPED;
        sglist->NumberOfElements = ADDRESS_AND_SIZE_TO_SPAN_PAGES(NULL, Length);
      }
      else
      {
        map_type = MAP_TYPE_MDL;
        for (curr_mdl = Mdl, sglist->NumberOfElements = 0; curr_mdl; curr_mdl = curr_mdl->Next)
          sglist->NumberOfElements += ADDRESS_AND_SIZE_TO_SPAN_PAGES(
            MmGetMdlVirtualAddress(curr_mdl), MmGetMdlByteCount(curr_mdl));
      }
    }
  }
  else
  {
    map_type = MAP_TYPE_MDL;
    for (curr_mdl = Mdl, sglist->NumberOfElements = 0; curr_mdl; curr_mdl = curr_mdl->Next)
      sglist->NumberOfElements += ADDRESS_AND_SIZE_TO_SPAN_PAGES(
        MmGetMdlVirtualAddress(curr_mdl), MmGetMdlByteCount(curr_mdl));
  }
  if (ScatterGatherBufferLength < FIELD_OFFSET(SCATTER_GATHER_LIST, Elements) +
    sizeof(SCATTER_GATHER_ELEMENT) * sglist->NumberOfElements + sizeof(sg_extra_t))
  {
    KdPrint((__DRIVER_NAME "     STATUS_BUFFER_TOO_SMALL (%d < %d)\n", ScatterGatherBufferLength, FIELD_OFFSET(SCATTER_GATHER_LIST, Elements) +
      sizeof(SCATTER_GATHER_ELEMENT) * sglist->NumberOfElements + sizeof(sg_extra_t)));
    return STATUS_BUFFER_TOO_SMALL;
  }
  
  sg_extra = (sg_extra_t *)((PUCHAR)sglist + FIELD_OFFSET(SCATTER_GATHER_LIST, Elements) +
    (sizeof(SCATTER_GATHER_ELEMENT)) * sglist->NumberOfElements);
  
  sg_extra->map_type = map_type;
  switch (map_type)
  {
  case MAP_TYPE_MDL:
    //KdPrint((__DRIVER_NAME "     MAP_TYPE_MDL - %p\n", MmGetMdlVirtualAddress(Mdl)));
    total_remaining = Length;
    for (sg_element = 0, curr_mdl = Mdl; curr_mdl; curr_mdl = curr_mdl->Next)
    {
      remaining = MmGetMdlByteCount(curr_mdl);
      offset = MmGetMdlByteOffset(curr_mdl);
      if (!remaining)
      {
        KdPrint((__DRIVER_NAME "     zero length MDL\n"));
      }
      for (i = 0; i < ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(curr_mdl), MmGetMdlByteCount(curr_mdl)); i++)
      {
//KdPrint((__DRIVER_NAME "     element = %d\n", sg_element));
//KdPrint((__DRIVER_NAME "     remaining = %d\n", remaining));
        pfn = MmGetMdlPfnArray(curr_mdl)[i];
        ASSERT(pfn);
        gref = (grant_ref_t)GntTbl_GrantAccess(xpdd, 0, (ULONG)pfn, FALSE, INVALID_GRANT_REF);
        ASSERT(gref != INVALID_GRANT_REF);
        sglist->Elements[sg_element].Address.QuadPart = (LONGLONG)(gref << PAGE_SHIFT) | offset;
        sglist->Elements[sg_element].Length = min(min(PAGE_SIZE - offset, remaining), total_remaining);
        total_remaining -= sglist->Elements[sg_element].Length;
        remaining -= sglist->Elements[sg_element].Length;
        offset = 0;
        sg_element++;
      }
    }
    break;
  case MAP_TYPE_REMAPPED:
    sg_extra->aligned_buffer = ExAllocatePoolWithTag(NonPagedPool, max(Length, PAGE_SIZE), XENPCI_POOL_TAG);
    if (!sg_extra->aligned_buffer)
    {
      KdPrint((__DRIVER_NAME "     MAP_TYPE_REMAPPED buffer allocation failed - requested va = %p, length = %d\n", MmGetMdlVirtualAddress(Mdl), Length));
      return STATUS_INSUFFICIENT_RESOURCES;
    }
    //KdPrint((__DRIVER_NAME "     MAP_TYPE_REMAPPED - %p -> %p\n", MmGetMdlVirtualAddress(Mdl), sg_extra->aligned_buffer));
    sg_extra->unaligned_buffer = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(sg_extra->unaligned_buffer); /* lazy */
    sg_extra->copy_length = Length;
    if (WriteToDevice)
      memcpy(sg_extra->aligned_buffer, sg_extra->unaligned_buffer, sg_extra->copy_length);
    for (sg_element = 0, remaining = Length; 
      sg_element < ADDRESS_AND_SIZE_TO_SPAN_PAGES(sg_extra->aligned_buffer, Length); sg_element++)
    {
      pfn = (PFN_NUMBER)(MmGetPhysicalAddress((PUCHAR)sg_extra->aligned_buffer + (sg_element << PAGE_SHIFT)).QuadPart >> PAGE_SHIFT);
      ASSERT(pfn);
      gref = (grant_ref_t)GntTbl_GrantAccess(xpdd, 0, (ULONG)pfn, FALSE, INVALID_GRANT_REF);
      ASSERT(gref);
      sglist->Elements[sg_element].Address.QuadPart = (ULONGLONG)gref << PAGE_SHIFT;
      sglist->Elements[sg_element].Length = min(PAGE_SIZE, remaining);
      remaining -= sglist->Elements[sg_element].Length;
    }
    break;
  case MAP_TYPE_VIRTUAL:
    ptr = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(ptr); /* lazy */
    sglist->Elements[0].Address.QuadPart = (ULONGLONG)ptr;
    sglist->Elements[0].Length = Length;
    //KdPrint((__DRIVER_NAME "     MAP_TYPE_VIRTUAL - %08x\n", sglist->Elements[0].Address.LowPart));
    break;
  default:
    KdPrint((__DRIVER_NAME "     map_type = %d\n", map_type));
    break;
  }

  ExecutionRoutine(DeviceObject, DeviceObject->CurrentIrp, ScatterGatherBuffer, Context);

  //FUNCTION_EXIT();
  
  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_DOP_BuildMdlFromScatterGatherList(
  PDMA_ADAPTER DmaAdapter,
  PSCATTER_GATHER_LIST ScatterGather,
  PMDL OriginalMdl,
  PMDL *TargetMdl)
{
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(ScatterGather);
  UNREFERENCED_PARAMETER(OriginalMdl);
  UNREFERENCED_PARAMETER(TargetMdl);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return STATUS_UNSUCCESSFUL;
}

static PDMA_ADAPTER
XenPci_BIS_GetDmaAdapter(PVOID context, PDEVICE_DESCRIPTION device_description, PULONG number_of_map_registers)
{
  xen_dma_adapter_t *xen_dma_adapter;
  PDEVICE_OBJECT curr, prev;
  PDRIVER_OBJECT fdo_driver_object;
  PVOID fdo_driver_extension;
  
  UNREFERENCED_PARAMETER(device_description);
  
  FUNCTION_ENTER();

  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));
  KdPrint((__DRIVER_NAME "     Device Description = %p:\n", device_description));
  KdPrint((__DRIVER_NAME "      Version  = %d\n", device_description->Version));
  KdPrint((__DRIVER_NAME "      Master = %d\n", device_description->Master));
  KdPrint((__DRIVER_NAME "      ScatterGather = %d\n", device_description->ScatterGather));
  KdPrint((__DRIVER_NAME "      DemandMode = %d\n", device_description->DemandMode));
  KdPrint((__DRIVER_NAME "      AutoInitialize = %d\n", device_description->AutoInitialize));
  KdPrint((__DRIVER_NAME "      Dma32BitAddresses = %d\n", device_description->Dma32BitAddresses));
  KdPrint((__DRIVER_NAME "      IgnoreCount = %d\n", device_description->IgnoreCount));
  KdPrint((__DRIVER_NAME "      Dma64BitAddresses = %d\n", device_description->Dma64BitAddresses));
  KdPrint((__DRIVER_NAME "      BusNumber = %d\n", device_description->BusNumber));
  KdPrint((__DRIVER_NAME "      DmaChannel = %d\n", device_description->DmaChannel));
  KdPrint((__DRIVER_NAME "      InterfaceType = %d\n", device_description->InterfaceType));
  KdPrint((__DRIVER_NAME "      DmaWidth = %d\n", device_description->DmaWidth));
  KdPrint((__DRIVER_NAME "      DmaSpeed = %d\n", device_description->DmaSpeed));
  KdPrint((__DRIVER_NAME "      MaximumLength = %d\n", device_description->MaximumLength));
  KdPrint((__DRIVER_NAME "      DmaPort = %d\n", device_description->DmaPort));
  
  if (!device_description->Master)
    return NULL;
/*
we have to allocate PAGE_SIZE bytes here because Windows thinks this is
actually an ADAPTER_OBJECT, and then the verifier crashes because
Windows accessed beyond the end of the structure :(
*/
  xen_dma_adapter = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);
  ASSERT(xen_dma_adapter);
  RtlZeroMemory(xen_dma_adapter, PAGE_SIZE);
  
  switch(device_description->Version)
  {
  case DEVICE_DESCRIPTION_VERSION1:
    xen_dma_adapter->adapter_object.DmaHeader.Version = 1;
    break;
  case DEVICE_DESCRIPTION_VERSION: /* ignore what the docs say here - DEVICE_DESCRIPTION_VERSION appears to mean the latest version */
  case DEVICE_DESCRIPTION_VERSION2:
    xen_dma_adapter->adapter_object.DmaHeader.Version = 2;
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unsupported device description version %d\n", device_description->Version));
    ExFreePoolWithTag(xen_dma_adapter, XENPCI_POOL_TAG);
    return NULL;
  }
    

  xen_dma_adapter->adapter_object.DmaHeader.Size = sizeof(X_ADAPTER_OBJECT); //xen_dma_adapter_t);
  xen_dma_adapter->adapter_object.MasterAdapter = NULL;
  xen_dma_adapter->adapter_object.MapRegistersPerChannel = 1024;
  xen_dma_adapter->adapter_object.AdapterBaseVa = NULL;
  xen_dma_adapter->adapter_object.MapRegisterBase = NULL;
  xen_dma_adapter->adapter_object.NumberOfMapRegisters = 0;
  xen_dma_adapter->adapter_object.CommittedMapRegisters = 0;
  xen_dma_adapter->adapter_object.CurrentWcb = NULL;
  KeInitializeDeviceQueue(&xen_dma_adapter->adapter_object.ChannelWaitQueue);
  xen_dma_adapter->adapter_object.RegisterWaitQueue = NULL;
  InitializeListHead(&xen_dma_adapter->adapter_object.AdapterQueue);
  KeInitializeSpinLock(&xen_dma_adapter->adapter_object.SpinLock);
  xen_dma_adapter->adapter_object.MapRegisters = NULL;
  xen_dma_adapter->adapter_object.PagePort = NULL;
  xen_dma_adapter->adapter_object.ChannelNumber = 0xff;
  xen_dma_adapter->adapter_object.AdapterNumber = 0;
  xen_dma_adapter->adapter_object.DmaPortAddress = 0;
  xen_dma_adapter->adapter_object.AdapterMode = 0;
  xen_dma_adapter->adapter_object.NeedsMapRegisters = FALSE; /* when true this causes a crash in the crash dump path */
  xen_dma_adapter->adapter_object.MasterDevice = 1;
  xen_dma_adapter->adapter_object.Width16Bits = 0;
  xen_dma_adapter->adapter_object.ScatterGather = device_description->ScatterGather;
  xen_dma_adapter->adapter_object.IgnoreCount = device_description->IgnoreCount;
  xen_dma_adapter->adapter_object.Dma32BitAddresses = device_description->Dma32BitAddresses;
  xen_dma_adapter->adapter_object.Dma64BitAddresses = device_description->Dma64BitAddresses;
  InitializeListHead(&xen_dma_adapter->adapter_object.AdapterList);  
  
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations = ExAllocatePoolWithTag(NonPagedPool, sizeof(DMA_OPERATIONS), XENPCI_POOL_TAG);
  ASSERT(xen_dma_adapter->adapter_object.DmaHeader.DmaOperations);
  if (xen_dma_adapter->adapter_object.DmaHeader.Version == 1)
  {
    xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->Size = FIELD_OFFSET(DMA_OPERATIONS, CalculateScatterGatherList);
  }
  else
  {
    xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->Size = sizeof(DMA_OPERATIONS);
  }
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->PutDmaAdapter = XenPci_DOP_PutDmaAdapter;
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->AllocateCommonBuffer = XenPci_DOP_AllocateCommonBuffer;
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->FreeCommonBuffer = XenPci_DOP_FreeCommonBuffer;
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->AllocateAdapterChannel = XenPci_DOP_AllocateAdapterChannel;
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->FlushAdapterBuffers = XenPci_DOP_FlushAdapterBuffers;
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->FreeAdapterChannel = XenPci_DOP_FreeAdapterChannel;
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->FreeMapRegisters = XenPci_DOP_FreeMapRegisters;
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->MapTransfer = XenPci_DOP_MapTransfer;
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->GetDmaAlignment = XenPci_DOP_GetDmaAlignment;
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->ReadDmaCounter = XenPci_DOP_ReadDmaCounter;
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->GetScatterGatherList = XenPci_DOP_GetScatterGatherList;
  xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->PutScatterGatherList = XenPci_DOP_PutScatterGatherList;
  if (xen_dma_adapter->adapter_object.DmaHeader.Version == 2)
  {
    xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->CalculateScatterGatherList = XenPci_DOP_CalculateScatterGatherList;
    xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->BuildScatterGatherList = XenPci_DOP_BuildScatterGatherList;
    xen_dma_adapter->adapter_object.DmaHeader.DmaOperations->BuildMdlFromScatterGatherList = XenPci_DOP_BuildMdlFromScatterGatherList;
  }
  xen_dma_adapter->xppdd = context;
  xen_dma_adapter->dma_extension = NULL;

  KdPrint((__DRIVER_NAME "     About to call IoGetAttachedDeviceReference\n"));
  curr = IoGetAttachedDeviceReference(WdfDeviceWdmGetDeviceObject(xen_dma_adapter->xppdd->wdf_device));
  KdPrint((__DRIVER_NAME "     Before start of loop - curr = %p\n", curr));
  while (curr != NULL)
  {
    fdo_driver_object = curr->DriverObject;
    if (fdo_driver_object)
    {
      ObReferenceObject(fdo_driver_object);
      fdo_driver_extension = IoGetDriverObjectExtension(fdo_driver_object, UlongToPtr(XEN_DMA_DRIVER_EXTENSION_MAGIC));
      if (fdo_driver_extension)
      {
        xen_dma_adapter->dma_extension_driver = fdo_driver_object; /* so we can dereference it on putdmaadapter */
        xen_dma_adapter->dma_extension = (dma_driver_extension_t *)fdo_driver_extension;
        ObDereferenceObject(curr);
        break;
      }
      else
      {
        ObDereferenceObject(fdo_driver_object);
      }
    }
    prev = curr;
    curr = IoGetLowerDeviceObject(curr);
    ObDereferenceObject(prev);
  }
  KdPrint((__DRIVER_NAME "     End of loop\n"));

  *number_of_map_registers = 1024; /* why not... */

  FUNCTION_EXIT();

  return &xen_dma_adapter->adapter_object.DmaHeader;
}

static ULONG
XenPci_BIS_SetBusData(PVOID context, ULONG data_type, PVOID buffer, ULONG offset, ULONG length)
{
  UNREFERENCED_PARAMETER(context);
  UNREFERENCED_PARAMETER(data_type);
  UNREFERENCED_PARAMETER(buffer);
  UNREFERENCED_PARAMETER(offset);
  UNREFERENCED_PARAMETER(length);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return 0;
}

static ULONG
XenPci_BIS_GetBusData(PVOID context, ULONG data_type, PVOID buffer, ULONG offset, ULONG length)
{
  UNREFERENCED_PARAMETER(context);
  UNREFERENCED_PARAMETER(data_type);
  UNREFERENCED_PARAMETER(buffer);
  UNREFERENCED_PARAMETER(offset);
  UNREFERENCED_PARAMETER(length);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return 0;
}

/*
Called at PASSIVE_LEVEL(?)
Called during restore
*/

static ULONG
XenPci_ReadBackendState(PXENPCI_PDO_DEVICE_DATA xppdd)
{
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
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
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  ULONG new_backend_state;

#if !DBG
  UNREFERENCED_PARAMETER(path);
#endif
  
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
    if (xppdd->frontend_state == XenbusStateConnected)
    {
      KdPrint((__DRIVER_NAME "     Requesting eject\n"));
      WdfPdoRequestEject(device);
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

static NTSTATUS
XenPci_GetBackendAndAddWatch(WDFDEVICE device)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
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
  XenBus_AddWatch(xpdd, XBT_NIL, path, XenPci_BackEndStateHandler, device);
  
  return STATUS_SUCCESS;
}

static NTSTATUS
XenConfig_InitConfigPage(WDFDEVICE device)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  //PXENCONFIG_DEVICE_DATA xcdd = (PXENCONFIG_DEVICE_DATA)device_object->DeviceExtension;
  //PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  //PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  PUCHAR ptr;
  PDEVICE_OBJECT curr, prev;
  PDRIVER_OBJECT fdo_driver_object;
  PUCHAR fdo_driver_extension;
  
  FUNCTION_ENTER();
  
  ptr = MmGetMdlVirtualAddress(xppdd->config_page_mdl);
  curr = IoGetAttachedDeviceReference(WdfDeviceWdmGetDeviceObject(device));
  //curr = WdfDeviceWdmGetAttachedDevice(device);
  while (curr != NULL)
  {
    fdo_driver_object = curr->DriverObject;
    KdPrint((__DRIVER_NAME "     fdo_driver_object = %p\n", fdo_driver_object));
    if (fdo_driver_object)
    {
      fdo_driver_extension = IoGetDriverObjectExtension(fdo_driver_object, UlongToPtr(XEN_INIT_DRIVER_EXTENSION_MAGIC));
      KdPrint((__DRIVER_NAME "     fdo_driver_extension = %p\n", fdo_driver_extension));
      if (fdo_driver_extension)
      {
        memcpy(ptr, fdo_driver_extension, PAGE_SIZE);
        ObDereferenceObject(curr);
        break;
      }
    }
    prev = curr;
    curr = IoGetLowerDeviceObject(curr);
    ObDereferenceObject(prev);
  }
  
  FUNCTION_EXIT();
  
  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_EvtChn_Bind(PVOID context, evtchn_port_t Port, PXEN_EVTCHN_SERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  return EvtChn_Bind(xpdd, Port, ServiceRoutine, ServiceContext);
}

static NTSTATUS
XenPci_EvtChn_BindDpc(PVOID context, evtchn_port_t Port, PXEN_EVTCHN_SERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  return EvtChn_BindDpc(xpdd, Port, ServiceRoutine, ServiceContext);
}

static NTSTATUS
XenPci_EvtChn_Unbind(PVOID context, evtchn_port_t Port)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  return EvtChn_Unbind(xpdd, Port);
}

static NTSTATUS
XenPci_EvtChn_Mask(PVOID context, evtchn_port_t Port)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  return EvtChn_Mask(xpdd, Port);
}

static NTSTATUS
XenPci_EvtChn_Unmask(PVOID context, evtchn_port_t Port)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  return EvtChn_Unmask(xpdd, Port);
}

static NTSTATUS
XenPci_EvtChn_Notify(PVOID context, evtchn_port_t Port)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  return EvtChn_Notify(xpdd, Port);
}

static BOOLEAN
XenPci_EvtChn_AckEvent(PVOID context, evtchn_port_t port)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  return EvtChn_AckEvent(xpdd, port);
}

typedef struct {
  PXEN_EVTCHN_SYNC_ROUTINE sync_routine;
  PVOID sync_context;
} sync_context_t;

static BOOLEAN
XenPci_EvtChn_Sync_Routine(WDFINTERRUPT interrupt, WDFCONTEXT context)
{
  sync_context_t *wdf_sync_context = context;
  UNREFERENCED_PARAMETER(interrupt);
  return wdf_sync_context->sync_routine(wdf_sync_context->sync_context);
}

static BOOLEAN
XenPci_EvtChn_Sync(PVOID context, PXEN_EVTCHN_SYNC_ROUTINE sync_routine, PVOID sync_context)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  sync_context_t wdf_sync_context;
  
  wdf_sync_context.sync_routine = sync_routine;
  wdf_sync_context.sync_context = sync_context;
  
  return WdfInterruptSynchronize(xpdd->interrupt, XenPci_EvtChn_Sync_Routine, &wdf_sync_context);
}

static grant_ref_t
XenPci_GntTbl_GrantAccess(PVOID context, domid_t domid, uint32_t frame, int readonly, grant_ref_t ref)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  return GntTbl_GrantAccess(xpdd, domid, frame, readonly, ref);
}

static BOOLEAN
XenPci_GntTbl_EndAccess(PVOID context, grant_ref_t ref, BOOLEAN keepref)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  return GntTbl_EndAccess(xpdd, ref, keepref);
}

static VOID
XenPci_GntTbl_PutRef(PVOID context, grant_ref_t ref)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  GntTbl_PutRef(xpdd, ref);
}

static grant_ref_t
XenPci_GntTbl_GetRef(PVOID context)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  return GntTbl_GetRef(xpdd);
}

PCHAR
XenPci_XenBus_Read(PVOID context, xenbus_transaction_t xbt, char *path, char **value)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  return XenBus_Read(xpdd, xbt, path, value);
}

PCHAR
XenPci_XenBus_Write(PVOID context, xenbus_transaction_t xbt, char *path, char *value)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  return XenBus_Write(xpdd, xbt, path, value);
}

PCHAR
XenPci_XenBus_Printf(PVOID context, xenbus_transaction_t xbt, char *path, char *fmt, ...)
{
  //PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  //PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  //return XenBus_Printf(xpdd, xbt, path, value);
  UNREFERENCED_PARAMETER(context);
  UNREFERENCED_PARAMETER(xbt);
  UNREFERENCED_PARAMETER(path);
  UNREFERENCED_PARAMETER(fmt);
  return NULL;
}

PCHAR
XenPci_XenBus_StartTransaction(PVOID context, xenbus_transaction_t *xbt)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  return XenBus_StartTransaction(xpdd, xbt);
}

PCHAR
XenPci_XenBus_EndTransaction(PVOID context, xenbus_transaction_t xbt, int abort, int *retry)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  return XenBus_EndTransaction(xpdd, xbt, abort, retry);
}

PCHAR
XenPci_XenBus_List(PVOID context, xenbus_transaction_t xbt, char *prefix, char ***contents)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  return XenBus_List(xpdd, xbt, prefix, contents);
}

PCHAR
XenPci_XenBus_AddWatch(PVOID context, xenbus_transaction_t xbt, char *path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  PCHAR retval;
  
  FUNCTION_ENTER();
  retval = XenBus_AddWatch(xpdd, xbt, path, ServiceRoutine, ServiceContext);
  if (retval == NULL)
  {
    KdPrint((__DRIVER_NAME "     XenPci_XenBus_AddWatch - %s = NULL\n", path));
  }
  else
  {
    KdPrint((__DRIVER_NAME "     XenPci_XenBus_AddWatch - %s = %s\n", path, retval));
  }
  FUNCTION_EXIT();
  return retval;
}

PCHAR
XenPci_XenBus_RemWatch(PVOID context, xenbus_transaction_t xbt, char *path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  return XenBus_RemWatch(xpdd, xbt, path, ServiceRoutine, ServiceContext);
}

/*
Called at PASSIVE_LEVEL
Called during restore
*/

static NTSTATUS
XenPci_ChangeFrontendState(WDFDEVICE device, ULONG frontend_state_set, ULONG backend_state_response, ULONG maximum_wait_ms)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  LARGE_INTEGER timeout;
  ULONG remaining;
  ULONG thiswait;
  char path[128];
  
  //KdPrint((__DRIVER_NAME " --> " __FUNCTION__ "\n"));
  
  xppdd->frontend_state = frontend_state_set;

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

static NTSTATUS
XenPci_XenConfigDevice(WDFDEVICE device);

static NTSTATUS
XenPci_XenShutdownDevice(PVOID context)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  PUCHAR in_ptr;
  ULONG i;
  UCHAR type;
  PVOID setting;
  PVOID value;
  PVOID value2;

  FUNCTION_ENTER();

  if (xppdd->backend_state == XenbusStateConnected)
  {
    XenPci_ChangeFrontendState(device, XenbusStateClosing, XenbusStateClosing, 30000);
    if (xppdd->backend_state == XenbusStateClosing)
      XenPci_ChangeFrontendState(device, XenbusStateClosed, XenbusStateClosed, 30000);
    if (xppdd->backend_state == XenbusStateClosed)
      XenPci_ChangeFrontendState(device, XenbusStateInitialising, XenbusStateInitWait, 30000);
  }
  else
  {
    if (xppdd->backend_state == XenbusStateClosing)
      XenPci_ChangeFrontendState(device, XenbusStateClosed, XenbusStateClosed, 30000);
  }

  if (xppdd->assigned_resources_start != NULL)
  {
    ADD_XEN_INIT_RSP(&xppdd->assigned_resources_ptr, XEN_INIT_TYPE_END, NULL, NULL, NULL);
    in_ptr = xppdd->assigned_resources_start;
    while((type = GET_XEN_INIT_RSP(&in_ptr, &setting, &value, &value2)) != XEN_INIT_TYPE_END)
    {
      switch (type)
      {
      case XEN_INIT_TYPE_RING: /* frontend ring */
        FreePages(value);
        break;
      case XEN_INIT_TYPE_EVENT_CHANNEL: /* frontend event channel */
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

struct dummy_sring {
    RING_IDX req_prod, req_event;
    RING_IDX rsp_prod, rsp_event;
    uint8_t  pad[48];
};

static NTSTATUS
XenPci_XenConfigDeviceSpecifyBuffers(WDFDEVICE device, PUCHAR src, PUCHAR dst)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  NTSTATUS status = STATUS_SUCCESS;
  ULONG i;
  char path[128];
  PCHAR setting, value;
  PCHAR res;
  PVOID address;
  UCHAR type;
  PUCHAR in_ptr;
  PUCHAR out_ptr;
  XENPCI_VECTORS vectors;
  ULONG event_channel;
  ULONG run_type = 0;
  PMDL ring;
  grant_ref_t gref;
  BOOLEAN done_xenbus_init = FALSE;
  PVOID value2;
  BOOLEAN active = TRUE;
  BOOLEAN dont_config = FALSE;
 
  FUNCTION_ENTER();

  in_ptr = src;
  out_ptr = dst;
  
  // always add vectors
  vectors.magic = XEN_DATA_MAGIC;
  vectors.length = sizeof(XENPCI_VECTORS);
  vectors.context = device;
  vectors.EvtChn_Bind = XenPci_EvtChn_Bind;
  vectors.EvtChn_BindDpc = XenPci_EvtChn_BindDpc;
  vectors.EvtChn_Unbind = XenPci_EvtChn_Unbind;
  vectors.EvtChn_Mask = XenPci_EvtChn_Mask;
  vectors.EvtChn_Unmask = XenPci_EvtChn_Unmask;
  vectors.EvtChn_Notify = XenPci_EvtChn_Notify;
  vectors.EvtChn_AckEvent = XenPci_EvtChn_AckEvent;
  vectors.EvtChn_Sync = XenPci_EvtChn_Sync;
  vectors.GntTbl_GetRef = XenPci_GntTbl_GetRef;
  vectors.GntTbl_PutRef = XenPci_GntTbl_PutRef;
  vectors.GntTbl_GrantAccess = XenPci_GntTbl_GrantAccess;
  vectors.GntTbl_EndAccess = XenPci_GntTbl_EndAccess;
  vectors.XenPci_XenConfigDevice = XenPci_XenConfigDevice;
  vectors.XenPci_XenShutdownDevice = XenPci_XenShutdownDevice;
  strncpy(vectors.path, xppdd->path, 128);
  strncpy(vectors.backend_path, xppdd->backend_path, 128);
  //vectors.pdo_event_channel = xpdd->pdo_event_channel;
  vectors.XenBus_Read = XenPci_XenBus_Read;
  vectors.XenBus_Write = XenPci_XenBus_Write;
  vectors.XenBus_Printf = XenPci_XenBus_Printf;
  vectors.XenBus_StartTransaction = XenPci_XenBus_StartTransaction;
  vectors.XenBus_EndTransaction = XenPci_XenBus_EndTransaction;
  vectors.XenBus_List = XenPci_XenBus_List;
  vectors.XenBus_AddWatch = XenPci_XenBus_AddWatch;
  vectors.XenBus_RemWatch = XenPci_XenBus_RemWatch;

  ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_QEMU_PROTOCOL_VERSION, NULL, UlongToPtr(qemu_protocol_version), NULL);
  
  ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_VECTORS, NULL, &vectors, NULL);
  ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_STATE_PTR, NULL, &xppdd->device_state, NULL);


  if (!qemu_filtered)
    active = FALSE;

  while((type = GET_XEN_INIT_REQ(&in_ptr, (PVOID)&setting, (PVOID)&value, (PVOID)&value2)) != XEN_INIT_TYPE_END)
  {
    BOOLEAN condition;
    PCHAR xb_value;
    switch (type)
    {
    case XEN_INIT_TYPE_MATCH_FRONT:
    case XEN_INIT_TYPE_MATCH_BACK:
      if (type == XEN_INIT_TYPE_MATCH_FRONT)
      {
        RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->path, setting);
      }
      else
      {
        RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->backend_path, setting);
      }
      KdPrint((__DRIVER_NAME "     testing path = %s\n", path));
      res = XenBus_Read(xpdd, XBT_NIL, path, &xb_value);
      if (res)
      {
        KdPrint((__DRIVER_NAME "     read failed (%s)\n", res));
        XenPci_FreeMem(res);
      }
      else
      {
        KdPrint((__DRIVER_NAME "     testing %s vs %s\n", xb_value, value));
        if (PtrToUlong(value2) & XEN_INIT_MATCH_TYPE_IF_MATCH)
          condition = (strcmp(xb_value, value) == 0)?TRUE:FALSE;
        else
          condition = (strcmp(xb_value, value) != 0)?TRUE:FALSE;
        KdPrint((__DRIVER_NAME "     condition = %d\n", condition));
  
        if ((PtrToUlong(value2) & XEN_INIT_MATCH_TYPE_ONLY_IF_QEMU_HIDE) && qemu_protocol_version && condition)
          condition = FALSE;
          
        if (condition)
        {
          if (PtrToUlong(value2) & XEN_INIT_MATCH_TYPE_SET_INACTIVE)
          {
            active = FALSE;
            KdPrint((__DRIVER_NAME "     set inactive\n"));
          }
          if (PtrToUlong(value2) & XEN_INIT_MATCH_TYPE_DONT_CONFIG)
          {
            dont_config = TRUE;
            KdPrint((__DRIVER_NAME "     set inactive with dont config\n"));
          }
        }
        XenPci_FreeMem(xb_value);
      }
      break;
    }
  }
  if (dont_config)
  {
    ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_END, NULL, NULL, NULL);
    FUNCTION_EXIT();
    return status;
  }
  
  // first pass, possibly before state == Connected
  in_ptr = src;
  while((type = GET_XEN_INIT_REQ(&in_ptr, (PVOID)&setting, (PVOID)&value, (PVOID)&value2)) != XEN_INIT_TYPE_END)
  {
  
    if (!done_xenbus_init)
    {
      if (XenPci_ChangeFrontendState(device, XenbusStateInitialising, XenbusStateInitWait, 2000) != STATUS_SUCCESS)
      {
        status = STATUS_UNSUCCESSFUL;
        goto error;
      }
      done_xenbus_init = TRUE;
    }
    
    ADD_XEN_INIT_REQ(&xppdd->requested_resources_ptr, type, setting, value, value2);

    switch (type)
    {
    case XEN_INIT_TYPE_RUN:
      run_type++;
      break;
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
          xpdd, 0, (ULONG)*MmGetMdlPfnArray(ring), FALSE, INVALID_GRANT_REF)) != INVALID_GRANT_REF)
        {
          RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->path, setting);
          XenBus_Printf(xpdd, XBT_NIL, path, "%d", gref);
          ADD_XEN_INIT_RSP(&out_ptr, type, setting, address, NULL);
          ADD_XEN_INIT_RSP(&xppdd->assigned_resources_ptr, type, setting, ring, NULL);
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
        ADD_XEN_INIT_RSP(&out_ptr, type, setting, UlongToPtr(event_channel), NULL);
        ADD_XEN_INIT_RSP(&xppdd->assigned_resources_ptr, type, setting, UlongToPtr(event_channel), NULL);
        if (type == XEN_INIT_TYPE_EVENT_CHANNEL_IRQ)
        {
          EvtChn_BindIrq(xpdd, event_channel, xppdd->irq_vector, path);
        }
        else
        {
          #pragma warning(suppress:4055)
          EvtChn_Bind(xpdd, event_channel, (PXEN_EVTCHN_SERVICE_ROUTINE)value, value2);
        }
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
  // If XEN_INIT_TYPE_RUN was specified more than once then we skip XenbusStateInitialised here and go straight to XenbusStateConnected at the end
  if (run_type == 1)
  {
    if (XenPci_ChangeFrontendState(device, XenbusStateInitialised, XenbusStateConnected, 2000) != STATUS_SUCCESS)
    {
      status = STATUS_UNSUCCESSFUL;
      goto error;
    }
  }

  // second pass, possibly after state == Connected
  in_ptr = src;
  while((type = GET_XEN_INIT_REQ(&in_ptr, (PVOID)&setting, (PVOID)&value, (PVOID)&value2)) != XEN_INIT_TYPE_END)
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
        ADD_XEN_INIT_RSP(&out_ptr, type, setting, NULL, NULL);
      }
      else
      {
        //KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = %s\n", setting, value));
        ADD_XEN_INIT_RSP(&out_ptr, type, setting, value, value2);
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
        gref = GntTbl_GetRef(xpdd);
        __ADD_XEN_INIT_ULONG(&out_ptr, gref);
        __ADD_XEN_INIT_ULONG(&xppdd->assigned_resources_ptr, gref);
      }
      break;
    }
  }
  if (active)
  {
    ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_ACTIVE, NULL, NULL, NULL);
  }
  ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_END, NULL, NULL, NULL);

  if (run_type)
  {
    if (XenPci_ChangeFrontendState(device, XenbusStateConnected, XenbusStateConnected, 2000) != STATUS_SUCCESS)
    {
      status = STATUS_UNSUCCESSFUL;
      goto error;
    }
  }
  FUNCTION_EXIT();
  return status;

error:
  XenPci_ChangeFrontendState(device, XenbusStateInitialising, XenbusStateInitWait, 2000);
  FUNCTION_EXIT_STATUS(status);
  return status;
}

static NTSTATUS
XenPci_XenConfigDevice(WDFDEVICE device)
{
  NTSTATUS status;
  PUCHAR src, dst;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);

  src = ExAllocatePoolWithTag(NonPagedPool, xppdd->config_page_length, XENPCI_POOL_TAG);
  dst = MmMapIoSpace(xppdd->config_page_phys, xppdd->config_page_length, MmNonCached);
  memcpy(src, dst, xppdd->config_page_length);
  
  status = XenPci_XenConfigDeviceSpecifyBuffers(device, src, dst);

  MmUnmapIoSpace(dst, xppdd->config_page_length);
  ExFreePoolWithTag(src, XENPCI_POOL_TAG);
  
  return status;
}

static NTSTATUS
XenPciPdo_EvtDeviceWdmIrpPreprocess_START_DEVICE(WDFDEVICE device, PIRP irp)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  PIO_STACK_LOCATION stack;
  PCM_PARTIAL_RESOURCE_LIST prl;
  PCM_PARTIAL_RESOURCE_DESCRIPTOR prd;
  ULONG i;
  //char path[128];
  //PMDL mdl;
 
  FUNCTION_ENTER();
  KdPrint((__DRIVER_NAME "     %s\n", xppdd->path));

  stack = IoGetCurrentIrpStackLocation(irp);

  prl = &stack->Parameters.StartDevice.AllocatedResources->List[0].PartialResourceList;
  for (i = 0; i < prl->Count; i++)
  {
    prd = & prl->PartialDescriptors[i];
    switch (prd->Type)
    {
    case CmResourceTypeMemory:
      if (prd->u.Memory.Start.QuadPart == xpdd->platform_mmio_addr.QuadPart && prd->u.Memory.Length == 0)
      {
        prd->u.Memory.Start.QuadPart = MmGetMdlPfnArray(xppdd->config_page_mdl)[0] << PAGE_SHIFT;
        prd->u.Memory.Length = MmGetMdlByteCount(xppdd->config_page_mdl);
      }
      else if (prd->u.Memory.Start.QuadPart == xpdd->platform_mmio_addr.QuadPart + 1 && prd->u.Memory.Length == 0)
      {
        RtlZeroMemory(prd, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
        prd->Type = CmResourceTypeInterrupt;
        prd->ShareDisposition = CmResourceShareShared;
        prd->Flags = (xpdd->irq_mode == Latched)?CM_RESOURCE_INTERRUPT_LATCHED:CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
        prd->u.Interrupt.Level = xpdd->irq_number;
        prd->u.Interrupt.Vector = xpdd->irq_number;
        prd->u.Interrupt.Affinity = (KAFFINITY)-1;
        xppdd->irq_number = xpdd->irq_number;
      }
      break;
    }
  }

  prl = &stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList;
  for (i = 0; i < prl->Count; i++)
  {
    prd = & prl->PartialDescriptors[i];
    switch (prd->Type)
    {
    case CmResourceTypeMemory:
      KdPrint((__DRIVER_NAME "     CmResourceTypeMemory (%d)\n", i));
      KdPrint((__DRIVER_NAME "     Start = %08x, Length = %d\n", prd->u.Memory.Start.LowPart, prd->u.Memory.Length));
      if (prd->u.Memory.Start.QuadPart == xpdd->platform_mmio_addr.QuadPart)
      {
        if (prd->u.Memory.Length == 0)
        {
          KdPrint((__DRIVER_NAME "     pfn[0] = %08x\n", (ULONG)MmGetMdlPfnArray(xppdd->config_page_mdl)[0]));
          prd->u.Memory.Start.QuadPart = (ULONGLONG)MmGetMdlPfnArray(xppdd->config_page_mdl)[0] << PAGE_SHIFT;
          prd->u.Memory.Length = MmGetMdlByteCount(xppdd->config_page_mdl);
          KdPrint((__DRIVER_NAME "     New Start = %08x%08x, Length = %d\n", prd->u.Memory.Start.HighPart, prd->u.Memory.Start.LowPart, prd->u.Memory.Length));
        }
        xppdd->config_page_phys = prd->u.Memory.Start;
        xppdd->config_page_length = prd->u.Memory.Length;
        xppdd->requested_resources_start = xppdd->requested_resources_ptr = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);
        xppdd->assigned_resources_start = xppdd->assigned_resources_ptr = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);
        
#if 0
        status = XenPci_XenConfigDevice(device);
        if (!NT_SUCCESS(status))
        {
          RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
          XenBus_RemWatch(xpdd, XBT_NIL, path, XenPci_BackEndStateHandler, device);
          FUNCTION_ERROR_EXIT();
          return status;
        }
#endif
      }
      else if (prd->u.Memory.Start.QuadPart == xpdd->platform_mmio_addr.QuadPart + 1 && prd->u.Memory.Length == 0)
      {
        RtlZeroMemory(prd, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
        prd->Type = CmResourceTypeInterrupt;
        prd->ShareDisposition = CmResourceShareShared;
        prd->Flags = (xpdd->irq_mode == Latched)?CM_RESOURCE_INTERRUPT_LATCHED:CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
        prd->u.Interrupt.Level = xpdd->irq_level;
        prd->u.Interrupt.Vector = xpdd->irq_vector;
        prd->u.Interrupt.Affinity = (KAFFINITY)-1;
        xppdd->irq_vector = xpdd->irq_vector;
        xppdd->irq_level = xpdd->irq_level;
      }
      break;
    }
  }

  IoSkipCurrentIrpStackLocation(irp);
  
  FUNCTION_EXIT();

  return WdfDeviceWdmDispatchPreprocessedIrp(device, irp);
}

#if 0
static NTSTATUS
XenPciPdo_EvtDeviceResourcesQuery(WDFDEVICE device, WDFCMRESLIST resources)
{
}
#endif

static NTSTATUS
XenPciPdo_EvtDeviceResourceRequirementsQuery(WDFDEVICE device, WDFIORESREQLIST requirements_list)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  WDFIORESLIST res_list;
  IO_RESOURCE_DESCRIPTOR ird;

  //FUNCTION_ENTER();
  
  WdfIoResourceRequirementsListSetInterfaceType(requirements_list, PNPBus);
  
  WdfIoResourceListCreate(requirements_list, WDF_NO_OBJECT_ATTRIBUTES, &res_list);
  ird.Option = 0;
  ird.Type = CmResourceTypeMemory;
  ird.ShareDisposition = CmResourceShareShared;
  ird.Flags = CM_RESOURCE_MEMORY_READ_WRITE | CM_RESOURCE_MEMORY_CACHEABLE;
  ird.u.Memory.MinimumAddress.QuadPart = xpdd->platform_mmio_addr.QuadPart;
  ird.u.Memory.MaximumAddress.QuadPart = xpdd->platform_mmio_addr.QuadPart;
  ird.u.Memory.Length = 0;
  ird.u.Memory.Alignment = 1; //PAGE_SIZE;
  WdfIoResourceListAppendDescriptor(res_list, &ird);
  
  ird.Option = 0;
  ird.Type = CmResourceTypeMemory;
  ird.ShareDisposition = CmResourceShareShared;
  ird.Flags = CM_RESOURCE_MEMORY_READ_WRITE | CM_RESOURCE_MEMORY_CACHEABLE;
  ird.u.Memory.MinimumAddress.QuadPart = xpdd->platform_mmio_addr.QuadPart + 1;
  ird.u.Memory.MaximumAddress.QuadPart = xpdd->platform_mmio_addr.QuadPart + 1;
  ird.u.Memory.Length = 0;
  ird.u.Memory.Alignment = 1; //PAGE_SIZE;
  WdfIoResourceListAppendDescriptor(res_list, &ird);
  
  WdfIoResourceRequirementsListAppendIoResList(requirements_list, res_list);

  //FUNCTION_EXIT();
  
  return STATUS_SUCCESS;
}

NTSTATUS
XenPciPdo_EvtDeviceD0Entry(WDFDEVICE device, WDF_POWER_DEVICE_STATE previous_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  CHAR path[128];
  
  FUNCTION_ENTER();

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
  
  if (previous_state == WdfPowerDevicePrepareForHibernation
      || (previous_state == WdfPowerDeviceD3 && xppdd->hiber_usage_kludge))
  {
    KdPrint((__DRIVER_NAME "     starting up from hibernation\n"));
  }
  else
  {
  }

  XenConfig_InitConfigPage(device);

  status = XenPci_GetBackendAndAddWatch(device);
  if (!NT_SUCCESS(status))
  {
    WdfDeviceSetFailed(device, WdfDeviceFailedNoRestart);
    FUNCTION_ERROR_EXIT();
    return status;
  }
  status = XenPci_XenConfigDevice(device);
  if (!NT_SUCCESS(status))
  {
    RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
    XenBus_RemWatch(xpdd, XBT_NIL, path, XenPci_BackEndStateHandler, device);
    WdfDeviceSetFailed(device, WdfDeviceFailedNoRestart);
    FUNCTION_ERROR_EXIT();
    return status;
  }

  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenPciPdo_EvtDeviceD0Exit(WDFDEVICE device, WDF_POWER_DEVICE_STATE target_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  char path[128];
  
  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(target_state);
  
  FUNCTION_ENTER();

  KdPrint((__DRIVER_NAME "     path = %s\n", xppdd->path));

  
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
  
  if (target_state == WdfPowerDevicePrepareForHibernation
      || (target_state == WdfPowerDeviceD3 && xppdd->hiber_usage_kludge))
  {
    KdPrint((__DRIVER_NAME "     not powering down as we are hibernating\n"));
  }
  else
  {
    status = XenPci_XenShutdownDevice(device);
    /* Remove watch on backend state */
    RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
    XenBus_RemWatch(xpdd, XBT_NIL, path, XenPci_BackEndStateHandler, device);
  }
  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenPciPdo_EvtDevicePrepareHardware(WDFDEVICE device, WDFCMRESLIST resources_raw, WDFCMRESLIST resources_translated)
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(resources_raw);
  UNREFERENCED_PARAMETER(resources_translated);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenPciPdo_EvtDeviceReleaseHardware(WDFDEVICE device, WDFCMRESLIST resources_translated)
{
  NTSTATUS status = STATUS_SUCCESS;
  
  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(resources_translated);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  
  return status;
}

static VOID
XenPciPdo_EvtDeviceUsageNotification(WDFDEVICE device, WDF_SPECIAL_FILE_TYPE notification_type, BOOLEAN is_in_notification_path)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);

  FUNCTION_ENTER();
  
  KdPrint((__DRIVER_NAME "     path = %s\n", xppdd->path));
  switch (notification_type)
  {
  case WdfSpecialFilePaging:
    KdPrint((__DRIVER_NAME "     notification_type = Paging, flag = %d\n", is_in_notification_path));
    break;
  case WdfSpecialFileHibernation:
    xppdd->hiber_usage_kludge = is_in_notification_path;
    KdPrint((__DRIVER_NAME "     notification_type = Hibernation, flag = %d\n", is_in_notification_path));
    break;
  case WdfSpecialFileDump:
    KdPrint((__DRIVER_NAME "     notification_type = Dump, flag = %d\n", is_in_notification_path));
    break;
  default:
    KdPrint((__DRIVER_NAME "     notification_type = %d, flag = %d\n", notification_type, is_in_notification_path));
    break;
  }

  FUNCTION_EXIT();  
}

NTSTATUS
XenPci_EvtChildListCreateDevice(WDFCHILDLIST child_list,
  PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER identification_header,
  PWDFDEVICE_INIT child_init)
{
  NTSTATUS status = STATUS_SUCCESS;
  WDF_OBJECT_ATTRIBUTES child_attributes;
  WDFDEVICE child_device;
  PXENPCI_PDO_IDENTIFICATION_DESCRIPTION identification = (PXENPCI_PDO_IDENTIFICATION_DESCRIPTION)identification_header;
  WDF_DEVICE_PNP_CAPABILITIES child_pnp_capabilities;
  DECLARE_UNICODE_STRING_SIZE(buffer, 512);
  DECLARE_CONST_UNICODE_STRING(location, L"Xen Bus");
  PXENPCI_PDO_DEVICE_DATA xppdd;
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(WdfChildListGetDevice(child_list));
  WDF_QUERY_INTERFACE_CONFIG interface_config;
  BUS_INTERFACE_STANDARD bus_interface;
  WDF_PDO_EVENT_CALLBACKS pdo_callbacks;
  WDF_PNPPOWER_EVENT_CALLBACKS child_pnp_power_callbacks;
  UCHAR pnp_minor_functions[] = { IRP_MN_START_DEVICE };
  WDF_DEVICE_POWER_CAPABILITIES child_power_capabilities;
  
  FUNCTION_ENTER();

  WdfDeviceInitSetDeviceType(child_init, FILE_DEVICE_UNKNOWN);
  
  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&child_pnp_power_callbacks);
  child_pnp_power_callbacks.EvtDeviceD0Entry = XenPciPdo_EvtDeviceD0Entry;
  //child_pnp_power_callbacks.EvtDeviceD0EntryPostInterruptsEnabled = XenPciPdo_EvtDeviceD0EntryPostInterruptsEnabled;
  child_pnp_power_callbacks.EvtDeviceD0Exit = XenPciPdo_EvtDeviceD0Exit;
  //child_pnp_power_callbacks.EvtDeviceD0ExitPreInterruptsDisabled = XenPciPdo_EvtDeviceD0ExitPreInterruptsDisabled;
  child_pnp_power_callbacks.EvtDevicePrepareHardware = XenPciPdo_EvtDevicePrepareHardware;
  child_pnp_power_callbacks.EvtDeviceReleaseHardware = XenPciPdo_EvtDeviceReleaseHardware;
  child_pnp_power_callbacks.EvtDeviceUsageNotification = XenPciPdo_EvtDeviceUsageNotification;
  WdfDeviceInitSetPnpPowerEventCallbacks(child_init, &child_pnp_power_callbacks);

  KdPrint((__DRIVER_NAME "     device = '%s', index = '%d', path = '%s'\n",
    identification->device, identification->index, identification->path));
  
  status = WdfDeviceInitAssignWdmIrpPreprocessCallback(child_init, XenPciPdo_EvtDeviceWdmIrpPreprocess_START_DEVICE,
    IRP_MJ_PNP, pnp_minor_functions, ARRAY_SIZE(pnp_minor_functions));
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  
  WDF_PDO_EVENT_CALLBACKS_INIT(&pdo_callbacks);
  //pdo_callbacks.EvtDeviceResourcesQuery = XenPciPdo_EvtDeviceResourcesQuery;
  pdo_callbacks.EvtDeviceResourceRequirementsQuery = XenPciPdo_EvtDeviceResourceRequirementsQuery;
  //pdo_callbacks.EvtDeviceEject = XenPciPdo_EvtDeviceEject;
  //pdo_callbacks.EvtDeviceSetLock  = XenPciPdo_EvtDeviceSetLock;
  WdfPdoInitSetEventCallbacks(child_init, &pdo_callbacks);

  RtlUnicodeStringPrintf(&buffer, L"xen\\%S", identification->device);
  status = WdfPdoInitAssignDeviceID(child_init, &buffer);
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  status = WdfPdoInitAddHardwareID(child_init, &buffer);
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  status = WdfPdoInitAddCompatibleID(child_init, &buffer);
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  
  RtlUnicodeStringPrintf(&buffer, L"%02d", identification->index);
  status = WdfPdoInitAssignInstanceID(child_init, &buffer);
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  
  RtlUnicodeStringPrintf(&buffer, L"Xen %S device #%d", identification->device, identification->index);
  status = WdfPdoInitAddDeviceText(child_init, &buffer, &location, 0x0409);
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  WdfPdoInitSetDefaultLocale(child_init, 0x0409);

  WdfDeviceInitSetPowerNotPageable(child_init);
  
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&child_attributes, XENPCI_PDO_DEVICE_DATA);
  status = WdfDeviceCreate(&child_init, &child_attributes, &child_device);
  if (!NT_SUCCESS(status))
  {
    return status;
  }

  xppdd = GetXppdd(child_device);
  
  xppdd->wdf_device = child_device;
  xppdd->wdf_device_bus_fdo = WdfChildListGetDevice(child_list);

  xppdd->config_page_mdl = AllocateUncachedPage();

  xppdd->device_state.magic = XEN_DEVICE_STATE_MAGIC;
  xppdd->device_state.length = sizeof(XENPCI_DEVICE_STATE);
  xppdd->device_state.suspend_resume_state_pdo = SR_STATE_RUNNING;
  xppdd->device_state.suspend_resume_state_fdo = SR_STATE_RUNNING;
  xppdd->device_state.pdo_event_channel = xpdd->pdo_event_channel;
  WdfDeviceSetSpecialFileSupport(child_device, WdfSpecialFilePaging, TRUE);
  WdfDeviceSetSpecialFileSupport(child_device, WdfSpecialFileHibernation, TRUE);
  WdfDeviceSetSpecialFileSupport(child_device, WdfSpecialFileDump, TRUE);

  WDF_DEVICE_PNP_CAPABILITIES_INIT(&child_pnp_capabilities);
  child_pnp_capabilities.LockSupported = WdfFalse;
  child_pnp_capabilities.EjectSupported  = WdfTrue;
  child_pnp_capabilities.Removable  = WdfTrue;
  child_pnp_capabilities.DockDevice  = WdfFalse;
  child_pnp_capabilities.UniqueID  = WdfFalse;
  child_pnp_capabilities.SilentInstall  = WdfTrue;
  child_pnp_capabilities.SurpriseRemovalOK  = WdfTrue;
  child_pnp_capabilities.HardwareDisabled = WdfFalse;
  WdfDeviceSetPnpCapabilities(child_device, &child_pnp_capabilities);

  WDF_DEVICE_POWER_CAPABILITIES_INIT(&child_power_capabilities);
  child_power_capabilities.DeviceD1 = WdfTrue;
  child_power_capabilities.WakeFromD1 = WdfTrue;
  child_power_capabilities.DeviceWake = PowerDeviceD1;
  child_power_capabilities.DeviceState[PowerSystemWorking]   = PowerDeviceD1;
  child_power_capabilities.DeviceState[PowerSystemSleeping1] = PowerDeviceD1;
  child_power_capabilities.DeviceState[PowerSystemSleeping2] = PowerDeviceD2;
  child_power_capabilities.DeviceState[PowerSystemSleeping3] = PowerDeviceD2;
  child_power_capabilities.DeviceState[PowerSystemHibernate] = PowerDeviceD3;
  child_power_capabilities.DeviceState[PowerSystemShutdown]  = PowerDeviceD3;
  WdfDeviceSetPowerCapabilities(child_device, &child_power_capabilities);  

  bus_interface.Size = sizeof(BUS_INTERFACE_STANDARD);
  bus_interface.Version = 1; //BUS_INTERFACE_STANDARD_VERSION;
  bus_interface.Context = xppdd;
  bus_interface.InterfaceReference = WdfDeviceInterfaceReferenceNoOp;
  bus_interface.InterfaceDereference = WdfDeviceInterfaceDereferenceNoOp;
  bus_interface.TranslateBusAddress = XenPci_BIS_TranslateBusAddress;
  bus_interface.GetDmaAdapter = XenPci_BIS_GetDmaAdapter;
  bus_interface.SetBusData = XenPci_BIS_SetBusData;
  bus_interface.GetBusData = XenPci_BIS_GetBusData;
  WDF_QUERY_INTERFACE_CONFIG_INIT(&interface_config, (PINTERFACE)&bus_interface, &GUID_BUS_INTERFACE_STANDARD, NULL);
  status = WdfDeviceAddQueryInterface(child_device, &interface_config);
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  
  RtlStringCbCopyA(xppdd->path, ARRAY_SIZE(xppdd->path), identification->path);
  RtlStringCbCopyA(xppdd->device, ARRAY_SIZE(xppdd->device), identification->device);
  xppdd->index = identification->index;
  KeInitializeEvent(&xppdd->backend_state_event, SynchronizationEvent, FALSE);
  xppdd->backend_state = XenbusStateUnknown;
  xppdd->frontend_state = XenbusStateUnknown;
  xppdd->backend_path[0] = '\0';
    
  FUNCTION_EXIT();
  
  return status;
}

static __forceinline VOID
XenPci_Pdo_ChangeSuspendState(WDFDEVICE device, ULONG new_state)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);

  FUNCTION_ENTER();
  KdPrint((__DRIVER_NAME "     setting pdo state to %d\n", new_state));
  xppdd->device_state.suspend_resume_state_pdo = new_state;
  KeMemoryBarrier();
  KdPrint((__DRIVER_NAME "     Notifying event channel %d\n", xpdd->pdo_event_channel));
  EvtChn_Notify(xpdd, xpdd->pdo_event_channel);    
  while(xppdd->device_state.suspend_resume_state_fdo != xppdd->device_state.suspend_resume_state_pdo)
  {
    KdPrint((__DRIVER_NAME "     waiting...\n"));
    KeWaitForSingleObject(&xpdd->pdo_suspend_event, Executive, KernelMode, FALSE, NULL);
  }
  KdPrint((__DRIVER_NAME "     fdo state set to %d\n", new_state));
  FUNCTION_EXIT();
}

/* called at PASSIVE_LEVEL */
NTSTATUS
XenPci_Pdo_Suspend(WDFDEVICE device)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  //LARGE_INTEGER wait_time;
  char path[128];
  PUCHAR in_ptr;
  UCHAR type;
  PVOID setting;
  PVOID value;
  PVOID value2;

  KdPrint((__DRIVER_NAME " --> " __FUNCTION__ " (%s)\n", xppdd->path));

  if (xppdd->backend_state == XenbusStateConnected)
  {
    xppdd->restart_on_resume = TRUE;
    XenPci_Pdo_ChangeSuspendState(device, SR_STATE_SUSPENDING);

    XenPci_ChangeFrontendState(device, XenbusStateClosing, XenbusStateClosing, 30000);
    XenPci_ChangeFrontendState(device, XenbusStateClosed, XenbusStateClosed, 30000);
    XenPci_ChangeFrontendState(device, XenbusStateInitialising, XenbusStateInitWait, 30000);

    if (xppdd->assigned_resources_start != NULL)
    {
      in_ptr = xppdd->assigned_resources_ptr;
      ADD_XEN_INIT_RSP(&in_ptr, XEN_INIT_TYPE_END, NULL, NULL, NULL);
      in_ptr = xppdd->assigned_resources_start;
      while((type = GET_XEN_INIT_RSP(&in_ptr, &setting, &value, &value2)) != XEN_INIT_TYPE_END)
      {
        switch (type)
        {
        case XEN_INIT_TYPE_EVENT_CHANNEL: /* frontend event channel */
        case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ: /* frontend event channel bound to irq */
          EvtChn_Unbind(xpdd, PtrToUlong(value));
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

NTSTATUS
XenPci_Pdo_Resume(WDFDEVICE device)
{
  NTSTATUS status = STATUS_SUCCESS;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  ULONG old_backend_state;
  PUCHAR src, dst;

  FUNCTION_ENTER();
  KdPrint((__DRIVER_NAME "     path = %s\n", xppdd->path));

  xppdd->device_state.pdo_event_channel = xpdd->pdo_event_channel;
  old_backend_state = xppdd->backend_state;

  if (xppdd->restart_on_resume)
  {  
    status = XenPci_GetBackendAndAddWatch(device);
  
    if (XenPci_ChangeFrontendState(device, XenbusStateInitialising, XenbusStateInitWait, 30000) != STATUS_SUCCESS)
    {
      KdPrint((__DRIVER_NAME "     Failed to change frontend state to Initialising\n"));
      // this is probably an unrecoverable situation...
      FUNCTION_ERROR_EXIT();
      return STATUS_UNSUCCESSFUL;
    }
    if (xppdd->assigned_resources_ptr)
    {
      // reset things - feed the 'requested resources' back in
      ADD_XEN_INIT_REQ(&xppdd->requested_resources_ptr, XEN_INIT_TYPE_END, NULL, NULL, NULL);
      src = xppdd->requested_resources_start;
      xppdd->requested_resources_ptr = xppdd->requested_resources_start = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);;
      xppdd->assigned_resources_ptr = xppdd->assigned_resources_start;
      
      dst = MmMapIoSpace(xppdd->config_page_phys, xppdd->config_page_length, MmNonCached);
      
      status = XenPci_XenConfigDeviceSpecifyBuffers(device, src, dst);

      MmUnmapIoSpace(dst, xppdd->config_page_length);
      ExFreePoolWithTag(src, XENPCI_POOL_TAG);
    }
    if (XenPci_ChangeFrontendState(device, XenbusStateConnected, XenbusStateConnected, 30000) != STATUS_SUCCESS)
    {
      // this is definitely an unrecoverable situation...
      KdPrint((__DRIVER_NAME "     Failed to change frontend state to connected\n"));
      FUNCTION_ERROR_EXIT();
      return STATUS_UNSUCCESSFUL;
    }
    XenPci_Pdo_ChangeSuspendState(device, SR_STATE_RESUMING);
    XenPci_Pdo_ChangeSuspendState(device, SR_STATE_RUNNING);
  }

  FUNCTION_EXIT();

  return STATUS_SUCCESS;
} 

#if 0
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

#if !DBG
  UNREFERENCED_PARAMETER(path);
#endif
  
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
XenPci_EvtChn_Bind(PVOID Context, evtchn_port_t Port, PXEN_EVTCHN_SERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return EvtChn_Bind(xpdd, Port, ServiceRoutine, ServiceContext);
}

static NTSTATUS
XenPci_EvtChn_BindDpc(PVOID Context, evtchn_port_t Port, PXEN_EVTCHN_SERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext)
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

static BOOLEAN
XenPci_EvtChn_AckEvent(PVOID context, evtchn_port_t port)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return EvtChn_AckEvent(xpdd, port);
}

static BOOLEAN
XenPci_EvtChn_Sync(PVOID context, PKSYNCHRONIZE_ROUTINE sync_routine, PVOID sync_context)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  
  return KeSynchronizeExecution(xpdd->interrupt, sync_routine, sync_context);
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

PCHAR
XenPci_XenBus_Read(PVOID Context, xenbus_transaction_t xbt, char *path, char **value)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  return XenBus_Read(xpdd, xbt, path, value);
}

PCHAR
XenPci_XenBus_Write(PVOID Context, xenbus_transaction_t xbt, char *path, char *value)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  return XenBus_Write(xpdd, xbt, path, value);
}

PCHAR
XenPci_XenBus_Printf(PVOID Context, xenbus_transaction_t xbt, char *path, char *fmt, ...)
{
  //PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  //PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  //return XenBus_Printf(xpdd, xbt, path, value);
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(xbt);
  UNREFERENCED_PARAMETER(path);
  UNREFERENCED_PARAMETER(fmt);
  return NULL;
}

PCHAR
XenPci_XenBus_StartTransaction(PVOID Context, xenbus_transaction_t *xbt)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  return XenBus_StartTransaction(xpdd, xbt);
}

PCHAR
XenPci_XenBus_EndTransaction(PVOID Context, xenbus_transaction_t xbt, int abort, int *retry)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  return XenBus_EndTransaction(xpdd, xbt, abort, retry);
}

PCHAR
XenPci_XenBus_List(PVOID Context, xenbus_transaction_t xbt, char *prefix, char ***contents)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  return XenBus_List(xpdd, xbt, prefix, contents);
}

PCHAR
XenPci_XenBus_AddWatch(PVOID Context, xenbus_transaction_t xbt, char *path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  PCHAR retval;
  
  FUNCTION_ENTER();
  retval = XenBus_AddWatch(xpdd, xbt, path, ServiceRoutine, ServiceContext);
  if (retval == NULL)
  {
    KdPrint((__DRIVER_NAME "     XenPci_XenBus_AddWatch - %s = NULL\n", path));
  }
  else
  {
    KdPrint((__DRIVER_NAME "     XenPci_XenBus_AddWatch - %s = %s\n", path, retval));
  }
  FUNCTION_EXIT();
  return retval;
}

PCHAR
XenPci_XenBus_RemWatch(PVOID Context, xenbus_transaction_t xbt, char *path, PXENBUS_WATCH_CALLBACK ServiceRoutine, PVOID ServiceContext)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = Context;
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  return XenBus_RemWatch(xpdd, xbt, path, ServiceRoutine, ServiceContext);
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
    ADD_XEN_INIT_RSP(&xppdd->assigned_resources_ptr, XEN_INIT_TYPE_END, NULL, NULL, NULL);
    in_ptr = xppdd->assigned_resources_start;
    while((type = GET_XEN_INIT_RSP(&in_ptr, &setting, &value, &value2)) != XEN_INIT_TYPE_END)
    {
      switch (type)
      {
      case XEN_INIT_TYPE_RING: /* frontend ring */
        FreePages(value);
        break;
      case XEN_INIT_TYPE_EVENT_CHANNEL: /* frontend event channel */
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
  PCHAR setting, value, value2;
  PCHAR res;
  PVOID address;
  UCHAR type;
  PUCHAR in_ptr; //, in_start;
  PUCHAR out_ptr; //, out_start;
  XENPCI_VECTORS vectors;
  ULONG event_channel;
  ULONG run_type = 0;
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
  vectors.EvtChn_AckEvent = XenPci_EvtChn_AckEvent;
  vectors.EvtChn_Sync = XenPci_EvtChn_Sync;
  vectors.GntTbl_GetRef = XenPci_GntTbl_GetRef;
  vectors.GntTbl_PutRef = XenPci_GntTbl_PutRef;
  vectors.GntTbl_GrantAccess = XenPci_GntTbl_GrantAccess;
  vectors.GntTbl_EndAccess = XenPci_GntTbl_EndAccess;
  vectors.XenPci_XenConfigDevice = XenPci_XenConfigDevice;
  vectors.XenPci_XenShutdownDevice = XenPci_XenShutdownDevice;
  strncpy(vectors.path, xppdd->path, 128);
  strncpy(vectors.backend_path, xppdd->backend_path, 128);
  vectors.pdo_event_channel = xpdd->pdo_event_channel;
  vectors.XenBus_Read = XenPci_XenBus_Read;
  vectors.XenBus_Write = XenPci_XenBus_Write;
  vectors.XenBus_Printf = XenPci_XenBus_Printf;
  vectors.XenBus_StartTransaction = XenPci_XenBus_StartTransaction;
  vectors.XenBus_EndTransaction = XenPci_XenBus_EndTransaction;
  vectors.XenBus_List = XenPci_XenBus_List;
  vectors.XenBus_AddWatch = XenPci_XenBus_AddWatch;
  vectors.XenBus_RemWatch = XenPci_XenBus_RemWatch;

  if (qemu_filtered)
    ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_ACTIVE, NULL, NULL, NULL);

  ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_QEMU_PROTOCOL_VERSION, NULL, UlongToPtr(qemu_protocol_version), NULL);
  
  ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_VECTORS, NULL, &vectors, NULL);
  ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_STATE_PTR, NULL, &xppdd->device_state, NULL);

  // first pass, possibly before state == Connected
  while((type = GET_XEN_INIT_REQ(&in_ptr, (PVOID)&setting, (PVOID)&value, (PVOID)&value2)) != XEN_INIT_TYPE_END)
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
    
    ADD_XEN_INIT_REQ(&xppdd->requested_resources_ptr, type, setting, value, value2);

    switch (type)
    {
    case XEN_INIT_TYPE_RUN:
      run_type++;
      break;
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
          xpdd, 0, (ULONG)*MmGetMdlPfnArray(ring), FALSE, INVALID_GRANT_REF)) != INVALID_GRANT_REF)
        {
          RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->path, setting);
          XenBus_Printf(xpdd, XBT_NIL, path, "%d", gref);
          ADD_XEN_INIT_RSP(&out_ptr, type, setting, address, NULL);
          ADD_XEN_INIT_RSP(&xppdd->assigned_resources_ptr, type, setting, ring, NULL);
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
        ADD_XEN_INIT_RSP(&out_ptr, type, setting, UlongToPtr(event_channel), NULL);
        ADD_XEN_INIT_RSP(&xppdd->assigned_resources_ptr, type, setting, UlongToPtr(event_channel), NULL);
        if (type == XEN_INIT_TYPE_EVENT_CHANNEL_IRQ)
          EvtChn_BindIrq(xpdd, event_channel, xppdd->irq_vector, path);
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
  // If XEN_INIT_TYPE_RUN was specified more than once then we skip XenbusStateInitialised here and go straight to XenbusStateConnected at the end
  if (run_type == 1)
  {
    if (XenPci_ChangeFrontendState(xppdd, XenbusStateInitialised, XenbusStateConnected, 30000) != STATUS_SUCCESS)
    {
      status = STATUS_UNSUCCESSFUL;
      goto error;
    }
  }

  // second pass, possibly after state == Connected
  in_ptr = src;
  while((type = GET_XEN_INIT_REQ(&in_ptr, (PVOID)&setting, (PVOID)&value, (PVOID)&value2)) != XEN_INIT_TYPE_END)
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
        ADD_XEN_INIT_RSP(&out_ptr, type, setting, NULL, NULL);
      }
      else
      {
        //KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = %s\n", setting, value));
        ADD_XEN_INIT_RSP(&out_ptr, type, setting, value, NULL);
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
        gref = GntTbl_GetRef(xpdd);
        __ADD_XEN_INIT_ULONG(&out_ptr, gref);
        __ADD_XEN_INIT_ULONG(&xppdd->assigned_resources_ptr, gref);
      }
      break;
    }
  }
  ADD_XEN_INIT_RSP(&out_ptr, XEN_INIT_TYPE_END, NULL, NULL);

  if (run_type)
  {
    if (XenPci_ChangeFrontendState(xppdd, XenbusStateConnected, XenbusStateConnected, 30000) != STATUS_SUCCESS)
    {
      status = STATUS_UNSUCCESSFUL;
      goto error;
    }
  }
  FUNCTION_EXIT();
  return status;
  
error:
  XenPci_ChangeFrontendState(xppdd, XenbusStateInitialising, XenbusStateInitWait, 30000);
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
  PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  ULONG old_backend_state;
  PUCHAR src, dst;

  FUNCTION_ENTER();

  old_backend_state = xppdd->backend_state;

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
  KeMemoryBarrier();
  EvtChn_Notify(xpdd, xpdd->pdo_event_channel);  

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
    EvtChn_Notify(xpdd, xpdd->pdo_event_channel);    
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

VOID
XenPci_DumpPdoConfig(PDEVICE_OBJECT device_object)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;

#if !DBG
  UNREFERENCED_PARAMETER(xppdd);
#endif

  KdPrint((__DRIVER_NAME "     path = %s\n", xppdd->path));
  KdPrint((__DRIVER_NAME "     backend_path = %s\n", xppdd->backend_path));
  KdPrint((__DRIVER_NAME "     irq_number = %d\n", xppdd->irq_number));
  KdPrint((__DRIVER_NAME "     irq_level = %d\n", xppdd->irq_level));
  KdPrint((__DRIVER_NAME "     irq_vector = %x\n", xppdd->irq_vector));
}

static PMDL
XenConfig_MakeConfigPage(PDEVICE_OBJECT device_object, PMDL mdl)
{
  //PXENCONFIG_DEVICE_DATA xcdd = (PXENCONFIG_DEVICE_DATA)device_object->DeviceExtension;
  //PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  //PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
  PMDL mdl;
  PUCHAR ptr;
  PDEVICE_OBJECT curr, prev;
  PDRIVER_OBJECT fdo_driver_object;
  PUCHAR fdo_driver_extension;
  
  ptr = MmGetMdlVirtualAddress(mdl);
  curr = IoGetAttachedDeviceReference(device_object);
  while (curr != NULL)
  {
    fdo_driver_object = curr->DriverObject;
    KdPrint((__DRIVER_NAME "     fdo_driver_object = %p\n", fdo_driver_object));
    if (fdo_driver_object)
    {
      fdo_driver_extension = IoGetDriverObjectExtension(fdo_driver_object, UlongToPtr(XEN_INIT_DRIVER_EXTENSION_MAGIC));
      KdPrint((__DRIVER_NAME "     fdo_driver_extension = %p\n", fdo_driver_extension));
      if (fdo_driver_extension)
      {
        memcpy(ptr, fdo_driver_extension, PAGE_SIZE);
        ObDereferenceObject(curr);
        break;
      }
    }
    prev = curr;
    curr = IoGetLowerDeviceObject(curr);
    ObDereferenceObject(prev);
  }
  return mdl;
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
  PMDL mdl;
 
  FUNCTION_ENTER();
  KdPrint((__DRIVER_NAME "     %s\n", xppdd->path));

  DUMP_CURRENT_PNP_STATE(xppdd);
  
  stack = IoGetCurrentIrpStackLocation(irp);

  status = XenPci_GetBackendAndAddWatch(device_object);
  if (!NT_SUCCESS(status)) {
    FUNCTION_ERROR_EXIT();
    return status;
  }

  mdl = XenConfig_MakeConfigPage(device_object);
  
  prl = &stack->Parameters.StartDevice.AllocatedResources->List[0].PartialResourceList;
  for (i = 0; i < prl->Count; i++)
  {
    prd = & prl->PartialDescriptors[i];
    switch (prd->Type)
    {
#if 0    
    case CmResourceTypeInterrupt:
      KdPrint((__DRIVER_NAME "     CmResourceTypeInterrupt\n"));
      KdPrint((__DRIVER_NAME "     irq_number = %02x\n", prd->u.Interrupt.Vector));
      xppdd->irq_number = prd->u.Interrupt.Vector;
      break;
#endif
    case CmResourceTypeMemory:
      if (prd->u.Memory.Start.QuadPart == xpdd->platform_mmio_addr.QuadPart && prd->u.Memory.Length == 0)
      {
        prd->u.Memory.Start.QuadPart = MmGetMdlPfnArray(mdl)[0] << PAGE_SHIFT;
        prd->u.Memory.Length = MmGetMdlByteCount(mdl);
      }
      else if (prd->u.Memory.Start.QuadPart == xpdd->platform_mmio_addr.QuadPart + 1 && prd->u.Memory.Length == 0)
      {
        RtlZeroMemory(prd, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
        prd->Type = CmResourceTypeInterrupt;
        prd->ShareDisposition = CmResourceShareShared;
        prd->Flags = (xpdd->irq_mode == Latched)?CM_RESOURCE_INTERRUPT_LATCHED:CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
        prd->u.Interrupt.Level = xpdd->irq_number;
        prd->u.Interrupt.Vector = xpdd->irq_number;
        prd->u.Interrupt.Affinity = (KAFFINITY)-1;
        xppdd->irq_number = xpdd->irq_number;
      }
      break;
    }
  }

  prl = &stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList;
  for (i = 0; i < prl->Count; i++)
  {
    prd = & prl->PartialDescriptors[i];
    switch (prd->Type)
    {
#if 0
    case CmResourceTypeInterrupt:
      KdPrint((__DRIVER_NAME "     CmResourceTypeInterrupt (%d)\n", i));
      KdPrint((__DRIVER_NAME "     irq_vector = %02x\n", prd->u.Interrupt.Vector));
      KdPrint((__DRIVER_NAME "     irq_level = %d\n", prd->u.Interrupt.Level));
      xppdd->irq_vector = prd->u.Interrupt.Vector;
      xppdd->irq_level = (KIRQL)prd->u.Interrupt.Level;
      break;
#endif
    case CmResourceTypeMemory:
      KdPrint((__DRIVER_NAME "     CmResourceTypeMemory (%d)\n", i));
      KdPrint((__DRIVER_NAME "     Start = %08x, Length = %d\n", prd->u.Memory.Start.LowPart, prd->u.Memory.Length));
      if (prd->u.Memory.Start.QuadPart == xpdd->platform_mmio_addr.QuadPart)
      {
        if (prd->u.Memory.Length == 0)
        {
          KdPrint((__DRIVER_NAME "     pfn[0] = %08x\n", (ULONG)MmGetMdlPfnArray(mdl)[0]));
          prd->u.Memory.Start.QuadPart = (ULONGLONG)MmGetMdlPfnArray(mdl)[0] << PAGE_SHIFT;
          prd->u.Memory.Length = MmGetMdlByteCount(mdl);
          KdPrint((__DRIVER_NAME "     New Start = %08x%08x, Length = %d\n", prd->u.Memory.Start.HighPart, prd->u.Memory.Start.LowPart, prd->u.Memory.Length));
        }
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
      else if (prd->u.Memory.Start.QuadPart == xpdd->platform_mmio_addr.QuadPart + 1 && prd->u.Memory.Length == 0)
      {
        RtlZeroMemory(prd, sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
        prd->Type = CmResourceTypeInterrupt;
        prd->ShareDisposition = CmResourceShareShared;
        prd->Flags = (xpdd->irq_mode == Latched)?CM_RESOURCE_INTERRUPT_LATCHED:CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
        prd->u.Interrupt.Level = xpdd->irq_level;
        prd->u.Interrupt.Vector = xpdd->irq_vector;
        prd->u.Interrupt.Affinity = (KAFFINITY)-1;
        xppdd->irq_vector = xpdd->irq_vector;
        xppdd->irq_level = xpdd->irq_level;
      }
      break;
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

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();
  
  length = FIELD_OFFSET(IO_RESOURCE_REQUIREMENTS_LIST, List) +
    FIELD_OFFSET(IO_RESOURCE_LIST, Descriptors) +
    sizeof(IO_RESOURCE_DESCRIPTOR) * 2;
  irrl = ExAllocatePoolWithTag(NonPagedPool,
    length,
    XENPCI_POOL_TAG);
  
  irrl->ListSize = length;
  irrl->InterfaceType = PNPBus; //Internal;
  irrl->BusNumber = 0;
  irrl->SlotNumber = 0;
  irrl->AlternativeLists = 1;
  irrl->List[0].Version = 1;
  irrl->List[0].Revision = 1;
  irrl->List[0].Count = 0;

  #if 0
  ird = &irrl->List[0].Descriptors[irrl->List[0].Count++];
  ird->Option = 0;
  ird->Type = CmResourceTypeInterrupt;
  ird->ShareDisposition = CmResourceShareShared;
  ird->Flags = (xpdd->irq_mode == Latched)?CM_RESOURCE_INTERRUPT_LATCHED:CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
  KdPrint((__DRIVER_NAME "      irq type = %s\n", (xpdd->irq_mode == Latched)?"Latched":"Level"));
  ird->u.Interrupt.MinimumVector = xpdd->irq_number;
  ird->u.Interrupt.MaximumVector = xpdd->irq_number;
  #endif
  
  ird = &irrl->List[0].Descriptors[irrl->List[0].Count++];
  ird->Option = 0;
  ird->Type = CmResourceTypeMemory;
  ird->ShareDisposition = CmResourceShareShared;
  ird->Flags = CM_RESOURCE_MEMORY_READ_WRITE | CM_RESOURCE_MEMORY_CACHEABLE;
  ird->u.Memory.MinimumAddress.QuadPart = xpdd->platform_mmio_addr.QuadPart;
  ird->u.Memory.MaximumAddress.QuadPart = xpdd->platform_mmio_addr.QuadPart;
  ird->u.Memory.Length = 0;
  ird->u.Memory.Alignment = PAGE_SIZE;

  ird = &irrl->List[0].Descriptors[irrl->List[0].Count++];
  ird->Option = 0;
  ird->Type = CmResourceTypeMemory;
  ird->ShareDisposition = CmResourceShareShared;
  ird->Flags = CM_RESOURCE_MEMORY_READ_WRITE | CM_RESOURCE_MEMORY_CACHEABLE;
  ird->u.Memory.MinimumAddress.QuadPart = xpdd->platform_mmio_addr.QuadPart + 1;
  ird->u.Memory.MaximumAddress.QuadPart = xpdd->platform_mmio_addr.QuadPart + 1;
  ird->u.Memory.Length = 0;
  ird->u.Memory.Alignment = PAGE_SIZE;

  irp->IoStatus.Information = (ULONG_PTR)irrl;

  FUNCTION_EXIT();
  
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

static VOID
XenPci_IS_InterfaceReference(PVOID context)
{
  UNREFERENCED_PARAMETER(context);
  FUNCTION_ENTER();
  FUNCTION_EXIT();
}

static VOID
XenPci_IS_InterfaceDereference(PVOID context)
{
  UNREFERENCED_PARAMETER(context);
  FUNCTION_ENTER();
  FUNCTION_EXIT();
}

static BOOLEAN
XenPci_BIS_TranslateBusAddress(PVOID context, PHYSICAL_ADDRESS bus_address, ULONG length, PULONG address_space, PPHYSICAL_ADDRESS translated_address)
{
  UNREFERENCED_PARAMETER(context);
  UNREFERENCED_PARAMETER(length);
  /* actually this isn't right - should look up the gref for the physical address and work backwards from that */
  FUNCTION_ENTER();
  if (*address_space != 0)
  {
    KdPrint((__DRIVER_NAME "      Cannot map I/O space\n"));
    FUNCTION_EXIT();
    return FALSE;
  }
  *translated_address = bus_address;
  FUNCTION_EXIT();
  return TRUE;
}

static VOID
XenPci_DOP_PutDmaAdapter(PDMA_ADAPTER dma_adapter)
{
  UNREFERENCED_PARAMETER(dma_adapter);
  
  FUNCTION_ENTER();
  // decrement ref count
  FUNCTION_EXIT();

  return;
}

static PVOID
XenPci_DOP_AllocateCommonBuffer(
  PDMA_ADAPTER DmaAdapter,
  ULONG Length,
  PPHYSICAL_ADDRESS LogicalAddress,
  BOOLEAN CacheEnabled
)
{
  xen_dma_adapter_t *xen_dma_adapter;
  PXENPCI_DEVICE_DATA xpdd;
  PVOID buffer;
  PFN_NUMBER pfn;
  grant_ref_t gref;
  
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(CacheEnabled);
  
  //FUNCTION_ENTER();

  xen_dma_adapter = (xen_dma_adapter_t *)DmaAdapter;
  xpdd = xen_dma_adapter->xppdd->bus_fdo->DeviceExtension;

  //KdPrint((__DRIVER_NAME "     Length = %d\n", Length));
  
  buffer = ExAllocatePoolWithTag(NonPagedPool, Length, XENPCI_POOL_TAG);

  pfn = (PFN_NUMBER)(MmGetPhysicalAddress(buffer).QuadPart >> PAGE_SHIFT);
  ASSERT(pfn);
  gref = (grant_ref_t)GntTbl_GrantAccess(xpdd, 0, pfn, FALSE, INVALID_GRANT_REF);
  ASSERT(gref);
  LogicalAddress->QuadPart = (gref << PAGE_SHIFT) | (PtrToUlong(buffer) & (PAGE_SIZE - 1));
  
  //FUNCTION_EXIT();
  return buffer;
}

static VOID
XenPci_DOP_FreeCommonBuffer(
  PDMA_ADAPTER DmaAdapter,
  ULONG Length,
  PHYSICAL_ADDRESS LogicalAddress,
  PVOID VirtualAddress,
  BOOLEAN CacheEnabled
)
{
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(Length);
  UNREFERENCED_PARAMETER(LogicalAddress);
  UNREFERENCED_PARAMETER(CacheEnabled);

  FUNCTION_ENTER();
  ExFreePoolWithTag(VirtualAddress, XENPCI_POOL_TAG);
  // TODO: free the grant ref here
  FUNCTION_EXIT();
}

static NTSTATUS
XenPci_DOP_AllocateAdapterChannel(
    IN PDMA_ADAPTER  DmaAdapter,
    IN PDEVICE_OBJECT  DeviceObject,
    IN ULONG  NumberOfMapRegisters,
    IN PDRIVER_CONTROL  ExecutionRoutine,
    IN PVOID  Context
    )
{
  IO_ALLOCATION_ACTION action;
  
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(NumberOfMapRegisters);
  
  FUNCTION_ENTER();
  action = ExecutionRoutine(DeviceObject, DeviceObject->CurrentIrp, UlongToPtr(64), Context);
  
  switch (action)
  {
  case KeepObject:
    KdPrint((__DRIVER_NAME "     KeepObject\n"));
    break;
  case DeallocateObject:
    KdPrint((__DRIVER_NAME "     DeallocateObject\n"));
    break;
  case DeallocateObjectKeepRegisters:
    KdPrint((__DRIVER_NAME "     DeallocateObjectKeepRegisters\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unknown action %d\n", action));
    break;
  }
  FUNCTION_EXIT();
  return STATUS_SUCCESS;
}

static BOOLEAN
XenPci_DOP_FlushAdapterBuffers(
  PDMA_ADAPTER DmaAdapter,
  PMDL Mdl,
  PVOID MapRegisterBase,
  PVOID CurrentVa,
  ULONG Length,
  BOOLEAN WriteToDevice)
{
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER( Mdl);
  UNREFERENCED_PARAMETER(MapRegisterBase);
  UNREFERENCED_PARAMETER(CurrentVa);
  UNREFERENCED_PARAMETER(Length);
  UNREFERENCED_PARAMETER(WriteToDevice);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return TRUE;
}

static VOID
XenPci_DOP_FreeAdapterChannel(
    IN PDMA_ADAPTER  DmaAdapter
    )
{
  UNREFERENCED_PARAMETER(DmaAdapter);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
}

static VOID
XenPci_DOP_FreeMapRegisters(
  PDMA_ADAPTER DmaAdapter,
  PVOID MapRegisterBase,
  ULONG NumberOfMapRegisters)
{
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(MapRegisterBase);
  UNREFERENCED_PARAMETER(NumberOfMapRegisters);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
}

static PHYSICAL_ADDRESS
XenPci_DOP_MapTransfer(
    PDMA_ADAPTER DmaAdapter,
    PMDL Mdl,
    PVOID MapRegisterBase,
    PVOID CurrentVa,
    PULONG Length,
    BOOLEAN WriteToDevice)
{
  PHYSICAL_ADDRESS physical;
  
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(Mdl);
  UNREFERENCED_PARAMETER(MapRegisterBase);
  UNREFERENCED_PARAMETER(CurrentVa);
  UNREFERENCED_PARAMETER(Length);
  UNREFERENCED_PARAMETER(WriteToDevice);

  FUNCTION_ENTER();
  
  physical.QuadPart = 0;
  
  FUNCTION_EXIT();
  return physical;
}

static ULONG
XenPci_DOP_GetDmaAlignment(
  PDMA_ADAPTER DmaAdapter)
{
  UNREFERENCED_PARAMETER(DmaAdapter);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return 0;
}

static ULONG
XenPci_DOP_ReadDmaCounter(
  PDMA_ADAPTER DmaAdapter)
{
  UNREFERENCED_PARAMETER(DmaAdapter);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return 0;
}

static NTSTATUS
XenPci_DOP_GetScatterGatherList(
  PDMA_ADAPTER DmaAdapter,
  PDEVICE_OBJECT DeviceObject,
  PMDL Mdl,
  PVOID CurrentVa,
  ULONG Length,
  PDRIVER_LIST_CONTROL ExecutionRoutine,
  PVOID Context,
  BOOLEAN WriteToDevice)
{
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(DeviceObject);
  UNREFERENCED_PARAMETER(Mdl);
  UNREFERENCED_PARAMETER(CurrentVa);
  UNREFERENCED_PARAMETER(Length);
  UNREFERENCED_PARAMETER(ExecutionRoutine);
  UNREFERENCED_PARAMETER(Context);
  UNREFERENCED_PARAMETER(WriteToDevice);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return STATUS_SUCCESS;
}

#define MAP_TYPE_VIRTUAL  1
#define MAP_TYPE_MDL      2
#define MAP_TYPE_REMAPPED 3

typedef struct {
  ULONG map_type;
  PVOID aligned_buffer;
  PVOID unaligned_buffer;
  ULONG copy_length;
} sg_extra_t;

static VOID
XenPci_DOP_PutScatterGatherList(
    IN PDMA_ADAPTER DmaAdapter,
    IN PSCATTER_GATHER_LIST ScatterGather,
    IN BOOLEAN WriteToDevice
    )
{
  xen_dma_adapter_t *xen_dma_adapter;
  PXENPCI_DEVICE_DATA xpdd;
  ULONG i;
  sg_extra_t *sg_extra;

  UNREFERENCED_PARAMETER(WriteToDevice);
  
  //FUNCTION_ENTER();

  xen_dma_adapter = (xen_dma_adapter_t *)DmaAdapter;
  xpdd = xen_dma_adapter->xppdd->bus_fdo->DeviceExtension;
  
  sg_extra = (sg_extra_t *)((PUCHAR)ScatterGather + FIELD_OFFSET(SCATTER_GATHER_LIST, Elements) +
    (sizeof(SCATTER_GATHER_ELEMENT)) * ScatterGather->NumberOfElements);

  switch (sg_extra->map_type)
  {
  case MAP_TYPE_REMAPPED:
    for (i = 0; i < ScatterGather->NumberOfElements; i++)
    {
      grant_ref_t gref;
      gref = (grant_ref_t)(ScatterGather->Elements[i].Address.QuadPart >> PAGE_SHIFT);
      GntTbl_EndAccess(xpdd, gref, FALSE);
      ScatterGather->Elements[i].Address.QuadPart = -1;
    }
    if (!WriteToDevice)
      memcpy(sg_extra->unaligned_buffer, sg_extra->aligned_buffer, sg_extra->copy_length);
    ExFreePoolWithTag(sg_extra->aligned_buffer, XENPCI_POOL_TAG);
    break;
  case MAP_TYPE_MDL:
    for (i = 0; i < ScatterGather->NumberOfElements; i++)
    {
      grant_ref_t gref;
      gref = (grant_ref_t)(ScatterGather->Elements[i].Address.QuadPart >> PAGE_SHIFT);
      GntTbl_EndAccess(xpdd, gref, FALSE);
      ScatterGather->Elements[i].Address.QuadPart = -1;
    }
    break;
  case MAP_TYPE_VIRTUAL:
    break;
  }
  //FUNCTION_EXIT();
}

static NTSTATUS
XenPci_DOP_CalculateScatterGatherList(
  PDMA_ADAPTER DmaAdapter,
  PMDL Mdl,
  PVOID CurrentVa,
  ULONG Length,
  PULONG ScatterGatherListSize,
  PULONG NumberOfMapRegisters
  )
{
  ULONG elements;
  PMDL curr_mdl;
  
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(Mdl);
  
  FUNCTION_ENTER();
  
  KdPrint((__DRIVER_NAME "     Mdl = %p\n", Mdl));
  KdPrint((__DRIVER_NAME "     CurrentVa = %p\n", CurrentVa));
  KdPrint((__DRIVER_NAME "     Length = %d\n", Length));
  if (Mdl)
  {
    for (curr_mdl = Mdl, elements = 0; curr_mdl; curr_mdl = curr_mdl->Next)
      elements += ADDRESS_AND_SIZE_TO_SPAN_PAGES(CurrentVa, Length);
  }
  else
  {
    elements = ADDRESS_AND_SIZE_TO_SPAN_PAGES(0, Length) + 1;
  }
  
  *ScatterGatherListSize = FIELD_OFFSET(SCATTER_GATHER_LIST, Elements)
    + sizeof(SCATTER_GATHER_ELEMENT) * elements
    + sizeof(sg_extra_t);
  if (NumberOfMapRegisters)
    *NumberOfMapRegisters = 1;

  KdPrint((__DRIVER_NAME "     ScatterGatherListSize = %d\n", *ScatterGatherListSize));

  FUNCTION_EXIT();
  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_DOP_BuildScatterGatherList(
  IN PDMA_ADAPTER DmaAdapter,
  IN PDEVICE_OBJECT DeviceObject,
  IN PMDL Mdl,
  IN PVOID CurrentVa,
  IN ULONG Length,
  IN PDRIVER_LIST_CONTROL ExecutionRoutine,
  IN PVOID Context,
  IN BOOLEAN WriteToDevice,
  IN PVOID ScatterGatherBuffer,
  IN ULONG ScatterGatherBufferLength)
{
  ULONG i;
  PSCATTER_GATHER_LIST sglist = ScatterGatherBuffer;
  PUCHAR ptr;
  ULONG remaining = Length;
  ULONG total_remaining;
  xen_dma_adapter_t *xen_dma_adapter;
  PXENPCI_DEVICE_DATA xpdd;
  sg_extra_t *sg_extra;
  PMDL curr_mdl;
  ULONG map_type;
  ULONG sg_element;
  ULONG offset;
  PFN_NUMBER pfn;
  grant_ref_t gref;
  
  UNREFERENCED_PARAMETER(WriteToDevice);

  //FUNCTION_ENTER();

  xen_dma_adapter = (xen_dma_adapter_t *)DmaAdapter;
  xpdd = xen_dma_adapter->xppdd->bus_fdo->DeviceExtension;

  ASSERT(Mdl);
  if (xen_dma_adapter->dma_extension)
  {
    if (xen_dma_adapter->dma_extension->need_virtual_address(DeviceObject->CurrentIrp))
    {
      ASSERT(!Mdl->Next); /* can only virtual a single buffer */
      map_type = MAP_TYPE_VIRTUAL;
      sglist->NumberOfElements = 1;
    }
    else
    {
      ULONG alignment = xen_dma_adapter->dma_extension->get_alignment(DeviceObject->CurrentIrp);
      if (PtrToUlong(CurrentVa) & (alignment - 1))
      {
        ASSERT(!Mdl->Next); /* can only remap a single buffer */
        map_type = MAP_TYPE_REMAPPED;
        sglist->NumberOfElements = ADDRESS_AND_SIZE_TO_SPAN_PAGES(NULL, Length);
      }
      else
      {
        map_type = MAP_TYPE_MDL;
        for (curr_mdl = Mdl, sglist->NumberOfElements = 0; curr_mdl; curr_mdl = curr_mdl->Next)
          sglist->NumberOfElements += ADDRESS_AND_SIZE_TO_SPAN_PAGES(
            MmGetMdlVirtualAddress(curr_mdl), MmGetMdlByteCount(curr_mdl));
      }
    }
  }
  else
  {
    map_type = MAP_TYPE_MDL;
    for (curr_mdl = Mdl, sglist->NumberOfElements = 0; curr_mdl; curr_mdl = curr_mdl->Next)
      sglist->NumberOfElements += ADDRESS_AND_SIZE_TO_SPAN_PAGES(
        MmGetMdlVirtualAddress(curr_mdl), MmGetMdlByteCount(curr_mdl));
  }
  if (ScatterGatherBufferLength < FIELD_OFFSET(SCATTER_GATHER_LIST, Elements) +
    sizeof(SCATTER_GATHER_ELEMENT) * sglist->NumberOfElements + sizeof(sg_extra_t))
  {
    return STATUS_BUFFER_TOO_SMALL;
  }
  
  sg_extra = (sg_extra_t *)((PUCHAR)sglist + FIELD_OFFSET(SCATTER_GATHER_LIST, Elements) +
    (sizeof(SCATTER_GATHER_ELEMENT)) * sglist->NumberOfElements);
  
  sg_extra->map_type = map_type;
  switch (map_type)
  {
  case MAP_TYPE_MDL:
    KdPrint((__DRIVER_NAME "     MAP_TYPE_MDL - %p\n", CurrentVa));
    total_remaining = Length;
    for (sg_element = 0, curr_mdl = Mdl; curr_mdl; curr_mdl = curr_mdl->Next)
    {
      remaining = MmGetMdlByteCount(curr_mdl);
      if (!MmGetMdlByteOffset(Mdl) && (PtrToUlong(CurrentVa) & (PAGE_SIZE - 1)))
        offset = (PtrToUlong(CurrentVa) & (PAGE_SIZE - 1));
      else
        offset = MmGetMdlByteOffset(curr_mdl);
      for (i = 0; i < ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(curr_mdl), MmGetMdlByteCount(curr_mdl)); i++)
      {
//KdPrint((__DRIVER_NAME "     element = %d\n", sg_element));
//KdPrint((__DRIVER_NAME "     remaining = %d\n", remaining));
        pfn = MmGetMdlPfnArray(curr_mdl)[i];
        ASSERT(pfn);
        gref = (grant_ref_t)GntTbl_GrantAccess(xpdd, 0, pfn, FALSE, INVALID_GRANT_REF);
        ASSERT(gref != INVALID_GRANT_REF);
        sglist->Elements[sg_element].Address.QuadPart = (LONGLONG)(gref << PAGE_SHIFT) | offset;
        sglist->Elements[sg_element].Length = min(min(PAGE_SIZE - offset, remaining), total_remaining);
        total_remaining -= sglist->Elements[sg_element].Length;
        remaining -= sglist->Elements[sg_element].Length;
        offset = 0;
        sg_element++;
      }
    }
    break;
  case MAP_TYPE_REMAPPED:
    sg_extra->aligned_buffer = ExAllocatePoolWithTag(NonPagedPool, max(Length, PAGE_SIZE), XENPCI_POOL_TAG);
    ASSERT(sg_extra->aligned_buffer); /* lazy */
    KdPrint((__DRIVER_NAME "     MAP_TYPE_REMAPPED - %p -> %p\n", CurrentVa, sg_extra->aligned_buffer));
    sg_extra->unaligned_buffer = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(sg_extra->unaligned_buffer); /* lazy */
    if (!MmGetMdlByteOffset(Mdl) && (PtrToUlong(CurrentVa) & (PAGE_SIZE - 1)))
      sg_extra->unaligned_buffer = (PUCHAR)sg_extra->unaligned_buffer + (PtrToUlong(CurrentVa) & (PAGE_SIZE - 1));
    sg_extra->copy_length = Length;
    if (WriteToDevice)
      memcpy(sg_extra->aligned_buffer, sg_extra->unaligned_buffer, sg_extra->copy_length);
    for (sg_element = 0, remaining = Length; 
      sg_element < ADDRESS_AND_SIZE_TO_SPAN_PAGES(sg_extra->aligned_buffer, Length); sg_element++)
    {
      pfn = (PFN_NUMBER)(MmGetPhysicalAddress((PUCHAR)sg_extra->aligned_buffer + (sg_element << PAGE_SHIFT)).QuadPart >> PAGE_SHIFT);
      ASSERT(pfn);
      gref = (grant_ref_t)GntTbl_GrantAccess(xpdd, 0, pfn, FALSE, INVALID_GRANT_REF);
      ASSERT(gref);
      sglist->Elements[sg_element].Address.QuadPart = (ULONGLONG)gref << PAGE_SHIFT;
      sglist->Elements[sg_element].Length = min(PAGE_SIZE, remaining);
      remaining -= sglist->Elements[sg_element].Length;
    }
    break;
  case MAP_TYPE_VIRTUAL:
    KdPrint((__DRIVER_NAME "     MAP_TYPE_VIRTUAL\n"));
    ptr = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(ptr); /* lazy */
    if (!MmGetMdlByteOffset(Mdl) && (PtrToUlong(CurrentVa) & (PAGE_SIZE - 1)))
      ptr += (PtrToUlong(CurrentVa) & (PAGE_SIZE - 1));
    sglist->Elements[0].Address.QuadPart = (ULONGLONG)ptr;
    sglist->Elements[0].Length = Length;
    break;
  }
#if 0
  KdPrint((__DRIVER_NAME "     Mdl = %p, CurrentVa = %p, Mdl->Va = %p, Offset = %d, Length = %d\n", 
    Mdl, CurrentVa, MmGetMdlVirtualAddress(Mdl), MmGetMdlByteOffset(Mdl), Length));
  for (i = 0; i < sglist->NumberOfElements; i++)
  {
    KdPrint((__DRIVER_NAME "     sge[%d]->Address = %08x%08x, Length = %d\n", i, sglist->Elements[i].Address.HighPart,
      sglist->Elements[i].Address.LowPart, sglist->Elements[i].Length));
  }
#endif
  ExecutionRoutine(DeviceObject, DeviceObject->CurrentIrp, ScatterGatherBuffer, Context);

  //FUNCTION_EXIT();
  
  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_DOP_BuildMdlFromScatterGatherList(
  PDMA_ADAPTER DmaAdapter,
  PSCATTER_GATHER_LIST ScatterGather,
  PMDL OriginalMdl,
  PMDL *TargetMdl)
{
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(ScatterGather);
  UNREFERENCED_PARAMETER(OriginalMdl);
  UNREFERENCED_PARAMETER(TargetMdl);

  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return STATUS_UNSUCCESSFUL;
}

static PDMA_ADAPTER
XenPci_BIS_GetDmaAdapter(PVOID context, PDEVICE_DESCRIPTION device_description, PULONG number_of_map_registers)
{
  xen_dma_adapter_t *xen_dma_adapter;
  PDEVICE_OBJECT curr, prev;
  PDRIVER_OBJECT fdo_driver_object;
  PVOID fdo_driver_extension;
  
  UNREFERENCED_PARAMETER(device_description);
  
  FUNCTION_ENTER();

  KdPrint((__DRIVER_NAME "     IRQL = %d\n", KeGetCurrentIrql()));
  KdPrint((__DRIVER_NAME "     Device Description = %p:\n", device_description));
  KdPrint((__DRIVER_NAME "      Version  = %d\n", device_description->Version));
  KdPrint((__DRIVER_NAME "      Master = %d\n", device_description->Master));
  KdPrint((__DRIVER_NAME "      ScatterGather = %d\n", device_description->ScatterGather));
  KdPrint((__DRIVER_NAME "      DemandMode = %d\n", device_description->DemandMode));
  KdPrint((__DRIVER_NAME "      AutoInitialize = %d\n", device_description->AutoInitialize));
  KdPrint((__DRIVER_NAME "      Dma32BitAddresses = %d\n", device_description->Dma32BitAddresses));
  KdPrint((__DRIVER_NAME "      IgnoreCount = %d\n", device_description->IgnoreCount));
  KdPrint((__DRIVER_NAME "      Dma64BitAddresses = %d\n", device_description->Dma64BitAddresses));
  KdPrint((__DRIVER_NAME "      BusNumber = %d\n", device_description->BusNumber));
  KdPrint((__DRIVER_NAME "      DmaChannel = %d\n", device_description->DmaChannel));
  KdPrint((__DRIVER_NAME "      InterfaceType = %d\n", device_description->InterfaceType));
  KdPrint((__DRIVER_NAME "      DmaWidth = %d\n", device_description->DmaWidth));
  KdPrint((__DRIVER_NAME "      DmaSpeed = %d\n", device_description->DmaSpeed));
  KdPrint((__DRIVER_NAME "      MaximumLength = %d\n", device_description->MaximumLength));
  KdPrint((__DRIVER_NAME "      DmaPort = %d\n", device_description->DmaPort));
  
/*
we have to allocate PAGE_SIZE bytes here because Windows thinks this is
actually an ADAPTER_OBJECT, and then the verifier crashes because
Windows accessed beyond the end of the structure :(
*/
  xen_dma_adapter = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);
  RtlZeroMemory(xen_dma_adapter, PAGE_SIZE);
  xen_dma_adapter->dma_adapter.Version = 2;
  xen_dma_adapter->dma_adapter.Size = sizeof(DMA_ADAPTER); //xen_dma_adapter_t);
  xen_dma_adapter->dma_adapter.DmaOperations = ExAllocatePoolWithTag(NonPagedPool, sizeof(DMA_OPERATIONS), XENPCI_POOL_TAG);
  //xen_dma_adapter->dma_adapter.DmaOperations = &xen_dma_adapter->dma_operations;
  xen_dma_adapter->dma_adapter.DmaOperations->Size = sizeof(DMA_OPERATIONS);
  xen_dma_adapter->dma_adapter.DmaOperations->PutDmaAdapter = XenPci_DOP_PutDmaAdapter;
  xen_dma_adapter->dma_adapter.DmaOperations->AllocateCommonBuffer = XenPci_DOP_AllocateCommonBuffer;
  xen_dma_adapter->dma_adapter.DmaOperations->FreeCommonBuffer = XenPci_DOP_FreeCommonBuffer;
  xen_dma_adapter->dma_adapter.DmaOperations->AllocateAdapterChannel = XenPci_DOP_AllocateAdapterChannel;
  xen_dma_adapter->dma_adapter.DmaOperations->FlushAdapterBuffers = XenPci_DOP_FlushAdapterBuffers;
  xen_dma_adapter->dma_adapter.DmaOperations->FreeAdapterChannel = XenPci_DOP_FreeAdapterChannel;
  xen_dma_adapter->dma_adapter.DmaOperations->FreeMapRegisters = XenPci_DOP_FreeMapRegisters;
  xen_dma_adapter->dma_adapter.DmaOperations->MapTransfer = XenPci_DOP_MapTransfer;
  xen_dma_adapter->dma_adapter.DmaOperations->GetDmaAlignment = XenPci_DOP_GetDmaAlignment;
  xen_dma_adapter->dma_adapter.DmaOperations->ReadDmaCounter = XenPci_DOP_ReadDmaCounter;
  xen_dma_adapter->dma_adapter.DmaOperations->GetScatterGatherList = XenPci_DOP_GetScatterGatherList;
  xen_dma_adapter->dma_adapter.DmaOperations->PutScatterGatherList = XenPci_DOP_PutScatterGatherList;
  xen_dma_adapter->dma_adapter.DmaOperations->CalculateScatterGatherList = XenPci_DOP_CalculateScatterGatherList;
  xen_dma_adapter->dma_adapter.DmaOperations->BuildScatterGatherList = XenPci_DOP_BuildScatterGatherList;
  xen_dma_adapter->dma_adapter.DmaOperations->BuildMdlFromScatterGatherList = XenPci_DOP_BuildMdlFromScatterGatherList;
  xen_dma_adapter->xppdd = context;
  xen_dma_adapter->dma_extension = NULL;

  KdPrint((__DRIVER_NAME "     About to call IoGetAttachedDeviceReference\n"));
  curr = IoGetAttachedDeviceReference(xen_dma_adapter->xppdd->common.pdo);
  KdPrint((__DRIVER_NAME "     Before start of loop - curr = %p\n", curr));
  while (curr != NULL)
  {
    fdo_driver_object = curr->DriverObject;
    KdPrint((__DRIVER_NAME "     fdo_driver_object = %p\n", fdo_driver_object));
    if (fdo_driver_object)
    {
      fdo_driver_extension = IoGetDriverObjectExtension(fdo_driver_object, UlongToPtr(XEN_DMA_DRIVER_EXTENSION_MAGIC));
      if (fdo_driver_extension)
      {
        xen_dma_adapter->dma_extension = (dma_driver_extension_t *)fdo_driver_extension;
        ObDereferenceObject(curr);
        break;
      }
    }
    prev = curr;
    curr = IoGetLowerDeviceObject(curr);
    ObDereferenceObject(prev);
  }
  KdPrint((__DRIVER_NAME "     End of loop\n"));

  *number_of_map_registers = 1024; //1024; /* why not... */

  FUNCTION_EXIT();

  return &xen_dma_adapter->dma_adapter;
}

static ULONG
XenPci_BIS_SetBusData(PVOID context, ULONG data_type, PVOID buffer, ULONG offset, ULONG length)
{
  UNREFERENCED_PARAMETER(context);
  UNREFERENCED_PARAMETER(data_type);
  UNREFERENCED_PARAMETER(buffer);
  UNREFERENCED_PARAMETER(offset);
  UNREFERENCED_PARAMETER(length);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return 0;
}

static ULONG
XenPci_BIS_GetBusData(PVOID context, ULONG data_type, PVOID buffer, ULONG offset, ULONG length)
{
  UNREFERENCED_PARAMETER(context);
  UNREFERENCED_PARAMETER(data_type);
  UNREFERENCED_PARAMETER(buffer);
  UNREFERENCED_PARAMETER(offset);
  UNREFERENCED_PARAMETER(length);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  return 0;
}

static NTSTATUS
XenPci_QueryInterface(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  PBUS_INTERFACE_STANDARD bis;
  PGUID guid;

  FUNCTION_ENTER();

  stack = IoGetCurrentIrpStackLocation(irp);

  if (memcmp(stack->Parameters.QueryInterface.InterfaceType, &GUID_BUS_INTERFACE_STANDARD, sizeof(GUID_BUS_INTERFACE_STANDARD)) == 0)
  {
    KdPrint((__DRIVER_NAME "      GUID_BUS_INTERFACE_STANDARD\n"));
    if (stack->Parameters.QueryInterface.Size < sizeof(BUS_INTERFACE_STANDARD))
    {
      KdPrint((__DRIVER_NAME "      buffer too small\n"));
      status = STATUS_INVALID_PARAMETER;
      FUNCTION_EXIT();
      return status;
    }
    if (stack->Parameters.QueryInterface.Version != 1)
    {
      KdPrint((__DRIVER_NAME "      incorrect version %d\n", stack->Parameters.QueryInterface.Version));
      status = STATUS_INVALID_PARAMETER;
      FUNCTION_EXIT();
      return status;
    }
    bis = (PBUS_INTERFACE_STANDARD)stack->Parameters.QueryInterface.Interface;
    bis->Size = sizeof(BUS_INTERFACE_STANDARD);
    bis->Version = 1; //BUS_INTERFACE_STANDARD_VERSION;
    bis->Context = xppdd;
    bis->InterfaceReference = XenPci_IS_InterfaceReference;
    bis->InterfaceDereference = XenPci_IS_InterfaceReference;
    bis->TranslateBusAddress = XenPci_BIS_TranslateBusAddress;
    bis->GetDmaAdapter = XenPci_BIS_GetDmaAdapter;
    bis->SetBusData = XenPci_BIS_SetBusData;
    bis->GetBusData = XenPci_BIS_GetBusData;
    status = STATUS_SUCCESS;
    FUNCTION_EXIT();
    return status;
  }
  else
  {
    guid = (PGUID)stack->Parameters.QueryInterface.InterfaceType;
    KdPrint((__DRIVER_NAME "      Unknown GUID %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
    guid->Data1, (ULONG)guid->Data2, (ULONG)guid->Data3, (ULONG)guid->Data4[0], (ULONG)guid->Data4[1],
    (ULONG)guid->Data4[2], (ULONG)guid->Data4[3], (ULONG)guid->Data4[4], (ULONG)guid->Data4[5],
    (ULONG)guid->Data4[6], (ULONG)guid->Data4[7]));
    status = irp->IoStatus.Status;
    FUNCTION_EXIT();
    return status;
  }
}

NTSTATUS
XenPci_Pnp_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;
  PIO_STACK_LOCATION stack;
  PXENPCI_PDO_DEVICE_DATA xppdd = (PXENPCI_PDO_DEVICE_DATA)device_object->DeviceExtension;
  //PXENPCI_DEVICE_DATA xpdd = xppdd->bus_fdo->DeviceExtension;
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
    SET_PNP_STATE(&xppdd->common, RemovePending);
    status = STATUS_SUCCESS;
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
    pbi->LegacyBusType = PNPBus; //Internal;
    pbi->BusNumber = 0;
    irp->IoStatus.Information = (ULONG_PTR)pbi;
    status = STATUS_SUCCESS;
    break;

  case IRP_MN_QUERY_INTERFACE:
    status = XenPci_QueryInterface(device_object, irp);
    break;
    
  case IRP_MN_QUERY_RESOURCES:
    KdPrint((__DRIVER_NAME "     IRP_MN_QUERY_RESOURCES (status = %08x)\n", irp->IoStatus.Status));
    status = irp->IoStatus.Status;
#if 0    
    crl = (PCM_RESOURCE_LIST)ExAllocatePoolWithTag(PagedPool, sizeof(CM_RESOURCE_LIST) - sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) + sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * 2, XENPCI_POOL_TAG);
    crl->Count = 1;
    crl->List[0].InterfaceType = PNPBus;
    crl->List[0].BusNumber = 0;
    crl->List[0].PartialResourceList.Version = 1;
    crl->List[0].PartialResourceList.Revision = 1;
    crl->List[0].PartialResourceList.Count = 0;

    prd = &crl->List[0].PartialResourceList.PartialDescriptors[crl->List[0].PartialResourceList.Count++];
    prd->Type = CmResourceTypeInterrupt;
    prd->ShareDisposition = CmResourceShareShared;
    prd->Flags = (xpdd->irq_mode == Latched)?CM_RESOURCE_INTERRUPT_LATCHED:CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
    prd->u.Interrupt.Level = xpdd->irq_number;
    prd->u.Interrupt.Vector = xpdd->irq_number;
    prd->u.Interrupt.Affinity = (KAFFINITY)-1;
    
    prd = &crl->List[0].PartialResourceList.PartialDescriptors[crl->List[0].PartialResourceList.Count++];
    prd->Type = CmResourceTypeMemory;
    prd->ShareDisposition = CmResourceShareShared;
    prd->Flags = CM_RESOURCE_MEMORY_READ_WRITE | CM_RESOURCE_MEMORY_CACHEABLE;
    prd->u.Memory.Start = xpdd->platform_mmio_addr;
    prd->u.Memory.Length = 0;
    
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
XenPci_Irp_Write_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
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

DDKAPI NTSTATUS
XenPci_SystemControl_Pdo(PDEVICE_OBJECT device_object, PIRP irp)
{
  NTSTATUS status;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();
  
  status = irp->IoStatus.Status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  
  FUNCTION_EXIT();

  return status;
}
#endif
