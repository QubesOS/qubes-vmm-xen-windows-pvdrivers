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
  ULONG copy_length;
  PMDL mdl;
  PVOID currentva;
  BOOLEAN allocated_by_me;
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
  gref = (grant_ref_t)GntTbl_GrantAccess(xpdd, 0, (ULONG)pfn, FALSE, INVALID_GRANT_REF);
  ASSERT(gref != INVALID_GRANT_REF); /* lazy */
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
  if (!map_register_base)
  {
    /* i'm not sure if this is ideal here, but NDIS definitely does it */
    return;
  }
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
  ASSERT(map_register_base);
  ASSERT(map_register_base->count < map_register_base->total_map_registers);
  
  if (xen_dma_adapter->dma_extension)
  {
    if (xen_dma_adapter->dma_extension->need_virtual_address && xen_dma_adapter->dma_extension->need_virtual_address(device_object->CurrentIrp))
    {
      map_register->map_type = MAP_TYPE_VIRTUAL;
    }
    else
    {
      if (xen_dma_adapter->dma_extension->get_alignment)
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
    mdl_offset = (ULONG)((UINT_PTR)CurrentVa - (UINT_PTR)MmGetMdlVirtualAddress(mdl));
    page_offset = PtrToUlong(CurrentVa) & (PAGE_SIZE - 1);
    *Length = min(*Length, PAGE_SIZE - page_offset);
    pfn_index = (ULONG)(((UINT_PTR)CurrentVa >> PAGE_SHIFT) - ((UINT_PTR)MmGetMdlVirtualAddress(mdl) >> PAGE_SHIFT));
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
    mdl_offset = (ULONG)((UINT_PTR)CurrentVa - (UINT_PTR)MmGetMdlVirtualAddress(mdl));
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

static VOID
XenPci_DOP_PutScatterGatherList(
    IN PDMA_ADAPTER DmaAdapter,
    IN PSCATTER_GATHER_LIST sg_list,
    IN BOOLEAN WriteToDevice
    )
{
  xen_dma_adapter_t *xen_dma_adapter;
  PXENPCI_DEVICE_DATA xpdd;
  ULONG i;
  sg_extra_t *sg_extra;
  PMDL curr_mdl;
  ULONG offset;
  BOOLEAN active;

  UNREFERENCED_PARAMETER(WriteToDevice);
  
  //FUNCTION_ENTER();

  xen_dma_adapter = (xen_dma_adapter_t *)DmaAdapter;
  ASSERT(xen_dma_adapter);
  xpdd = GetXpdd(xen_dma_adapter->xppdd->wdf_device_bus_fdo);
  
  sg_extra = (sg_extra_t *)((PUCHAR)sg_list + FIELD_OFFSET(SCATTER_GATHER_LIST, Elements) +
    (sizeof(SCATTER_GATHER_ELEMENT)) * sg_list->NumberOfElements);

  switch (sg_extra->map_type)
  {
  case MAP_TYPE_REMAPPED:
    for (i = 0; i < sg_list->NumberOfElements; i++)
    {
      grant_ref_t gref;
      gref = (grant_ref_t)(sg_list->Elements[i].Address.QuadPart >> PAGE_SHIFT);
      GntTbl_EndAccess(xpdd, gref, FALSE);
      sg_list->Elements[i].Address.QuadPart = -1;
    }
    ASSERT(sg_extra->mdl);
    if (!WriteToDevice)
    {
      for (curr_mdl = sg_extra->mdl, offset = 0, active = FALSE; curr_mdl; curr_mdl = curr_mdl->Next)
      {
        PVOID mdl_start_va = MmGetMdlVirtualAddress(curr_mdl);
        ULONG mdl_byte_count = MmGetMdlByteCount(curr_mdl);
        ULONG mdl_offset = 0;
        /* need to use <= va + len - 1 to avoid ptr wraparound */
        if ((UINT_PTR)sg_extra->currentva >= (UINT_PTR)mdl_start_va && (UINT_PTR)sg_extra->currentva <= (UINT_PTR)mdl_start_va + mdl_byte_count - 1)
        {
          active = TRUE;
          mdl_byte_count -= (ULONG)((UINT_PTR)sg_extra->currentva - (UINT_PTR)mdl_start_va);
          mdl_offset = (ULONG)((UINT_PTR)sg_extra->currentva - (UINT_PTR)mdl_start_va);
          mdl_start_va = sg_extra->currentva;
        }
        if (active)
        {
          PVOID unaligned_buffer;
          unaligned_buffer = MmGetSystemAddressForMdlSafe(curr_mdl, NormalPagePriority);
          ASSERT(unaligned_buffer); /* lazy */
          memcpy((PUCHAR)unaligned_buffer + mdl_offset, (PUCHAR)sg_extra->aligned_buffer + offset, mdl_byte_count);
          offset += mdl_byte_count;
        }
      }
    }
    ExFreePoolWithTag(sg_extra->aligned_buffer, XENPCI_POOL_TAG);
    break;
  case MAP_TYPE_MDL:
    for (i = 0; i < sg_list->NumberOfElements; i++)
    {
      grant_ref_t gref;
      gref = (grant_ref_t)(sg_list->Elements[i].Address.QuadPart >> PAGE_SHIFT);
      GntTbl_EndAccess(xpdd, gref, FALSE);
      sg_list->Elements[i].Address.QuadPart = -1;
    }
    break;
  case MAP_TYPE_VIRTUAL:
    break;
  }
  if (sg_extra->allocated_by_me)
    ExFreePoolWithTag(sg_list, XENPCI_POOL_TAG);
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
  xen_dma_adapter_t *xen_dma_adapter;
  ULONG elements;
  PMDL curr_mdl;
  
  UNREFERENCED_PARAMETER(CurrentVa);
    
  //FUNCTION_ENTER();
  
  //KdPrint((__DRIVER_NAME "     Mdl = %p\n", Mdl));
  //KdPrint((__DRIVER_NAME "     CurrentVa = %p\n", CurrentVa));
  //KdPrint((__DRIVER_NAME "     Length = %d\n", Length));

  xen_dma_adapter = (xen_dma_adapter_t *)DmaAdapter;

  if (Mdl)
  {
    //if (CurrentVa != MmGetMdlVirtualAddress(Mdl))
    //{
    //  KdPrint((__DRIVER_NAME "     CurrentVa (%p) != MdlVa (%p)\n", CurrentVa, MmGetMdlVirtualAddress(Mdl)));
    //

    //KdPrint((__DRIVER_NAME "     CurrentVa = %p, MdlVa = %p\n", CurrentVa, MmGetMdlVirtualAddress(Mdl)));

    for (curr_mdl = Mdl, elements = 0; curr_mdl; curr_mdl = curr_mdl->Next)
    {
      //KdPrint((__DRIVER_NAME "     curr_mdlVa = %p, curr_mdl size = %d\n", MmGetMdlVirtualAddress(curr_mdl), MmGetMdlByteCount(curr_mdl)));
      elements += ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(curr_mdl), MmGetMdlByteCount(curr_mdl));
    }
  }
  else
  {
    elements = ADDRESS_AND_SIZE_TO_SPAN_PAGES(0, Length); // + 1;
  }

  if (elements > xen_dma_adapter->adapter_object.MapRegistersPerChannel)
  {
    //KdPrint((__DRIVER_NAME "     elements = %d - too many\n", elements));
    if (NumberOfMapRegisters)
      *NumberOfMapRegisters = 0;
    *ScatterGatherListSize = 0;
    
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  
  *ScatterGatherListSize = FIELD_OFFSET(SCATTER_GATHER_LIST, Elements)
    + sizeof(SCATTER_GATHER_ELEMENT) * elements
    + sizeof(sg_extra_t);
  if (NumberOfMapRegisters)
    *NumberOfMapRegisters = elements;

  //KdPrint((__DRIVER_NAME "     ScatterGatherListSize = %d, NumberOfMapRegisters = %d\n", *ScatterGatherListSize, elements));

  //FUNCTION_EXIT();
  return STATUS_SUCCESS;
}

static NTSTATUS
XenPci_DOP_BuildScatterGatherListButDontExecute(
  IN PDMA_ADAPTER DmaAdapter,
  IN PDEVICE_OBJECT DeviceObject,
  IN PMDL Mdl,
  IN PVOID CurrentVa,
  IN ULONG Length,
  IN BOOLEAN WriteToDevice,
  IN PVOID ScatterGatherBuffer,
  IN ULONG ScatterGatherBufferLength,
  BOOLEAN allocated_by_me)
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
  BOOLEAN active;
  PVOID mdl_start_va;
  ULONG mdl_byte_count;
  ULONG mdl_offset;
  ULONG remapped_bytes = 0;
  
  //FUNCTION_ENTER();
  
  if (!ScatterGatherBuffer)
  {
    KdPrint((__DRIVER_NAME "     NULL ScatterGatherBuffer\n"));
    return STATUS_INVALID_PARAMETER;
  }
  //if (MmGetMdlVirtualAddress(Mdl) != CurrentVa)
  //{
  //  KdPrint((__DRIVER_NAME "     MmGetMdlVirtualAddress = %p, CurrentVa = %p, Length = %d\n", MmGetMdlVirtualAddress(Mdl), CurrentVa, Length));
  //}

  xen_dma_adapter = (xen_dma_adapter_t *)DmaAdapter;
  xpdd = GetXpdd(xen_dma_adapter->xppdd->wdf_device_bus_fdo);

  ASSERT(Mdl);
  
  if (xen_dma_adapter->dma_extension)
  {
    if (xen_dma_adapter->dma_extension->need_virtual_address && xen_dma_adapter->dma_extension->need_virtual_address(DeviceObject->CurrentIrp))
    {
      ASSERT(!Mdl->Next); /* can only virtual a single buffer */
      //ASSERT(MmGetMdlVirtualAddress(Mdl) == CurrentVa);
      map_type = MAP_TYPE_VIRTUAL;
      sglist->NumberOfElements = 1;
    }
    else
    {
      if (xen_dma_adapter->dma_extension->get_alignment)
      {
        ULONG alignment = xen_dma_adapter->dma_extension->get_alignment(DeviceObject->CurrentIrp);

        map_type = MAP_TYPE_MDL;
        sglist->NumberOfElements = 0;
        for (curr_mdl = Mdl, remapped_bytes = 0, active = FALSE; curr_mdl; curr_mdl = curr_mdl->Next)
        {
          mdl_start_va = MmGetMdlVirtualAddress(curr_mdl);
          mdl_byte_count = MmGetMdlByteCount(curr_mdl);
          /* need to use <= va + len - 1 to avoid ptr wraparound */
          if ((UINT_PTR)CurrentVa >= (UINT_PTR)mdl_start_va && (UINT_PTR)CurrentVa <= (UINT_PTR)mdl_start_va + mdl_byte_count - 1)
          {
            active = TRUE;
            mdl_byte_count -= (ULONG)((UINT_PTR)CurrentVa - (UINT_PTR)mdl_start_va);
            mdl_start_va = CurrentVa;
          }
          if (active)
          {
            if (((UINT_PTR)mdl_start_va & (alignment - 1)) || (mdl_byte_count & (alignment - 1)))
              map_type = MAP_TYPE_REMAPPED;
            remapped_bytes += mdl_byte_count;
          }
        }
        sglist->NumberOfElements += ADDRESS_AND_SIZE_TO_SPAN_PAGES(NULL, remapped_bytes);
      }
      else
      {
        map_type = MAP_TYPE_MDL;
      }
    }
  }
  else
  {
    map_type = MAP_TYPE_MDL;
  }
  if (map_type == MAP_TYPE_MDL)
  {    
    for (curr_mdl = Mdl, sglist->NumberOfElements = 0, total_remaining = Length, active = FALSE; total_remaining > 0; curr_mdl = curr_mdl->Next)
    {
      ASSERT(curr_mdl);
      mdl_start_va = MmGetMdlVirtualAddress(curr_mdl);
      mdl_byte_count = MmGetMdlByteCount(curr_mdl);
      /* need to use <= va + len - 1 to avoid ptr wraparound */
      if ((UINT_PTR)CurrentVa >= (UINT_PTR)mdl_start_va && (UINT_PTR)CurrentVa <= (UINT_PTR)mdl_start_va + mdl_byte_count - 1)
      {
        active = TRUE;
        mdl_byte_count -= (ULONG)((UINT_PTR)CurrentVa - (UINT_PTR)mdl_start_va);
        mdl_start_va = CurrentVa;
      }
      mdl_byte_count = min(mdl_byte_count, total_remaining);
      if (active && mdl_byte_count)
      {
        sglist->NumberOfElements += ADDRESS_AND_SIZE_TO_SPAN_PAGES(
          mdl_start_va, mdl_byte_count);
        total_remaining -= mdl_byte_count;
      }
    }
  }
  if (ScatterGatherBufferLength < FIELD_OFFSET(SCATTER_GATHER_LIST, Elements) +
    sizeof(SCATTER_GATHER_ELEMENT) * sglist->NumberOfElements + sizeof(sg_extra_t))
  {
    //KdPrint((__DRIVER_NAME "     STATUS_BUFFER_TOO_SMALL (%d < %d)\n", ScatterGatherBufferLength, FIELD_OFFSET(SCATTER_GATHER_LIST, Elements) +
    //  sizeof(SCATTER_GATHER_ELEMENT) * sglist->NumberOfElements + sizeof(sg_extra_t)));
    return STATUS_BUFFER_TOO_SMALL;
  }
  
  sg_extra = (sg_extra_t *)((PUCHAR)sglist + FIELD_OFFSET(SCATTER_GATHER_LIST, Elements) +
    (sizeof(SCATTER_GATHER_ELEMENT)) * sglist->NumberOfElements);

  sg_extra->allocated_by_me = allocated_by_me;
  
  sg_extra->map_type = map_type;
  switch (map_type)
  {
  case MAP_TYPE_MDL:
    //KdPrint((__DRIVER_NAME "     MAP_TYPE_MDL - %p\n", MmGetMdlVirtualAddress(Mdl)));
    total_remaining = Length;
    for (sg_element = 0, curr_mdl = Mdl, active = FALSE; total_remaining > 0; curr_mdl = curr_mdl->Next)
    {
      ASSERT(curr_mdl);
      mdl_start_va = MmGetMdlVirtualAddress(curr_mdl);
      mdl_byte_count = MmGetMdlByteCount(curr_mdl);
      /* need to use <= va + len - 1 to avoid ptr wraparound */
      if ((UINT_PTR)CurrentVa >= (UINT_PTR)mdl_start_va && (UINT_PTR)CurrentVa <= (UINT_PTR)mdl_start_va + mdl_byte_count - 1)
      {
        active = TRUE;
        mdl_byte_count -= (ULONG)((UINT_PTR)CurrentVa - (UINT_PTR)mdl_start_va);
        mdl_start_va = CurrentVa;
      }
      if (active && mdl_byte_count)
      {
        ULONG pfn_offset;
        remaining = min(mdl_byte_count, total_remaining);
        offset = (ULONG)((UINT_PTR)mdl_start_va & (PAGE_SIZE - 1));
        pfn_offset = (ULONG)(((UINT_PTR)mdl_start_va >> PAGE_SHIFT) - ((UINT_PTR)MmGetMdlVirtualAddress(curr_mdl) >> PAGE_SHIFT));
        //for (i = 0; i < ADDRESS_AND_SIZE_TO_SPAN_PAGES(mdl_start_va, mdl_byte_count); i++)
        for (i = 0; remaining > 0; i++)
        {
          pfn = MmGetMdlPfnArray(curr_mdl)[pfn_offset + i];
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
    }
    if (sg_element != sglist->NumberOfElements)
    {
      KdPrint((__DRIVER_NAME "     sg_element = %d, sglist->NumberOfElements = %d\n", sg_element, sglist->NumberOfElements));
      KdPrint((__DRIVER_NAME "     CurrentVa = %p, Length = %d\n", CurrentVa, Length));
for (curr_mdl = Mdl; curr_mdl; curr_mdl = curr_mdl->Next)
{
  KdPrint((__DRIVER_NAME "     Mdl = %p, VirtualAddress = %p, ByteCount = %d\n", Mdl, MmGetMdlVirtualAddress(curr_mdl), MmGetMdlByteCount(curr_mdl)));
}
    }
    ASSERT(sg_element == sglist->NumberOfElements);
    break;
  case MAP_TYPE_REMAPPED:
    sg_extra->aligned_buffer = ExAllocatePoolWithTag(NonPagedPool, max(remapped_bytes, PAGE_SIZE), XENPCI_POOL_TAG);
    if (!sg_extra->aligned_buffer)
    {
      KdPrint((__DRIVER_NAME "     MAP_TYPE_REMAPPED buffer allocation failed - requested va = %p, length = %d\n", MmGetMdlVirtualAddress(Mdl), remapped_bytes));
      return STATUS_INSUFFICIENT_RESOURCES;
    }
    //KdPrint((__DRIVER_NAME "     MAP_TYPE_REMAPPED - %p\n", sg_extra->aligned_buffer));
    sg_extra->mdl = Mdl;
    sg_extra->currentva = CurrentVa;
    sg_extra->copy_length = remapped_bytes;

    if (WriteToDevice)
    {
      for (curr_mdl = Mdl, offset = 0, active = FALSE; curr_mdl; curr_mdl = curr_mdl->Next)
      {
        mdl_start_va = MmGetMdlVirtualAddress(curr_mdl);
        mdl_byte_count = MmGetMdlByteCount(curr_mdl);
        mdl_offset = 0;
        /* need to use <= va + len - 1 to avoid ptr wraparound */
        if ((UINT_PTR)CurrentVa >= (UINT_PTR)mdl_start_va && (UINT_PTR)CurrentVa <= (UINT_PTR)mdl_start_va + mdl_byte_count - 1)
        {
          active = TRUE;
          mdl_byte_count -= (ULONG)((UINT_PTR)CurrentVa - (UINT_PTR)mdl_start_va);
          mdl_offset = (ULONG)((UINT_PTR)CurrentVa - (UINT_PTR)mdl_start_va);
          mdl_start_va = CurrentVa;
        }
        if (active)
        {
          PVOID unaligned_buffer;
          unaligned_buffer = (PUCHAR)MmGetSystemAddressForMdlSafe(curr_mdl, NormalPagePriority);
          ASSERT(unaligned_buffer); /* lazy */
          memcpy((PUCHAR)sg_extra->aligned_buffer + offset, (PUCHAR)unaligned_buffer + mdl_offset, mdl_byte_count);
          offset += mdl_byte_count;
        }
      }
    }
    for (sg_element = 0, remaining = remapped_bytes; 
      sg_element < ADDRESS_AND_SIZE_TO_SPAN_PAGES(sg_extra->aligned_buffer, remapped_bytes); sg_element++)
    {
      pfn = (PFN_NUMBER)(MmGetPhysicalAddress((PUCHAR)sg_extra->aligned_buffer + (sg_element << PAGE_SHIFT)).QuadPart >> PAGE_SHIFT);
      ASSERT(pfn);
      gref = (grant_ref_t)GntTbl_GrantAccess(xpdd, 0, (ULONG)pfn, FALSE, INVALID_GRANT_REF);
      ASSERT(gref != INVALID_GRANT_REF);
      sglist->Elements[sg_element].Address.QuadPart = (ULONGLONG)gref << PAGE_SHIFT;
      sglist->Elements[sg_element].Length = min(PAGE_SIZE, remaining);
      remaining -= sglist->Elements[sg_element].Length;
    }
    break;
  case MAP_TYPE_VIRTUAL:
    ptr = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(ptr); /* lazy */
    sglist->Elements[0].Address.QuadPart = (ULONGLONG)ptr + ((UINT_PTR)CurrentVa - (UINT_PTR)MmGetMdlVirtualAddress(Mdl));
    sglist->Elements[0].Length = Length;
    //KdPrint((__DRIVER_NAME "     MAP_TYPE_VIRTUAL - %08x\n", sglist->Elements[0].Address.LowPart));
    break;
  default:
    KdPrint((__DRIVER_NAME "     map_type = %d\n", map_type));
    break;
  }
  //FUNCTION_EXIT();
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
  NTSTATUS status;
  
  status = XenPci_DOP_BuildScatterGatherListButDontExecute(DmaAdapter, DeviceObject, Mdl, CurrentVa, Length, WriteToDevice, ScatterGatherBuffer, ScatterGatherBufferLength, FALSE);
  
  if (NT_SUCCESS(status))
    ExecutionRoutine(DeviceObject, DeviceObject->CurrentIrp, ScatterGatherBuffer, Context);

  //FUNCTION_EXIT();
  
  return status;
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
  NTSTATUS status;
  ULONG list_size;
  ULONG map_registers;
  PSCATTER_GATHER_LIST sg_list;
  
  //FUNCTION_ENTER();

  status = XenPci_DOP_CalculateScatterGatherList(DmaAdapter, Mdl, CurrentVa, Length, &list_size, &map_registers);
  if (!NT_SUCCESS(status))
  {
    //FUNCTION_EXIT();
    return status;
  }

  sg_list = ExAllocatePoolWithTag(NonPagedPool, list_size, XENPCI_POOL_TAG);
  if (!sg_list)
  {
    KdPrint((__DRIVER_NAME "     Cannot allocate memory for sg_list\n"));
    //FUNCTION_EXIT();
    return STATUS_INSUFFICIENT_RESOURCES;
  }
    
  status = XenPci_DOP_BuildScatterGatherListButDontExecute(DmaAdapter, DeviceObject, Mdl, CurrentVa, Length, WriteToDevice, sg_list, list_size, TRUE);
  
  if (NT_SUCCESS(status))
    ExecutionRoutine(DeviceObject, DeviceObject->CurrentIrp, sg_list, Context);
  
  //FUNCTION_EXIT();
  
  return status;
}

static NTSTATUS
XenPci_DOP_BuildMdlFromScatterGatherList(
  PDMA_ADAPTER DmaAdapter,
  PSCATTER_GATHER_LIST ScatterGather,
  PMDL OriginalMdl,
  PMDL *TargetMdl)
{
  NTSTATUS status = STATUS_SUCCESS;
  UNREFERENCED_PARAMETER(DmaAdapter);
  UNREFERENCED_PARAMETER(ScatterGather);
  UNREFERENCED_PARAMETER(OriginalMdl);
  UNREFERENCED_PARAMETER(TargetMdl);

  FUNCTION_ENTER();
  
  if (OriginalMdl)
  {
    *TargetMdl = OriginalMdl;
  }
  else
  {
    *TargetMdl = NULL;
    status = STATUS_INVALID_PARAMETER;
  }
  
  FUNCTION_EXIT();
  
  return status;
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

  xen_dma_adapter->adapter_object.DmaHeader.Size = sizeof(X_ADAPTER_OBJECT); //xen_dma_adapter_t);
  xen_dma_adapter->adapter_object.MasterAdapter = NULL;
  if (xen_dma_adapter->dma_extension && xen_dma_adapter->dma_extension->max_sg_elements)
  {
    xen_dma_adapter->adapter_object.MapRegistersPerChannel = xen_dma_adapter->dma_extension->max_sg_elements;
  }
  else
  {
    xen_dma_adapter->adapter_object.MapRegistersPerChannel = 256;
  }
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

  *number_of_map_registers = xen_dma_adapter->adapter_object.MapRegistersPerChannel; //1024; /* why not... */

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

static NTSTATUS
XenPciPdo_ReconfigureCompletionRoutine(
  PDEVICE_OBJECT device_object,
  PIRP irp,
  PVOID context)
{
  UNREFERENCED_PARAMETER(device_object);
  
  if (irp->PendingReturned)
  {
    KeSetEvent ((PKEVENT)context, IO_NO_INCREMENT, FALSE);
  }
  return STATUS_MORE_PROCESSING_REQUIRED;
}

static VOID
XenPci_UpdateBackendState(PVOID context)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  ULONG new_backend_state;

  FUNCTION_ENTER();

  ExAcquireFastMutex(&xppdd->backend_state_mutex);

  new_backend_state = XenPci_ReadBackendState(xppdd);
  if (new_backend_state == XenbusStateUnknown)
  {
    if (xpdd->suspend_state != SUSPEND_STATE_NONE)
    {
      ExReleaseFastMutex(&xppdd->backend_state_mutex);
      return;
    }
    KdPrint(("Failed to read path, assuming closed\n"));
    new_backend_state = XenbusStateClosed;
  }

  if (xppdd->backend_state == new_backend_state)
  {
    KdPrint((__DRIVER_NAME "     state unchanged\n"));
    ExReleaseFastMutex(&xppdd->backend_state_mutex);
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
    KdPrint((__DRIVER_NAME "     Requesting eject\n"));
    WdfPdoRequestEject(device);
    break;

  case XenbusStateClosed:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Closed\n"));
    break;
  
  default:
    KdPrint((__DRIVER_NAME "     Backend State Changed to Undefined = %d\n", xppdd->backend_state));
    break;
  }

  KeSetEvent(&xppdd->backend_state_event, 1, FALSE);

  ExReleaseFastMutex(&xppdd->backend_state_mutex);
  FUNCTION_EXIT();

  return;
}

static VOID
XenPci_BackendStateHandler(char *path, PVOID context)
{
  UNREFERENCED_PARAMETER(path);

  /* check that path == device/id/state */
  //RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->path);

  XenPci_UpdateBackendState(context);
}

static NTSTATUS
XenPci_GetBackendAndAddWatch(WDFDEVICE device)
{
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  char path[128];
  PCHAR res;
  PCHAR value;

  FUNCTION_ENTER();
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
  XenBus_AddWatch(xpdd, XBT_NIL, path, XenPci_BackendStateHandler, device);

  FUNCTION_EXIT();  
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
XenPci_EvtChn_AckEvent(PVOID context, evtchn_port_t port, BOOLEAN *last_interrupt)
{
  WDFDEVICE device = context;
  PXENPCI_PDO_DEVICE_DATA xppdd = GetXppdd(device);
  PXENPCI_DEVICE_DATA xpdd = GetXpdd(xppdd->wdf_device_bus_fdo);
  
  return EvtChn_AckEvent(xpdd, port, last_interrupt);
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
  
  FUNCTION_ENTER();
  
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
      /* it's possible that the workitems are blocked because the pagefile isn't available. Lets just re-read the backend value for now */
      XenPci_UpdateBackendState(device);
      remaining -= thiswait;
      if (remaining == 0)
      {
        KdPrint((__DRIVER_NAME "     Timed out waiting for %d!\n", backend_state_response));
        return STATUS_UNSUCCESSFUL;
      }
      KdPrint((__DRIVER_NAME "     Still waiting for %d (currently %d)...\n", backend_state_response, xppdd->backend_state));
    }
  }
  FUNCTION_EXIT();
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
      case XEN_INIT_TYPE_EVENT_CHANNEL_DPC: /* frontend event channel bound to dpc */
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
    case XEN_INIT_TYPE_EVENT_CHANNEL_DPC: /* frontend event channel bound to dpc */
    case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ: /* frontend event channel bound to irq */
      if ((event_channel = EvtChn_AllocUnbound(xpdd, 0)) != 0)
      {
        KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_EVENT_CHANNEL - %s = %d\n", setting, event_channel));
        RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/%s", xppdd->path, setting);
        XenBus_Printf(xpdd, XBT_NIL, path, "%d", event_channel);
        ADD_XEN_INIT_RSP(&out_ptr, type, setting, UlongToPtr(event_channel), NULL);
        ADD_XEN_INIT_RSP(&xppdd->assigned_resources_ptr, type, setting, UlongToPtr(event_channel), NULL);
        if (type == XEN_INIT_TYPE_EVENT_CHANNEL_IRQ)
        {
          EvtChn_BindIrq(xpdd, event_channel, xppdd->irq_vector, path);
        }
        else if (type == XEN_INIT_TYPE_EVENT_CHANNEL_DPC)
        {
          #pragma warning(suppress:4055)
          EvtChn_BindDpc(xpdd, event_channel, (PXEN_EVTCHN_SERVICE_ROUTINE)value, value2);
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
        KdPrint((__DRIVER_NAME "     XEN_INIT_TYPE_READ_STRING - %s = <failed>\n", setting));
        XenPci_FreeMem(res);
        ADD_XEN_INIT_RSP(&out_ptr, type, setting, "", "");
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
        prd->u.Interrupt.Level = 0;       // Set group and level to zero (group = upper word)
        prd->u.Interrupt.Level = xpdd->irq_number & 0xffff; // Only set the lower word
        prd->u.Interrupt.Vector = xpdd->irq_number;
        prd->u.Interrupt.Affinity = KeQueryActiveProcessors();
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
        //xppdd->assigned_resources_start = xppdd->assigned_resources_ptr = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);
        
#if 0
        status = XenPci_XenConfigDevice(device);
        if (!NT_SUCCESS(status))
        {
          RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
          XenBus_RemWatch(xpdd, XBT_NIL, path, XenPci_BackendStateHandler, device);
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
        prd->u.Interrupt.Level = 0;       // Set group and level to zero (group = upper word)
        prd->u.Interrupt.Level = xpdd->irq_level & 0xffff; // Only set the lower word
        prd->u.Interrupt.Vector = xpdd->irq_vector;
        prd->u.Interrupt.Affinity = KeQueryActiveProcessors();
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

  if (previous_state == WdfPowerDevicePrepareForHibernation || previous_state == WdfPowerDeviceD3 || previous_state == WdfPowerDeviceD3Final)
  {
    xppdd->requested_resources_ptr = xppdd->requested_resources_start;
    xppdd->assigned_resources_start = xppdd->assigned_resources_ptr = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);
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
    XenBus_RemWatch(xpdd, XBT_NIL, path, XenPci_BackendStateHandler, device);
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
  }
  
  /* Remove watch on backend state */
  RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
  XenBus_RemWatch(xpdd, XBT_NIL, path, XenPci_BackendStateHandler, device);
  
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
  ExInitializeFastMutex(&xppdd->backend_state_mutex);
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
        case XEN_INIT_TYPE_EVENT_CHANNEL_DPC: /* frontend event channel bound to dpc */
        case XEN_INIT_TYPE_EVENT_CHANNEL_IRQ: /* frontend event channel bound to irq */
          EvtChn_Unbind(xpdd, PtrToUlong(value));
          EvtChn_Close(xpdd, PtrToUlong(value));
          break;
        }
      }
    }

    RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/state", xppdd->backend_path);
    XenBus_RemWatch(xpdd, XBT_NIL, path, XenPci_BackendStateHandler, xppdd);  
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
