/******************************************************************************
 * gntmem_device_interface.c
 *
 * Driver for pinning and granting userspace pages to other domains
 *
 * Copyright (c) 2009 Chris Smowton
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "xenpci.h"
#include <gntmem_ioctl.h>

struct grant_record
{
    LIST_ENTRY head;
    grant_ref_t* grants;
    int n_pages;
    PMDL mdl;
    int notify_offset;
    evtchn_port_t notify_port;
};

struct map_record
{
    LIST_ENTRY entry;
    PMDL mdl;
    PVOID user_va;
    PVOID kernel_va;
    grant_handle_t map_handle;
    PEPROCESS process;
    int notify_offset;
    evtchn_port_t notify_port;
};

typedef struct
{
    WDFREQUEST request;
    NTSTATUS status;
    PXENPCI_DEVICE_DATA xpdd;
} XENPCI_UNMAP_WORK_ITEM_CONTEXT, *PXENPCI_UNMAP_WORK_ITEM_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(XENPCI_UNMAP_WORK_ITEM_CONTEXT, GetUnmapContext)

typedef struct
{
    PMDL mdl;
} XENPCI_FREE_MDL_WORK_ITEM_CONTEXT, *PXENPCI_FREE_MDL_WORK_ITEM_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(XENPCI_FREE_MDL_WORK_ITEM_CONTEXT, GetFreeMdlContext)

/* The prelude to the grant-memory ioctl. Needs to:
   1. Record the process we're running in,
   2. Allocate kernel memory,
   3. Map it into userspace.
   The IOCTL can then do the actual granting, before pending forever waiting on cancellation if the thread
   is dying. On cancellation it then unmaps from userspace, handing off the ungranting task to our timer task. */

   VOID GntMem_EvtIoInCallerContext(PXENPCI_DEVICE_INTERFACE_DATA xpdid, WDFREQUEST Request, WDFDEVICE Device)
{
    WDF_REQUEST_PARAMETERS RqParams;
    struct ioctl_gntmem_grant_pages* gprq;
    NTSTATUS status;
    PXENPCI_REQUEST_DATA rqdata = GetRequestData(Request);
    PXENPCI_DEVICE_DATA xpdd = GetXpdd(Device);
    int refund_quotas = 0;

    WDF_REQUEST_PARAMETERS_INIT(&RqParams);
    WdfRequestGetParameters(Request, &RqParams);

    /* Note that we don't need to check if this is a gntmem device; that's done by XenPCI */
    if (RqParams.Type == WdfRequestTypeDeviceControl
        && RqParams.Parameters.DeviceIoControl.IoControlCode == IOCTL_GNTMEM_GRANT_PAGES)
    {
        DEBUGF("Request was a grant-pages IOCTL, attaching MDL");
        /* This checks for buffer-too-small as well as fetching the buffer pointer */
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(*gprq), (PVOID*) &gprq, NULL);
        if (NT_SUCCESS(status))
        {
            DEBUGF("...request is to pin %d pages and give them to domain %d", gprq->n_pages, gprq->domid);
            WdfSpinLockAcquire(xpdd->gntmem_quota_lock);

            if (((xpdid->gntmem.mapped_pages + gprq->n_pages) > xpdid->gntmem.allowed_pages)
                || ((xpdd->gntmem_mapped_pages + gprq->n_pages) > xpdd->gntmem_allowed_pages))
            {
                DEBUGF("refusing to map a further %d pages, as only %d are allowed and %d are taken on local device",
                       gprq->n_pages, xpdid->gntmem.allowed_pages, xpdid->gntmem.mapped_pages);
                DEBUGF("%d pages are allowed and %d mapped overall", xpdd->gntmem_mapped_pages, xpdd->gntmem_allowed_pages);
                status = STATUS_ACCESS_DENIED;
            }
            else
            {
                xpdid->gntmem.mapped_pages += gprq->n_pages;
                xpdd->gntmem_mapped_pages += gprq->n_pages;
                refund_quotas = gprq->n_pages;
                DEBUGF("accepted quota request for %d pages; now %d/%d local and %d/%d global",
                       gprq->n_pages, xpdid->gntmem.mapped_pages, xpdid->gntmem.allowed_pages,
                       xpdd->gntmem_mapped_pages, xpdd->gntmem_allowed_pages);
            }

            WdfSpinLockRelease(xpdd->gntmem_quota_lock);

            if (NT_SUCCESS(status))
            {
                PHYSICAL_ADDRESS lowaddr;
                PHYSICAL_ADDRESS highaddr;
                PHYSICAL_ADDRESS skip_bytes;

                rqdata->process = PsGetCurrentProcess();
                rqdata->mdl = 0;

                lowaddr.QuadPart = 0;
                highaddr.QuadPart = 0xFFFFFFFF;
                skip_bytes.QuadPart = 0;
                // Alright, now we must leave WDF-land, as its page-locking facilities have a mandatory
                // attachment to a WDFREQUEST, whereas for Xen granting we want to lock across multiple IRPs.
                DEBUGF("Allocating MDL and %d pages", gprq->n_pages);
                rqdata->mdl = MmAllocatePagesForMdl(lowaddr, highaddr, skip_bytes, (gprq->n_pages * PAGE_SIZE));
                DEBUGF("Success; got an MDL at 0x%Ix", rqdata->mdl);
                if ((!rqdata->mdl) || (MmGetMdlByteCount(rqdata->mdl) != ((unsigned int) (gprq->n_pages * PAGE_SIZE))))
                {
                    /* Allocate can return some but not all the pages we asked for, hence the extra check */
                    DEBUGF("gntmem: MDL not allocated or too small; dying with ENOMEM");
                    status = STATUS_NO_MEMORY;
                    if (rqdata->mdl)
                    {
                        MmFreePagesFromMdl(rqdata->mdl);
                        ExFreePool(rqdata->mdl);
                    }
                }
                else
                {
                    __try
                    {
                        DEBUGF("Mapping pages into userspace");
                        rqdata->base_vaddr = MmMapLockedPagesSpecifyCache(rqdata->mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
                        DEBUGF("Successfully mapped %d pages to user address %Ix", gprq->n_pages, rqdata->base_vaddr);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        status = GetExceptionCode();
                        DEBUGF("User mapping caused exception (0X%08X)", status);
                        MmFreePagesFromMdl(rqdata->mdl);
                        ExFreePool(rqdata->mdl);
                    }
                }
                // Okay, we have some user memory, and it's pinned down. The rest is for Evtioctl.
            }
        }

        if (!NT_SUCCESS(status))
        {
            DEBUGF("Failing a request with status 0x%08X", status);
            if (refund_quotas)
            {
                WdfSpinLockAcquire(xpdd->gntmem_quota_lock);
                DEBUGF("Refunding %d pages for a failed request", refund_quotas);
                xpdd->gntmem_mapped_pages -= refund_quotas;
                xpdid->gntmem.mapped_pages -= refund_quotas;
                WdfSpinLockRelease(xpdd->gntmem_quota_lock);
            }
            WdfRequestComplete(Request, status);
            return;
        }
    }

    DEBUGF("Queueing a request");
    // Either we successfully locked some pages, or this wasn't a GRANT_PAGES IOCTL at all
    WdfDeviceEnqueueRequest(Device, Request);
}

static void possibly_notify_unmap(struct grant_record* rec, PXENPCI_DEVICE_DATA xpdd)
{
    PVOID mapped_area;
    char *mapped_area_char;

    if (rec->notify_offset >= 0)
    {
        mapped_area = MmGetSystemAddressForMdlSafe(rec->mdl, LowPagePriority);
        if (!mapped_area)
        {
            DEBUGF("failed to map MDL for notification");
        }
        else
        {
            mapped_area_char = mapped_area;
            mapped_area_char[rec->notify_offset] = 0;
            MmUnmapLockedPages(mapped_area, rec->mdl);
        }
        rec->notify_offset = -1;
    }

    if (rec->notify_port != -1)
    {
        EvtChn_Notify(xpdd, rec->notify_port);
        rec->notify_port = (evtchn_port_t) -1;
    }
}

/* Tries to free all the grants indicated by a given grant_record, and free the grant list.
   Returns TRUE if successful; otherwise the grant list still stands and some remain to be
   ungranted. Does not touch the MDL, as freeing that would be incompatible with our current IRQL.

   Runs at <= DISPATCH_LEVEL */
static BOOLEAN try_destroy_grant_record(struct grant_record* rec, PXENPCI_DEVICE_DATA xpdd)
{
    int i;
    BOOLEAN any_failures = FALSE;

    possibly_notify_unmap(rec, xpdd);

    for (i = 0; i < rec->n_pages; i++)
    {
        if (rec->grants[i] != INVALID_GRANT_REF)
        {
            if (GntTbl_EndAccess(xpdd, rec->grants[i], FALSE, 0))
            {
                DEBUGF("successfully freed grant %d", (int) rec->grants[i]);
                rec->grants[i] = INVALID_GRANT_REF;
            }
            else
            {
                DEBUGF("couldn't free grant %d at this time", (int) rec->grants[i]);
                any_failures = TRUE;
            }
        }
    }

    if (!any_failures)
    {
        DEBUGF("Freed the entire region; releasing pages");
        WdfSpinLockAcquire(xpdd->gntmem_quota_lock);
        xpdd->gntmem_mapped_pages -= rec->n_pages;
        DEBUGF("destroyed region of %d pages; global quota now %d/%d global",
               rec->n_pages, xpdd->gntmem_mapped_pages, xpdd->gntmem_allowed_pages);
        WdfSpinLockRelease(xpdd->gntmem_quota_lock);
        ExFreePoolWithTag(rec->grants, XENPCI_POOL_TAG);
        return TRUE;
    }
    else
    {
        DEBUGF("At least one grant still outstanding from region");
        return FALSE;
    }
}

/* Runs at PASSIVE_LEVEL. Used because FreePagesFromMdl requires <= APC_LEVEL */
static VOID GntMem_EvtFreeMdlWorkItem(WDFWORKITEM work)
{
    PXENPCI_FREE_MDL_WORK_ITEM_CONTEXT work_context;

    work_context = GetFreeMdlContext(work);

    DEBUGF("Free-MDL work item: freeing MDL at 0x%Ix", work_context->mdl);

    MmFreePagesFromMdl(work_context->mdl);
    ExFreePool(work_context->mdl);

    WdfObjectDelete(work);
}

/* Runs at DISPATCH_LEVEL (from a timer) */
static VOID queue_free_mdl_work_item(PMDL mdl, PXENPCI_DEVICE_DATA xpdd)
{
    WDF_WORKITEM_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFWORKITEM new_workitem;
    NTSTATUS status;
    PXENPCI_FREE_MDL_WORK_ITEM_CONTEXT work_context;

    DEBUGF("Queueing work item to free mdl at 0x%Ix", mdl);

    WDF_WORKITEM_CONFIG_INIT(&config, GntMem_EvtFreeMdlWorkItem);
    config.AutomaticSerialization = FALSE; /* Driver functions can be at DISPATCH_LEVEL */
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, XENPCI_FREE_MDL_WORK_ITEM_CONTEXT);
    attributes.ParentObject = xpdd->wdf_device;
    status = WdfWorkItemCreate(&config, &attributes, &new_workitem);
    if (!NT_SUCCESS(status))
    {
        DEBUGF("Couldn't allocate a work item to free an MDL. Non-fatal, but leaks physical pages");
        return;
    }

    work_context = GetFreeMdlContext(new_workitem);
    work_context->mdl = mdl;

    WdfWorkItemEnqueue(new_workitem);
}

static BOOLEAN try_destroy_all_pending(PXENPCI_DEVICE_DATA xpdd)
{
    BOOLEAN all_freed = TRUE;
    struct grant_record* next_record;

    next_record = (struct grant_record*)xpdd->gntmem_pending_free_list_head.Flink;
    DEBUGF("Trying to free all pending regions");

    while (next_record != (struct grant_record*)&(xpdd->gntmem_pending_free_list_head))
    {
        if (try_destroy_grant_record(next_record, xpdd))
        {
            struct grant_record* to_destroy = next_record;
            next_record = (struct grant_record*)next_record->head.Flink;
            DEBUGF("Successfully freed a region; deleting and queueing free-MDL work item");
            queue_free_mdl_work_item(to_destroy->mdl, xpdd);
            RemoveEntryList((PLIST_ENTRY) to_destroy);
            ExFreePoolWithTag(to_destroy, XENPCI_POOL_TAG);
        }
        else
        {
            DEBUGF("A region could not be freed at this time; retaining");
            next_record = (struct grant_record*)next_record->head.Flink;
            all_freed = FALSE;
        }
    }

    if (all_freed)
    {
        DEBUGF("Successfully destroyed all pending regions");
        return TRUE;
    }
    else
    {
        DEBUGF("At least one region still pending");
        return FALSE;
    }
}

VOID GntMem_EvtTimerFunc(WDFTIMER timer)
{
    WDFDEVICE device = WdfTimerGetParentObject(timer);
    PXENPCI_DEVICE_DATA xpdd = GetXpdd(device);

    WdfSpinLockAcquire(xpdd->gntmem_pending_free_lock);

    if (try_destroy_all_pending(xpdd))
    {
        DEBUGF("Timer task successfully destroyed all remaining sections!");
        xpdd->gntmem_free_work_queued = FALSE;
        WdfTimerStop(timer, FALSE); /* FALSE = don't wait... for ourselves :) */
    }
    else
    {
        DEBUGF("Timer task left at least one region alive; running again in 10s");
        // Timer is periodic; this will happen automatically.
    }

    WdfSpinLockRelease(xpdd->gntmem_pending_free_lock);
}

static VOID queue_grant_record_for_destruction(PXENPCI_DEVICE_DATA xpdd, struct grant_record* rec)
{
    WdfSpinLockAcquire(xpdd->gntmem_pending_free_lock);
    InsertTailList(&xpdd->gntmem_pending_free_list_head, (PLIST_ENTRY) rec);
    if (!xpdd->gntmem_free_work_queued)
    {
        WdfTimerStart(xpdd->gntmem_cleanup_timer, 10 /*us*/ * 1000/*ms*/ * 1000/*s*/ * 10/*10s*/);
        xpdd->gntmem_free_work_queued = TRUE;
    }
    WdfSpinLockRelease(xpdd->gntmem_pending_free_lock);
}

/* Runs at PASSIVE_LEVEL */
static VOID GntMem_EvtUnmapWorkItem(WDFWORKITEM work)
{
    PXENPCI_UNMAP_WORK_ITEM_CONTEXT work_context;
    KAPC_STATE old_state;
    PXENPCI_REQUEST_DATA rq_context;
    struct grant_record* record;
    PMDL mdl;
    BOOLEAN grants_freed = FALSE;

    work_context = GetUnmapContext(work);
    rq_context = GetRequestData(work_context->request);

    DEBUGF("In unmap-from-userspace, trying to unmap user address 0x%Ix", rq_context->base_vaddr);

    KeStackAttachProcess(rq_context->process, &old_state);

    DEBUGF("Switched into process");

    MmUnmapLockedPages(rq_context->base_vaddr, rq_context->mdl);

    DEBUGF("Voided PTEs");

    KeUnstackDetachProcess(&old_state);

    DEBUGF("Back in system thread");

    /* Alright, the user address space is cleaned; now we can complete the request and get on with
       trying to free up the grants, and finally the kernel memory. */
    // First, grab some stuff from the request's context which we'll need
    record = rq_context->record;
    mdl = rq_context->mdl;

    DEBUGF("unmap work item completing request with status 0x%lx", (unsigned long) work_context->status);

    WdfRequestComplete(work_context->request, work_context->status);

    // Try to free grants right now, as our currently passive IRQL might enable us to dodge a second work item
    if (!record)
    { // This is the error-recovery case -- we're unmapping after a failure that came before granting
        grants_freed = TRUE;
        DEBUGF("work item gives no grant list; this must be error recovery");
    }
    else
    {
        grants_freed = try_destroy_grant_record(record, work_context->xpdd);
        DEBUGF("Tried to destroy grant record right now; returned %d", (int) grants_freed);
    }

    if (grants_freed)
    {
        DEBUGF("Freeing kernel memory from userspace-unmap work");
        // Excellent, free the kernel memory and we're done
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
        if (record)
            ExFreePoolWithTag(record, XENPCI_POOL_TAG);
    }
    else
    {
        DEBUGF("Userspace-unmap work queued grant record for destruction later");
        // Never mind, hand it over to the timer DPC, which will need another workitem to get the pages freed
        queue_grant_record_for_destruction(work_context->xpdd, record);
    }

    // Finally, free this work item
    WdfObjectDelete(work);
}

/* Runs at <= DISPATCH_LEVEL */
static VOID queue_unmap_work_item(WDFREQUEST Request, NTSTATUS status, PXENPCI_DEVICE_DATA xpdd)
{
    WDF_WORKITEM_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFWORKITEM new_workitem;
    NTSTATUS local_status;
    PXENPCI_UNMAP_WORK_ITEM_CONTEXT work_context;

    WDF_WORKITEM_CONFIG_INIT(&config, GntMem_EvtUnmapWorkItem);
    config.AutomaticSerialization = FALSE; /* Driver functions can be at DISPATCH_LEVEL */
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, XENPCI_UNMAP_WORK_ITEM_CONTEXT);
    attributes.ParentObject = xpdd->wdf_device;
    local_status = WdfWorkItemCreate(&config, &attributes, &new_workitem);
    if (!NT_SUCCESS(local_status))
    {
        DEBUGF("Couldn't allocate a work item to unmap pages from userspace. Ignoring, but expect a BSOD on process termination");
        return;
    }

    DEBUGF("Queued a work item for userspace-unmap");

    work_context = GetUnmapContext(new_workitem);
    work_context->request = Request;
    work_context->status = status;
    work_context->xpdd = xpdd;

    WdfWorkItemEnqueue(new_workitem);
}

// Needed for the process callback since it doesn't receive any context...
PXENPCI_DEVICE_DATA gntmem_xpdd_global = 0;

#pragma warning(push)
#pragma warning(disable: 4127) // conditional expression is constant (for set_xen_guest_handle)

static VOID GntMem_UnmapNotify(PXENPCI_DEVICE_DATA xpdd, struct map_record *record)
{
    DEBUGF("offset %d, port %u", record->notify_offset, record->notify_port);

    if (record->notify_offset >= 0)
    {
        ((BYTE *) record->kernel_va)[record->notify_offset] = 0;
    }

    if (record->notify_port > 0)
    {
        EvtChn_Notify(xpdd, record->notify_port);
        record->notify_port = (evtchn_port_t) -1;
    }
}

// Actual unmapping/cleanup is performed here.
// xpdd->gntmem_mapped_lock spinlock must be held.
static VOID GntMem_UnmapForeign(struct map_record *record, PEPROCESS current_process)
{
    xen_memory_reservation_t xmr;
    PFN_NUMBER pfn;
    int ret;
    BOOLEAN leak = FALSE;

    pfn = MmGetMdlPfnArray(record->mdl)[0];
    DEBUGF("process %p: freeing map handle 0x%x (record %p)", current_process, record->map_handle, record);
    DEBUGF("record: user %p, kernel %p, phys %p, handle 0x%x, mdl size: %u",
           record->user_va, record->kernel_va, MmGetPhysicalAddress(record->kernel_va), record->map_handle, record->mdl->ByteCount);

    GntMem_UnmapNotify(gntmem_xpdd_global, record);

    // unmap the page
    ret = GntTbl_UnmapForeignPage(gntmem_xpdd_global, record->map_handle, MmGetPhysicalAddress(record->kernel_va));
    if (ret != GNTST_okay)
    {
        DEBUGF("WARNING: GntTbl_UnmapForeignPage failed for handle 0x%x, leaking pages", record->map_handle);
        leak = TRUE;
        // This is not necessarily fatal, but now we can't free this page to the OS
        // because the foreign domain still controls its contents.
    }
    else
        DEBUGF("successfully unmapped map handle 0x%x", record->map_handle);

    if (!leak)
    {
        // repopulate the unmapped page with memory
        RtlZeroMemory(&xmr, sizeof(xmr));
        xmr.domid = DOMID_SELF;
        xmr.nr_extents = 1;
        set_xen_guest_handle(xmr.extent_start, &pfn);
        ret = HYPERVISOR_memory_op(gntmem_xpdd_global, XENMEM_populate_physmap, &xmr);
        if (ret != 1) // number of pages populated
        {
            DEBUGF("WARNING: XENMEM_populate_physmap failed for pfn %x (%d), leaking pages", pfn, ret);
            // Can't free the page either, OS will crash if we give it
            // a page that is not backed by physical memory.
            leak = TRUE;
        }

        DEBUGF("XENMEM_populate_physmap returned pfn %x", pfn);
    }

    // free the rest
    MmUnmapLockedPages(record->user_va, record->mdl); // undo user mapping
    IoFreeMdl(record->mdl);

    if (!leak)
        ExFreePoolWithTag(record->kernel_va, XENPCI_POOL_TAG); // page itself
    else
        DEBUGF("!!! LEAKING PAGE: va %p, pfn %x", record->kernel_va, pfn);

    RemoveEntryList((PLIST_ENTRY) record);
    ExFreePoolWithTag(record, XENPCI_POOL_TAG);
}

// Process creation/destruction notify routine.
// Used for cleaning up mapped grants done by IOCTL_GNTMEM_MAP_FOREIGN_PAGES.
// TODO: make IOCTL_GNTMEM_GRANT_PAGES use this as well, this is much easier than what it's currently doing.
// Runs at PASSIVE_LEVEL and if Create==FALSE, in the context of the process being destroyed.
VOID GntMem_ProcessCallback(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    PEPROCESS current_process;
    PLIST_ENTRY node;

    UNREFERENCED_PARAMETER(ParentId);
    UNREFERENCED_PARAMETER(ProcessId);

    // we're only interested in process destruction for cleanup purposes
    if (Create)
        return;

    current_process = PsGetCurrentProcess();

    // walk the map list, free everything that's allocated by this process and still in the list
    WdfSpinLockAcquire(gntmem_xpdd_global->gntmem_mapped_lock);
    node = gntmem_xpdd_global->gntmem_mapped_list.Flink;
    while (node->Flink != gntmem_xpdd_global->gntmem_mapped_list.Flink)
    {
        struct map_record *record = CONTAINING_RECORD(node, struct map_record, entry);

        node = node->Flink;
        if (record->process != current_process)
            continue;

        DEBUGF("cleanup from process callback");
        GntMem_UnmapForeign(record, current_process);
    }
    WdfSpinLockRelease(gntmem_xpdd_global->gntmem_mapped_lock);
}

static VOID GntMem_EvtIoDeviceControl(IN WDFQUEUE Queue, IN WDFREQUEST Request, IN size_t OutputBufferLength, IN size_t InputBufferLength, IN ULONG IoControlCode)
{
    NTSTATUS rc = STATUS_SUCCESS;
    PVOID inbuffer = 0;
    PVOID outbuffer = 0;
    ULONG info = 0;

    PXENPCI_DEVICE_DATA xpdd = GetXpdd(WdfIoQueueGetDevice(Queue));
    WDFFILEOBJECT file_object = WdfRequestGetFileObject(Request);
    PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
    PXENPCI_REQUEST_DATA xprq = GetRequestData(Request);

    DEBUGF("IOCTL 0x%x with in/out buffers %d/%d", IoControlCode, InputBufferLength, OutputBufferLength);

    /* These modes of failure can't happen for grant-pages calls, which checked their input buffer
       in caller context, and which don't have output buffers since they never return. */

    if (InputBufferLength)
    {
        rc = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inbuffer, NULL);
        if (!NT_SUCCESS(rc))
        {
            DEBUGF("IOCTL couldn't map in-buffer");
            WdfRequestCompleteWithInformation(Request, rc, 0);
            return;
        }
    }

    if (OutputBufferLength)
    {
        rc = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &outbuffer, NULL);
        if (!NT_SUCCESS(rc))
        {
            DEBUGF("IOCTL couldn't map out-buffer");
            WdfRequestCompleteWithInformation(Request, rc, 0);
            return;
        }
    }

    switch (IoControlCode)
    {
    case IOCTL_GNTMEM_SET_LOCAL_LIMIT:
    {
        struct ioctl_gntmem_set_limit* set_limit = (struct ioctl_gntmem_set_limit*)inbuffer;
        if (InputBufferLength < sizeof(*set_limit))
        {
            rc = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        DEBUGF("Setting device-local mapping quota to %d", set_limit->new_limit);
        WdfSpinLockAcquire(xpdd->gntmem_quota_lock);
        xpdid->gntmem.allowed_pages = set_limit->new_limit;
        WdfSpinLockRelease(xpdd->gntmem_quota_lock);
        rc = STATUS_SUCCESS;
        info = 0;
        break;
    }

    case IOCTL_GNTMEM_SET_GLOBAL_LIMIT:
    {
        struct ioctl_gntmem_set_limit* set_limit = (struct ioctl_gntmem_set_limit*)inbuffer;
        if (InputBufferLength < sizeof(*set_limit))
        {
            rc = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        DEBUGF("Setting machine-global mapping quota to %d", set_limit->new_limit);
        WdfSpinLockAcquire(xpdd->gntmem_quota_lock);
        xpdd->gntmem_allowed_pages = set_limit->new_limit;
        WdfSpinLockRelease(xpdd->gntmem_quota_lock);
        rc = STATUS_SUCCESS;
        info = 0;
        break;
    }

    case IOCTL_GNTMEM_GRANT_PAGES:
    {
        /* This case is special: because NT doesn't think we care about process context, we don't get
           a callback when our handle is dup'd into another process, by inheritence or by DuplicateHandle.
           A cleanup IRP is only dispatched to us when the last handle dies, by which time an address
           space containing granted pages may have been destroyed. And the icing on the cake: those pages
           are locked, and trying to destroy a VAS with locked pages is bugcheckworthy in the eyes of MS.

           So, what we need is to force a callback whenever a process is dying. So, we pend this IOCTL.
           Forever. Then when its originating thread dies, which must happen before VAS destruction, we
           get a Cancel callback. Then all we need to do is nuke the offending mapping on cancellation.
           To do that, we have an internal queue with a CancelInQueue callback.

           Finally, the VAS nuking is a bit tricky in itself. It must happen at PASSIVE_LEVEL, and in the
           context (i.e. with the VAS mapped) belonging to the right process. To achieve passiveness we
           queue a work item to complete the cancel op, and to move VASes we use the KeAttachProcess line
           of voodoo which warps a thread between process contexts.

           Ideally speaking we'd use an APC for this last bit, as it's the right fit; however, MS in their
           infinite wisdom did not deign to expose this rather useful facility to driver developers.
           */

        struct ioctl_gntmem_grant_pages* grant_request = (struct ioctl_gntmem_grant_pages*)inbuffer;
        grant_ref_t* grant_record_list = 0;
        struct grant_record* grant_record = 0;
        domid_t grant_to_domain = 0;
        int i;
        PPFN_NUMBER grant_pfns = 0;

        DEBUGF("IOCTL is grant-pages: asked to grant %d pages to domain %u; associate UID %d", grant_request->n_pages, grant_request->domid, grant_request->uid);
        grant_record_list = ExAllocatePoolWithTag(NonPagedPool, sizeof(grant_ref_t) * grant_request->n_pages, XENPCI_POOL_TAG);
        grant_record = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct grant_record), XENPCI_POOL_TAG);
        grant_to_domain = grant_request->domid;
        xprq->record = grant_record;
        xprq->uid = grant_request->uid;

        if ((!grant_record_list) || (!grant_record))
        {
            DEBUGF("Failed to allocate grant record");
            rc = STATUS_NO_MEMORY;
        }
        else
        {
            if ((!xprq->mdl) || (!xprq->base_vaddr))
            {
                // This shouldn't have got here, but just in case...
                DEBUGF("Rejected grant-pages request because it had no MDL or user vaddr");
                rc = STATUS_INVALID_PARAMETER;
            }
            else
            {
                grant_pfns = MmGetMdlPfnArray(xprq->mdl);
                if (!grant_pfns)
                {
                    DEBUGF("Rejected grant-pages because we couldn't get PFNs for its MDL");
                    rc = STATUS_UNSUCCESSFUL;
                }
            }
        }

        // See whether our early setup all worked out...
        if (!NT_SUCCESS(rc))
        {
            DEBUGF("Bailing early from grant-pages");
            WdfSpinLockAcquire(xpdd->gntmem_quota_lock);
            xpdd->gntmem_mapped_pages -= grant_request->n_pages;
            xpdid->gntmem.mapped_pages -= grant_request->n_pages;
            WdfSpinLockRelease(xpdd->gntmem_quota_lock);
            DEBUGF("rescinded quota request for %d pages; now %d/%d local and %d/%d global",
                   grant_request->n_pages, xpdid->gntmem.mapped_pages, xpdid->gntmem.allowed_pages,
                   xpdd->gntmem_mapped_pages, xpdd->gntmem_allowed_pages);
            if (grant_record)
                ExFreePoolWithTag(grant_record, XENPCI_POOL_TAG);
            if (grant_record_list)
                ExFreePoolWithTag(grant_record_list, XENPCI_POOL_TAG);
            if (xprq->mdl)
            {
                if (!xprq->base_vaddr)
                {
                    // Free now; no need for in-process work. This shouldn't happen, though.
                    MmFreePagesFromMdl(xprq->mdl);
                    ExFreePool(xprq->mdl);
                }
                else
                {
                    // Queue work item to unmap from userspace in appropriate context
                    xprq->record = NULL; /* Signal that we have no grants to release */
                    queue_unmap_work_item(Request, rc, xpdd);
                    // The work item will complete this request for us
                    return;
                }
            }
            else
            {
                DEBUGF("Very weird: got a grant IOCTL without an MDL. Shouldn't ever happen; expect a BSOD soon");
                // If we didn't have an MDL, we can complete from here.
            }
            break;
        }

        // Initialise the grant-list; ungranted pages should always be marked as invalid

        for (i = 0; i < grant_request->n_pages; i++)
        {
            grant_record_list[i] = INVALID_GRANT_REF;
        }

        // Assemble the grant record which will be used by our work item to free the granted memory
        // when it's all ungrantable (i.e. remote domains have released all reference)

        grant_record->n_pages = grant_request->n_pages;
        grant_record->grants = grant_record_list;
        grant_record->mdl = xprq->mdl;
        grant_record->notify_offset = -1;
        grant_record->notify_port = (evtchn_port_t) -1;

        for (i = 0; i < grant_record->n_pages; i++)
        {
            grant_ref_t new_grant;
            new_grant = GntTbl_GrantAccess(xpdd, grant_to_domain, (uint32_t) grant_pfns[i], 0, INVALID_GRANT_REF, 0);
            if (new_grant == INVALID_GRANT_REF)
            {
                DEBUGF("Granting failed! Bailing out...");
                rc = STATUS_UNSUCCESSFUL;
                break; // From the for loop, not the switch block
            }
            DEBUGF("Granted frame %u; got grant %u", (uint32_t) grant_pfns[i], new_grant);
            grant_record_list[i] = new_grant;
        }

        if (!NT_SUCCESS(rc))
        {
            DEBUGF("Some grant failed; queueing work to unmap from userspace...");
            WdfSpinLockAcquire(xpdd->gntmem_quota_lock);
            xpdid->gntmem.mapped_pages -= grant_record->n_pages;
            WdfSpinLockRelease(xpdd->gntmem_quota_lock);
            DEBUGF("released local aspect of %d pages; now %d/%d local and %d/%d global",
                   grant_record->n_pages, xpdid->gntmem.mapped_pages, xpdid->gntmem.allowed_pages,
                   xpdd->gntmem_mapped_pages, xpdd->gntmem_allowed_pages);
            queue_unmap_work_item(Request, rc, xpdd); // Will complete this request, then move on to ungranting
            return;
        }

        // Alright, success! Queue this region indefinitely. The user will then need to call GRANT_GET_INFO
        // to find this region's vaddr and so forth.

        WdfRequestForwardToIoQueue(Request, xpdid->gntmem.pending_grant_requests);
        return;
    }

    case IOCTL_GNTMEM_GET_GRANTS:
    {
        struct ioctl_gntmem_get_grants* get_grants = (struct ioctl_gntmem_get_grants*)inbuffer;
        void** grant_address_out = (void**) outbuffer;
        grant_ref_t* grants_out = (grant_ref_t*) (&(grant_address_out[1]));
        WDFREQUEST last_rq_examined = NULL;
        PXENPCI_REQUEST_DATA this_rq_data = NULL;

        DEBUGF("IOCTL is GET_GRANTS for granted section UID %d", get_grants->uid);

        if (InputBufferLength < sizeof(*get_grants))
        {
            rc = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        WdfSpinLockAcquire(xpdid->gntmem.pending_queue_lock);

        while (NT_SUCCESS(WdfIoQueueFindRequest(xpdid->gntmem.pending_grant_requests, last_rq_examined, NULL, NULL, &last_rq_examined)))
        {
            this_rq_data = GetRequestData(last_rq_examined);
            if (this_rq_data->uid == get_grants->uid)
                break;
        }

        WdfSpinLockRelease(xpdid->gntmem.pending_queue_lock);

        if (!last_rq_examined)
        {
            DEBUGF("No such section");
            rc = STATUS_INVALID_PARAMETER;
            break;
        }

        if (OutputBufferLength < (sizeof(void*) + (this_rq_data->record->n_pages * sizeof(grant_ref_t))))
        {
            DEBUGF("Output buffer too small for a section with %d pages", this_rq_data->record->n_pages);
            rc = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        *grant_address_out = this_rq_data->base_vaddr;
        RtlCopyMemory(grants_out, this_rq_data->record->grants, sizeof(grant_ref_t) * this_rq_data->record->n_pages);
        rc = STATUS_SUCCESS;
        info = (sizeof(void*) + (sizeof(grant_ref_t) * this_rq_data->record->n_pages));

        break;
    }

    case IOCTL_GNTMEM_UNMAP_NOTIFY:
    {
        struct ioctl_gntmem_unmap_notify* unmap_notify = (struct ioctl_gntmem_unmap_notify*)inbuffer;
        WDFREQUEST last_rq_examined = NULL;
        PXENPCI_REQUEST_DATA this_rq_data = NULL;

        DEBUGF("IOCTL is UNMAP_NOTIFY for granted section UID %d", unmap_notify->uid);

        WdfSpinLockAcquire(xpdid->gntmem.pending_queue_lock);

        while (NT_SUCCESS(WdfIoQueueFindRequest(xpdid->gntmem.pending_grant_requests, last_rq_examined, NULL, NULL, &last_rq_examined)))
        {
            this_rq_data = GetRequestData(last_rq_examined);
            if (this_rq_data->uid == unmap_notify->uid)
                break;
        }

        WdfSpinLockRelease(xpdid->gntmem.pending_queue_lock);

        if (!last_rq_examined)
        {
            DEBUGF("No such section");
            rc = STATUS_INVALID_PARAMETER;
            break;
        }

        if (unmap_notify->notify_offset > this_rq_data->record->n_pages * PAGE_SIZE)
        {
            DEBUGF("notify_offest outside of mapped area");
            rc = STATUS_INVALID_PARAMETER;
            break;
        }

        this_rq_data->record->notify_offset = unmap_notify->notify_offset;
        this_rq_data->record->notify_port = unmap_notify->notify_port;

        rc = STATUS_SUCCESS;
        info = 0;
        break;
    }

    case IOCTL_GNTMEM_MAP_FOREIGN_PAGES:
    {
        // TODO: batch mapping of multiple pages
        struct ioctl_gntmem_map_foreign_pages input;
        struct ioctl_gntmem_map_foreign_pages_out *output = (struct ioctl_gntmem_map_foreign_pages_out *) outbuffer;
        struct map_record *record;
        PHYSICAL_ADDRESS phys_addr;
        xen_memory_reservation_t xmr;
        PFN_NUMBER pfn = { 0 };
        int released_pages = 0, ret;

        if ((InputBufferLength < sizeof(input)) || (OutputBufferLength < sizeof(*output)))
        {
            rc = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        info = sizeof(*output); // size of data returned to user mode
        // copy input because writing to output will overwrite it (same buffer)
        memcpy(&input, inbuffer, sizeof(input));

        if (input.notify_offset >= PAGE_SIZE) // watch this when adding support for multiple page mapping
        {
            rc = STATUS_INVALID_PARAMETER;
            break;
        }

        DEBUGF("mapping foreign page ref %u from domain %u, process %p", input.grant_ref, input.foreign_domain, PsGetCurrentProcess());

        record = ExAllocatePoolWithTag(NonPagedPool, sizeof(*record), XENPCI_POOL_TAG);
        if (record == NULL)
        {
            rc = STATUS_NO_MEMORY;
            DEBUGF("failed to alloc map record");
            goto map_cleanup;
        }

        RtlZeroMemory(record, sizeof(*record));
        record->map_handle = (grant_handle_t) -1;
        record->notify_offset = input.notify_offset;
        record->notify_port = input.notify_port;

        // TODO: don't allocate memory, use xenpci's io address space instead
        record->kernel_va = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);
        if (record->kernel_va == NULL)
        {
            rc = STATUS_NO_MEMORY;
            DEBUGF("failed to alloc mapped page");
            goto map_cleanup;
        }

        RtlZeroMemory(record->kernel_va, PAGE_SIZE);
        phys_addr = MmGetPhysicalAddress(record->kernel_va);
        pfn = phys_addr.QuadPart >> PAGE_SHIFT;

        DEBUGF("record %p: kernel va %p, phys addr %p", record, record->kernel_va, phys_addr);

        // release underlying memory to xen since it'll be replaced with the mapped page anyway
        // (and we'll need to repopulate it with memory after unmapping)
        RtlZeroMemory(&xmr, sizeof(xmr));
        xmr.domid = DOMID_SELF;
        xmr.nr_extents = 1;
        set_xen_guest_handle(xmr.extent_start, &pfn);
        released_pages = HYPERVISOR_memory_op(xpdd, XENMEM_decrease_reservation, &xmr);
        if (released_pages != 1) // number of pages released
        {
            rc = STATUS_UNSUCCESSFUL;
            DEBUGF("XENMEM_decrease_reservation failed for pfn %x", pfn);
            goto map_cleanup;
        }

        DEBUGF("pfn %x released to Xen", pfn);

        // perform the actual grant mapping
        record->map_handle = GntTbl_MapForeignPage(xpdd, input.foreign_domain, input.grant_ref, phys_addr,
                                                   input.read_only ? GNTMAP_host_map | GNTMAP_readonly : GNTMAP_host_map);
        if (((int) record->map_handle) < 0) // funny how grant_handle_t is unsigned but the hypercall returns "negative values on error"...
        {
            rc = STATUS_UNSUCCESSFUL;
            DEBUGF("GntTbl_MapForeignPage failed");
            goto map_cleanup;
        }

        DEBUGF("grant map OK, handle: 0x%x", record->map_handle);

        // map the page into user space
        record->mdl = IoAllocateMdl(record->kernel_va, PAGE_SIZE, FALSE, FALSE, NULL);
        if (record->mdl == NULL)
        {
            rc = STATUS_NO_MEMORY;
            DEBUGF("IoAllocateMdl failed");
            goto map_cleanup;
        }

        MmBuildMdlForNonPagedPool(record->mdl);

        __try
        {
            record->user_va = MmMapLockedPagesSpecifyCache(record->mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
            DEBUGF("successfully mapped page to user address %p", record->user_va);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            rc = GetExceptionCode();
            DEBUGF("user mapping caused exception 0x%08x", rc);
            goto map_cleanup;
        }

        // complete filling the structures
        record->process = PsGetCurrentProcess();
        output->map_handle = record->map_handle;
        output->mapped_va = record->user_va;
        output->context = record;

        // add record to the list
        WdfSpinLockAcquire(xpdd->gntmem_mapped_lock);
        InsertTailList(&xpdd->gntmem_mapped_list, (PLIST_ENTRY) record);
        WdfSpinLockRelease(xpdd->gntmem_mapped_lock);

        rc = STATUS_SUCCESS;

    map_cleanup:
        if (rc != STATUS_SUCCESS)
        {
            DEBUGF("cleanup on failed map");
            if (record)
            {
                BOOLEAN leak = FALSE;

                if (record->mdl)
                    IoFreeMdl(record->mdl);

                if (((int) record->map_handle) > 0)
                {
                    // foreign pages were mapped, need to unmap again
                    ret = GntTbl_UnmapForeignPage(xpdd, record->map_handle, MmGetPhysicalAddress(record->kernel_va));
                    if (ret != GNTST_okay)
                    {
                        DEBUGF("WARNING: GntTbl_UnmapForeignPage failed for handle 0x%x, leaking pages", record->map_handle);
                        leak = TRUE;
                    }
                    else
                        DEBUGF("successfully unmapped map handle 0x%x", record->map_handle);
                }

                if ((released_pages > 0) && !leak) // memory was released to xen, need to reacquire
                {
                    // repopulate unmapped page with memory
                    RtlZeroMemory(&xmr, sizeof(xmr));
                    xmr.domid = DOMID_SELF;
                    xmr.nr_extents = 1;
                    set_xen_guest_handle(xmr.extent_start, &pfn); // pfn is valid if we are here
                    ret = HYPERVISOR_memory_op(xpdd, XENMEM_populate_physmap, &xmr);
                    if (ret != 1)
                    {
                        DEBUGF("WARNING: XENMEM_populate_physmap failed for pfn %x (%d), leaking pages", pfn, ret);
                        leak = TRUE;
                    }
                }

                if (record->kernel_va)
                {
                    if (!leak)
                        ExFreePoolWithTag(record->kernel_va, XENPCI_POOL_TAG);
                    else // see GntMem_UnmapForeign() for why we're leaking pages
                        DEBUGF("!!! LEAKING PAGE: va %p, pfn %x", record->kernel_va, pfn); // pfn is valid if we're here
                }

                ExFreePoolWithTag(record, XENPCI_POOL_TAG);
            }
        }
        break;
    }

    case IOCTL_GNTMEM_UNMAP_FOREIGN_PAGES:
    {
        // TODO: batch unmapping of multiple pages
        struct ioctl_gntmem_unmap_foreign_pages *input = (struct ioctl_gntmem_unmap_foreign_pages *) inbuffer;
        PLIST_ENTRY node;
        PEPROCESS current_process;

        if (InputBufferLength < sizeof(*input))
        {
            rc = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        info = 0;
        rc = STATUS_NOT_FOUND;
        current_process = PsGetCurrentProcess();
        DEBUGF("unmapping grant: record %p, process %p", input->context, current_process);

        // walk the map list, search for provided record (context)
        WdfSpinLockAcquire(xpdd->gntmem_mapped_lock);
        node = xpdd->gntmem_mapped_list.Flink;
        while (node->Flink != xpdd->gntmem_mapped_list.Flink)
        {
            struct map_record *record = CONTAINING_RECORD(node, struct map_record, entry);

            node = node->Flink;
            if (record == input->context)
            {
                if (record->process != current_process)
                {
                    DEBUGF("WARNING: current process is different than the mapping holder, will clean up on holder's destruction");
                    rc = STATUS_UNSUCCESSFUL;
                    break;
                }

                GntMem_UnmapForeign(record, current_process);
                rc = STATUS_SUCCESS;
                break; // while
            }
        }

        WdfSpinLockRelease(xpdd->gntmem_mapped_lock);
        break; // switch
    }

#pragma warning(pop)

    default:
        DEBUGF("IOCTL code was not recognised");
        rc = STATUS_INVALID_PARAMETER;
        break;
    }

    WdfRequestCompleteWithInformation(Request, rc, info);
}

/* Runs at IRQL <= DISPATCH, so we queue a work item to do the address space mangling */
static VOID GntMem_EvtIoCanceledOnPendingGrantQueue(WDFQUEUE Queue, WDFREQUEST Request)
{
    PXENPCI_DEVICE_DATA xpdd = GetXpdd(WdfIoQueueGetDevice(Queue));
    WDFFILEOBJECT file_object = WdfRequestGetFileObject(Request);
    PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);

    DEBUGF("Got a cancellation on a pending IOCTL; scheduling work item to complete request");

    WdfSpinLockAcquire(xpdid->gntmem.pending_queue_lock);

    queue_unmap_work_item(Request, STATUS_CANCELLED, xpdd);
    // Will be completed by unmap item, which will pass freeing work on appropriately.

    WdfSpinLockRelease(xpdid->gntmem.pending_queue_lock);
}

static VOID GntMem_EvtFileCleanup(WDFFILEOBJECT file_object)
{
    UNREFERENCED_PARAMETER(file_object);

    DEBUGF("file cleanup (ignored, should be dealt with by cancellations)");
}

static VOID GntMem_EvtFileClose(WDFFILEOBJECT file_object)
{
    UNREFERENCED_PARAMETER(file_object);

    DEBUGF("close (ignored)");

    FUNCTION_ENTER();
    FUNCTION_EXIT();
}

NTSTATUS GntMem_DeviceFileInit(WDFDEVICE device, PWDF_IO_QUEUE_CONFIG queue_config, WDFFILEOBJECT file_object)
{
    PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
    PXENPCI_DEVICE_DATA xpdd = GetXpdd(device);
    WDF_IO_QUEUE_CONFIG internal_queue_config;
    WDF_OBJECT_ATTRIBUTES internal_queue_attributes;
    NTSTATUS status;
    ULONG grant_entries;

    UNREFERENCED_PARAMETER(device);
    DEBUGF("DeviceFileInit");

    xpdid->EvtFileCleanup = GntMem_EvtFileCleanup;
    xpdid->EvtFileClose = GntMem_EvtFileClose;
    queue_config->EvtIoDeviceControl = GntMem_EvtIoDeviceControl;

    WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &xpdid->gntmem.pending_queue_lock);
    WDF_IO_QUEUE_CONFIG_INIT(&internal_queue_config, WdfIoQueueDispatchManual);
    internal_queue_config.EvtIoCanceledOnQueue = GntMem_EvtIoCanceledOnPendingGrantQueue;
    WDF_OBJECT_ATTRIBUTES_INIT(&internal_queue_attributes);
    internal_queue_attributes.ParentObject = file_object;
    status = WdfIoQueueCreate(device, &internal_queue_config, &internal_queue_attributes, &xpdid->gntmem.pending_grant_requests);
    if (!NT_SUCCESS(status))
        return status;

    // FIXME: this is local-only (device open)
    grant_entries = min(NR_GRANT_ENTRIES, (xpdd->grant_frames * PAGE_SIZE / sizeof(grant_entry_t))) - NR_RESERVED_ENTRIES;
    DEBUGF("setting local and global quota to %u grants", grant_entries);

    xpdid->gntmem.allowed_pages = grant_entries;
    xpdid->gntmem.mapped_pages = 0;
    xpdd->gntmem_allowed_pages = grant_entries;
    xpdd->gntmem_mapped_pages = 0;

    DEBUGF("completing init");

    return STATUS_SUCCESS;
}
