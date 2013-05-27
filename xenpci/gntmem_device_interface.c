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

struct grant_record {

	LIST_ENTRY head;
	grant_ref_t* grants;
	int n_pages;
	PMDL mdl;
	int notify_offset;
	evtchn_port_t notify_port;
};

typedef struct {

	WDFREQUEST request;
	NTSTATUS status;
	PXENPCI_DEVICE_DATA xpdd;

} XENPCI_UNMAP_WORK_ITEM_CONTEXT, *PXENPCI_UNMAP_WORK_ITEM_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(XENPCI_UNMAP_WORK_ITEM_CONTEXT, GetUnmapContext)

typedef struct {

	PMDL mdl;

} XENPCI_FREE_MDL_WORK_ITEM_CONTEXT, *PXENPCI_FREE_MDL_WORK_ITEM_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(XENPCI_FREE_MDL_WORK_ITEM_CONTEXT, GetFreeMdlContext)

/* The prelude to the grant-memory ioctl. Needs to:
   1. Record the process we're running in,
   2. Allocate kernel memory,
   3. Map it into userspace.
   The IOCTL can then do the actual granting, before pending forever waiting on cancellation if the thread
   is dying. On cancellation it then unmaps from userspace, handing off the ungranting task to our timer task. */

VOID GntMem_EvtIoInCallerContext(PXENPCI_DEVICE_INTERFACE_DATA xpdid, WDFREQUEST Request, WDFDEVICE Device) {

	WDF_REQUEST_PARAMETERS RqParams;
	struct ioctl_gntmem_grant_pages* gprq;
	NTSTATUS status;
	PXENPCI_REQUEST_DATA rqdata = GetRequestData(Request);
	PXENPCI_DEVICE_DATA xpdd = GetXpdd(Device);
	int refund_quotas = 0;

	WDF_REQUEST_PARAMETERS_INIT(&RqParams);
	WdfRequestGetParameters(Request, &RqParams);

	/* Note that we don't need to check if this is a gntmem device; that's done by XenPCI */
	if(RqParams.Type == WdfRequestTypeDeviceControl 
	&& RqParams.Parameters.DeviceIoControl.IoControlCode == IOCTL_GNTMEM_GRANT_PAGES) {

		KdPrint(("GntMem_EvtIoInCallerContextCallback: Request was a grant-pages IOCTL, attaching MDL\n"));
		/* This checks for buffer-too-small as well as fetching the buffer pointer */
		status = WdfRequestRetrieveInputBuffer(Request, sizeof(*gprq), (PVOID*)&gprq, NULL);
		if(NT_SUCCESS(status)) {

			KdPrint(("...request is to pin %d pages and give them to domain %d\n", gprq->n_pages, gprq->domid));
			WdfSpinLockAcquire(xpdd->gntmem_quota_lock);

			if(((xpdid->gntmem.mapped_pages + gprq->n_pages) > xpdid->gntmem.allowed_pages)
			|| ((xpdd->gntmem_mapped_pages + gprq->n_pages) > xpdd->gntmem_allowed_pages)) {
				KdPrint(("Gntmem: refusing to map a further %d pages, as only %d are allowed and %d are taken on local device\n",
						 gprq->n_pages, xpdid->gntmem.allowed_pages, xpdid->gntmem.mapped_pages));
				KdPrint(("Gntmem: %d pages are allowed and %d mapped overall\n", xpdd->gntmem_mapped_pages, xpdd->gntmem_allowed_pages));
				status = STATUS_ACCESS_DENIED;
			}
			else {
				xpdid->gntmem.mapped_pages += gprq->n_pages;
				xpdd->gntmem_mapped_pages += gprq->n_pages;
				refund_quotas = gprq->n_pages;
				KdPrint(("Gntmem: accepted quota request for %d pages; now %d/%d local and %d/%d global\n",
					gprq->n_pages, xpdid->gntmem.mapped_pages, xpdid->gntmem.allowed_pages,
					xpdd->gntmem_mapped_pages, xpdd->gntmem_allowed_pages));
			}

			WdfSpinLockRelease(xpdd->gntmem_quota_lock);

			if(NT_SUCCESS(status)) {

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
				KdPrint(("gntmem: Allocating MDL and %d pages\n", gprq->n_pages));
				rqdata->mdl = MmAllocatePagesForMdl(lowaddr, highaddr, skip_bytes, (gprq->n_pages * PAGE_SIZE));
				KdPrint(("gntmem: Success; got an MDL at 0x%Ix\n", rqdata->mdl));
				if((!rqdata->mdl) || (MmGetMdlByteCount(rqdata->mdl) != ((unsigned int)(gprq->n_pages * PAGE_SIZE)))) {
					/* Allocate can return some but not all the pages we asked for, hence the extra check */
					KdPrint(("gntmem: MDL not allocated or too small; dying with ENOMEM\n"));
					status = STATUS_NO_MEMORY;
					if(rqdata->mdl) {
						MmFreePagesFromMdl(rqdata->mdl);
						ExFreePool(rqdata->mdl);
					}
				}
				else {
					__try {
						KdPrint(("gntmem: Mapping pages into userspace\n"));
						rqdata->base_vaddr = MmMapLockedPagesSpecifyCache(rqdata->mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
						KdPrint(("gntmem: Successfully mapped %d pages to user address %Ix\n", gprq->n_pages, rqdata->base_vaddr));
					}
					__except(EXCEPTION_EXECUTE_HANDLER) {
						status = GetExceptionCode();
						KdPrint(("GntMem_EvtIoInCallerContext: User mapping caused exception (0X%08X)\n", status));
						MmFreePagesFromMdl(rqdata->mdl);
						ExFreePool(rqdata->mdl);
					}
				}
				// Okay, we have some user memory, and it's pinned down. The rest is for Evtioctl.
			}
		}

		if(!NT_SUCCESS(status)) {
			KdPrint(("GntMem_EvtIoInCallerContextCallback: Failing a request with status 0x%08X\n", status));
			if(refund_quotas) {
				WdfSpinLockAcquire(xpdd->gntmem_quota_lock);
				KdPrint(("gntmem: Refunding %d pages for a failed request\n", refund_quotas));
				xpdd->gntmem_mapped_pages -= refund_quotas;
				xpdid->gntmem.mapped_pages -= refund_quotas;
				WdfSpinLockRelease(xpdd->gntmem_quota_lock);
			}
			WdfRequestComplete(Request, status);
			return;
		}

	}

	KdPrint(("GntMem_EvtIoInCallerContextCallback: Queueing a request\n"));
	// Either we successfully locked some pages, or this wasn't a GRANT_PAGES IOCTL at all
	WdfDeviceEnqueueRequest(Device, Request);

}

static void possibly_notify_unmap(struct grant_record* rec, PXENPCI_DEVICE_DATA xpdd) {
	PVOID mapped_area;
	char *mapped_area_char;

	if (rec->notify_offset >= 0) {
		mapped_area = MmGetSystemAddressForMdlSafe(rec->mdl, LowPagePriority);
		if (!mapped_area) {
			KdPrint(("gntmem: failed to map MDL for notification\n"));
		} else {
			mapped_area_char = mapped_area;
			mapped_area_char[rec->notify_offset] = 0;
			MmUnmapLockedPages(mapped_area, rec->mdl);
		}
		rec->notify_offset = -1;
	}

	if (rec->notify_port != -1) {
		EvtChn_Notify(xpdd, rec->notify_port);
		rec->notify_port = (evtchn_port_t)-1;
	}
}

/* Tries to free all the grants indicated by a given grant_record, and free the grant list.
   Returns TRUE if successful; otherwise the grant list still stands and some remain to be
   ungranted. Does not touch the MDL, as freeing that would be incompatible with our current IRQL.
   
   Runs at <= DISPATCH_LEVEL */
static BOOLEAN try_destroy_grant_record(struct grant_record* rec, PXENPCI_DEVICE_DATA xpdd) {

	int i;
	BOOLEAN any_failures = FALSE;

	possibly_notify_unmap(rec, xpdd);

	for(i = 0; i < rec->n_pages; i++) {

		if(rec->grants[i] != INVALID_GRANT_REF) {
			if(GntTbl_EndAccess(xpdd, rec->grants[i], FALSE, 0)) {
				KdPrint(("gntmem: successfully freed grant %d\n", (int)rec->grants[i]));
				rec->grants[i] = INVALID_GRANT_REF;
			}
			else {
				KdPrint(("gntmem: couldn't free grant %d at this time\n", (int)rec->grants[i]));
				any_failures = TRUE;
			}
		}

	}
	if(!any_failures) {
		KdPrint(("gntmem: Freed the entire region; releasing pages\n"));
		WdfSpinLockAcquire(xpdd->gntmem_quota_lock);
		xpdd->gntmem_mapped_pages -= rec->n_pages;
		KdPrint(("Gntmem: destroyed region of %d pages; global quota now %d/%d global\n",
			rec->n_pages, xpdd->gntmem_mapped_pages, xpdd->gntmem_allowed_pages));
		WdfSpinLockRelease(xpdd->gntmem_quota_lock);
		ExFreePoolWithTag(rec->grants, XENPCI_POOL_TAG);
		return TRUE;
	}
	else {
		KdPrint(("gntmem: At least one grant still outstanding from region"));
		return FALSE;
	}

}

/* Runs at PASSIVE_LEVEL. Used because FreePagesFromMdl requires <= APC_LEVEL */
static VOID GntMem_EvtFreeMdlWorkItem(WDFWORKITEM work) {

	PXENPCI_FREE_MDL_WORK_ITEM_CONTEXT work_context;

	work_context = GetFreeMdlContext(work);

	KdPrint(("gntmem: Free-MDL work item: freeing MDL at 0x%Ix", work_context->mdl));

	MmFreePagesFromMdl(work_context->mdl);
	ExFreePool(work_context->mdl);

	WdfObjectDelete(work);

}

/* Runs at DISPATCH_LEVEL (from a timer) */
static VOID queue_free_mdl_work_item(PMDL mdl, PXENPCI_DEVICE_DATA xpdd) {

	WDF_WORKITEM_CONFIG config;
	WDF_OBJECT_ATTRIBUTES attributes;
	WDFWORKITEM new_workitem;
	NTSTATUS status;
	PXENPCI_FREE_MDL_WORK_ITEM_CONTEXT work_context;

	KdPrint(("gntmem: Queueing work item to free mdl at 0x%Ix\n", mdl));

	WDF_WORKITEM_CONFIG_INIT(&config, GntMem_EvtFreeMdlWorkItem);
	config.AutomaticSerialization = FALSE; /* Driver functions can be at DISPATCH_LEVEL */
	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, XENPCI_FREE_MDL_WORK_ITEM_CONTEXT);
	attributes.ParentObject = xpdd->wdf_device;
	status = WdfWorkItemCreate(&config, &attributes, &new_workitem);
	if(!NT_SUCCESS(status)) {
		KdPrint(("gntmem: Couldn't allocate a work item to free an MDL. Non-fatal, but leaks physical pages.\n"));
		return;
	}

	work_context = GetFreeMdlContext(new_workitem);
	work_context->mdl = mdl;

	WdfWorkItemEnqueue(new_workitem);

}

static BOOLEAN try_destroy_all_pending(PXENPCI_DEVICE_DATA xpdd) {

	BOOLEAN all_freed = TRUE;
	struct grant_record* next_record;
	
	next_record = (struct grant_record*)xpdd->gntmem_pending_free_list_head.Flink;
	KdPrint(("gntmem: Trying to free all pending regions\n"));

	while(next_record != (struct grant_record*)&(xpdd->gntmem_pending_free_list_head)) {
		if(try_destroy_grant_record(next_record, xpdd)) {
			struct grant_record* to_destroy = next_record;
			next_record = (struct grant_record*)next_record->head.Flink;
			KdPrint(("gntmem: Successfully freed a region; deleting and queueing free-MDL work item\n"));
			queue_free_mdl_work_item(to_destroy->mdl, xpdd);
			RemoveEntryList((PLIST_ENTRY)to_destroy);
			ExFreePoolWithTag(to_destroy, XENPCI_POOL_TAG);
		}
		else {
			KdPrint(("gntmem: A region could not be freed at this time; retaining\n"));
			next_record = (struct grant_record*)next_record->head.Flink;
			all_freed = FALSE;
		}
	}

	if(all_freed) {
		KdPrint(("gntmem: Successfully destroyed all pending regions"));
		return TRUE;
	}
	else {
		KdPrint(("gntmem: At least one region still pending"));
		return FALSE;
	}

}

VOID GntMem_EvtTimerFunc(WDFTIMER timer) {

	WDFDEVICE device = WdfTimerGetParentObject(timer);
	PXENPCI_DEVICE_DATA xpdd = GetXpdd(device);

	WdfSpinLockAcquire(xpdd->gntmem_pending_free_lock);

	if(try_destroy_all_pending(xpdd)) {
		KdPrint(("gntmem: Timer task successfully destroyed all remaining sections!\n"));
		xpdd->gntmem_free_work_queued = FALSE;
		WdfTimerStop(timer, FALSE); /* FALSE = don't wait... for ourselves :) */
	}
	else {
		KdPrint(("gntmem: Timer task left at least one region alive; running again in 10s\n"));
		// Timer is periodic; this will happen automatically.
	}

	WdfSpinLockRelease(xpdd->gntmem_pending_free_lock);

}

static VOID queue_grant_record_for_destruction(PXENPCI_DEVICE_DATA xpdd, struct grant_record* rec) {

	WdfSpinLockAcquire(xpdd->gntmem_pending_free_lock);
	InsertTailList(&xpdd->gntmem_pending_free_list_head, (PLIST_ENTRY)rec);
	if(!xpdd->gntmem_free_work_queued) {

		WdfTimerStart(xpdd->gntmem_cleanup_timer, 10 /*us*/* 1000/*ms*/ * 1000/*s*/ * 10/*10s*/);
		xpdd->gntmem_free_work_queued = TRUE;

	}
	WdfSpinLockRelease(xpdd->gntmem_pending_free_lock);

}

/* Runs at PASSIVE_LEVEL */
static VOID GntMem_EvtUnmapWorkItem(WDFWORKITEM work) {

	PXENPCI_UNMAP_WORK_ITEM_CONTEXT work_context;
	KAPC_STATE old_state; 
	PXENPCI_REQUEST_DATA rq_context;
	struct grant_record* record;
	PMDL mdl;
	BOOLEAN grants_freed = FALSE;

	work_context = GetUnmapContext(work);
	rq_context = GetRequestData(work_context->request);

	KdPrint(("gntmem: In unmap-from-userspace, trying to unmap user address 0x%Ix\n", rq_context->base_vaddr));

	KeStackAttachProcess(rq_context->process, &old_state);

	KdPrint(("gntmem: Switched into process\n"));

	MmUnmapLockedPages(rq_context->base_vaddr, rq_context->mdl);

	KdPrint(("gntmem: Voided PTEs\n"));

	KeUnstackDetachProcess(&old_state);

	KdPrint(("gntmem: Back in system thread\n"));

	/* Alright, the user address space is cleaned; now we can complete the request and get on with
	   trying to free up the grants, and finally the kernel memory. */
	// First, grab some stuff from the request's context which we'll need
	record = rq_context->record;
	mdl = rq_context->mdl;

	KdPrint(("gntmem: unmap work item completing request with status 0x%lx\n", (unsigned long)work_context->status));

	WdfRequestComplete(work_context->request, work_context->status);

	// Try to free grants right now, as our currently passive IRQL might enable us to dodge a second work item
	if(!record) { // This is the error-recovery case -- we're unmapping after a failure that came before granting
		grants_freed = TRUE;
		KdPrint(("gntmem: work item gives no grant list; this must be error recovery\n"));
	}
	else {
		grants_freed = try_destroy_grant_record(record, work_context->xpdd);
		KdPrint(("gntmem: Tried to destroy grant record right now; returned %d\n", (int)grants_freed));
	}

	if(grants_freed) {
		KdPrint(("gntmem: Freeing kernel memory from userspace-unmap work\n"));
		// Excellent, free the kernel memory and we're done
		MmFreePagesFromMdl(mdl);
		ExFreePool(mdl);
		if(record)
			ExFreePoolWithTag(record, XENPCI_POOL_TAG);
	}
	else {
		KdPrint(("gntmem: Userspace-unmap work queued grant record for destruction later\n"));
		// Never mind, hand it over to the timer DPC, which will need another workitem to get the pages freed
		queue_grant_record_for_destruction(work_context->xpdd, record);
	}

	// Finally, free this work item
	WdfObjectDelete(work);

}

/* Runs at <= DISPATCH_LEVEL */
static VOID queue_unmap_work_item(WDFREQUEST Request, NTSTATUS status, PXENPCI_DEVICE_DATA xpdd) {

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
	if(!NT_SUCCESS(local_status)) {
		KdPrint(("gntmem: Couldn't allocate a work item to unmap pages from userspace. Ignoring, but expect a BSOD on process termination\n"));
		return;
	}

	KdPrint(("gntmem: Queued a work item for userspace-unmap\n"));

	work_context = GetUnmapContext(new_workitem);
	work_context->request = Request;
	work_context->status = status;
	work_context->xpdd = xpdd;

	WdfWorkItemEnqueue(new_workitem);

}

static VOID
  GntMem_EvtIoDeviceControl (
    IN WDFQUEUE  Queue,
    IN WDFREQUEST  Request,
    IN size_t  OutputBufferLength,
    IN size_t  InputBufferLength,
    IN ULONG  IoControlCode
    )
{

	NTSTATUS rc = STATUS_SUCCESS;
	PVOID inbuffer = 0;
	PVOID outbuffer = 0;
	ULONG info = 0;

	PXENPCI_DEVICE_DATA xpdd = GetXpdd(WdfIoQueueGetDevice(Queue));
	WDFFILEOBJECT file_object = WdfRequestGetFileObject(Request);
	PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
	PXENPCI_REQUEST_DATA xprq = GetRequestData(Request);

	KdPrint(("GntMem: IOCTL %ux with in/out buffers %d/%d\n", IoControlCode, InputBufferLength, OutputBufferLength));

	/* These modes of failure can't happen for grant-pages calls, which checked their input buffer
	   in caller context, and which don't have output buffers since they never return. */

	if(InputBufferLength) {
		rc = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inbuffer, NULL);
		if(!NT_SUCCESS(rc)) {
			KdPrint(("GntMem: IOCTL couldn't map in-buffer\n"));
			WdfRequestCompleteWithInformation(Request, rc, 0);
			return;
		}
	}
	if(OutputBufferLength) {
		rc = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &outbuffer, NULL);
		if(!NT_SUCCESS(rc)) {
			KdPrint(("EvtChn: IOCTL couldn't map out-buffer\n"));
			WdfRequestCompleteWithInformation(Request, rc, 0);
			return;
		}
	}

	switch (IoControlCode) {

		case IOCTL_GNTMEM_SET_LOCAL_LIMIT: 
			{
				struct ioctl_gntmem_set_limit* set_limit = (struct ioctl_gntmem_set_limit*)inbuffer;
				if(InputBufferLength < sizeof(*set_limit)) {
					rc = STATUS_BUFFER_TOO_SMALL;
					break;
				}
				KdPrint(("Setting device-local mapping quota to %d\n", set_limit->new_limit));
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
				if(InputBufferLength < sizeof(*set_limit)) {
					rc = STATUS_BUFFER_TOO_SMALL;
					break;
				}
				KdPrint(("Setting machine-global mapping quota to %d\n", set_limit->new_limit));
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

				KdPrint(("IOCTL is grant-pages: asked to grant %d pages to domain %u; associate UID %d\n", grant_request->n_pages, grant_request->domid, grant_request->uid));
				grant_record_list = ExAllocatePoolWithTag(NonPagedPool, sizeof(grant_ref_t) * grant_request->n_pages, XENPCI_POOL_TAG);
				grant_record = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct grant_record), XENPCI_POOL_TAG);
				grant_to_domain = grant_request->domid;
				xprq->record = grant_record;
				xprq->uid = grant_request->uid;
				if((!grant_record_list) || (!grant_record)) {
					KdPrint(("gntmem: Failed to allocate grant record\n"));
					rc = STATUS_NO_MEMORY;
				}
				else {
					if((!xprq->mdl) || (!xprq->base_vaddr)) {
						// This shouldn't have got here, but just in case...
						KdPrint(("gntmem: Rejected grant-pages request because it had no MDL or user vaddr\n"));
						rc = STATUS_INVALID_PARAMETER;
					}
					else {
						grant_pfns = MmGetMdlPfnArray(xprq->mdl);
						if(!grant_pfns) {
							KdPrint(("gntmem: Rejected grant-pages because we couldn't get PFNs for its MDL\n"));
							rc = STATUS_UNSUCCESSFUL;
						}
					}
				}
				// See whether our early setup all worked out...
				if(!NT_SUCCESS(rc)) {
					KdPrint(("gntmem: Bailing early from grant-pages\n"));
					WdfSpinLockAcquire(xpdd->gntmem_quota_lock);
					xpdd->gntmem_mapped_pages -= grant_request->n_pages;
					xpdid->gntmem.mapped_pages -= grant_request->n_pages;
					WdfSpinLockRelease(xpdd->gntmem_quota_lock);
					KdPrint(("Gntmem: rescinded quota request for %d pages; now %d/%d local and %d/%d global\n",
						grant_request->n_pages, xpdid->gntmem.mapped_pages, xpdid->gntmem.allowed_pages,
						xpdd->gntmem_mapped_pages, xpdd->gntmem_allowed_pages));
					if(grant_record)
						ExFreePoolWithTag(grant_record, XENPCI_POOL_TAG);
					if(grant_record_list)
						ExFreePoolWithTag(grant_record_list, XENPCI_POOL_TAG);
					if(xprq->mdl) {
						if(!xprq->base_vaddr) {
							// Free now; no need for in-process work. This shouldn't happen, though.
							MmFreePagesFromMdl(xprq->mdl);
							ExFreePool(xprq->mdl);
						}
						else {
							// Queue work item to unmap from userspace in appropriate context
							xprq->record = NULL; /* Signal that we have no grants to release */
							queue_unmap_work_item(Request, rc, xpdd);
							// The work item will complete this request for us
							return;
						}
					}
					else {
						KdPrint(("gntmem: Very weird: got a grant IOCTL without an MDL. Shouldn't ever happen; expect a BSOD soon\n"));
						// If we didn't have an MDL, we can complete from here.
					}
					break;
				}

				// Initialise the grant-list; ungranted pages should always be marked as invalid

				for(i = 0; i < grant_request->n_pages; i++) {
					grant_record_list[i] = INVALID_GRANT_REF;
				}

				// Assemble the grant record which will be used by our work item to free the granted memory
				// when it's all ungrantable (i.e. remote domains have released all reference)

				grant_record->n_pages = grant_request->n_pages;
				grant_record->grants = grant_record_list;
				grant_record->mdl = xprq->mdl;
				grant_record->notify_offset = -1;
				grant_record->notify_port = (evtchn_port_t)-1;

				for(i = 0; i < grant_record->n_pages; i++) {
					grant_ref_t new_grant;
					new_grant = GntTbl_GrantAccess(xpdd, grant_to_domain, (uint32_t)grant_pfns[i], 0, INVALID_GRANT_REF, 0);
					if(new_grant == INVALID_GRANT_REF) {
						KdPrint(("gntmem: Granting failed! Bailing out...\n"));
						rc = STATUS_UNSUCCESSFUL;
						break; // From the for loop, not the switch block
					}
					KdPrint(("gntmem: Granted frame %u; got grant %u\n", (uint32_t)grant_pfns[i], new_grant));
					grant_record_list[i] = new_grant;
				}
				
				if(!NT_SUCCESS(rc)) {
					KdPrint(("gntmem: Some grant failed; queueing work to unmap from userspace...\n"));
					WdfSpinLockAcquire(xpdd->gntmem_quota_lock);
					xpdid->gntmem.mapped_pages -= grant_record->n_pages;
					WdfSpinLockRelease(xpdd->gntmem_quota_lock);
					KdPrint(("Gntmem: released local aspect of %d pages; now %d/%d local and %d/%d global\n",
						grant_record->n_pages, xpdid->gntmem.mapped_pages, xpdid->gntmem.allowed_pages,
						xpdd->gntmem_mapped_pages, xpdd->gntmem_allowed_pages));
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
				void** grant_address_out = (void**)outbuffer;
				grant_ref_t* grants_out = (grant_ref_t*)(&(grant_address_out[1]));
				WDFREQUEST last_rq_examined = NULL;
				PXENPCI_REQUEST_DATA this_rq_data = NULL;

				KdPrint(("IOCTL is GET_GRANTS for granted section UID %d\n", get_grants->uid));

				if(InputBufferLength < sizeof(*get_grants)) {
					rc = STATUS_BUFFER_TOO_SMALL;
					break;
				}

				WdfSpinLockAcquire(xpdid->gntmem.pending_queue_lock);

				while(NT_SUCCESS(WdfIoQueueFindRequest(xpdid->gntmem.pending_grant_requests, last_rq_examined, NULL, NULL, &last_rq_examined))) {

					this_rq_data = GetRequestData(last_rq_examined);
					if(this_rq_data->uid == get_grants->uid)
						break;

				}

				WdfSpinLockRelease(xpdid->gntmem.pending_queue_lock);

				if(!last_rq_examined) {
					KdPrint(("gntmem: No such section\n"));
					rc = STATUS_INVALID_PARAMETER;
					break;
				}
				if(OutputBufferLength < (sizeof(void*) + (this_rq_data->record->n_pages * sizeof(grant_ref_t)))) {
					KdPrint(("gntmem: Output buffer too small for a section with %d pages\n", this_rq_data->record->n_pages));
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

				KdPrint(("IOCTL is UNMAP_NOTIFY for granted section UID %d\n", unmap_notify->uid));

				WdfSpinLockAcquire(xpdid->gntmem.pending_queue_lock);

				while(NT_SUCCESS(WdfIoQueueFindRequest(xpdid->gntmem.pending_grant_requests, last_rq_examined, NULL, NULL, &last_rq_examined))) {

					this_rq_data = GetRequestData(last_rq_examined);
					if(this_rq_data->uid == unmap_notify->uid)
						break;

				}

				WdfSpinLockRelease(xpdid->gntmem.pending_queue_lock);

				if(!last_rq_examined) {
					KdPrint(("gntmem: No such section\n"));
					rc = STATUS_INVALID_PARAMETER;
					break;
				}
				if (unmap_notify->notify_offset > this_rq_data->record->n_pages * PAGE_SIZE) {
					KdPrint(("gntmem: notify_offest outside of mapped area\n"));
					rc = STATUS_INVALID_PARAMETER;
					break;
				}
				this_rq_data->record->notify_offset = unmap_notify->notify_offset;
				this_rq_data->record->notify_port = unmap_notify->notify_port;

				rc = STATUS_SUCCESS;
				info = 0;
				break;
			}

		default:
			KdPrint(("GntMem: IOCTL code was not recognised\n"));
			rc = STATUS_INVALID_PARAMETER;
			break;
	}

	WdfRequestCompleteWithInformation(Request, rc, info);

}

/* Runs at IRQL <= DISPATCH, so we queue a work item to do the address space mangling */
static VOID GntMem_EvtIoCanceledOnPendingGrantQueue(WDFQUEUE Queue, WDFREQUEST Request) {

	PXENPCI_DEVICE_DATA xpdd = GetXpdd(WdfIoQueueGetDevice(Queue));
	WDFFILEOBJECT file_object = WdfRequestGetFileObject(Request);
	PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);

	KdPrint(("Got a cancellation on a pending IOCTL; scheduling work item to complete request\n"));

	WdfSpinLockAcquire(xpdid->gntmem.pending_queue_lock);

	queue_unmap_work_item(Request, STATUS_CANCELLED, xpdd); 
	// Will be completed by unmap item, which will pass freeing work on appropriately.

	WdfSpinLockRelease(xpdid->gntmem.pending_queue_lock);

}

static VOID
GntMem_EvtFileCleanup(WDFFILEOBJECT file_object)
{
    UNREFERENCED_PARAMETER(file_object);

	KdPrint(("gntmem: file cleanup (ignored, should be dealt with by cancellations)\n"));

}

static VOID
GntMem_EvtFileClose(WDFFILEOBJECT file_object)
{
  UNREFERENCED_PARAMETER(file_object);

  KdPrint(("GntMem: close (ignored)\n"));

  FUNCTION_ENTER();
  FUNCTION_EXIT();
}

NTSTATUS
GntMem_DeviceFileInit(WDFDEVICE device, PWDF_IO_QUEUE_CONFIG queue_config, WDFFILEOBJECT file_object)
{

    PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
	WDF_IO_QUEUE_CONFIG internal_queue_config;
	WDF_OBJECT_ATTRIBUTES internal_queue_attributes;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(device);
	KdPrint(("GntMem: DeviceFileInit\n"));

	xpdid->EvtFileCleanup = GntMem_EvtFileCleanup;  
    xpdid->EvtFileClose = GntMem_EvtFileClose;
	queue_config->EvtIoDeviceControl = GntMem_EvtIoDeviceControl;

	WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &xpdid->gntmem.pending_queue_lock);
	WDF_IO_QUEUE_CONFIG_INIT(&internal_queue_config, WdfIoQueueDispatchManual);
	internal_queue_config.EvtIoCanceledOnQueue = GntMem_EvtIoCanceledOnPendingGrantQueue;
	WDF_OBJECT_ATTRIBUTES_INIT(&internal_queue_attributes);
	internal_queue_attributes.ParentObject = file_object;
	status = WdfIoQueueCreate(device, &internal_queue_config, &internal_queue_attributes, &xpdid->gntmem.pending_grant_requests);
	if(!NT_SUCCESS(status))
		return status;
	
	xpdid->gntmem.allowed_pages = 0;
	xpdid->gntmem.mapped_pages = 0;

	KdPrint(("GntMem: completing init\n"));

	return STATUS_SUCCESS;
}


