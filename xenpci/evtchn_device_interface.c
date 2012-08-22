/******************************************************************************
 * evtchn.c
 * 
 * Driver for receiving and demuxing event-channel signals.
 * 
 * Copyright (c) 2004-2005, K A Fraser
 * Multi-process extensions Copyright (c) 2004, Steven Smith
 * Port to WDF Copyright (c) 2009, Chris Smowton
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

/* TODO: evtchn ioctl codes */

#include "xenpci.h"
#include <evtchn_ioctl.h>

#define ALLOW_EMPTY_EVTCHN_READ

#define EVTCHN_RING_SIZE     (PAGE_SIZE / sizeof(evtchn_port_t))
#define EVTCHN_RING_MASK(_i) ((_i)&(EVTCHN_RING_SIZE-1))

#define UNRESTRICTED_DOMID ((domid_t)-1)

typedef struct
{

  LIST_ENTRY entry;
  PXENPCI_DEVICE_DATA xpdd;
  PXENPCI_DEVICE_INTERFACE_DATA xpdid;
  evtchn_port_t port;

} XENPCI_EVTCHN_DPC_CONTEXT, *PXENPCI_EVTCHN_DPC_CONTEXT;

/* Called with device spinlock held, and so at DISPATCH level */
static VOID
EvtChn_ProcessReadRequest(WDFREQUEST request, size_t length, NTSTATUS* retcode, ULONG* retinfo)
{

	NTSTATUS status;
	WDFFILEOBJECT file_object = WdfRequestGetFileObject(request);
	PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
	unsigned int c, p, bytes1, bytes2;
	PVOID buffer;

	KdPrint(("Evtchn: processing read request\n"));
  
	status = WdfRequestRetrieveOutputBuffer(request, length, &buffer, NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint((__DRIVER_NAME, "     WdfRequestRetrieveOutputBuffer failed status = %08x\n", status));
		*retcode = status;
		*retinfo = 0;
		return;
	}

	/* Whole number of ports. Redundant check for some paths */
	length &= ~(sizeof(evtchn_port_t)-1);
	if (length == 0) {
#ifndef ALLOW_EMPTY_EVTCHN_READ
		KdPrint(("EvtChn: buffer size %d too small\n", length));
		*retcode = STATUS_BUFFER_TOO_SMALL;
		*retinfo = 0;
#else
		*retcode = STATUS_SUCCESS;
		*retinfo = 0;
#endif
		return;
	}

	if (length > PAGE_SIZE)
		length = PAGE_SIZE;
	// Because the ring is only a page itself

	c = xpdid->evtchn.ring_cons;
	p = xpdid->evtchn.ring_prod;

  	/* Byte lengths of two chunks. Chunk split (if any) is at ring wrap. */
	if (((c ^ p) & EVTCHN_RING_SIZE) != 0) {
		bytes1 = (EVTCHN_RING_SIZE - EVTCHN_RING_MASK(c)) *
			sizeof(evtchn_port_t);
		bytes2 = EVTCHN_RING_MASK(p) * sizeof(evtchn_port_t);
	} else {
		bytes1 = (p - c) * sizeof(evtchn_port_t);
		bytes2 = 0;
	}

	/* Truncate chunks according to caller's maximum byte count. */
	if (bytes1 > length) {
		bytes1 = (unsigned int)length;
		bytes2 = 0;
	} else if ((bytes1 + bytes2) > length) {
		bytes2 = (unsigned int)length - bytes1;
	}

	KeMemoryBarrier(); /* Ensure that we see the port before we copy it. */
	RtlCopyMemory(buffer, &xpdid->evtchn.ring[EVTCHN_RING_MASK(c)], bytes1);
	if(bytes2 != 0)
	     RtlCopyMemory(&(((char*)buffer)[bytes1]), &xpdid->evtchn.ring[0], bytes2);
	
//	evtchn_check_wrong_delivery(u);

	xpdid->evtchn.ring_cons += ((bytes1 + bytes2) / sizeof(evtchn_port_t));
	*retcode = STATUS_SUCCESS;
	*retinfo = (bytes1 + bytes2);
	KdPrint(("EvtChn: transferred %d bytes\n", bytes1+bytes2));

}

static void try_drain_read_queue(PXENPCI_DEVICE_INTERFACE_DATA xpdid) {

	WDFREQUEST next_request;
	NTSTATUS status;
	ULONG information;

	KdPrint(("EvtChn: Trying to drain read queue\n"));

	WdfSpinLockAcquire(xpdid->evtchn.lock);

	while(((xpdid->evtchn.ring_cons != xpdid->evtchn.ring_prod) || xpdid->evtchn.ring_overflow)
		&& NT_SUCCESS(WdfIoQueueRetrieveNextRequest(xpdid->evtchn.io_queue, &next_request))) {

		/* If a write happens now, the writer DPC will run try_drain_read_queue in a moment */

		KdPrint(("EvtChn: ring non-empty and got an IO request: going to read\n"));

		if (xpdid->evtchn.ring_overflow) {
			status = STATUS_DATA_OVERRUN;
			information = 0;
		}
		else {
			// Data available; service this request!
		    WDF_REQUEST_PARAMETERS parameters;
		    WDF_REQUEST_PARAMETERS_INIT(&parameters);
			WdfRequestGetParameters(next_request, &parameters);
			EvtChn_ProcessReadRequest(next_request, parameters.Parameters.Read.Length, &status, &information);
		}

		KdPrint(("EvtChn: completing request with status %d, information %d\n", status, information));

		WdfRequestCompleteWithInformation(next_request, status, information);
	}

	KdPrint(("EvtChn: Leaving drain-read-queue\n"));

	WdfSpinLockRelease(xpdid->evtchn.lock);

}

/* TODO: Create a mask-on-fire thing in evtchn.c

/* Called at DPC level */
void evtchn_device_upcall(PVOID context)
{

	PXENPCI_EVTCHN_DPC_CONTEXT ctx = (PXENPCI_EVTCHN_DPC_CONTEXT)context;
	/* Safe to run concurrent with unbinds/device-destroys, which call EvtChn_Unbind, which calls KeFlushQueuedDpcs,
	   therefore we are not running concurrently with them. */

	PXENPCI_DEVICE_INTERFACE_DATA xpdid = ctx->xpdid;

	KdPrint(("EvtChn: upcall against port %d\n", ctx->port));

	/* No locks for this bit; we'll take a spinlock in try_drain_read_queue to protect
	   against concurrent read events, however. */
	// TOCHECK: Is this definitely right? No concurrent DPC on another CPU can mess this up?

	if ((xpdid->evtchn.ring_prod - xpdid->evtchn.ring_cons) < EVTCHN_RING_SIZE) {
		xpdid->evtchn.ring[EVTCHN_RING_MASK(xpdid->evtchn.ring_prod)] = ctx->port;
		xpdid->evtchn.ring_prod++;
		KeMemoryBarrier(); /* Ensure ring contents visible */
	} else {
		KdPrint(("EvtChn: ring overflow\n"));
		xpdid->evtchn.ring_overflow = 1;
	}

	KdPrint(("EvtChn: Going to try drain from DPC\n"));

	try_drain_read_queue(xpdid);

}

/* HVM events are apparently always directed to CPU 0, so check_wrong_delivery is gone */

static VOID
EvtChn_EvtIoRead(WDFQUEUE queue, WDFREQUEST request, size_t length) {

	NTSTATUS status;
	WDFFILEOBJECT file_object = WdfRequestGetFileObject(request);
	PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);

	UNREFERENCED_PARAMETER(queue);
  
	FUNCTION_ENTER();

	KdPrint(("EvtChn: user read, length %d\n", length));

	/* Whole number of ports. */
	length &= ~(sizeof(evtchn_port_t)-1);
#ifndef ALLOW_EMPTY_EVTCHN_READ
	if (length == 0) {
		/* Might as well reject this early, rather than taking locks for nothing */
		KdPrint(("EvtChn: buffer of size %d too small\n", length));
		WdfRequestCompleteWithInformation(request, STATUS_BUFFER_TOO_SMALL, 0);
		return;
	}
#endif

	// Okay, this request is acceptable: queue it up
	status = WdfRequestForwardToIoQueue(request, xpdid->evtchn.io_queue);
	if(!NT_SUCCESS(status)) {
		KdPrint(("Failed to add to evtchn IO queue"));
		WdfRequestCompleteWithInformation(request, status, 0);
	}

	KdPrint(("EvtChn: Going to drain read queue from user call\n"));

	try_drain_read_queue(xpdid);

}

static VOID
EvtChn_EvtIoWrite(WDFQUEUE queue, WDFREQUEST request, size_t length)
{
	NTSTATUS status;
	PVOID buffer;
	evtchn_port_t* ports;
	PXENPCI_DEVICE_DATA xpdd = GetXpdd(WdfIoQueueGetDevice(queue));
	WDFFILEOBJECT file_object = WdfRequestGetFileObject(request);
	PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
	unsigned int i;

	KdPrint(("EvtChn: Write buffer size %d\n", length));

	status = WdfRequestRetrieveInputBuffer(request, length, &buffer, NULL);
	if(!NT_SUCCESS(status)) {
		KdPrint(("EvtChn: Failed to get write input buffer\n"));
		WdfRequestCompleteWithInformation(request, status, 0);
		return;
	}
	ports = (evtchn_port_t*)buffer;

	/* Whole number of ports. */
	length &= ~(sizeof(evtchn_port_t)-1);

	if (length == 0) {
		KdPrint(("EvtChn: write buffer smaller than one port\n"));
		WdfRequestCompleteWithInformation(request, STATUS_BUFFER_TOO_SMALL, 0);
		return;
	}

	if (length > PAGE_SIZE)
		length = PAGE_SIZE;

	WdfSpinLockAcquire(xpdd->evtchn_port_user_lock);
	for (i = 0; i < (length/sizeof(evtchn_port_t)); i++) {
		if ((ports[i] < ((unsigned)NR_EVENT_CHANNELS)) && (xpdd->evtchn_port_user[ports[i]] == xpdid)) {
			if (!EvtChn_Test_Masked(xpdd, ports[i])) {
				KdPrint(("EvtChn: user unmask of already unmasked port %d\n", ports[i]));
				continue;
			}
			KdPrint(("EvtChn: user unmask of port %d\n", ports[i]));
			EvtChn_Unmask(xpdd, ports[i]);
			EvtChn_Reset(xpdd, ports[i]); 
			/* If the channel fired whilst masked, reset so that a future fire will be recognised.
			   In the exceedingly unlikely case that the channel fired between the calls to Unmask and Reset,
			   we will see a spurious double-fire. */
		}
		else {
			KdPrint(("EvtChn: user tried to unmask non-owned port %d\n", ports[i]));
		}
	}
	WdfSpinLockRelease(xpdd->evtchn_port_user_lock);

	KdPrint(("EvtChn: Write complete\n"));

	WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, length);

}

static NTSTATUS evtchn_bind_to_user(PXENPCI_DEVICE_INTERFACE_DATA xpdid, PXENPCI_DEVICE_DATA xpdd, int port)
{

	PXENPCI_EVTCHN_DPC_CONTEXT new_context;
	NTSTATUS status;

	KdPrint(("EvtChn: Binding DPC to port %d\n", port));

	new_context = ExAllocatePoolWithTag(NonPagedPool, sizeof(*new_context), XENPCI_POOL_TAG);
	if(!new_context) {
		return STATUS_UNSUCCESSFUL;
	}

	new_context->xpdid = xpdid;
	new_context->xpdd = xpdd;
	new_context->port = port;

	WdfSpinLockAcquire(xpdd->evtchn_port_user_lock);

	InsertTailList(&xpdid->evtchn.bound_channels_list_head, (PLIST_ENTRY)new_context);
	xpdd->evtchn_port_user[port] = xpdid;

	/* Register a DPC for this channel */
	if(!NT_SUCCESS(status = EvtChn_BindDpcReplace(xpdd, port, evtchn_device_upcall, new_context, EVT_ACTION_FLAGS_DEFAULT, FALSE /* Replace */, TRUE /* Mask-on-fire */))) {
		KdPrint(("BindDpcReplace failed, status %d\n", status));
		WdfSpinLockRelease(xpdd->evtchn_port_user_lock);
		RemoveEntryList((PLIST_ENTRY)new_context);
		ExFreePoolWithTag(new_context, XENPCI_POOL_TAG);
		return status;
	}

	WdfSpinLockRelease(xpdd->evtchn_port_user_lock);

	KdPrint(("EvtChn: Add DPC complete\n"));

	EvtChn_Unmask(xpdd, port);

	return STATUS_SUCCESS;
}

static VOID
  EvtChn_EvtIoDeviceControl (
    IN WDFQUEUE  Queue,
    IN WDFREQUEST  Request,
    IN size_t  OutputBufferLength,
    IN size_t  InputBufferLength,
    IN ULONG  IoControlCode
    )
{
	NTSTATUS rc;
	PVOID inbuffer = 0;
	PVOID outbuffer = 0;
	ULONG info = 0;

	PXENPCI_DEVICE_DATA xpdd = GetXpdd(WdfIoQueueGetDevice(Queue));
	WDFFILEOBJECT file_object = WdfRequestGetFileObject(Request);
	PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);

	KdPrint(("EvtChn: IOCTL %ux with in/out buffers %d/%d\n", IoControlCode, InputBufferLength, OutputBufferLength));

	if(InputBufferLength) {
		rc = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inbuffer, NULL);
		if(!NT_SUCCESS(rc)) {
			KdPrint(("EvtChn: IOCTL couldn't map in-buffer\n"));
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
/*
	case IOCTL_EVTCHN_BIND_VIRQ: {

		struct ioctl_evtchn_bind_virq bind;
		struct evtchn_bind_virq bind_virq;

		rc = STATUS_ACCESS_DENIED;
		if (xpdid->evtchn.restrict_domid != UNRESTRICTED_DOMID)
			break;

		rc = STATUS_INVALID_ADDRESS;

		if (copy_from_user(&bind, uarg, sizeof(bind)))
			break;

		bind_virq.virq = bind.virq;
		bind_virq.vcpu = 0;
		rc = HYPERVISOR_event_channel_op(EVTCHNOP_bind_virq,
						 &bind_virq);
		if (rc != 0)
			break;

		rc = bind_virq.port;
		evtchn_bind_to_user(u, rc);
		break;
	}
	*/

	/*
	case IOCTL_EVTCHN_BIND_INTERDOMAIN: {
		
		struct ioctl_evtchn_bind_interdomain bind;
		struct evtchn_bind_interdomain bind_interdomain;

		rc = -EFAULT;
		if (copy_from_user(&bind, uarg, sizeof(bind)))
			break;

		rc = -EACCES;
		if (u->restrict_domid != UNRESTRICTED_DOMID &&
		    u->restrict_domid != bind.remote_domain)
			break;

		bind_interdomain.remote_dom  = bind.remote_domain;
		bind_interdomain.remote_port = bind.remote_port;
		rc = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain,
						 &bind_interdomain);
		if (rc != 0)
			break;

		rc = bind_interdomain.local_port;
		evtchn_bind_to_user(u, rc);
		break;
	}
	*/

	case IOCTL_EVTCHN_BIND_UNBOUND_PORT: {
		struct ioctl_evtchn_bind_unbound_port* bind = inbuffer;
		evtchn_port_t port_out;

		rc = STATUS_BUFFER_TOO_SMALL;
		if(OutputBufferLength < sizeof(evtchn_port_t) || InputBufferLength < sizeof(*bind))
			break;

		KdPrint(("EvtChn: IOCTL is bind-unbound-port with remote domain %d\n", bind->remote_domain));

		rc = STATUS_ACCESS_DENIED;
		if (xpdid->evtchn.restrict_domid != UNRESTRICTED_DOMID)
			break;

		port_out = EvtChn_AllocUnbound(xpdd, (domid_t)bind->remote_domain);
		evtchn_bind_to_user(xpdid, xpdd, port_out);

		rc = STATUS_SUCCESS;
		info = sizeof(evtchn_port_t);
		KdPrint(("EvtChn: returning new local channel %d\n", port_out));
		/* Note: overwrites first sizeof(evtchn_port_t) of input buffer */
		*(evtchn_port_t*)outbuffer = port_out;

		break;
	}

	case IOCTL_EVTCHN_UNBIND: {

		struct ioctl_evtchn_unbind* unbind = inbuffer;
		PLIST_ENTRY next_entry = 0;

		rc = STATUS_BUFFER_TOO_SMALL;
		if(InputBufferLength < sizeof(*unbind))
			break;

		KdPrint(("IOCTL is unbind port %d\n", unbind->port));

		rc = STATUS_INVALID_PARAMETER;
		if (unbind->port >= NR_EVENT_CHANNELS)
			break;

		WdfSpinLockAcquire(xpdd->evtchn_port_user_lock);
   
		if (xpdd->evtchn_port_user[unbind->port] != xpdid) {
			KdPrint(("Unbind: port does not belong to this device\n"));
			WdfSpinLockRelease(xpdd->evtchn_port_user_lock);
			break; /* i.e. return INVALID_PARAMETER */
		}

		/* Do this first, as after the actual UnBind this port could be realloc'd */
		xpdd->evtchn_port_user[unbind->port] = NULL;

		WdfSpinLockRelease(xpdd->evtchn_port_user_lock);
		// Release so we can kill the DPC, which must happen at PASSIVE_LEVEL
		KdPrint(("Unbind: flushing DPCs...\n"));
		EvtChn_Unbind(xpdd, unbind->port);
		// Flushes DPCs; the DPC bound to this port is certainly not running any longer.
		KdPrint(("Unbind: DPC disabled\n"));
		EvtChn_Close(xpdd, unbind->port);
		KdPrint(("Unbind: port closed\n"));

		/* This just stops us conflicting with a concurrent IOCTL-unbind,
		   though that may be impossible. To check: might be able to eliminate some of this
		   locking considering the rules regarding WDF IO queues; BUT bear in mind
		   that the DPC we get from EvtChn core must be synchronised w.r.t. the internal
		   pending request queue. */

		WdfSpinLockAcquire(xpdid->evtchn.lock);

		next_entry = xpdid->evtchn.bound_channels_list_head.Flink;
		while(next_entry != &xpdid->evtchn.bound_channels_list_head) {
			PXENPCI_EVTCHN_DPC_CONTEXT ctx = (PXENPCI_EVTCHN_DPC_CONTEXT)next_entry;
			if(ctx->port == unbind->port) {
				KdPrint(("Unbind: removed local record\n"));
				RemoveEntryList(next_entry);
				ExFreePoolWithTag(ctx, XENPCI_POOL_TAG);
				break;
			}
			next_entry = next_entry->Flink;
		}

		WdfSpinLockRelease(xpdid->evtchn.lock);

		rc = STATUS_SUCCESS;
		info = 0;
		break;
	}

	case IOCTL_EVTCHN_NOTIFY: {
		struct ioctl_evtchn_notify* notify = inbuffer;

		rc = STATUS_BUFFER_TOO_SMALL;
		if(InputBufferLength < sizeof(*notify))
			break;

		KdPrint(("EvtChn: IOCTL is Notify on port %d\n", notify->port));

		if (notify->port >= NR_EVENT_CHANNELS) {
			rc = STATUS_INVALID_PARAMETER;
		} else if (xpdd->evtchn_port_user[notify->port] != xpdid) {
			rc = STATUS_ACCESS_DENIED;
		} else {
			rc = EvtChn_Notify(xpdd, notify->port);
			info = 0;
		}
		break;
	}

	case IOCTL_EVTCHN_RESET: {
		KdPrint(("EvtChn: IOCTL is RESET\n"));
		/* Initialise the ring to empty. Clear errors. */
		// TOCHECK: Safe against DPCs?
		WdfSpinLockAcquire(xpdid->evtchn.lock);
		xpdid->evtchn.ring_cons = xpdid->evtchn.ring_prod = xpdid->evtchn.ring_overflow = 0;
		WdfSpinLockRelease(xpdid->evtchn.lock);
		rc = STATUS_SUCCESS;
		info = 0;
		break;
	}

	case IOCTL_EVTCHN_RESTRICT_DOMID: {
		struct ioctl_evtchn_restrict_domid* ierd = inbuffer;

		rc = STATUS_BUFFER_TOO_SMALL;
		if(InputBufferLength < sizeof(*ierd))
			break;

		KdPrint(("EvtChn: IOCTL is restrict-domid to %d\n", ierd->domid));

		rc = STATUS_ACCESS_DENIED;
		if (xpdid->evtchn.restrict_domid != UNRESTRICTED_DOMID)
			break;

		rc = STATUS_INVALID_PARAMETER;
		if (ierd->domid == 0 || ierd->domid >= DOMID_FIRST_RESERVED)
			break;

		xpdid->evtchn.restrict_domid = ierd->domid;
		rc = STATUS_SUCCESS;
		info = 0;

		break;
	}

	default:
		KdPrint(("EvtChn: IOCTL code was not recognised\n"));
		rc = STATUS_INVALID_PARAMETER;
		break;
	}

	WdfRequestCompleteWithInformation(Request, rc, info);

}

static VOID
EvtChn_EvtFileCleanup(WDFFILEOBJECT file_object)
{
    PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
    PXENPCI_DEVICE_DATA xpdd = GetXpdd(WdfFileObjectGetDevice(file_object));
	PLIST_ENTRY next_entry;

	KdPrint(("EvtChn: file cleanup entered\n"));

	ExFreePoolWithTag(xpdid->evtchn.ring, XENPCI_POOL_TAG);

	// First release ports we hold from the user-event-channels list.
	// This is sane because nobody else will get them until we call
	// EvtChn_Unbind, which must be done outside this lock.

	WdfSpinLockAcquire(xpdd->evtchn_port_user_lock);

	for(next_entry = xpdid->evtchn.bound_channels_list_head.Flink;
		next_entry != &xpdid->evtchn.bound_channels_list_head;
		next_entry = next_entry->Flink) {
		PXENPCI_EVTCHN_DPC_CONTEXT ctx = 
			(PXENPCI_EVTCHN_DPC_CONTEXT)next_entry;
		KdPrint(("EvtChn cleanup: freeing port %d\n", ctx->port));
		xpdd->evtchn_port_user[ctx->port] = NULL;
	}

	WdfSpinLockRelease(xpdd->evtchn_port_user_lock);

	// Loop once around our list of owned ports again, unregistering DPCs.
	// Deleting the contexts is alright because once we're here, there
	// can't possibly be anyone binding new channels to this device, and the
	// unbind operation flushes DPCs.
	// That flush means we couldn't do this inside the spinlock above, as flush
	// must happen as PASSIVE_LEVEL.

	KdPrint(("EvtChn: cleanup unbinding DPCs and freeing contexts...\n"));

	while(!IsListEmpty(&xpdid->evtchn.bound_channels_list_head)) {
		PXENPCI_EVTCHN_DPC_CONTEXT to_remove = 
			(PXENPCI_EVTCHN_DPC_CONTEXT)RemoveHeadList(&xpdid->evtchn.bound_channels_list_head);
		EvtChn_Unbind(xpdd, to_remove->port);
		EvtChn_Close(xpdd, to_remove->port);
		ExFreePoolWithTag(to_remove, XENPCI_POOL_TAG);
	}

	KdPrint(("EvtChn: cleanup complete\n"));

}

static VOID
EvtChn_EvtFileClose(WDFFILEOBJECT file_object)
{
  UNREFERENCED_PARAMETER(file_object);

  KdPrint(("EvtChn: close (ignored)\n"));

  FUNCTION_ENTER();
  FUNCTION_EXIT();
}

NTSTATUS
EvtChn_DeviceFileInit(WDFDEVICE device, PWDF_IO_QUEUE_CONFIG queue_config, WDFFILEOBJECT file_object)
{

	NTSTATUS status;
    PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
    WDF_IO_QUEUE_CONFIG internal_queue_config;

	KdPrint(("EvtChn: DeviceFileInit\n"));

	memset(xpdid, 0, sizeof(*xpdid));
	xpdid->EvtFileCleanup = EvtChn_EvtFileCleanup;  
    xpdid->EvtFileClose = EvtChn_EvtFileClose;
    queue_config->EvtIoRead = EvtChn_EvtIoRead;
    queue_config->EvtIoWrite = EvtChn_EvtIoWrite;
	queue_config->EvtIoDeviceControl = EvtChn_EvtIoDeviceControl;

	InitializeListHead(&xpdid->evtchn.bound_channels_list_head);
	xpdid->evtchn.ring = (evtchn_port_t *)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENPCI_POOL_TAG);

	if (xpdid->evtchn.ring == NULL) {
		KdPrint(("EvtChn: Init: Could not allocate a page\n"));
		return STATUS_NO_MEMORY;
	}

	xpdid->evtchn.ring_cons = xpdid->evtchn.ring_prod = xpdid->evtchn.ring_overflow = 0;

	WdfSpinLockCreate(NULL, &xpdid->evtchn.lock);
	xpdid->evtchn.restrict_domid = UNRESTRICTED_DOMID;

	WDF_IO_QUEUE_CONFIG_INIT(&internal_queue_config, WdfIoQueueDispatchManual);
	status = WdfIoQueueCreate(device, &internal_queue_config, WDF_NO_OBJECT_ATTRIBUTES, &xpdid->evtchn.io_queue);
    if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(xpdid->evtchn.ring, XENPCI_POOL_TAG);
		KdPrint(("Error creating queue 0x%x\n", status));
		FUNCTION_EXIT();
		return status;
    }

	KdPrint(("EvtChn: completing init\n"));

	return STATUS_SUCCESS;
}


