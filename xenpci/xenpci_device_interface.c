/*
PV Drivers for Windows Xen HVM Domains
Copyright (C) 2009 James Harper

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

VOID
XenPci_EvtDeviceFileCreate(WDFDEVICE device, WDFREQUEST request, WDFFILEOBJECT file_object)
{
  NTSTATUS status;
  PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);
  WDF_IO_QUEUE_CONFIG queue_config;
  PUNICODE_STRING filename = WdfFileObjectGetFileName(file_object);
  PWSTR reference_token;
  
  FUNCTION_ENTER();
  
  KdPrint(("XenPci_EvtDeviceFileCreate: file is %wZ\n", filename));

  if(filename->Length < 12) { /* 6 wide chars */
	  if(!filename->Buffer) {
		  KdPrint(("Failed to create a device file because the file object had no name\n"));
	  }
	  else {
		  KdPrint(("Failed to create a device file for %wZ because the name is too short\n", filename));
	  }
	  WdfRequestComplete(request, STATUS_UNSUCCESSFUL);
	  return;
  }

  // i.e. a pointer to the last 6 wide-chars of the buffer.
  // I can't find any better way of referencing a substring on a UNICODE_STRING...
  // ...but that's mostly because MSDN documentation is the work of Hades himself...
  reference_token = (PWSTR)(((char*)filename->Buffer) + (filename->Length - 12));

  KdPrint(("First 6 wchars of ref_token: %wc%wc%wc%wc%wc%wc",
	  reference_token[0], reference_token[1], reference_token[2],
	  reference_token[3], reference_token[4], reference_token[5]));

  if(RtlCompareMemory(reference_token, L"xenbus", 12) == 12) {
	  KdPrint(("File type matches Xenbus\n"));
	  xpdid->type = DEVICE_INTERFACE_TYPE_XENBUS;
  }
  else if(RtlCompareMemory(reference_token, L"evtchn", 12) == 12) {
	  KdPrint(("File type matches Evtchn\n"));
	  xpdid->type = DEVICE_INTERFACE_TYPE_EVTCHN;
  }
  else if(RtlCompareMemory(reference_token, L"gntmem", 12) == 12) {
  	  KdPrint(("File type matches Gntmem\n"));
	  xpdid->type = DEVICE_INTERFACE_TYPE_GNTMEM;
  }
  else {
	  KdPrint(("Failed to create a device file: %wZ does not end with a valid reference string\n", filename));
	  WdfRequestComplete(request, STATUS_UNSUCCESSFUL);
	  return;
  }
  
  KeInitializeSpinLock(&xpdid->lock);
  WDF_IO_QUEUE_CONFIG_INIT(&queue_config, WdfIoQueueDispatchSequential);
  status = XenBus_DeviceFileInit(device, &queue_config, file_object); /* this completes the queue init */  
  if(xpdid->type == DEVICE_INTERFACE_TYPE_XENBUS) {
	  status = XenBus_DeviceFileInit(device, &queue_config, file_object); /* this completes the queue init */  
  }
  else if(xpdid->type == DEVICE_INTERFACE_TYPE_EVTCHN) {
	  status = EvtChn_DeviceFileInit(device, &queue_config, file_object);
  }
  else {
	  status = GntMem_DeviceFileInit(device, &queue_config, file_object);
  }
  if (!NT_SUCCESS(status)) {
      WdfRequestComplete(request, STATUS_UNSUCCESSFUL);
  }
  status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, &xpdid->io_queue);
  if (!NT_SUCCESS(status)) {
      KdPrint(("Error creating queue 0x%x\n", status));
      WdfRequestComplete(request, STATUS_UNSUCCESSFUL);
  }

  WdfRequestComplete(request, STATUS_SUCCESS);
  
  FUNCTION_EXIT();
}

VOID
XenPci_EvtIoInCallerContext(WDFDEVICE Device, WDFREQUEST Request) {

	PXENPCI_DEVICE_INTERFACE_DATA xpdid;
	WDFFILEOBJECT file;
	NTSTATUS status;
	
	file = WdfRequestGetFileObject(Request);
	if(!file) {
		KdPrint(("XenPci_EvtIoInCallerContext: rejected request for null file\n"));
		WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
	}

	xpdid = GetXpdid(file);

	if(xpdid->type == DEVICE_INTERFACE_TYPE_GNTMEM) {
		GntMem_EvtIoInCallerContext(xpdid, Request, Device); // Responsible for calling enqueue
	}
	else {
		status = WdfDeviceEnqueueRequest(Device, Request);
		if(!NT_SUCCESS(status)) {
			KdPrint(("XenPci_EvtIoInCallerContext: failed to enqueue request: error %x\n", status));
			WdfRequestComplete(Request, status);
		}
		// else, drop out -- the request will now be fed to EvtRead, EvtWrite etc
	}

}

VOID
XenPci_EvtFileCleanup(WDFFILEOBJECT file_object)
{
  PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);

  FUNCTION_ENTER();
  xpdid->EvtFileCleanup(file_object);
  FUNCTION_EXIT();
}

VOID
XenPci_EvtFileClose(WDFFILEOBJECT file_object)
{
  
  PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);

  FUNCTION_ENTER();
  xpdid->EvtFileClose(file_object);
  FUNCTION_EXIT();
}

VOID
XenPci_EvtIoDefault(WDFQUEUE queue, WDFREQUEST request)
{
  WDFFILEOBJECT file_object = WdfRequestGetFileObject(request);
  PXENPCI_DEVICE_INTERFACE_DATA xpdid = GetXpdid(file_object);

  UNREFERENCED_PARAMETER(queue);
  
  FUNCTION_ENTER();
  WdfRequestForwardToIoQueue(request, xpdid->io_queue);
  FUNCTION_EXIT();
}
