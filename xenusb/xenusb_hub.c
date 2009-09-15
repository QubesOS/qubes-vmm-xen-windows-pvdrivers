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

#include "xenusb.h"
#include <stdlib.h>

#pragma warning(disable: 4127) // conditional expression is constant

static VOID
XenUsbHub_EvtIoDefault(
  WDFQUEUE queue,
  WDFREQUEST request)
{
  NTSTATUS status;
  WDF_REQUEST_PARAMETERS parameters;

  FUNCTION_ENTER();

  UNREFERENCED_PARAMETER(queue);

  status = STATUS_UNSUCCESSFUL;

  WDF_REQUEST_PARAMETERS_INIT(&parameters);
  WdfRequestGetParameters(request, &parameters);

  switch (parameters.Type)
  {
  case WdfRequestTypeCreate:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeCreate\n"));
    break;
  case WdfRequestTypeClose:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeClose\n"));
    break;
  case WdfRequestTypeRead:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeRead\n"));
    break;
  case WdfRequestTypeWrite:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeWrite\n"));
    break;
  case WdfRequestTypeDeviceControl:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeDeviceControl\n"));
    
    break;
  case WdfRequestTypeDeviceControlInternal:
    KdPrint((__DRIVER_NAME "     WdfRequestTypeDeviceControlInternal\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unknown type %x\n", parameters.Type));
    break;
  }
  WdfRequestComplete(request, status);  

  FUNCTION_EXIT();
}

static NTSTATUS
XenUsbHub_BusIrpCompletionRoutine(
  PDEVICE_OBJECT device_object,
  PIRP irp,
  PVOID context)
{
  WDFREQUEST request = context;

  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();

  WdfRequestCompleteWithInformation(request, irp->IoStatus.Status, irp->IoStatus.Information);
  IoFreeIrp(irp);

  FUNCTION_EXIT();

  return STATUS_MORE_PROCESSING_REQUIRED;
}

static VOID
XenUsbHub_EvtIoDeviceControl(
  WDFQUEUE queue,
  WDFREQUEST request,
  size_t output_buffer_length,
  size_t input_buffer_length,
  ULONG io_control_code)
{
  NTSTATUS status;
  //WDFDEVICE device = WdfIoQueueGetDevice(queue);
  //PXENUSB_PDO_DEVICE_DATA xupdd = GetXupdd(device);
  //WDF_REQUEST_PARAMETERS wrp;
  //PURB urb;
  //xenusb_device_t *usb_device;

  UNREFERENCED_PARAMETER(queue);
  UNREFERENCED_PARAMETER(input_buffer_length);
  UNREFERENCED_PARAMETER(output_buffer_length);

  FUNCTION_ENTER();

  status = STATUS_UNSUCCESSFUL;

  //WDF_REQUEST_PARAMETERS_INIT(&wrp);
  //WdfRequestGetParameters(request, &wrp);

  // these are in api\usbioctl.h
  switch(io_control_code)
  {
  case IOCTL_USB_GET_NODE_INFORMATION:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_INFORMATION\n"));
    break;
  case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_CONNECTION_INFORMATION\n"));
    break;
  case IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION\n"));
    break;
  case IOCTL_USB_GET_NODE_CONNECTION_NAME:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_CONNECTION_NAME\n"));
    break;
  case IOCTL_USB_DIAG_IGNORE_HUBS_ON:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_DIAG_IGNORE_HUBS_ON\n"));
    break;
  case IOCTL_USB_DIAG_IGNORE_HUBS_OFF:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_DIAG_IGNORE_HUBS_OFF\n"));
    break;
  case IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME\n"));
    break;
  case IOCTL_USB_GET_HUB_CAPABILITIES:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_HUB_CAPABILITIES\n"));
    break;
  case IOCTL_USB_HUB_CYCLE_PORT:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_HUB_CYCLE_PORT\n"));
    break;
  case IOCTL_USB_GET_NODE_CONNECTION_ATTRIBUTES:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_CONNECTION_ATTRIBUTES\n"));
    break;
  case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX:
    KdPrint((__DRIVER_NAME "     IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX\n"));
    break;
  case IOCTL_GET_HCD_DRIVERKEY_NAME:
    KdPrint((__DRIVER_NAME "     IOCTL_GET_HCD_DRIVERKEY_NAME\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unknown IOCTL %08x\n", io_control_code));
    break;
  }
  KdPrint((__DRIVER_NAME "     Calling WdfRequestComplete with status = %08x\n", status));
  WdfRequestComplete(request, status);

  FUNCTION_EXIT();
}

static VOID
XenUsbHub_EvtIoInternalDeviceControl(
  WDFQUEUE queue,
  WDFREQUEST request,
  size_t output_buffer_length,
  size_t input_buffer_length,
  ULONG io_control_code)
{
  NTSTATUS status;
  WDFDEVICE device = WdfIoQueueGetDevice(queue);
  PXENUSB_PDO_DEVICE_DATA xupdd = GetXupdd(device);
  WDF_REQUEST_PARAMETERS wrp;
  PURB urb;
  xenusb_device_t *usb_device;

  UNREFERENCED_PARAMETER(input_buffer_length);
  UNREFERENCED_PARAMETER(output_buffer_length);

  //FUNCTION_ENTER();

  status = STATUS_UNSUCCESSFUL;

  WDF_REQUEST_PARAMETERS_INIT(&wrp);
  WdfRequestGetParameters(request, &wrp);

  // these are in api\usbioctl.h
  switch(io_control_code)
  {
  case IOCTL_INTERNAL_USB_CYCLE_PORT:
    KdPrint((__DRIVER_NAME "     IOCTL_INTERNAL_USB_CYCLE_PORT\n"));
    break;
  case IOCTL_INTERNAL_USB_ENABLE_PORT:
    KdPrint((__DRIVER_NAME "     IOCTL_INTERNAL_USB_ENABLE_PORT\n"));
    break;
  case IOCTL_INTERNAL_USB_GET_BUS_INFO:
    KdPrint((__DRIVER_NAME "     IOCTL_INTERNAL_USB_GET_BUS_INFO\n"));
    break;
  case IOCTL_INTERNAL_USB_GET_CONTROLLER_NAME:
    KdPrint((__DRIVER_NAME "     IOCTL_INTERNAL_USB_GET_CONTROLLER_NAME\n"));
    break;
  case IOCTL_INTERNAL_USB_GET_HUB_COUNT:
    KdPrint((__DRIVER_NAME "     IOCTL_INTERNAL_USB_GET_HUB_COUNT\n"));
    KdPrint((__DRIVER_NAME "     Count before increment = %p\n", *(PULONG)wrp.Parameters.Others.Arg1));
    (*(PULONG)wrp.Parameters.Others.Arg1)++;
    status = STATUS_SUCCESS;
    break;
  case IOCTL_INTERNAL_USB_GET_HUB_NAME:
    KdPrint((__DRIVER_NAME "     IOCTL_INTERNAL_USB_GET_HUB_NAME\n"));
    break;
  case IOCTL_INTERNAL_USB_GET_PORT_STATUS:
    KdPrint((__DRIVER_NAME "     IOCTL_INTERNAL_USB_GET_PORT_STATUS\n"));
    *(PULONG)wrp.Parameters.Others.Arg1 = USBD_PORT_ENABLED | USBD_PORT_CONNECTED; /* enabled and connected */
    status = STATUS_SUCCESS;
    break;
  case IOCTL_INTERNAL_USB_GET_ROOTHUB_PDO:
    KdPrint((__DRIVER_NAME "     IOCTL_INTERNAL_USB_GET_ROOTHUB_PDO\n"));
    KdPrint((__DRIVER_NAME "     WdfDeviceWdmGetPhysicalDevice(device) = %p\n", WdfDeviceWdmGetPhysicalDevice(device)));
    KdPrint((__DRIVER_NAME "     WdfDeviceWdmGetDeviceObject(device) = %p\n", WdfDeviceWdmGetDeviceObject(device)));
    KdPrint((__DRIVER_NAME "     WdfDeviceWdmGetAttachedDevice(device) = %p\n", WdfDeviceWdmGetAttachedDevice(device)));
    KdPrint((__DRIVER_NAME "     IoGetAttachedDevice(WdfDeviceWdmGetDeviceObject(device)) = %p\n", IoGetAttachedDevice(WdfDeviceWdmGetDeviceObject(device))));
    *(PVOID *)wrp.Parameters.Others.Arg1 = WdfDeviceWdmGetPhysicalDevice(device);
    *(PVOID *)wrp.Parameters.Others.Arg2 = IoGetAttachedDevice(WdfDeviceWdmGetDeviceObject(device));
    status = STATUS_SUCCESS;
    break;
  case IOCTL_INTERNAL_USB_RESET_PORT:
    KdPrint((__DRIVER_NAME "     IOCTL_INTERNAL_USB_RESET_PORT\n"));
    break;
  case IOCTL_INTERNAL_USB_SUBMIT_IDLE_NOTIFICATION:
    KdPrint((__DRIVER_NAME "     IOCTL_INTERNAL_USB_SUBMIT_IDLE_NOTIFICATION\n"));
    break;
  case IOCTL_INTERNAL_USB_SUBMIT_URB:
    urb = (PURB)wrp.Parameters.Others.Arg1;
    ASSERT(urb);
    usb_device = urb->UrbHeader.UsbdDeviceHandle;
    if (!usb_device)
      usb_device = xupdd->usb_device;
    WdfRequestForwardToIoQueue(request, usb_device->urb_queue);
    return;
  case IOCTL_INTERNAL_USB_GET_DEVICE_HANDLE:
    KdPrint((__DRIVER_NAME "     IOCTL_INTERNAL_USB_GET_DEVICE_HANDLE (returning %p)\n", xupdd->usb_device));
    *(PVOID *)wrp.Parameters.Others.Arg1 = xupdd->usb_device;
    status = STATUS_SUCCESS;
    break;
  default:
    KdPrint((__DRIVER_NAME "     Unknown IOCTL %08x\n", io_control_code));
    break;
  }  

  KdPrint((__DRIVER_NAME "     Calling WdfRequestComplete with status = %08x\n", status));
  WdfRequestComplete(request, status);

  //FUNCTION_EXIT();
}

NTSTATUS
XenUsbHub_EvtDeviceD0Entry(WDFDEVICE device, WDF_POWER_DEVICE_STATE previous_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  
  UNREFERENCED_PARAMETER(device);

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
  
  FUNCTION_EXIT();
  
  return status;
}

NTSTATUS
XenUsbHub_EvtDeviceD0Exit(WDFDEVICE device, WDF_POWER_DEVICE_STATE target_state)
{
  NTSTATUS status = STATUS_SUCCESS;
  //PXENUSB_PDO_DEVICE_DATA xupdd = GetXupdd(device);
  //PXENUSB_DEVICE_DATA xudd = GetXudd(xupdd->wdf_device_bus_fdo);

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
XenUsbHub_EvtDevicePrepareHardware(WDFDEVICE device, WDFCMRESLIST resources_raw, WDFCMRESLIST resources_translated)
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
XenUsbHub_EvtDeviceReleaseHardware(WDFDEVICE device, WDFCMRESLIST resources_translated)
{
  NTSTATUS status = STATUS_SUCCESS;
  
  UNREFERENCED_PARAMETER(device);
  UNREFERENCED_PARAMETER(resources_translated);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
  
  return status;
}

static VOID
XenUsbHub_EvtDeviceUsageNotification(WDFDEVICE device, WDF_SPECIAL_FILE_TYPE notification_type, BOOLEAN is_in_notification_path)
{
  PXENUSB_PDO_DEVICE_DATA xupdd = GetXupdd(device);

  UNREFERENCED_PARAMETER(xupdd);

  FUNCTION_ENTER();
  
  switch (notification_type)
  {
  case WdfSpecialFilePaging:
    KdPrint((__DRIVER_NAME "     notification_type = Paging, flag = %d\n", is_in_notification_path));
    break;
  case WdfSpecialFileHibernation:
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

static NTSTATUS
XenUsb_SubmitCompletionRoutine(
  PDEVICE_OBJECT device_object,
  PIRP irp,
  PVOID context)
{
  UNREFERENCED_PARAMETER(device_object);

  FUNCTION_ENTER();
  
  if (irp->PendingReturned)
  {
    KeSetEvent ((PKEVENT)context, IO_NO_INCREMENT, FALSE);
  }

  FUNCTION_EXIT();

  return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
XenPciPdo_UBIH_CreateUsbDevice(
  PVOID BusContext,
  PUSB_DEVICE_HANDLE *DeviceHandle,
  PUSB_DEVICE_HANDLE *HubDeviceHandle,
  USHORT PortStatus,
  USHORT PortNumber)
{
  NTSTATUS status = STATUS_SUCCESS;
  WDFDEVICE device = BusContext;
  FUNCTION_ENTER();

  KdPrint((__DRIVER_NAME "     device = %p\n", device));
  KdPrint((__DRIVER_NAME "     DeviceHandle = %p\n", DeviceHandle));
  KdPrint((__DRIVER_NAME "     *DeviceHandle = %p\n", *DeviceHandle));
  KdPrint((__DRIVER_NAME "     HubDeviceHandle = %p\n", HubDeviceHandle));
  KdPrint((__DRIVER_NAME "     *HubDeviceHandle = %p\n", *HubDeviceHandle));
  KdPrint((__DRIVER_NAME "     PortStatus = %04X\n", PortStatus));
  KdPrint((__DRIVER_NAME "     PortNumber = %d\n", PortNumber));
  *DeviceHandle = ExAllocatePoolWithTag(NonPagedPool, sizeof(xenusb_device_t), XENUSB_POOL_TAG);
  
  FUNCTION_EXIT();
  return status;
}

static VOID
XenUsb_SetEventCallback(usbif_shadow_t *shadow)
{
  FUNCTION_ENTER();
  KeSetEvent(&shadow->event, IO_NO_INCREMENT, FALSE);
  FUNCTION_EXIT();
}

static NTSTATUS
XenPciPdo_UBIH_InitializeUsbDevice(
 PVOID BusContext,
 PUSB_DEVICE_HANDLE DeviceHandle)
{
  NTSTATUS status = STATUS_SUCCESS;
  WDFDEVICE device = BusContext;
  PXENUSB_PDO_DEVICE_DATA xupdd = GetXupdd(device);
  PXENUSB_DEVICE_DATA xudd = GetXudd(xupdd->wdf_device_bus_fdo);
  WDF_IO_QUEUE_CONFIG queue_config;
  xenusb_device_t *usb_device = DeviceHandle;
  PUCHAR ptr;
  PVOID buf;
  PMDL mdl;
  usbif_shadow_t *shadow;
  PUSB_DEVICE_DESCRIPTOR device_descriptor;
  PUSB_CONFIGURATION_DESCRIPTOR config_descriptor;
  PUSB_INTERFACE_DESCRIPTOR interface_descriptor;
  PUSB_ENDPOINT_DESCRIPTOR endpoint_descriptor;
  int i, j, k;
  PUSB_DEFAULT_PIPE_SETUP_PACKET setup_packet;
  
  FUNCTION_ENTER();

  KdPrint((__DRIVER_NAME "     device = %p\n", device));
  KdPrint((__DRIVER_NAME "     usb_device = %p\n", usb_device));
  usb_device->pdo_device = BusContext;
  
  // get address from freelist and assign it to the device...
  usb_device->address = 2;
  // and get this stuff properly...
  usb_device->port_number = 1;
  xupdd->usb_device->device_speed = UsbHighSpeed;
  xupdd->usb_device->device_type = Usb20Device;

  buf = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENUSB_POOL_TAG);
  mdl = IoAllocateMdl(buf, PAGE_SIZE, FALSE, FALSE, NULL);
  MmBuildMdlForNonPagedPool(mdl);
  shadow = get_shadow_from_freelist(xudd);

  /* set the address */
  KeInitializeEvent(&shadow->event, NotificationEvent, FALSE);
  shadow->callback = XenUsb_SetEventCallback;
  shadow->req.id = shadow->id;
  shadow->req.pipe = LINUX_PIPE_TYPE_CTRL | usb_device->port_number;
  shadow->req.transfer_flags = 0; 
  shadow->req.buffer_length = 0;
  setup_packet = (PUSB_DEFAULT_PIPE_SETUP_PACKET)shadow->req.u.ctrl;
  setup_packet->bmRequestType.Recipient = BMREQUEST_TO_DEVICE;
  setup_packet->bmRequestType.Type = BMREQUEST_STANDARD;
  setup_packet->bmRequestType.Dir = BMREQUEST_HOST_TO_DEVICE;
  setup_packet->bRequest = USB_REQUEST_SET_ADDRESS;
  setup_packet->wValue.W = usb_device->address;
  setup_packet->wIndex.W = 0;
  setup_packet->wLength = shadow->req.buffer_length;
  status = XenUsb_ExecuteRequest(xudd, shadow, NULL, NULL, 0);
  //TODO: Handle failure here
  KeWaitForSingleObject(&shadow->event, Executive, KernelMode, FALSE, NULL);
  KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
  KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
  KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
  KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
  KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));

  /* get the device descriptor */
  KeInitializeEvent(&shadow->event, NotificationEvent, FALSE);
  shadow->callback = XenUsb_SetEventCallback;
  shadow->req.id = shadow->id;
  shadow->req.pipe = LINUX_PIPE_DIRECTION_IN | LINUX_PIPE_TYPE_CTRL | (usb_device->address << 8) | usb_device->port_number;
  shadow->req.transfer_flags = 0; 
  shadow->req.buffer_length = PAGE_SIZE;
  setup_packet = (PUSB_DEFAULT_PIPE_SETUP_PACKET)shadow->req.u.ctrl;
  setup_packet->bmRequestType.Recipient = BMREQUEST_TO_DEVICE;
  setup_packet->bmRequestType.Type = BMREQUEST_STANDARD;
  setup_packet->bmRequestType.Dir = BMREQUEST_DEVICE_TO_HOST;
  setup_packet->bRequest = USB_REQUEST_GET_DESCRIPTOR;
  setup_packet->wValue.LowByte = 0;
  setup_packet->wValue.HiByte = USB_DEVICE_DESCRIPTOR_TYPE; //device descriptor
  setup_packet->wIndex.W = 0;
  setup_packet->wLength = shadow->req.buffer_length;
  status = XenUsb_ExecuteRequest(xudd, shadow, NULL, mdl, PAGE_SIZE);
  //TODO: Handle failure here
  KeWaitForSingleObject(&shadow->event, Executive, KernelMode, FALSE, NULL);
  KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
  KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
  KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
  KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
  KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));
  ptr = buf;
  device_descriptor = (PUSB_DEVICE_DESCRIPTOR)ptr;
  KdPrint((__DRIVER_NAME "     bLength = %d\n", device_descriptor->bLength));
  KdPrint((__DRIVER_NAME "     bNumConfigurations = %d\n", device_descriptor->bNumConfigurations));
  memcpy(&usb_device->device_descriptor, device_descriptor, device_descriptor->bLength);
  usb_device->configs = ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID) * device_descriptor->bNumConfigurations, XENUSB_POOL_TAG);
  KdPrint((__DRIVER_NAME "     bLength = %d\n", device_descriptor->bLength));
  KdPrint((__DRIVER_NAME "     bDescriptorType = %d\n", device_descriptor->bDescriptorType));
  KdPrint((__DRIVER_NAME "     bcdUSB = %04x\n", device_descriptor->bcdUSB));
  KdPrint((__DRIVER_NAME "     bDeviceClass = %02x\n", device_descriptor->bDeviceClass));
  KdPrint((__DRIVER_NAME "     bDeviceSubClass = %02x\n", device_descriptor->bDeviceSubClass));
  KdPrint((__DRIVER_NAME "     bDeviceProtocol = %02x\n", device_descriptor->bDeviceProtocol));
  KdPrint((__DRIVER_NAME "     idVendor = %04x\n", device_descriptor->idVendor));
  KdPrint((__DRIVER_NAME "     idProduct = %04x\n", device_descriptor->idProduct));
  KdPrint((__DRIVER_NAME "     bcdDevice = %04x\n", device_descriptor->bcdDevice));
  KdPrint((__DRIVER_NAME "     bNumConfigurations = %04x\n", device_descriptor->bNumConfigurations));

  /* get the config descriptor */
  for (i = 0; i < device_descriptor->bNumConfigurations; i++)
  {
    KeInitializeEvent(&shadow->event, NotificationEvent, FALSE);
    shadow->callback = XenUsb_SetEventCallback;
    shadow->req.id = shadow->id;
    shadow->req.pipe = LINUX_PIPE_DIRECTION_IN | LINUX_PIPE_TYPE_CTRL | (usb_device->address << 8) | usb_device->port_number;
    shadow->req.transfer_flags = 0; 
    shadow->req.buffer_length = PAGE_SIZE;
    setup_packet = (PUSB_DEFAULT_PIPE_SETUP_PACKET)shadow->req.u.ctrl;
    setup_packet->bmRequestType.Recipient = BMREQUEST_TO_DEVICE;
    setup_packet->bmRequestType.Type = BMREQUEST_STANDARD;
    setup_packet->bmRequestType.Dir = BMREQUEST_DEVICE_TO_HOST;
    setup_packet->bRequest = USB_REQUEST_GET_DESCRIPTOR;
    setup_packet->wValue.LowByte = (UCHAR)(i + 1);
    setup_packet->wValue.HiByte = USB_CONFIGURATION_DESCRIPTOR_TYPE; //device descriptor
    setup_packet->wIndex.W = 0;
    setup_packet->wLength = shadow->req.buffer_length;
    status = XenUsb_ExecuteRequest(xudd, shadow, buf, NULL, PAGE_SIZE);
    //TODO: Handle failure here
    KeWaitForSingleObject(&shadow->event, Executive, KernelMode, FALSE, NULL);
    KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
    KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
    KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
    KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
    KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));
    ptr = buf;
    config_descriptor = (PUSB_CONFIGURATION_DESCRIPTOR)ptr;
    KdPrint((__DRIVER_NAME "     Config %d\n", i));
    KdPrint((__DRIVER_NAME "      bLength = %d\n", config_descriptor->bLength));
    KdPrint((__DRIVER_NAME "      bDescriptorType = %d\n", config_descriptor->bDescriptorType));
    KdPrint((__DRIVER_NAME "      wTotalLength = %d\n", config_descriptor->wTotalLength));
    KdPrint((__DRIVER_NAME "      bNumInterfaces = %d\n", config_descriptor->bNumInterfaces));
    KdPrint((__DRIVER_NAME "      iConfiguration = %d\n", config_descriptor->iConfiguration));
    KdPrint((__DRIVER_NAME "      bConfigurationValue = %d\n", config_descriptor->bConfigurationValue));
    KdPrint((__DRIVER_NAME "      bmAttributes = %02x\n", config_descriptor->bmAttributes));
    KdPrint((__DRIVER_NAME "      MaxPower = %d\n", config_descriptor->MaxPower));
    usb_device->configs[i] = ExAllocatePoolWithTag(NonPagedPool, sizeof(xenusb_config_t) + sizeof(PVOID) * config_descriptor->bNumInterfaces, XENUSB_POOL_TAG);
    usb_device->configs[i]->device = usb_device;
    memcpy(&usb_device->configs[i]->config_descriptor, config_descriptor, sizeof(USB_CONFIGURATION_DESCRIPTOR));
    ptr += config_descriptor->bLength;
    for (j = 0; j < config_descriptor->bNumInterfaces; j++)
    {
      interface_descriptor = (PUSB_INTERFACE_DESCRIPTOR)ptr;
      KdPrint((__DRIVER_NAME "       Interface %d\n", j));
      KdPrint((__DRIVER_NAME "        bLength = %d\n", interface_descriptor->bLength));
      KdPrint((__DRIVER_NAME "        bDescriptorType = %d\n", interface_descriptor->bDescriptorType));
      KdPrint((__DRIVER_NAME "        bInterfaceNumber = %d\n", interface_descriptor->bInterfaceNumber));
      KdPrint((__DRIVER_NAME "        bAlternateSetting = %d\n", interface_descriptor->bAlternateSetting));
      KdPrint((__DRIVER_NAME "        bNumEndpoints = %d\n", interface_descriptor->bNumEndpoints));
      KdPrint((__DRIVER_NAME "        bInterfaceClass = %d\n", interface_descriptor->bInterfaceClass));
      KdPrint((__DRIVER_NAME "        bInterfaceSubClass = %d\n", interface_descriptor->bInterfaceSubClass));
      KdPrint((__DRIVER_NAME "        bInterfaceProtocol = %d\n", interface_descriptor->bInterfaceProtocol));
      KdPrint((__DRIVER_NAME "        iInterface = %d\n", interface_descriptor->iInterface));
      ptr += interface_descriptor->bLength;
      usb_device->configs[i]->interfaces[j] = ExAllocatePoolWithTag(NonPagedPool, sizeof(xenusb_interface_t) + sizeof(PVOID) * interface_descriptor->bNumEndpoints, XENUSB_POOL_TAG);
      usb_device->configs[i]->interfaces[j]->config = usb_device->configs[i];
      memcpy(&usb_device->configs[i]->interfaces[j]->interface_descriptor, interface_descriptor, sizeof(USB_INTERFACE_DESCRIPTOR));
      for (k = 0; k < interface_descriptor->bNumEndpoints; k++)
      {
        endpoint_descriptor = (PUSB_ENDPOINT_DESCRIPTOR)ptr;
        KdPrint((__DRIVER_NAME "        Endpoint %d\n", k));
        KdPrint((__DRIVER_NAME "         bLength = %d\n", endpoint_descriptor->bLength));
        KdPrint((__DRIVER_NAME "         bDescriptorType = %d\n", endpoint_descriptor->bDescriptorType));
        KdPrint((__DRIVER_NAME "         bEndpointAddress = %02x\n", endpoint_descriptor->bEndpointAddress));
        KdPrint((__DRIVER_NAME "         bmAttributes = %02x\n", endpoint_descriptor->bmAttributes));
        KdPrint((__DRIVER_NAME "         wMaxPacketSize = %d\n", endpoint_descriptor->wMaxPacketSize));
        KdPrint((__DRIVER_NAME "         bInterval = %d\n", endpoint_descriptor->bInterval));
        ptr += endpoint_descriptor->bLength;
        usb_device->configs[i]->interfaces[j]->endpoints[k] = ExAllocatePoolWithTag(NonPagedPool, sizeof(xenusb_endpoint_t), XENUSB_POOL_TAG);
        usb_device->configs[i]->interfaces[j]->endpoints[k]->interface = usb_device->configs[i]->interfaces[j];
        usb_device->configs[i]->interfaces[j]->endpoints[k]->pipe_value = (usb_device->address << 8) | usb_device->port_number;
        /* linux uses nonstandard endpoint type identifiers... */
        switch(endpoint_descriptor->bmAttributes & USB_ENDPOINT_TYPE_MASK)
        {
        case USB_ENDPOINT_TYPE_CONTROL:
          usb_device->configs[i]->interfaces[j]->endpoints[k]->pipe_value |= LINUX_PIPE_TYPE_CTRL;
          break;
        case USB_ENDPOINT_TYPE_ISOCHRONOUS:
          usb_device->configs[i]->interfaces[j]->endpoints[k]->pipe_value |= LINUX_PIPE_TYPE_ISOC;
          break;
        case USB_ENDPOINT_TYPE_BULK:
          usb_device->configs[i]->interfaces[j]->endpoints[k]->pipe_value |= LINUX_PIPE_TYPE_BULK;
          break;
        case USB_ENDPOINT_TYPE_INTERRUPT:
          usb_device->configs[i]->interfaces[j]->endpoints[k]->pipe_value |= LINUX_PIPE_TYPE_INTR;
          break;
        }
        usb_device->configs[i]->interfaces[j]->endpoints[k]->pipe_value |= (endpoint_descriptor->bEndpointAddress & 0x80);
        usb_device->configs[i]->interfaces[j]->endpoints[k]->pipe_value |= (endpoint_descriptor->bEndpointAddress & 0x0F) << 15;
        memcpy(&usb_device->configs[i]->interfaces[j]->endpoints[k]->endpoint_descriptor, endpoint_descriptor, sizeof(USB_ENDPOINT_DESCRIPTOR));
      }
    }
  }
  usb_device->active_config = usb_device->configs[0];
  usb_device->active_interface = usb_device->configs[0]->interfaces[0];

  WDF_IO_QUEUE_CONFIG_INIT(&queue_config, WdfIoQueueDispatchParallel);
  queue_config.EvtIoInternalDeviceControl = XenUsb_EvtIoInternalDeviceControl_DEVICE_SUBMIT_URB;
  queue_config.PowerManaged = TRUE; /* power managed queue for SUBMIT_URB */
  status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, &usb_device->urb_queue);
  if (!NT_SUCCESS(status)) {
      KdPrint((__DRIVER_NAME "     Error creating urb_queue 0x%x\n", status));
      return status;
  }

  put_shadow_on_freelist(xudd, shadow);

  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIH_GetUsbDescriptors(
  PVOID BusContext,
  PUSB_DEVICE_HANDLE DeviceHandle,
  PUCHAR DeviceDescriptorBuffer,
  PULONG DeviceDescriptorBufferLength,
  PUCHAR ConfigDescriptorBuffer,
  PULONG ConfigDescriptorBufferLength
  )
{
  NTSTATUS status = STATUS_SUCCESS;
  WDFDEVICE device = BusContext;
  xenusb_device_t *usb_device = DeviceHandle;
  xenusb_config_t *usb_config;
  PUCHAR ptr;

  FUNCTION_ENTER();

  KdPrint((__DRIVER_NAME "     device = %p\n", device));
  KdPrint((__DRIVER_NAME "     DeviceHandle = %p\n", DeviceHandle));
  KdPrint((__DRIVER_NAME "     DeviceDescriptorBuffer = %p\n", DeviceDescriptorBuffer));
  KdPrint((__DRIVER_NAME "     DeviceDescriptorBufferLength = %d\n", *DeviceDescriptorBufferLength));
  KdPrint((__DRIVER_NAME "     ConfigDescriptorBuffer = %p\n", ConfigDescriptorBuffer));
  KdPrint((__DRIVER_NAME "     ConfigDescriptorBufferLength = %d\n", *ConfigDescriptorBufferLength));
  
  memcpy(DeviceDescriptorBuffer, &usb_device->device_descriptor, usb_device->device_descriptor.bLength);
  *DeviceDescriptorBufferLength = usb_device->device_descriptor.bLength;
  
  usb_config = usb_device->active_config;
  ptr = ConfigDescriptorBuffer;
  KdPrint((__DRIVER_NAME "     memcpy(%p, %p, %d)\n", ptr, &usb_config->config_descriptor, sizeof(USB_CONFIGURATION_DESCRIPTOR)));
  memcpy(ptr, &usb_config->config_descriptor, sizeof(USB_CONFIGURATION_DESCRIPTOR));
  ptr += sizeof(USB_CONFIGURATION_DESCRIPTOR);
#if 0
  for (i = 0; i < usb_config->config_descriptor.bNumInterfaces; i++)
  {
    memcpy(ptr, &usb_config->interfaces[i]->interface_descriptor, sizeof(USB_INTERFACE_DESCRIPTOR));
    ptr += sizeof(USB_INTERFACE_DESCRIPTOR);
    ((PUSB_CONFIGURATION_DESCRIPTOR)ConfigDescriptorBuffer)->wTotalLength += sizeof(USB_INTERFACE_DESCRIPTOR);
    for (j = 0; j < usb_config->interfaces[i]->interface_descriptor.bNumEndpoints; j++)
    {
      memcpy(ptr, &usb_config->interfaces[i]->endpoints[j]->endpoint_descriptor, sizeof(USB_ENDPOINT_DESCRIPTOR));
      ptr += sizeof(USB_ENDPOINT_DESCRIPTOR);
      ((PUSB_CONFIGURATION_DESCRIPTOR)ConfigDescriptorBuffer)->wTotalLength += sizeof(USB_ENDPOINT_DESCRIPTOR);
    }
  }
#endif
  *ConfigDescriptorBufferLength = sizeof(USB_CONFIGURATION_DESCRIPTOR); //((PUSB_CONFIGURATION_DESCRIPTOR)ConfigDescriptorBuffer)->wTotalLength;
  
  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIH_RemoveUsbDevice (
 PVOID BusContext,
 PUSB_DEVICE_HANDLE DeviceHandle,
 ULONG Flags)
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(BusContext);
  UNREFERENCED_PARAMETER(DeviceHandle);

  FUNCTION_ENTER();
  
  if (Flags & USBD_KEEP_DEVICE_DATA)
    KdPrint((__DRIVER_NAME "     USBD_KEEP_DEVICE_DATA\n"));
    
  if (Flags & USBD_MARK_DEVICE_BUSY)
    KdPrint((__DRIVER_NAME "     USBD_MARK_DEVICE_BUSY\n"));

  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIH_RestoreUsbDevice(
  PVOID BusContext,
  PUSB_DEVICE_HANDLE OldDeviceHandle,
  PUSB_DEVICE_HANDLE NewDeviceHandle)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  UNREFERENCED_PARAMETER(BusContext);
  UNREFERENCED_PARAMETER(OldDeviceHandle);
  UNREFERENCED_PARAMETER(NewDeviceHandle);
  
  FUNCTION_ENTER();

  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIH_GetPortHackFlags(
 PVOID BusContext,
 PULONG HackFlags)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  UNREFERENCED_PARAMETER(BusContext);
  UNREFERENCED_PARAMETER(HackFlags);

  FUNCTION_ENTER();

  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIH_QueryDeviceInformation(
  PVOID BusContext,
  PUSB_DEVICE_HANDLE DeviceHandle,
  PVOID DeviceInformationBuffer,
  ULONG DeviceInformationBufferLength,
  PULONG LengthOfDataReturned)
{
  PUSB_DEVICE_INFORMATION_0 udi = DeviceInformationBuffer;
  xenusb_device_t *usb_device = DeviceHandle;
  ULONG i;

  FUNCTION_ENTER();

  KdPrint((__DRIVER_NAME "     BusContext = %p\n", BusContext));
  KdPrint((__DRIVER_NAME "     DeviceHandle = %p\n", DeviceHandle));
  KdPrint((__DRIVER_NAME "     DeviceInformationBuffer = %p\n", DeviceInformationBuffer));
  KdPrint((__DRIVER_NAME "     DeviceInformationBufferLength = %d\n", DeviceInformationBufferLength));
  KdPrint((__DRIVER_NAME "     ->InformationLevel = %d\n", udi->InformationLevel));
  if (DeviceInformationBufferLength < (ULONG)FIELD_OFFSET(USB_DEVICE_INFORMATION_0, PipeList[usb_device->active_interface->interface_descriptor.bNumEndpoints]))
  {
    KdPrint((__DRIVER_NAME "     STATUS_BUFFER_TOO_SMALL\n"));
    FUNCTION_EXIT();
    return STATUS_BUFFER_TOO_SMALL;
  }
  if (udi->InformationLevel != 0)
  {
    KdPrint((__DRIVER_NAME "     STATUS_NOT_SUPPORTED\n"));
    FUNCTION_EXIT();
    return STATUS_NOT_SUPPORTED;
  }
  udi->ActualLength = FIELD_OFFSET(USB_DEVICE_INFORMATION_0, PipeList[usb_device->active_interface->interface_descriptor.bNumEndpoints]);
  udi->PortNumber = 1;
  memcpy(&udi->DeviceDescriptor, &usb_device->device_descriptor, sizeof(USB_DEVICE_DESCRIPTOR));
  udi->CurrentConfigurationValue = usb_device->active_config->config_descriptor.bConfigurationValue;
  udi->DeviceAddress = usb_device->address;
  udi->HubAddress = 1; // ?
  udi->DeviceSpeed = usb_device->device_speed;
  udi->DeviceType = usb_device->device_type;
  udi->NumberOfOpenPipes = usb_device->active_interface->interface_descriptor.bNumEndpoints;
  for (i = 0; i < usb_device->active_interface->interface_descriptor.bNumEndpoints; i++)
  {
    memcpy(&udi->PipeList[i].EndpointDescriptor, &usb_device->active_interface->endpoints[i]->endpoint_descriptor, sizeof(USB_ENDPOINT_DESCRIPTOR));
    udi->PipeList[0].ScheduleOffset = 0; // not necessarily right
  }
  *LengthOfDataReturned = udi->ActualLength;
  FUNCTION_EXIT();
  return STATUS_SUCCESS;
}

static NTSTATUS
XenPciPdo_UBIH_GetControllerInformation (
  PVOID BusContext,
  PVOID ControllerInformationBuffer,
  ULONG ControllerInformationBufferLength,
  PULONG LengthOfDataReturned)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;
  PUSB_CONTROLLER_INFORMATION_0 uci = ControllerInformationBuffer;
  //WDFDEVICE device = BusContext;
  //xenusb_device_t *usb_device = DeviceHandle;

  FUNCTION_ENTER();

  KdPrint((__DRIVER_NAME "     BusContext = %p\n", BusContext));
  KdPrint((__DRIVER_NAME "     ControllerInformationBuffer = %p\n", ControllerInformationBuffer));
  KdPrint((__DRIVER_NAME "     ControllerInformationBufferLength = %d\n", ControllerInformationBufferLength));
  KdPrint((__DRIVER_NAME "     ->InformationLevel = %d\n", uci->InformationLevel));
  if (ControllerInformationBufferLength < sizeof(USB_CONTROLLER_INFORMATION_0))
  {
    KdPrint((__DRIVER_NAME "     STATUS_BUFFER_TOO_SMALL\n"));
    FUNCTION_EXIT();
    return STATUS_BUFFER_TOO_SMALL;
  }
  if (uci->InformationLevel != 0)
  {
    KdPrint((__DRIVER_NAME "     STATUS_NOT_SUPPORTED\n"));
    FUNCTION_EXIT();
    return STATUS_NOT_SUPPORTED;
  }
  
  uci->ActualLength = sizeof(USB_CONTROLLER_INFORMATION_0);
  uci->SelectiveSuspendEnabled = FALSE;
  uci->IsHighSpeedController = TRUE;
  *LengthOfDataReturned = uci->ActualLength;
  
  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIH_ControllerSelectiveSuspend (
  PVOID BusContext,
  BOOLEAN Enable)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  UNREFERENCED_PARAMETER(BusContext);
  UNREFERENCED_PARAMETER(Enable);
  
  FUNCTION_ENTER();

  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIH_GetExtendedHubInformation (
  PVOID BusContext,
  PDEVICE_OBJECT HubPhysicalDeviceObject,
  PVOID HubInformationBuffer,
  ULONG HubInformationBufferLength,
  PULONG LengthOfDataReturned)
{
  PUSB_EXTHUB_INFORMATION_0 hib = HubInformationBuffer;
  ULONG i;

  FUNCTION_ENTER();

  KdPrint((__DRIVER_NAME "     BusContext = %p\n", BusContext));
  KdPrint((__DRIVER_NAME "     HubPhysicalDeviceObject = %p\n", HubPhysicalDeviceObject));
  KdPrint((__DRIVER_NAME "     HubInformationBuffer = %p\n", HubInformationBuffer));
  KdPrint((__DRIVER_NAME "     HubInformationBufferLength = %d\n", HubInformationBufferLength));
  KdPrint((__DRIVER_NAME "     ->InformationLevel = %d\n", hib->InformationLevel));
  if (HubInformationBufferLength < (ULONG)FIELD_OFFSET(USB_EXTHUB_INFORMATION_0, Port[8]))
  {
    KdPrint((__DRIVER_NAME "     STATUS_BUFFER_TOO_SMALL\n"));
    FUNCTION_EXIT();
    return STATUS_BUFFER_TOO_SMALL;
  }
  if (hib->InformationLevel != 0)
  {
    KdPrint((__DRIVER_NAME "     STATUS_NOT_SUPPORTED\n"));
    FUNCTION_EXIT();
    return STATUS_NOT_SUPPORTED;
  }
  //hib->InformationLevel = 0;
  hib->NumberOfPorts = 8;
  for (i = 0; i < hib->NumberOfPorts; i++)
  {
    hib->Port[i].PhysicalPortNumber = i + 1;
    hib->Port[i].PortLabelNumber = i + 1;
    hib->Port[i].VidOverride = 0;
    hib->Port[i].PidOverride = 0;
    hib->Port[i].PortAttributes = USB_PORTATTR_SHARED_USB2; // | USB_PORTATTR_NO_OVERCURRENT_UI;
  }
  *LengthOfDataReturned = FIELD_OFFSET(USB_EXTHUB_INFORMATION_0, Port[8]);
  FUNCTION_EXIT();
  return STATUS_SUCCESS;
}

static NTSTATUS
XenPciPdo_UBIH_GetRootHubSymbolicName(
  PVOID BusContext,
  PVOID HubInformationBuffer,
  ULONG HubInformationBufferLength,
  PULONG HubNameActualLength)
{
  NTSTATUS status = STATUS_SUCCESS;
  WDFDEVICE device = BusContext;
  FUNCTION_ENTER();

  KdPrint((__DRIVER_NAME "     device = %p\n", device));
  KdPrint((__DRIVER_NAME "     HubInformationBuffer = %p\n", HubInformationBuffer));
  KdPrint((__DRIVER_NAME "     HubInformationBufferLength = %d\n", HubInformationBufferLength));
  RtlStringCbCopyW(HubInformationBuffer, HubInformationBufferLength, L"ROOT_HUB");
  *HubNameActualLength = 16;

  FUNCTION_EXIT();
  return status;
}

static PVOID
XenPciPdo_UBIH_GetDeviceBusContext(
  PVOID BusContext,
  PVOID DeviceHandle)
{
  UNREFERENCED_PARAMETER(BusContext);
  UNREFERENCED_PARAMETER(DeviceHandle);
  
  FUNCTION_ENTER();

  FUNCTION_EXIT();
  return NULL;
}

static NTSTATUS
XenPciPdo_UBIH_Initialize20Hub (
  PVOID BusContext,
  PUSB_DEVICE_HANDLE HubDeviceHandle,
  ULONG TtCount)
{
  NTSTATUS status = STATUS_SUCCESS;
  FUNCTION_ENTER();
  KdPrint((__DRIVER_NAME "     BusContext = %p\n", BusContext));
  KdPrint((__DRIVER_NAME "     HubDeviceHandle = %p\n", HubDeviceHandle));
  KdPrint((__DRIVER_NAME "     TtCount = %d\n", TtCount));
  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIH_RootHubInitNotification(
  PVOID BusContext,
  PVOID CallbackContext,
  PRH_INIT_CALLBACK CallbackFunction)
{
  NTSTATUS status = STATUS_SUCCESS;
  WDFDEVICE device = BusContext;
  PXENUSB_PDO_DEVICE_DATA xupdd = GetXupdd(device);
  
  FUNCTION_ENTER();
  
  xupdd->BusCallbackFunction = CallbackFunction;
  xupdd->BusCallbackContext = CallbackContext;

  xupdd->BusCallbackFunction(xupdd->BusCallbackContext);
  
  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIH_FlushTransfers(
  PVOID BusContext,
  PUSB_DEVICE_HANDLE DeviceHandle)
{
  NTSTATUS status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(BusContext);
  UNREFERENCED_PARAMETER(DeviceHandle);
  
  FUNCTION_ENTER();

  FUNCTION_EXIT();
  return status;
}

static VOID
XenPciPdo_UBIH_SetDeviceHandleData(
  PVOID BusContext,
  PUSB_DEVICE_HANDLE DeviceHandle,
  PDEVICE_OBJECT UsbDevicePdo)
{
  UNREFERENCED_PARAMETER(BusContext);
  UNREFERENCED_PARAMETER(DeviceHandle);
  UNREFERENCED_PARAMETER(UsbDevicePdo);
  
  FUNCTION_ENTER();
  FUNCTION_EXIT();
}

static NTSTATUS
XenPciPdo_UBIU_GetUSBDIVersion(
  PVOID BusContext,
  PUSBD_VERSION_INFORMATION VersionInformation,
  PULONG HcdCapabilities
  )
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  UNREFERENCED_PARAMETER(BusContext);
  UNREFERENCED_PARAMETER(VersionInformation);
  UNREFERENCED_PARAMETER(HcdCapabilities);

  FUNCTION_ENTER();

  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIU_QueryBusTime(
  PVOID BusContext,
  PULONG CurrentFrame
  )
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  UNREFERENCED_PARAMETER(BusContext);
  UNREFERENCED_PARAMETER(CurrentFrame);
  
  FUNCTION_ENTER();

  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIU_SubmitIsoOutUrb(
  PVOID BusContext,
  PURB Urb
  )
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  UNREFERENCED_PARAMETER(BusContext);
  UNREFERENCED_PARAMETER(Urb);
  
  FUNCTION_ENTER();

  FUNCTION_EXIT();
  return status;
}

static NTSTATUS
XenPciPdo_UBIU_QueryBusInformation(
  PVOID BusContext,
  ULONG Level,
  PVOID BusInformationBuffer,
  PULONG BusInformationBufferLength,
  PULONG BusInformationActualLength)
{
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  UNREFERENCED_PARAMETER(BusContext);
  UNREFERENCED_PARAMETER(Level);
  UNREFERENCED_PARAMETER(BusInformationBuffer);
  UNREFERENCED_PARAMETER(BusInformationBufferLength);
  UNREFERENCED_PARAMETER(BusInformationActualLength);
  
  FUNCTION_ENTER();

  FUNCTION_EXIT();
  return status;
}

static BOOLEAN
XenPciPdo_UBIU_IsDeviceHighSpeed(PVOID BusContext)
{
  UNREFERENCED_PARAMETER(BusContext);
  
  FUNCTION_ENTER();

  FUNCTION_EXIT();
  return TRUE; //TODO: get port value
}

static NTSTATUS
XenPciPdo_UBIU_EnumLogEntry(
  PVOID BusContext,
  ULONG DriverTag,
  ULONG EnumTag,
  ULONG P1,
  ULONG P2
)
{
  NTSTATUS status = STATUS_SUCCESS;
  FUNCTION_ENTER();
  
  UNREFERENCED_PARAMETER(BusContext);
  
  KdPrint((__DRIVER_NAME "     DriverTag = %08x\n", DriverTag));
  KdPrint((__DRIVER_NAME "     EnumTag = %08x\n", EnumTag));
  KdPrint((__DRIVER_NAME "     P1 = %08x\n", P1));
  KdPrint((__DRIVER_NAME "     P2 = %08x\n", P2));

  FUNCTION_EXIT();
  return status;
}

VOID
XenUsb_EnumeratePorts(WDFDEVICE device)
{
  PXENUSB_PDO_DEVICE_DATA xupdd = GetXupdd(device);
  PXENUSB_DEVICE_DATA xudd = GetXudd(xupdd->wdf_device_bus_fdo);
  CHAR path[128];
  PCHAR err;
  PCHAR value;
  ULONG i;
  
  for (i = 0; i < xudd->num_ports; i++)
  {
    ULONG port_value;
    RtlStringCbPrintfA(path, ARRAY_SIZE(path), "%s/port-%d", xudd->vectors.backend_path, i + 1);
    err = xudd->vectors.XenBus_Read(xudd->vectors.context, XBT_NIL, path, &value);
    if (err)
    {
      XenPci_FreeMem(err);
      KdPrint((__DRIVER_NAME "     Failed to read port-%d\n", i + 1));
      continue;
    }
    // 0=disconnected, 1=low_speed, 2=full_speed, 3= high_speed
    port_value = (ULONG)parse_numeric_string(value);
    XenPci_FreeMem(value);
    KdPrint((__DRIVER_NAME "     port-%d : %d -> %d\n", i, xudd->ports[i].port_type, port_value));
    if (port_value != xudd->ports[i].port_type)
    {
      xudd->ports[i].port_type = port_value;
      // need to do more than this - probably flush everything and ensure no more activity to the new port until it is set up...
      switch (port_value)
      {
      case USB_PORT_TYPE_NOT_CONNECTED:
        xudd->ports[i].port_status = (1 << PORT_ENABLE);
        break;
      case USB_PORT_TYPE_LOW_SPEED:
        xudd->ports[i].port_status = (1 << PORT_LOW_SPEED) | (1 << PORT_CONNECTION) | (1 << PORT_ENABLE);
        break;
      case USB_PORT_TYPE_FULL_SPEED:
        xudd->ports[i].port_status = (1 << PORT_CONNECTION) | (1 << PORT_ENABLE);
        break;
      case USB_PORT_TYPE_HIGH_SPEED:
        xudd->ports[i].port_status = (1 << PORT_HIGH_SPEED) | (1 << PORT_CONNECTION) | (1 << PORT_ENABLE);
        break;
      }      
      xudd->ports[i].port_change |= (1 << PORT_CONNECTION);
    }
  }  
}

static VOID
XenUsbHub_HubInterruptTimer(WDFTIMER timer)
{
  NTSTATUS status;
  xenusb_endpoint_t *endpoint = *GetEndpoint(timer);
  WDFDEVICE pdo_device = endpoint->interface->config->device->pdo_device;
  PXENUSB_PDO_DEVICE_DATA xupdd = GetXupdd(pdo_device);
  PXENUSB_DEVICE_DATA xudd = GetXudd(xupdd->wdf_device_bus_fdo);
  WDF_REQUEST_PARAMETERS wrp;
  WDFREQUEST request;
  PURB urb;
  ULONG i;
  
  //FUNCTION_ENTER();
  WdfSpinLockAcquire(endpoint->interrupt_lock);
  status = WdfIoQueueRetrieveNextRequest(endpoint->interrupt_queue, &request);
  if (status == STATUS_NO_MORE_ENTRIES)
  {
    WdfTimerStop(timer, FALSE);
    WdfSpinLockRelease(endpoint->interrupt_lock);
    KdPrint((__DRIVER_NAME "      No More Entries\n", status));
    //FUNCTION_EXIT();
    return;
  }
  if (!NT_SUCCESS(status))
  {
    WdfTimerStop(timer, FALSE);
    WdfSpinLockRelease(endpoint->interrupt_lock);
    KdPrint((__DRIVER_NAME "      Failed to get request from queue %08x\n", status));
    //FUNCTION_EXIT();
    return;
  }
  
  WDF_REQUEST_PARAMETERS_INIT(&wrp);
  WdfRequestGetParameters(request, &wrp);

  urb = (PURB)wrp.Parameters.Others.Arg1;
  ASSERT(urb);
  ASSERT(urb->UrbHeader.Function == URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER);
  RtlZeroMemory(urb->UrbBulkOrInterruptTransfer.TransferBuffer, urb->UrbBulkOrInterruptTransfer.TransferBufferLength);
  if (urb->UrbBulkOrInterruptTransfer.TransferFlags & (USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK))
  {
    //urb->UrbBulkOrInterruptTransfer.TransferBufferLength = 0;
    // check for hub change too
    //((PUCHAR)urb->UrbBulkOrInterruptTransfer.TransferBuffer)[0] |= 1;
    for (i = 0; i < xudd->num_ports; i++)
    {
      if (xudd->ports[i].port_change)
      {
        KdPrint((__DRIVER_NAME "      Port change on port %d - status = %04x, change = %04x\n",
          xudd->ports[i].port_number, xudd->ports[i].port_status, xudd->ports[i].port_change));
        ((PUCHAR)urb->UrbBulkOrInterruptTransfer.TransferBuffer)[xudd->ports[i].port_number >> 3] |= 1 << (xudd->ports[i].port_number & 7);
      }
    }
    urb->UrbHeader.Status = USBD_STATUS_SUCCESS;
    WdfSpinLockRelease(endpoint->interrupt_lock);
    WdfRequestComplete(request, STATUS_SUCCESS);
  }
  else
  {
    KdPrint((__DRIVER_NAME "      Direction mismatch\n"));
    urb->UrbHeader.Status = USBD_STATUS_INVALID_PARAMETER;
    WdfSpinLockRelease(endpoint->interrupt_lock);
    WdfRequestComplete(request, STATUS_UNSUCCESSFUL);
  }
  //FUNCTION_EXIT();
  return;
}

NTSTATUS
XenUsb_EvtChildListCreateDevice(WDFCHILDLIST child_list,
  PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER identification_header,
  PWDFDEVICE_INIT child_init)
{
  NTSTATUS status = STATUS_SUCCESS;
  WDFDEVICE bus_device = WdfChildListGetDevice(child_list);
  WDF_OBJECT_ATTRIBUTES child_attributes;
  WDFDEVICE child_device;
  PXENUSB_PDO_IDENTIFICATION_DESCRIPTION identification = (PXENUSB_PDO_IDENTIFICATION_DESCRIPTION)identification_header;
  WDF_DEVICE_PNP_CAPABILITIES child_pnp_capabilities;
  DECLARE_UNICODE_STRING_SIZE(buffer, 512);
  DECLARE_CONST_UNICODE_STRING(location, L"Xen Bus");
  PXENUSB_PDO_DEVICE_DATA xupdd;
  PXENUSB_DEVICE_DATA xudd = GetXudd(bus_device);
  WDF_PNPPOWER_EVENT_CALLBACKS child_pnp_power_callbacks;
  WDF_DEVICE_POWER_CAPABILITIES child_power_capabilities;
  WDF_IO_QUEUE_CONFIG queue_config;
  WDF_QUERY_INTERFACE_CONFIG interface_config;
  USB_BUS_INTERFACE_HUB_V5 ubih;
  USB_BUS_INTERFACE_USBDI_V2 ubiu;
  WDF_TIMER_CONFIG timer_config;
  WDF_OBJECT_ATTRIBUTES timer_attributes;

  UNREFERENCED_PARAMETER(xudd);
  
  FUNCTION_ENTER();

  //KdPrint((__DRIVER_NAME "     device = %d, port = %d, vendor_id = %04x, product_id = %04x\n",

  WdfDeviceInitSetDeviceType(child_init, FILE_DEVICE_UNKNOWN);
  
  child_pnp_power_callbacks.EvtDeviceD0Entry = XenUsbHub_EvtDeviceD0Entry;
  child_pnp_power_callbacks.EvtDeviceD0Exit = XenUsbHub_EvtDeviceD0Exit;
  child_pnp_power_callbacks.EvtDevicePrepareHardware = XenUsbHub_EvtDevicePrepareHardware;
  child_pnp_power_callbacks.EvtDeviceReleaseHardware = XenUsbHub_EvtDeviceReleaseHardware;
  child_pnp_power_callbacks.EvtDeviceUsageNotification = XenUsbHub_EvtDeviceUsageNotification;
  WdfDeviceInitSetPnpPowerEventCallbacks(child_init, &child_pnp_power_callbacks);

  RtlUnicodeStringPrintf(&buffer, L"USB\\ROOT_HUB");
  status = WdfPdoInitAssignDeviceID(child_init, &buffer);
  status = WdfPdoInitAddHardwareID(child_init, &buffer);

  RtlUnicodeStringPrintf(&buffer, L"VUSB_%d", identification->device_number);
  status = WdfPdoInitAssignInstanceID(child_init, &buffer);
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  
  RtlUnicodeStringPrintf(&buffer, L"PVUSB device #%d", identification->device_number, identification);
  status = WdfPdoInitAddDeviceText(child_init, &buffer, &location, 0x0409);
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  WdfPdoInitSetDefaultLocale(child_init, 0x0409);

  WdfDeviceInitSetPowerNotPageable(child_init);

  WdfDeviceInitSetIoType(child_init, WdfDeviceIoDirect);

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&child_attributes, XENUSB_PDO_DEVICE_DATA);
  status = WdfDeviceCreate(&child_init, &child_attributes, &child_device);
  if (!NT_SUCCESS(status))
  {
    return status;
  }

  xupdd = GetXupdd(child_device);

  xudd->root_hub_device = child_device;
  
  xupdd->wdf_device = child_device;
  xupdd->wdf_device_bus_fdo = WdfChildListGetDevice(child_list);
  
  xupdd->usb_device = ExAllocatePoolWithTag(NonPagedPool, sizeof(xenusb_device_t), XENUSB_POOL_TAG);
  // get address from freelist...
  xupdd->usb_device->pdo_device = child_device;
  xupdd->usb_device->address = 1;
  xupdd->usb_device->device_speed = UsbHighSpeed;
  xupdd->usb_device->device_type = Usb20Device;
  xupdd->usb_device->device_descriptor.bLength = sizeof(USB_DEVICE_DESCRIPTOR);
  xupdd->usb_device->device_descriptor.bDescriptorType = USB_DEVICE_DESCRIPTOR_TYPE;
  xupdd->usb_device->device_descriptor.bcdUSB = 0x0200;
  xupdd->usb_device->device_descriptor.bDeviceClass = 9;
  xupdd->usb_device->device_descriptor.bDeviceSubClass = 0;
  xupdd->usb_device->device_descriptor.bDeviceProtocol = 1;
  xupdd->usb_device->device_descriptor.bMaxPacketSize0 = 64;
  xupdd->usb_device->device_descriptor.idVendor = 0x0000;
  xupdd->usb_device->device_descriptor.idProduct = 0x0000;
  xupdd->usb_device->device_descriptor.bcdDevice = 0x0206;
  xupdd->usb_device->device_descriptor.iManufacturer = 3;
  xupdd->usb_device->device_descriptor.iProduct = 2;
  xupdd->usb_device->device_descriptor.iSerialNumber = 1;
  xupdd->usb_device->device_descriptor.bNumConfigurations = 1;
  xupdd->usb_device->configs = ExAllocatePoolWithTag(NonPagedPool, sizeof(PVOID) * 1, XENUSB_POOL_TAG);
  xupdd->usb_device->configs[0] = ExAllocatePoolWithTag(NonPagedPool, sizeof(xenusb_config_t) + sizeof(PVOID) * 1, XENUSB_POOL_TAG);
  xupdd->usb_device->active_config = xupdd->usb_device->configs[0];
  xupdd->usb_device->configs[0]->device = xupdd->usb_device;
  xupdd->usb_device->configs[0]->config_descriptor.bLength = sizeof(USB_CONFIGURATION_DESCRIPTOR);
  xupdd->usb_device->configs[0]->config_descriptor.bDescriptorType = USB_CONFIGURATION_DESCRIPTOR_TYPE;
  xupdd->usb_device->configs[0]->config_descriptor.wTotalLength = sizeof(USB_CONFIGURATION_DESCRIPTOR);
  xupdd->usb_device->configs[0]->config_descriptor.bNumInterfaces = 1;
  xupdd->usb_device->configs[0]->config_descriptor.bConfigurationValue = 1;
  xupdd->usb_device->configs[0]->config_descriptor.iConfiguration = 0;
  xupdd->usb_device->configs[0]->config_descriptor.bmAttributes = 0xe0;
  xupdd->usb_device->configs[0]->config_descriptor.MaxPower = 0;
  xupdd->usb_device->configs[0]->interfaces[0] = ExAllocatePoolWithTag(NonPagedPool, sizeof(xenusb_interface_t) + sizeof(PVOID) * 1, XENUSB_POOL_TAG);
  xupdd->usb_device->active_interface = xupdd->usb_device->configs[0]->interfaces[0];
  xupdd->usb_device->configs[0]->interfaces[0]->config = xupdd->usb_device->configs[0];
  xupdd->usb_device->configs[0]->interfaces[0]->interface_descriptor.bLength = 9;
  xupdd->usb_device->configs[0]->interfaces[0]->interface_descriptor.bDescriptorType = USB_INTERFACE_DESCRIPTOR_TYPE;
  xupdd->usb_device->configs[0]->interfaces[0]->interface_descriptor.bInterfaceNumber = 0;
  xupdd->usb_device->configs[0]->interfaces[0]->interface_descriptor.bAlternateSetting = 0;
  xupdd->usb_device->configs[0]->interfaces[0]->interface_descriptor.bNumEndpoints = 1;
  xupdd->usb_device->configs[0]->interfaces[0]->interface_descriptor.bInterfaceClass = 9;
  xupdd->usb_device->configs[0]->interfaces[0]->interface_descriptor.bInterfaceSubClass = 0;
  xupdd->usb_device->configs[0]->interfaces[0]->interface_descriptor.bInterfaceProtocol = 0;
  xupdd->usb_device->configs[0]->interfaces[0]->interface_descriptor.iInterface = 0;
  xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0] = ExAllocatePoolWithTag(NonPagedPool, sizeof(xenusb_endpoint_t), XENUSB_POOL_TAG);
  xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->interface = xupdd->usb_device->configs[0]->interfaces[0];
  xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->pipe_value = 0;
  xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->endpoint_descriptor.bLength = 7;
  xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->endpoint_descriptor.bDescriptorType = USB_ENDPOINT_DESCRIPTOR_TYPE;
  xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->endpoint_descriptor.bEndpointAddress = 0x81; // EP 1 IN
  xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->endpoint_descriptor.bmAttributes = USB_ENDPOINT_TYPE_INTERRUPT;
  xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->endpoint_descriptor.wMaxPacketSize = 2;
  xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->endpoint_descriptor.bInterval = 12;
  WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->interrupt_lock);
  WDF_TIMER_CONFIG_INIT(&timer_config, XenUsbHub_HubInterruptTimer);  
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&timer_attributes, pxenusb_endpoint_t);
  timer_attributes.ParentObject = child_device;
  status = WdfTimerCreate(&timer_config, &timer_attributes, &xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->interrupt_timer);
  if (!NT_SUCCESS(status)) {
      KdPrint((__DRIVER_NAME "     Error creating timer 0x%x\n", status));
      return status;
  }
  *GetEndpoint(xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->interrupt_timer) = xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0];

  WDF_IO_QUEUE_CONFIG_INIT(&queue_config, WdfIoQueueDispatchParallel);
  queue_config.EvtIoInternalDeviceControl = XenUsb_EvtIoInternalDeviceControl_ROOTHUB_SUBMIT_URB;
  queue_config.PowerManaged = TRUE; /* power managed queue for SUBMIT_URB */
  status = WdfIoQueueCreate(child_device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, &xupdd->usb_device->urb_queue);
  if (!NT_SUCCESS(status)) {
      KdPrint((__DRIVER_NAME "     Error creating urb_queue 0x%x\n", status));
      return status;
  }
  WDF_IO_QUEUE_CONFIG_INIT(&queue_config, WdfIoQueueDispatchManual);
  queue_config.PowerManaged = TRUE;
  status = WdfIoQueueCreate(child_device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES,
    &xupdd->usb_device->configs[0]->interfaces[0]->endpoints[0]->interrupt_queue);
  if (!NT_SUCCESS(status)) {
      KdPrint((__DRIVER_NAME "     Error creating timer io_queue 0x%x\n", status));
      return status;
  }

  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config, WdfIoQueueDispatchParallel);
  queue_config.EvtIoInternalDeviceControl = XenUsbHub_EvtIoInternalDeviceControl;
  queue_config.EvtIoDeviceControl = XenUsbHub_EvtIoDeviceControl;
  queue_config.EvtIoDefault = XenUsbHub_EvtIoDefault;
  /* can't be power managed or deadlocks occur */
  queue_config.PowerManaged = FALSE;
  status = WdfIoQueueCreate(child_device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, &xupdd->io_queue);
  if (!NT_SUCCESS(status)) {
      KdPrint((__DRIVER_NAME "     Error creating io_queue 0x%x\n", status));
      return status;
  }

  WdfDeviceSetSpecialFileSupport(child_device, WdfSpecialFilePaging, TRUE);
  WdfDeviceSetSpecialFileSupport(child_device, WdfSpecialFileHibernation, TRUE);
  WdfDeviceSetSpecialFileSupport(child_device, WdfSpecialFileDump, TRUE);

  WDF_DEVICE_PNP_CAPABILITIES_INIT(&child_pnp_capabilities);
  child_pnp_capabilities.LockSupported = WdfFalse;
  child_pnp_capabilities.EjectSupported  = WdfTrue;
  child_pnp_capabilities.Removable  = WdfTrue;
  child_pnp_capabilities.DockDevice  = WdfFalse;
  child_pnp_capabilities.UniqueID  = WdfTrue;
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

  ubih.BusContext = child_device;
  ubih.InterfaceReference = WdfDeviceInterfaceReferenceNoOp;
  ubih.InterfaceDereference = WdfDeviceInterfaceDereferenceNoOp;
  ubih.CreateUsbDevice = XenPciPdo_UBIH_CreateUsbDevice;
  ubih.InitializeUsbDevice = XenPciPdo_UBIH_InitializeUsbDevice;
  ubih.GetUsbDescriptors = XenPciPdo_UBIH_GetUsbDescriptors;
  ubih.RemoveUsbDevice = XenPciPdo_UBIH_RemoveUsbDevice;
  ubih.RestoreUsbDevice = XenPciPdo_UBIH_RestoreUsbDevice;
  ubih.GetPortHackFlags = XenPciPdo_UBIH_GetPortHackFlags;
  ubih.QueryDeviceInformation = XenPciPdo_UBIH_QueryDeviceInformation;
  ubih.GetControllerInformation = XenPciPdo_UBIH_GetControllerInformation;
  ubih.ControllerSelectiveSuspend = XenPciPdo_UBIH_ControllerSelectiveSuspend;
  ubih.GetExtendedHubInformation = XenPciPdo_UBIH_GetExtendedHubInformation;
  ubih.GetRootHubSymbolicName = XenPciPdo_UBIH_GetRootHubSymbolicName;
  ubih.GetDeviceBusContext = XenPciPdo_UBIH_GetDeviceBusContext;
  ubih.Initialize20Hub = XenPciPdo_UBIH_Initialize20Hub;
  ubih.RootHubInitNotification = XenPciPdo_UBIH_RootHubInitNotification;
  ubih.FlushTransfers = XenPciPdo_UBIH_FlushTransfers;
  ubih.SetDeviceHandleData = XenPciPdo_UBIH_SetDeviceHandleData;
  ubih.Size = sizeof(USB_BUS_INTERFACE_HUB_V5);
  ubih.Version = USB_BUSIF_HUB_VERSION_5;
  WDF_QUERY_INTERFACE_CONFIG_INIT(&interface_config, (PINTERFACE)&ubih, &USB_BUS_INTERFACE_HUB_GUID, NULL);
  status = WdfDeviceAddQueryInterface(child_device, &interface_config);
  if (!NT_SUCCESS(status))
    return status;

  ubiu.BusContext = child_device;
  ubiu.InterfaceReference = WdfDeviceInterfaceReferenceNoOp;
  ubiu.InterfaceDereference = WdfDeviceInterfaceDereferenceNoOp;
  ubiu.GetUSBDIVersion = XenPciPdo_UBIU_GetUSBDIVersion;
  ubiu.QueryBusTime = XenPciPdo_UBIU_QueryBusTime;
  ubiu.SubmitIsoOutUrb = XenPciPdo_UBIU_SubmitIsoOutUrb;
  ubiu.QueryBusInformation = XenPciPdo_UBIU_QueryBusInformation;
  ubiu.IsDeviceHighSpeed = XenPciPdo_UBIU_IsDeviceHighSpeed;
  ubiu.EnumLogEntry  = XenPciPdo_UBIU_EnumLogEntry;
  ubiu.Size = sizeof(USB_BUS_INTERFACE_USBDI_V2);
  ubiu.Version = USB_BUSIF_HUB_VERSION_2;
  WDF_QUERY_INTERFACE_CONFIG_INIT(&interface_config, (PINTERFACE)&ubiu, &USB_BUS_INTERFACE_USBDI_GUID, NULL);
  status = WdfDeviceAddQueryInterface(child_device, &interface_config);
  if (!NT_SUCCESS(status))
    return status;
  
  status = WdfDeviceCreateDeviceInterface(child_device, &GUID_DEVINTERFACE_USB_HUB, NULL);
  if (!NT_SUCCESS(status))
    return status;

  FUNCTION_EXIT();
  
  return status;
}