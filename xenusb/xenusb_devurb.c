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

#define EPROTO          71      /* Protocol error */

static VOID
XenUsb_UrbCallback(usbif_shadow_t *shadow)
{
  WDFQUEUE queue;
  WDFDEVICE device;
  PXENUSB_DEVICE_DATA xudd;
  //ULONG i;

  FUNCTION_ENTER();

  ASSERT(shadow->request);
  queue = WdfRequestGetIoQueue(shadow->request);
  ASSERT(queue);
  device = WdfIoQueueGetDevice(queue);
  ASSERT(device);
  xudd = GetXudd(device);

  switch (shadow->urb->UrbHeader.Function)
  {
  case URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE:
    KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
    KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
    KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
    KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
    KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));
    KdPrint((__DRIVER_NAME "     total_length = %d\n", shadow->total_length));
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE\n"));
    shadow->urb->UrbControlDescriptorRequest.TransferBufferLength = shadow->total_length;
    break;
  case URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE:
    KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
    KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
    KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
    KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
    KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));
    KdPrint((__DRIVER_NAME "     total_length = %d\n", shadow->total_length));
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE\n"));
    shadow->urb->UrbControlDescriptorRequest.TransferBufferLength = shadow->total_length;
    break;
  case URB_FUNCTION_SELECT_CONFIGURATION:
    KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
    KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
    KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
    KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
    KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));
    KdPrint((__DRIVER_NAME "     total_length = %d\n", shadow->total_length));
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_SELECT_CONFIGURATION\n"));
    break;
  case URB_FUNCTION_SELECT_INTERFACE:
    KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
    KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
    KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
    KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
    KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));
    KdPrint((__DRIVER_NAME "     total_length = %d\n", shadow->total_length));
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_SELECT_INTERFACE\n"));
    break;
  case URB_FUNCTION_CLASS_INTERFACE:
    KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
    KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
    KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
    KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
    KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));
    KdPrint((__DRIVER_NAME "     total_length = %d\n", shadow->total_length));
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_CLASS_INTERFACE\n"));
    shadow->urb->UrbControlVendorClassRequest.TransferBufferLength = shadow->total_length;
    break;
  case URB_FUNCTION_CONTROL_TRANSFER:
  case URB_FUNCTION_CONTROL_TRANSFER_EX:
    KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
    KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
    KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
    KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
    KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));
    KdPrint((__DRIVER_NAME "     total_length = %d\n", shadow->total_length));
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_CONTROL_TRANSFER (_EX)\n"));
    shadow->urb->UrbControlTransfer.TransferBufferLength = shadow->total_length;
    break;
  case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
//    if (shadow->rsp.status)
    {
      KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
      KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
      KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
      KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
      KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));
      KdPrint((__DRIVER_NAME "     total_length = %d\n", shadow->total_length));
      KdPrint((__DRIVER_NAME "     URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER\n"));
    }
    shadow->urb->UrbBulkOrInterruptTransfer.TransferBufferLength = shadow->total_length;
    break;
  case URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL:
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL\n"));
    break;
  default:
    KdPrint((__DRIVER_NAME "     rsp id = %d\n", shadow->rsp.id));
    KdPrint((__DRIVER_NAME "     rsp start_frame = %d\n", shadow->rsp.start_frame));
    KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
    KdPrint((__DRIVER_NAME "     rsp actual_length = %d\n", shadow->rsp.actual_length));
    KdPrint((__DRIVER_NAME "     rsp error_count = %d\n", shadow->rsp.error_count));
    KdPrint((__DRIVER_NAME "     total_length = %d\n", shadow->total_length));
    KdPrint((__DRIVER_NAME "     Unknown function %x\n", shadow->urb->UrbHeader.Function));
    break;
  }
  switch (shadow->rsp.status)
  {
  case 0:
    shadow->urb->UrbHeader.Status = USBD_STATUS_SUCCESS;
    break;
  case -EPROTO: /*  ? */
    shadow->urb->UrbHeader.Status = USBD_STATUS_CRC;
    KdPrint((__DRIVER_NAME "     rsp status = -EPROTO\n"));
    break;
  case -EPIPE: /* see linux code - EPIPE is when the HCD returned a stall */
    shadow->urb->UrbHeader.Status = USBD_STATUS_STALL_PID;
    KdPrint((__DRIVER_NAME "     rsp status = -EPIPE (USBD_STATUS_STALL_PID)\n"));
    break;
#if 0
  case -EOVERFLOW:
    shadow->urb->UrbHeader.Status USBD_STATUS_DATA_OVERRUN;
    break;
  case -EREMOTEIO:
    shadow->urb->UrbHeader.Status USBD_STATUS_ERROR_SHORT_TRANSFER;
    break;
#endif
  default:
    //shadow->urb->UrbHeader.Status = USBD_STATUS_ENDPOINT_HALTED;
    shadow->urb->UrbHeader.Status = USBD_STATUS_INTERNAL_HC_ERROR;
    KdPrint((__DRIVER_NAME "     rsp status = %d\n", shadow->rsp.status));
    break;
  }
  if (shadow->urb->UrbHeader.Status == USBD_STATUS_SUCCESS)
    WdfRequestComplete(shadow->request, STATUS_SUCCESS);
  else
    WdfRequestComplete(shadow->request, STATUS_UNSUCCESSFUL);
  put_shadow_on_freelist(xudd, shadow);

  FUNCTION_EXIT();
}

VOID
XenUsb_EvtIoInternalDeviceControl_DEVICE_SUBMIT_URB(
  WDFQUEUE queue,
  WDFREQUEST request,
  size_t output_buffer_length,
  size_t input_buffer_length,
  ULONG io_control_code)
{
  NTSTATUS status;
  WDFDEVICE device = WdfIoQueueGetDevice(queue);
  PXENUSB_DEVICE_DATA xudd = GetXudd(device);
  WDF_REQUEST_PARAMETERS wrp;
  PURB urb;
  usbif_shadow_t *shadow;
  PUSB_DEFAULT_PIPE_SETUP_PACKET setup_packet;
  //PMDL mdl;
  PUSBD_INTERFACE_INFORMATION interface_information;
  ULONG i, j;
  xenusb_device_t *usb_device;
  //PUSB_HUB_DESCRIPTOR uhd;
  xenusb_endpoint_t *endpoint;
  urb_decode_t decode_data;
  ULONG decode_retval;

  UNREFERENCED_PARAMETER(input_buffer_length);
  UNREFERENCED_PARAMETER(output_buffer_length);
  UNREFERENCED_PARAMETER(io_control_code);

  FUNCTION_ENTER();

  ASSERT(io_control_code == IOCTL_INTERNAL_USB_SUBMIT_URB);

  status = STATUS_ACCESS_VIOLATION; //STATUS_UNSUCCESSFUL;

  WDF_REQUEST_PARAMETERS_INIT(&wrp);
  WdfRequestGetParameters(request, &wrp);

  urb = (PURB)wrp.Parameters.Others.Arg1;
  ASSERT(urb);
#if 0
  KdPrint((__DRIVER_NAME "     urb = %p\n", urb));
  KdPrint((__DRIVER_NAME "      Length = %d\n", urb->UrbHeader.Length));
  KdPrint((__DRIVER_NAME "      Function = %d\n", urb->UrbHeader.Function));
  KdPrint((__DRIVER_NAME "      Status = %d\n", urb->UrbHeader.Status));
  KdPrint((__DRIVER_NAME "      UsbdDeviceHandle = %p\n", urb->UrbHeader.UsbdDeviceHandle));
  KdPrint((__DRIVER_NAME "      UsbdFlags = %08x\n", urb->UrbHeader.UsbdFlags));
#endif
  usb_device = urb->UrbHeader.UsbdDeviceHandle;

  ASSERT(usb_device);

  decode_retval = XenUsb_DecodeControlUrb(urb, &decode_data);
  if (decode_retval == URB_DECODE_UNKNOWN)
  {
    FUNCTION_MSG("Calling WdfRequestCompletestatus with status = %08x\n", STATUS_UNSUCCESSFUL);
    urb->UrbHeader.Status = USBD_STATUS_INVALID_URB_FUNCTION;
    WdfRequestComplete(request, STATUS_UNSUCCESSFUL);
    return;
  }

#if 0
  if (decode_retval != URB_DECODE_NOT_CONTROL)
  {
    FUNCTION_MSG("bmRequestType = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.bmRequestType.B);
    FUNCTION_MSG(" Recipient = %x\n", decode_data.setup_packet.default_pipe_setup_packet.bmRequestType.Recipient);
    FUNCTION_MSG(" Type = %x\n", decode_data.setup_packet.default_pipe_setup_packet.bmRequestType.Type);
    FUNCTION_MSG(" Dir = %x\n", decode_data.setup_packet.default_pipe_setup_packet.bmRequestType.Dir);
    FUNCTION_MSG("bRequest = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.bRequest);
    FUNCTION_MSG("wValue = %04x\n", decode_data.setup_packet.default_pipe_setup_packet.wValue.W);
    FUNCTION_MSG(" Low = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.wValue.LowByte);
    FUNCTION_MSG(" High = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.wValue.HiByte);
    FUNCTION_MSG("wIndex = %04x\n", decode_data.setup_packet.default_pipe_setup_packet.wIndex);
    FUNCTION_MSG(" Low = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.wIndex.LowByte);
    FUNCTION_MSG(" High = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.wIndex.HiByte);
    FUNCTION_MSG("wLength = %04x\n", decode_data.setup_packet.default_pipe_setup_packet.wLength);
  }
#endif
  
  switch(urb->UrbHeader.Function)
  {
  case URB_FUNCTION_SELECT_CONFIGURATION:
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_SELECT_CONFIGURATION\n"));
    KdPrint((__DRIVER_NAME "      ConfigurationDescriptor = %p\n", urb->UrbSelectConfiguration.ConfigurationDescriptor));
    if (urb->UrbSelectConfiguration.ConfigurationDescriptor)
    {
      KdPrint((__DRIVER_NAME "       bLength = %d\n", urb->UrbSelectConfiguration.ConfigurationDescriptor->bLength));
      KdPrint((__DRIVER_NAME "       bDescriptorType = %d\n", urb->UrbSelectConfiguration.ConfigurationDescriptor->bDescriptorType));
      KdPrint((__DRIVER_NAME "       wTotalLength = %d\n", urb->UrbSelectConfiguration.ConfigurationDescriptor->wTotalLength));
      KdPrint((__DRIVER_NAME "       bNumInterfaces = %d\n", urb->UrbSelectConfiguration.ConfigurationDescriptor->bNumInterfaces));
      KdPrint((__DRIVER_NAME "       bConfigurationValue = %d\n", urb->UrbSelectConfiguration.ConfigurationDescriptor->bConfigurationValue));
      KdPrint((__DRIVER_NAME "       iConfiguration = %d\n", urb->UrbSelectConfiguration.ConfigurationDescriptor->iConfiguration));
      KdPrint((__DRIVER_NAME "       bmAttributes = %04x\n", urb->UrbSelectConfiguration.ConfigurationDescriptor->bmAttributes));
      KdPrint((__DRIVER_NAME "       MaxPower = %d\n", urb->UrbSelectConfiguration.ConfigurationDescriptor->MaxPower));
    }
    if (urb->UrbSelectConfiguration.ConfigurationDescriptor)
    {
      xenusb_config_t *usb_config = NULL;
      for (i = 0; i < usb_device->device_descriptor.bNumConfigurations; i++)
      {
        if (usb_device->configs[i]->config_descriptor.bConfigurationValue == urb->UrbSelectConfiguration.ConfigurationDescriptor->bConfigurationValue)
          usb_config = usb_device->configs[i];
      }
      urb->UrbSelectConfiguration.ConfigurationHandle = usb_config;
      interface_information = &urb->UrbSelectConfiguration.Interface;
      /* configuration is fully populated */
      for (i = 0; i < urb->UrbSelectConfiguration.ConfigurationDescriptor->bNumInterfaces; i++)
      {
        /* i think we need to pay attention to the alt setting here .. */
        xenusb_interface_t *usb_interface = usb_config->interfaces[i];
        interface_information->InterfaceNumber = usb_interface->interface_descriptor.bInterfaceNumber;
        interface_information->AlternateSetting = usb_interface->interface_descriptor.bAlternateSetting;
        interface_information->Class = usb_interface->interface_descriptor.bInterfaceClass;
        interface_information->SubClass = usb_interface->interface_descriptor.bInterfaceSubClass;
        interface_information->Protocol = usb_interface->interface_descriptor.bInterfaceProtocol;
        interface_information->InterfaceHandle = usb_interface;
        KdPrint((__DRIVER_NAME "     InterfaceInformation[%d]\n", i));
        KdPrint((__DRIVER_NAME "      Length = %d\n", interface_information->Length));
        KdPrint((__DRIVER_NAME "      InterfaceNumber = %d\n", interface_information->InterfaceNumber));
        KdPrint((__DRIVER_NAME "      AlternateSetting = %d\n", interface_information->AlternateSetting));
        KdPrint((__DRIVER_NAME "      Class = %02x\n", (ULONG)interface_information->Class));
        KdPrint((__DRIVER_NAME "      SubClass = %02x\n", (ULONG)interface_information->SubClass));
        KdPrint((__DRIVER_NAME "      Protocol = %02x\n", (ULONG)interface_information->Protocol));
        KdPrint((__DRIVER_NAME "      InterfaceHandle = %p\n", interface_information->InterfaceHandle));
        KdPrint((__DRIVER_NAME "      NumberOfPipes = %d\n", interface_information->NumberOfPipes));
        for (j = 0; j < interface_information->NumberOfPipes; j++)
        {
          xenusb_endpoint_t *usb_endpoint = usb_interface->endpoints[j];
          KdPrint((__DRIVER_NAME "      Pipe[%d] (before)\n", j));
          KdPrint((__DRIVER_NAME "       MaximumPacketSize = %d\n", interface_information->Pipes[j].MaximumPacketSize));
          KdPrint((__DRIVER_NAME "       EndpointAddress = %d\n", interface_information->Pipes[j].EndpointAddress));
          KdPrint((__DRIVER_NAME "       Interval = %d\n", interface_information->Pipes[j].Interval));
          KdPrint((__DRIVER_NAME "       PipeType = %d\n", interface_information->Pipes[j].PipeType));
          KdPrint((__DRIVER_NAME "       PipeHandle = %p\n", interface_information->Pipes[j].PipeHandle));
          KdPrint((__DRIVER_NAME "       MaximumTransferSize = %d\n", interface_information->Pipes[j].MaximumTransferSize));
          KdPrint((__DRIVER_NAME "       PipeFlags = %08x\n", interface_information->Pipes[j].PipeFlags));
          interface_information->Pipes[j].MaximumPacketSize = usb_endpoint->endpoint_descriptor.wMaxPacketSize;
          interface_information->Pipes[j].EndpointAddress = usb_endpoint->endpoint_descriptor.bEndpointAddress;
          interface_information->Pipes[j].Interval = usb_endpoint->endpoint_descriptor.bInterval;
          switch (usb_endpoint->endpoint_descriptor.bmAttributes & USB_ENDPOINT_TYPE_MASK)
          {
          case USB_ENDPOINT_TYPE_CONTROL:
            FUNCTION_MSG("USB_ENDPOINT_TYPE_CONTROL");
            interface_information->Pipes[j].PipeType = UsbdPipeTypeControl;
            break;
          case USB_ENDPOINT_TYPE_ISOCHRONOUS:
            FUNCTION_MSG("USB_ENDPOINT_TYPE_ISOCHRONOUS");
            interface_information->Pipes[j].PipeType = UsbdPipeTypeIsochronous;
            break;
          case USB_ENDPOINT_TYPE_BULK:
            FUNCTION_MSG("USB_ENDPOINT_TYPE_BULK");
            interface_information->Pipes[j].PipeType = UsbdPipeTypeBulk;
            break;
          case USB_ENDPOINT_TYPE_INTERRUPT:
            FUNCTION_MSG("USB_ENDPOINT_TYPE_INTERRUPT");
            interface_information->Pipes[j].PipeType = UsbdPipeTypeInterrupt;
            break;
          }
          interface_information->Pipes[j].PipeHandle = usb_endpoint;
          KdPrint((__DRIVER_NAME "      Pipe[%d] (after)\n", j));
          KdPrint((__DRIVER_NAME "       MaximumPacketSize = %d\n", interface_information->Pipes[j].MaximumPacketSize));
          KdPrint((__DRIVER_NAME "       EndpointAddress = %d\n", interface_information->Pipes[j].EndpointAddress));
          KdPrint((__DRIVER_NAME "       Interval = %d\n", interface_information->Pipes[j].Interval));
          KdPrint((__DRIVER_NAME "       PipeType = %d\n", interface_information->Pipes[j].PipeType));
          KdPrint((__DRIVER_NAME "       PipeHandle = %p\n", interface_information->Pipes[j].PipeHandle));
          KdPrint((__DRIVER_NAME "       MaximumTransferSize = %d\n", interface_information->Pipes[j].MaximumTransferSize));
          KdPrint((__DRIVER_NAME "       PipeFlags = %08x\n", interface_information->Pipes[j].PipeFlags));
        }
        interface_information = (PUSBD_INTERFACE_INFORMATION)((PUCHAR)interface_information + interface_information->Length);
      }
    }
    else
    {
      // ? unconfigure device here
    }
    shadow = get_shadow_from_freelist(xudd);
    shadow->request = request;
    shadow->urb = urb;
    shadow->mdl = NULL;
    //shadow->dma_transaction = NULL;
    shadow->callback = XenUsb_UrbCallback;
    shadow->req.id = shadow->id;
    shadow->req.pipe = LINUX_PIPE_TYPE_CTRL | (usb_device->address << 8) | usb_device->port_number;
    shadow->req.transfer_flags = 0;
    setup_packet = (PUSB_DEFAULT_PIPE_SETUP_PACKET)shadow->req.u.ctrl;
    setup_packet->bmRequestType.Recipient = BMREQUEST_TO_DEVICE;
    setup_packet->bmRequestType.Type = BMREQUEST_STANDARD;
    setup_packet->bmRequestType.Dir = BMREQUEST_HOST_TO_DEVICE;
    setup_packet->bRequest = USB_REQUEST_SET_CONFIGURATION;
    setup_packet->wLength = 0;
    setup_packet->wValue.W = urb->UrbSelectConfiguration.ConfigurationDescriptor->bConfigurationValue;
    setup_packet->wIndex.W = 0;
    status = XenUsb_ExecuteRequest(xudd, shadow, NULL, NULL, 0);
    if (!NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     XenUsb_ExecuteRequest status = %08x\n", status));
    }
    break;
  case URB_FUNCTION_SELECT_INTERFACE:
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_SELECT_INTERFACE\n"));
    interface_information = &urb->UrbSelectInterface.Interface;
    KdPrint((__DRIVER_NAME "     InterfaceInformation\n"));
    KdPrint((__DRIVER_NAME "      Length = %d\n", interface_information->Length));
    KdPrint((__DRIVER_NAME "      InterfaceNumber = %d\n", interface_information->InterfaceNumber));
    KdPrint((__DRIVER_NAME "      AlternateSetting = %d\n", interface_information->AlternateSetting));
    KdPrint((__DRIVER_NAME "      Class = %02x\n", (ULONG)interface_information->Class));
    KdPrint((__DRIVER_NAME "      SubClass = %02x\n", (ULONG)interface_information->SubClass));
    KdPrint((__DRIVER_NAME "      Protocol = %02x\n", (ULONG)interface_information->Protocol));
    KdPrint((__DRIVER_NAME "      Reserved = %02x\n", (ULONG)interface_information->Reserved));
    KdPrint((__DRIVER_NAME "      InterfaceHandle = %p\n", interface_information->InterfaceHandle));
    KdPrint((__DRIVER_NAME "      NumberOfPipes = %d\n", interface_information->NumberOfPipes));
    for (i = 0; i < interface_information->NumberOfPipes; i++)
    {
      KdPrint((__DRIVER_NAME "      Pipe[%d]\n", i));
      KdPrint((__DRIVER_NAME "       MaximumPacketSize = %d\n", interface_information->Pipes[i].MaximumPacketSize));
      KdPrint((__DRIVER_NAME "       EndpointAddress = %d\n", interface_information->Pipes[i].EndpointAddress));
      KdPrint((__DRIVER_NAME "       Interval = %d\n", interface_information->Pipes[i].Interval));
      KdPrint((__DRIVER_NAME "       PipeType = %d\n", interface_information->Pipes[i].PipeType));
      KdPrint((__DRIVER_NAME "       PipeHandle = %p\n", interface_information->Pipes[i].PipeHandle));
      KdPrint((__DRIVER_NAME "       MaximumTransferSize = %d\n", interface_information->Pipes[i].MaximumTransferSize));
      KdPrint((__DRIVER_NAME "       PipeFlags = %08x\n", interface_information->Pipes[i].PipeFlags));
    }

    shadow = get_shadow_from_freelist(xudd);
    shadow->request = request;
    shadow->urb = urb;
    shadow->mdl = NULL;
    //shadow->dma_transaction = NULL;
    shadow->callback = XenUsb_UrbCallback;
    shadow->req.id = shadow->id;
    shadow->req.pipe = LINUX_PIPE_TYPE_CTRL | (usb_device->address << 8) | usb_device->port_number;
    shadow->req.transfer_flags = 0;
    setup_packet = (PUSB_DEFAULT_PIPE_SETUP_PACKET)shadow->req.u.ctrl;
    setup_packet->bmRequestType.Recipient = BMREQUEST_TO_INTERFACE;
    setup_packet->bmRequestType.Type = BMREQUEST_STANDARD;
    setup_packet->bmRequestType.Dir = BMREQUEST_HOST_TO_DEVICE;
    setup_packet->bRequest = USB_REQUEST_SET_INTERFACE;
    setup_packet->wLength = 0;
    setup_packet->wValue.W = urb->UrbSelectInterface.Interface.AlternateSetting;
    setup_packet->wIndex.W = urb->UrbSelectInterface.Interface.InterfaceNumber;
    status = XenUsb_ExecuteRequest(xudd, shadow, NULL, NULL, 0);
    if (!NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     XenUsb_ExecuteRequest status = %08x\n", status));
    }
    break;
#if (NTDDI_VERSION >= NTDDI_VISTA)  
  case URB_FUNCTION_CONTROL_TRANSFER_EX:
#endif
  case URB_FUNCTION_CONTROL_TRANSFER:
  case URB_FUNCTION_CLASS_DEVICE:
  case URB_FUNCTION_CLASS_INTERFACE:
  case URB_FUNCTION_CLASS_OTHER:
  case URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE:
  case URB_FUNCTION_GET_DESCRIPTOR_FROM_INTERFACE:
  case URB_FUNCTION_GET_STATUS_FROM_DEVICE:
    FUNCTION_MSG("URB_FUNCTION_%04x\n", urb->UrbHeader.Function);
    FUNCTION_MSG("bmRequestType = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.bmRequestType.B);
    FUNCTION_MSG(" Recipient = %x\n", decode_data.setup_packet.default_pipe_setup_packet.bmRequestType.Recipient);
    FUNCTION_MSG(" Type = %x\n", decode_data.setup_packet.default_pipe_setup_packet.bmRequestType.Type);
    FUNCTION_MSG(" Dir = %x\n", decode_data.setup_packet.default_pipe_setup_packet.bmRequestType.Dir);
    FUNCTION_MSG("bRequest = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.bRequest);
    FUNCTION_MSG("wValue = %04x\n", decode_data.setup_packet.default_pipe_setup_packet.wValue.W);
    FUNCTION_MSG(" Low = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.wValue.LowByte);
    FUNCTION_MSG(" High = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.wValue.HiByte);
    FUNCTION_MSG("wIndex = %04x\n", decode_data.setup_packet.default_pipe_setup_packet.wIndex);
    FUNCTION_MSG(" Low = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.wIndex.LowByte);
    FUNCTION_MSG(" High = %02x\n", decode_data.setup_packet.default_pipe_setup_packet.wIndex.HiByte);
    FUNCTION_MSG("wLength = %04x\n", decode_data.setup_packet.default_pipe_setup_packet.wLength);
    FUNCTION_MSG("decode_data.transfer_flags = %08x\n", decode_data.transfer_flags);
    FUNCTION_MSG("*decode_data.length = %04x\n", *decode_data.length);
    shadow = get_shadow_from_freelist(xudd);
    shadow->request = request;
    shadow->urb = urb;
    shadow->callback = XenUsb_UrbCallback;
    shadow->req.id = shadow->id;
    shadow->req.pipe = LINUX_PIPE_TYPE_CTRL | (usb_device->address << 8) | usb_device->port_number;
    shadow->req.transfer_flags = 0; 
    if (!(decode_data.transfer_flags & USBD_SHORT_TRANSFER_OK))
      shadow->req.transfer_flags |= LINUX_URB_SHORT_NOT_OK;
    if (decode_data.transfer_flags & (USBD_TRANSFER_DIRECTION_IN | USBD_SHORT_TRANSFER_OK))
      shadow->req.pipe |= LINUX_PIPE_DIRECTION_IN;
    else
      shadow->req.pipe |= LINUX_PIPE_DIRECTION_OUT;
    memcpy(shadow->req.u.ctrl, decode_data.setup_packet.raw, 8);
    FUNCTION_MSG("req.pipe = %08x\n", shadow->req.pipe);
    FUNCTION_MSG("req.transfer_flags = %08x\n", shadow->req.transfer_flags);
    status = XenUsb_ExecuteRequest(xudd, shadow, decode_data.buffer, decode_data.mdl, *decode_data.length);
    if (!NT_SUCCESS(status)) {
      KdPrint((__DRIVER_NAME "     XenUsb_ExecuteRequest status = %08x\n", status));
    }
    break;
  case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER: /* 11.12.4 */
    endpoint = urb->UrbBulkOrInterruptTransfer.PipeHandle;    
    KdPrint((__DRIVER_NAME "      pipe_handle = %p\n", endpoint));
    KdPrint((__DRIVER_NAME "      pipe_value = %08x\n", endpoint->pipe_value));
    shadow = get_shadow_from_freelist(xudd);
    KdPrint((__DRIVER_NAME "      id = %d\n", shadow->id));
    shadow->request = request;
    shadow->urb = urb;
    shadow->callback = XenUsb_UrbCallback;
    shadow->req.id = shadow->id;
    shadow->req.pipe = endpoint->pipe_value;
    shadow->req.transfer_flags = 0;
    shadow->req.u.intr.interval = endpoint->endpoint_descriptor.bInterval; /* check this... maybe there is some overridden value that should be used? */
    if (!(urb->UrbBulkOrInterruptTransfer.TransferFlags & USBD_SHORT_TRANSFER_OK) && (endpoint->pipe_value & LINUX_PIPE_DIRECTION_IN))
      shadow->req.transfer_flags |= LINUX_URB_SHORT_NOT_OK;
    switch(endpoint->endpoint_descriptor.bmAttributes & USB_ENDPOINT_TYPE_MASK)
    {
    case USB_ENDPOINT_TYPE_BULK:
      KdPrint((__DRIVER_NAME "      USB_ENDPOINT_TYPE_BULK\n"));
      break;
    case USB_ENDPOINT_TYPE_INTERRUPT:
      KdPrint((__DRIVER_NAME "      USB_ENDPOINT_TYPE_INTERRUPT\n"));
      break;
    default:
      KdPrint((__DRIVER_NAME "      USB_ENDPOINT_TYPE_%d\n", endpoint->endpoint_descriptor.bmAttributes));
      break;
    }

    FUNCTION_MSG("endpoint address = %02x\n", endpoint->endpoint_descriptor.bEndpointAddress);
    FUNCTION_MSG("endpoint interval = %02x\n", endpoint->endpoint_descriptor.bInterval);
    FUNCTION_MSG("pipe_direction_bit = %08x\n", endpoint->pipe_value & LINUX_PIPE_DIRECTION_IN);
    FUNCTION_MSG("short_ok_bit = %08x\n", urb->UrbBulkOrInterruptTransfer.TransferFlags & USBD_SHORT_TRANSFER_OK);
    FUNCTION_MSG("flags_direction_bit = %08x\n", urb->UrbBulkOrInterruptTransfer.TransferFlags & USBD_TRANSFER_DIRECTION_IN);
    status = XenUsb_ExecuteRequest(xudd, shadow, urb->UrbBulkOrInterruptTransfer.TransferBuffer, urb->UrbBulkOrInterruptTransfer.TransferBufferMDL, urb->UrbBulkOrInterruptTransfer.TransferBufferLength);
    if (!NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     XenUsb_ExecuteRequest status = %08x\n", status));
    }
    break;
  case URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL:
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL\n"));
    KdPrint((__DRIVER_NAME "      PipeHandle = %p\n", urb->UrbPipeRequest.PipeHandle));
    /* we only clear the stall here */
    endpoint = urb->UrbBulkOrInterruptTransfer.PipeHandle;    
    shadow = get_shadow_from_freelist(xudd);
    shadow->request = request;
    shadow->urb = urb;
    shadow->mdl = NULL;
    shadow->callback = XenUsb_UrbCallback;
    shadow->req.id = shadow->id;
    shadow->req.pipe = LINUX_PIPE_TYPE_CTRL | (usb_device->address << 8) | usb_device->port_number;
    shadow->req.transfer_flags = 0;
    setup_packet = (PUSB_DEFAULT_PIPE_SETUP_PACKET)shadow->req.u.ctrl;
    setup_packet->bmRequestType.Recipient = BMREQUEST_TO_ENDPOINT;
    setup_packet->bmRequestType.Type = BMREQUEST_STANDARD;
    setup_packet->bmRequestType.Dir = BMREQUEST_HOST_TO_DEVICE;
    setup_packet->bRequest = USB_REQUEST_CLEAR_FEATURE;
    setup_packet->wLength = 0;
    setup_packet->wValue.W = 0; /* 0 == ENDPOINT_HALT */
    setup_packet->wIndex.W = endpoint->endpoint_descriptor.bEndpointAddress;
    status = XenUsb_ExecuteRequest(xudd, shadow, NULL, NULL, 0);
    if (!NT_SUCCESS(status))
    {
      KdPrint((__DRIVER_NAME "     XenUsb_ExecuteRequest status = %08x\n", status));
    }
    break;
  case URB_FUNCTION_ABORT_PIPE:
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_ABORT_PIPE\n"));
    KdPrint((__DRIVER_NAME "      PipeHandle = %p\n", urb->UrbPipeRequest.PipeHandle));
    /* just fake this.... i think we really need to flush any pending requests too */
    urb->UrbHeader.Status = USBD_STATUS_SUCCESS;
    WdfRequestComplete(request, STATUS_SUCCESS);
    break;
  default:
    KdPrint((__DRIVER_NAME "     URB_FUNCTION_%04x\n", urb->UrbHeader.Function));
    KdPrint((__DRIVER_NAME "     Calling WdfRequestCompletestatus with status = %08x\n", status));
    urb->UrbHeader.Status = USBD_STATUS_INVALID_URB_FUNCTION;
    WdfRequestComplete(request, STATUS_ACCESS_VIOLATION); //STATUS_UNSUCCESSFUL);
    break;
  }
  FUNCTION_EXIT();
}

