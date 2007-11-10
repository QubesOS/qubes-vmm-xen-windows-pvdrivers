#if !defined(_XEN_PUBLIC_H_)
#define _XEN_PUBLIC_H_

DEFINE_GUID( GUID_XEN_IFACE_XEN, 0x5C568AC5, 0x9DDF, 0x4FA5, 0xA9, 0x4A, 0x39, 0xD6, 0x70, 0x77, 0x81, 0x9C);
//{5C568AC5-9DDF-4FA5-A94A-39D67077819C}

typedef PHYSICAL_ADDRESS
(*PXEN_ALLOCMMIO)(ULONG Length);


typedef struct _XEN_IFACE_XEN {
  INTERFACE InterfaceHeader;

  // hypervisor calls
  PXEN_ALLOCMMIO AllocMMIO;
  // allocate a page from the mmio space
  // release a page from the mmio space

} XEN_IFACE_XEN, *PXEN_IFACE_XEN;


typedef struct {
  char BasePath[128];
  PXENBUS_WATCH_CALLBACK WatchHandler;
} XENPCI_XEN_DEVICE_DATA, *PXENPCI_XEN_DEVICE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(XENPCI_XEN_DEVICE_DATA, GetXenDeviceData);

#endif