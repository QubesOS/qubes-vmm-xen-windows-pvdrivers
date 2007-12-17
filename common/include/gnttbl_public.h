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

#if !defined(_GNTTBL_PUBLIC_H_)
#define _GNTTBL_PUBLIC_H_

// {6A71ACF8-0F6D-4022-BA60-19986EBEEA73}
DEFINE_GUID(GUID_XEN_IFACE_GNTTBL, 0x6a71acf8, 0xf6d, 0x4022, 0xba, 0x60, 0x19, 0x98, 0x6e, 0xbe, 0xea, 0x73);

typedef grant_ref_t
(*PXEN_GNTTBL_GRANTACCESS)(WDFDEVICE Device, domid_t domid, unsigned long frame, int readonly);
typedef BOOLEAN
(*PXEN_GNTTBL_ENDACCESS)(WDFDEVICE Device, grant_ref_t ref);

typedef struct _XEN_IFACE_GNTTBL {
  INTERFACE InterfaceHeader;

  PXEN_GNTTBL_GRANTACCESS GrantAccess;
  PXEN_GNTTBL_ENDACCESS EndAccess;
} XEN_IFACE_GNTTBL, *PXEN_IFACE_GNTTBL;

#endif