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

#if !defined(_XENCONFIG_H_)
#define _XENCONFIG_H_

#include <ntddk.h>
#include <wdm.h>
#include <initguid.h>
#include <wdmguid.h>
#include <errno.h>
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#define __DRIVER_NAME "XenConfig"
#include <xen_windows.h>
#include <xen_public.h>

#define XENCONFIG_POOL_TAG (ULONG) 'XenC'

typedef struct
{
  PDEVICE_OBJECT filter_do;
  PDEVICE_OBJECT pdo;
  PDEVICE_OBJECT lower_do;

  PMDL config_mdl;
} XENCONFIG_DEVICE_DATA, *PXENCONFIG_DEVICE_DATA;

#endif
