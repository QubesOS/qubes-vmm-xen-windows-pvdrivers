/*
PV Drivers for Windows Xen HVM Domains
Copyright (C) 2007 James Harper
Copyright (C) 2007 Andrew Grover <andy.grover@oracle.com>

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

#pragma warning(disable: 4201)
#pragma warning(disable: 4214)

#include <wdm.h>
#include <wdf.h>
#include <wdfminiport.h>
#include <initguid.h>
#define NDIS_MINIPORT_DRIVER
#define NDIS51_MINIPORT 1
#include <ndis.h>
#define NDIS_MAJOR_VER 5
#define NDIS_MINOR_VER 1

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#define __DRIVER_NAME "XenNet"

#include <xen_windows.h>
#include <memory.h>
#include <grant_table.h>
#include <event_channel.h>
#include <hvm/params.h>
#include <hvm/hvm_op.h>
#include <xen_public.h>
#include <io/ring.h>
#include <io/netif.h>
#define XENNET_POOL_TAG (ULONG) 'XenN'

#define NAME_SIZE 64

#define ETH_ALEN 6

/* TODO: crank this up if we support higher mtus? */
#define XN_DATA_SIZE 1500
#define XN_HDR_SIZE 14
#define XN_MIN_PKT_SIZE 60
#define XN_MAX_PKT_SIZE (XN_HDR_SIZE + XN_DATA_SIZE)

#define XN_MAX_SEND_PKTS 16

#define XENSOURCE_MAC_HDR 0x00163E
#define XN_VENDOR_DESC "Xensource"