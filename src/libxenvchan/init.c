/**
 * @file
 * @section AUTHORS
 *
 * Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 *
 *  Authors:
 *       Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 *       Daniel De Graaf <dgdegra@tycho.nsa.gov>
 *
 * @section LICENSE
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * @section DESCRIPTION
 *
 *  This file contains the setup code used to establish the ring buffer.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "libxenvchan.h"

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define SMALL_RING_SHIFT 10
#define LARGE_RING_SHIFT 11

#define MAX_SMALL_RING (1 << SMALL_RING_SHIFT)
#define SMALL_RING_OFFSET 1024
#define MAX_LARGE_RING (1 << LARGE_RING_SHIFT)
#define LARGE_RING_OFFSET 2048

// if you go over this size, you'll have too many grants to fit in the shared page.
#define MAX_RING_SHIFT 20
#define MAX_RING_SIZE (1 << MAX_RING_SHIFT)

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#define snprintf _snprintf

static void _Log(XENCONTROL_LOG_LEVEL logLevel, LPCSTR function, struct libxenvchan *ctrl, PWCHAR format, ...)
{
    va_list args;

    if (!ctrl)
        return;

    if (!ctrl->logger)
        return;

    va_start(args, format);
    ctrl->logger(logLevel, function, format, args);
    va_end(args);
}

#ifdef __MINGW32__
#define Log(level, msg, ...) _Log(level, __FUNCTION__, ctrl, L"(%p) " L##msg L"\n", ctrl, ##__VA_ARGS__)
#else
#define Log(level, msg, ...) _Log(level, __FUNCTION__, ctrl, L"(%p) " L##msg L"\n", ctrl, __VA_ARGS__)
#endif

static int init_gnt_srv(struct libxenvchan *ctrl, USHORT domain)
{
    int pages_left = ctrl->read.order >= PAGE_SHIFT ? 1 << (ctrl->read.order - PAGE_SHIFT) : 0;
    int pages_right = ctrl->write.order >= PAGE_SHIFT ? 1 << (ctrl->write.order - PAGE_SHIFT) : 0;
    uint32_t ring_ref;
    void *ring;
    DWORD status;

    status = XcGnttabPermitForeignAccess(ctrl->xc,
                                         domain,
                                         1,
                                         offsetof(struct vchan_interface, srv_live),
                                         ctrl->event_port,
                                         XENIFACE_GNTTAB_USE_NOTIFY_OFFSET | XENIFACE_GNTTAB_USE_NOTIFY_PORT,
                                         &ring,
                                         &ring_ref);

    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "Granting ring to domain %u failed", domain);
        ring_ref = ~0ul;
        goto out;
    }

    ctrl->ring = ring;
    ctrl->read.shr = &ctrl->ring->left;
    ctrl->write.shr = &ctrl->ring->right;
    ctrl->ring->left_order = (uint16_t)ctrl->read.order;
    ctrl->ring->right_order = (uint16_t)ctrl->write.order;
    ctrl->ring->cli_live = 2;
    ctrl->ring->srv_live = 1;
    ctrl->ring->cli_notify = VCHAN_NOTIFY_WRITE;

    switch (ctrl->read.order)
    {
    case SMALL_RING_SHIFT:
        ctrl->read.buffer = ((uint8_t*)ctrl->ring) + SMALL_RING_OFFSET;
        break;

    case LARGE_RING_SHIFT:
        ctrl->read.buffer = ((uint8_t*)ctrl->ring) + LARGE_RING_OFFSET;
        break;

    default:
        status = XcGnttabPermitForeignAccess(ctrl->xc,
                                             domain,
                                             pages_left,
                                             0,
                                             0,
                                             0, // no notifications
                                             &ctrl->read.buffer,
                                             ctrl->ring->grants);

        if (status != ERROR_SUCCESS)
        {
            Log(XLL_ERROR, "Granting read buffer (%d pages) to domain %u failed", pages_left, domain);
            goto out_ring;
        }
    }

    switch (ctrl->write.order)
    {
    case SMALL_RING_SHIFT:
        ctrl->write.buffer = ((uint8_t*)ctrl->ring) + SMALL_RING_OFFSET;
        break;

    case LARGE_RING_SHIFT:
        ctrl->write.buffer = ((uint8_t*)ctrl->ring) + LARGE_RING_OFFSET;
        break;

    default:
        status = XcGnttabPermitForeignAccess(ctrl->xc,
                                             domain,
                                             pages_right,
                                             0,
                                             0,
                                             0, // no notifications
                                             &ctrl->write.buffer,
                                             ctrl->ring->grants + pages_left);

        if (status != ERROR_SUCCESS)
        {
            Log(XLL_ERROR, "Granting write buffer (%d pages) to domain %u failed", pages_right, domain);
            goto out_unmap_left;
        }
    }

out:
    Log(XLL_TRACE, "returning %d", ring_ref);
    return ring_ref;

out_unmap_left:
    if (pages_left > 0)
        XcGnttabRevokeForeignAccess(ctrl->xc, ctrl->read.buffer);

out_ring:
    XcGnttabRevokeForeignAccess(ctrl->xc, ctrl->ring);
    ring_ref = ~0ul;
    ctrl->ring = NULL;
    ctrl->write.order = ctrl->read.order = 0;
    goto out;
}

static int init_gnt_cli(struct libxenvchan *ctrl, USHORT domain, uint32_t ring_ref)
{
    int rv = -1;
    uint32_t *grants;
    DWORD status;

    status = XcGnttabMapForeignPages(ctrl->xc,
                                   domain,
                                   1,
                                   &ring_ref,
                                   offsetof(struct vchan_interface, cli_live),
                                   ctrl->event_port,
                                   XENIFACE_GNTTAB_USE_NOTIFY_OFFSET | XENIFACE_GNTTAB_USE_NOTIFY_PORT,
                                   &ctrl->ring);

    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "Mapping ring (ref %u) from domain %u failed", ring_ref, domain);
        goto out;
    }

    ctrl->write.order = ctrl->ring->left_order;
    ctrl->read.order = ctrl->ring->right_order;
    ctrl->write.shr = &ctrl->ring->left;
    ctrl->read.shr = &ctrl->ring->right;

    if (ctrl->write.order < SMALL_RING_SHIFT || ctrl->write.order > MAX_RING_SHIFT)
        goto out_unmap_ring;
    if (ctrl->read.order < SMALL_RING_SHIFT || ctrl->read.order > MAX_RING_SHIFT)
        goto out_unmap_ring;
    if (ctrl->read.order == ctrl->write.order && ctrl->read.order < PAGE_SHIFT)
        goto out_unmap_ring;

    grants = ctrl->ring->grants;

    switch (ctrl->write.order)
    {
    case SMALL_RING_SHIFT:
        ctrl->write.buffer = ((uint8_t*)ctrl->ring) + SMALL_RING_OFFSET;
        break;

    case LARGE_RING_SHIFT:
        ctrl->write.buffer = ((uint8_t*)ctrl->ring) + LARGE_RING_OFFSET;
        break;

    default:
    {
        int pages_left = 1 << (ctrl->write.order - PAGE_SHIFT);

        status = XcGnttabMapForeignPages(ctrl->xc,
                                         domain,
                                         pages_left,
                                         grants,
                                         0,
                                         0,
                                         0, // no notifications
                                         &ctrl->write.buffer);

        if (status != ERROR_SUCCESS)
        {
            Log(XLL_ERROR, "Mapping write buffer (%d pages) from domain %u failed", pages_left, domain);
            goto out_unmap_ring;
        }

        grants += pages_left;
    }
    }

    switch (ctrl->read.order)
    {
    case SMALL_RING_SHIFT:
        ctrl->read.buffer = ((uint8_t*)ctrl->ring) + SMALL_RING_OFFSET;
        break;

    case LARGE_RING_SHIFT:
        ctrl->read.buffer = ((uint8_t*)ctrl->ring) + LARGE_RING_OFFSET;
        break;

    default:
    {
        int pages_right = 1 << (ctrl->read.order - PAGE_SHIFT);

        status = XcGnttabMapForeignPages(ctrl->xc,
                                         domain,
                                         pages_right,
                                         grants,
                                         0,
                                         0,
                                         XENIFACE_GNTTAB_READONLY, // no notifications
                                         &ctrl->read.buffer);

        if (status != ERROR_SUCCESS)
        {
            Log(XLL_ERROR, "Mapping read buffer (%d pages) from domain %u failed", pages_right, domain);
            goto out_unmap_left;
        }
    }
    }

    rv = 0;
out:
    Log(XLL_TRACE, "returning %d", rv);
    return rv;

out_unmap_left:
    if (ctrl->write.order >= PAGE_SHIFT)
        XcGnttabUnmapForeignPages(ctrl->xc, ctrl->write.buffer);

out_unmap_ring:
    XcGnttabUnmapForeignPages(ctrl->xc, ctrl->ring);
    ctrl->ring = 0;
    ctrl->write.order = ctrl->read.order = 0;
    rv = -1;
    goto out;
}

static int init_evt_srv(struct libxenvchan *ctrl, USHORT domain)
{
    DWORD status;

    ctrl->event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ctrl->event == NULL)
    {
        Log(XLL_ERROR, "CreateEvent failed: 0x%x", GetLastError());
        goto fail;
    }

    status = XcEvtchnOpenUnbound(ctrl->xc, domain, ctrl->event, FALSE, &ctrl->event_port);
    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "failed to bind event channel for domain %u: 0x%x", domain, status);
        goto fail;
    }

    /*
    if (xc_evtchn_unmask(ctrl->event, ctrl->event_port))
    goto fail;
    */

    return 0;

fail:
    if (ctrl->event)
        CloseHandle(ctrl->event);
    ctrl->event = NULL;
    return -1;
}

static int init_xs_srv(struct libxenvchan *ctrl, USHORT domain, const char *xs_base, uint32_t ring_ref)
{
    int ret = -1;
    XENIFACE_STORE_PERMISSION perms[2];
    char buf[64];
    char ref[16];
    char domid_str[16];
    DWORD status;

    status = XcStoreRead(ctrl->xc, "domid", sizeof(domid_str), domid_str);
    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "failed to read own domid from xenstore: 0x%x", status);
        goto fail;
    }

    // owner domain is us
    perms[0].Domain = (USHORT)atoi(domid_str);
    // permissions for domains not listed = none
    perms[0].Mask = XENIFACE_STORE_PERM_NONE;
    // peer domain
    perms[1].Domain = domain;
    perms[1].Mask = XENIFACE_STORE_PERM_READ;

    snprintf(ref, sizeof(ref), "%d", ring_ref);
    snprintf(buf, sizeof(buf), "%s/ring-ref", xs_base);

    status = XcStoreWrite(ctrl->xc, buf, ref);
    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "store write (%S, %S) failed: 0x%x", buf, ref, status);
        goto fail;
    }

    status = XcStoreSetPermissions(ctrl->xc, buf, 2, perms);
    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "failed to set store permissions on '%S': 0x%x", buf, status);
        goto fail;
    }

    snprintf(ref, sizeof(ref), "%d", ctrl->event_port);
    snprintf(buf, sizeof(buf), "%s/event-channel", xs_base);

    status = XcStoreWrite(ctrl->xc, buf, ref);
    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "store write (%S, %S) failed: 0x%x", buf, ref, status);
        goto fail;
    }

    status = XcStoreSetPermissions(ctrl->xc, buf, 2, perms);
    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "failed to set store permissions on '%S': 0x%x", buf, status);
        goto fail;
    }

    ret = 0;

fail:
    return ret;
}

static int min_order(int size)
{
    int rv = PAGE_SHIFT;

    while (size > (1 << rv))
        rv++;

    return rv;
}

struct libxenvchan *libxenvchan_server_init(XENCONTROL_LOGGER *logger, int domain, const char *xs_path, size_t left_min, size_t right_min)
{
    struct libxenvchan *ctrl;
    uint32_t ring_ref;
    DWORD status;

    if (left_min > MAX_RING_SIZE || right_min > MAX_RING_SIZE)
        return NULL;

    ctrl = malloc(sizeof(*ctrl));
    if (!ctrl)
        return NULL;

    ZeroMemory(ctrl, sizeof(*ctrl));
    ctrl->logger = logger;
    ctrl->is_server = 1;
    ctrl->server_persist = 0;

    ctrl->read.order = min_order((int)left_min);
    ctrl->write.order = min_order((int)right_min);

    // if we can avoid allocating extra pages by using in-page rings, do so
    if (left_min <= MAX_SMALL_RING && right_min <= MAX_LARGE_RING)
    {
        ctrl->read.order = SMALL_RING_SHIFT;
        ctrl->write.order = LARGE_RING_SHIFT;
    }
    else if (left_min <= MAX_LARGE_RING && right_min <= MAX_SMALL_RING)
    {
        ctrl->read.order = LARGE_RING_SHIFT;
        ctrl->write.order = SMALL_RING_SHIFT;
    }
    else if (left_min <= MAX_LARGE_RING)
    {
        ctrl->read.order = LARGE_RING_SHIFT;
    }
    else if (right_min <= MAX_LARGE_RING)
    {
        ctrl->write.order = LARGE_RING_SHIFT;
    }

    status = XcOpen(logger, &ctrl->xc);
    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "failed to open xencontrol: 0x%x", status);
        /*
        This error signifies that xeniface is not available.
        We need to return a well-defined code so the caller can potentially
        wait for xeniface to become active (this can happen after the first
        reboot after pvdrivers installation, xeniface takes a while to load).
        */
        SetLastError(ERROR_NOT_SUPPORTED);
        goto out;
    }

    if (init_evt_srv(ctrl, (USHORT)domain))
        goto out;

    ring_ref = init_gnt_srv(ctrl, (USHORT)domain);
    if (ring_ref == ~0ul)
        goto out;

    if (init_xs_srv(ctrl, (USHORT)domain, xs_path, ring_ref))
        goto out;

    Log(XLL_DEBUG, "returning %p", ctrl);
    return ctrl;

out:
    libxenvchan_close(ctrl);
    return NULL;
}

static int init_evt_cli(struct libxenvchan *ctrl, USHORT domain)
{
    DWORD status;
    ULONG port;

    ctrl->event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ctrl->event == NULL)
    {
        Log(XLL_ERROR, "CreateEvent failed: 0x%x", GetLastError());
        goto fail;
    }

    status = XcEvtchnBindInterdomain(ctrl->xc, domain, ctrl->event_port, ctrl->event, FALSE, &port);
    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "failed to bind event channel (%u, %u): 0x%x", domain, ctrl->event_port, status);
        goto fail;
    }

    ctrl->event_port = port;
    /*
    if (xc_evtchn_unmask(ctrl->event, ctrl->event_port))
    goto fail;
    */
    return 0;

fail:
    if (ctrl->event)
        CloseHandle(ctrl->event);
    ctrl->event = NULL;
    return -1;
}

struct libxenvchan *libxenvchan_client_init(XENCONTROL_LOGGER *logger, int domain, const char *xs_path)
{
    struct libxenvchan *ctrl = malloc(sizeof(struct libxenvchan));
    char buf[64], ref[64];
    uint32_t ring_ref;
    DWORD status;

    if (!ctrl)
        return NULL;

    ZeroMemory(ctrl, sizeof(*ctrl));
    ctrl->logger = logger;
    ctrl->write.order = ctrl->read.order = 0;
    ctrl->is_server = 0;

    status = XcOpen(logger, &ctrl->xc);
    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "failed to open xencontrol: 0x%x", status);
        /*
        This error signifies that xeniface is not available.
        We need to return a well-defined code so the caller can potentially
        wait for xeniface to become active (this can happen after the first
        reboot after pvdrivers installation, xeniface takes a while to load).
        */
        SetLastError(ERROR_NOT_SUPPORTED);
        goto fail;
    }

    // find xenstore entry
    snprintf(buf, sizeof buf, "%s/ring-ref", xs_path);
    status = XcStoreRead(ctrl->xc, buf, sizeof(ref), ref);
    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "failed to read '%S' from store: 0x%x", buf, status);
        goto fail;
    }

    ring_ref = atoi(ref);
    if (!ring_ref)
        goto fail;

    snprintf(buf, sizeof buf, "%s/event-channel", xs_path);
    status = XcStoreRead(ctrl->xc, buf, sizeof(ref), ref);
    if (status != ERROR_SUCCESS)
    {
        Log(XLL_ERROR, "failed to read '%S' from store: 0x%x", buf, status);
        goto fail;
    }

    ctrl->event_port = atoi(ref);
    if (!ctrl->event_port)
        goto fail;

    Log(XLL_DEBUG, "ring-ref %u, event-channel %u", ring_ref, ctrl->event_port);

    // set up event channel
    if (init_evt_cli(ctrl, (USHORT)domain))
        goto fail;

    // set up shared page(s)
    if (init_gnt_cli(ctrl, (USHORT)domain, ring_ref))
        goto fail;

    ctrl->ring->cli_live = 1;
    ctrl->ring->srv_notify = VCHAN_NOTIFY_WRITE;

out:
    Log(XLL_DEBUG, "returning %p", ctrl);
    return ctrl;

fail:
    libxenvchan_close(ctrl);
    ctrl = NULL;
    goto out;
}
