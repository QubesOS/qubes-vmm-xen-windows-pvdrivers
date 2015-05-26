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

// TODO: use xencontrol's logger
#if defined(DBG) || defined(DEBUG) || defined(_DEBUG)
#   define Log(msg, ...) fprintf(stderr, __FUNCTION__ ": " msg "\n", __VA_ARGS__)
#else
#   define Log(msg, ...)
#endif

static int init_gnt_srv(struct libxenvchan *ctrl, USHORT domain)
{
    int pages_left = ctrl->read.order >= PAGE_SHIFT ? 1 << (ctrl->read.order - PAGE_SHIFT) : 0;
    int pages_right = ctrl->write.order >= PAGE_SHIFT ? 1 << (ctrl->write.order - PAGE_SHIFT) : 0;
    uint32_t ring_ref;
    void *ring;
    DWORD status;

    status = GnttabGrantPages(ctrl->xeniface,
                              domain,
                              1,
                              offsetof(struct vchan_interface, srv_live),
                              ctrl->event_port,
                              GNTTAB_GRANT_PAGES_USE_NOTIFY_OFFSET | GNTTAB_GRANT_PAGES_USE_NOTIFY_PORT,
                              &ctrl->ring_handle,
                              &ring,
                              &ring_ref);

    if (status != ERROR_SUCCESS)
    {
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
        status = GnttabGrantPages(ctrl->xeniface,
                                  domain,
                                  pages_left,
                                  0,
                                  0,
                                  0, // no notifications
                                  &ctrl->read.handle,
                                  &ctrl->read.buffer,
                                  ctrl->ring->grants);

        if (status != ERROR_SUCCESS)
            goto out_ring;
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
        status = GnttabGrantPages(ctrl->xeniface,
                                  domain,
                                  pages_right,
                                  0,
                                  0,
                                  0, // no notifications
                                  &ctrl->write.handle,
                                  &ctrl->write.buffer,
                                  ctrl->ring->grants + pages_left);

        if (status != ERROR_SUCCESS)
            goto out_unmap_left;
    }

out:
    return ring_ref;

out_unmap_left:
    if (pages_left > 0)
        GnttabUngrantPages(ctrl->xeniface, ctrl->read.handle);

out_ring:
    GnttabUngrantPages(ctrl->xeniface, ctrl->ring_handle);
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

    status = GnttabMapForeignPages(ctrl->xeniface,
                                   domain,
                                   1,
                                   &ring_ref,
                                   offsetof(struct vchan_interface, cli_live),
                                   ctrl->event_port,
                                   GNTTAB_GRANT_PAGES_USE_NOTIFY_OFFSET | GNTTAB_GRANT_PAGES_USE_NOTIFY_PORT,
                                   &ctrl->ring_handle,
                                   &ctrl->ring);

    if (status != ERROR_SUCCESS)
        goto out;

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

        status = GnttabMapForeignPages(ctrl->xeniface,
                                       domain,
                                       pages_left,
                                       grants,
                                       0,
                                       0,
                                       0, // no notifications
                                       &ctrl->write.handle,
                                       &ctrl->write.buffer);

        if (status != ERROR_SUCCESS)
            goto out_unmap_ring;

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

        status = GnttabMapForeignPages(ctrl->xeniface,
                                       domain,
                                       pages_right,
                                       grants,
                                       0,
                                       0,
                                       GNTTAB_GRANT_PAGES_READONLY, // no notifications
                                       &ctrl->read.handle,
                                       &ctrl->read.buffer);

        if (status != ERROR_SUCCESS)
            goto out_unmap_left;
    }
    }

    rv = 0;
out:
    return rv;

out_unmap_left:
    if (ctrl->write.order >= PAGE_SHIFT)
        GnttabUnmapForeignPages(ctrl->xeniface, ctrl->write.handle);

out_unmap_ring:
    GnttabUnmapForeignPages(ctrl->xeniface, ctrl->ring_handle);
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
        goto fail;
    status = EvtchnBindUnboundPort(ctrl->xeniface, domain, ctrl->event, FALSE, &ctrl->event_port);
    if (status != ERROR_SUCCESS)
        goto fail;

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
    XENBUS_STORE_PERMISSION perms[2];
    char buf[64];
    char ref[16];
    char domid_str[16];
    DWORD status;

    status = StoreRead(ctrl->xeniface, "domid", sizeof(domid_str), domid_str);
    if (status != ERROR_SUCCESS)
        goto fail;

    // owner domain is us
    perms[0].Domain = (USHORT)atoi(domid_str);
    // permissions for domains not listed = none
    perms[0].Mask = XS_PERM_NONE;
    // peer domain
    perms[1].Domain = domain;
    perms[1].Mask = XS_PERM_READ;

    snprintf(ref, sizeof(ref), "%d", ring_ref);
    snprintf(buf, sizeof(buf), "%s/ring-ref", xs_base);

    status = StoreWrite(ctrl->xeniface, buf, ref);
    if (status != ERROR_SUCCESS)
        goto fail;

    status = StoreSetPermissions(ctrl->xeniface, buf, 2, perms);
    if (status != ERROR_SUCCESS)
        goto fail;

    snprintf(ref, sizeof(ref), "%d", ctrl->event_port);
    snprintf(buf, sizeof(buf), "%s/event-channel", xs_base);

    status = StoreWrite(ctrl->xeniface, buf, ref);
    if (status != ERROR_SUCCESS)
        goto fail;

    status = StoreSetPermissions(ctrl->xeniface, buf, 2, perms);
    if (status != ERROR_SUCCESS)
        goto fail;

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

struct libxenvchan *libxenvchan_server_init(XenifaceLogger *logger, int domain, const char *xs_path, size_t left_min, size_t right_min)
{
    struct libxenvchan *ctrl;
    uint32_t ring_ref;

    if (left_min > MAX_RING_SIZE || right_min > MAX_RING_SIZE)
        return NULL;

    ctrl = malloc(sizeof(*ctrl));
    if (!ctrl)
        return NULL;

    ctrl->logger = logger;
    XenifaceRegisterLogger(logger);

    ZeroMemory(ctrl, sizeof(*ctrl));
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

    if (XenifaceOpen(&ctrl->xeniface) != ERROR_SUCCESS)
        goto out;

    if (init_evt_srv(ctrl, (USHORT)domain))
        goto out;

    ring_ref = init_gnt_srv(ctrl, (USHORT)domain);
    if (ring_ref == ~0ul)
        goto out;

    if (init_xs_srv(ctrl, (USHORT)domain, xs_path, ring_ref))
        goto out;

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
        goto fail;
    status = EvtchnBindInterdomain(ctrl->xeniface, domain, ctrl->event_port, ctrl->event, FALSE, &port);
    if (status != ERROR_SUCCESS)
        goto fail;

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

struct libxenvchan *libxenvchan_client_init(XenifaceLogger *logger, int domain, const char *xs_path)
{
    struct libxenvchan *ctrl = malloc(sizeof(struct libxenvchan));
    char buf[64], ref[64];
    uint32_t ring_ref;
    DWORD status;

    if (!ctrl)
        return NULL;

    ctrl->logger = logger;
    XenifaceRegisterLogger(logger);

    ZeroMemory(ctrl, sizeof(*ctrl));
    ctrl->write.order = ctrl->read.order = 0;
    ctrl->is_server = 0;

    status = XenifaceOpen(&ctrl->xeniface);
    if (status != ERROR_SUCCESS)
        goto fail;

    // find xenstore entry
    snprintf(buf, sizeof buf, "%s/ring-ref", xs_path);
    status = StoreRead(ctrl->xeniface, buf, sizeof(ref), ref);
    if (status != ERROR_SUCCESS)
        goto fail;

    ring_ref = atoi(ref);
    if (!ring_ref)
        goto fail;

    snprintf(buf, sizeof buf, "%s/event-channel", xs_path);
    status = StoreRead(ctrl->xeniface, buf, sizeof(ref), ref);
    if (status != ERROR_SUCCESS)
        goto fail;

    ctrl->event_port = atoi(ref);
    if (!ctrl->event_port)
        goto fail;

    // set up event channel
    if (init_evt_cli(ctrl, (USHORT)domain))
        goto fail;

    // set up shared page(s)
    if (init_gnt_cli(ctrl, (USHORT)domain, ring_ref))
        goto fail;

    ctrl->ring->cli_live = 1;
    ctrl->ring->srv_notify = VCHAN_NOTIFY_WRITE;

out:
    return ctrl;

fail:
    libxenvchan_close(ctrl);
    ctrl = NULL;
    goto out;
}
