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
 *  This file contains the communications interface built on the ring buffer.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

#include "libxenvchan.h"

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static void _Log(XENCONTROL_LOG_LEVEL logLevel, PCHAR function, struct libxenvchan *ctrl, PWCHAR format, ...)
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

#define Log(level, msg, ...) _Log(level, __FUNCTION__, ctrl, L"(%p) " L##msg L"\n", ctrl, __VA_ARGS__)

#define inline __inline
#define xen_mb()  _ReadWriteBarrier()
#define xen_rmb() _ReadBarrier()
#define xen_wmb() _WriteBarrier()

#define __sync_or_and_fetch(a, b)   ((*(a)) |= (b))
#define __sync_fetch_and_and        InterlockedAnd8

static inline int rd_prod(struct libxenvchan *ctrl)
{
    return ctrl->read.shr->prod;
}

static inline int* _rd_cons(struct libxenvchan *ctrl)
{
    return &ctrl->read.shr->cons;
}
#define rd_cons(x) (*_rd_cons(x))

static inline int* _wr_prod(struct libxenvchan *ctrl)
{
    return &ctrl->write.shr->prod;
}
#define wr_prod(x) (*_wr_prod(x))

static inline int wr_cons(struct libxenvchan *ctrl)
{
    return ctrl->write.shr->cons;
}

static inline const void* rd_ring(struct libxenvchan *ctrl)
{
    return ctrl->read.buffer;
}

static inline void* wr_ring(struct libxenvchan *ctrl)
{
    return ctrl->write.buffer;
}

static inline int wr_ring_size(struct libxenvchan *ctrl)
{
    return (1 << ctrl->write.order);
}

static inline int rd_ring_size(struct libxenvchan *ctrl)
{
    return (1 << ctrl->read.order);
}

static inline void request_notify(struct libxenvchan *ctrl, uint8_t bit)
{
    uint8_t *notify = ctrl->is_server ? &ctrl->ring->cli_notify : &ctrl->ring->srv_notify;

    __sync_or_and_fetch(notify, bit);
    xen_mb(); /* post the request /before/ caller re-reads any indexes */
}

static inline int send_notify(struct libxenvchan *ctrl, uint8_t bit)
{
    uint8_t *notify, prev;
    DWORD status;

    xen_mb(); /* caller updates indexes /before/ we decode to notify */
    notify = ctrl->is_server ? &ctrl->ring->srv_notify : &ctrl->ring->cli_notify;
    prev = __sync_fetch_and_and(notify, ~bit);

    if (prev & bit)
    {
        status = XcEvtchnNotify(ctrl->xc, ctrl->event_port);
        if (status == ERROR_SUCCESS)
            return 0;

        Log(XLL_ERROR, "failed to notify event channel %u: 0x%x", ctrl->event_port, status);
        return -1;
    }
    else
    {
        return 0;
    }
}

/*
 * Get the amount of buffer space available, and do nothing about
 * notifications.
 */
static inline int raw_get_data_ready(struct libxenvchan *ctrl)
{
    int ready = rd_prod(ctrl) - rd_cons(ctrl);

    if (ready > rd_ring_size(ctrl))
    {
        /* We have no way to return errors.  Locking up the ring is
         * better than the alternatives. */
        Log(XLL_ERROR, "ready > rd_ring_size(ctrl)");
        return 0;
    }
    return ready;
}

/**
 * Get the amount of buffer space available and enable notifications if needed.
 */
static inline int fast_get_data_ready(struct libxenvchan *ctrl, int request)
{
    int ready;

    ready = raw_get_data_ready(ctrl);
    if (ready >= request)
    {
        return ready;
    }

    /* We plan to consume all data; please tell us if you send more */
    request_notify(ctrl, VCHAN_NOTIFY_WRITE);
    /*
     * If the writer moved rd_prod after our read but before request, we
     * will not get notified even though the actual amount of data ready is
     * above request. Reread rd_prod to cover this case.
     */
    ready = raw_get_data_ready(ctrl);
    return ready;
}

int libxenvchan_data_ready(struct libxenvchan *ctrl)
{
    /* Since this value is being used outside libxenvchan, request notification
     * when it changes
     */
    int ready;
    request_notify(ctrl, VCHAN_NOTIFY_WRITE);
    ready = raw_get_data_ready(ctrl);
    return ready;
}

/**
 * Get the amount of buffer space available, and do nothing
 * about notifications
 */
static inline int raw_get_buffer_space(struct libxenvchan *ctrl)
{
    int ready = wr_ring_size(ctrl) - (wr_prod(ctrl) - wr_cons(ctrl));

    if (ready > wr_ring_size(ctrl))
    {
        /* We have no way to return errors.  Locking up the ring is
        * better than the alternatives. */
        Log(XLL_ERROR, "0");
        return 0;
    }
    return ready;
}

/**
 * Get the amount of buffer space available and enable notifications if needed.
 */
static inline int fast_get_buffer_space(struct libxenvchan *ctrl, int request)
{
    int ready = raw_get_buffer_space(ctrl);

    if (ready >= request)
    {
        return ready;
    }
    /* We plan to fill the buffer; please tell us when you've read it */
    request_notify(ctrl, VCHAN_NOTIFY_READ);
    /*
     * If the reader moved wr_cons after our read but before request, we
     * will not get notified even though the actual amount of buffer space
     * is above request. Reread wr_cons to cover this case.
     */
    ready = raw_get_buffer_space(ctrl);
    return ready;
}

int libxenvchan_buffer_space(struct libxenvchan *ctrl)
{
    /* Since this value is being used outside libxenvchan, request notification
     * when it changes
     */
    int ready;
    request_notify(ctrl, VCHAN_NOTIFY_READ);
    ready = raw_get_buffer_space(ctrl);
    return ready;
}

int libxenvchan_wait(struct libxenvchan *ctrl)
{
    DWORD ret;

    ret = WaitForSingleObject(ctrl->event, INFINITE);
    if (ret != WAIT_OBJECT_0)
    {
        Log(XLL_ERROR, "WaitForSingleObject failed: 0x%x", ret);
        return -1;
    }
    return 0;
}

/**
 * returns -1 on error, or size on success
 *
 * caller must have checked that enough space is available
 */
static int do_send(struct libxenvchan *ctrl, const void *data, int size)
{
    int real_idx = wr_prod(ctrl) & (wr_ring_size(ctrl) - 1);
    int avail_contig = wr_ring_size(ctrl) - real_idx;

    if (avail_contig > size)
        avail_contig = size;

    xen_mb(); /* read indexes /then/ write data */
    memcpy((uint8_t*)wr_ring(ctrl) + real_idx, data, avail_contig);

    if (avail_contig < size)
    {
        // we rolled across the end of the ring
        memcpy(wr_ring(ctrl), (uint8_t*)data + avail_contig, size - avail_contig);
    }

    xen_wmb(); /* write data /then/ notify */
    wr_prod(ctrl) += size;

    if (send_notify(ctrl, VCHAN_NOTIFY_WRITE))
    {
        Log(XLL_ERROR, "send_notify failed");
        return -1;
    }

    return size;
}

/**
 * returns 0 if no buffer space is available, -1 on error, or size on success
 */
int libxenvchan_send(struct libxenvchan *ctrl, const void *data, size_t size)
{
    int avail;
    int sent;

    while (1)
    {
        if (!libxenvchan_is_open(ctrl))
        {
            Log(XLL_ERROR, "vchan not open");
            return -1;
        }

        avail = fast_get_buffer_space(ctrl, (int)size);
        if ((int)size <= avail)
        {
            sent = do_send(ctrl, data, (int)size);
            return sent;
        }

        if (!ctrl->blocking)
        {
            return 0;
        }

        if ((int)size > wr_ring_size(ctrl))
        {
            Log(XLL_ERROR, "size > wr_ring_size(ctrl)");
            return -1;
        }

        if (libxenvchan_wait(ctrl))
        {
            Log(XLL_ERROR, "wait failed");
            return -1;
        }
    }
}

int libxenvchan_write(struct libxenvchan *ctrl, const void *data, size_t size)
{
    int avail;
    int sent;

    if (!libxenvchan_is_open(ctrl))
    {
        Log(XLL_ERROR, "vchan not open");
        return -1;
    }

    if (ctrl->blocking)
    {
        int pos = 0;

        while (1)
        {
            avail = fast_get_buffer_space(ctrl, (int)size - pos);

            if (pos + avail > (int)size)
                avail = (int)size - pos;

            if (avail)
            {
                sent = do_send(ctrl, (uint8_t*)data + pos, avail);
                pos += sent;
            }

            if (pos == size)
            {
                return pos;
            }

            if (libxenvchan_wait(ctrl))
            {
                Log(XLL_ERROR, "wait failed");
                return -1;
            }

            if (!libxenvchan_is_open(ctrl))
            {
                Log(XLL_ERROR, "vchan not open");
                return -1;
            }
        }
    }
    else
    {
        avail = fast_get_buffer_space(ctrl, (int)size);

        if ((int)size > avail)
            size = avail;

        if (size == 0)
            return 0;

        sent = do_send(ctrl, data, (int)size);
        return sent;
    }
}

/**
 * returns -1 on error, or size on success
 *
 * caller must have checked that enough data is available
 */
static int do_recv(struct libxenvchan *ctrl, void *data, int size)
{
    int real_idx = rd_cons(ctrl) & (rd_ring_size(ctrl) - 1);
    int avail_contig = rd_ring_size(ctrl) - real_idx;

    if (avail_contig > size)
        avail_contig = size;

    xen_rmb(); /* data read must happen /after/ rd_cons read */
    memcpy(data, (uint8_t*)rd_ring(ctrl) + real_idx, avail_contig);

    if (avail_contig < size)
    {
        // we rolled across the end of the ring
        memcpy((uint8_t*)data + avail_contig, rd_ring(ctrl), size - avail_contig);
    }

    xen_mb(); /* consume /then/ notify */
    rd_cons(ctrl) += size;

    if (send_notify(ctrl, VCHAN_NOTIFY_READ))
    {
        Log(XLL_ERROR, "send_notify failed");
        return -1;
    }

    return size;
}

/**
 * reads exactly size bytes from the vchan.
 * returns 0 if insufficient data is available, -1 on error, or size on success
 */
int libxenvchan_recv(struct libxenvchan *ctrl, void *data, size_t size)
{
    int tx;

    while (1)
    {
        int avail = fast_get_data_ready(ctrl, (int)size);

        if ((int)size <= avail)
        {
            tx = do_recv(ctrl, data, (int)size);
            return tx;
        }

        if (!libxenvchan_is_open(ctrl))
        {
            Log(XLL_ERROR, "vchan not open");
            return -1;
        }

        if (!ctrl->blocking)
        {
            return 0;
        }

        if ((int)size > rd_ring_size(ctrl))
        {
            Log(XLL_ERROR, "size > rd_ring_size(ctrl)");
            return -1;
        }

        if (libxenvchan_wait(ctrl))
        {
            Log(XLL_ERROR, "wait failed");
            return -1;
        }
    }
}

int libxenvchan_read(struct libxenvchan *ctrl, void *data, size_t size)
{
    int tx;

    while (1)
    {
        int avail = fast_get_data_ready(ctrl, (int)size);

        if (avail && (int)size > avail)
            size = avail;

        if (avail)
        {
            tx = do_recv(ctrl, data, (int)size);
            return tx;
        }

        if (!libxenvchan_is_open(ctrl))
        {
            Log(XLL_ERROR, "vchan not open");
            return -1;
        }

        if (!ctrl->blocking)
        {
            return 0;
        }

        if (libxenvchan_wait(ctrl))
        {
            Log(XLL_ERROR, "wait failed");
            return -1;
        }
    }
}

int libxenvchan_is_open(struct libxenvchan* ctrl)
{
    if (ctrl->is_server)
        return ctrl->server_persist ? 1 : ctrl->ring->cli_live;
    else
        return ctrl->ring->srv_live;
}

HANDLE libxenvchan_fd_for_select(struct libxenvchan *ctrl)
{
    return ctrl->event;
}

void libxenvchan_close(struct libxenvchan *ctrl)
{
    if (!ctrl)
        return;

    Log(XLL_DEBUG, "start");
    if (ctrl->read.order >= PAGE_SHIFT && ctrl->read.buffer)
    {
        if (ctrl->is_server)
            XcGnttabRevokeForeignAccess(ctrl->xc, ctrl->read.buffer);
        else
            XcGnttabUnmapForeignPages(ctrl->xc, ctrl->read.buffer);
    }

    if (ctrl->write.order >= PAGE_SHIFT && ctrl->write.buffer)
    {
        if (ctrl->is_server)
            XcGnttabRevokeForeignAccess(ctrl->xc, ctrl->write.buffer);
        else
            XcGnttabUnmapForeignPages(ctrl->xc, ctrl->write.buffer);
    }

    if (ctrl->ring)
    {
        if (ctrl->is_server)
        {
            ctrl->ring->srv_live = 0;
            XcGnttabRevokeForeignAccess(ctrl->xc, ctrl->ring);
        }
        else
        {
            ctrl->ring->cli_live = 0;
            XcGnttabUnmapForeignPages(ctrl->xc, ctrl->ring);
        }
    }

    if (ctrl->event)
    {
        if (ctrl->ring)
            XcEvtchnNotify(ctrl->xc, ctrl->event_port);

        XcEvtchnClose(ctrl->xc, ctrl->event_port);
    }

    if (ctrl->xc)
        XcClose(ctrl->xc);

    free(ctrl);
}
