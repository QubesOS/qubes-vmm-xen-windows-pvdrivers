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
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * @section DESCRIPTION
 *
 * This is a test program for libxenvchan.  Communications are in one direction,
 * either server (grant offeror) to client or vice versa.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#include <libxenvchan.h>
#include <xencontrol.h>

#include <strsafe.h>

void XifLogger(XENCONTROL_LOG_LEVEL level, const CHAR *function, const WCHAR *format, va_list args)
{
    WCHAR buf[1024];
    StringCbVPrintfW(buf, sizeof(buf), format, args);
    fprintf(stderr, "[X] %s: %S\n", function, buf);
}

#if defined(DEBUG) || defined(_DEBUG) || defined(DBG)
#define Log(msg, ...) fprintf(stderr, __FUNCTION__ ": " msg "\n", __VA_ARGS__)
#else
#define Log(msg, ...)
#endif

#define perror(msg) fprintf(stderr, __FUNCTION__ ": " msg " failed: error 0x%x\n", GetLastError())

int libxenvchan_write_all(struct libxenvchan *ctrl, char *buf, int size)
{
    int written = 0;
    int ret;

    Log("> size %d", size);
    while (written < size)
    {
        ret = libxenvchan_write(ctrl, buf + written, size - written);
        if (ret <= 0)
        {
            perror("write");
            exit(1);
        }
        written += ret;
    }
    return size;
}

void write_all(HANDLE fd, char *buf, DWORD size)
{
    DWORD written = 0;
    DWORD tx;

    while (written < size)
    {
        if (!WriteFile(fd, buf + written, size - written, &tx, NULL))
        {
            perror("write");
            exit(1);
        }
        written += tx;
        Log("stdout written %d, total %d", tx, written);
    }
}

void usage(char** argv)
{
    fprintf(stderr, "usage:\n"
            "%s [client|server] [read|write] domid nodepath\n", argv[0]);
    exit(1);
}

#define BUFSIZE 5000
char buf[BUFSIZE];
void reader(struct libxenvchan *ctrl)
{
    int size;
    HANDLE fd = GetStdHandle(STD_OUTPUT_HANDLE);

    while (1)
    {
        size = rand() % (BUFSIZE - 1) + 1;
        Log("reading %d", size);
        size = libxenvchan_read(ctrl, buf, size);
        Log("read %d", size);
        fprintf(stderr, "#");
        if (size < 0)
        {
            perror("read vchan");
            libxenvchan_close(ctrl);
            exit(1);
        }
        write_all(fd, buf, size);
    }
}

void writer(struct libxenvchan *ctrl)
{
    int size;
    HANDLE fd = GetStdHandle(STD_INPUT_HANDLE);
    DWORD tx;

    while (1)
    {
        size = rand() % (BUFSIZE - 1) + 1;
        if (!ReadFile(fd, buf, size, &tx, NULL))
        {
            perror("read stdin");
            libxenvchan_close(ctrl);
            exit(1);
        }
        Log("stdin read %d", tx);

        if (tx == 0)
            break;

        Log("writing %d", tx);
        size = libxenvchan_write_all(ctrl, buf, tx);
        Log("written %d", size);
        fprintf(stderr, "#");
        
        if (size < 0)
        {
            perror("vchan write");
            exit(1);
        }
        if (size == 0)
        {
            perror("write size=0?\n");
            exit(1);
        }
    }
}

/**
    Simple libxenvchan application, both client and server.
    One side does writing, the other side does reading; both from
    standard input/output fds.
    */
int __cdecl main(int argc, char **argv)
{
    int seed = (int)time(0);
    struct libxenvchan *ctrl = 0;
    int wr = 0;

    if (argc < 4)
        usage(argv);
    
    if (!strcmp(argv[2], "read"))
        wr = 0;
    else if (!strcmp(argv[2], "write"))
        wr = 1;
    else
        usage(argv);

    if (!strcmp(argv[1], "server"))
        ctrl = libxenvchan_server_init(XifLogger, atoi(argv[3]), argv[4], 0, 0, XLL_DEBUG);
    else if (!strcmp(argv[1], "client"))
        ctrl = libxenvchan_client_init(XifLogger, atoi(argv[3]), argv[4], XLL_DEBUG);
    else
        usage(argv);

    if (!ctrl)
    {
        perror("libxenvchan_*_init");
        exit(1);
    }

    XcSetLogLevel(ctrl->xc, XLL_DEBUG);
    ctrl->blocking = 1;
    Log("blocking: %d", ctrl->blocking);

    srand(seed);
    fprintf(stderr, "seed=%d\n", seed);
    if (wr)
        writer(ctrl);
    else
        reader(ctrl);
    libxenvchan_close(ctrl);
    return 0;
}
