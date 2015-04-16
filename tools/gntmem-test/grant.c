#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include "xen_gntmem.h"
#include "xenctrl.h"
#include "gntmem_ioctl.h"

#define CLIENT_NOTIFY_OFFSET 62
#define SERVER_NOTIFY_OFFSET 63
#define PORT_OFFSET 64
#define BUF_CHAR_COUNT 16
#define PB(va, offset) (((BYTE *) va) + offset)

static void ReadSig(PVOID va)
{
    UINT32 i;
    char buf[BUF_CHAR_COUNT + 1] = { 0 };
    char buf2[(BUF_CHAR_COUNT + 1) * 2] = { 0 };
    BYTE *server_flag = PB(va, SERVER_NOTIFY_OFFSET);
    BYTE *client_flag = PB(va, CLIENT_NOTIFY_OFFSET);

    for (i = 0; i < BUF_CHAR_COUNT; i++)
    {
        buf[i] = PB(va, 0)[i];
        sprintf(buf2 + i * 2, "%02x", buf[i]);
    }
    wprintf(L"%p: '%S' %S S=%d C=%d\n", va, buf, buf2, *server_flag, *client_flag);
}

typedef struct _EVT_CTX
{
    HANDLE evtchn;
    evtchn_port_or_error_t port;
    BOOL is_server;
    PVOID va;
    BOOL exit;
} EVT_CTX;

DWORD EventThread(void *context)
{
    EVT_CTX *ctx = (EVT_CTX *) context;
    OVERLAPPED ol = { 0 };
    DWORD status;
    int fired_port;
    BYTE *flag;
    DWORD bytes_read;

    ol.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    while (TRUE)
    {
        HANDLE event = xc_evtchn_fd(ctx->evtchn);
        // this is the main read operation that is waited for
        if (!ReadFile(event, &fired_port, sizeof(fired_port), NULL, &ol))
        {
            status = GetLastError();
            if (ERROR_IO_PENDING != status)
            {
                wprintf(L"async read from event failed: 0x%x\n", status);
                return status;
            }
        }

        WaitForSingleObject(ol.hEvent, INFINITE);
        if (!GetOverlappedResult(event, &ol, &bytes_read, TRUE))
        {
            wprintf(L"GetOverlappedResult failed: 0x%x\n", status = GetLastError());
            return status;
        }

        if (bytes_read != sizeof(fired_port))
        {
            wprintf(L"read %d bytes, expected %d\n", bytes_read, sizeof(fired_port));
            return ERROR_INTERNAL_ERROR;
        }

        wprintf(L"event signaled: port %d fired\n", fired_port);

        // events are masked after firing by default
        xc_evtchn_unmask(ctx->evtchn, ctx->port);

        // check if the other peer exited
        if (ctx->is_server)
        {
            flag = PB(ctx->va, CLIENT_NOTIFY_OFFSET);
            if (*flag == 0) // client exited
            {
                wprintf(L"client exited\n");
                ctx->exit = TRUE;
                return 0;
            }
            if (*flag == 1) // client is running
            {
                wprintf(L"client has connected\n");
            }
        }
        else // client
        {
            flag = PB(ctx->va, SERVER_NOTIFY_OFFSET);
            if (*flag == 0) // server exited
            {
                wprintf(L"server exited\n");
                ctx->exit = TRUE;
                return 0;
            }
        }
    }
    return 0;
}

int wmain(int argc, WCHAR *argv[])
{
    struct gntmem_handle *gh;
    HANDLE evtchn;
    evtchn_port_or_error_t port;
    domid_t domid;
    grant_ref_t ref;
    void *mapped;
    struct ioctl_gntmem_map_foreign_pages_out out = { 0 };
    struct ioctl_gntmem_map_foreign_pages in = { 0 };
    struct ioctl_gntmem_unmap_foreign_pages inu = { 0 };
    int i = 0;
    BYTE *server_flag, *client_flag;
    int *port_shared;
    EVT_CTX ctx;

    if (argc < 2)
    {
        wprintf(L"Usage:\n"
                L"server:   grant s <client-domid>\n"
                L"client:   grant <server-domid> <grant-ref>\n");
        return 0;
    }

    gh = gntmem_open();
    if (gh == INVALID_HANDLE_VALUE)
    {
        wprintf(L"failed to open gntmem handle\n");
        return 1;
    }

    evtchn = xc_evtchn_open();
    if (evtchn == INVALID_HANDLE_VALUE)
    {
        wprintf(L"failed to open evtchn handle\n");
        return 2;
    }

    ctx.evtchn = evtchn;
    ctx.exit = FALSE;

    if (argv[1][0] == L's') // server
    {
        domid = (domid_t) _wtoi(argv[2]);

        port = xc_evtchn_bind_unbound_port(evtchn, domid);
        wprintf(L"client domain: %u, event port: %d\n", domid, port);

        mapped = gntmem_grant_pages_to_domain_notify(gh, domid, 1, SERVER_NOTIFY_OFFSET, port, &ref);
        wprintf(L"mapped page: %p, ref: %u\n", mapped, ref);

        if (mapped == 0)
            return 3;

        server_flag = PB(mapped, SERVER_NOTIFY_OFFSET);
        client_flag = PB(mapped, CLIENT_NOTIFY_OFFSET);
        port_shared = (int *) PB(mapped, PORT_OFFSET);

        *server_flag = 1;
        *port_shared = port;

        if (xc_evtchn_unmask(evtchn, port) < 0)
        {
            wprintf(L"xc_evtchn_unmask failed\n");
            return 4;
        }

        // start event thread
        ctx.port = port;
        ctx.is_server = TRUE;
        ctx.va = mapped;
        CreateThread(NULL, 0, EventThread, &ctx, 0, NULL);

        wprintf(L"initial memory: ");
        ReadSig(mapped);

        while (TRUE)
        {
            sprintf((char*) mapped, "QTWMAP %d", i++);
            ReadSig(mapped);
            Sleep(1000);
            if (ctx.exit)
                break;
        }

        // read for the last time
        ReadSig(mapped);
    }
    else // client
    {
        int local_port;

        in.foreign_domain = (domid_t) _wtoi(argv[1]);
        in.grant_ref = (grant_ref_t) _wtoi(argv[2]);
        in.read_only = FALSE;
        in.notify_offset = CLIENT_NOTIFY_OFFSET;
        in.notify_port = -1;

        wprintf(L"server domain: %u, grant ref: %u\n", in.foreign_domain, in.grant_ref);

        wprintf(L"performing initial map\n");
        if (gntmem_map_foreign_pages(gh, &in, &out) < 0)
        {
            wprintf(L"map failed\n");
            return 5;
        }

        mapped = out.mapped_va;
        port_shared = (int *) (((BYTE *) mapped) + PORT_OFFSET);

        port = *port_shared;
        wprintf(L"map ok! va=%p, handle 0x%x, ctx %p, event port %d\n", out.mapped_va, out.map_handle, out.context, port);
        ReadSig(mapped);

        wprintf(L"remapping with the event channel notification\n");
        inu.context = out.context;
        if (gntmem_unmap_foreign_pages(gh, &inu) < 0)
        {
            wprintf(L"unmap failed\n");
            return 6;
        }

        in.foreign_domain = (domid_t) _wtoi(argv[1]);
        in.grant_ref = (grant_ref_t) _wtoi(argv[2]);
        in.read_only = FALSE;
        in.notify_offset = CLIENT_NOTIFY_OFFSET;
        local_port = xc_evtchn_bind_interdomain(evtchn, in.foreign_domain, port);
        in.notify_port = local_port;
        //in.notify_port = -1;
        wprintf(L"local event port: %d\n", local_port);
        if (local_port < 0)
            return 7;

        if (xc_evtchn_unmask(evtchn, port) < 0)
        {
            wprintf(L"xc_evtchn_unmask failed\n");
            return 8;
        }

        if (gntmem_map_foreign_pages(gh, &in, &out) < 0)
        {
            wprintf(L"map failed\n");
            return 9;
        }

        mapped = out.mapped_va;
        server_flag = PB(mapped, SERVER_NOTIFY_OFFSET);
        client_flag = PB(mapped, CLIENT_NOTIFY_OFFSET);
        port_shared = (int *) PB(mapped, PORT_OFFSET);
        wprintf(L"map ok! va=%p, handle 0x%x, ctx %p\n", out.mapped_va, out.map_handle, out.context);

        wprintf(L"initial memory: ");
        ReadSig(mapped);

        // let the server know we're live
        *client_flag = 1;
        xc_evtchn_notify(evtchn, local_port);

        // start event thread
        ctx.port = local_port;
        ctx.is_server = FALSE;
        ctx.va = mapped;
        CreateThread(NULL, 0, EventThread, &ctx, 0, NULL);

        for (i = 0; i < 60; i++)
        {
            ReadSig(mapped);
            Sleep(1000);
            if (ctx.exit)
                break;
        }

        // read for the last time
        ReadSig(mapped);

        inu.context = out.context;
        if (gntmem_unmap_foreign_pages(gh, &inu) < 0)
        {
            wprintf(L"unmap failed\n");
            return 10;
        }
    }

    wprintf(L"done\n");

    gntmem_close(gh);
    xc_evtchn_close(evtchn);
    return 0;
}
