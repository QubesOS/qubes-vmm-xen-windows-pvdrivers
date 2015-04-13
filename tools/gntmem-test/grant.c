#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include "xen_gntmem.h"
#include "gntmem_ioctl.h"

#define PB(va) ((BYTE*)(va))

static void ReadSig(PVOID va)
{
    UINT32 i;
    char buf[16];
    char buf2[32] = { 0 };
    for (i = 0; i < 15; i++)
    {
        buf[i] = PB(va)[i];
        sprintf(buf2 + i * 2, "%02x", buf[i]);
    }
    wprintf(L"%p: '%S' %S\n", va, buf, buf2);
}

int wmain(int argc, WCHAR *argv[])
{
    struct gntmem_handle *gh;
    domid_t domid;
    grant_ref_t ref;
    void *mapped;
    struct ioctl_gntmem_map_foreign_pages_out out = { 0 };
    struct ioctl_gntmem_map_foreign_pages in = { 0 };
    struct ioctl_gntmem_unmap_foreign_pages inu = { 0 };
    int i = 0;

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
        wprintf(L"failed to open gnt driver\n");
        return 1;
    }

    if (argv[1][0] == L's') // server
    {
        domid = (domid_t) _wtoi(argv[2]);
        wprintf(L"client domain: %u\n", domid);

        mapped = gntmem_grant_pages_to_domain(gh, domid, 1, &ref);
        wprintf(L"mapped page: %p, ref: %u\n", mapped, ref);

        if (mapped == 0)
            return 2;

        wprintf(L"initial memory:\n");
        ReadSig(mapped);

        while (1)
        {
            sprintf((char*) mapped, "QTWMAP %d", i++);
            wprintf(L"%S\n", mapped);
            Sleep(1000);
        }
    }
    else // client
    {
        in.foreign_domain = (domid_t) _wtoi(argv[1]);
        in.grant_ref = (grant_ref_t) _wtoi(argv[2]);
        in.read_only = FALSE;
        in.notify_offset = -1;
        in.notify_port = -1;

        wprintf(L"server domain: %u, ref: %u\n", in.foreign_domain, in.grant_ref);

        if (gntmem_map_foreign_pages(gh, &in, &out) < 0)
        {
            wprintf(L"map failed\n");
            return 3;
        }

        wprintf(L"map ok! va=%p, handle 0x%x, ctx %p\n", out.mapped_va, out.map_handle, out.context);
        wprintf(L"first bytes: %02x%02x%02x%02x\n", PB(out.mapped_va)[0], PB(out.mapped_va)[1], PB(out.mapped_va)[2], PB(out.mapped_va)[3]);

        for (i = 0; i < 10; i++)
        {
            ReadSig(out.mapped_va);
            Sleep(1000);
        }

        inu.context = out.context;
        gntmem_unmap_foreign_pages(gh, &inu);
    }

    wprintf(L"done\n");

    gntmem_close(gh);
    return 0;
}
