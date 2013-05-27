
#include <xenctrl.h>
#include <xen_gntmem.h>
#include <stdint.h>

xc_gntshr *xc_gntshr_open(xentoollog_logger *logger,
                      unsigned open_flags)
{

    return gntmem_open();
}

int xc_gntshr_close(xc_gntshr *xcg)
{
    gntmem_close(xcg);
    return 0;
}


void *xc_gntshr_share_pages(xc_gntshr *xcg, domid_t domid,
        int count, uint32_t *refs, int writable)
{
    if (!writable) {
        /* read-only not supported */
        return NULL;
    }
    return gntmem_grant_pages_to_domain(xcg, domid, count, refs);
}

void *xc_gntshr_share_page_notify(xc_gntshr *xcg, domid_t domid,
                uint32_t *ref, int writable,
                uint32_t notify_offset,
                evtchn_port_t notify_port)
{
    if (!writable) {
        /* read-only not supported */
        return NULL;
    }
    return gntmem_grant_pages_to_domain_notify(xcg, domid, 1,
            notify_offset, notify_port, ref);
}

int xc_gntshr_munmap(xc_gntshr *xcg, void *start_address, uint32_t count)
{
    /* FIXME: Current kernel interface doesn't allow to unmap some pages, only
     * all of them or none */

    return -1;
}


