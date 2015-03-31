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

#include "xenpci.h"

VOID GntTbl_PutRef(PVOID Context, grant_ref_t ref, ULONG tag)
{
    PXENPCI_DEVICE_DATA xpdd = Context;

    UNREFERENCED_PARAMETER(tag);

#if DBG
    if (xpdd->gnttbl_tag[ref].tag != tag)
        DEBUGF("Grant Entry %d for %.4s doesn't match %.4s", ref, (PUCHAR) &tag, (PUCHAR) &xpdd->gnttbl_tag[ref].tag);
    ASSERT(xpdd->gnttbl_tag[ref].tag == tag);
    xpdd->gnttbl_tag[ref].tag = 0;
    xpdd->gnttbl_tag[ref].generation = (ULONG) -1;
#endif
    stack_push(xpdd->gnttbl_ss, (PVOID) ref);
}

grant_ref_t GntTbl_GetRef(PVOID Context, ULONG tag)
{
    PXENPCI_DEVICE_DATA xpdd = Context;
    unsigned int ref;
    PVOID ptr_ref;

    UNREFERENCED_PARAMETER(tag);

    if (!stack_pop(xpdd->gnttbl_ss, &ptr_ref))
    {
        DEBUGF("No free grant refs");
        return INVALID_GRANT_REF;
    }
    ref = (grant_ref_t) (ULONG_PTR) ptr_ref;
#if DBG
    if (xpdd->gnttbl_tag[ref].tag)
        DEBUGF("Grant Entry %d for %.4s in use by %.4s", ref, (PUCHAR) &tag, (PUCHAR) &xpdd->gnttbl_tag[ref].tag);
    ASSERT(!xpdd->gnttbl_tag[ref].tag);
    xpdd->gnttbl_tag[ref].generation = xpdd->gnttbl_generation;
    xpdd->gnttbl_tag[ref].tag = tag;
#endif

    return ref;
}

int GntTbl_Map(PVOID Context, unsigned int start_idx, unsigned int end_idx)
{
    PXENPCI_DEVICE_DATA xpdd = Context;
    struct xen_add_to_physmap xatp;
    unsigned int i = end_idx;

    FUNCTION_ENTER();
    /* Loop backwards, so that the first hypercall has the largest index,  ensuring that the table will grow only once.  */
    do
    {
        xatp.domid = DOMID_SELF;
        xatp.idx = i;
        xatp.space = XENMAPSPACE_grant_table;
        xatp.gpfn = (xen_pfn_t) MmGetMdlPfnArray(xpdd->gnttbl_mdl)[i];
        if (HYPERVISOR_memory_op(xpdd, XENMEM_add_to_physmap, &xatp))
        {
            DEBUGF("*** ERROR MAPPING FRAME %d ***", i);
        }
    } while (i-- > start_idx);
    FUNCTION_EXIT();

    return 0;
}

grant_ref_t GntTbl_GrantAccess(PVOID Context, domid_t domid, uint32_t frame, int readonly, grant_ref_t ref, ULONG tag)
{
    // xen api limits pfn to 32bit, so no guests over 8TB
    PXENPCI_DEVICE_DATA xpdd = Context;

    //DEBUGF(" --> GntTbl_GrantAccess\n");

    if (ref == INVALID_GRANT_REF)
        ref = GntTbl_GetRef(Context, tag);
    if (ref == INVALID_GRANT_REF)
        return ref;

    ASSERT(xpdd->gnttbl_tag[ref].tag == tag);

    xpdd->gnttbl_table[ref].frame = frame;
    xpdd->gnttbl_table[ref].domid = domid;

    if (xpdd->gnttbl_table[ref].flags)
    {
#if DBG
        DEBUGF("Grant Entry %d for %.4s still in use by %.4s", ref, (PUCHAR) &tag, (PUCHAR) &xpdd->gnttbl_tag[ref].tag);
#else
        DEBUGF("Grant Entry %d for %.4s still in use", ref, (PUCHAR)&tag);
#endif
    }
    ASSERT(!xpdd->gnttbl_table[ref].flags);

    KeMemoryBarrier();
    readonly *= GTF_readonly;
    xpdd->gnttbl_table[ref].flags = GTF_permit_access | (uint16_t) readonly;

    return ref;
}

BOOLEAN GntTbl_EndAccess(PVOID Context, grant_ref_t ref, BOOLEAN keepref, ULONG tag)
{
    PXENPCI_DEVICE_DATA xpdd = Context;
    unsigned short flags, nflags;

    ASSERT(ref != INVALID_GRANT_REF);
    ASSERT(xpdd->gnttbl_tag[ref].tag == tag);

    nflags = xpdd->gnttbl_table[ref].flags;
    do
    {
        if ((flags = nflags) & (GTF_reading | GTF_writing))
        {
            DEBUGF("Grant Entry %d for %.4s still use", ref, (PUCHAR) &tag);
            return FALSE;
        }
    } while ((nflags = InterlockedCompareExchange16(
        (volatile SHORT *) &xpdd->gnttbl_table[ref].flags, 0, flags)) != flags);

    if (!keepref)
        GntTbl_PutRef(Context, ref, tag);
    //DEBUGF(" <-- GntTbl_EndAccess\n");
    return TRUE;
}

grant_handle_t GntTbl_MapForeignPage(PVOID Context, domid_t foreign_domain, grant_ref_t grant_ref, PFN_NUMBER local_pfn, uint32_t flags)
{
    PXENPCI_DEVICE_DATA xpdd = Context;
    struct gnttab_map_grant_ref op;
    int status;

    // TODO: batch mapping of multiple pages
    FUNCTION_ENTER();

    op.dom = foreign_domain;
    op.ref = grant_ref;
    op.flags = flags;
    op.host_addr = local_pfn;

    status = HYPERVISOR_grant_table_op(xpdd, GNTTABOP_map_grant_ref, &op, 1);

    if ((status < 0) || (((int) op.handle) < 0) || (op.status != GNTST_okay))
    {
        DEBUGF("Error mapping foreign page: domain %u, grant ref %u, flags 0x%x, pfn 0x%I64x; status=%d (%d)",
               foreign_domain, grant_ref, flags, local_pfn, op.handle, op.status);
    }

    FUNCTION_EXIT();

    return op.handle;
}

int GntTbl_UnmapForeignPage(PVOID Context, grant_handle_t grant_handle, PFN_NUMBER local_pfn)
{
    PXENPCI_DEVICE_DATA xpdd = Context;
    struct gnttab_unmap_grant_ref op;
    int status;

    // TODO: batch unmapping of multiple pages
    FUNCTION_ENTER();

    op.handle = grant_handle;
    op.host_addr = local_pfn;

    status = HYPERVISOR_grant_table_op(xpdd, GNTTABOP_unmap_grant_ref, &op, 1);

    if ((status < 0) || (op.status != GNTST_okay))
    {
        DEBUGF("Error unmapping foreign page: grant handle %u, pfn 0x%I64x; status=%d",
               grant_handle, local_pfn, op.status);
    }

    FUNCTION_EXIT();

    return op.status;
}

static unsigned int GntTbl_QueryMaxFrames(PXENPCI_DEVICE_DATA xpdd)
{
    struct gnttab_query_size query;
    int rc;

    query.dom = DOMID_SELF;

    rc = HYPERVISOR_grant_table_op(xpdd, GNTTABOP_query_size, &query, 1);
    if ((rc < 0) || (query.status != GNTST_okay))
    {
        DEBUGF("*** CANNOT QUERY MAX GRANT FRAME ***");
        return 4; /* Legacy max supported number of frames */
    }
    return query.max_nr_frames;
}

VOID GntTbl_Init(PXENPCI_DEVICE_DATA xpdd)
{
    int i;
    int grant_entries;

    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

    FUNCTION_ENTER();

    xpdd->grant_frames = GntTbl_QueryMaxFrames(xpdd);
    DEBUGF("grant_frames = %d", xpdd->grant_frames);
    grant_entries = min(NR_GRANT_ENTRIES, (xpdd->grant_frames * PAGE_SIZE / sizeof(grant_entry_t)));
    DEBUGF("grant_entries = %d", grant_entries);
#if DBG
    xpdd->gnttbl_tag = ExAllocatePoolWithTag(NonPagedPool, grant_entries * sizeof(grant_tag_t), XENPCI_POOL_TAG);
    RtlZeroMemory(xpdd->gnttbl_tag, grant_entries * sizeof(grant_tag_t));
    xpdd->gnttbl_tag_copy = ExAllocatePoolWithTag(NonPagedPool, grant_entries * sizeof(grant_tag_t), XENPCI_POOL_TAG);
    xpdd->gnttbl_generation = 0;
#endif
    xpdd->gnttbl_table_copy = ExAllocatePoolWithTag(NonPagedPool, xpdd->grant_frames * PAGE_SIZE, XENPCI_POOL_TAG);
    ASSERT(xpdd->gnttbl_table_copy); // lazy
    xpdd->gnttbl_table = ExAllocatePoolWithTag(NonPagedPool, xpdd->grant_frames * PAGE_SIZE, XENPCI_POOL_TAG);
    ASSERT(xpdd->gnttbl_table); // lazy
    /* dom0 crashes if we allocate the wrong amount of memory here! */
    xpdd->gnttbl_mdl = IoAllocateMdl(xpdd->gnttbl_table, (xpdd->grant_frames) * PAGE_SIZE, FALSE, FALSE, NULL);
    ASSERT(xpdd->gnttbl_mdl); // lazy
    MmBuildMdlForNonPagedPool(xpdd->gnttbl_mdl);

    /* make some holes for the grant pages to fill in */
    for (i = 0; i < (int) xpdd->grant_frames; i++)
    {
        struct xen_memory_reservation reservation;
        xen_pfn_t pfn;
        ULONG ret;

        reservation.address_bits = 0;
        reservation.extent_order = 0;
        reservation.domid = DOMID_SELF;
        reservation.nr_extents = 1;
#pragma warning(disable: 4127) /* conditional expression is constant */
        pfn = (xen_pfn_t) MmGetMdlPfnArray(xpdd->gnttbl_mdl)[i];
        DEBUGF("pfn = %x", (ULONG) pfn);
        set_xen_guest_handle(reservation.extent_start, &pfn);

        DEBUGF("Calling HYPERVISOR_memory_op - pfn = %x", (ULONG) pfn);
        ret = HYPERVISOR_memory_op(xpdd, XENMEM_decrease_reservation, &reservation);
        DEBUGF("decreased %d pages for grant table frame %d", ret, i);
    }

    stack_new(&xpdd->gnttbl_ss, grant_entries);

    for (i = NR_RESERVED_ENTRIES; i < grant_entries; i++)
        stack_push(xpdd->gnttbl_ss, (PVOID) i);

    GntTbl_Map(xpdd, 0, xpdd->grant_frames - 1);

    RtlZeroMemory(xpdd->gnttbl_table, PAGE_SIZE * xpdd->grant_frames);

    FUNCTION_EXIT();
}

VOID GntTbl_Suspend(PXENPCI_DEVICE_DATA xpdd)
{
#if DBG
    int grant_entries;
#endif
    int i;

    FUNCTION_ENTER();

#if DBG
    for (i = 0; i < (int) min(NR_GRANT_ENTRIES, (xpdd->grant_frames * PAGE_SIZE / sizeof(grant_entry_t))); i++)
    {
        if (xpdd->gnttbl_tag[i].tag != 0) // && xpdd->gnttbl_tag[i].generation < xpdd->gnttbl_generation)
        {
            DEBUGF("grant entry for %.4s from generation %d", (PUCHAR) &xpdd->gnttbl_tag[i].tag, xpdd->gnttbl_tag[i].generation);
        }
    }
    xpdd->gnttbl_generation++;
#endif

    /* copy some grant refs and switch to an alternate freelist, but only on hiber */
    if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
    {
        DEBUGF("backing up grant ref stack");
        for (i = 0; i < HIBER_GREF_COUNT; i++)
        {
            xpdd->hiber_grefs[i] = INVALID_GRANT_REF;
        }
        for (i = 0; i < HIBER_GREF_COUNT; i++)
        {
            if ((xpdd->hiber_grefs[i] = GntTbl_GetRef(xpdd, (ULONG)'HIBR')) == INVALID_GRANT_REF)
                break;
        }
        DEBUGF("%d grant refs reserved", i);
        xpdd->gnttbl_ss_copy = xpdd->gnttbl_ss;
        stack_new(&xpdd->gnttbl_ss, HIBER_GREF_COUNT);
    }
    else
    {
        xpdd->gnttbl_ss_copy = NULL;
    }

    memcpy(xpdd->gnttbl_table_copy, xpdd->gnttbl_table, xpdd->grant_frames * PAGE_SIZE);
#if DBG
    /* even though gnttbl_tag is actually preserved, it is used by the dump driver so must be restored to exactly the same state as it was on suspend */
    grant_entries = min(NR_GRANT_ENTRIES, (xpdd->grant_frames * PAGE_SIZE / sizeof(grant_entry_t)));
    memcpy(xpdd->gnttbl_tag_copy, xpdd->gnttbl_tag, grant_entries * sizeof(grant_tag_t));
#endif

    /* put the grant entries on the new freelist, after copying the tables above */
    if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
    {
        for (i = 0; i < HIBER_GREF_COUNT; i++)
        {
            if (xpdd->hiber_grefs[i] == INVALID_GRANT_REF)
                break;
            GntTbl_PutRef(xpdd, xpdd->hiber_grefs[i], (ULONG)'HIBR');
        }
    }

    FUNCTION_EXIT();
}

VOID GntTbl_Resume(PXENPCI_DEVICE_DATA xpdd)
{
    ULONG new_grant_frames;
    ULONG result;
    int i;
#if DBG
    int grant_entries;
#endif

    FUNCTION_ENTER();

    for (i = 0; i < (int) xpdd->grant_frames; i++)
    {
        struct xen_memory_reservation reservation;
        xen_pfn_t pfn;
        ULONG ret;

        reservation.address_bits = 0;
        reservation.extent_order = 0;
        reservation.domid = DOMID_SELF;
        reservation.nr_extents = 1;
#pragma warning(disable: 4127) /* conditional expression is constant */
        pfn = (xen_pfn_t) MmGetMdlPfnArray(xpdd->gnttbl_mdl)[i];
        DEBUGF("pfn = %x", (ULONG) pfn);
        set_xen_guest_handle(reservation.extent_start, &pfn);

        DEBUGF("Calling HYPERVISOR_memory_op - pfn = %x", (ULONG) pfn);
        ret = HYPERVISOR_memory_op(xpdd, XENMEM_decrease_reservation, &reservation);
        DEBUGF("decreased %d pages for grant table frame %d", ret, i);
    }

    new_grant_frames = GntTbl_QueryMaxFrames(xpdd);
    DEBUGF("new_grant_frames = %d", new_grant_frames);
    ASSERT(new_grant_frames >= xpdd->grant_frames); // lazy
    result = GntTbl_Map(xpdd, 0, xpdd->grant_frames - 1);
    DEBUGF("GntTbl_Map result = %d", result);
    memcpy(xpdd->gnttbl_table, xpdd->gnttbl_table_copy, xpdd->grant_frames * PAGE_SIZE);
#if DBG
    grant_entries = min(NR_GRANT_ENTRIES, (xpdd->grant_frames * PAGE_SIZE / sizeof(grant_entry_t)));
    memcpy(xpdd->gnttbl_tag, xpdd->gnttbl_tag_copy, grant_entries * sizeof(grant_tag_t));
#endif

    /* switch back and put the hiber grants back again */
    if (xpdd->gnttbl_ss_copy)
    {
        DEBUGF("restoring grant ref stack");
        stack_delete(xpdd->gnttbl_ss, NULL, NULL);
        xpdd->gnttbl_ss = xpdd->gnttbl_ss_copy;
        for (i = 0; i < HIBER_GREF_COUNT; i++)
        {
            if (xpdd->hiber_grefs[i] == INVALID_GRANT_REF)
                break;
            GntTbl_PutRef(xpdd, xpdd->hiber_grefs[i], (ULONG)'HIBR');
        }
        xpdd->gnttbl_ss_copy = NULL;
    }

    FUNCTION_EXIT();
}
