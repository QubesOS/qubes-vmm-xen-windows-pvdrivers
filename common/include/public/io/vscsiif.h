/******************************************************************************
 * scsiif.h
 * 
 * Based on the blkif.h code.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright(c) FUJITSU Limited 2008.
 */

#ifndef __XEN__PUBLIC_IO_SCSI_H__
#define __XEN__PUBLIC_IO_SCSI_H__

#include "ring.h"
#include "../grant_table.h"

#define VSCSIIF_CMND_SCSI			1	/* scsi */
#define VSCSIIF_CMND_SCSI_RESET			2	/* scsi */

/* ----------------------------------------------------------------------
	Definition of Ring Structures
   ---------------------------------------------------------------------- */

#define VSCSIIF_DEFAULT_CAN_QUEUE	256
#define VSCSIIF_MAX_COMMAND_SIZE	16
#define VSCSIIF_SG_TABLESIZE		27

struct vscsiif_request {
	uint16_t rqid;
	uint8_t cmd;
	/* SCSI */
	uint8_t cmnd[VSCSIIF_MAX_COMMAND_SIZE];
	uint8_t cmd_len;
	uint16_t id, lun, channel;
	uint8_t sc_data_direction;
	uint8_t use_sg;
	uint32_t request_bufflen;
	/*int32_t timeout_per_command;*/
	struct scsiif_request_segment {
		grant_ref_t gref;
		uint16_t offset;
		uint16_t length;
	} seg[VSCSIIF_SG_TABLESIZE];
};

#define VSCSIIF_SENSE_BUFFERSIZE 	96

struct vscsiif_response {
	uint16_t rqid;
	int32_t  rslt;
	uint8_t sense_len;
	uint8_t sense_buffer[VSCSIIF_SENSE_BUFFERSIZE];
};

DEFINE_RING_TYPES(vscsiif, struct vscsiif_request, struct vscsiif_response);

#endif