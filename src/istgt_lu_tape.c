/*
 * Copyright (C) 2008-2012 Daisuke Aoyama <aoyama@peach.ne.jp>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <inttypes.h>
#include <stdint.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>

#ifdef HAVE_UUID_H
#include <uuid.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include "istgt.h"
#include "istgt_ver.h"
#include "istgt_log.h"
#include "istgt_conf.h"
#include "istgt_sock.h"
#include "istgt_misc.h"
#include "istgt_iscsi.h"
#include "istgt_lu.h"
#include "istgt_proto.h"
#include "istgt_scsi.h"

#if !defined(__GNUC__)
#undef __attribute__
#define __attribute__(x)
#endif

#define TAPE_DEBUG
//#define ISTGT_TRACE_TAPE

#define DENSITY_DFLT (TAPE_DENSITY_DEFAULT)
//#define MEDIATYPE_DFLT (TAPE_MEDIATYPE_DLT_III)
//#define DENSITY_DFLT (TAPE_DENSITY_DLT_III)
#define MEDIATYPE_DFLT (TAPE_MEDIATYPE_DLT_IV)
//#define DENSITY_DFLT (TAPE_DENSITY_DLT_IV)
//#define MEDIATYPE_DFLT (TAPE_MEDIATYPE_SDLT_I)
//#define DENSITY_DFLT (TAPE_DENSITY_SDLT_I)
//#define MEDIATYPE_DFLT (TAPE_MEDIATYPE_LTO4)
//#define DENSITY_DFLT (TAPE_DENSITY_LTO4)

/* Block Alignment for emulation tape */
#define TAPE_BLOCKLEN 512
#define TAPE_ALIGNMENT 8
#define COMPRESSION_DFLT 1

#define ISCSI_DLT 0
#define ISCSI_LTO 1

#define TAPE_VENDOR  "QUANTUM"
#define TAPE_PRODUCT "DLT8000"
#define TAPE_REVISION "CX01" /* servo + r/w */
#define TAPE_MODULE_REV "C001"
#if 0
#define TAPE_PRODUCT "DLT4000"
#define TAPE_REVISION "CD01"
#define TAPE_MODULE_REV "C001"
#endif

#if 0
/* Quantum DLT8000 */
#define TAPE_MAXIMUM_BLOCK_LENGTH 0x0ffffe
#define TAPE_MINIMUM_BLOCK_LENGTH 0x000000
#define TAPE_WRITE_DELAY 200 /* x 100ms */
/* for multiple of 4bytes */
#define TAPE_MAXIMUM_BLOCK_LENGTH 0xfffffc
#define TAPE_MINIMUM_BLOCK_LENGTH 0x000004
#endif
/* for multiple of 8bytes */
#define TAPE_MAXIMUM_BLOCK_LENGTH 0xfffff8
#define TAPE_MINIMUM_BLOCK_LENGTH 0x000008
//#define TAPE_WRITE_DELAY 0x000f /* x 100ms */
#define TAPE_WRITE_DELAY 200 /* x 100ms */
#define TAPE_COMP_ALGORITHM 0x10 /* IBM IDRC */

#define TAPE_MEDIATYPE_NONE      0x00
#define TAPE_MEDIATYPE_DLT_CL    0x81
#define TAPE_MEDIATYPE_DLT_III   0x83
#define TAPE_MEDIATYPE_DLT_IIIXT 0x84
#define TAPE_MEDIATYPE_DLT_IV    0x85
#define TAPE_MEDIATYPE_SDLT_I    0x86
#define TAPE_MEDIATYPE_SDLT_II   0x87
#define TAPE_MEDIATYPE_DLT_S4    0x91
#define TAPE_MEDIATYPE_LTO1      0x18
#define TAPE_MEDIATYPE_LTO2      0x28
#define TAPE_MEDIATYPE_LTO3      0x38
#define TAPE_MEDIATYPE_LTO4      0x48

#define TAPE_DENSITY_DEFAULT     0x00
#define TAPE_DENSITY_DLT_III     0x19
#define TAPE_DENSITY_DLT_IV20    0x1a
#define TAPE_DENSITY_DLT_IV35    0x1b
#define TAPE_DENSITY_DLT_IV      0x41
#define TAPE_DENSITY_SDLT_I      0x49
#define TAPE_DENSITY_SDLT_II     0x4a
#define TAPE_DENSITY_DLT_S4      0x4b
#define TAPE_DENSITY_LTO1        0x40
#define TAPE_DENSITY_LTO2        0x42
#define TAPE_DENSITY_LTO3        0x44
#define TAPE_DENSITY_LTO4        0x46

#define CTLBLOCKLEN     (128*1024)
#define CTLMAGIC        "ISVTCTRL"
#define CTLMAGICLEN     8
#define CTLVERSION      0ULL
#define CTLENDIAN       0x1122334455667788ULL
#define MARK_END        0xffffffffffffffffULL
#define MARK_EOD        0xfffffffffffffffeULL
#define LBPOS_INVALID   0xffffffffffffffffULL
#define LBPOS_MAX       0xfffffffffffffffeULL

typedef struct tape_markpos_t {
	uint64_t lbpos;				/* logical position */
	uint64_t offset;			/* physical position */
	uint64_t prev;				/* previous position if not zero */
	uint64_t junk1;
} tape_markpos_t;

/* Control Block = 128K */
#define MAX_FILEMARKS (1024)
typedef struct tape_ctlblock_t {
	/* 16k block 0-2 */
	uint8_t magic[8];			/* 'ISVTCTRL' (network order) */
	uint64_t endian;			/* endian ID = 0x1122334455667788ULL */
	uint64_t version;			/* version = 0 */
	uint64_t ctlblocklen;			/* ctlblocklen = 128K */

	uint64_t blocklen;			/* blocklen = 512 */
	uint64_t marklen;			/* marklen = 128 */
	uint64_t alignment;			/* alignment = 8 */
	uint64_t allocate;			/* allocate = 0 */

	uint64_t type;				/* media type = default */
	uint64_t id;				/* media ID = empty */
	uint64_t size;				/* media size = empty */
	uint64_t junk1;

	uint64_t reserve0[512-12];		/* room for 4K(8x512) */
	tape_markpos_t marks[MAX_FILEMARKS];	/* marks[0] = BOT, ..., EOT 32K */
	uint8_t reserve2[(16*1024) - (8*512)];

	/* 16k block 3-7 */
	uint8_t reserve3[(16*1024)];
	uint8_t reserve4[(16*1024)];
	uint8_t reserve5[(16*1024)];
	uint8_t reserve6[(16*1024)];
	uint8_t reserve7[(16*1024)];
} tape_ctlblock_t;

/* physical marker in virtual tape */
#define MARK_LENGTH     128
#define MARK_MAXLENGTH  (TAPE_BLOCKLEN)
#define MARK_MAGICLEN   8
#define MARK_VERSION    0ULL
#define MARK_ENDIAN     0x1122334455667788ULL
#define MARK_BOTMAGIC   "ISVTBOTB"
#define MARK_EOTMAGIC   "ISVTEOTB"
#define MARK_EOFMAGIC   "ISVTEOFB"
#define MARK_EODMAGIC   "ISVTEODB"
#define MARK_DATAMAGIC  "ISVTDATA"
#define MARK_COMPALGO_NONE 0

/* Mark Block = 128B */
typedef struct tape_markblock_t {
	uint8_t magic[8];			/* 'ISVT'+ 'BOTB' / 'DATA' / 'EOFB' */
	uint64_t endian;			/* endian ID = 0x1122334455667788ULL */
	uint64_t version;			/* version = 0 */
	uint64_t marklen;			/* marklen = 128 */

	uint64_t lblen;				/* logical block length */
	uint64_t lbpos;				/* logical block position */
	uint64_t offset;			/* self physical offset */
	uint64_t prev;				/* previous offset if non zero */

	uint64_t compalgo;			/* compression algorithm (0=none) */
	uint64_t vtcompalgo;			/* VT compression algorithm (0=none) */
	uint64_t vtdecomplen;			/* VT decompression length */
	uint64_t junk1;

	/* reserved */
	uint64_t reserve[16-12];		/* 128B(8x16) */
} tape_markblock_t;


typedef struct istgt_lu_tape_t {
	ISTGT_LU_Ptr lu;
	int num;
	int lun;

	int fd;
	const char *file;
	uint64_t size;
	uint64_t blocklen;
	uint64_t blockcnt;

#ifdef HAVE_UUID_H
	uuid_t uuid;
#endif /* HAVE_UUID_H */

	/* flags */
	int mflags;

	tape_ctlblock_t *ctlblock;		/* control block */
	tape_markblock_t *markblock;		/* mark block */

	uint64_t lblen;				/* logical block length for fixed */
	uint64_t lbpos;				/* logical block position */

	uint64_t offset;			/* physical offset in virtual tape */
	uint64_t prev;				/* previous offset if not zero */
	int index;				/* current maker index */

	int compalgo;				/* compression algorithme */
	int vtcompalgo;				/* compression algorithme in vtape */

	/* pending flags */
	int need_savectl;
	int need_writeeod;

	/* media state */
	volatile int mload;
	volatile int mchanged;
	volatile int mwait;

	/* mode flags */
	volatile int lock;
	int compression;
	int bot;
	int eof;
	int eod;
	int eom;

	/* SCSI sense code */
	volatile int sense;

	/* command information */
	uint32_t info;
} ISTGT_LU_TAPE;

#define BUILD_SENSE(SK,ASC,ASCQ)					\
	do {								\
		*sense_len =						\
			istgt_lu_tape_build_sense_data(spec, sense_data, \
			    ISTGT_SCSI_SENSE_ ## SK,			\
			    (ASC), (ASCQ));				\
	} while (0)

static int istgt_lu_tape_save_ctlblock(ISTGT_LU_TAPE *spec);
static int istgt_lu_tape_allocate(ISTGT_LU_TAPE *spec);
static int istgt_lu_tape_build_sense_data(ISTGT_LU_TAPE *spec, uint8_t *data, int sk, int asc, int ascq);

static int
istgt_lu_tape_open(ISTGT_LU_TAPE *spec, int flags, int mode)
{
	int rc;

	rc = open(spec->file, flags, mode);
	if (rc < 0) {
		return -1;
	}
	spec->fd = rc;
	return 0;
}

static int
istgt_lu_tape_close(ISTGT_LU_TAPE *spec)
{
	int rc;

	if (spec->fd == -1)
		return 0;
	rc = close(spec->fd);
	if (rc < 0) {
		return -1;
	}
	spec->fd = -1;
	return 0;
}

static int64_t
istgt_lu_tape_seek(ISTGT_LU_TAPE *spec, uint64_t offset)
{
	off_t rc;

	rc = lseek(spec->fd, (off_t) offset, SEEK_SET);
	if (rc < 0) {
		return -1;
	}
	return 0;
}

static int64_t
istgt_lu_tape_read(ISTGT_LU_TAPE *spec, void *buf, uint64_t nbytes)
{
	int64_t rc;

	rc = (int64_t) read(spec->fd, buf, (size_t) nbytes);
	if (rc < 0) {
		return -1;
	}
	return rc;
}

static int64_t
istgt_lu_tape_write(ISTGT_LU_TAPE *spec, const void *buf, uint64_t nbytes)
{
	int64_t rc;

	rc = (int64_t) write(spec->fd, buf, (size_t) nbytes);
	if (rc < 0) {
		return -1;
	}
	return rc;
}

static int64_t
istgt_lu_tape_sync(ISTGT_LU_TAPE *spec, uint64_t offset __attribute__((__unused__)), uint64_t nbytes __attribute__((__unused__)))
{
	int64_t rc;

	rc = (int64_t) fsync(spec->fd);
	if (rc < 0) {
		return -1;
	}
	return rc;
}

#if 0
static uint64_t
swap_uint64(uint64_t val)
{
	uint64_t r;
	int i;

	r = 0;
	for (i = 0; i < sizeof(uint64_t); i++) {
		r |= val & 0xffULL;
		r <<= 8;
		val >>= 8;
	}
	return r;
}
#endif

#define SWAP_UINT64(D)						\
	(     (((D) >> (56 - 0 )) & 0x00000000000000ffULL)	\
	    | (((D) << (56 - 0 )) & 0xff00000000000000ULL)	\
	    | (((D) >> (48 - 8 )) & 0x000000000000ff00ULL)	\
	    | (((D) << (48 - 8 )) & 0x00ff000000000000ULL)	\
	    | (((D) >> (40 - 16)) & 0x0000000000ff0000ULL)	\
	    | (((D) << (40 - 16)) & 0x0000ff0000000000ULL)	\
	    | (((D) >> (32 - 24)) & 0x00000000ff000000ULL)	\
	    | (((D) << (32 - 24)) & 0x000000ff00000000ULL))

#define ASSERT_PTR_ALIGN(P,A)						\
	do {								\
		assert((((uintptr_t)(P)) & ((uintptr_t)(A) - 1ULL)) == 0); \
	} while (0)
#define ASSERT_PTR_ALIGN32(P) ASSERT_PTR_ALIGN(P,4)
#define ASSERT_PTR_ALIGN64(P) ASSERT_PTR_ALIGN(P,8)


static int
istgt_lu_tape_read_native_mark(ISTGT_LU_TAPE *spec, tape_markblock_t *mbp)
{
	uint64_t marklen;
	uint64_t *lp;
	int64_t rc;
	int i;

	marklen = spec->ctlblock->marklen;

	rc = istgt_lu_tape_read(spec, mbp, marklen);
	if (rc < 0 || (uint64_t) rc != marklen) {
		ISTGT_ERRLOG("lu_tape_read() failed: rc %"PRId64"\n", rc);
		return -1;
	}
	if (mbp->endian != MARK_ENDIAN) {
		/* convert byte order but except magic */
		lp = (uint64_t *) mbp;
		for (i = 1; i < (int) (marklen / sizeof(uint64_t)); i++) {
			lp[i] = SWAP_UINT64(lp[i]);
		}
	}
	return 0;
}

static int
istgt_lu_tape_write_native_mark(ISTGT_LU_TAPE *spec, tape_markblock_t *mbp)
{
	uint64_t marklen;
	int64_t rc;

	marklen = spec->ctlblock->marklen;

	rc = istgt_lu_tape_write(spec, mbp, marklen);
	if ((uint64_t) rc != marklen) {
		ISTGT_ERRLOG("lu_tape_write() failed at offset %" PRIu64 ", size %" PRIu64 "\n", spec->offset, spec->size);
		return -1;
	}
	return 0;
}

static int
istgt_lu_tape_write_padding(ISTGT_LU_TAPE *spec, uint8_t *data)
{
	uint64_t tape_leader;
	uint64_t offset;
	uint64_t alignment, padlen;
	int64_t rc;

	tape_leader = spec->ctlblock->ctlblocklen;
	offset = spec->offset;
	alignment = spec->ctlblock->alignment;

	if (offset % alignment) {
		padlen = alignment;
		padlen -= offset % alignment;
		memset(data, 0, alignment);
		if (istgt_lu_tape_seek(spec, (tape_leader + offset)) == -1) {
			ISTGT_ERRLOG("lu_tape_seek() failed\n");
			return -1;
		}
		rc = istgt_lu_tape_write(spec, data, padlen);
		if (rc < 0 || (uint64_t) rc != padlen) {
			ISTGT_ERRLOG("lu_tape_write() failed\n");
			return -1;
		}
		offset += padlen;
		spec->offset = offset;
	}
	return 0;
}

static int
istgt_lu_tape_write_eof(ISTGT_LU_TAPE *spec, int count, uint8_t *data)
{
	tape_markblock_t *mbp;
	uint64_t tape_leader;
	uint64_t lbpos, offset, prev, version, marklen;
	int index_i;
	int i;

	if (count <= 0) {
		// flush buffer
		return 0;
	}

	if (istgt_lu_tape_write_padding(spec, data) < 0) {
		ISTGT_ERRLOG("lu_tape_write_padding() failed\n");
		return -1;
	}

	tape_leader = spec->ctlblock->ctlblocklen;
	lbpos = spec->lbpos;
	offset = spec->offset;
	prev = spec->prev;
	index_i = spec->index;
	version = spec->ctlblock->version;
	marklen = spec->ctlblock->marklen;

	/* prepare mark */
	ASSERT_PTR_ALIGN64(data);
	mbp = (tape_markblock_t *) ((uintptr_t)data);
	memset(mbp, 0, marklen);
	memcpy(mbp->magic, MARK_EOFMAGIC, MARK_MAGICLEN);
	mbp->endian = MARK_ENDIAN;
	mbp->version = MARK_VERSION;
	mbp->marklen = marklen;
	mbp->lblen = 0ULL;
	mbp->compalgo = 0ULL;
	mbp->vtcompalgo = 0ULL;
	mbp->vtdecomplen = 0ULL;

	/* seek to current physical position */
	if (istgt_lu_tape_seek(spec, (tape_leader + offset)) == -1) {
		ISTGT_ERRLOG("lu_tape_seek() failed\n");
		return -1;
	}

	/* write EOF N blocks */
	for (i = 0; i < count; i++) {
		mbp->lbpos = lbpos;
		mbp->offset = offset;
		mbp->prev = prev;
		index_i++;
		spec->ctlblock->marks[index_i].lbpos = lbpos;
		spec->ctlblock->marks[index_i].offset = offset;
		spec->ctlblock->marks[index_i].prev = prev;
		spec->ctlblock->marks[index_i + 1].lbpos = MARK_END;
		spec->ctlblock->marks[index_i + 1].offset = MARK_END;
		spec->ctlblock->marks[index_i + 1].prev = offset + marklen;
		spec->index = index_i;
		spec->offset = offset;
		if (istgt_lu_tape_write_native_mark(spec, mbp) < 0) {
			ISTGT_ERRLOG("istgt_lu_tape_write_native_mark() failed\n");
			spec->prev = 0ULL;
			return -1;
		}
		lbpos++;
		prev = offset;
		offset += marklen;
		/* update information */
		spec->lbpos = lbpos;
		spec->prev = prev;
		spec->offset = offset;
		spec->eof = 1;
	}
	return 0;
}

static int
istgt_lu_tape_write_bot(ISTGT_LU_TAPE *spec, uint8_t *data)
{
	tape_markblock_t *mbp;
	uint64_t tape_leader;
	uint64_t lbpos, offset, prev, version, marklen;
	int index_i;

	tape_leader = spec->ctlblock->ctlblocklen;
	lbpos = 0ULL;
	offset = 0ULL;
	prev = 0ULL;
	index_i = 0ULL;
	version = spec->ctlblock->version;
	marklen = spec->ctlblock->marklen;

	/* prepare mark */
	ASSERT_PTR_ALIGN64(data);
	mbp = (tape_markblock_t *) ((uintptr_t)data);
	memset(mbp, 0, marklen);
	memcpy(mbp->magic, MARK_BOTMAGIC, MARK_MAGICLEN);
	mbp->endian = MARK_ENDIAN;
	mbp->version = MARK_VERSION;
	mbp->marklen = marklen;
	mbp->lblen = 0ULL;
	mbp->compalgo = 0ULL;
	mbp->vtcompalgo = 0ULL;
	mbp->vtdecomplen = 0ULL;

	/* seek to current physical position */
	if (istgt_lu_tape_seek(spec, (tape_leader + offset)) == -1) {
		ISTGT_ERRLOG("lu_tape_seek() failed\n");
		return -1;
	}

	/* write BOT block */
	mbp->lbpos = lbpos;
	mbp->offset = offset;
	mbp->prev = prev;
	index_i++;
	spec->ctlblock->marks[index_i].lbpos = lbpos;
	spec->ctlblock->marks[index_i].offset = offset;
	spec->ctlblock->marks[index_i].prev = prev;
	spec->ctlblock->marks[index_i + 1].lbpos = MARK_END;
	spec->ctlblock->marks[index_i + 1].offset = MARK_END;
	spec->ctlblock->marks[index_i + 1].prev = offset + marklen;
	spec->index = index_i;
	spec->offset = offset;
	if (istgt_lu_tape_write_native_mark(spec, mbp) < 0) {
		ISTGT_ERRLOG("lu_tape_write_native_mark() failed\n");
		spec->prev = 0ULL;
		return -1;
	}
	lbpos++;
	prev = offset;
	offset += marklen;
	/* update information */
	spec->lbpos = lbpos;
	spec->prev = prev;
	spec->offset = offset;
	return 0;
}

static int
istgt_lu_tape_write_eod(ISTGT_LU_TAPE *spec, uint8_t *data)
{
	tape_markblock_t *mbp;
	uint64_t tape_leader;
	uint64_t lbpos, offset, prev, version, marklen;
	int index_i;

	tape_leader = spec->ctlblock->ctlblocklen;
	lbpos = spec->lbpos;
	offset = spec->offset;
	prev = spec->prev;
	index_i = spec->index;
	version = spec->ctlblock->version;
	marklen = spec->ctlblock->marklen;

	/* prepare mark */
	ASSERT_PTR_ALIGN64(data);
	mbp = (tape_markblock_t *) ((uintptr_t)data);
	memset(mbp, 0, marklen);
	memcpy(mbp->magic, MARK_EODMAGIC, MARK_MAGICLEN);
	mbp->endian = MARK_ENDIAN;
	mbp->version = MARK_VERSION;
	mbp->marklen = marklen;
	mbp->lblen = 0ULL;
	mbp->compalgo = 0ULL;
	mbp->vtcompalgo = 0ULL;
	mbp->vtdecomplen = 0ULL;

	/* seek to current physical position */
	if (istgt_lu_tape_seek(spec, (tape_leader + offset)) == -1) {
		ISTGT_ERRLOG("lu_tape_seek() failed\n");
		return -1;
	}

	/* write EOD block */
	mbp->lbpos = lbpos;
	mbp->offset = offset;
	mbp->prev = prev;
	if (istgt_lu_tape_write_native_mark(spec, mbp) < 0) {
		ISTGT_ERRLOG("lu_tape_write_native_mark() failed\n");
		return -1;
	}
	/* no update information */
	return 0;
}

static int
istgt_lu_tape_write_media_check(ISTGT_LU_TAPE *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd, uint64_t request_len)
{
	uint64_t tape_leader;
	uint64_t extendsize;
	uint64_t mediasize;
	uint64_t offset;
	int data_len;

	tape_leader = spec->ctlblock->ctlblocklen;
	mediasize = spec->size;
	offset = spec->offset;

	/* writable media? */
	if (spec->lu->readonly
	    || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
		/* WRITE PROTECTED */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_DATA_PROTECT,
			    0x27, 0x00);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	/* always keep control block */
	if (mediasize < tape_leader) {
		/* INTERNAL TARGET FAILURE */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_HARDWARE_ERROR,
			    0x44, 0x00);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}
	mediasize -= tape_leader;

	/* request can store? */
	if (request_len > mediasize || offset > mediasize - request_len) {
		/* determine extend size */
		extendsize = request_len / ISTGT_LU_MEDIA_EXTEND_UNIT;
		extendsize *= ISTGT_LU_MEDIA_EXTEND_UNIT;
		if (request_len % ISTGT_LU_MEDIA_EXTEND_UNIT) {
			extendsize += ISTGT_LU_MEDIA_EXTEND_UNIT;
		}
		/* can handle? */
		if (mediasize < MARK_END - 1 - tape_leader - extendsize) {
			if (spec->mflags & ISTGT_LU_FLAG_MEDIA_DYNAMIC) {
				/* OK dynamic allocation */
				mediasize += extendsize;
			} else if (spec->mflags & ISTGT_LU_FLAG_MEDIA_EXTEND) {
				/* OK extend media size */
				mediasize += extendsize;
			} else {
				/* no space virtual EOM */
				goto eom_error;
			}
		} else {
		eom_error:
			/* physical EOM */
			spec->eom = 1;
			/* END-OF-PARTITION/MEDIUM DETECTED */
			/* VOLUME OVERFLOW */
			data_len
				= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
				    ISTGT_SCSI_SENSE_VOLUME_OVERFLOW,
				    0x00, 0x02);
			lu_cmd->sense_data_len = data_len;
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
	}

	/* update information */
	spec->size = tape_leader + mediasize;

	/* complete check, ready to write */
	return 0;
}

static int
istgt_lu_tape_read_media_check(ISTGT_LU_TAPE *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd, uint64_t request_len)
{
	uint64_t tape_leader;
	uint64_t mediasize;
	uint64_t offset;
	int data_len;

	tape_leader = spec->ctlblock->ctlblocklen;
	mediasize = spec->size;
	offset = spec->offset;

	/* always keep control block */
	if (mediasize < tape_leader) {
		/* INTERNAL TARGET FAILURE */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_HARDWARE_ERROR,
			    0x44, 0x00);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}
	mediasize -= tape_leader;

	/* request can seek? */
	if (request_len > mediasize || offset > mediasize - request_len) {
		/* physical EOM */
		spec->eom = 1;
		/* END-OF-PARTITION/MEDIUM DETECTED */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_MEDIUM_ERROR,
			    0x00, 0x02);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	/* complete check, ready to read */
	return 0;
}

static int
istgt_lu_tape_prepare_offset(ISTGT_LU_TAPE *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd __attribute__((__unused__)))
{
	uint64_t lbpos, offset, prev, marklen;
	int index_i;

	lbpos = spec->lbpos;
	offset = spec->offset;
	prev = spec->prev;
	index_i = spec->index;
	marklen = spec->ctlblock->marklen;

	/* position to logical block zero */
	if (spec->bot) {
		spec->bot = 0;
		spec->eof = spec->eod = spec->eom = 0;
		offset = 0;
		prev = offset;
		offset += marklen;
		lbpos++;
	}

	if (spec->eom || offset == MARK_END) {
		spec->eom = 1;
		spec->bot = spec->eof = spec->eod = 0;
	}

	/* update information */
	spec->index = index_i;
	spec->lbpos = lbpos;
	spec->prev = prev;
	spec->offset = offset;
	return 0;
}

static int
istgt_lu_tape_write_pending_data(ISTGT_LU_TAPE *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	uint64_t marklen;
	int data_len;

	if (spec->need_savectl) {
		if (istgt_lu_tape_save_ctlblock(spec) < 0) {
			ISTGT_ERRLOG("lu_tape_save_ctlblock() failed\n");
		io_failure:
			/* INTERNAL TARGET FAILURE */
			data_len
				= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
				    ISTGT_SCSI_SENSE_HARDWARE_ERROR,
				    0x44, 0x00);
			lu_cmd->sense_data_len = data_len;
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return 0;
		}
		spec->need_savectl = 0;
	}
	if (spec->need_writeeod) {
		marklen = spec->ctlblock->marklen;
		if (istgt_lu_tape_write_media_check(spec, conn, lu_cmd, marklen) < 0) {
			goto io_failure;
		}
		if (istgt_lu_tape_write_eod(spec, lu_cmd->data) < 0) {
			ISTGT_ERRLOG("lu_tape_write_eod() failed\n");
			goto io_failure;
		}
		spec->need_writeeod = 0;
	}
	return 0;
}

static int
istgt_lu_tape_rewind(ISTGT_LU_TAPE *spec)
{
	uint64_t lbpos, offset, prev;
	int index_i;

	/* position to BOT */
	spec->bot = 1;
	spec->eof = spec->eod = spec->eom = 0;
	index_i = 0;
	lbpos = spec->ctlblock->marks[index_i].lbpos;
	offset = spec->ctlblock->marks[index_i].offset;
	prev = spec->ctlblock->marks[index_i].prev;

	/* update information */
	spec->index = index_i;
	spec->lbpos = lbpos;
	spec->prev = prev;
	spec->offset = offset;
	return 0;
}

static int
istgt_lu_tape_load_ctlblock(ISTGT_LU_TAPE *spec)
{
	int64_t rc;

	if (istgt_lu_tape_seek(spec, 0) == -1) {
		return -1;
	}
	rc = istgt_lu_tape_read(spec, spec->ctlblock, CTLBLOCKLEN);
	if (rc < 0 || rc != CTLBLOCKLEN) {
		return -1;
	}
	return rc;
}

static int
istgt_lu_tape_save_ctlblock(ISTGT_LU_TAPE *spec)
{
	int64_t rc;

	if (istgt_lu_tape_seek(spec, 0) == -1) {
		return -1;
	}
	rc = istgt_lu_tape_write(spec, spec->ctlblock,
	    spec->ctlblock->ctlblocklen);
	if (rc < 0 || (uint64_t) rc != spec->ctlblock->ctlblocklen) {
		return -1;
	}
	return rc;
}

static int
istgt_lu_tape_init_ctlblock(ISTGT_LU_TAPE *spec, int newfile)
{
	tape_ctlblock_t *cbp;
	uint64_t *lp;
	int rc;
	int i;

	cbp = spec->ctlblock;

	rc = istgt_lu_tape_load_ctlblock(spec);
	if (rc < 0) {
		return -1;
	}
	if (memcmp(cbp->magic, CTLMAGIC, CTLMAGICLEN) != 0) {
		if (spec->lu->readonly
		    || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)
		    || !newfile) {
			ISTGT_ERRLOG("Can not initialize \"%s\"\n", spec->file);
			return -1;
		}
		/* initialize control block */
		memset(cbp, 0, CTLBLOCKLEN);
		memcpy(cbp->magic, CTLMAGIC, CTLMAGICLEN);
		cbp->marks[0].offset = 0ULL;
		cbp->marks[0].lbpos = 0ULL;
		cbp->marks[0].prev = 0ULL;
		cbp->marks[1].offset = MARK_END;
		cbp->marks[1].lbpos = MARK_END;
		cbp->marks[1].prev = 0ULL;
		cbp->endian = CTLENDIAN;
		cbp->version = CTLVERSION;
		cbp->ctlblocklen = (uint64_t) CTLBLOCKLEN;
		cbp->blocklen = (uint64_t) TAPE_BLOCKLEN;
		cbp->marklen = (uint64_t) MARK_LENGTH;
		cbp->alignment = (uint64_t) TAPE_ALIGNMENT;
		cbp->allocate = 0ULL;
		cbp->type = 0ULL;
		cbp->id = 0ULL;
		cbp->size = 0ULL;
		rc = istgt_lu_tape_save_ctlblock(spec);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_tape_save_ctlblock() failed\n");
			return -1;
		}
		rc = istgt_lu_tape_write_bot(spec, (uint8_t *) spec->markblock);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_tape_write_bot() failed\n");
			return -1;
		}
		rc = istgt_lu_tape_write_eod(spec, (uint8_t *) spec->markblock);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_tape_write_eod() failed\n");
			return -1;
		}
	} else {
		if (cbp->endian != CTLENDIAN) {
			/* convert byte order but except magic */
			lp = (uint64_t *) cbp;
			for (i = 1; i < (int) (CTLBLOCKLEN / sizeof(uint64_t)); i++) {
				lp[i] = SWAP_UINT64(lp[i]);
			}
		}
		if (cbp->ctlblocklen == 0ULL
		    || cbp->blocklen == 0ULL
		    || cbp->marklen == 0ULL
		    || cbp->alignment == 0ULL) {
			ISTGT_ERRLOG("bad length\n");
			return -1;
		}
		if (cbp->version > CTLVERSION) {
			ISTGT_ERRLOG("unsupported tape version 0x%"PRIx64"\n",
			    cbp->version);
			return -1;
		}
		if (cbp->marklen > MARK_MAXLENGTH) {
			ISTGT_ERRLOG("marklen is too long\n");
			return -1;
		}
	}
	return 0;
}

int
istgt_lu_tape_media_present(ISTGT_LU_TAPE *spec)
{
	if (spec->mload) {
		return 1;
	}
	return 0;
}

int
istgt_lu_tape_media_lock(ISTGT_LU_TAPE *spec)
{
	if (spec->lock) {
		return 1;
	}
	return 0;
}

int
istgt_lu_tape_load_media(ISTGT_LU_TAPE *spec)
{
	ISTGT_LU_Ptr lu;
	int flags;
	int newfile;
	int rc;

	if (istgt_lu_tape_media_present(spec)) {
		/* media present */
		return -1;
	}
	if (spec->mchanged) {
		/* changed soon */
		return -1;
	}

	lu = spec->lu;
	if (lu->lun[spec->lun].type != ISTGT_LU_LUN_TYPE_REMOVABLE) {
		ISTGT_ERRLOG("LU%d: not removable\n", lu->num);
		return -1;
	}
	if (strcasecmp(lu->lun[spec->lun].u.removable.file,
		"/dev/null") == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: empty\n", lu->num);
		spec->file = NULL;
		spec->size = 0;
		spec->mflags = 0;
		spec->blocklen = TAPE_BLOCKLEN;
		spec->blockcnt = spec->size / spec->blocklen;
		spec->compalgo = TAPE_COMP_ALGORITHM;
		spec->vtcompalgo = MARK_COMPALGO_NONE;
		spec->compression = COMPRESSION_DFLT;
		spec->lblen = 0ULL;   /* default to variable length */
		spec->index = 0;      /* position to BOT */
		spec->lbpos = 0ULL;
		spec->offset = 0ULL;
		spec->prev = 0ULL;
		spec->bot = 0;
		spec->eof = spec->eod = spec->eom = 0;
		spec->prev = spec->offset;
		spec->need_savectl = 0;
		spec->need_writeeod = 0;
		return 0;
	}
	spec->file = lu->lun[spec->lun].u.removable.file;
	spec->size = lu->lun[spec->lun].u.removable.size;
	spec->mflags = lu->lun[spec->lun].u.removable.flags;
	spec->blocklen = TAPE_BLOCKLEN;
	spec->blockcnt = spec->size / spec->blocklen;
	spec->compalgo = TAPE_COMP_ALGORITHM;
	spec->vtcompalgo = MARK_COMPALGO_NONE;
	spec->compression = COMPRESSION_DFLT;
	spec->lblen = 0ULL;   /* default to variable length */
	spec->index = 0;      /* position to BOT */
	spec->lbpos = 0ULL;
	spec->offset = 0ULL;
	spec->prev = 0ULL;
	spec->bot = 1;
	spec->eof = spec->eod = spec->eom = 0;
	spec->prev = spec->offset;
	spec->need_savectl = 0;
	spec->need_writeeod = 0;

	spec->mload = 0;
	spec->mchanged = 1;
	spec->mwait = 3;

	if (access(spec->file, W_OK) != 0) {
		if (errno != ENOENT) {
			spec->mflags |= ISTGT_LU_FLAG_MEDIA_READONLY;
		}
	} else {
		struct stat st;
		rc = stat(spec->file, &st);
		if (rc != 0 || !S_ISREG(st.st_mode)) {
			spec->mflags |= ISTGT_LU_FLAG_MEDIA_READONLY;
		} else {
			if ((st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0) {
				spec->mflags |= ISTGT_LU_FLAG_MEDIA_READONLY;
			}
		}
	}
	if (spec->lu->readonly
	    || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
		flags = O_RDONLY;
	} else {
		flags = O_RDWR;
	}
	newfile = 0;
	rc = istgt_lu_tape_open(spec, flags, 0666);
	if (rc < 0) {
		/* new file? */
		newfile = 1;
		if (spec->lu->readonly
		    || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
			flags = O_RDONLY;
		} else {
			flags = (O_CREAT | O_EXCL | O_RDWR);
		}
		rc = istgt_lu_tape_open(spec, flags, 0666);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: LUN%d: open error(errno=%d)\n",
			    lu->num, spec->lun, errno);
			return -1;
		}
		if (lu->lun[spec->lun].u.removable.size < ISTGT_LU_MEDIA_SIZE_MIN) {
			lu->lun[spec->lun].u.removable.size = ISTGT_LU_MEDIA_SIZE_MIN;
		}
	}

	if (spec->lu->readonly
	    || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
		/* readonly */
	} else {
		if (newfile == 0) {
			/* existing file check */
			if (istgt_lu_tape_init_ctlblock(spec, newfile) < 0) {
				ISTGT_ERRLOG("lu_tape_init_ctlblock() failed\n");
				return -1;
			}
		}
		rc = istgt_lu_tape_allocate(spec);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: LUN%d: allocate error\n", lu->num, spec->lun);
			return -1;
		}
	}
	/* initialize filemarks */
	if (istgt_lu_tape_init_ctlblock(spec, newfile) < 0) {
		ISTGT_ERRLOG("lu_tape_init_ctlblock() failed\n");
		return -1;
	}
	istgt_lu_tape_rewind(spec);
	return 0;
}

int
istgt_lu_tape_unload_media(ISTGT_LU_TAPE *spec)
{
	int rc;

	if (!istgt_lu_tape_media_present(spec)
	    && !spec->mchanged) {
		/* media absent */
		return 0;
	}
	if (istgt_lu_tape_media_lock(spec)) {
		return -1;
	}

	if (spec->need_savectl) {
		if (istgt_lu_tape_save_ctlblock(spec) < 0) {
			ISTGT_ERRLOG("lu_tape_save_ctlblock() failed\n");
			return -1;
		}
		spec->need_savectl = 0;
	}
	if (spec->need_writeeod) {
		if (istgt_lu_tape_write_eod(spec, (uint8_t *) spec->markblock) < 0) {
			ISTGT_ERRLOG("write_eod() failed\n");
			return -1;
		}
		spec->need_writeeod = 0;
	}

	if (!spec->lu->readonly
	    && !(spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
		rc = istgt_lu_tape_sync(spec, 0, spec->size);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_tape_sync() failed\n");
			return -1;
		}
	}
	rc = (int64_t) istgt_lu_tape_close(spec);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_tape_close() failed\n");
		return -1;
	}

	spec->file = NULL;
	spec->size = 0;
	spec->mflags = 0;
	spec->blocklen = TAPE_BLOCKLEN;
	spec->blockcnt = spec->size / spec->blocklen;
	spec->compalgo = TAPE_COMP_ALGORITHM;
	spec->vtcompalgo = MARK_COMPALGO_NONE;
	spec->compression = COMPRESSION_DFLT;
	spec->lblen = 0ULL;   /* default to variable length */
	spec->index = 0;      /* position to BOT */
	spec->lbpos = 0ULL;
	spec->offset = 0ULL;
	spec->prev = 0ULL;
	spec->bot = 0;
	spec->eof = spec->eod = spec->eom = 0;
	spec->prev = spec->offset;
	spec->need_savectl = 0;
	spec->need_writeeod = 0;

	spec->mload = 0;
	spec->mchanged = 0;
	spec->mwait = 3;

	return 0;
}

int
istgt_lu_tape_change_media(ISTGT_LU_TAPE *spec, char *type, char *flags, char *file, char *size)
{
	ISTGT_LU_Ptr lu;
	char *mfile;
	uint64_t msize;
	int mflags;
	int rc;

	if (istgt_lu_tape_media_lock(spec)) {
		return -1;
	}

	lu = spec->lu;
	if (lu->lun[spec->lun].type != ISTGT_LU_LUN_TYPE_REMOVABLE) {
		ISTGT_ERRLOG("LU%d: not removable\n", lu->num);
		return -1;
	}

	if (strcmp(type, "-") == 0) {
		/* use VT image */
		;
	} else {
		ISTGT_ERRLOG("unsupported media type\n");
		return -1;
	}

	mfile = xstrdup(file);
	mflags = istgt_lu_parse_media_flags(flags);
	msize = istgt_lu_parse_media_size(file, size, &mflags);

	rc = istgt_lu_tape_unload_media(spec);
	if (rc < 0) {
		return -1;
	}

	/* replace */
	xfree(lu->lun[spec->lun].u.removable.file);
	lu->lun[spec->lun].u.removable.file = mfile;
	lu->lun[spec->lun].u.removable.size = msize;
	lu->lun[spec->lun].u.removable.flags = mflags;

	/* reload */
	rc = istgt_lu_tape_load_media(spec);
	if (rc < 0) {
		(void) istgt_lu_tape_unload_media(spec);
	}
	if (spec->file == NULL) {
		(void) istgt_lu_tape_unload_media(spec);
	}
	spec->mwait = 5;
	return rc;
}

static int
istgt_lu_tape_allocate(ISTGT_LU_TAPE *spec)
{
	uint8_t *data;
	uint64_t fsize;
	uint64_t size;
	uint64_t blocklen;
	uint64_t offset;
	uint64_t nbytes;
	int64_t rc;

	size = spec->size;
	blocklen = spec->blocklen;
	nbytes = blocklen;
	data = xmalloc(nbytes);
	memset(data, 0, nbytes);

	fsize = istgt_lu_get_filesize(spec->file);
	if (fsize > size) {
		xfree(data);
		return 0;
	}

	offset = size - nbytes;
	rc = istgt_lu_tape_seek(spec, offset);
	if (rc == -1) {
		ISTGT_ERRLOG("lu_tape_seek() failed\n");
		xfree(data);
		return -1;
	}
	rc = istgt_lu_tape_read(spec, data, nbytes);
	/* EOF is OK */
	if (rc == -1) {
		ISTGT_ERRLOG("lu_tape_read() failed\n");
		xfree(data);
		return -1;
	}
	rc = istgt_lu_tape_seek(spec, offset);
	if (rc == -1) {
		ISTGT_ERRLOG("lu_tape_seek() failed\n");
		xfree(data);
		return -1;
	}
	rc = istgt_lu_tape_write(spec, data, nbytes);
	if (rc == -1 || (uint64_t) rc != nbytes) {
		ISTGT_ERRLOG("lu_tape_write() failed\n");
		xfree(data);
		return -1;
	}

	xfree(data);
	return 0;
}

int
istgt_lu_tape_init(ISTGT_Ptr istgt __attribute__((__unused__)), ISTGT_LU_Ptr lu)
{
	ISTGT_LU_TAPE *spec;
	uint64_t gb_size;
	uint64_t mb_size;
#ifdef HAVE_UUID_H
	uint32_t status;
#endif /* HAVE_UUID_H */
	int mb_digit;
	int ro;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_tape_init\n");

	if (sizeof(tape_ctlblock_t) != CTLBLOCKLEN) {
		ISTGT_ERRLOG("Invalid ctlblock len %" PRIu64 ".\n",
		    (uint64_t) sizeof(tape_ctlblock_t));
		return -1;
	}

	printf("LU%d TAPE UNIT\n", lu->num);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d TargetName=%s\n",
	    lu->num, lu->name);
	for (i = 0; i < lu->maxlun; i++) {
		if (lu->lun[i].type == ISTGT_LU_LUN_TYPE_NONE) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d none\n",
			    lu->num, i);
			lu->lun[i].spec = NULL;
			continue;
		}
		if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_REMOVABLE) {
			ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
			return -1;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d removable\n",
		    lu->num, i);

		spec = xmalloc(sizeof *spec);
		memset(spec, 0, sizeof *spec);
		spec->lu = lu;
		spec->num = lu->num;
		spec->lun = i;
		spec->fd = -1;

#ifdef HAVE_UUID_H
		uuid_create(&spec->uuid, &status);
		if (status != uuid_s_ok) {
			ISTGT_ERRLOG("LU%d: LUN%d: uuid_create() failed\n", lu->num, i);
			xfree(spec);
			return -1;
		}
#endif /* HAVE_UUID_H */

		spec->ctlblock = xmalloc(CTLBLOCKLEN);
		spec->markblock = xmalloc(MARK_MAXLENGTH);

		spec->mload = 0;
		spec->mchanged = 0;
		spec->mwait = 0;
		rc = istgt_lu_tape_load_media(spec);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_tape_load_media() failed\n");
			xfree(spec->markblock);
			xfree(spec->ctlblock);
			xfree(spec);
			return -1;
		}

		if (spec->file != NULL) {
			/* initial state */
			spec->mload = 1;
			spec->mchanged = 0;
			spec->mwait = 0;

			if (spec->lu->readonly
			    || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
				ro = 1;
			} else {
				ro = 0;
			}

			printf("LU%d: LUN%d file=%s, size=%"PRIu64", flag=%s\n",
			    lu->num, i, spec->file, spec->size, ro ? "ro" : "rw");
			printf("LU%d: LUN%d %"PRIu64" blocks, %"PRIu64" bytes/block\n",
			    lu->num, i, spec->blockcnt, spec->blocklen);

			gb_size = spec->size / ISTGT_LU_1GB;
			mb_size = (spec->size % ISTGT_LU_1GB) / ISTGT_LU_1MB;
			if (gb_size > 0) {
				mb_digit = (int) (((mb_size * 100) / 1024) / 10);
				printf("LU%d: LUN%d %"PRIu64".%dGB %sstorage for %s\n",
				    lu->num, i, gb_size, mb_digit,
				    lu->readonly ? "readonly " : "", lu->name);
			} else {
				printf("LU%d: LUN%d %"PRIu64"MB %sstorage for %s\n",
				    lu->num, i, mb_size,
				    lu->readonly ? "readonly " : "", lu->name);
			}
		} else {
			/* initial state */
			spec->mload = 0;
			spec->mchanged = 0;
			spec->mwait = 0;

			printf("LU%d: LUN%d empty slot\n",
			    lu->num, i);
		}

		lu->lun[i].spec = spec;
	}

	return 0;
}

int
istgt_lu_tape_shutdown(ISTGT_Ptr istgt __attribute__((__unused__)), ISTGT_LU_Ptr lu)
{
	ISTGT_LU_CMD lu_cmd;
	ISTGT_LU_TAPE *spec;
	uint8_t *data;
	int alloc_len;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_tape_shutdown\n");

	alloc_len = 65536;
	data = xmalloc(alloc_len);
	memset(&lu_cmd, 0, sizeof lu_cmd);
	lu_cmd.iobuf = data;
	lu_cmd.iobufsize = alloc_len;
	lu_cmd.data = data;
	lu_cmd.data_len = 0;
	lu_cmd.alloc_len = alloc_len;
	lu_cmd.sense_data = data;
	lu_cmd.sense_alloc_len = alloc_len;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d TargetName=%s\n",
	    lu->num, lu->name);
	for (i = 0; i < lu->maxlun; i++) {
		if (lu->lun[i].type == ISTGT_LU_LUN_TYPE_NONE) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d none\n",
			    lu->num, i);
			continue;
		}
		if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_REMOVABLE) {
			ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
			xfree(data);
			return -1;
		}
		spec = (ISTGT_LU_TAPE *) lu->lun[i].spec;

		/* flush pending data */
		rc = istgt_lu_tape_write_pending_data(spec, NULL, &lu_cmd);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_tape_write_pending_data() failed\n");
			/* ignore error for other cleanup */
		}

		if (!spec->lu->readonly
		    && !(spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
			rc = istgt_lu_tape_sync(spec, 0, spec->size);
			if (rc < 0) {
				//ISTGT_ERRLOG("LU%d: lu_tape_sync() failed\n", lu->num);
				/* ignore error */
			}
		}
		rc = istgt_lu_tape_close(spec);
		if (rc < 0) {
			//ISTGT_ERRLOG("LU%d: lu_tape_close() failed\n", lu->num);
			/* ignore error */
		}
		xfree(spec->ctlblock);
		xfree(spec->markblock);
		xfree(spec);
		lu->lun[i].spec = NULL;
	}

	xfree(data);
	return 0;
}

static int
istgt_lu_tape_scsi_report_luns(ISTGT_LU_Ptr lu, CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), int sel, uint8_t *data, int alloc_len)
{
	uint64_t fmt_lun, lun, method;
	int hlen = 0, len = 0;
	int i;

	if (alloc_len < 8) {
		return -1;
	}

	if (sel == 0x00) {
		/* logical unit with addressing method */
	} else if (sel == 0x01) {
		/* well known logical unit */
	} else if (sel == 0x02) {
		/* logical unit */
	} else {
		return -1;
	}

	/* LUN LIST LENGTH */
	DSET32(&data[0], 0);
	/* Reserved */
	DSET32(&data[4], 0);
	hlen = 8;

	for (i = 0; i < lu->maxlun; i++) {
		if (lu->lun[i].type == ISTGT_LU_LUN_TYPE_NONE) {
#if 0
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d none\n",
			    lu->num, i);
#endif
			continue;
		}
		if (alloc_len - (hlen + len) < 8) {
			return -1;
		}
		lun = (uint64_t) i;
		if (lu->maxlun <= 0x0100) {
			/* below 256 */
			method = 0x00U;
			fmt_lun = (method & 0x03U) << 62;
			fmt_lun |= (lun & 0x00ffU) << 48;
		} else if (lu->maxlun <= 0x4000) {
			/* below 16384 */
			method = 0x01U;
			fmt_lun = (method & 0x03U) << 62;
			fmt_lun |= (lun & 0x3fffU) << 48;
		} else {
			/* XXX */
			fmt_lun = 0;
		}
		/* LUN */
		DSET64(&data[hlen + len], fmt_lun);
		len += 8;
	}
	/* LUN LIST LENGTH */
	DSET32(&data[0], len);
	return hlen + len;
}

static int
istgt_lu_tape_scsi_inquiry(ISTGT_LU_TAPE *spec, CONN_Ptr conn, uint8_t *cdb, uint8_t *data, int alloc_len)
{
	char buf[MAX_TMPBUF];
	uint64_t LUI, TPI;
	uint8_t *cp, *cp2;
	int hlen = 0, len = 0, plen, plen2;
	int pc;
	int pq, pd;
	int rmb;
	int evpd;
	int pg_tag;
	int i, j;

	if (alloc_len < 0xff) {
		return -1;
	}

	pq = 0x00;
	pd = SPC_PERIPHERAL_DEVICE_TYPE_TAPE;
	rmb = 1;

	LUI = istgt_get_lui(spec->lu->name, spec->lun & 0xffffU);
	TPI = istgt_get_lui(spec->lu->name, conn->portal.tag << 16);

	pc = cdb[2];
	evpd = BGET8(&cdb[1], 0);
	if (evpd) {
		/* Vital product data */
		switch (pc) {
		case SPC_VPD_SUPPORTED_VPD_PAGES:
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* Reserved */
			data[2] = 0;
			/* PAGE LENGTH */
			data[3] = 0;
			hlen = 4;

#if 0
			data[4] = SPC_VPD_SUPPORTED_VPD_PAGES;      /* 0x00 */
			data[5] = SPC_VPD_UNIT_SERIAL_NUMBER;       /* 0x80 */
			data[6] = SPC_VPD_DEVICE_IDENTIFICATION;    /* 0x83 */
			data[7] = SPC_VPD_MANAGEMENT_NETWORK_ADDRESSES; /* 0x85 */
			data[8] = SPC_VPD_EXTENDED_INQUIRY_DATA;    /* 0x86 */
			data[9] = SPC_VPD_MODE_PAGE_POLICY;         /* 0x87 */
			data[10]= SPC_VPD_SCSI_PORTS;               /* 0x88 */
			len = 11 - hlen;

			/* for DLT8000 */
			data[4] = SPC_VPD_SUPPORTED_VPD_PAGES;      /* 0x00 */
			data[5] = SPC_VPD_UNIT_SERIAL_NUMBER;   	/* 0x80 */
			data[6] = 0xc0; /* Firmware Build Information */
			data[7] = 0xc1; /* Subsystem Components Revision */
			len = 8 - hlen;
#else
			/* for DLT-S4 */
			data[4] = SPC_VPD_SUPPORTED_VPD_PAGES;      /* 0x00 */
			data[5] = SPC_VPD_UNIT_SERIAL_NUMBER;       /* 0x80 */
			data[6] = SPC_VPD_DEVICE_IDENTIFICATION;    /* 0x83 */
			data[7] = 0xb0; /* Sequential-Access Device Capabilities */
			data[8] = 0xb1; /* Manufacturer-assigned Serial Number */
			data[9] = 0xc0; /* Firmware Build Information */
			data[10] = 0xc1; /* Subsystem Components Revision */
			len = 11 - hlen;
#endif

			/* PAGE LENGTH */
			data[3] = len;
			break;

		case SPC_VPD_UNIT_SERIAL_NUMBER:
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* Reserved */
			data[2] = 0;
			/* PAGE LENGTH */
			data[3] = 0;
			hlen = 4;

			/* PRODUCT SERIAL NUMBER */
			len = strlen(spec->lu->inq_serial);
			if (len > MAX_LU_SERIAL_STRING) {
				len = MAX_LU_SERIAL_STRING;
			}
			istgt_strcpy_pad(&data[4], len, spec->lu->inq_serial, ' ');

			/* PAGE LENGTH */
			data[3] = len;
			break;

		case SPC_VPD_DEVICE_IDENTIFICATION:
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* PAGE LENGTH */
			DSET16(&data[2], 0);
			hlen = 4;

			/* Identification descriptor 1 */
			/* Vendor-Unique Logical Unit Identifier */
			cp = &data[hlen + len];

			/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
			BDSET8W(&cp[0], 0, 7, 4);
			BDADD8W(&cp[0], SPC_VPD_CODE_SET_ASCII, 3, 4);
			/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
			BDSET8W(&cp[1], 0, 7, 1); /* PIV */
			BDADD8W(&cp[1], SPC_VPD_ASSOCIATION_LOGICAL_UNIT, 5, 2);
			BDADD8W(&cp[1], SPC_VPD_IDENTIFIER_TYPE_T10_VENDOR_ID, 3, 4);
			/* Reserved */
			cp[2] = 0;
			/* IDENTIFIER LENGTH */
			cp[3] = 0;

			/* IDENTIFIER */
			/* T10 VENDOR IDENTIFICATION */
			istgt_strcpy_pad(&cp[4], 8, spec->lu->inq_vendor, ' ');
			/* PRODUCT IDENTIFICATION */
			istgt_strcpy_pad(&cp[16], 16, spec->lu->inq_product, ' ');
			/* PRODUCT SERIAL NUMBER */
			istgt_strcpy_pad(&cp[32], 10, spec->lu->inq_serial, ' ');
			plen = 8 + 16 + 10;

			cp[3] = plen;
			len += 4 + plen;

			/* Identification descriptor 2 */
			/* Logical Unit NAA Identifier */
			cp = &data[hlen + len];

			/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
			BDSET8W(&cp[0], 0, 7, 4);
			//BDSET8W(&cp[0], SPC_PROTOCOL_IDENTIFIER_FC, 7, 4);
			//BDSET8W(&cp[0], SPC_PROTOCOL_IDENTIFIER_SAS, 7, 4);
			BDADD8W(&cp[0], SPC_VPD_CODE_SET_BINARY, 3, 4);
			/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
			BDSET8W(&cp[1], 1, 7, 1); /* PIV */
			BDADD8W(&cp[1], SPC_VPD_ASSOCIATION_LOGICAL_UNIT, 5, 2);
			BDADD8W(&cp[1], SPC_VPD_IDENTIFIER_TYPE_NAA, 3, 4);
			/* Reserved */
			cp[2] = 0;
			/* IDENTIFIER LENGTH */
			cp[3] = 0;

			/* IDENTIFIER */
			/* NAA Identifier (WWNN) */
			plen = istgt_lu_set_lid(&cp[4], LUI);

			cp[3] = plen;
			len += 4 + plen;

			/* Identification descriptor 3 */
			/* Port NAA Identifier */
			cp = &data[hlen + len];

			/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
			BDSET8W(&cp[0], 0, 7, 4);
			//BDSET8W(&cp[0], SPC_PROTOCOL_IDENTIFIER_FC, 7, 4);
			//BDSET8W(&cp[0], SPC_PROTOCOL_IDENTIFIER_SAS, 7, 4);
			BDADD8W(&cp[0], SPC_VPD_CODE_SET_BINARY, 3, 4);
			/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
			BDSET8W(&cp[1], 1, 7, 1); /* PIV */
			BDADD8W(&cp[1], SPC_VPD_ASSOCIATION_TARGET_PORT, 5, 2);
			BDADD8W(&cp[1], SPC_VPD_IDENTIFIER_TYPE_NAA, 3, 4);
			/* Reserved */
			cp[2] = 0;
			/* IDENTIFIER LENGTH */
			cp[3] = 0;

			/* IDENTIFIER */
			/* NAA Identifier (WWPN) */
			plen = istgt_lu_set_lid(&cp[4], TPI);

			cp[3] = plen;
			len += 4 + plen;

			/* Identification descriptor 4 */
			/* Relative Target Port Identifier */
			cp = &data[hlen + len];

			/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
			BDSET8W(&cp[0], 0, 7, 4);
			//BDSET8W(&cp[0], SPC_PROTOCOL_IDENTIFIER_FC, 7, 4);
			//BDSET8W(&cp[0], SPC_PROTOCOL_IDENTIFIER_SAS, 7, 4);
			BDADD8W(&cp[0], SPC_VPD_CODE_SET_BINARY, 3, 4);
			/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
			BDSET8W(&cp[1], 1, 7, 1); /* PIV */
			BDADD8W(&cp[1], SPC_VPD_ASSOCIATION_TARGET_PORT, 5, 2);
			BDADD8W(&cp[1], SPC_VPD_IDENTIFIER_TYPE_RELATIVE_TARGET_PORT,
					3, 4);
			/* Reserved */
			cp[2] = 0;
			/* IDENTIFIER LENGTH */
			cp[3] = 0;

			/* IDENTIFIER */
			/* Obsolete */
			DSET16(&cp[4], 0);
			/* Relative Target Port Identifier */
			DSET16(&cp[6], 1); /* port1 as port A */
			//DSET16(&cp[6], 2); /* port2 as port B */
			plen = 4;

			cp[3] = plen;
			len += 4 + plen;

#undef LU_ISCSI_IDENTIFIER
#ifdef LU_ISCSI_IDENTIFIER
			/* Identification descriptor 1 */
			/* Logical Unit */
			cp = &data[hlen + len];

			/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
			BDSET8W(&cp[0], 0, 7, 4);
			BDADD8W(&cp[0], SPC_VPD_CODE_SET_BINARY, 3, 4);
			/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
			BDSET8W(&cp[1], 0, 7, 1); /* PIV=0 */
			BDADD8W(&cp[1], SPC_VPD_ASSOCIATION_LOGICAL_UNIT, 5, 2);
			BDADD8W(&cp[1], SPC_VPD_IDENTIFIER_TYPE_NAA, 3, 4);
			/* Reserved */
			cp[2] = 0;
			/* IDENTIFIER LENGTH */
			cp[3] = 0;

			/* IDENTIFIER */
#if 0
			/* 16bytes ID */
			plen = istgt_lu_set_extid(&cp[4], 0, LUI);
#else
			plen = istgt_lu_set_lid(&cp[4], LUI);
#endif

			cp[3] = plen;
			len += 4 + plen;

			/* Identification descriptor 2 */
			/* T10 VENDOR IDENTIFICATION */
			cp = &data[hlen + len];

			/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
			BDSET8W(&cp[0], 0, 7, 4);
			BDADD8W(&cp[0], SPC_VPD_CODE_SET_UTF8, 3, 4);
			/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
			BDSET8W(&cp[1], 0, 7, 1); /* PIV=0 */
			BDADD8W(&cp[1], SPC_VPD_ASSOCIATION_LOGICAL_UNIT, 5, 2);
			BDADD8W(&cp[1], SPC_VPD_IDENTIFIER_TYPE_T10_VENDOR_ID, 3, 4);
			/* Reserved */
			cp[2] = 0;
			/* IDENTIFIER LENGTH */
			cp[3] = 0;

			/* IDENTIFIER */
			/* T10 VENDOR IDENTIFICATION */
			istgt_strcpy_pad(&cp[4], 8, spec->lu->inq_vendor, ' ');
			plen = 8;
			/* VENDOR SPECIFIC IDENTIFIER */
			/* PRODUCT IDENTIFICATION */
			istgt_strcpy_pad(&cp[12], 16, spec->lu->inq_product, ' ');
			/* PRODUCT SERIAL NUMBER */
			istgt_strcpy_pad(&cp[28], MAX_LU_SERIAL_STRING,
			    spec->lu->inq_serial, ' ');
			plen += 16 + MAX_LU_SERIAL_STRING;

			cp[3] = plen;
			len += 4 + plen;

			/* Identification descriptor 3 */
			/* Target Device */
			cp = &data[hlen + len];

			/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
			BDSET8W(&cp[0], SPC_PROTOCOL_IDENTIFIER_ISCSI, 7, 4);
			BDADD8W(&cp[0], SPC_VPD_CODE_SET_UTF8, 3, 4);
			/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
			BDSET8W(&cp[1], 1, 7, 1); /* PIV */
			BDADD8W(&cp[1], SPC_VPD_ASSOCIATION_TARGET_DEVICE, 5, 2);
			BDADD8W(&cp[1], SPC_VPD_IDENTIFIER_TYPE_SCSI_NAME, 3, 4);
			/* Reserved */
			cp[2] = 0;
			/* IDENTIFIER LENGTH */
			cp[3] = 0;

			/* IDENTIFIER */
			plen = snprintf((char *) &cp[4], MAX_TARGET_NAME,
			    "%s", spec->lu->name);
			cp[3] = plen;
			len += 4 + plen;

			/* Identification descriptor 4 */
			/* Target Port */
			cp = &data[hlen + len];

			/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
			BDSET8W(&cp[0], SPC_PROTOCOL_IDENTIFIER_ISCSI, 7, 4);
			BDADD8W(&cp[0], SPC_VPD_CODE_SET_UTF8, 3, 4);
			/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
			BDSET8W(&cp[1], 1, 7, 1); /* PIV */
			BDADD8W(&cp[1], SPC_VPD_ASSOCIATION_TARGET_PORT, 5, 2);
			BDADD8W(&cp[1], SPC_VPD_IDENTIFIER_TYPE_SCSI_NAME, 3, 4);
			/* Reserved */
			cp[2] = 0;
			/* IDENTIFIER LENGTH */
			cp[3] = 0;

			/* IDENTIFIER */
			plen = snprintf((char *) &cp[4], MAX_TARGET_NAME,
			    "%s"",t,0x""%4.4x", spec->lu->name, conn->portal.tag);
			cp[3] = plen;
			len += 4 + plen;

			/* Identification descriptor 5 */
			/* Relative Target Port */
			cp = &data[hlen + len];

			/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
			BDSET8W(&cp[0], SPC_PROTOCOL_IDENTIFIER_ISCSI, 7, 4);
			BDADD8W(&cp[0], SPC_VPD_CODE_SET_BINARY, 3, 4);
			/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
			BDSET8W(&cp[1], 1, 7, 1); /* PIV */
			BDADD8W(&cp[1], SPC_VPD_ASSOCIATION_TARGET_PORT, 5, 2);
			BDADD8W(&cp[1], SPC_VPD_IDENTIFIER_TYPE_RELATIVE_TARGET_PORT,
			    3, 4);
			/* Reserved */
			cp[2] = 0;
			/* IDENTIFIER LENGTH */
			cp[3] = 0;

			/* IDENTIFIER */
			/* Obsolete */
			DSET16(&cp[4], 0);
			/* Relative Target Port Identifier */
			//DSET16(&cp[6], 1); /* port1 as port A */
			//DSET16(&cp[6], 2); /* port2 as port B */
			DSET16(&cp[6], (uint16_t) (1 + conn->portal.idx));
			plen = 4;

			cp[3] = plen;
			len += 4 + plen;

			/* Identification descriptor 6 */
			/* Target port group */
			cp = &data[hlen + len];

			/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
			BDSET8W(&cp[0], SPC_PROTOCOL_IDENTIFIER_ISCSI, 7, 4);
			BDADD8W(&cp[0], SPC_VPD_CODE_SET_BINARY, 3, 4);
			/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
			BDSET8W(&cp[1], 1, 7, 1); /* PIV */
			BDADD8W(&cp[1], SPC_VPD_ASSOCIATION_TARGET_PORT, 5, 2);
			BDADD8W(&cp[1], SPC_VPD_IDENTIFIER_TYPE_TARGET_PORT_GROUP,
			    3, 4);
			/* Reserved */
			cp[2] = 0;
			/* IDENTIFIER LENGTH */
			cp[3] = 0;

			/* IDENTIFIER */
			/* Reserved */
			DSET16(&cp[4], 0);
			/* TARGET PORT GROUP */
			DSET16(&cp[6], (uint16_t) (conn->portal.tag));
			plen = 4;

			cp[3] = plen;
			len += 4 + plen;

			/* Identification descriptor 7 */
			/* Logical unit group */
			cp = &data[hlen + len];

			/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
			BDSET8W(&cp[0], SPC_PROTOCOL_IDENTIFIER_ISCSI, 7, 4);
			BDADD8W(&cp[0], SPC_VPD_CODE_SET_BINARY, 3, 4);
			/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
			BDSET8W(&cp[1], 1, 7, 1); /* PIV */
			BDADD8W(&cp[1], SPC_VPD_ASSOCIATION_TARGET_PORT, 5, 2);
			BDADD8W(&cp[1], SPC_VPD_IDENTIFIER_TYPE_LOGICAL_UNIT_GROUP,
			    3, 4);
			/* Reserved */
			cp[2] = 0;
			/* IDENTIFIER LENGTH */
			cp[3] = 0;

			/* IDENTIFIER */
			/* Reserved */
			DSET16(&cp[4], 0);
			/* LOGICAL UNIT GROUP */
			DSET16(&cp[6], (uint16_t) (spec->lu->num));
			plen = 4;

			cp[3] = plen;
			len += 4 + plen;
#endif /* LU_ISCSI_IDENTIFIER */

			/* PAGE LENGTH */
			if (len > 0xffff) {
				len = 0xffff;
			}
			DSET16(&data[2], len);
			break;

		case SPC_VPD_EXTENDED_INQUIRY_DATA:
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* Reserved */
			data[2] = 0;
			/* PAGE LENGTH */
			data[3] = 0;
			hlen = 4;

			/* RTO(3) GRD_CHK(2) APP_CHK(1) REF_CHK(0) */
			data[4] = 0;
			/* GROUP_SUP(4) PRIOR_SUP(3) HEADSUP(2) ORDSUP(1) SIMPSUP(0) */
			data[5] = 0;
			/* NV_SUP(1) V_SUP(0) */
			data[6] = 0;
			/* Reserved[7-63] */
			memset(&data[7], 0, (64 - 7));
			len = 64 - hlen;

			/* PAGE LENGTH */
			data[3] = len;
			break;

		case SPC_VPD_MANAGEMENT_NETWORK_ADDRESSES:
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* PAGE LENGTH */
			DSET16(&data[2], 0);
			hlen = 4;

#if 0
			/* Network services descriptor N */
			cp = &data[hlen + len];

			/* ASSOCIATION(6-5) SERVICE TYPE(4-0) */
			BDSET8W(&cp[0], 0x00, 6, 2);
			BDADD8W(&cp[0], 0x00, 4, 5);
			/* Reserved */
			cp[1] = 0;
			/* NETWORK ADDRESS LENGTH */
			DSET16(&cp[2], 0);
			/* NETWORK ADDRESS */
			cp[4] = 0;
			/* ... */
			plen = 0;
			DSET16(&cp[2], plen);
			len += 4 + plen;
#endif

			/* PAGE LENGTH */
			if (len > 0xffff) {
				len = 0xffff;
			}
			DSET16(&data[2], len);
			break;

		case SPC_VPD_MODE_PAGE_POLICY:
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* PAGE LENGTH */
			DSET16(&data[2], 0);
			hlen = 4;

			/* Mode page policy descriptor 1 */
			cp = &data[hlen + len];

			/* POLICY PAGE CODE(5-0) */
			BDSET8W(&cp[0], 0x3f, 5, 6);    /* all page code */
			/* POLICY SUBPAGE CODE */
			cp[1] = 0xff;                   /* all sub page */
			/* MLUS(7) MODE PAGE POLICY(1-0) */
			//BDSET8(&cp[2], 1, 7); /* multiple logical units share */
			BDSET8(&cp[2], 0, 7); /* own copy */
			BDADD8W(&cp[2], 0x00, 1, 2); /* Shared */
			//BDADD8W(&cp[2], 0x01, 1, 2); /* Per target port */
			//BDADD8W(&cp[2], 0x02, 1, 2); /* Per initiator port */
			//BDADD8W(&cp[2], 0x03, 1, 2); /* Per I_T nexus */
			/* Reserved */
			cp[3] = 0;
			len += 4;

			/* PAGE LENGTH */
			if (len > 0xffff) {
				len = 0xffff;
			}
			DSET16(&data[2], len);
			break;

		case SPC_VPD_SCSI_PORTS:
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* PAGE LENGTH */
			DSET16(&data[2], 0);
			hlen = 4;

			/* Identification descriptor list */
			for (i = 0; i < spec->lu->maxmap; i++) {
				pg_tag = spec->lu->map[i].pg_tag;
				/* skip same pg_tag */
				for (j = 0; j < i; j++) {
					if (spec->lu->map[j].pg_tag == pg_tag) {
						goto skip_pg_tag;
					}
				}

				/* Identification descriptor N */
				cp = &data[hlen + len];

				/* Reserved */
				DSET16(&cp[0], 0);
				/* RELATIVE PORT IDENTIFIER */
				DSET16(&cp[2], (uint16_t) (1 + pg_tag));
				/* Reserved */
				DSET16(&cp[4], 0);
				/* INITIATOR PORT TRANSPORTID LENGTH */
				DSET16(&cp[6], 0);
				/* Reserved */
				DSET16(&cp[8], 0);
				/* TARGET PORT DESCRIPTORS LENGTH */
				DSET16(&cp[10], 0);
				len += 12;

				plen2 = 0;
				/* Target port descriptor 1 */
				cp2 = &data[hlen + len + plen2];

				/* PROTOCOL IDENTIFIER(7-4) CODE SET(3-0) */
				BDSET8W(&cp2[0], SPC_PROTOCOL_IDENTIFIER_ISCSI, 7, 4);
				BDADD8W(&cp2[0], SPC_VPD_CODE_SET_UTF8, 3, 4);
				/* PIV(7) ASSOCIATION(5-4) IDENTIFIER TYPE(3-0) */
				BDSET8W(&cp2[1], 1, 7, 1); /* PIV */
				BDADD8W(&cp2[1], SPC_VPD_ASSOCIATION_TARGET_PORT, 5, 2);
				BDADD8W(&cp2[1], SPC_VPD_IDENTIFIER_TYPE_SCSI_NAME, 3, 4);
				/* Reserved */
				cp2[2] = 0;
				/* IDENTIFIER LENGTH */
				cp2[3] = 0;

				/* IDENTIFIER */
				plen = snprintf((char *) &cp2[4], MAX_TARGET_NAME,
				    "%s"",t,0x""%4.4x", spec->lu->name, pg_tag);
				cp2[3] = plen;
				plen2 += 4 + plen;

				/* TARGET PORT DESCRIPTORS LENGTH */
				DSET16(&cp[10], plen2);
				len += plen2;
			skip_pg_tag:
				;
			}

			/* PAGE LENGTH */
			if (len > 0xffff) {
				len = 0xffff;
			}
			DSET16(&data[2], len);
			break;

		/* for DLT-S4 */
		case 0xb0: /* Sequential-Access Device Capabilities */
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* Reserved */
			data[2] = 0;
			/* PAGE LENGTH */
			data[3] = 0;
			hlen = 4;

			len = 0x4;
			memset(&data[4], 0, len);
			//BSET8(&data[4], 0); /* WORM */

			/* PAGE LENGTH */
			data[3] = len;
			break;

		case 0xb1: /* Manufacturer-assigned Serial Number */
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* Reserved */
			data[2] = 0;
			/* PAGE LENGTH */
			data[3] = 0;
			hlen = 4;

			len = 0x10;
			memset(&data[4], 0, len);

			/* Manufacturer Serial Number */
			snprintf(buf, sizeof buf, "%16.16d", 0);
			istgt_strcpy_pad(&data[4], 16, buf, ' ');

			/* PAGE LENGTH */
			data[3] = len;
			break;

		/* for DLT8000 */
		case 0xc0: /* Firmware Build Information */
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* Reserved */
			data[2] = 0;
			/* PAGE LENGTH */
			data[3] = 0;
			hlen = 4;

			len = 0x20;
			memset(&data[4], 0, len);

			/* PAGE LENGTH */
			data[3] = len;
			break;

		case 0xc1: /* Subsystem Components Revision */
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* Reserved */
			data[2] = 0;
			/* PAGE LENGTH */
			data[3] = 0;
			hlen = 4;

			len = 0x14;
			memset(&data[4], 0, len);

			/* Media Loader Present Flag */
			data[18] = 0;
			/* Library Present Flag */
			data[19] = 0;

			/* PAGE LENGTH */
			data[3] = len;
			break;

		default:
			if (pc >= 0xc0 && pc <= 0xff) {
				ISTGT_WARNLOG("Vendor specific INQUIRY VPD page 0x%x\n", pc);
			} else {
				ISTGT_ERRLOG("unsupported INQUIRY VPD page 0x%x\n", pc);
			}
			return -1;
		}
	} else {
		/* Standard INQUIRY data */
		/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
		BDSET8W(&data[0], pq, 7, 3);
		BDADD8W(&data[0], pd, 4, 5);
		/* RMB(7) */
		BDSET8W(&data[1], rmb, 7, 1);
		/* VERSION */
		/* See SPC3/SBC2/MMC4/SAM2 for more details */
		data[2] = SPC_VERSION_SPC3;
		/* NORMACA(5) HISUP(4) RESPONSE DATA FORMAT(3-0) */
		BDSET8W(&data[3], 2, 3, 4);		/* format 2 */
		/* ADDITIONAL LENGTH */
		data[4] = 0;
		hlen = 5;

		/* SCCS(7) ACC(6) TPGS(5-4) 3PC(3) PROTECT(0) */
		data[5] = 0;
		/* BQUE(7) ENCSERV(6) VS(5) MULTIP(4) MCHNGR(3) ADDR16(0) */
		data[6] = 0;
		/* WBUS16(5) SYNC(4) LINKED(3) CMDQUE(1) VS(0) */
		data[7] = 0;
		/* T10 VENDOR IDENTIFICATION */
		istgt_strcpy_pad(&data[8], 8, spec->lu->inq_vendor, ' ');
		/* PRODUCT IDENTIFICATION */
		istgt_strcpy_pad(&data[16], 16, spec->lu->inq_product, ' ');
		/* PRODUCT REVISION LEVEL */
		istgt_strcpy_pad(&data[32], 4, spec->lu->inq_revision, ' ');
		/* Vendor specific */
		memset(&data[36], 0x20, 20);
#if 1
		/* for Quantum DLT */
		/* Product Family(7-4) Released Firmware(3-0) */
		//BDSET8W(&data[36], 5, 7, 4); /* 20/40GB */
		BDSET8W(&data[36], 11, 7, 4); /* 40/80GB */
		BDSET8W(&data[36], 1, 3, 4); /* Vxxx firmware */
		/* Firmware Major Version # */
		data[37] = 0x01;
		/* Firmware Minor Version # */
		data[38] = 0x00;
		/* EEPROM Format Major Version # */
		data[39] = 0x01;
		/* EEPROM Format Minor Version # */
		data[40] = 0x00;
		/* Firmware Personality */
		data[41] = 0x04; /* OEM family */
		/* Firmware Sub-Personality */
		data[42] = 0x01; /* primary firmware personality variant */
		/* Vendor Unique Subtype */
		data[43] = 0x00;
		/* Controller Hardware Version # */
		data[44] = 0x01;
		/* Drive EEPROM Version # */
		data[45] = 0x01;
		/* Drive Hardware Version # */
		data[46] = 0x01;
		/* Media Loader Firmware Version # */
		data[47] = 0x00;
		/* Media Loader Hardware Version # */
		data[48] = 0x00;
		/* Media Loader Mechanical Version # */
		data[49]=  0x00;
		/* Media Loader Present Flag */
		data[50] = 0;
		/* Library Present Flag */
		data[51] = 0;
		/* Module Revision */
		istgt_strcpy_pad(&data[54], 4, TAPE_MODULE_REV, ' ');
#endif
		/* CLOCKING(3-2) QAS(1) IUS(0) */
		data[56] = 0;
		/* Reserved */
		data[57] = 0;
		/* VERSION DESCRIPTOR 1-8 */
		DSET16(&data[58], 0x0960); /* iSCSI (no version claimed) */
		DSET16(&data[60], 0x0300); /* SPC-3 (no version claimed) */
		DSET16(&data[62], 0x0360); /* SSC-2 (no version claimed) */
		DSET16(&data[64], 0x0040); /* SAM-2 (no version claimed) */
		DSET16(&data[66], 0x0000);
		DSET16(&data[68], 0x0000);
		DSET16(&data[70], 0x0000);
		DSET16(&data[72], 0x0000);
		/* Reserved[74-95] */
		memset(&data[74], 0, (96 - 74));
		/* Vendor specific parameters[96-n] */
		//data[96] = 0;
		len = 96 - hlen;

		/* ADDITIONAL LENGTH */
		data[4] = len;
	}

	return hlen + len;
}

#define MODE_SENSE_PAGE_INIT(B,L,P,SP)					\
	do {								\
		memset((B), 0, (L));					\
		if ((SP) != 0x00) {					\
			(B)[0] = (P) | 0x40; /* PAGE + SPF=1 */		\
			(B)[1] = (SP);					\
			DSET16(&(B)[2], (L) - 4);			\
		} else {						\
			(B)[0] = (P);					\
			(B)[1] = (L) - 2;				\
		}							\
	} while (0)

static int
istgt_lu_tape_scsi_mode_sense_page(ISTGT_LU_TAPE *spec, CONN_Ptr conn, uint8_t *cdb, int pc, int page, int subpage, uint8_t *data, int alloc_len)
{
	uint8_t *cp;
	int len = 0;
	int plen;
	int i;

#if 0
	printf("SENSE pc=%d, page=%2.2x, subpage=%2.2x\n", pc, page, subpage);
#endif
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE: pc=%d, page=%2.2x, subpage=%2.2x\n", pc, page, subpage);

	if (pc == 0x00) {
		/* Current values */
	} else if (pc == 0x01) {
		/* Changeable values */
		if (page != 0x0f) {
			/* not supported */
			return -1;
		}
	} else if (pc == 0x02) {
		/* Default values */
	} else {
		/* Saved values */
	}

	cp = &data[len];
	switch (page) {
	case 0x00:
		/* Vendor specific */
		break;
	case 0x01:
		/* Read-Write Error Recovery */
		break;
	case 0x02:
		/* Disconnect-Reconnect mode page */
		break;
	case 0x03:
	case 0x04:
	case 0x05:
	case 0x06:
	case 0x07:
	case 0x08:
		/* Reserved */
		break;
	case 0x09:
		/* Obsolete */
		break;
	case 0x0a:
		/* Control mode page */
		break;
	case 0x0b:
	case 0x0c:
	case 0x0d:
	case 0x0e:
		/* Reserved */
		break;
	case 0x0f:
		/* Data Compression */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Data Compression\n");
		if (subpage != 0x00)
			break;

		plen = 0x0e + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		if (pc == 0x01) {
			// Changeable values
			BDADD8(&cp[2], 1, 7);       /* DCE data compression enable */
			BDADD8(&cp[2], 1, 6);       /* DCC data compression capable */
			BDADD8(&cp[3], 1, 7);       /* DDE data decompression enable */
			BDADD8W(&cp[3], 0, 6, 2);   /* RED report exception on decompression */
			DSET32(&cp[4], 0xffffffffU); /* COMPRESSION ALGORITHM */
			DSET32(&cp[8], 0xffffffffU); /* DECOMPRESSION ALGORITHM */
			len += plen;
			break;
		}
		if (spec->compression) {
			BDADD8(&cp[2], 1, 7);   /* DCE=1 compression enable */
		} else {
			BDADD8(&cp[2], 0, 7);   /* DCE=0 compression disable */
		}
		//BDADD8(&cp[2], 0, 6);     /* DCC=0 not support compression */
		BDADD8(&cp[2], 1, 6);       /* DCC=1 support compression */
		BDADD8(&cp[3], 1, 7);       /* DDE=1 decompression enable */
		BDADD8W(&cp[3], 0, 6, 2);   /* RED=0 not support */
		/* COMPRESSION ALGORITHM */
		//DSET32(&cp[4], 0);
		//DSET32(&cp[4], 0x03); /* IBM ALDC with 512 byte buffer */
		//DSET32(&cp[4], 0x04); /* IBM ALDC with 1024 byte buffer */
		//DSET32(&cp[4], 0x05); /* IBM ALDC with 2048 byte buffer */
		//DSET32(&cp[4], 0x10); /* IBM IDRC */
		DSET32(&cp[4], TAPE_COMP_ALGORITHM);
		/* DECOMPRESSION ALGORITHM */
		//DSET32(&cp[8], 0);
		DSET32(&cp[8], TAPE_COMP_ALGORITHM);
		len += plen;
		break;
	case 0x10:
		/* Device Configuration */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Device Configuration\n");
		if (subpage != 0x00)
			break;

		plen = 0x0e + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		/* WRITE DELAY TIME */
		DSET16(&cp[6], TAPE_WRITE_DELAY);
		/* RSMK(5) */
		BDADD8(&data[8], 0, 5); /* report setmarks not support */
		/* LOIS(6) */
		BDADD8(&data[8], 1, 6);
		/* EEG(4) SEW(3) */
		BDADD8(&data[10], 1, 4);
		BDADD8(&data[10], 1, 3);
		/* SELECT DATA COMPRESSION ALGORITHM */
		if (spec->compression) {
			data[14] = 1; /* data compression is enabled */
		}
		len += plen;
		break;
	case 0x11:
		/* Medium Partition */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Medium Partition\n");
		if (subpage != 0x00)
			break;

		plen = 0x08 + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		len += plen;
		break;
	case 0x12:
		/* Obsolete */
		break;
	case 0x13:
		/* Obsolete */
		break;
	case 0x14:
		/* Obsolete */
		break;
	case 0x15:
	case 0x16:
	case 0x17:
		/* Reserved */
		break;
	case 0x18:
		/* Protocol Specific LUN */
		break;
	case 0x19:
		/* Protocol Specific Port */
		break;
	case 0x1a:
		/* Power Condition */
		break;
	case 0x1b:
		/* Reserved */
		break;
	case 0x1c:
		/* Informational Exceptions Control */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Informational Exceptions Control\n");
		if (subpage != 0x00)
			break;

		plen = 0x0a + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		len += plen;
		break;
	case 0x1d:
	case 0x1e:
	case 0x1f:
		/* Reserved */
		break;
	case 0x20:
	case 0x21:
	case 0x22:
	case 0x23:
	case 0x24:
	case 0x25:
	case 0x26:
	case 0x27:
	case 0x28:
	case 0x29:
	case 0x2a:
	case 0x2b:
	case 0x2c:
	case 0x2d:
	case 0x2e:
	case 0x2f:
	case 0x30:
	case 0x31:
	case 0x32:
	case 0x33:
	case 0x34:
	case 0x35:
	case 0x36:
	case 0x37:
	case 0x38:
	case 0x39:
	case 0x3a:
	case 0x3b:
	case 0x3c:
	case 0x3d:
	case 0x3e:
		/* Vendor-specific */
		break;
	case 0x3f:
		switch (subpage) {
		case 0x00:
			/* All mode pages */
			for (i = 0x00; i < 0x3e; i ++) {
				len += istgt_lu_tape_scsi_mode_sense_page(spec, conn, cdb, pc, i, 0x00, &cp[len], alloc_len);
			}
			break;
		case 0xff:
			/* All mode pages and subpages */
			for (i = 0x00; i < 0x3e; i ++) {
				len += istgt_lu_tape_scsi_mode_sense_page(spec, conn, cdb, pc, i, 0x00, &cp[len], alloc_len);
			}
			for (i = 0x00; i < 0x3e; i ++) {
				len += istgt_lu_tape_scsi_mode_sense_page(spec, conn, cdb, pc, i, 0xff, &cp[len], alloc_len);
			}
			break;
		default:
			/* 0x01-0x3e: Reserved */
			break;
		}
	}

	return len;
}

static int
istgt_lu_tape_scsi_mode_sense6(ISTGT_LU_TAPE *spec, CONN_Ptr conn, uint8_t *cdb, int dbd, int pc, int page, int subpage, uint8_t *data, int alloc_len)
{
	uint8_t *cp;
	int hlen = 0, len = 0, plen;
	int total;
	int llbaa = 0;

	data[0] = 0;                    /* Mode Data Length */
	if (spec->mload) {
		//data[1] = 0;                    /* Medium Type (no media) */
		//data[1] = TAPE_MEDIATYPE_LTO;   /* Medium Type (LTO) */
		data[1] = MEDIATYPE_DFLT;       /* Medium Type */
		data[2] = 0;                    /* Device-Specific Parameter */
		if (spec->lu->readonly
		    || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
			BDADD8(&data[2], 1, 7);     /* WP */
		}
	} else {
		data[1] = 0;                    /* Medium Type (no media) */
		data[2] = 0;                    /* Device-Specific Parameter */
	}
	BDADD8W(&data[2], 1, 6, 3);		/* Buffed Mode=1 */
	data[3] = 0;                    /* Block Descripter Length */
	hlen = 4;

	cp = &data[4];
	if (dbd) {                      /* Disable Block Descripters */
		len = 0;
	} else {
		if (llbaa) {
			if (spec->mload) {
				/* Number of Blocks */
				DSET64(&cp[0], 0ULL);   /* all of the remaining */
				/* Reserved */
				DSET32(&cp[8], 0);
				/* Block Length */
				DSET32(&cp[12], (uint32_t) spec->lblen);
			} else {
				/* Number of Blocks */
				DSET64(&cp[0], 0ULL);   /* all of the remaining */
				/* Reserved */
				DSET32(&cp[8], 0);
				/* Block Length */
				DSET32(&cp[12], 0);
			}
			len = 16;
		} else {
			if (spec->mload) {
				/* Number of Blocks */
				DSET32(&cp[0], 0);      /* all of the remaining */
				/* Block Length */
				DSET32(&cp[4], (uint32_t) spec->lblen);
				cp[0] = DENSITY_DFLT;   /* Density Code */
				cp[4] = 0;              /* Reserved */
			} else {
				/* Number of Blocks */
				DSET32(&cp[0], 0);      /* all of the remaining */
				/* Block Length */
				DSET32(&cp[4], 0);
				cp[0] = 0;              /* Density Code */
				cp[4] = 0;              /* Reserved */
			}
			len = 8;
		}
		cp += len;
	}
	data[3] = len;                  /* Block Descripter Length */

	plen = istgt_lu_tape_scsi_mode_sense_page(spec, conn, cdb, pc, page, subpage, &cp[0], alloc_len);
	if (plen < 0) {
		return -1;
	}
	cp += plen;

	total = hlen + len + plen;
	data[0] = total - 1;            /* Mode Data Length */

	return total;
}

static int
istgt_lu_tape_scsi_mode_sense10(ISTGT_LU_TAPE *spec, CONN_Ptr conn, uint8_t *cdb, int dbd, int llbaa, int pc, int page, int subpage, uint8_t *data, int alloc_len)
{
	uint8_t *cp;
	int hlen = 0, len = 0, plen;
	int total;

	DSET16(&data[0], 0);            /* Mode Data Length */
	if (spec->mload) {
		//data[2] = 0;                    /* Medium Type (no media) */
		//data[2] = TAPE_MEDIATYPE_LTO;   /* Medium Type (DLT) */
		data[2] = MEDIATYPE_DFLT;       /* Medium Type */
		data[3] = 0;                    /* Device-Specific Parameter */
		if (spec->lu->readonly
		    || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
			BDADD8(&data[3], 1, 7);     /* WP */
		}
	} else {
		data[2] = 0;                    /* Medium Type (no media) */
		data[3] = 0;                    /* Device-Specific Parameter */
	}
	BDADD8W(&data[3], 1, 6, 3);		/* Buffed Mode=1 */
	if (llbaa) {
		BDSET8(&data[4], 1, 1);      /* Long LBA */
	} else {
		BDSET8(&data[4], 0, 1);      /* Short LBA */
	}
	data[5] = 0;                    /* Reserved */
	DSET16(&data[6], 0);  		    /* Block Descripter Length */
	hlen = 8;

	cp = &data[8];
	if (dbd) {                      /* Disable Block Descripters */
		len = 0;
	} else {
		if (llbaa) {
			if (spec->mload) {
				/* Number of Blocks */
				DSET64(&cp[0], 0ULL);   /* all of the remaining */
				/* Reserved */
				DSET32(&cp[8], 0);
				/* Block Length */
				DSET32(&cp[12], (uint32_t) spec->lblen);
			} else {
				/* Number of Blocks */
				DSET64(&cp[0], 0ULL);   /* all of the remaining */
				/* Reserved */
				DSET32(&cp[8], 0);
				/* Block Length */
				DSET32(&cp[12], 0);
			}
			len = 16;
		} else {
			if (spec->mload) {
				/* Number of Blocks */
				DSET32(&cp[0], 0);      /* all of the remaining */
				/* Block Length */
				DSET32(&cp[4], (uint32_t) spec->lblen);
				cp[0] = DENSITY_DFLT;   /* Density Code */
				cp[4] = 0;              /* Reserved */
			} else {
				/* Number of Blocks */
				DSET32(&cp[0], 0);      /* all of the remaining */
				/* Block Length */
				DSET32(&cp[4], 0);
				cp[0] = 0;              /* Density Code */
				cp[4] = 0;              /* Reserved */
			}
			len = 8;
		}
		cp += len;
	}
	DSET16(&data[6], len);          /* Block Descripter Length */

	plen = istgt_lu_tape_scsi_mode_sense_page(spec, conn, cdb, pc, page, subpage, &cp[0], alloc_len);
	if (plen < 0) {
		return -1;
	}
	cp += plen;

	total = hlen + len + plen;
	DSET16(&data[0], total - 2);	/* Mode Data Length */

	return total;
}

static int
istgt_lu_tape_transfer_data(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint8_t *buf, size_t bufsize, size_t len)
{
	int rc;

	if (len > bufsize) {
		ISTGT_ERRLOG("bufsize(%zd) too small\n", bufsize);
		return -1;
	}
	rc = istgt_iscsi_transfer_out(conn, lu_cmd, buf, bufsize, len);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_transfer_out()\n");
		return -1;
	}
	return 0;
}

static int
istgt_lu_tape_scsi_mode_select_page(ISTGT_LU_TAPE *spec, CONN_Ptr conn, uint8_t *cdb, int pf, int sp, uint8_t *data, size_t len)
{
	size_t hlen, plen;
	int ps, spf, page, subpage;
	int rc;

	if (pf == 0) {
		/* vendor specific */
		return 0;
	}

	if (len < 1)
		return 0;
	ps = BGET8(&data[0], 7);
	spf = BGET8(&data[0], 6);
	page = data[0] & 0x3f;
	if (spf) {
		/* Sub_page mode page format */
		hlen = 4;
		if (len < hlen)
			return 0;
		subpage = data[1];

		plen = DGET16(&data[2]);
	} else {
		/* Page_0 mode page format */
		hlen = 2;
		if (len < hlen)
			return 0;
		subpage = 0;
		plen = data[1];
	}
	plen += hlen;
	if (len < plen)
		return 0;

#if 0
	printf("SELECT ps=%d, page=%2.2x, subpage=%2.2x\n", ps, page, subpage);
#endif
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SELECT: ps=%d, page=%2.2x, subpage=%2.2x\n", ps, page, subpage);
	switch (page) {
	case 0x0f:
		/* Data Compression */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SELECT Data Compression\n");
		{
			int dce, dde, red;
			uint32_t compalgo, decompalgo;

			if (subpage != 0x00)
				break;
			if (plen != 0x0e + hlen) {
				/* unknown format */
				break;
			}

			dce = BGET8(&data[2], 7); /* DCE */
			dde = BGET8(&data[3], 7); /* DDE */
			red = BGET8W(&data[3], 6, 2); /* RED */

			compalgo = DGET32(&data[4]);
			decompalgo = DGET32(&data[8]);

			switch (compalgo) {
			case 0x00: /* default by hard */
				compalgo = TAPE_COMP_ALGORITHM;
			case 0x03: /* ALDC 512 */
			case 0x04: /* ALDC 1024 */
			case 0x05: /* ALDC 2048 */
			case 0x10: /* IDRC */
				spec->compalgo = compalgo;
				spec->vtcompalgo = MARK_COMPALGO_NONE;
				break;
			default:
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "unsupported Compression Algorithm\n");
				/* force to default */
				spec->compalgo = TAPE_COMP_ALGORITHM;
				spec->vtcompalgo = MARK_COMPALGO_NONE;
				break;
			}

			if (dce) {
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SELECT Data compression enable\n");
				spec->compression = 1;
			} else {
				spec->compression = 0;
			}
			if (dde) {
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SELECT Data decompression enable\n");
			}
			break;
		}
	case 0x10:
		/* Device Configuration */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SELECT Device Configuration\n");
		{
			if (subpage != 0x00)
				break;
			if (plen != 0x0e + hlen) {
				/* unknown format */
				break;
			}
			break;
		}
	default:
		/* not supported */
		break;
	}

	len -= plen;
	if (len != 0) {
		rc = istgt_lu_tape_scsi_mode_select_page(spec, conn, cdb,  pf, sp, &data[plen], len);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}

static int
istgt_convert_signed_24bits(uint32_t usval)
{
	int value;

	/* 24bits two's complement notation */
	if (usval > 0x007fffff) {
		usval -= 1;
		usval = ~usval;
		usval &= 0x00ffffff;
		value = (int) usval;
		value = -value;
	} else {
		value = (int) usval;
	}
	return value;
}

#define THREAD_YIELD do { istgt_yield(); usleep(1000); } while (0)

static int
istgt_lu_tape_shrink_media(ISTGT_LU_TAPE *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd __attribute__((__unused__)), uint64_t request_len, uint8_t *data __attribute__((__unused__)))
{
	struct stat st;
	uint64_t mediasize;
	uint64_t marklen;
	uint32_t mediaflags;
	int fd;

	fd = spec->fd;
	mediasize = spec->size;
	mediaflags = spec->mflags;
	marklen = spec->ctlblock->marklen;

	if (fstat(fd, &st) == -1) {
		ISTGT_ERRLOG("fstat() failed\n");
		return -1;
	}

	if (S_ISREG(st.st_mode)) {
		/* media is file */
		if (mediaflags & ISTGT_LU_FLAG_MEDIA_DYNAMIC) {
			if (request_len < ISTGT_LU_MEDIA_SIZE_MIN) {
				request_len = ISTGT_LU_MEDIA_SIZE_MIN;
			}
			mediasize = request_len;
#ifdef TAPE_DEBUG
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "Shrink: %" PRIu64 " -> %" PRIu64 "\n", st.st_size, request_len);
#endif /* TAPE_DEBUG */
			/* truncate */
			if (ftruncate(fd, request_len) == -1) {
				ISTGT_ERRLOG("ftruncate() failed\n");
				return -1;
			}
			fsync(fd);
			spec->size = mediasize;
		}
	} else {
		/* media is not file */
	}
	return 0;
}

static int
istgt_lu_tape_scsi_erase(ISTGT_LU_TAPE *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd, uint8_t *data)
{
	struct stat st;
	uint64_t mediasize;
	uint64_t ctlblocklen;
	uint64_t marklen;
	uint64_t request_len;
	uint32_t mediaflags;
	int data_len;
	int newfile;
	int fd;

	fd = spec->fd;
	mediasize = spec->size;
	mediaflags = spec->mflags;

	ctlblocklen = spec->ctlblock->ctlblocklen;
	marklen = spec->ctlblock->marklen;
	if (ctlblocklen < CTLBLOCKLEN) {
		ctlblocklen = CTLBLOCKLEN;
	}
	if (marklen < MARK_LENGTH) {
		marklen = MARK_LENGTH;
	}

	if (spec->lu->readonly
	    || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
		/* WRITE PROTECTED */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_DATA_PROTECT,
			    0x27, 0x00);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}
	if (!spec->bot) {
		/* PARAMETER VALUE INVALID */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_ILLEGAL_REQUEST,
			    0x26, 0x02);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}
	if (spec->lu->lun[spec->lun].type != ISTGT_LU_LUN_TYPE_REMOVABLE) {
		/* INTERNAL TARGET FAILURE */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_HARDWARE_ERROR,
			    0x44, 0x00);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	/* low I/O */
	if (fstat(fd, &st) == -1) {
		ISTGT_ERRLOG("fstat() failed\n");
	io_failure:
		/* LOGICAL UNIT FAILURE */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_HARDWARE_ERROR,
			    0x3e, 0x01);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	/* clear ctlblock + BOT + EOD */
	request_len = ctlblocklen + marklen * 2;
	spec->ctlblock->marks[1].offset = MARK_END;
	spec->ctlblock->marks[1].lbpos = MARK_END;
	spec->ctlblock->marks[1].prev = 0ULL;
	memset(data, 0, request_len);
	if (istgt_lu_tape_seek(spec, 0) == -1) {
		ISTGT_ERRLOG("lu_tape_lseek() failed\n");
		goto io_failure;
	}
	if ((uint64_t) istgt_lu_tape_write(spec, data, request_len) != request_len) {
		ISTGT_ERRLOG("lu_tape_write() failed\n");
		goto io_failure;
	}
	fsync(fd);
	/* initialize filemarks */
	newfile = 1;
	if (istgt_lu_tape_init_ctlblock(spec, newfile) < 0) {
		ISTGT_ERRLOG("lu_tape_init_ctlblock() failed\n");
		goto io_failure;
	}
	fsync(fd);

	if (S_ISREG(st.st_mode)) {
		/* media is file */
		/* truncate and extend */
		if (ftruncate(fd, request_len) == -1) {
			ISTGT_ERRLOG("ftruncate() failed\n");
			goto io_failure;
		}
		fsync(fd);
		if (mediaflags & ISTGT_LU_FLAG_MEDIA_DYNAMIC) {
			if (request_len < ISTGT_LU_MEDIA_SIZE_MIN) {
				request_len = ISTGT_LU_MEDIA_SIZE_MIN;
			}
			mediasize = request_len;
		}
		memset(data, 0, marklen);
		if (istgt_lu_tape_seek(spec, (mediasize - marklen)) == -1) {
			ISTGT_ERRLOG("lu_tape_seek() failed\n");
			goto io_failure;
		}
		if ((uint64_t) istgt_lu_tape_write(spec, data, marklen) != marklen) {
			ISTGT_ERRLOG("istgt_lu_tape_write() failed\n");
			goto io_failure;
		}
		fsync(fd);
		spec->size = mediasize;
	} else {
		/* media is not file */
		uint64_t offset, wlen, rest;
		/* clear with 256K */
		offset = request_len;
		wlen = 256*1024;
		memset(data, 0, wlen);
		for ( ; offset < mediasize - wlen; offset += wlen) {
			THREAD_YIELD;
			if ((uint64_t) istgt_lu_tape_write(spec, data, wlen) != wlen) {
				ISTGT_ERRLOG("lu_tape_write() failed\n");
				goto io_failure;
			}
		}
		/* clear rest size */
		rest = mediasize % wlen;
		if (rest != 0) {
			THREAD_YIELD;
			if ((uint64_t) istgt_lu_tape_write(spec, data, rest) != rest) {
				ISTGT_ERRLOG("lu_tape_write() failed\n");
				goto io_failure;
			}
		}
		THREAD_YIELD;
		fsync(fd);
	}

	/* rewind */
	istgt_lu_tape_rewind(spec);

	/* complete erase */
	lu_cmd->data_len = 0;
	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_tape_valid_mark_magic(tape_markblock_t *mbp)
{
	if (mbp == NULL)
		return 0;
	if (memcmp(mbp->magic, MARK_BOTMAGIC, MARK_MAGICLEN) == 0)
		return 1;
	if (memcmp(mbp->magic, MARK_EOTMAGIC, MARK_MAGICLEN) == 0)
		return 1;
	if (memcmp(mbp->magic, MARK_EOFMAGIC, MARK_MAGICLEN) == 0)
		return 1;
	if (memcmp(mbp->magic, MARK_EODMAGIC, MARK_MAGICLEN) == 0)
		return 1;
	if (memcmp(mbp->magic, MARK_DATAMAGIC, MARK_MAGICLEN) == 0)
		return 1;
	return 0;
}

static int
istgt_lu_tape_search_lbpos(ISTGT_LU_TAPE *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lbpos, uint8_t *data)
{
	tape_markblock_t *mbp;
	uint64_t tape_leader;
	uint64_t marklen, alignment, padlen;
	uint64_t lbpos1, offset1, lbpos2, offset2;
	uint64_t offset, prev;
	int found_lbpos = 0;
	int data_len;
	int index_i;
	int rc;
	int i;

	tape_leader = spec->ctlblock->ctlblocklen;
	marklen = spec->ctlblock->marklen;
	alignment = spec->ctlblock->alignment;

#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "search lbpos=%" PRIu64 "\n", lbpos);
#endif /* TAPE_DEBUG */
	/*  firset step, jump near position by EOF */
	index_i = -1;
	for (i = 0; i < MAX_FILEMARKS - 1; i++) {
		offset1 = spec->ctlblock->marks[i].offset;
		offset2 = spec->ctlblock->marks[i + 1].offset;
		lbpos1 = spec->ctlblock->marks[i].lbpos;
		lbpos2 = spec->ctlblock->marks[i + 1].lbpos;
		if (offset1 == MARK_END) {
			/* no more marks */
			break;
		}
		if (offset2 == MARK_END) {
			/* adjust to real media size */
			offset2 = spec->size;
		}
		/* lbpos within EOFs? */
		if (lbpos >= lbpos1 && lbpos < lbpos2) {
			index_i = i;
			break;
		}
	}
	if (index_i < 0) {
		/* END-OF-PARTITION/MEDIUM DETECTED */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_MEDIUM_ERROR,
			    0x00, 0x02);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	/* next step, search in file */
	ASSERT_PTR_ALIGN64(data);
	mbp = (tape_markblock_t *) ((uintptr_t)data);
	prev = spec->ctlblock->marks[index_i].prev;
	found_lbpos = 0;
	for (offset = offset1; offset < offset2; ) {
		if (istgt_lu_tape_seek(spec, (tape_leader + offset)) == -1) {
			ISTGT_ERRLOG("lu_tape_seek() failed\n");
			break;
		}
		rc = istgt_lu_tape_read_native_mark(spec, mbp);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_tape_read_native_mark() failed: rc %d\n", rc);
			break;
		}
		/* check in logical block */
		if (!istgt_lu_tape_valid_mark_magic(mbp)) {
			ISTGT_ERRLOG("bad magic offset %" PRIu64 "\n", offset);
			break;
		}
#ifdef TAPE_DEBUG
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "read mlbpos=%" PRIu64 ", mlblen=%" PRIu64 ", moffset=%" PRIu64 ", offset=%" PRIu64 ", index=%d\n",
		    mbp->lbpos, mbp->lblen, mbp->offset, offset, index_i);
#endif /* TAPE_DEBUG */
		if (lbpos == mbp->lbpos) {
			found_lbpos = 1;
			offset = mbp->offset;
			break;
		}

		/* next offset to read */
		prev = offset;
		offset += marklen + mbp->lblen;
		if (offset % alignment) {
			padlen = alignment;
			padlen -= offset % alignment;
			offset += padlen;
		}
	}
	if (!found_lbpos) {
		/* within EOFs, but not found */
		/* INTERNAL TARGET FAILURE */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_HARDWARE_ERROR,
			    0x44, 0x00);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "set lbpos=%" PRIu64 ", offset=%" PRIu64 ", index=%d\n", lbpos, offset, index_i);
#endif /* TAPE_DEBUG */
	/* update information */
	spec->index = index_i;
	spec->lbpos = lbpos;
	spec->prev = prev;
	spec->offset = offset;

	spec->bot = spec->eof = spec->eod = spec->eom = 0;
	if (index_i == 0 && offset == 0) {
		spec->bot = 1;
	} else if (offset == spec->ctlblock->marks[index_i].offset) {
		if (offset == MARK_END) {
			spec->eom = 1;
		} else {
			spec->eof = 1;
		}
	}

	/* complete search, new position to lbpos */
	lu_cmd->data_len = 0;
	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_tape_search_lbpos_fast_reverse(ISTGT_LU_TAPE *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lbpos, int count, uint8_t *data __attribute__((__unused__)))
{
	uint64_t xlbpos, offset, prev;
	int index_i;

	xlbpos = spec->lbpos;
	offset = spec->offset;
	prev = spec->prev;
	index_i = spec->index;

	/* now only support -1 */
	if (count != -1)
		return -1;

	/* END mark is special */
	if (offset == MARK_END
	    || spec->ctlblock->marks[index_i].offset == MARK_END
	    || spec->ctlblock->marks[index_i + 1].offset == MARK_END)
		return -1;

	/* this lbpos have previous offset? */
	if (lbpos != xlbpos)
		return -1;
	if (offset == spec->ctlblock->marks[index_i + 1].offset
		&& spec->ctlblock->marks[index_i + 1].prev != 0ULL) {
		/* get from EOF mark */
		offset = spec->ctlblock->marks[index_i + 1].prev;
		lbpos = spec->ctlblock->marks[index_i + 1].lbpos;
		lbpos--;
		prev = 0ULL;

#ifdef TAPE_DEBUG
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "set lbpos=%" PRIu64 ", offset=%" PRIu64 ", index=%d\n", lbpos, offset, index_i);
#endif /* TAPE_DEBUG */
		/* update information */
		spec->index = index_i;
		spec->lbpos = lbpos;
		spec->prev = prev;
		spec->offset = offset;

		spec->bot = spec->eof = spec->eod = spec->eom = 0;
		if (index_i == 0 && offset == 0) {
			spec->bot = 1;
		} else if (offset == spec->ctlblock->marks[index_i].offset) {
			if (offset == MARK_END) {
				spec->eom = 1;
			} else {
				spec->eof = 1;
			}
		}

		/* complete search, new position to lbpos */
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		return 0;
	}

	/* no method for fast reverse */
	return -1;
}

static int
istgt_lu_tape_scsi_space(ISTGT_LU_TAPE *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, int code, int count, uint8_t *data)
{
	uint64_t lbpos, offset, prev;
	int found_bot = 0, found_eom = 0;
	int data_len;
	int index_i;
	int i;

	if (code != 0x03 && count == 0) {
		/* no-op except EOD */
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		return 0;
	}

	lbpos = spec->lbpos;
	offset = spec->offset;
	prev = spec->prev;
	index_i = spec->index;

	if (code == 0x00) {
		/* Logical blocks */
		if (count < 0) {
			/* reverse */
			/* first check search cache etc. */
			data_len
				= istgt_lu_tape_search_lbpos_fast_reverse(spec, conn, lu_cmd,
				    lbpos, count, data);
			if (data_len > 0) {
				/* scsi condition met */
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return data_len;
			} else if (data_len == 0) {
				/* found position */
				lu_cmd->data_len = 0;
				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				return 0;
			}
			count = -count;
			if (lbpos < (uint64_t) count) {
				lbpos = 0ULL;
			} else {
				lbpos -= (uint64_t) count;
			}
		} else if (count > 0) {
			/* forward */
			if ((uint64_t) count > LBPOS_MAX - lbpos) {
				lbpos = LBPOS_MAX;
			} else {
				lbpos += (uint64_t) count;
			}
		} 

		/* search in file (logical blocks) */
		data_len = istgt_lu_tape_search_lbpos(spec, conn, lu_cmd, lbpos, data);
		if (data_len != 0) {
			/* sense data build by function */
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return data_len;
		}
	} else if (code == 0x01) {
		/* Filemarks */
		if (count < 0) {
			/* reverse */
			for (i = 0; i > count; i--) {
				if (index_i + i == 0) {
					found_bot = 1;
					break;
				}
			}
			index_i += i;
			offset = spec->ctlblock->marks[index_i].offset;
			if (offset == MARK_END) {
				/* INTERNAL TARGET FAILURE */
				data_len
					= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
					    ISTGT_SCSI_SENSE_HARDWARE_ERROR,
					    0x44, 0x00);
				lu_cmd->sense_data_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return data_len;
			}
			/* position to EOF */
			lbpos = spec->ctlblock->marks[index_i + 1].lbpos;
			offset = spec->ctlblock->marks[index_i + 1].offset;
			prev = spec->ctlblock->marks[index_i + 1].prev;
		} else if (count > 0) {
			/* forward */
			for (i = 0; i < count; i++) {
				if (spec->ctlblock->marks[index_i + i].offset == MARK_END) {
					found_eom = 1;
					break;
				}
			}
			index_i += i;
			offset = spec->ctlblock->marks[index_i].offset;
			if (found_eom || offset == MARK_END) {
				/* END-OF-DATA DETECTED */
				data_len
					= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
					    ISTGT_SCSI_SENSE_BLANK_CHECK,
					    0x00, 0x05);
				DSET32(&data[2+3], (uint32_t) count - i);
				lu_cmd->sense_data_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return data_len;
			}
			lbpos = spec->ctlblock->marks[index_i].lbpos;
			/* position to next block of EOF */
			prev = offset;
			offset += spec->ctlblock->marklen;
			lbpos++;
		}

#ifdef TAPE_DEBUG
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "set lbpos=%" PRIu64 ", offset=%" PRIu64 ", index=%d\n", lbpos, offset, index_i);
#endif /* TAPE_DEBUG */
		/* update information */
		spec->index = index_i;
		spec->lbpos = lbpos;
		spec->prev = prev;
		spec->offset = offset;

		spec->bot = spec->eof = spec->eod = spec->eom = 0;
		if (index_i == 0 && offset == 0) {
			spec->bot = 1;
		} else if (offset == spec->ctlblock->marks[index_i].offset) {
			if (offset == MARK_END) {
				spec->eom = 1;
			} else {
				spec->eof = 1;
			}
		}
	} else if (code == 0x03) {
		/* End-of-data */
		index_i = -1;
		for (i = 0; i < MAX_FILEMARKS ; i++) {
			if (spec->ctlblock->marks[i].offset == MARK_END) {
				index_i = i;
				break;
			}
		}
		if (index_i <= 0) {
			/* INTERNAL TARGET FAILURE */
			data_len
				= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
				    ISTGT_SCSI_SENSE_HARDWARE_ERROR,
				    0x44, 0x00);
			lu_cmd->sense_data_len = data_len;
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return data_len;
		}

		/* skip EOT (position to last EOF) */
		index_i--;
		lbpos = spec->ctlblock->marks[index_i].lbpos;
		offset = spec->ctlblock->marks[index_i].offset;
		/* position to next block of EOF */
		prev = offset;
		offset += spec->ctlblock->marklen;
		lbpos++;

#ifdef TAPE_DEBUG
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "set lbpos=%" PRIu64 ", offset=%" PRIu64 ", index=%d\n", lbpos, offset, index_i);
#endif /* TAPE_DEBUG */
		/* update information */
		spec->index = index_i;
		spec->lbpos = lbpos;
		spec->prev = prev;
		spec->offset = offset;

		spec->bot = spec->eof = spec->eod = spec->eom = 0;
		if (index_i == 0 && offset == 0) {
			spec->bot = 1;
		} else if (offset == spec->ctlblock->marks[index_i].offset) {
			if (offset == MARK_END) {
				spec->eom = 1;
			} else {
				spec->eof = 1;
			}
		}
	} else {
		/* INVALID FIELD IN CDB */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_ILLEGAL_REQUEST,
			    0x24, 0x00);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return data_len;
	}

	/* complete space command, new position to lbpos */
	lu_cmd->data_len = 0;
	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_tape_scsi_locate(ISTGT_LU_TAPE *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint32_t loi, uint8_t *data)
{
	uint64_t lbpos;
	int data_len;

	if (loi == 0) {
		/* position to zero (BOT) */
		istgt_lu_tape_rewind(spec);
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		return 0;
	}

	lbpos = (uint64_t) loi;

	/* search logical block */
	data_len = istgt_lu_tape_search_lbpos(spec, conn, lu_cmd, lbpos, data);
	if (data_len != 0) {
		/* sense data build by function */
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return data_len;
	}

	/* complete locate command, new position to lbpos */
	lu_cmd->data_len = 0;
	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_tape_scsi_read_position(ISTGT_LU_TAPE *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd, int sa, uint8_t *data)
{
	uint64_t lbpos;
	int data_len;

	lbpos = spec->lbpos;

	switch (sa) {
	case 0x00:
		/* 0x00 SHORT FORM -- BLOCK ID */
	case 0x01:
		/* 0x01 SHORT FORM -- VENDOR-SPECIFIC */
		data_len = 20;
		memset(&data[0], 0, data_len);

		/* BOP(7) EOP(6) LOCU(5) BYCU(4) LOLU(2) PERR(1) */
		/* only one partision is supported, BOT/EOT equal BOP/EOP */
		if (lbpos == 0ULL) {
			BSET8(&data[0], 7);      /* BOP=1 */
		}
		if (spec->eom) {
			BSET8(&data[0], 6);      /* EOP=1 */
		}
		/* logical object count unknown */
		BSET8(&data[0], 5);         /* LOCU=1 */
		/* byte count unknown */
		BSET8(&data[0], 4);         /* BYCU=1 */
		/* logical object location unknown */
		//BSET8(&data[0], 2);         /* LOLU=1 */
		if (lbpos > 0xffffffffULL) {
			BSET8(&data[0], 0);     /* PERR=1 */
		}

		/* PARTITION NUMBER */
		data[1] = 0;
		/* FIRST LOGICAL OBJECT LOCATION */
		DSET32(&data[4], (uint32_t)lbpos);
		/* LAST LOGICAL OBJECT LOCATION */
		DSET32(&data[8], 0);
		/* NUMBER OF LOGICAL OBJECTS IN OBJECT BUFFER */
		DSET24(&data[13], 0);
		/* NUMBER OF BYTES IN OBJECT BUFFER */
		DSET32(&data[16], 0);
		break;

	case 0x06:
		/* LONG FORM */
		data_len = 32;
		memset(&data[0], 0, data_len);

		/* BOP(7) EOP(6) MPU(3) LONU(2) */
		/* only one partision is supported, BOT/EOT equal BOP/EOP */
		if (lbpos == 0ULL) {
			BSET8(&data[0], 7);      /* BOP=1 */
		}
		if (spec->eom) {
			BSET8(&data[0], 6);      /* EOP=1 */
		}

		/* mark position unknown */
		BSET8(&data[0], 3);         /* MPU=1 */
		/* logical object number unknown */
		//BSET8(&data[0], 2);         /* LONU=1 */

		/* PARTITION NUMBER */
		DSET32(&data[4], 0);
		/* LOGICAL OBJECT NUMBER */
		DSET64(&data[8], lbpos);
		/* LOGICAL FILE IDENTIFIER */
		DSET64(&data[16], 0ULL);
		/* LOGICAL SET IDENTIFIER */
		DSET64(&data[24], 0ULL);
		break;

	default:
		/* INVALID FIELD IN CDB */
		data_len
			= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_ILLEGAL_REQUEST,
			    0x24, 0x00);
		lu_cmd->sense_data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	lu_cmd->data_len = data_len;
	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_tape_build_sense_data(ISTGT_LU_TAPE *spec, uint8_t *data, int sk, int asc, int ascq)
{
	uint8_t *cp;
	int hlen = 0, len = 0, plen;
	int total;
	int data_len;

	data_len = istgt_lu_scsi_build_sense_data(data, sk, asc, ascq);
	hlen = 2;
	if (data_len < (hlen + 18)) {
		return data_len;
	}

	cp = &data[hlen + len];
	len = 8;

	/* FILEMARK(7) EOM(6) ILI(5) SENSE KEY(3-0) */
	if (spec != NULL && spec->eof) {
		BSET8(&cp[2], 7); /* FILEMARK=1 */
	}
	if (spec != NULL && spec->eom) {
		BSET8(&cp[2], 6); /* EOM=1 */
	}

	/* Additional sense bytes */

	/* for DLT8000 */
	/* Internal Status Code */
	cp[18] = 0;
	//cp[18] = 0x86; /* Directory Bad */
	/* Tape Motion Hours */
	DSET16(&cp[19], 0);
	/* Power On Hours */
	DSET32(&cp[21], 0);
	/* Tape Remaining */
	DSET32(&cp[25], 0);
	//DSET32(&cp[25], (uint32_t) (spec->size / spec->ctlblock->blocklen));
	/* Reserved */
	cp[29] = 0;
	plen = 30 - len;

	/* ADDITIONAL SENSE LENGTH */
	cp[7] = plen;

	total = hlen + len + plen;

	/* SenseLength */
	DSET16(&data[0], total - 2);

	return total;
}

static int
istgt_lu_tape_build_sense_media(ISTGT_LU_TAPE *spec, uint8_t *data)
{
	uint8_t *sense_data;
	int *sense_len;
	int data_len;

	sense_data = data;
	sense_len = &data_len;
	*sense_len = 0;

	if (!spec->mload && !spec->mchanged) {
		/* MEDIUM NOT PRESENT */
		BUILD_SENSE(NOT_READY, 0x3a, 0x00);
		return data_len;
	}
	if (spec->mchanged) {
		/* MEDIUM NOT PRESENT */
		BUILD_SENSE(NOT_READY, 0x3a, 0x00);
		return data_len;
#if 0
		/* LOGICAL UNIT NOT READY, CAUSE NOT REPORTABLE */
		BUILD_SENSE(NOT_READY, 0x04, 0x00);
		return data_len;
		/* LOGICAL UNIT IS IN PROCESS OF BECOMING READY */
		BUILD_SENSE(NOT_READY, 0x04, 0x01);
		return data_len;
#endif
	}
	return 0;
}

static int
istgt_lu_tape_variable_lbread(ISTGT_LU_TAPE *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lblen)
{
	tape_markblock_t *mbp;
	uint8_t *data;
	uint64_t mediasize;
	uint64_t tape_leader;
	uint64_t marklen, alignment, padlen;
	uint64_t lbpos, offset, prev;
	uint64_t blen;
	uint64_t total;
	uint64_t request_len;
	uint32_t u;
	int64_t rc;

	mediasize = spec->size;
	tape_leader = spec->ctlblock->ctlblocklen;
	marklen = spec->ctlblock->marklen;
	alignment = spec->ctlblock->alignment;
	lbpos = spec->lbpos;
	offset = spec->offset;
	ASSERT_PTR_ALIGN64(lu_cmd->iobuf);
	mbp = (tape_markblock_t *) ((uintptr_t)lu_cmd->iobuf);
	data = (uint8_t *) lu_cmd->iobuf + marklen;
	total = 0ULL;
	u = 0;
	/* header + data + EOD */
	request_len = marklen + lblen + marklen;
	spec->info = (uint32_t) lblen;

#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_LU, "Read: %"PRIu64" (%"PRIu64")\n",
	    lblen, offset);
#endif /* TAPE_DEBUG */

	if (request_len > lu_cmd->iobufsize) {
		ISTGT_ERRLOG("request_len(%"PRIu64") > iobufsize(%zu)\n",
		    request_len, lu_cmd->iobufsize);
		return -1;
	}

	/* read media check */
	if (istgt_lu_tape_read_media_check(spec, conn, lu_cmd, request_len) < 0) {
		/* INFORMATION */
		DSET32(&lu_cmd->sense_data[2+3], (uint32_t) spec->info);
		/* not I/O error */
		return 0;
	}

	/* position to virtual tape mark */
	if (istgt_lu_tape_seek(spec, (tape_leader + offset)) == -1) {
		ISTGT_ERRLOG("lu_tape_seek() failed\n");
		return -1;
	}
	/* virtual tape mark */
	rc = istgt_lu_tape_read_native_mark(spec, mbp);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_tape_read_native_mark() failed\n");
		return -1;
	}
	if (!istgt_lu_tape_valid_mark_magic(mbp)) {
		ISTGT_ERRLOG("bad magic offset %"PRIu64"\n", offset);
		return -1;
	}
	if (lbpos != mbp->lbpos) {
		ISTGT_ERRLOG("bad position offset %"PRIu64" lbpos %"PRIu64
		    " mlbpos %"PRIu64"\n", offset, lbpos, mbp->lbpos);
		return -1;
	}
	if (memcmp(mbp->magic, MARK_EOFMAGIC, MARK_MAGICLEN) == 0) {
#ifdef TAPE_DEBUG
		ISTGT_TRACELOG(ISTGT_TRACE_LU, "EOF found\n");
#endif /* TAPE_DEBUG */
		/* EOF detected */
		spec->eof = 1;
		goto early_return;
	}
	if (memcmp(mbp->magic, MARK_EODMAGIC, MARK_MAGICLEN) == 0) {
#ifdef TAPE_DEBUG
		ISTGT_TRACELOG(ISTGT_TRACE_LU, "EOD found\n");
#endif /* TAPE_DEBUG */
		/* EOD detected */
		spec->eod = 1;
		goto early_return;
	}
	/* user data */
	rc = istgt_lu_tape_read(spec, data + total, mbp->lblen);
	if (rc < 0 || (uint64_t) rc != mbp->lblen) {
		ISTGT_ERRLOG("lu_tape_read() failed: rc %"PRId64"\n", rc);
		return -1;
	}
#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_LU, "read mlbpos=%"PRIu64", lblen=%"PRIu64
	    ", offset=%"PRIu64"\n", mbp->lbpos, mbp->lblen, offset);
#endif /* TAPE_DEBUG */
	/* 1 block OK */
	spec->info -= (uint32_t) lblen;
	/* next offset to read */
	prev = offset;
	offset += marklen + mbp->lblen;
	if (offset % alignment) {
		padlen = alignment;
		padlen -= offset % alignment;
		offset += padlen;
	}
	lbpos++;
	/* update information */
	spec->lbpos = lbpos;
	spec->prev = prev;
	spec->offset = offset;

	if (lblen > mbp->lblen) {
		blen = mbp->lblen;
	} else {
		blen = lblen;
	}
#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_LU, "Read %"PRIu64" bytes\n", blen);
#endif /* TAPE_DEBUG */
	total += blen;
	u++;

 early_return:
#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_LU, "Read %"PRIu64" bytes total\n", total);
#endif /* TAPE_DEBUG */
	lu_cmd->data = data;
	lu_cmd->data_len = total;
	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_tape_fixed_lbread(ISTGT_LU_TAPE *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lblen, uint32_t count)
{
	tape_markblock_t *mbp;
	uint8_t *data;
	uint64_t mediasize;
	uint64_t tape_leader;
	uint64_t marklen, alignment, padlen;
	uint64_t lbpos, offset, prev;
	uint64_t blen;
	uint64_t total;
	uint64_t request_len;
	uint64_t rest;
	uint32_t u;
	int data_len;
	int64_t rc;

	mediasize = spec->size;
	tape_leader = spec->ctlblock->ctlblocklen;
	marklen = spec->ctlblock->marklen;
	alignment = spec->ctlblock->alignment;
	lbpos = spec->lbpos;
	offset = spec->offset;
	ASSERT_PTR_ALIGN64(lu_cmd->iobuf);
	mbp = (tape_markblock_t *) ((uintptr_t)lu_cmd->iobuf);
	data = (uint8_t *) lu_cmd->iobuf + marklen;
	total = 0ULL;
	/* (header + data) x N + EOD */
	request_len = ((marklen + lblen) * (uint64_t) count) + marklen;
	spec->info = count;

#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_LU, "Read: %"PRIu64" x %u (%"PRIu64")\n",
	    lblen, count, offset);
#endif /* TAPE_DEBUG */

	if (request_len > lu_cmd->iobufsize) {
		ISTGT_ERRLOG("request_len(%"PRIu64") > iobufsize(%zu)\n",
		    request_len, lu_cmd->iobufsize);
		return -1;
	}

	/* read media check */
	if (istgt_lu_tape_read_media_check(spec, conn, lu_cmd, request_len) < 0) {
		/* INFORMATION */
		DSET32(&lu_cmd->sense_data[2+3], (uint32_t) spec->info);
		/* not I/O error */
		return 0;
	}

	/* position to virtual tape mark */
	if (istgt_lu_tape_seek(spec, (tape_leader + offset)) == -1) {
		ISTGT_ERRLOG("lu_tape_seek() failed\n");
		return -1;
	}

	rest = 0ULL;
	/* read N blocks */
	for (u = 0; u < count; u++) {
		if (rest == 0) {
			/* virtual tape mark */
			rc = istgt_lu_tape_read_native_mark(spec, mbp);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_tape_read_native_mark() failed\n");
				return -1;
			}
			if (!istgt_lu_tape_valid_mark_magic(mbp)) {
				ISTGT_ERRLOG("bad magic offset %"PRIu64"\n", offset);
				return -1;
			}
			if (lbpos != mbp->lbpos) {
				ISTGT_ERRLOG("bad position offset %"PRIu64" lbpos %"PRIu64
				    " mlbpos %"PRIu64"\n", offset, lbpos, mbp->lbpos);
				return -1;
			}
			if (memcmp(mbp->magic, MARK_EOFMAGIC, MARK_MAGICLEN) == 0) {
#ifdef TAPE_DEBUG
				ISTGT_TRACELOG(ISTGT_TRACE_LU, "EOF found\n");
#endif /* TAPE_DEBUG */
				/* EOF detected */
				spec->eof = 1;
				goto early_return;
			}
			if (memcmp(mbp->magic, MARK_EODMAGIC, MARK_MAGICLEN) == 0) {
#ifdef TAPE_DEBUG
				ISTGT_TRACELOG(ISTGT_TRACE_LU, "EOD found\n");
#endif /* TAPE_DEBUG */
				/* EOD detected */
				spec->eod = 1;
				goto early_return;
			}
			/* user data */
			rc = istgt_lu_tape_read(spec, data + total, mbp->lblen);
			if (rc < 0 || (uint64_t) rc != mbp->lblen) {
				ISTGT_ERRLOG("lu_tape_read() failed: rc %"PRId64"\n", rc);
				return -1;
			}
#ifdef TAPE_DEBUG
			ISTGT_TRACELOG(ISTGT_TRACE_LU, "read mlbpos=%"PRIu64", lblen=%"
			    PRIu64", offset=%"PRIu64"\n",
			    mbp->lbpos, mbp->lblen, offset);
#endif /* TAPE_DEBUG */
			rest = mbp->lblen;
		}
		/* check logical block size */
		if ((rest > lblen * (count - u))
			|| rest < lblen) {
			/* incorrect length */
			data_len
				= istgt_lu_tape_build_sense_data(spec, lu_cmd->sense_data,
				    ISTGT_SCSI_SENSE_NO_SENSE,
				    0x00, 0x00);
			BSET8(&lu_cmd->sense_data[2+2], 5); /* ILI=1 */
			//spec->info = count - u;
			/* INFORMATION */
			DSET32(&lu_cmd->sense_data[2+3], spec->info);
			lu_cmd->sense_data_len = data_len;
			lu_cmd->data = data;
			lu_cmd->data_len = total;
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		} else {
			/* 1 block OK */
			spec->info--;
			rest -= lblen;
			blen = lblen;
		}

		/* buffer empty? */
		if (rest == 0) {
			/* next offset to read */
			prev = offset;
			offset += marklen + mbp->lblen;
			if (offset % alignment) {
				padlen = alignment;
				padlen -= offset % alignment;
				offset += padlen;
			}
			lbpos++;
			/* update information */
			spec->lbpos = lbpos;
			spec->prev = prev;
			spec->offset = offset;
		}

#ifdef TAPE_DEBUG
		ISTGT_TRACELOG(ISTGT_TRACE_LU, "Read %"PRIu64" bytes\n", blen);
#endif /* TAPE_DEBUG */
		total += blen;
	}

 early_return:
#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_LU, "Read %"PRIu64" bytes total\n", total);
#endif /* TAPE_DEBUG */
	lu_cmd->data = data;
	lu_cmd->data_len = total;
	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_tape_variable_lbwrite(ISTGT_LU_TAPE *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lblen)
{
	tape_markblock_t *mbp;
	uint8_t *data;
	uint64_t mediasize;
	uint64_t tape_leader;
	uint64_t marklen, alignment, padlen;
	uint64_t lbpos, offset, prev;
	uint64_t total;
	uint64_t request_len;
	int64_t rc;

	mediasize = spec->size;
	tape_leader = spec->ctlblock->ctlblocklen;
	marklen = spec->ctlblock->marklen;
	alignment = spec->ctlblock->alignment;
	lbpos = spec->lbpos;
	offset = spec->offset;
	prev = spec->prev;
	ASSERT_PTR_ALIGN64(lu_cmd->iobuf);
	mbp = (tape_markblock_t *) ((uintptr_t)lu_cmd->iobuf);
	data = (uint8_t *) lu_cmd->iobuf + marklen;
	total = 0ULL;
	/* header + data + EOD */
	request_len = marklen + lblen + marklen;
	spec->info = (uint32_t) lblen;

#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_LU, "Write: %"PRIu64" (%"PRIu64")\n",
	    lblen, offset);
#endif /* TAPE_DEBUG */

	if (request_len > lu_cmd->iobufsize) {
		ISTGT_ERRLOG("request_len(%"PRIu64") > iobufsize(%zu)\n",
		    request_len, lu_cmd->iobufsize);
		return -1;
	}

	/* prepare mark */
	memset(mbp, 0, marklen);
	memcpy(mbp->magic, MARK_DATAMAGIC, MARK_MAGICLEN);
	mbp->endian = MARK_ENDIAN;
	mbp->version = MARK_VERSION;
	mbp->marklen = marklen;
	mbp->lblen = lblen;
	if (spec->compression) {
		/* not supported yet */
		mbp->compalgo = spec->compalgo;
		mbp->vtcompalgo = MARK_COMPALGO_NONE;
		mbp->vtdecomplen = 0ULL;
	} else {
		mbp->compalgo = 0ULL;
		mbp->vtcompalgo = MARK_COMPALGO_NONE;
		mbp->vtdecomplen = 0ULL;
	}

	mbp->lbpos = lbpos;
	mbp->offset = offset;
	mbp->prev = prev;

	/* DATAOUT */
	rc = istgt_lu_tape_transfer_data(conn, lu_cmd, data,
	    lu_cmd->iobufsize - marklen, lblen);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_tape_transfer_data() failed\n");
		return -1;
	}

	/* write media check */
	if (istgt_lu_tape_write_media_check(spec, conn, lu_cmd, request_len) < 0) {
		/* INFORMATION */
		DSET32(&lu_cmd->sense_data[2+3], (uint32_t) spec->info);
		/* not I/O error */
		return 0;
	}

	/* position to virtual tape mark */
	if (istgt_lu_tape_seek(spec, (tape_leader + offset)) == -1) {
		ISTGT_ERRLOG("lu_tape_seek() failed\n");
		return -1;
	}
#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_LU, "write mlbpos=%"PRIu64", lblen=%"PRIu64
	    ", offset=%"PRIu64"\n", mbp->lbpos, mbp->lblen, offset);
#endif /* TAPE_DEBUG */
	/* virtual tape mark */
	rc = istgt_lu_tape_write_native_mark(spec, mbp);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_tape_write_native_mark() failed\n");
		return -1;
	}
	/* user data */
	rc = istgt_lu_tape_write(spec, data + total, lblen);
	if ((uint64_t) rc != lblen) {
		ISTGT_ERRLOG("lu_tape_write() failed\n");
		return -1;
	}
	/* 1 block OK */
	spec->info -= (uint32_t) lblen;
	/* next offset to read */
	prev = offset;
	offset += marklen + mbp->lblen;
	if (offset % alignment) {
		padlen = alignment;
		padlen -= offset % alignment;
		offset += padlen;
	}
	lbpos++;
	/* update information */
	spec->lbpos = lbpos;
	spec->prev = prev;
	spec->offset = offset;

	mbp->lbpos = lbpos;
	mbp->offset = offset;
	mbp->prev = prev;

	total += lblen;

#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_LU, "Wrote %"PRIu64" bytes\n", total);
#endif /* TAPE_DEBUG */
	lu_cmd->data_len = total;
	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_tape_fixed_lbwrite(ISTGT_LU_TAPE *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lblen, uint32_t count)
{
	tape_markblock_t *mbp;
	uint8_t *data;
	uint64_t mediasize;
	uint64_t tape_leader;
	uint64_t marklen, alignment, padlen;
	uint64_t lbpos, offset, prev;
	uint64_t total;
	uint64_t request_len;
	uint32_t u;
	int64_t rc;

	mediasize = spec->size;
	tape_leader = spec->ctlblock->ctlblocklen;
	marklen = spec->ctlblock->marklen;
	alignment = spec->ctlblock->alignment;
	lbpos = spec->lbpos;
	offset = spec->offset;
	prev = spec->prev;
	ASSERT_PTR_ALIGN64(lu_cmd->iobuf);
	mbp = (tape_markblock_t *) ((uintptr_t)lu_cmd->iobuf);
	data = (uint8_t *) lu_cmd->iobuf + marklen;
	total = 0ULL;
	/* (header + data) x N + EOD */
	request_len = ((marklen + lblen) * (uint64_t) count) + marklen;
	spec->info = count;

#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_LU, "Write: %"PRIu64" (%"PRIu64")\n",
	    lblen, offset);
#endif /* TAPE_DEBUG */

	if (request_len > lu_cmd->iobufsize) {
		ISTGT_ERRLOG("request_len(%"PRIu64") > iobufsize(%zu)\n",
		    request_len, lu_cmd->iobufsize);
		return -1;
	}

	/* prepare mark */
	memset(mbp, 0, marklen);
	memcpy(mbp->magic, MARK_DATAMAGIC, MARK_MAGICLEN);
	mbp->endian = MARK_ENDIAN;
	mbp->version = MARK_VERSION;
	mbp->marklen = marklen;
	mbp->lblen = lblen;
	if (spec->compression) {
		/* not supported yet */
		mbp->compalgo = spec->compalgo;
		mbp->vtcompalgo = MARK_COMPALGO_NONE;
		mbp->vtdecomplen = 0ULL;
	} else {
		mbp->compalgo = 0ULL;
		mbp->vtcompalgo = MARK_COMPALGO_NONE;
		mbp->vtdecomplen = 0ULL;
	}

	mbp->lbpos = lbpos;
	mbp->offset = offset;
	mbp->prev = prev;

	/* DATAOUT */
	rc = istgt_lu_tape_transfer_data(conn, lu_cmd, data,
	    lu_cmd->iobufsize - marklen, lblen * count);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_tape_transfer_data() failed\n");
		return -1;
	}

	/* write media check */
	if (istgt_lu_tape_write_media_check(spec, conn, lu_cmd, request_len) < 0) {
		/* INFORMATION */
		DSET32(&lu_cmd->sense_data[2+3], (uint32_t) spec->info);
		/* not I/O error */
		return 0;
	}

	/* position to virtual tape mark */
	if (istgt_lu_tape_seek(spec, (tape_leader + offset)) == -1) {
		ISTGT_ERRLOG("lu_tape_seek() failed\n");
		return -1;
	}
	/* write N blocks */
	for (u = 0; u < count; u++) {
#ifdef TAPE_DEBUG
		ISTGT_TRACELOG(ISTGT_TRACE_LU, "write mlbpos=%"PRIu64", lblen=%"PRIu64
		    ", offset=%"PRIu64"\n", mbp->lbpos, mbp->lblen, offset);
#endif /* TAPE_DEBUG */
		/* virtual tape mark */
		rc = istgt_lu_tape_write_native_mark(spec, mbp);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_tape_write_native_mark() failed\n");
			return -1;
		}
		/* user data */
		rc = istgt_lu_tape_write(spec, data + total, lblen);
		if ((uint64_t) rc != lblen) {
			ISTGT_ERRLOG("lu_tape_write() failed\n");
			return -1;
		}
		/* 1 block OK */
		spec->info--;
		/* next offset to read */
		prev = offset;
		offset += marklen + mbp->lblen;
		if (offset % alignment) {
			padlen = alignment;
			padlen -= offset % alignment;
			offset += padlen;
		}
		lbpos++;
		/* update information */
		spec->lbpos = lbpos;
		spec->prev = prev;
		spec->offset = offset;

		mbp->lbpos = lbpos;
		mbp->offset = offset;
		mbp->prev = prev;

		total += lblen;
	}

#ifdef TAPE_DEBUG
	ISTGT_TRACELOG(ISTGT_TRACE_LU, "Wrote %"PRIu64" bytes\n", total);
#endif /* TAPE_DEBUG */
	lu_cmd->data_len = total;
	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

int
istgt_lu_tape_reset(ISTGT_LU_Ptr lu, int lun)
{
	ISTGT_LU_TAPE *spec;
	int flags;
	int rc;

	if (lu == NULL) {
		return -1;
	}
	if (lun >= lu->maxlun) {
		return -1;
	}
	if (lu->lun[lun].type == ISTGT_LU_LUN_TYPE_NONE) {
		return -1;
	}
	if (lu->lun[lun].type != ISTGT_LU_LUN_TYPE_REMOVABLE) {
		return -1;
	}
	spec = (ISTGT_LU_TAPE *) lu->lun[lun].spec;

	if (spec->lock) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "unlock by reset\n");
		spec->lock = 0;
	}

	/* re-open file */
	if (!spec->lu->readonly
	    && !(spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
		rc = istgt_lu_tape_sync(spec, 0, spec->size);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: LUN%d: lu_tape_sync() failed\n",
			    lu->num, lun);
			/* ignore error */
		}
	}
	rc = istgt_lu_tape_close(spec);
	if (rc < 0) {
		ISTGT_ERRLOG("LU%d: LUN%d: lu_tape_close() failed\n",
		    lu->num, lun);
		/* ignore error */
	}
	flags = (lu->readonly || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY))
		? O_RDONLY : O_RDWR;
	rc = istgt_lu_tape_open(spec, flags, 0666);
	if (rc < 0) {
		ISTGT_ERRLOG("LU%d: LUN%d: lu_tape_open() failed\n",
		    lu->num, lun);
		return -1;
	}

	return 0;
}

int
istgt_lu_tape_execute(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	ISTGT_LU_Ptr lu;
	ISTGT_LU_TAPE *spec;
	uint8_t *data;
	uint8_t *cdb;
	uint64_t fmt_lun;
	uint64_t lun;
	uint64_t method;
	uint32_t allocation_len;
	int data_len;
	int data_alloc_len;
	uint32_t transfer_len;
	uint8_t *sense_data;
	size_t *sense_len;
	int rc;

	if (lu_cmd == NULL)
		return -1;
	lu = lu_cmd->lu;
	if (lu == NULL) {
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}
	spec = NULL;
	cdb = lu_cmd->cdb;
	data = lu_cmd->data;
	data_alloc_len = lu_cmd->alloc_len;
	sense_data = lu_cmd->sense_data;
	sense_len = &lu_cmd->sense_data_len;
	*sense_len = 0;

	fmt_lun = lu_cmd->lun;
	method = (fmt_lun >> 62) & 0x03U;
	fmt_lun = fmt_lun >> 48;
	if (method == 0x00U) {
		lun = fmt_lun & 0x00ffU;
	} else if (method == 0x01U) {
		lun = fmt_lun & 0x3fffU;
	} else {
		lun = 0xffffU;
	}
	if (lun >= (uint64_t) lu->maxlun) {
#ifdef ISTGT_TRACE_TAPE
		ISTGT_ERRLOG("LU%d: LUN%4.4"PRIx64" invalid\n",
		    lu->num, lun);
#endif /* ISTGT_TRACE_TAPE */
		if (cdb[0] == SPC_INQUIRY) {
			allocation_len = DGET16(&cdb[3]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], 0x03, 7, 3);
			BDADD8W(&data[0], 0x1f, 4, 5);
			data_len = 96;
			memset(&data[1], 0, data_len - 1);
			/* ADDITIONAL LENGTH */
			data[4] = data_len - 5;
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			return 0;
		} else {
			/* LOGICAL UNIT NOT SUPPORTED */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x25, 0x00);
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return 0;
		}
	}
	spec = (ISTGT_LU_TAPE *) lu->lun[lun].spec;
	if (spec == NULL) {
		/* LOGICAL UNIT NOT SUPPORTED */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x25, 0x00);
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return 0;
	}

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "SCSI OP=0x%x, LUN=0x%16.16"PRIx64"\n",
	    cdb[0], lu_cmd->lun);
#ifdef ISTGT_TRACE_TAPE
	if (cdb[0] != SPC_TEST_UNIT_READY) {
		istgt_scsi_dump_cdb(cdb);
	}
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "mload=%d, mchanged=%d, mwait=%d\n", spec->mload, spec->mchanged, spec->mwait);
#endif /* ISTGT_TRACE_TAPE */

	if (cdb[0] == SSC_WRITE_6 || cdb[0] == SSC_WRITE_FILEMARKS_6) {
		/* write operation (no sync) */
	} else {
		/* non write operation */
		if (spec->need_savectl || spec->need_writeeod) {
			/* flush pending data */
			if (istgt_lu_tape_write_pending_data(spec, conn, lu_cmd) < 0) {
				ISTGT_ERRLOG("lu_tape_write_pending_data() failed\n");
				lu_cmd->data_len = 0;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return 0;
			}
		}
	}

	switch (cdb[0]) {
	case SPC_INQUIRY:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "INQUIRY\n");
		if (lu_cmd->R_bit == 0) {
			ISTGT_ERRLOG("R_bit == 0\n");
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		allocation_len = DGET16(&cdb[3]);
		if (allocation_len > (size_t) data_alloc_len) {
			ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
			    data_alloc_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		memset(data, 0, allocation_len);
		data_len = istgt_lu_tape_scsi_inquiry(spec, conn, cdb,
		    data, data_alloc_len);
		if (data_len < 0) {
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			break;
		}
		ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "INQUIRY", data, data_len);
		lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		break;

	case SPC_REPORT_LUNS:
		{
			int sel;

			ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "REPORT LUNS\n");
			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				return -1;
			}

			sel = cdb[2];
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "sel=%x\n", sel);

			allocation_len = DGET32(&cdb[6]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			if (allocation_len < 16) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			memset(data, 0, allocation_len);
			data_len = istgt_lu_tape_scsi_report_luns(lu, conn, cdb, sel,
			    data, data_alloc_len);
			if (data_len < 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "REPORT LUNS", data, data_len);
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		}
		break;

	case SPC_TEST_UNIT_READY:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "TEST_UNIT_READY\n");
		{
			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);

			/* media state change? */
			if (spec->mchanged) {
				/* wait OS polling */
				if (spec->mwait > 0) {
					spec->mwait--;
				} else {
					/* load new media */
					spec->mchanged = 0;
					spec->mload = 1;
				}
			}

			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			/* OK media present */
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SSC_LOAD_UNLOAD:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "LOAD_UNLOAD\n");
		{
			int hold, eot, reten, load;

			hold = BGET8(&cdb[4], 3);
			eot = BGET8(&cdb[4], 2);
			reten = BGET8(&cdb[4], 1);
			load = BGET8(&cdb[4], 0);

			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			if (load) {
				if (!spec->mload) {
					if (istgt_lu_tape_load_media(spec) < 0) {
						ISTGT_ERRLOG("lu_tape_load_media() failed\n");
						/* INTERNAL TARGET FAILURE */
						BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
						lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
						break;
					}
					/* OK load */
				}
				if (hold) {
					/* loding tape to unit */
				} else {
					/* loding tape to unit and potision to zero */
					istgt_lu_tape_rewind(spec);
				}
			} else {
				if (hold) {
					/* if media in unit, position by eot,reten */
				} else {
					/* unload tape from unit */
					if (!spec->lock) {
						if (!spec->mload) {
							lu_cmd->data_len = 0;
							lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
							break;
						}
						if (istgt_lu_tape_unload_media(spec) < 0) {
							ISTGT_ERRLOG("lu_tape_unload_media() failed\n");
							/* INTERNAL TARGET FAILURE */
							BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
							lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
							break;
						}
						/* OK unload */
					} else {
						/* MEDIUM REMOVAL PREVENTED */
						BUILD_SENSE(ILLEGAL_REQUEST, 0x53, 0x02);
						lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
						break;
					}
				}
			}

			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SPC_PREVENT_ALLOW_MEDIUM_REMOVAL:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "PREVENT_ALLOW_MEDIUM_REMOVAL\n");
		{
			int persistent, prevent;

			persistent = BGET8(&cdb[4], 1);
			prevent = BGET8(&cdb[4], 0);

			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			if (persistent) {
				if (prevent) {
					/* Persistent Prevent */
				} else {
					/* Persistent Allow */
				}
			} else {
				if (prevent) {
					/* Locked */
					spec->lock = 1;
				} else {
					/* Unlocked */
					spec->lock = 0;
				}
			}

			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SSC_READ_BLOCK_LIMITS:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ_BLOCK_LIMITS\n");
		{
			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				return -1;
			}

			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			data_len = 6;
			/* GRANULARITY */
			data[0] = 0;
			/* MAXIMUM BLOCK LENGTH LIMIT */
			DSET24(&data[1], TAPE_MAXIMUM_BLOCK_LENGTH);
			/* MINIMUM BLOCK LENGTH LIMIT */
			DSET16(&data[4], TAPE_MINIMUM_BLOCK_LENGTH);

			lu_cmd->data_len = data_len;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SPC_MODE_SELECT_6:
		{
			int pf, sp, pllen;
			int mdlen, mt, dsp, bdlen;

			pf = BGET8(&cdb[1], 4);
			sp = BGET8(&cdb[1], 0);
			pllen = cdb[4];             /* Parameter List Length */

			/* Data-Out */
			rc = istgt_lu_tape_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
			    lu_cmd->iobufsize, pllen);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_tape_transfer_data() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
#if 0
			istgt_dump("MODE SELECT(6)", lu_cmd->iobuf, pllen);
#endif
			data = lu_cmd->iobuf;
			mdlen = data[0];            /* Mode Data Length */
			mt = data[1];               /* Medium Type */
			dsp = data[2];              /* Device-Specific Parameter */
			bdlen = data[3];            /* Block Descriptor Length */

			if (bdlen > 0) {
				/* Short LBA mode parameter block descriptor */
				/* data[4]-data[7] Number of Blocks */
				/* data[8]-data[11] Block Length */
				spec->lblen = (uint64_t) (DGET32(&data[8]) & 0x00ffffffU);
#ifdef TAPE_DEBUG
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "set to lblen=%"PRIu64"\n", spec->lblen);
#endif /* TAPE_DEBUG */
			}

			/* page data */
			data_len = istgt_lu_tape_scsi_mode_select_page(spec, conn, cdb, pf, sp, &data[4 + bdlen], pllen - (4 + bdlen));
			if (data_len != 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = pllen;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SPC_MODE_SELECT_10:
		{
			int pf, sp, pllen;
			int mdlen, mt, dsp, bdlen;
			int llba;

			pf = BGET8(&cdb[1], 4);
			sp = BGET8(&cdb[1], 0);
			pllen = DGET16(&cdb[7]);    /* Parameter List Length */

			/* Data-Out */
			rc = istgt_lu_tape_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
			    lu_cmd->iobufsize, pllen);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_tape_transfer_data() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
#if 0
			istgt_dump("MODE SELECT(10)", lu_cmd->iobuf, pllen);
#endif
			data = lu_cmd->iobuf;
			mdlen = DGET16(&data[0]);   /* Mode Data Length */
			mt = data[2];               /* Medium Type */
			dsp = data[3];              /* Device-Specific Parameter */
			llba = BGET8(&data[4], 0);  /* Long LBA */
			bdlen = DGET16(&data[6]);   /* Block Descriptor Length */

			if (llba) {
				if (bdlen > 0) {
					/* Long LBA mode parameter block descriptor */
					/* data[8]-data[15] Number of Blocks */
					/* data[16]-data[19] Reserved */
					/* data[20]-data[23] Block Length */
					spec->lblen = (uint64_t) DGET32(&data[20]);
#ifdef TAPE_DEBUG
					ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "set to lblen=%"PRIu64"\n", spec->lblen);
#endif /* TAPE_DEBUG */
				}
			} else {
				if (bdlen > 0) {
					/* Short LBA mode parameter block descriptor */
					/* data[8]-data[11] Number of Blocks */
					/* data[12]-data[15] Block Length */
					spec->lblen = (uint64_t) (DGET32(&data[12]) & 0x00ffffffU);
#ifdef TAPE_DEBUG
					ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "set to lblen=%"PRIu64"\n", spec->lblen);
#endif /* TAPE_DEBUG */
				}
			}

			/* page data */
			data_len = istgt_lu_tape_scsi_mode_select_page(spec, conn, cdb, pf, sp, &data[8 + bdlen], pllen - (8 + bdlen));
			if (data_len != 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = pllen;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SPC_MODE_SENSE_6:
		{
			int dbd, pc, page, subpage;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			dbd = BGET8(&cdb[1], 3);
			pc = BGET8W(&cdb[2], 7, 2);
			page = BGET8W(&cdb[2], 5, 6);
			subpage = cdb[3];

			allocation_len = cdb[4];
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
							 data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			data_len = istgt_lu_tape_scsi_mode_sense6(spec, conn, cdb, dbd, pc, page, subpage, data, data_alloc_len);
			if (data_len < 0) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
#if 0
			istgt_dump("MODE SENSE(6)", data, data_len);
#endif
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SPC_MODE_SENSE_10:
		{
			int dbd, pc, page, subpage;
			int llbaa;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			llbaa = BGET8(&cdb[1], 4);
			dbd = BGET8(&cdb[1], 3);
			pc = BGET8W(&cdb[2], 7, 2);
			page = BGET8W(&cdb[2], 5, 6);
			subpage = cdb[3];

			allocation_len = DGET16(&cdb[7]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			data_len = istgt_lu_tape_scsi_mode_sense10(spec, conn, cdb, llbaa, dbd, pc, page, subpage, data, data_alloc_len);
			if (data_len < 0) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
#if 0
			istgt_dump("MODE SENSE(10)", data, data_len);
#endif
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SPC_LOG_SELECT:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "LOG_SELECT\n");
		/* INVALID COMMAND OPERATION CODE */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		break;

	case SPC_LOG_SENSE:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "LOG_SENSE\n");
#if 0
		/* INVALID FIELD IN CDB */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
		/* INVALID FIELD IN PARAMETER LIST */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x00);
		/* PARAMETER NOT SUPPORTED */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x01);
#endif
		/* INVALID COMMAND OPERATION CODE */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		break;

	case SPC_REQUEST_SENSE:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "REQUEST_SENSE\n");
		{
			int desc;
			int sk, asc, ascq;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			desc = BGET8(&cdb[1], 0);
			if (desc != 0) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);

			/* media state change? */
			if (spec->mchanged) {
				/* wait OS polling */
				if (spec->mwait > 0) {
					spec->mwait--;
				} else {
					/* load new media */
					spec->mchanged = 0;
					spec->mload = 1;
				}
			}

			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			allocation_len = cdb[4];
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			if (!spec->sense) {
				/* NO ADDITIONAL SENSE INFORMATION */
				sk = ISTGT_SCSI_SENSE_NO_SENSE;
				asc = 0x00;
				ascq = 0x00;
			} else {
				sk = (spec->sense >> 16) & 0xffU;
				asc = (spec->sense >> 8) & 0xffU;
				ascq = spec->sense & 0xffU;
			}
			data_len = istgt_lu_tape_build_sense_data(spec, sense_data,
			    sk, asc, ascq);
			if (data_len < 0 || data_len < 2) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			/* omit SenseLength */
			data_len -= 2;
			memcpy(data, sense_data + 2, data_len);

			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SSC_ERASE_6:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "ERASE_6\n");
		{
			int xlong;

			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			xlong = BGET8(&cdb[1], 0);

			if (!xlong) {
				/* short no operation */
				lu_cmd->data_len = 0;
				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				break;
			}
			data_len = istgt_lu_tape_scsi_erase(spec, conn, lu_cmd, data);
			if (data_len != 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SSC_REWIND:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "REWIND\n");
		{
			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			/* position to BOT */
			istgt_lu_tape_rewind(spec);
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SSC_SPACE_6:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "SPACE_6\n");
		{
			int code;
			int count;

			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			code = BGET8W(&cdb[1], 3, 4);
			count = istgt_convert_signed_24bits(DGET24(&cdb[2]));

#ifdef TAPE_DEBUG
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "SPACE %d (code = %d)\n", count, code);
#endif /* TAPE_DEBUG */
			data_len = istgt_lu_tape_scsi_space(spec, conn, lu_cmd, code,
												count, data);
			if (data_len != 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SSC_WRITE_FILEMARKS_6:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "WRITE_FILEMARKS_6\n");
		{
			uint64_t request_len;
			uint64_t marklen;
			int wsmk;
			int count;

			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			wsmk = BGET8(&cdb[1], 1);
			count = (int) DGET24(&cdb[2]);

#ifdef TAPE_DEBUG
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "WRITE_FILEMARK %d\n", count);
#endif /* TAPE_DEBUG */
			if (wsmk) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (count == 0) {
				/* no mark but flush buffer */
				if (spec->need_savectl || spec->need_writeeod) {
					/* flush pending data */
					rc = istgt_lu_tape_write_pending_data(spec, conn, lu_cmd);
					if (rc < 0) {
						ISTGT_ERRLOG("lu_tape_write_pending_data() failed\n");
						lu_cmd->data_len = 0;
						lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
						return 0;
					}
				}
				lu_cmd->data_len = 0;
				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				break;
			}
			if (spec->index + 1 + count > MAX_FILEMARKS - 1) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			istgt_lu_tape_prepare_offset(spec, conn, lu_cmd);
			if (spec->eom) {
				/* END-OF-PARTITION/MEDIUM DETECTED */
				BUILD_SENSE(VOLUME_OVERFLOW, 0x00, 0x02);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			/* EOF x N + EOD */
			marklen = spec->ctlblock->marklen;
			request_len = marklen * (uint64_t) count;
			request_len += marklen;
			/* write media check */
			if (istgt_lu_tape_write_media_check(spec, conn, lu_cmd,
				request_len) < 0) {
				/* sense data build by function */
				break;
			}
			/* actual wirte to media */
			if (istgt_lu_tape_write_eof(spec, count, data) < 0) {
				ISTGT_ERRLOG("lu_tape_write_eof() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (istgt_lu_tape_write_eod(spec, data) < 0) {
				ISTGT_ERRLOG("lu_tape_write_eod() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			spec->need_writeeod = 0;
			if (istgt_lu_tape_save_ctlblock(spec) < 0) {
				ISTGT_ERRLOG("lu_tape_save_ctlblock() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			spec->need_savectl = 0;
			/* dynamic/extend media handle here */
			/* Control + DATA(BOT/File/EOF) + EOD */
			request_len = spec->ctlblock->ctlblocklen;
			request_len += spec->offset;
			request_len += marklen;
			if (istgt_lu_tape_shrink_media(spec, conn, lu_cmd,
				request_len, data) < 0) {
				ISTGT_ERRLOG("lu_tape_shrink_media() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			/* write done */

			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SSC_READ_POSITION:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ_POSITION\n");
		{
			int sa;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			sa = BGET8W(&cdb[1], 4, 5);

			allocation_len = DGET16(&cdb[7]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			data_len = istgt_lu_tape_scsi_read_position(spec, conn, lu_cmd,
			    sa, data);
			if (data_len != 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
#if 0
			istgt_dump("READ_POSITION", data, lu_cmd->data_len);
#endif
			lu_cmd->data_len = DMIN32(lu_cmd->data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SSC_LOCATE_10:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "LOCATE_10\n");
		{
			uint32_t loi;
			int bt, cp, partition;

			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			bt = BGET8(&cdb[1], 2);
			cp = BGET8(&cdb[1], 1);
			loi = DGET32(&cdb[3]);
			partition = cdb[8];

			if (cp) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

#ifdef TAPE_DEBUG
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "LOCATE %u\n", loi);
#endif /* TAPE_DEBUG */
			data_len = istgt_lu_tape_scsi_locate(spec, conn, lu_cmd,
			    loi, data);
			if (data_len != 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SSC_READ_6:
		{
			int sili, fixed;
			uint64_t lblen;
			uint64_t request_len;
			uint64_t rest;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			sili = BGET8(&cdb[1], 1);
			fixed = BGET8(&cdb[1], 0);
			transfer_len = DGET24(&cdb[2]);
			lblen = spec->lblen;

			if (fixed) {
				request_len = (uint64_t) transfer_len * lblen;
			} else {
				request_len = (uint64_t) transfer_len;
			}

			istgt_lu_tape_prepare_offset(spec, conn, lu_cmd);
			if (spec->eom) {
				/* END-OF-PARTITION/MEDIUM DETECTED */
				BUILD_SENSE(MEDIUM_ERROR, 0x00, 0x02);
				/* INFORMATION */
				DSET32(&lu_cmd->sense_data[2+3], (uint32_t) transfer_len);
				lu_cmd->data_len = 0;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			/* clear EOF/EOD before reading */
			spec->eof = spec->eod = 0;

			if (fixed) {
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
				    "READ_6 transfer %u x blocks %u SILI=%d\n",
				    (uint32_t) lblen, (uint32_t) transfer_len,
				    sili);
				rc = istgt_lu_tape_fixed_lbread(spec, conn, lu_cmd, lblen,
				    (uint32_t) transfer_len);
			} else {
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
				    "READ_6 transfer %u SILI=%d\n",
				    (uint32_t) transfer_len, sili);
				rc = istgt_lu_tape_variable_lbread(spec, conn, lu_cmd,
				    transfer_len);
			}
			if (rc < 0) {
				ISTGT_ERRLOG("lu_tape_lbread() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (lu_cmd->status != ISTGT_SCSI_STATUS_GOOD) {
				/* sense data build by function */
				break;
			}
			rest = request_len - lu_cmd->data_len;

#if 0
			istgt_dump("READ", lu_cmd->iobuf, 256);
#endif

			if (spec->eof) {
				/* position to EOF */
				spec->index++;
				spec->offset = spec->ctlblock->marks[spec->index].offset;
				spec->lbpos = spec->ctlblock->marks[spec->index].lbpos;
				spec->prev = spec->ctlblock->marks[spec->index].prev;
				/* position to next block of EOF */
				spec->lbpos++;
				spec->prev = spec->offset;
				spec->offset += spec->ctlblock->marklen;
				/* FILEMARK DETECTED */
				BUILD_SENSE(NO_SENSE, 0x00, 0x01);
				/* INFORMATION */
				DSET32(&lu_cmd->sense_data[2+3], spec->info);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (spec->eod) {
				/* END-OF-DATA DETECTED */
				BUILD_SENSE(BLANK_CHECK, 0x00, 0x05);
				/* INFORMATION */
				DSET32(&lu_cmd->sense_data[2+3], spec->info);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			if (lu_cmd->data_len < request_len) {
#ifdef TAPE_DEBUG
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
				    "Underflow total=%zu, transfer_len=%u, lblen=%u\n",
				    lu_cmd->data_len, (uint32_t) request_len,
				    (uint32_t) lblen);
#endif /* TAPE_DEBUG */
				/* over size? */
				if (rest > spec->size
				    || spec->offset > spec->size - rest) {
					spec->eom = 1;
					/* END-OF-PARTITION/MEDIUM DETECTED */
					BUILD_SENSE(MEDIUM_ERROR, 0x00, 0x02);
					/* INFORMATION */
					DSET32(&lu_cmd->sense_data[2+3], spec->info);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					break;
				}
				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				break;
			}

			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SSC_WRITE_6:
		{
			int sili, fixed;
			uint64_t lblen;
			uint64_t request_len;
			uint64_t rest;
			int index_i;

			if (lu_cmd->W_bit == 0) {
				ISTGT_ERRLOG("W_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			sili = BGET8(&cdb[1], 1);
			fixed = BGET8(&cdb[1], 0);
			transfer_len = DGET24(&cdb[2]);
			lblen = spec->lblen;

			if (fixed) {
				request_len = (uint64_t) transfer_len * lblen;
			} else {
				request_len = (uint64_t) transfer_len;
			}

			data_len = istgt_lu_tape_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				rc = istgt_lu_tape_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
				    lu_cmd->iobufsize, request_len);
				if (rc < 0) {
					ISTGT_ERRLOG("lu_tape_transfer_data() failed\n");
					lu_cmd->data_len = 0;
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					break;
				}
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			istgt_lu_tape_prepare_offset(spec, conn, lu_cmd);
			if (spec->eom) {
				rc = istgt_lu_tape_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
				    lu_cmd->iobufsize, request_len);
				if (rc < 0) {
					ISTGT_ERRLOG("lu_tape_transfer_data() failed\n");
					lu_cmd->data_len = 0;
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					break;
				}
				/* END-OF-PARTITION/MEDIUM DETECTED */
				BUILD_SENSE(VOLUME_OVERFLOW, 0x00, 0x02);
				/* INFORMATION */
				DSET32(&lu_cmd->sense_data[2+3], (uint32_t) transfer_len);
				lu_cmd->data_len = 0;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			if (fixed) {
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
				    "WRITE_6 transfer %u x blocks %u SILI=%d\n",
				    (uint32_t) lblen, (uint32_t) transfer_len,
				    sili);
				rc = istgt_lu_tape_fixed_lbwrite(spec, conn, lu_cmd, lblen,
				    (uint32_t) transfer_len);
			} else {
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
				    "WRITE_6 transfer %u SILI=%d\n",
				    (uint32_t) transfer_len, sili);
				rc = istgt_lu_tape_variable_lbwrite(spec, conn, lu_cmd,
				    transfer_len);
			}
			if (rc < 0) {
				ISTGT_ERRLOG("lu_tape_lbwrite() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (lu_cmd->status != ISTGT_SCSI_STATUS_GOOD) {
				/* sense data build by function */
				break;
			}
			rest = request_len - lu_cmd->data_len;

			/* clean up marks after this file */
			index_i = spec->index;
			if (spec->ctlblock->marks[index_i + 1].offset != MARK_END) {
#ifdef TAPE_DEBUG
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
				    "save ctlblock and write EOD\n");
#endif /* TAPE_DEBUG */
				spec->ctlblock->marks[index_i + 1].offset = MARK_END;
				spec->ctlblock->marks[index_i + 1].lbpos = MARK_END;
				spec->ctlblock->marks[index_i + 1].prev = spec->offset;
				if (istgt_lu_tape_save_ctlblock(spec) < 0) {
					ISTGT_ERRLOG("lu_tape_save_ctlblock() failed\n");
				write_failure:
					/* INTERNAL TARGET FAILURE */
					BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					break;
				}
				request_len = spec->ctlblock->marklen;
				if (istgt_lu_tape_write_media_check(spec, conn, lu_cmd,
					request_len) < 0) {
					goto write_failure;
				}
				if (istgt_lu_tape_write_eod(spec, lu_cmd->data) < 0) {
					ISTGT_ERRLOG("lu_tape_write_eod() failed\n");
					goto write_failure;
				}
			} else {
				/* pending some blocks for performance */
				spec->ctlblock->marks[index_i + 1].prev = spec->offset;
				spec->need_savectl = 1;
				spec->need_writeeod = 1;
			}

#if 0
			if (spec->index == 2) {
				istgt_dump("WRITE", lu_cmd->iobuf, 256);
			}
#endif

			if (lu_cmd->data_len < request_len) {
#ifdef TAPE_DEBUG
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
				    "Underflow total=%zu, transfer_len=%u, lblen=%u\n",
				    lu_cmd->data_len, (uint32_t) request_len,
				    (uint32_t) lblen);
#endif /* TAPE_DEBUG */
				spec->eom = 1;
				/* WRITE ERROR */
				BUILD_SENSE(MEDIUM_ERROR, 0x0c, 0x00);
				/* INFORMATION */
				DSET32(&lu_cmd->sense_data[2+3], spec->info);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	/* XXX TODO: fix */
	case SPC2_RELEASE_6:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "RELEASE_6\n");
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		break;
	case SPC2_RELEASE_10:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "RELEASE_10\n");
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		break;
	case SPC2_RESERVE_6:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "RESERVE_6\n");
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		break;
	case SPC2_RESERVE_10:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "RESERVE_10\n");
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		break;

	default:
		ISTGT_ERRLOG("unsupported SCSI OP=0x%x\n", cdb[0]);
		/* INVALID COMMAND OPERATION CODE */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		break;
	}

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
	    "SCSI OP=0x%x, LUN=0x%16.16"PRIx64" status=0x%x,"
	    " complete\n",
	    cdb[0], lu_cmd->lun, lu_cmd->status);
	return 0;
}
