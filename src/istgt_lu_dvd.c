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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>

#ifdef HAVE_UUID_H
#include <uuid.h>
#endif

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

//#define ISTGT_TRACE_DVD

#define DEFAULT_DVD_BLOCKLEN 2048
#define DEFAULT_DVD_PROFILE MM_PROF_DVDROM

enum {
	MM_PROF_CDROM = 0x0008,
	MM_PROF_DVDROM = 0x0010,
} ISTGT_LU_MM_PROF;

typedef struct istgt_lu_dvd_t {
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

	/* cache flags */
	int read_cache;
	int write_cache;

	/* flags */
	int mflags;
	/* current DVD/CD profile */
	int profile;

	/* media state */
	volatile int mload;
	volatile int mchanged;
	volatile int mwait;

	/* mode flags */
	volatile int lock;

	/* SCSI sense code */
	volatile int sense;
} ISTGT_LU_DVD;

#define BUILD_SENSE(SK,ASC,ASCQ)					\
	do {								\
		*sense_len =						\
			istgt_lu_dvd_build_sense_data(spec, sense_data,	\
			    ISTGT_SCSI_SENSE_ ## SK,			\
			    (ASC), (ASCQ));				\
	} while (0)

static int istgt_lu_dvd_build_sense_data(ISTGT_LU_DVD *spec, uint8_t *data, int sk, int asc, int ascq);

static int
istgt_lu_dvd_open(ISTGT_LU_DVD *spec, int flags, int mode)
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
istgt_lu_dvd_close(ISTGT_LU_DVD *spec)
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
istgt_lu_dvd_seek(ISTGT_LU_DVD *spec, uint64_t offset)
{
	off_t rc;

	rc = lseek(spec->fd, (off_t) offset, SEEK_SET);
	if (rc < 0) {
		return -1;
	}
	return 0;
}

static int64_t
istgt_lu_dvd_read(ISTGT_LU_DVD *spec, void *buf, uint64_t nbytes)
{
	int64_t rc;

	rc = (int64_t) read(spec->fd, buf, (size_t) nbytes);
	if (rc < 0) {
		return -1;
	}
	return rc;
}

static int64_t
istgt_lu_dvd_write(ISTGT_LU_DVD *spec, const void *buf, uint64_t nbytes)
{
	int64_t rc;

	rc = (int64_t) write(spec->fd, buf, (size_t) nbytes);
	if (rc < 0) {
		return -1;
	}
	return rc;
}

static int64_t
istgt_lu_dvd_sync(ISTGT_LU_DVD *spec, uint64_t offset __attribute__((__unused__)), uint64_t nbytes __attribute__((__unused__)))
{
	int64_t rc;

	rc = (int64_t) fsync(spec->fd);
	if (rc < 0) {
		return -1;
	}
	return rc;
}

int
istgt_lu_dvd_media_present(ISTGT_LU_DVD *spec)
{
	if (spec->mload) {
		return 1;
	}
	return 0;
}

int
istgt_lu_dvd_media_lock(ISTGT_LU_DVD *spec)
{
	if (spec->lock) {
		return 1;
	}
	return 0;
}

static int istgt_lu_dvd_allocate(ISTGT_LU_DVD *spec);

int
istgt_lu_dvd_load_media(ISTGT_LU_DVD *spec)
{
	ISTGT_LU_Ptr lu;
	int flags;
	int newfile;
	int rc;

	if (istgt_lu_dvd_media_present(spec)) {
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
		spec->blocklen = DEFAULT_DVD_BLOCKLEN;
		spec->blockcnt = spec->size / spec->blocklen;
		spec->profile = DEFAULT_DVD_PROFILE;
		return 0;
	}
	spec->file = lu->lun[spec->lun].u.removable.file;
	spec->size = lu->lun[spec->lun].u.removable.size;
	spec->mflags = lu->lun[spec->lun].u.removable.flags;
	//spec->blocklen = lu->blocklen;
	spec->blocklen = DEFAULT_DVD_BLOCKLEN;
	spec->blockcnt = spec->size / spec->blocklen;
	spec->profile = DEFAULT_DVD_PROFILE;

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
	if (lu->readonly
		|| (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
		flags = O_RDONLY;
	} else {
		flags = O_RDWR;
	}
	newfile = 0;
	rc = istgt_lu_dvd_open(spec, flags, 0666);
	if (rc < 0) {
		newfile = 1;
		if (lu->readonly
			|| (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
			flags = O_RDONLY;
		} else {
			flags = (O_CREAT | O_EXCL | O_RDWR);
		}
		rc = istgt_lu_dvd_open(spec, flags, 0666);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: LUN%d: open error(errno=%d)\n",
			    lu->num, spec->lun, errno);
			return -1;
		}
		if (lu->lun[spec->lun].u.removable.size < ISTGT_LU_MEDIA_SIZE_MIN) {
			lu->lun[spec->lun].u.removable.size = ISTGT_LU_MEDIA_SIZE_MIN;
		}
	}
	if (lu->readonly
		|| (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
		/* readonly */
	} else {
		if (newfile == 0) {
			/* XXX TODO: existing file check */
		}
		rc = istgt_lu_dvd_allocate(spec);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: LUN%d: allocate error\n", lu->num, spec->lun);
			return -1;
		}
	}
	return 0;
}

int
istgt_lu_dvd_unload_media(ISTGT_LU_DVD *spec)
{
	int64_t rc;

	if (!istgt_lu_dvd_media_present(spec)
		&& !spec->mchanged) {
		/* media absent */
		return 0;
	}
	if (istgt_lu_dvd_media_lock(spec)) {
		return -1;
	}

	if (!spec->lu->readonly
		&& !(spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
		rc = istgt_lu_dvd_sync(spec, 0, spec->size);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_dvd_sync() failed\n");
			return -1;
		}
	}
	rc = (int64_t) istgt_lu_dvd_close(spec);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_dvd_close() failed\n");
		return -1;
	}

	spec->file = NULL;
	spec->size = 0;
	spec->mflags = 0;
	spec->blocklen = DEFAULT_DVD_BLOCKLEN;
	spec->blockcnt = spec->size / spec->blocklen;
	spec->profile = DEFAULT_DVD_PROFILE;

	spec->mload = 0;
	spec->mchanged = 0;
	spec->mwait = 3;
	return 0;
}

int
istgt_lu_dvd_change_media(ISTGT_LU_DVD *spec, char *type, char *flags, char *file, char *size)
{
	ISTGT_LU_Ptr lu;
	char *mfile;
	uint64_t msize;
	int mflags;
	int rc;

	if (istgt_lu_dvd_media_lock(spec)) {
		return -1;
	}

	lu = spec->lu;
	if (lu->lun[spec->lun].type != ISTGT_LU_LUN_TYPE_REMOVABLE) {
		ISTGT_ERRLOG("LU%d: not removable\n", lu->num);
		return -1;
	}

	if (strcmp(type, "-") == 0) {
		/* use ISO image */
		;
	} else {
		ISTGT_ERRLOG("unsupported media type\n");
		return -1;
	}

	mfile = xstrdup(file);
	mflags = istgt_lu_parse_media_flags(flags);
	msize = istgt_lu_parse_media_size(file, size, &mflags);

	rc = istgt_lu_dvd_unload_media(spec);
	if (rc < 0) {
		return -1;
	}

	/* replace */
	xfree(lu->lun[spec->lun].u.removable.file);
	lu->lun[spec->lun].u.removable.file = mfile;
	lu->lun[spec->lun].u.removable.size = msize;
	lu->lun[spec->lun].u.removable.flags = mflags;

	/* reload */
	rc = istgt_lu_dvd_load_media(spec);
	if (rc < 0) {
		(void) istgt_lu_dvd_unload_media(spec);
	}
	if (spec->file == NULL) {
		(void) istgt_lu_dvd_unload_media(spec);
	}
	spec->mwait = 5;
	return rc;
}

static int
istgt_lu_dvd_allocate(ISTGT_LU_DVD *spec)
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
	rc = istgt_lu_dvd_seek(spec, offset);
	if (rc == -1) {
		ISTGT_ERRLOG("lu_dvd_seek() failed\n");
		xfree(data);
		return -1;
	}
	rc = istgt_lu_dvd_read(spec, data, nbytes);
	/* EOF is OK */
	if (rc == -1) {
		ISTGT_ERRLOG("lu_dvd_read() failed\n");
		xfree(data);
		return -1;
	}
	rc = istgt_lu_dvd_seek(spec, offset);
	if (rc == -1) {
		ISTGT_ERRLOG("lu_dvd_seek() failed\n");
		xfree(data);
		return -1;
	}
	rc = istgt_lu_dvd_write(spec, data, nbytes);
	if (rc == -1 || (uint64_t) rc != nbytes) {
		ISTGT_ERRLOG("lu_dvd_write() failed\n");
		xfree(data);
		return -1;
	}

	xfree(data);
	return 0;
}

int
istgt_lu_dvd_init(ISTGT_Ptr istgt __attribute__((__unused__)), ISTGT_LU_Ptr lu)
{
	ISTGT_LU_DVD *spec;
	uint64_t gb_size;
	uint64_t mb_size;
#ifdef HAVE_UUID_H
	uint32_t status;
#endif /* HAVE_UUID_H */
	int mb_digit;
	int ro;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_dvd_init\n");

	printf("LU%d DVD UNIT\n", lu->num);
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
		spec->read_cache = 1;
		spec->write_cache = 1;

#ifdef HAVE_UUID_H
		uuid_create(&spec->uuid, &status);
		if (status != uuid_s_ok) {
			ISTGT_ERRLOG("LU%d: LUN%d: uuid_create() failed\n", lu->num, i);
			xfree(spec);
			return -1;
		}
#endif /* HAVE_UUID_H */

		spec->mload = 0;
		spec->mchanged = 0;
		spec->mwait = 0;
		rc = istgt_lu_dvd_load_media(spec);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_dvd_load_media() failed\n");
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
istgt_lu_dvd_shutdown(ISTGT_Ptr istgt __attribute__((__unused__)), ISTGT_LU_Ptr lu)
{
	ISTGT_LU_DVD *spec;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_dvd_shutdown\n");

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
			return -1;
		}
		spec = (ISTGT_LU_DVD *) lu->lun[i].spec;

		if (!spec->lu->readonly
			&& !(spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
			rc = istgt_lu_dvd_sync(spec, 0, spec->size);
			if (rc < 0) {
				//ISTGT_ERRLOG("LU%d: lu_dvd_sync() failed\n", lu->num);
				/* ignore error */
			}
		}
		rc = istgt_lu_dvd_close(spec);
		if (rc < 0) {
			//ISTGT_ERRLOG("LU%d: lu_dvd_close() failed\n", lu->num);
			/* ignore error */
		}
		xfree(spec);
		lu->lun[i].spec = NULL;
	}

	return 0;
}

static int
istgt_lu_dvd_scsi_report_luns(ISTGT_LU_Ptr lu, CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), int sel, uint8_t *data, int alloc_len)
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
istgt_lu_dvd_scsi_inquiry(ISTGT_LU_DVD *spec, CONN_Ptr conn, uint8_t *cdb, uint8_t *data, int alloc_len)
{
	uint64_t LUI;
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
	pd = SPC_PERIPHERAL_DEVICE_TYPE_DVD;
	rmb = 1;

	LUI = istgt_get_lui(spec->lu->name, spec->lun & 0xffffU);

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

			data[4] = SPC_VPD_SUPPORTED_VPD_PAGES;      /* 0x00 */
			data[5] = SPC_VPD_UNIT_SERIAL_NUMBER;       /* 0x80 */
			data[6] = SPC_VPD_DEVICE_IDENTIFICATION;    /* 0x83 */
			data[7] = SPC_VPD_MANAGEMENT_NETWORK_ADDRESSES; /* 0x85 */
			data[8] = SPC_VPD_EXTENDED_INQUIRY_DATA;    /* 0x86 */
			data[9] = SPC_VPD_MODE_PAGE_POLICY;         /* 0x87 */
			data[10]= SPC_VPD_SCSI_PORTS;               /* 0x88 */
			len = 11 - hlen;

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
		BDADD8(&data[1], 1, 4);         /* hierarchical support */
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
		/* CLOCKING(3-2) QAS(1) IUS(0) */
		data[56] = 0;
		/* Reserved */
		data[57] = 0;
		/* VERSION DESCRIPTOR 1-8 */
		DSET16(&data[58], 0x0960); /* iSCSI (no version claimed) */
		DSET16(&data[60], 0x0300); /* SPC-3 (no version claimed) */
		DSET16(&data[62], 0x03a0); /* MMC-4 (no version claimed) */
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
istgt_lu_dvd_scsi_mode_sense_page(ISTGT_LU_DVD *spec, CONN_Ptr conn, uint8_t *cdb, int pc, int page, int subpage, uint8_t *data, int alloc_len)
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
		if (page != 0x08) {
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
		/* Reserved */
		break;
	case 0x03:
		/* MRW */
		break;
	case 0x04:
		/* Reserved */
		break;
	case 0x05:
		/* Write Parameter */
		break;
	case 0x06:
		/* Reserved */
		break;
	case 0x07:
		/* Verify Error Recovery */
		break;
	case 0x08:
		/* Caching */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Caching\n");
		if (subpage != 0x00)
			break;

		plen = 0x12 + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		BDADD8(&cp[0], 1, 7); /* PS */
		if (pc == 0x01) {
			// Changeable values
			BDADD8(&cp[2], 1, 2); /* WCE */
			BDADD8(&cp[2], 1, 0); /* RCD */
			len += plen;
			break;
		}
		BDADD8(&cp[2], 1, 2); /* WCE */
		//BDADD8(&cp[2], 1, 0); /* RCD */
		if (spec->write_cache == 1) {
			BDADD8(&cp[2], 1, 2); /* WCE=1 */
		} else {
			BDADD8(&cp[2], 0, 2); /* WCE=0 */
		}
		if (spec->read_cache == 0) {
			BDADD8(&cp[2], 1, 0); /* RCD=1 */
		} else {
			BDADD8(&cp[2], 0, 0); /* RCD=0 */
		}
		len += plen;
		break;
	case 0x09:
	case 0x0a:
		/* Reserved */
		break;
	case 0x0b:
		/* Medium Types Supported */
		break;
	case 0x0c:
		/* Reserved */
		break;
	case 0x0d:
		/* CD Device Parameters */
		break;
	case 0x0e:
		/* CD Audio Control */
		break;
	case 0x0f:
	case 0x10:
	case 0x11:
	case 0x12:
	case 0x13:
	case 0x14:
	case 0x15:
	case 0x16:
	case 0x17:
	case 0x18:
	case 0x19:
		/* Reserved */
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
		/* Time-out & Protect */
		break;
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
		/* Vendor-specific */
		break;
	case 0x2a:
		/* MM Capabilities & Mechanical Status */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE MM Capabilities & Mechanical Status\n");
		if (subpage != 0x00)
			break;

		plen = 28 + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);

		BDADD8(&cp[2], 1, 3); /* DVD-ROM read */

		len += plen;
		break;
	case 0x2b:
		/* Reserved */
		break;
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
				len += istgt_lu_dvd_scsi_mode_sense_page(spec, conn, cdb, pc, i, 0x00, &cp[len], alloc_len);
			}
			break;
		case 0xff:
			/* All mode pages and subpages */
			for (i = 0x00; i < 0x3e; i ++) {
				len += istgt_lu_dvd_scsi_mode_sense_page(spec, conn, cdb, pc, i, 0x00, &cp[len], alloc_len);
			}
			for (i = 0x00; i < 0x3e; i ++) {
				len += istgt_lu_dvd_scsi_mode_sense_page(spec, conn, cdb, pc, i, 0xff, &cp[len], alloc_len);
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
istgt_lu_dvd_scsi_mode_sense6(ISTGT_LU_DVD *spec, CONN_Ptr conn, uint8_t *cdb, int dbd, int pc, int page, int subpage, uint8_t *data, int alloc_len)
{
	uint8_t *cp;
	int hlen = 0, len = 0, plen;
	int total;
	int llbaa = 0;

	data[0] = 0;                    /* Mode Data Length */
	if (spec->mload) {
		data[1] = 0;            /* Medium Type */
		data[2] = 0;            /* Device-Specific Parameter */
		if (spec->lu->readonly
		    || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
			BDADD8(&data[2], 1, 7);     /* WP */
		}
	} else {
		data[1] = 0;            /* Medium Type */
		data[2] = 0;            /* Device-Specific Parameter */
	}
	data[3] = 0;                    /* Block Descripter Length */
	hlen = 4;

	cp = &data[4];
	if (dbd) {                      /* Disable Block Descripters */
		len = 0;
	} else {
		if (llbaa) {
			if (spec->mload) {
				/* Number of Blocks */
				DSET64(&cp[0], spec->blockcnt);
				/* Reserved */
				DSET32(&cp[8], 0);
				/* Block Length */
				DSET32(&cp[12], (uint32_t) spec->blocklen);
			} else {
				/* Number of Blocks */
				DSET64(&cp[0], 0ULL);
				/* Reserved */
				DSET32(&cp[8], 0);
				/* Block Length */
				DSET32(&cp[12], 0);
			}
			len = 16;
		} else {
			if (spec->mload) {
				/* Number of Blocks */
				if (spec->blockcnt > 0xffffffffULL) {
					DSET32(&cp[0], 0xffffffffUL);
				} else {
					DSET32(&cp[0], (uint32_t) spec->blockcnt);
				}
				/* Block Length */
				DSET32(&cp[4], (uint32_t) spec->blocklen);
			} else {
				/* Number of Blocks */
				DSET32(&cp[0], 0);
				/* Block Length */
				DSET32(&cp[4], 0);
			}
			len = 8;
		}
		cp += len;
	}
	data[3] = len;                  /* Block Descripter Length */

	plen = istgt_lu_dvd_scsi_mode_sense_page(spec, conn, cdb, pc, page, subpage, &cp[0], alloc_len);
	if (plen < 0) {
		return -1;
	}
	cp += plen;

	total = hlen + len + plen;
	data[0] = total - 1;            /* Mode Data Length */

	return total;
}

static int
istgt_lu_dvd_scsi_mode_sense10(ISTGT_LU_DVD *spec, CONN_Ptr conn, uint8_t *cdb, int dbd, int llbaa, int pc, int page, int subpage, uint8_t *data, int alloc_len)
{
	uint8_t *cp;
	int hlen = 0, len = 0, plen;
	int total;

	DSET16(&data[0], 0);            /* Mode Data Length */
	if (spec->mload) {
		data[2] = 0;            /* Medium Type */
		data[3] = 0;            /* Device-Specific Parameter */
		if (spec->lu->readonly
		    || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
			BDADD8(&data[3], 1, 7);     /* WP */
		}
	} else {
		data[2] = 0;            /* Medium Type */
		data[3] = 0;            /* Device-Specific Parameter */
	}
	if (llbaa) {
		BDSET8(&data[4], 1, 1);      /* Long LBA */
	} else {
		BDSET8(&data[4], 0, 1);      /* Short LBA */
	}
	data[5] = 0;                    /* Reserved */
	DSET16(&data[6], 0);  		/* Block Descripter Length */
	hlen = 8;

	cp = &data[8];
	if (dbd) {                      /* Disable Block Descripters */
		len = 0;
	} else {
		if (llbaa) {
			if (spec->mload) {
				/* Number of Blocks */
				DSET64(&cp[0], spec->blockcnt);
				/* Reserved */
				DSET32(&cp[8], 0);
				/* Block Length */
				DSET32(&cp[12], (uint32_t) spec->blocklen);
			} else {
				/* Number of Blocks */
				DSET64(&cp[0], 0ULL);
				/* Reserved */
				DSET32(&cp[8], 0);
				/* Block Length */
				DSET32(&cp[12], 0);
			}
			len = 16;
		} else {
			if (spec->mload) {
				/* Number of Blocks */
				if (spec->blockcnt > 0xffffffffULL) {
					DSET32(&cp[0], 0xffffffffUL);
				} else {
					DSET32(&cp[0], (uint32_t) spec->blockcnt);
				}
				/* Block Length */
				DSET32(&cp[4], (uint32_t) spec->blocklen);
			} else {
				/* Number of Blocks */
				DSET32(&cp[0], 0);
				/* Block Length */
				DSET32(&cp[4], 0);
			}
			len = 8;
		}
		cp += len;
	}
	DSET16(&data[6], len);          /* Block Descripter Length */

	plen = istgt_lu_dvd_scsi_mode_sense_page(spec, conn, cdb, pc, page, subpage, &cp[0], alloc_len);
	if (plen < 0) {
		return -1;
	}
	cp += plen;

	total = hlen + len + plen;
	DSET16(&data[0], total - 2);	/* Mode Data Length */

	return total;
}

static int
istgt_lu_dvd_transfer_data(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint8_t *buf, size_t bufsize, size_t len)
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
istgt_lu_dvd_scsi_mode_select_page(ISTGT_LU_DVD *spec, CONN_Ptr conn, uint8_t *cdb, int pf, int sp, uint8_t *data, size_t len)
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
	printf("ps=%d, page=%2.2x, subpage=%2.2x\n", ps, page, subpage);
#endif
	switch (page) {
	case 0x08:
		/* Caching */
		{
			int wce, rcd;

			ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SELECT Caching\n");
			if (subpage != 0x00)
				break;
			if (plen != 0x12 + hlen) {
				/* unknown format */
				break;
			}
			wce = BGET8(&data[2], 2); /* WCE */
			rcd = BGET8(&data[2], 0); /* RCD */

			if (wce) {
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SELECT Writeback cache enable\n");
				spec->write_cache = 1;
			} else {
				spec->write_cache = 0;
			}
			if (rcd) {
				ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SELECT Read cache disable\n");
				spec->read_cache = 0;
			} else {
				spec->read_cache = 1;
			}
		}
		break;
	default:
		/* not supported */
		break;
	}

	len -= plen;
	if (len != 0) {
		rc = istgt_lu_dvd_scsi_mode_select_page(spec, conn, cdb,  pf, sp, &data[plen], len);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}

#define FEATURE_DESCRIPTOR_INIT(B,L,FC)					\
	do {								\
		memset((B), 0, (L));					\
		DSET16(&(B)[0], (FC));					\
		(B)[3] = (L) - 4;					\
	} while (0)

static int
istgt_lu_dvd_get_feature_descriptor(ISTGT_LU_DVD *spec, CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), int fc, uint8_t *data)
{
	uint8_t *cp;
	int hlen = 0, len = 0, plen;

	switch (fc) {
	case 0x0000:
		/* Profile List */
		plen = 2 * 4 + 4;
		FEATURE_DESCRIPTOR_INIT(data, plen, fc);
		/* Version(5-2) Persistent(1) Current(0) */
		BDSET8W(&data[2], 0, 5, 4);
		BSET8(&data[2], 1);			/* Persistent=1 */
		BSET8(&data[2], 0);			/* Current=1 */
		hlen = 4;

		/* Profile Descriptor */
		cp = &data[hlen + len];
		/* Profile 1 (CDROM) */
		DSET16(&cp[0], 0x0008);
		if (spec->profile == MM_PROF_CDROM) {
			BSET8(&cp[2], 0);		/* CurrentP(0)=1 */
		}
		plen = 4;
		len += plen;

		cp = &data[hlen + len];
		/* Profile 2 (DVDROM) */
		DSET16(&cp[0], 0x0010);
		if (spec->profile == MM_PROF_DVDROM) {
			BSET8(&cp[2], 0);		/* CurrentP(0)=1 */
		}
		plen = 4;
		len += plen;
		break;

	case 0x0001:
		/* Core Feature */
		/* GET CONFIGURATION/GET EVENT STATUS NOTIFICATION/INQUIRY */
		/* MODE SELECT (10)/MODE SENSE (10)/REQUEST SENSE/TEST UNIT READY */
		plen = 8 + 4;
		FEATURE_DESCRIPTOR_INIT(data, plen, fc);
		/* Version(5-2) Persistent(1) Current(0) */
		BDSET8W(&data[2], 0x01, 5, 4);          /* MMC4 */
		BSET8(&data[2], 1);			/* Persistent=1 */
		BSET8(&data[2], 0);			/* Current=1 */
		hlen = 4;

		/* Physical Interface Standard */
		DSET32(&data[4], 0x00000000);           /* Unspecified */
		/* DBE(0) */
		BCLR8(&data[8], 0);			/* DBE=0*/
		len = 8;
		break;

	case 0x0003:
		/* Removable Medium */
		/* MECHANISM STATUS/PREVENT ALLOW MEDIUM REMOVAL/START STOP UNIT */
		plen = 0x04 + 4;
		FEATURE_DESCRIPTOR_INIT(data, plen, fc);
		/* Version(5-2) Persistent(1) Current(0) */
		BDSET8W(&data[2], 0x01, 5, 4);
		BSET8(&data[2], 1);			/* Persistent=1 */
		BSET8(&data[2], 0);			/* Current=1 */
		hlen = 4;

		/* Loading Mechanism Type(7-5) Eject(3) Pvnt Jmpr(2) Lock(0) */
		BDSET8W(&data[4], 0x01, 7, 3); /* Tray type loading mechanism */
		BSET8(&data[4], 3);			/* eject via START/STOP YES */
		BSET8(&data[4], 0);			/* locking YES */
		len = 8;
		break;

	case 0x0010:
		/* Random Readable */
		/* READ CAPACITY/READ (10) */
		plen = 4 + 4;
		FEATURE_DESCRIPTOR_INIT(data, plen, fc);
		/* Version(5-2) Persistent(1) Current(0) */
		BDSET8W(&data[2], 0x00, 5, 4);
		BSET8(&data[2], 1);			/* Persistent=1 */
		BSET8(&data[2], 0);			/* Current=1 */
		hlen = 4;

		/* Logical Block Size */
		DSET32(&data[4], (uint32_t) spec->blocklen);
		/* Blocking */
		DSET16(&data[8], 1);
		/* PP(0) */
		BCLR8(&data[10], 0);			/* PP=0 */
		len = 4;
		break;

	case 0x001d:
		/* Multi-Read Feature */
		/* READ (10)/READ CD/READ DISC INFORMATION/READ TRACK INFORMATION */
		plen = 4;
		FEATURE_DESCRIPTOR_INIT(data, plen, fc);
		/* Version(5-2) Persistent(1) Current(0) */
		BDSET8W(&data[2], 0x00, 5, 4);
		BSET8(&data[2], 1);			/* Persistent=1 */
		BSET8(&data[2], 0);			/* Current=1 */
		hlen = 4;
		len = 0;
		break;

	case 0x001e:
		/* CD Read */
		/* READ CD/READ CD MSF/READ TOC/PMA/ATIP */
		plen = 4 + 4;
		FEATURE_DESCRIPTOR_INIT(data, plen, fc);
		/* Version(5-2) Persistent(1) Current(0) */
		BDSET8W(&data[2], 0x02, 5, 4); /* MMC4 */
		BCLR8(&data[2], 1);			/* Persistent=0 */
		if (spec->profile == MM_PROF_CDROM) {
			BSET8(&data[2], 0);		/* Current=1 */
		} else {
			BCLR8(&data[2], 0);		/* Current=0 */
		}
		hlen = 4;

		/* DAP(7) C2 Flags(1) CD-Text(0) */
		BCLR8(&data[4], 7);		/* not support DAP */
		BCLR8(&data[4], 1);		/* not support C2 */
		BCLR8(&data[4], 0);		/* not support CD-Text */
		len = 4;
		break;

	case 0x001f:
		/* DVD Read */
		/* READ (10)/READ (12)/READ DVD STRUCTURE/READ TOC/PMA/ATIP */
		plen = 4;
		FEATURE_DESCRIPTOR_INIT(data, plen, fc);
		/* Version(5-2) Persistent(1) Current(0) */
		BDSET8W(&data[2], 0x00, 5, 4);
		BCLR8(&data[2], 1);			/* Persistent=0 */
		if (spec->profile == MM_PROF_DVDROM) {
			BSET8(&data[2], 0);		/* Current=1 */
		} else {
			BCLR8(&data[2], 0);		/* Current=0 */
		}
		hlen = 4;
		len = 0;
		break;

	default:
		/* not supported */
		break;
	}

	return hlen + len;
}

static int
istgt_lu_dvd_scsi_get_configuration(ISTGT_LU_DVD *spec, CONN_Ptr conn, uint8_t *cdb, int rt, int sfn, uint8_t *data)
{
	uint8_t *cp;
	int hlen = 0, len = 0, plen;
	int fc;

	/* Feature Header */
	/* Data Length */
	DSET32(&data[0], 0);
	/* Reserved */
	data[4] = 0;
	/* Reserved */
	data[5] = 0;
	/* Current Profile */
	DSET16(&data[6], spec->profile);
	hlen = 8;

	cp = &data[hlen];
	switch (rt) {
	case 0x00:
		/* all of features */
		for (fc = sfn; fc < 0xffff; fc++) {
			plen = istgt_lu_dvd_get_feature_descriptor(spec, conn, cdb, fc, &cp[len]);
			len += plen;
		}
		break;

	case 0x01:
		/* current of features */
		for (fc = sfn; fc < 0xffff; fc++) {
			plen = istgt_lu_dvd_get_feature_descriptor(spec, conn, cdb, fc, &cp[len]);
			if (BGET8(&cp[2], 0) == 1) {
				len += plen;
			} else {
				/* drop non active descriptors */
			}
		}
		break;

	case 0x02:
		/* specified feature */
		fc = sfn;
		plen = istgt_lu_dvd_get_feature_descriptor(spec, conn, cdb, fc, &cp[len]);
		len += plen;
		break;

	default:
		/* not supported */
		break;
	}

	/* Data Length */
	DSET32(&data[0], len);

	return hlen + len;
}

static int
istgt_lu_dvd_scsi_get_event_status_notification(ISTGT_LU_DVD *spec, CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), int keep __attribute__((__unused__)), int ncr, uint8_t *data)
{
	uint8_t *cp;
	int hlen = 0, len = 0;

	/* Event Descriptor Length */
	DSET16(&data[0], 0);
	/* NEA(7) Notification Class(2-0) */
	data[2] = 0;
	/* Supported Event Classes */
	data[3] = 0x7e;
	hlen = 4;

	cp = &data[hlen];
	/* Lowest class number has highest priority */
	if (ncr & (1 << 0)) {
		/* Reserved */
		len = 0;
	}
	if (ncr & (1 << 1)) {
		/* Operational Change */
		BDSET8W(&data[2], 0x01, 2, 3);		/* Notification Class */
		/* Event Code */
		BDSET8W(&cp[0], 0x00, 3, 4);		/* NoChg */
		/* Persistent Prevented(7) Operational Status(3-0) */
		BDSET8(&cp[1], 0, 7);			/* not prevented */
		BDADD8W(&cp[1], 0, 3, 4);
		/* Operational Change */
		DSET16(&cp[2], 0x00);			/* NoChg */
		len = 4;
		goto event_available;
	}
	if (ncr & (1 << 2)) {
		/* Power Management */
		BDSET8W(&data[2], 0x02, 2, 3);		/* Notification Class */
		/* Event Code */
		BDSET8W(&cp[0], 0x00, 3, 4);		/* NoChg */
		/* Power Status */
		cp[1] = 0x01;				/* Active */
		/* Reserved */
		cp[2] = 0;
		/* Reserved */
		cp[3] = 0;
		len = 4;
		goto event_available;
	}
	if (ncr & (1 << 3)) {
		/* External Request */
		BDSET8W(&data[2], 0x03, 2, 3);		/* Notification Class */
		/* Event Code */
		BDSET8W(&cp[0], 0x00, 3, 4);		/* NoChg */
		/* Persistent Prevented(7) External Request Status(3-0) */
		BDSET8(&cp[1], 0, 7);			/* not prevented */
		BDADD8W(&cp[1], 0, 3, 4);		/* Ready */
		/* External Request */
		DSET16(&cp[2], 0x00);			/* No Request */
		len = 4;
		goto event_available;
	}
	if (ncr & (1 << 4)) {
		/* Media */
		BDSET8W(&data[2], 0x04, 2, 3);		/* Notification Class */
		if (spec->mchanged) {
			if (spec->mwait > 0) {
				spec->mwait--;
			} else {
				spec->mchanged = 0;
				spec->mload = 1;
			}
			if (spec->mload) {
				/* Event Code */
				BDSET8W(&cp[0], 0x02, 3, 4);	/* NewMedia */
				/* Media Status */
				/* Media Present(1) Door or Tray open(0) */
				BDSET8(&cp[1], 1, 1);		/* media present */
				BDADD8(&cp[1], 0, 0);		/* tray close */
			} else {
				/* Event Code */
				BDSET8W(&cp[0], 0x03, 3, 4);	/* MediaRemoval */
				/* Media Status */
				/* Media Present(1) Door or Tray open(0) */
				BDSET8(&cp[1], 0, 1);		/* media absent */
				BDADD8(&cp[1], 1, 0);		/* tray open */
			}
		} else {
			if (spec->mwait > 0) {
				spec->mwait--;
				/* Event Code */
				BDSET8W(&cp[0], 0x01, 3, 4);	/* EjectRequest */
				/* Media Status */
				/* Media Present(1) Door or Tray open(0) */
				BDSET8(&cp[1], 0, 1);		/* media absent */
				BDADD8(&cp[1], 1, 0);		/* tray open */
			} else {
				if (spec->mload) {
					/* Event Code */
					BDSET8W(&cp[0], 0x00, 3, 4);	/* NoChg */
					/* Media Status */
					/* Media Present(1) Door or Tray open(0) */
					BDSET8(&cp[1], 1, 1);	/* media present */
					BDADD8(&cp[1], 0, 0);	/* tray close */
				} else {
					/* Event Code */
					BDSET8W(&cp[0], 0x00, 3, 4);	/* NoChg */
					/* Media Status */
					/* Media Present(1) Door or Tray open(0) */
					BDSET8(&cp[1], 0, 1);	/* media absent */
					BDADD8(&cp[1], 0, 0);	/* tray close */
				}
			}
		}
		/* Start Slot */
		cp[2] = 0;
		/* End Slot */
		cp[3] = 0;
		len = 4;
		goto event_available;
	}
	if (ncr & (1 << 5)) {
		/* Multi-Initiator */
		BDSET8W(&data[2], 0x05, 2, 3);		/* Notification Class */
		/* Event Code */
		BDSET8W(&cp[0], 0x00, 3, 4);		/* NoChg */
		/* Persistent Prevented(7) Multiple Initiator Status(3-0) */
		BDSET8(&cp[1], 0, 7);			/* not prevented */
		BDADD8W(&cp[1], 0, 3, 4);		/* Ready */
		/* Multiple Initiator Priority */
		DSET16(&cp[2], 0x00);			/* No Request */
		len = 4;
		goto event_available;
	}
	if (ncr & (1 << 6)) {
		/* Device Busy */
		BDSET8W(&data[2], 0x06, 2, 3);		/* Notification Class */
		/* Event Code */
		BDSET8W(&cp[0], 0x00, 3, 4);		/* NoChg */
		/* Media Status */
		/* Device Busy Status */
		cp[1] = 0;				/* Not Busy */
		/* Time */
		DSET16(&cp[2], 0);
		len = 4;
		goto event_available;
	}
	if (ncr & (1 << 7)) {
		/* Reserved */
		len = 0;
	}

	if (len == 0) {
		/* No Event Available */
		BDSET8(&data[2], 0, 7);			/* NEA=1 */
	}

event_available:
	/* Event Descriptor Length */
	DSET16(&data[0], len + (hlen - 2));

	return hlen + len;
}

static int
istgt_lu_dvd_scsi_mechanism_status(ISTGT_LU_DVD *spec, CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), uint8_t *data)
{
	uint8_t *cp;
	int hlen = 0, len = 0, plen;
	int selected_slot = 0, max_slots = 1;

	/* Mechanism Status Header */
	/* Fault(7) Changer State(6-5) Current Slot(4-0) */
	BDSET8(&data[0], 0, 7);
	BDADD8W(&data[0], 0x00, 6, 2);			/* Ready */
	BDADD8W(&data[0], (selected_slot & 0x1f), 4, 5); /* slot low bits */
	/* Mechanism State(7-5) Door open(4) Current Slot(2-0) */
	BDSET8W(&data[1], 0x00, 7, 3);		/* Idle */
	BDADD8W(&data[1], (selected_slot & 0xe0) >> 5, 2, 3); /* slot high bits */
	/* Current LBA (Legacy) */
	DSET24(&data[2], 0);
	/* Number of Slots Available */
	data[5] = max_slots;
	/* Length of Slot Tables */
	DSET16(&data[6], 0);
	hlen = 8;

	/* Slot Tables */
	/* Slot 0 */
	cp = &data[hlen + len];

	if (spec->mchanged) {
		if (spec->mload) {
			/* Disc Present(7) Change(0) */
			BDSET8(&cp[0], 1, 7);		/* disc in slot */
		} else {
			/* Disc Present(7) Change(0) */
			BDSET8(&cp[0], 0, 7);		/* no disc in slot */
		}
		BDADD8(&cp[0], 1, 0);			/* disc changed */
	} else {
		if (spec->mload) {
			/* Disc Present(7) Change(0) */
			BDSET8(&cp[0], 1, 7);		/* disc in slot */
		} else {
			/* Disc Present(7) Change(0) */
			BDSET8(&cp[0], 0, 7);		/* no disc in slot */
		}
		BDADD8(&cp[0], 0, 0);			/* disc not changed */
	}
	/* CWP_V(1) CWP(0) */
	BDSET8(&cp[1], 0, 1);				/* non Cartridge Write Protection */
	BDADD8(&cp[1], 0, 0);				/* CWP=0 */
	/* Reserved */
	cp[2] = 0;
	/* Reserved */
	cp[3] = 0;
	plen = 4;
	len += plen;

	/* Length of Slot Tables */
	DSET16(&data[6], len);

	return hlen + len;
}

static int
istgt_lu_dvd_scsi_read_toc(ISTGT_LU_DVD *spec, CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), int msf, int format, int track __attribute__((__unused__)), uint8_t *data)
{
	uint8_t *cp;
	int hlen = 0, len = 0, plen;

	switch (format) {
	case 0x00: /* Formatted TOC */
		/* TOC Data Length */
		DSET16(&data[0], 0);
		/* First Track Number */
		data[2] = 1;
		/* Last Track Number */
		data[3] = 1;
		hlen = 4;

		/* TOC Track Descriptor */
		/* Track 1 Descriptor */
		cp = &data[hlen + len];

		/* Reserved */
		cp[0] = 0;
		/* ADR(7-4) CONTROL(3-0) */
		cp[1] = 0x14;
		/* Track Number */
		cp[2] = 1;
		/* Reserved */
		cp[3] = 0;
		/* Track Start Address */
		if (msf) {
			DSET32(&cp[4], istgt_lba2msf(0));
		} else {
			DSET32(&cp[4], 0);
		}
		plen = 8;
		len += plen;

		/* Track AAh (Lead-out) Descriptor */
		cp = &data[hlen + len];

		/* Reserved */
		cp[0] = 0;
		/* ADR(7-4) CONTROL(3-0) */
		cp[1] = 0x14;
		/* Track Number */
		cp[2] = 0xaa;
		/* Reserved */
		cp[3] = 0;
		/* Track Start Address */
		if (msf) {
			DSET32(&cp[4], istgt_lba2msf(spec->blockcnt));
		} else {
			DSET32(&cp[4], spec->blockcnt);
		}
		plen = 8;
		len += plen;

		/* TOC Data Length */
		DSET16(&data[0], hlen + len - 2);
		break;

	case 0x01: /* Multi-session Information */
		/* TOC Data Length */
		DSET16(&data[0], 0);
		/* First Complete Session Number */
		data[2] = 1;
		/* Last Complete Session Number */
		data[3] = 1;
		hlen = 4;

		/* TOC Track Descriptor */
		cp = &data[hlen + len];

		/* Reserved */
		cp[0] = 0;
		/* ADR(7-4) CONTROL(3-0) */
		cp[1] = 0x14;
		/* First Track Number In Last Complete Session */
		cp[2] = 1;
		/* Reserved */
		cp[3] = 0;
		/* Start Address of First Track in Last Session */
		if (msf) {
			DSET32(&cp[4], istgt_lba2msf(0));
		} else {
			DSET32(&cp[4], 0);
		}
		len = 8;

		/* TOC Data Length */
		DSET16(&data[0], hlen + len - 2);
		break;

	case 0x02: /* Raw TOC */
		/* TOC Data Length */
		DSET16(&data[0], 0);
		/* First Complete Session Number */
		data[2] = 1;
		/* Last Complete Session Number */
		data[3] = 1;
		hlen = 4;

		/* TOC Track Descriptor */
		/* First Track number in the program area */
		cp = &data[hlen + len];

		/* Session Number */
		cp[0] = 1;
		/* ADR(7-4) CONTROL(3-0) */
		cp[1] = 0x14;
		/* TNO */
		cp[2] = 0;
		/* POINT */
		cp[3] = 0xa0;
		/* Min */
		cp[4] = 0;
		/* Sec */
		cp[5] = 0;
		/* Frame */
		cp[6] = 0;
		/* Zero */
		cp[7] = 0;
		/* PMIN / First Track Number */
		cp[8] = 1;
		/* PSEC / Disc Type */
		cp[9] = 0x00; /* CD-DA or CD Data with first track in Mode 1 */
		/* PFRAME */
		cp[10] = 0;
		plen = 11;
		len += plen;

		/* Last Track number in the program area */
		cp = &data[hlen + len];

		/* Session Number */
		cp[0] = 1;
		/* ADR(7-4) CONTROL(3-0) */
		cp[1] = 0x14;
		/* TNO */
		cp[2] = 0;
		/* POINT */
		cp[3] = 0xa1;
		/* Min */
		cp[4] = 0;
		/* Sec */
		cp[5] = 0;
		/* Frame */
		cp[6] = 0;
		/* Zero */
		cp[7] = 0;
		/* PMIN / Last Track Number */
		cp[8] = 1;
		/* PSEC */
		cp[9] = 0;
		/* PFRAME */
		cp[10] = 0;
		plen = 11;
		len += plen;

		/* Start location of the Lead-out area */
		cp = &data[hlen + len];

		/* Session Number */
		cp[0] = 1;
		/* ADR(7-4) CONTROL(3-0) */
		cp[1] = 0x14;
		/* TNO */
		cp[2] = 0;
		/* POINT */
		cp[3] = 0xa2;
		/* Min */
		cp[4] = 0;
		/* Sec */
		cp[5] = 0;
		/* Frame */
		cp[6] = 0;
		/* Zero */
		cp[7] = 0;
		/* PMIN / Start position of Lead-out */
		/* PSEC / Start position of Lead-out */
		/* PFRAME / Start position of Lead-out */
		if (msf) {
			DSET24(&cp[8], istgt_lba2msf(spec->blockcnt));
		} else {
			DSET24(&cp[8], spec->blockcnt);
		}
		plen = 11;
		len += plen;

		/* Track data */
		cp = &data[hlen + len];

		/* Session Number */
		cp[0] = 1;
		/* ADR(7-4) CONTROL(3-0) */
		cp[1] = 0x14;
		/* TNO */
		cp[2] = 0;
		/* POINT */
		cp[3] = 1;
		/* Min */
		cp[4] = 0;
		/* Sec */
		cp[5] = 0;
		/* Frame */
		cp[6] = 0;
		/* Zero */
		cp[7] = 0;
		/* PMIN / Start position of Lead-out */
		/* PSEC / Start position of Lead-out */
		/* PFRAME / Start position of Lead-out */
		if (msf) {
			DSET24(&cp[8], istgt_lba2msf(0));
		} else {
			DSET24(&cp[8], 0);
		}
		plen = 11;
		len += plen;

		/* TOC Data Length */
		DSET16(&data[0], hlen + len - 2);
		break;

	default:
		ISTGT_ERRLOG("unsupported format 0x%x\n", format);
		return -1;
	}

	return hlen + len;
}

static int
istgt_lu_dvd_scsi_read_disc_information(ISTGT_LU_DVD *spec __attribute__((__unused__)), CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), int datatype, uint8_t *data)
{
	int hlen = 0, len = 0;

	switch (datatype) {
	case 0x00: /* Disc Information Block */
		/* Disc Information Length */
		DSET16(&data[0], 0);
		hlen = 2;

		/* Disc Information Data Type(7-5) Erasable(4) */
		/* State of last Session(3-2) Disc Status(1-0) */
		BDSET8W(&data[2], datatype, 7, 3);
		BDADD8W(&data[2], 0, 4, 1);
		BDADD8W(&data[2], 0x03, 3, 2);		/* Complete Session */
		BDADD8W(&data[2], 0x02, 1, 2);		/* Finalized Disc */
		/* Number of First Track on Disc */
		data[3] = 1;
		/* Number of Sessions (Least Significant Byte) */
		data[4] = (1) & 0xff;
		/* First Track Number in Last Session (Least Significant Byte) */
		data[5] = (1) & 0xff;
		/* Last Track Number in Last Session (Least Significant Byte) */
		data[6] = (1) & 0xff;
		/* DID_V(7) DBC_V(6) URU(5) DAC_V(4) BG Format Status(1-0) */
		BDSET8(&data[7], 0, 7);			/* Disc ID Valid */
		BDADD8(&data[7], 0, 6);			/* Disc Bar Code Valid */
		BDADD8(&data[7], 1, 5);			/* Unrestricted Use Disc */
		BDADD8(&data[7], 0, 4);			/* Disc Application Code Valid */
		BDADD8W(&data[7], 0, 1, 2);		/* BG Format Status */
		/* Disc Type */
		data[8] = 0x00;				/* CD-DA or CD-ROM Disc */
		/* Number of Sessions (Most Significant Byte) */
		data[9] = (1 >> 8) & 0xff;
		/* First Track Number in Last Session (Most Significant Byte) */
		data[10] = (1 >> 8) & 0xff;
		/* Last Track Number in Last Session (Most Significant Byte) */
		data[11] = (1 >> 8) & 0xff;
		/* Disc Identification */
		DSET32(&data[12], 0);
		/* Last Session Lead-in Start Address */
		DSET32(&data[16], 0);
		/* Last Possible Lead-out Start Address */
		DSET32(&data[20], 0);
		/* Disc Bar Code */
		memset(&data[24], 0, 8);
		/* Disc Application Code */
		data[32] = 0;
		/* Number of OPC Tables */
		data[33] = 0;
		/* OPC Table Entries */
		//data[34] = 0;
		len = 34 - hlen;

		/* Disc Information Length */
		DSET16(&data[0], len);
		break;

	case 0x01: /* Track Resources Information Block */
		/* Disc Information Length */
		DSET16(&data[0], 0);
		hlen = 2;

		/* Disc Information Data Type(7-5) */
		BDSET8W(&data[2], datatype, 7, 3);
		/* Reserved */
		data[3] = 0;
		/* Maximum possible number of the Tracks on the disc */
		DSET16(&data[4], 99);
		/* Number of the assigned Tracks on the disc */
		DSET16(&data[6], 1);
		/* Maximum possible number of appendable Tracks on the disc */
		DSET16(&data[8], 99);
		/* Current number of appendable Tracks on the disc */
		DSET16(&data[10], 99);
		len = 12 - hlen;

		/* Disc Information Length */
		DSET16(&data[0], len);
		break;

	case 0x02: /* POW Resources Information Block */
		/* Disc Information Length */
		DSET16(&data[0], 0);
		hlen = 2;

		/* Disc Information Data Type(7-5) */
		BDSET8W(&data[2], datatype, 7, 3);
		/* Reserved */
		data[3] = 0;
		/* Remaining POW Replacements */
		DSET32(&data[4], 0);
		/* Remaining POW Reallocation Map Entries */
		DSET32(&data[8], 0);
		/* Number of Remaining POW Updates */
		DSET32(&data[12], 0);
		len = 16 - hlen;

		/* Disc Information Length */
		DSET16(&data[0], len);
		break;

	default:
		ISTGT_ERRLOG("unsupported datatype 0x%x\n", datatype);
		return -1;
	}

	return hlen + len;
}

static int
istgt_lu_dvd_scsi_read_disc_structure(ISTGT_LU_DVD *spec, CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), int mediatype, int layernumber __attribute__((__unused__)), int format, int agid __attribute__((__unused__)), uint8_t *data)
{
	uint8_t *cp;
	int hlen = 0, len = 0;

	if (mediatype == 0x00) {
		/* DVD and HD DVD types */
	} else if (mediatype == 0x01) {
		/* BD */
	} else {
		/* Reserved */
	}

	switch (format) {
	case 0x00: /* Physical Format Information */
		/* Disc Structure Data Length */
		DSET16(&data[0], 0);
		/* Reserved */
		data[2] = 0;
		/* Reserved */
		data[3] = 0;
		hlen = 4;

		/* Physical Format Information */
		cp = &data[hlen + len];

		/* Disk Category(7-4) Part Version(3-0) */
		BDSET8W(&cp[0], 0x00, 7, 4);		/* DVD-ROM */
		BDADD8W(&cp[0], 0x01, 3, 4);		/* part 1 */
		/* Disc Size(7-4) Maximum Rate(0-3) */
		BDSET8W(&cp[1], 0x00, 7, 4);		/* 120mm */
		BDADD8W(&cp[1], 0x0f, 3, 4);		/* Not Specified */
		/* Number of Layers(6-5) Track(4) Layer Type(3-0) */
		BDSET8W(&cp[2], 0x00, 6, 2);		/* one layer */
		BDADD8W(&cp[2], 0x00, 4, 1);		/* Parallel Track Path */
		BDADD8W(&cp[2], 0x00, 3, 4);		/* embossed data */
		/* Linear Density(7-4) Track Density(3-0) */
		BDSET8W(&cp[3], 0x00, 7, 4);		/* 0.267 um/bit */
		BDADD8W(&cp[3], 0x00, 3, 4);		/* 0.74 um/track */
		/* Starting Physical Sector Number of Data Area */
		DSET32(&cp[4], 0);
		/* End Physical Sector Number of Data Area */
		DSET32(&cp[8], spec->blockcnt - 1);
		/* End Physical Sector Number in Layer 0 */
		DSET32(&cp[12], spec->blockcnt - 1);
		/* BCA(7) */
		BDSET8(&cp[16], 0, 7);
		/* Media Specific */
		memset(&cp[17], 0, 2048 - 16);
		len = 2048;

		/* Disc Information Length */
		DSET16(&data[0], hlen + len - 2);
		break;

	case 0x01: /* DVD Copyright Information */
		/* Disc Structure Data Length */
		DSET16(&data[0], 0);
		/* Reserved */
		data[2] = 0;
		/* Reserved */
		data[3] = 0;
		hlen = 4;

		/* DVD Copyright Information */
		cp = &data[hlen + len];

		/* Copyright Protection System Type */
		cp[0] = 0x00;
		//cp[0] = 0x01;				/* CSS/CPPM */
		/* Region Management Information */
		cp[1] = 0x00;
		//cp[1] = 0xff & ~(1 << (2 - 1));	/* 2=Japan */
		/* Reserved */
		cp[2] = 0;
		/* Reserved */
		cp[3] = 0;
		len = 4;

		/* Disc Information Length */
		DSET16(&data[0], hlen + len - 2);
		break;

	default:
		ISTGT_ERRLOG("unsupported format 0x%x\n", format);
		return -1;
	}

	return hlen + len;
}

static int
istgt_lu_dvd_scsi_report_key(ISTGT_LU_DVD *spec __attribute__((__unused__)), CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), int keyclass, int agid __attribute__((__unused__)), int keyformat, uint8_t *data)
{
	uint8_t *cp;
	int hlen = 0, len = 0;

	if (keyclass == 0x00) {
		/* DVD CSS/CPPM or CPRM */
	} else {
		return -1;
	}

	switch (keyformat) {
	case 0x08: /* Report Drive region settings */
		/* REPORT KEY Data Length */
		DSET16(&data[0], 6);
		/* Reserved */
		data[2] = 0;
		/* Reserved */
		data[3] = 0;
		hlen = 4;

		/* RPC State */
		cp = &data[hlen + len];

		/* Type Code(7-6) # of Vendor Resets Available(5-3) */
		/* # of User Controlled Changes Available(2-0) */
		BDSET8W(&cp[0], 0x00, 7, 2);	/* No Drive region setting */
		//BDSET8W(&cp[0], 0x01, 7, 2);	/* Drive region is set */
		BDADD8W(&cp[0], 4, 5, 3);		/* # of vendor */
		BDADD8W(&cp[0], 5, 2, 3);		/* # of user */
		/* Region Mask */
		cp[1] = 0;
		//cp[1] = 0xff & ~(1 << (2 - 1));	/* 2=Japan */
		/* RPC Scheme */
		cp[2] = 0;
		//cp[2] = 0x01;	/* RPC Phase II */
		/* Reserved */
		cp[3] = 0;
		len = 4;

		/* REPORT KEY Data Length */
		DSET16(&data[0], hlen + len - 2);
		break;

	case 0x00: /* AGID for CSS/CPPM */
	case 0x01: /* Challenge Key */
	case 0x02: /* KEY1 */
	case 0x04: /* TITLE KEY */
	case 0x05: /* ASF */
	case 0x11: /* AGID for CPRM */
		/* not supported */
		return -1;

	default:
		ISTGT_ERRLOG("unsupported keyformat 0x%x\n", keyformat);
		return -1;
	}

	return hlen + len;
}

static int
istgt_lu_dvd_lbread(ISTGT_LU_DVD *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lba, uint32_t len)
{
	uint8_t *data;
	uint64_t maxlba;
	uint64_t llen;
	uint64_t blen;
	uint64_t offset;
	uint64_t nbytes;
	int64_t rc;

	if (len == 0) {
		lu_cmd->data = NULL;
		lu_cmd->data_len = 0;
		return 0;
	}

	maxlba = spec->blockcnt;
	llen = (uint64_t) len;
	blen = spec->blocklen;
	offset = lba * blen;
	nbytes = llen * blen;

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
	    "Read: max=%"PRIu64", lba=%"PRIu64", len=%u\n",
	    maxlba, lba, len);

	if (lba >= maxlba || llen > maxlba || lba > (maxlba - llen)) {
		ISTGT_ERRLOG("end of media\n");
		return -1;
	}

	if (nbytes > lu_cmd->iobufsize) {
		ISTGT_ERRLOG("nbytes(%zu) > iobufsize(%zu)\n",
		    (size_t) nbytes, lu_cmd->iobufsize);
		return -1;
	}
	data = lu_cmd->iobuf;

	rc = istgt_lu_dvd_seek(spec, offset);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_dvd_seek() failed\n");
		return -1;
	}

	rc = istgt_lu_dvd_read(spec, data, nbytes);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_dvd_read() failed\n");
		return -1;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "Read %"PRId64"/%"PRIu64" bytes\n",
	    rc, nbytes);

	lu_cmd->data = data;
	lu_cmd->data_len = rc;

	return 0;
}

#if 0
static int
istgt_lu_dvd_lbwrite(ISTGT_LU_DVD *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lba, uint32_t len)
{
	uint8_t *data;
	uint64_t maxlba;
	uint64_t llen;
	uint64_t blen;
	uint64_t offset;
	uint64_t nbytes;
	int64_t rc;

	if (len == 0) {
		lu_cmd->data_len = 0;
		return 0;
	}

	maxlba = spec->blockcnt;
	llen = (uint64_t) len;
	blen = spec->blocklen;
	offset = lba * blen;
	nbytes = llen * blen;

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
	    "Write: max=%"PRIu64", lba=%"PRIu64", len=%u\n",
	    maxlba, lba, len);

	if (lba >= maxlba || llen > maxlba || lba > (maxlba - llen)) {
		ISTGT_ERRLOG("end of media\n");
		return -1;
	}

	if (nbytes > lu_cmd->iobufsize) {
		ISTGT_ERRLOG("nbytes(%u) > iobufsize(%u)\n",
		    nbytes, lu_cmd->iobufsize);
		return -1;
	}
	data = lu_cmd->iobuf;

	rc = istgt_lu_dvd_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
	    lu_cmd->iobufsize, nbytes);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_dvd_transfer_data() failed\n");
		return -1;
	}

	if (spec->lu->readonly) {
		ISTGT_ERRLOG("LU%d: readonly unit\n", spec->lu->num);
		return -1;
	}
	if (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY) {
		ISTGT_ERRLOG("LU%d: readonly media\n", spec->lu->num);
		return -1;
	}

	rc = istgt_lu_dvd_seek(spec, offset);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_dvd_seek() failed\n");
		return -1;
	}

	rc = istgt_lu_dvd_write(spec, data, nbytes);
	if (rc < 0 || rc != nbytes) {
		ISTGT_ERRLOG("lu_dvd_write() failed\n");
		return -1;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "Wrote %"PRId64"/%"PRIu64" bytes\n",
	    rc, nbytes);

	lu_cmd->data_len = rc;

	return 0;
}

static int
istgt_lu_dvd_lbsync(ISTGT_LU_DVD *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lba, uint32_t len)
{
	uint64_t maxlba;
	uint64_t llen;
	uint64_t blen;
	uint64_t offset;
	uint64_t nbytes;
	int64_t rc;

	if (len == 0) {
		return 0;
	}

	maxlba = spec->blockcnt;
	llen = (uint64_t) len;
	blen = spec->blocklen;
	offset = lba * blen;
	nbytes = llen * blen;

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
	    "Sync: max=%"PRIu64", lba=%"PRIu64", len=%u\n",
	    maxlba, lba, len);

	if (lba >= maxlba || llen > maxlba || lba > (maxlba - llen)) {
		ISTGT_ERRLOG("end of media\n");
		return -1;
	}

	rc = istgt_lu_dvd_sync(spec, offset, nbytes);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_dvd_sync() failed\n");
		return -1;
	}

	return 0;
}
#endif

static int
istgt_lu_dvd_build_sense_data(ISTGT_LU_DVD *spec __attribute__((__unused__)), uint8_t *data, int sk, int asc, int ascq)
{
	int rc;

	rc = istgt_lu_scsi_build_sense_data(data, sk, asc, ascq);
	if (rc < 0) {
		return -1;
	}
	return rc;
}

static int
istgt_lu_dvd_build_sense_media(ISTGT_LU_DVD *spec, uint8_t *data)
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

int
istgt_lu_dvd_reset(ISTGT_LU_Ptr lu, int lun)
{
	ISTGT_LU_DVD *spec;
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
	spec = (ISTGT_LU_DVD *) lu->lun[lun].spec;

	if (spec->lock) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "unlock by reset\n");
		spec->lock = 0;
	}

	/* re-open file */
	if (!spec->lu->readonly
	    && !(spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY)) {
		rc = istgt_lu_dvd_sync(spec, 0, spec->size);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: LUN%d: lu_dvd_sync() failed\n",
			    lu->num, lun);
			/* ignore error */
		}
	}
	rc = istgt_lu_dvd_close(spec);
	if (rc < 0) {
		ISTGT_ERRLOG("LU%d: LUN%d: lu_dvd_close() failed\n",
		    lu->num, lun);
		/* ignore error */
	}
	flags = (lu->readonly || (spec->mflags & ISTGT_LU_FLAG_MEDIA_READONLY))
		? O_RDONLY : O_RDWR;
	rc = istgt_lu_dvd_open(spec, flags, 0666);
	if (rc < 0) {
		ISTGT_ERRLOG("LU%d: LUN%d: lu_dvd_open() failed\n",
		    lu->num, lun);
		return -1;
	}

	return 0;
}

int
istgt_lu_dvd_execute(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	ISTGT_LU_Ptr lu;
	ISTGT_LU_DVD *spec;
	uint8_t *data;
	uint8_t *cdb;
	uint64_t fmt_lun;
	uint64_t lun;
	uint64_t method;
	uint32_t allocation_len;
	int data_len;
	int data_alloc_len;
	uint64_t lba;
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
#ifdef ISTGT_TRACE_DVD
		ISTGT_ERRLOG("LU%d: LUN%4.4"PRIx64" invalid\n",
					 lu->num, lun);
#endif /* ISTGT_TRACE_DVD */
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
	spec = (ISTGT_LU_DVD *) lu->lun[lun].spec;
	if (spec == NULL) {
		/* LOGICAL UNIT NOT SUPPORTED */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x25, 0x00);
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return 0;
	}

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "SCSI OP=0x%x, LUN=0x%16.16"PRIx64"\n",
	    cdb[0], lu_cmd->lun);
#ifdef ISTGT_TRACE_DVD
	if (cdb[0] != SPC_TEST_UNIT_READY
		&& cdb[0] != MMC_GET_EVENT_STATUS_NOTIFICATION) {
		istgt_scsi_dump_cdb(cdb);
	} else {
		istgt_scsi_dump_cdb(cdb);
	}
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "mload=%d, mchanged=%d, mwait=%d\n", spec->mload, spec->mchanged, spec->mwait);
#endif /* ISTGT_TRACE_DVD */
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
		data_len = istgt_lu_dvd_scsi_inquiry(spec, conn, cdb,
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
			data_len = istgt_lu_dvd_scsi_report_luns(lu, conn, cdb, sel,
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
			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);

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

	case MMC_START_STOP_UNIT:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "START_STOP_UNIT\n");
		{
			int pc, fl, loej, start;

			pc = BGET8W(&cdb[4], 7, 4);
			fl = BGET8(&cdb[4], 2);
			loej = BGET8(&cdb[4], 1);
			start = BGET8(&cdb[4], 0);

			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			if (!loej) {
				if (start) {
					/* start */
				} else {
					/* stop */
				}
				lu_cmd->data_len = 0;
				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				break;
			}

			/* loej=1 */
			if (start) {
				/* load disc */
				if (!spec->mload) {
					if (istgt_lu_dvd_load_media(spec) < 0) {
						ISTGT_ERRLOG("lu_dvd_load_media() failed\n");
						/* INTERNAL TARGET FAILURE */
						BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
						lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
						break;
					}
					/* OK load */
				}
			} else {
				/* eject */
				if (!spec->lock) {
					if (spec->mload) {
						if (istgt_lu_dvd_unload_media(spec) < 0) {
							ISTGT_ERRLOG("lu_dvd_unload_media() failed\n");
							/* INTERNAL TARGET FAILURE */
							BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
							lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
							break;
						}
						/* OK unload */
					}
				} else {
					/* MEDIUM REMOVAL PREVENTED */
					BUILD_SENSE(ILLEGAL_REQUEST, 0x53, 0x02);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					break;
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

			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
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

	case MMC_READ_CAPACITY:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ_CAPACITY\n");
		if (lu_cmd->R_bit == 0) {
			ISTGT_ERRLOG("R_bit == 0\n");
			return -1;
		}

		data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
		if (data_len != 0) {
			*sense_len = data_len;
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			break;
		}

		if (spec->blockcnt - 1 > 0xffffffffULL) {
			DSET32(&data[0], 0xffffffffUL);
		} else {
			DSET32(&data[0], (uint32_t) (spec->blockcnt - 1));
		}
		DSET32(&data[4], (uint32_t) spec->blocklen);
		data_len = 8;
		lu_cmd->data_len = data_len;
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		break;

	case SPC_MODE_SELECT_6:
		{
			int pf, sp, pllen;
			int mdlen, mt, dsp, bdlen;

			pf = BGET8(&cdb[1], 4);
			sp = BGET8(&cdb[1], 0);
			pllen = cdb[4];             /* Parameter List Length */

			/* Data-Out */
			rc = istgt_lu_dvd_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
			    lu_cmd->iobufsize, pllen);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_dvd_transfer_data() failed\n");
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

			/* Short LBA mode parameter block descriptor */
			/* data[4]-data[7] Number of Blocks */
			/* data[8]-data[11] Block Length */

			/* page data */
			data_len = istgt_lu_dvd_scsi_mode_select_page(spec, conn, cdb, pf, sp, &data[4 + bdlen], pllen - (4 + bdlen));
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
			rc = istgt_lu_dvd_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
			    lu_cmd->iobufsize, pllen);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_dvd_transfer_data() failed\n");
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
				/* Long LBA mode parameter block descriptor */
				/* data[8]-data[15] Number of Blocks */
				/* data[16]-data[19] Reserved */
				/* data[20]-data[23] Block Length */
			} else {
				/* Short LBA mode parameter block descriptor */
				/* data[8]-data[11] Number of Blocks */
				/* data[12]-data[15] Block Length */
			}

			/* page data */
			data_len = istgt_lu_dvd_scsi_mode_select_page(spec, conn, cdb, pf, sp, &data[8 + bdlen], pllen - (8 + bdlen));
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

			data_len = istgt_lu_dvd_scsi_mode_sense6(spec, conn, cdb, dbd, pc, page, subpage, data, data_alloc_len);
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

			data_len = istgt_lu_dvd_scsi_mode_sense10(spec, conn, cdb, llbaa, dbd, pc, page, subpage, data, data_alloc_len);
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
	case SPC_LOG_SENSE:
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

			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);

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
			data_len = istgt_lu_dvd_build_sense_data(spec, sense_data,
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

	case MMC_GET_CONFIGURATION:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "GET_CONFIGURATION\n");
		{
			int rt, sfn;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			rt = BGET8W(&cdb[1], 1, 2);
			sfn = DGET16(&cdb[2]);

			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			allocation_len = DGET16(&cdb[7]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			data_len = istgt_lu_dvd_scsi_get_configuration(spec, conn, cdb, rt, sfn, data);
			if (data_len < 0) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case MMC_GET_EVENT_STATUS_NOTIFICATION:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "GET_EVENT_STATUS_NOTIFICATION\n");
		{
			int polled, ncr;
			int keep = 0;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			polled = BGET8(&cdb[1], 0);
			ncr = cdb[4];

			allocation_len = DGET16(&cdb[7]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			if (!polled) {
				/* asynchronous operation */
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (allocation_len <= 4) {
				/* shall not clear any event */
				keep = 1;
			}
			data_len = istgt_lu_dvd_scsi_get_event_status_notification(spec, conn, cdb, keep, ncr, data);
			if (data_len < 0) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "EVENT", data, data_len);
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case MMC_GET_PERFORMANCE:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "GET_PERFORMANCE\n");
		{
			int dt, mnd, type;

			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			dt = BGET8W(&cdb[1], 4, 5);
			lba = DGET32(&cdb[2]);
			mnd = DGET16(&cdb[8]);
			type = cdb[10];

			/* INVALID COMMAND OPERATION CODE */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			break;
		}

	case MMC_MECHANISM_STATUS:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MECHANISM_STATUS\n");
		{
			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			allocation_len = DGET16(&cdb[8]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			data_len = istgt_lu_dvd_scsi_mechanism_status(spec, conn, cdb, data);
			if (data_len < 0) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case MMC_READ_TOC_PMA_ATIP:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ_TOC_PMA_ATIP\n");
		{
			int msf, format, track;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			msf = BGET8(&cdb[1], 1);
			format = BGET8W(&cdb[2], 3, 4);
			track = cdb[6];

			allocation_len = DGET16(&cdb[7]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			data_len = istgt_lu_dvd_scsi_read_toc(spec, conn, cdb, msf, format, track, data);
			if (data_len < 0) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case MMC_READ_DISC_INFORMATION:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ_DISC_INFORMATION\n");
		{
			int datatype;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			datatype = BGET8W(&cdb[1], 2, 3);

			allocation_len = DGET16(&cdb[7]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			data_len = istgt_lu_dvd_scsi_read_disc_information(spec, conn, cdb, datatype, data);
			if (data_len < 0) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case MMC_READ_DISC_STRUCTURE:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ_DISC_STRUCTURE\n");
		{
			int mediatype, layernumber, format, agid;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			mediatype = BGET8W(&cdb[1], 3, 4);
			layernumber = cdb[6];
			format = cdb[7];
			agid = BGET8W(&cdb[10], 7, 2);

			allocation_len = DGET16(&cdb[8]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			data_len = istgt_lu_dvd_scsi_read_disc_structure(spec, conn, cdb, mediatype, layernumber, format, agid, data);
			if (data_len < 0) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case MMC_READ_SUB_CHANNEL:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ_SUB_CHANNEL\n");
		{
			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			/* INVALID COMMAND OPERATION CODE */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			break;
		}

	case MMC_REPORT_KEY:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "REPORT_KEY\n");
		{
			int keyclass, agid, keyformat;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			keyclass = cdb[7];
			agid = BGET8W(&cdb[10], 7, 2);
			keyformat = BGET8W(&cdb[10], 5, 6);

			allocation_len = DGET16(&cdb[8]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			data_len = istgt_lu_dvd_scsi_report_key(spec, conn, cdb, keyclass, agid, keyformat, data);
			if (data_len < 0) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case MMC_SEND_KEY:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "SEND_KEY\n");
		{
			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			/* INVALID COMMAND OPERATION CODE */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			break;
		}

	case MMC_READ_10:
		{
			int dpo, fua;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			dpo = BGET8(&cdb[1], 4);
			fua = BGET8(&cdb[1], 3);
			lba = (uint64_t) DGET32(&cdb[2]);
			transfer_len = (uint32_t) DGET16(&cdb[7]);
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "READ_10(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_dvd_lbread(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_dvd_lbread() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case MMC_READ_12:
		{
			int dpo, fua;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			data_len = istgt_lu_dvd_build_sense_media(spec, sense_data);
			if (data_len != 0) {
				*sense_len = data_len;
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			dpo = BGET8(&cdb[1], 4);
			fua = BGET8(&cdb[1], 3);
			lba = (uint64_t) DGET32(&cdb[2]);
			transfer_len = (uint32_t) DGET32(&cdb[6]);
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "READ_12(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_dvd_lbread(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_dvd_lbread() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

#if 0
	case MMC_WRITE_10:
	case MMC_WRITE_AND_VERIFY_10:
	case MMC_WRITE_12:
	case MMC_VERIFY_10:
	case MMC_SYNCHRONIZE_CACHE:
		/* INVALID COMMAND OPERATION CODE */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		break;
#endif

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
