/*
 * Copyright (C) 2008-2012 Daisuke Aoyama <aoyama@peach.ne.jp>.
 * Copyright (C) 2013 David Disseldorp
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
#include <stdbool.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include <fcntl.h>
#include <unistd.h>

#include "istgt.h"
#include "istgt_log.h"
#include "istgt_misc.h"
#include "istgt_lu.h"
#include "istgt_proto.h"

#if !defined(__GNUC__)
#undef __attribute__
#define __attribute__(x)
#endif

#ifdef HAVE_ELASTO
#include "elasto/data.h"
#include "elasto/file.h"

struct istgt_lu_disk_elasto {
	struct elasto_fh *efh;
};

static int
istgt_lu_disk_open_elasto(ISTGT_LU_DISK *spec,
			int flags,
			int mode __attribute__((__unused__)))
{
	struct elasto_fauth auth;
	int ret;
	struct istgt_lu_disk_elasto *exspec
				= (struct istgt_lu_disk_elasto *)spec->exspec;

	if (flags != O_RDWR) {
		ISTGT_ERRLOG("read-only Elasto cloud disk not supported\n");
		return -1;
	}

	auth.type = ELASTO_FILE_AZURE;
	auth.az.ps_path = xstrdup(spec->ps_file);
	auth.insecure_http = true;

	ret = elasto_fcreate(&auth,
			     spec->file,
			     spec->size,
			     &exspec->efh);
	if (ret < 0) {
		ISTGT_ERRLOG("failed to open Elasto file: %s\n", spec->file);
		xfree(auth.az.ps_path);
		return -1;
	}

	xfree(auth.az.ps_path);
	return 0;
}

static int
istgt_lu_disk_close_elasto(ISTGT_LU_DISK *spec)
{
	int ret;
	struct istgt_lu_disk_elasto *exspec
				= (struct istgt_lu_disk_elasto *)spec->exspec;

	ret = elasto_fclose(exspec->efh);
	if (ret < 0) {
		ISTGT_ERRLOG("failed to close Elasto file: %s\n", spec->file);
		return -1;
	}

	return 0;
}

static int64_t
istgt_lu_disk_seek_elasto(ISTGT_LU_DISK *spec, uint64_t offset)
{
	spec->foffset = offset;
	return 0;
}

static int64_t
istgt_lu_disk_read_elasto(ISTGT_LU_DISK *spec, void *buf, uint64_t nbytes)
{
	struct istgt_lu_disk_elasto *exspec
				= (struct istgt_lu_disk_elasto *)spec->exspec;
	struct elasto_data *data;
	int ret;

	ret = elasto_data_iov_new((uint8_t *)buf, nbytes, 0, false, &data);
	if (ret < 0) {
		ISTGT_ERRLOG("read data init error\n");
		return -1;
	}

	ret = elasto_fread(exspec->efh, spec->foffset, nbytes, data);
	if (ret < 0) {
		ISTGT_ERRLOG("elasto_fread error\n");
		return -1;
	}

	data->iov.buf = NULL;
	elasto_data_free(data);

	spec->foffset += nbytes;
	return (int64_t)nbytes;
}

static int64_t
istgt_lu_disk_write_elasto(ISTGT_LU_DISK *spec, const void *buf, uint64_t nbytes)
{
	struct istgt_lu_disk_elasto *exspec
				= (struct istgt_lu_disk_elasto *)spec->exspec;
	struct elasto_data *data;
	int ret;

	ret = elasto_data_iov_new((uint8_t *)buf, nbytes, 0, false, &data);
	if (ret < 0) {
		ISTGT_ERRLOG("write data init error\n");
		return -1;
	}

	ret = elasto_fwrite(exspec->efh, spec->foffset, nbytes, data);
	if (ret < 0) {
		ISTGT_ERRLOG("elasto_fwrite error\n");
		return -1;
	}

	data->iov.buf = NULL;
	elasto_data_free(data);

	spec->foffset += nbytes;
	return (int64_t)nbytes;
}

static int64_t
istgt_lu_disk_sync_elasto(ISTGT_LU_DISK *spec, uint64_t offset __attribute__((__unused__)), uint64_t nbytes __attribute__((__unused__)))
{
	struct istgt_lu_disk_elasto *exspec
				= (struct istgt_lu_disk_elasto *)spec->exspec;

	/* IO is done synchronously, so nothing to do here */

	return 0;
}

static int
istgt_lu_disk_allocate_elasto(ISTGT_LU_DISK *spec __attribute__((__unused__)))
{
	struct istgt_lu_disk_elasto *exspec
				= (struct istgt_lu_disk_elasto *)spec->exspec;

	/* not implemented */

	return 0;
}

static int
istgt_lu_disk_setcache_elasto(ISTGT_LU_DISK *spec)
{
	struct istgt_lu_disk_elasto *exspec
				= (struct istgt_lu_disk_elasto *)spec->exspec;

	/* not implemented */

	if (spec->read_cache) {
	}
	if (spec->write_cache) {
	}
	return 0;
}

int
istgt_lu_disk_elasto_lun_init(ISTGT_LU_DISK *spec,
			      ISTGT_Ptr istgt __attribute__((__unused__)),
			      ISTGT_LU_Ptr lu)
{
	struct istgt_lu_disk_elasto *exspec;
	int flags;
	int rc;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_disk_elasto_lun_init\n");

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d for disktype=%s\n",
	    spec->num, spec->lun, spec->disktype);

	spec->open = istgt_lu_disk_open_elasto;
	spec->close = istgt_lu_disk_close_elasto;
	spec->seek = istgt_lu_disk_seek_elasto;
	spec->read = istgt_lu_disk_read_elasto;
	spec->write = istgt_lu_disk_write_elasto;
	spec->sync = istgt_lu_disk_sync_elasto;
	spec->allocate = istgt_lu_disk_allocate_elasto;
	spec->setcache = istgt_lu_disk_setcache_elasto;

	exspec = xmalloc(sizeof(*exspec));
	memset(exspec, 0, sizeof(*exspec));
	spec->exspec = exspec;

	/* file, size and ps_file already filled by config */
	spec->blocklen = 512;
	spec->blockcnt = spec->size / spec->blocklen;
	if (spec->blockcnt == 0) {
		ISTGT_ERRLOG("LU%d: LUN%d: size zero\n", spec->num, spec->lun);
		return -1;
	}

	flags = lu->readonly ? O_RDONLY : O_RDWR;
	rc = spec->open(spec, flags, 0666);
	if (rc < 0) {
		ISTGT_ERRLOG("LU%d: LUN%d: open error(rc=%d)\n",
		    spec->num, spec->lun, rc);
		return -1;
	}

	printf("LU%d: LUN%d cloud_path=%s, size=%"PRIu64"\n",
	    spec->num, spec->lun, spec->file, spec->size);
	printf("LU%d: LUN%d %"PRIu64" blocks, %"PRIu64" bytes/block\n",
	    spec->num, spec->lun, spec->blockcnt, spec->blocklen);

	return 0;
}

int
istgt_lu_disk_elasto_lun_shutdown(ISTGT_LU_DISK *spec,
				  ISTGT_Ptr istgt __attribute__((__unused__)),
				  ISTGT_LU_Ptr lu __attribute__((__unused__)))
{
	struct istgt_lu_disk_elasto *exspec
				= (struct istgt_lu_disk_elasto *)spec->exspec;
	int rc;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_disk_elasto_lun_shutdown\n");

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d for disktype=%s\n",
	    spec->num, spec->lun, spec->disktype);

	if (!spec->lu->readonly) {
		rc = spec->sync(spec, 0, spec->size);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_disk_sync() failed\n", lu->num);
			/* ignore error */
		}
	}
	rc = spec->close(spec);
	if (rc < 0) {
		ISTGT_ERRLOG("LU%d: lu_disk_close() failed\n", lu->num);
		/* ignore error */
	}

	xfree(exspec);
	spec->exspec = NULL;
	return 0;
}

#else /* HAVE_ELASTO */
int
istgt_lu_disk_elasto_lun_init(ISTGT_LU_DISK *spec,
			      ISTGT_Ptr istgt __attribute__((__unused__)),
			      ISTGT_LU_Ptr lu __attribute__((__unused__)))
{
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d unsupported virtual disk\n",
	    spec->num, spec->lun);
	return -1;
}

int
istgt_lu_disk_elasto_lun_shutdown(ISTGT_LU_DISK *spec,
				  ISTGT_Ptr istgt __attribute__((__unused__)),
				  ISTGT_LU_Ptr lu __attribute__((__unused__)))
{
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d unsupported virtual disk\n",
	    spec->num, spec->lun);
	return -1;
}
#endif /* HAVE_ELASTO */
