/*
 * Copyright (C) 2008-2014 Daisuke Aoyama <aoyama@peach.ne.jp>.
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
#include <time.h>

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
#include "istgt_crc32c.h"
#include "istgt_md5.h"
#include "istgt_iscsi.h"
#include "istgt_lu.h"
#include "istgt_proto.h"
#include "istgt_scsi.h"
#include "istgt_queue.h"

#if !defined(__GNUC__)
#undef __attribute__
#define __attribute__(x)
#endif

#ifndef O_FSYNC
#define O_FSYNC O_SYNC
#endif

//#define ISTGT_TRACE_DISK

typedef enum {
	ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE = 0x01,
	ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS = 0x03,
	ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_REGISTRANTS_ONLY = 0x05,
	ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_REGISTRANTS_ONLY = 0x06,
	ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS = 0x07,
	ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS = 0x08,
} ISTGT_LU_PR_TYPE;

#define PR_ALLOW(WE,EA,ALLRR,WERR,EARR) \
	((((WE)&1) << 4) | (((EA)&1) << 3) | (((ALLRR)&1) << 2) \
	 | (((WERR)&1) << 1) | (((EARR)&1) << 0))
#define PR_ALLOW_WE    0x0010
#define PR_ALLOW_EA    0x0008
#define PR_ALLOW_ALLRR 0x0004
#define PR_ALLOW_WERR  0x0002
#define PR_ALLOW_EARR  0x0001

#define BUILD_SENSE(SK,ASC,ASCQ)					\
	do {								\
		*sense_len =						\
			istgt_lu_disk_build_sense_data(spec, sense_data, \
			    ISTGT_SCSI_SENSE_ ## SK,			\
			    (ASC), (ASCQ));				\
	} while (0)
#define BUILD_SENSE2(SK,ASC,ASCQ)					\
	do {								\
		*sense_len =						\
			istgt_lu_disk_build_sense_data2(spec, sense_data, \
			    ISTGT_SCSI_SENSE_ ## SK,			\
			    (ASC), (ASCQ));				\
	} while (0)

static void istgt_lu_disk_free_pr_key(ISTGT_LU_PR_KEY *prkey);
static int istgt_lu_disk_build_sense_data(ISTGT_LU_DISK *spec, uint8_t *data, int sk, int asc, int ascq);
static int istgt_lu_disk_queue_abort_ITL(ISTGT_LU_DISK *spec, const char *initiator_port);

static int
istgt_lu_disk_open_raw(ISTGT_LU_DISK *spec, int flags, int mode)
{
	int rc;

	rc = open(spec->file, flags, mode);
	if (rc < 0) {
		return -1;
	}
	spec->fd = rc;
	spec->foffset = 0;
	return 0;
}

static int
istgt_lu_disk_close_raw(ISTGT_LU_DISK *spec)
{
	int rc;

	if (spec->fd == -1)
		return 0;
	rc = close(spec->fd);
	if (rc < 0) {
		return -1;
	}
	spec->fd = -1;
	spec->foffset = 0;
	return 0;
}

#if 0
static off_t
istgt_lu_disk_lseek_raw(ISTGT_LU_DISK *spec, off_t offset, int whence)
{
	off_t rc;

	rc = lseek(spec->fd, offset, whence);
	if (rc < 0) {
		return -1;
	}
	spec->foffset = offset;
	return rc;
}
#endif

static int64_t
istgt_lu_disk_seek_raw(ISTGT_LU_DISK *spec, uint64_t offset)
{
	off_t rc;

	rc = lseek(spec->fd, (off_t) offset, SEEK_SET);
	if (rc < 0) {
		return -1;
	}
	spec->foffset = offset;
	return 0;
}

static int64_t
istgt_lu_disk_read_raw(ISTGT_LU_DISK *spec, void *buf, uint64_t nbytes)
{
	int64_t rc;

	if (spec->lu->istgt->swmode >= ISTGT_SWMODE_EXPERIMENTAL) {
		if (spec->foffset + nbytes <= spec->fsize) {
			/* inside media */
			rc = (int64_t) read(spec->fd, buf, (size_t) nbytes);
		} else if (spec->foffset >= spec->fsize) {
			/* outside media */
			memset(buf, 0, nbytes);
			rc = nbytes;
			if (spec->foffset + nbytes >= spec->size) {
				rc = spec->size - spec->foffset;
			}
		} else if (spec->foffset + nbytes > spec->fsize) {
			/* both */
			uint64_t request = spec->fsize - spec->foffset;
			memset(buf, 0, nbytes);
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "read %"PRIu64" bytes at %"PRIu64"/%"PRIu64"\n",
				    request, spec->foffset, spec->fsize);
			rc = (int64_t) read(spec->fd, buf, (size_t) request);
			if (rc < 0) {
				return -1;
			}
			if ((uint64_t) rc != request) {
				/* read size < request */
				if (spec->foffset + rc >= spec->size) {
					rc = spec->size - spec->foffset;
				}
				spec->foffset += rc;
				return rc;
			}
			rc = nbytes;
			if (spec->foffset + nbytes >= spec->size) {
				rc = spec->size - spec->foffset;
			}
		} else {
			rc = -1;
		}
		if (rc < 0) {
			return -1;
		}
		spec->foffset += rc;
		return rc;
	}
	rc = (int64_t) read(spec->fd, buf, (size_t) nbytes);
	if (rc < 0) {
		return -1;
	}
	spec->foffset += rc;
	return rc;
}

static int64_t
istgt_lu_disk_write_raw(ISTGT_LU_DISK *spec, const void *buf, uint64_t nbytes)
{
	int64_t rc;

	if (spec->lu->istgt->swmode >= ISTGT_SWMODE_EXPERIMENTAL) {
		if (spec->foffset + nbytes <= spec->fsize) {
			/* inside media */
			rc = (int64_t) write(spec->fd, buf, (size_t) nbytes);
		} else if (spec->foffset + nbytes <= ISTGT_LU_MEDIA_SIZE_MIN) {
			/* allways write in minimum size */
			rc = (int64_t) write(spec->fd, buf, (size_t) nbytes);
		} else if (spec->foffset >= spec->fsize) {
			/* outside media */
			const uint8_t *p = (const uint8_t *) buf;
			uint64_t n;
			for (n = 0; n < nbytes; n++) {
				if (p[n] != 0)
					break;
			}
			if (n == nbytes) {
				/* write all zero (skip) */
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "write zero %"PRIu64" bytes at %"PRIu64"/%"PRIu64"\n",
				    nbytes, spec->foffset, spec->fsize);
				rc = nbytes;
				spec->foffset += rc;
				return rc;
			}
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "write %"PRIu64" bytes at %"PRIu64"/%"PRIu64"\n",
			    nbytes, spec->foffset, spec->fsize);
			rc = (int64_t) write(spec->fd, buf, (size_t) nbytes);
		} else if (spec->foffset + nbytes > spec->fsize) {
			/* both */
			rc = (int64_t) write(spec->fd, buf, (size_t) nbytes);
		} else {
			rc = -1;
		}
		if (rc < 0) {
			return -1;
		}
		spec->foffset += rc;
		if (spec->foffset > spec->fsize) {
			spec->fsize = spec->foffset;
		}
		return rc;
	}
	rc = (int64_t) write(spec->fd, buf, (size_t) nbytes);
	if (rc < 0) {
		return -1;
	}
	spec->foffset += rc;
	if (spec->foffset > spec->fsize) {
		spec->fsize = spec->foffset;
	}
	return rc;
}

static int64_t
istgt_lu_disk_sync_raw(ISTGT_LU_DISK *spec, uint64_t offset, uint64_t nbytes)
{
	int64_t rc;

	rc = (int64_t) fsync(spec->fd);
	if (rc < 0) {
		return -1;
	}
	spec->foffset = offset + nbytes;
	return rc;
}

static int
istgt_lu_disk_allocate_raw(ISTGT_LU_DISK *spec)
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
	spec->fsize = fsize;

	offset = size - nbytes;
	rc = istgt_lu_disk_seek_raw(spec, offset);
	if (rc == -1) {
		ISTGT_ERRLOG("lu_disk_seek() failed\n");
		xfree(data);
		return -1;
	}
	rc = istgt_lu_disk_read_raw(spec, data, nbytes);
	/* EOF is OK */
	if (rc == -1) {
		ISTGT_ERRLOG("lu_disk_read() failed\n");
		xfree(data);
		return -1;
	}
	if (spec->lu->istgt->swmode >= ISTGT_SWMODE_EXPERIMENTAL) {
		/* allocate minimum size */
		if (fsize < ISTGT_LU_MEDIA_SIZE_MIN) {
			fsize = ISTGT_LU_MEDIA_SIZE_MIN;
			if (size < ISTGT_LU_MEDIA_SIZE_MIN) {
				fsize = size;
			}
			offset = fsize - nbytes;
			rc = istgt_lu_disk_seek_raw(spec, offset);
			if (rc == -1) {
				ISTGT_ERRLOG("lu_disk_seek() failed\n");
				xfree(data);
				return -1;
			}
			rc = istgt_lu_disk_write_raw(spec, data, nbytes);
			if (rc == -1 || (uint64_t) rc != nbytes) {
				ISTGT_ERRLOG("lu_disk_write() failed\n");
				xfree(data);
				return -1;
			}
			spec->fsize = fsize;
			spec->foffset = fsize;
		}
	} else {
		/* allocate complete size */
		rc = istgt_lu_disk_seek_raw(spec, offset);
		if (rc == -1) {
			ISTGT_ERRLOG("lu_disk_seek() failed\n");
			xfree(data);
			return -1;
		}
		rc = istgt_lu_disk_write_raw(spec, data, nbytes);
		if (rc == -1 || (uint64_t) rc != nbytes) {
			ISTGT_ERRLOG("lu_disk_write() failed\n");
			xfree(data);
			return -1;
		}
		spec->foffset = size;
	}

	xfree(data);
	return 0;
}

static int
istgt_lu_disk_setcache_raw(ISTGT_LU_DISK *spec)
{
	int flags;
	int rc;
	int fd;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_disk_setcache\n");

	fd = spec->fd;
	if (spec->read_cache) {
		/* not implement */
	} else {
		/* not implement */
	}
	flags = fcntl(fd , F_GETFL, 0);
	if (flags != -1) {
		if (spec->write_cache) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "write cache enable\n");
			rc = fcntl(fd, F_SETFL, (flags & ~O_FSYNC));
			spec->write_cache = 1;
		} else {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "write cache disable\n");
			rc = fcntl(fd, F_SETFL, (flags | O_FSYNC));
			spec->write_cache = 0;
		}
		if (rc == -1) {
#if 0
			ISTGT_ERRLOG("LU%d: LUN%d: fcntl(F_SETFL) failed(errno=%d)\n",
			    spec->num, spec->lun, errno);
#endif
		}
	} else {
		ISTGT_ERRLOG("LU%d: LUN%d: fcntl(F_GETFL) failed(errno=%d)\n",
		    spec->num, spec->lun, errno);
	}
	return 0;
}

static const char *
istgt_get_disktype_by_ext(const char *file)
{
	size_t n;

	if (file == NULL || file[0] == '\n')
		return "RAW";

	n = strlen(file);
	if (n > 4 && strcasecmp(file + (n - 4), ".vdi") == 0)
		return "VDI";
	if (n > 4 && strcasecmp(file + (n - 4), ".vhd") == 0)
		return "VHD";
	if (n > 5 && strcasecmp(file + (n - 5), ".vmdk") == 0)
		return "VMDK";

	if (n > 5 && strcasecmp(file + (n - 5), ".qcow") == 0)
		return "QCOW";
	if (n > 6 && strcasecmp(file + (n - 6), ".qcow2") == 0)
		return "QCOW";
	if (n > 4 && strcasecmp(file + (n - 4), ".qed") == 0)
		return "QED";
	if (n > 5 && strcasecmp(file + (n - 5), ".vhdx") == 0)
		return "VHDX";

	return "RAW";
}

int
istgt_lu_disk_init(ISTGT_Ptr istgt __attribute__((__unused__)), ISTGT_LU_Ptr lu)
{
	ISTGT_LU_DISK *spec;
	uint64_t gb_size;
	uint64_t mb_size;
#ifdef HAVE_UUID_H
	uint32_t status;
#endif /* HAVE_UUID_H */
	int mb_digit;
	int flags;
	int newfile;
	int rc;
	int i, j;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_disk_init\n");

	printf("LU%d HDD UNIT\n", lu->num);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d TargetName=%s\n",
	    lu->num, lu->name);
	for (i = 0; i < lu->maxlun; i++) {
		if (lu->lun[i].type == ISTGT_LU_LUN_TYPE_NONE) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d none\n",
			    lu->num, i);
			lu->lun[i].spec = NULL;
			continue;
		}
		if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_STORAGE) {
			ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
			return -1;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d storage\n",
		    lu->num, i);

		spec = xmalloc(sizeof *spec);
		memset(spec, 0, sizeof *spec);
		spec->lu = lu;
		spec->num = lu->num;
		spec->lun = i;
		spec->fd = -1;
		if (spec->lu->lun[i].readcache) {
			spec->read_cache = 1;
		} else {
			spec->read_cache = 0;
		}
		if (spec->lu->lun[i].writecache) {
			spec->write_cache = 1;
		} else {
			spec->write_cache = 0;
		}
		if (spec->lu->istgt->swmode >= ISTGT_SWMODE_EXPERIMENTAL) {
			spec->wbufsize = ISTGT_LU_MAX_WRITE_CACHE_SIZE;
			spec->wbuf = xmalloc(spec->wbufsize);
			memset(spec->wbuf, 0, spec->wbufsize);
		} else {
			spec->wbufsize = 0;
			spec->wbuf = NULL;
		}
		spec->woffset = 0;
		spec->wnbytes = 0;
		spec->req_write_cache = 0;
		spec->err_write_cache = 0;
		spec->thin_provisioning = 0;
		spec->watssize = 0;
		spec->watsbuf = NULL;

		rc = pthread_mutex_init(&spec->ats_mutex, NULL);
		if (rc != 0) {
			ISTGT_ERRLOG("LU%d: mutex_init() failed\n", lu->num);
			return -1;
		}

		spec->queue_depth = lu->queue_depth;
		rc = pthread_mutex_init(&spec->cmd_queue_mutex, &istgt->mutex_attr);
		if (rc != 0) {
			ISTGT_ERRLOG("LU%d: mutex_init() failed\n", lu->num);
			return -1;
		}
		istgt_queue_init(&spec->cmd_queue);
		rc = pthread_mutex_init(&spec->wait_lu_task_mutex, NULL);
		if (rc != 0) {
			ISTGT_ERRLOG("LU%d: mutex_init() failed\n", lu->num);
			return -1;
		}
		spec->wait_lu_task = NULL;

		spec->npr_keys = 0;
		/* spec is cleared, only pointer is handled */
		for (j = 0; j < MAX_LU_RESERVE; j++) {
			spec->pr_keys[j].registered_initiator_port = NULL;
			spec->pr_keys[j].registered_target_port = NULL;
			spec->pr_keys[j].initiator_ports = NULL;
		}
		spec->pr_generation = 0;
		spec->rsv_port = NULL;
		spec->rsv_key = 0;
		spec->rsv_scope = 0;
		spec->rsv_type = 0;

		spec->sense = 0;
		{
			int sk, asc, ascq;
			/* POWER ON, RESET, OR BUS DEVICE RESET OCCURRED */
			sk = ISTGT_SCSI_SENSE_UNIT_ATTENTION;
			asc = 0x29;
			ascq = 0x00;
			spec->sense = (((sk & 0xffU) << 16)
			    | ((asc & 0xffU) << 8)
			    | ((ascq & 0xffU) << 0));
		}

#ifdef HAVE_UUID_H
		uuid_create(&spec->uuid, &status);
		if (status != uuid_s_ok) {
			ISTGT_ERRLOG("LU%d: LUN%d: uuid_create() failed\n", lu->num, i);
			(void) pthread_mutex_destroy(&spec->wait_lu_task_mutex);
			(void) pthread_mutex_destroy(&spec->cmd_queue_mutex);
			(void) pthread_mutex_destroy(&spec->ats_mutex);
			istgt_queue_destroy(&spec->cmd_queue);
			xfree(spec);
			return -1;
		}
#endif /* HAVE_UUID_H */

		spec->file = lu->lun[i].u.storage.file;
		spec->size = lu->lun[i].u.storage.size;
		spec->disktype = istgt_get_disktype_by_ext(spec->file);
		if (strcasecmp(spec->disktype, "VDI") == 0
		    || strcasecmp(spec->disktype, "VHD") == 0
		    || strcasecmp(spec->disktype, "VMDK") == 0
		    || strcasecmp(spec->disktype, "QCOW") == 0
		    || strcasecmp(spec->disktype, "QED") == 0
		    || strcasecmp(spec->disktype, "VHDX") == 0) {
			rc = istgt_lu_disk_vbox_lun_init(spec, istgt, lu);
			if (rc < 0) {
				ISTGT_ERRLOG("LU%d: LUN%d: lu_disk_vbox_lun_init() failed\n",
				    lu->num, i);
				goto error_return;
			}
		} else if (strcasecmp(spec->disktype, "RAW") == 0) {
			spec->open = istgt_lu_disk_open_raw;
			spec->close = istgt_lu_disk_close_raw;
			spec->seek = istgt_lu_disk_seek_raw;
			spec->read = istgt_lu_disk_read_raw;
			spec->write = istgt_lu_disk_write_raw;
			spec->sync = istgt_lu_disk_sync_raw;
			spec->allocate = istgt_lu_disk_allocate_raw;
			spec->setcache = istgt_lu_disk_setcache_raw;

			spec->blocklen = lu->blocklen;
			if (spec->blocklen != 512
			    && spec->blocklen != 1024
			    && spec->blocklen != 2048
			    && spec->blocklen != 4096
			    && spec->blocklen != 8192
			    && spec->blocklen != 16384
			    && spec->blocklen != 32768
			    && spec->blocklen != 65536
			    && spec->blocklen != 131072
			    && spec->blocklen != 262144
			    && spec->blocklen != 524288) {
				ISTGT_ERRLOG("LU%d: LUN%d: invalid blocklen %"PRIu64"\n",
				    lu->num, i, spec->blocklen);
			error_return:
				(void) pthread_mutex_destroy(&spec->wait_lu_task_mutex);
				(void) pthread_mutex_destroy(&spec->cmd_queue_mutex);
				(void) pthread_mutex_destroy(&spec->ats_mutex);
				istgt_queue_destroy(&spec->cmd_queue);
				xfree(spec);
				return -1;
			}
			spec->blockcnt = spec->size / spec->blocklen;
			if (spec->blockcnt == 0) {
				ISTGT_ERRLOG("LU%d: LUN%d: size zero\n", lu->num, i);
				goto error_return;
			}

#if 0
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "LU%d: LUN%d file=%s, size=%"PRIu64"\n",
			    lu->num, i, spec->file, spec->size);
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "LU%d: LUN%d %"PRIu64" blocks, %"
			    PRIu64" bytes/block\n",
			    lu->num, i, spec->blockcnt, spec->blocklen);
#endif
			printf("LU%d: LUN%d file=%s, size=%"PRIu64"\n",
			    lu->num, i, spec->file, spec->size);
			printf("LU%d: LUN%d %"PRIu64" blocks, %"PRIu64" bytes/block\n",
			    lu->num, i, spec->blockcnt, spec->blocklen);
			
			flags = lu->readonly ? O_RDONLY : O_RDWR;
			newfile = 0;
			rc = spec->open(spec, flags, 0666);
			if (rc < 0) {
				newfile = 1;
				flags = lu->readonly ? O_RDONLY : (O_CREAT | O_EXCL | O_RDWR);
				rc = spec->open(spec, flags, 0666);
				if (rc < 0) {
					ISTGT_ERRLOG("LU%d: LUN%d: open error(errno=%d)\n",
					    lu->num, i, errno);
					goto error_return;
				}
			}
			if (!lu->readonly) {
				rc = spec->allocate(spec);
				if (rc < 0) {
					ISTGT_ERRLOG("LU%d: LUN%d: allocate error\n",
					    lu->num, i);
					goto error_return;
				}
			}
			rc = spec->setcache(spec);
			if (rc < 0) {
				ISTGT_ERRLOG("LU%d: LUN%d: setcache error\n", lu->num, i);
				goto error_return;
			}
		} else {
			ISTGT_ERRLOG("LU%d: LUN%d: unsupported format\n", lu->num, i);
			goto error_return;
		}

		gb_size = spec->size / ISTGT_LU_1GB;
		mb_size = (spec->size % ISTGT_LU_1GB) / ISTGT_LU_1MB;
		if (gb_size > 0) {
			mb_digit = (int) (((mb_size * 100) / 1024) / 10);
#if 0
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "LU%d LUN%d %"PRIu64".%dGB %sstorage for %s\n",
			    lu->num, i, gb_size, mb_digit,
			    lu->readonly ? "readonly " : "", lu->name);
#endif
			printf("LU%d: LUN%d %"PRIu64".%dGB %sstorage for %s\n",
			    lu->num, i, gb_size, mb_digit,
			    lu->readonly ? "readonly " : "", lu->name);
		} else {
#if 0
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "LU%d: LUN%d %"PRIu64"MB %sstorage for %s\n",
			    lu->num, i, mb_size,
			    lu->readonly ? "readonly " : "", lu->name);
#endif
			printf("LU%d: LUN%d %"PRIu64"MB %sstorage for %s\n",
			    lu->num, i, mb_size,
			    lu->readonly ? "readonly " : "", lu->name);
		}
		if (spec->lu->lun[i].serial != NULL) {
			printf("LU%d: LUN%d serial %s\n",
			    lu->num, i, spec->lu->lun[i].serial);
		} else {
			printf("LU%d: LUN%d serial %s\n",
			    lu->num, i, spec->lu->inq_serial);
		}
		printf("LU%d: LUN%d ", lu->num, i);
		if (spec->read_cache) {
			printf("read cache enabled");
		} else {
			printf("read cache disabled");
		}
		printf(", ");
		if (spec->write_cache) {
			printf("write cache enabled");
		} else {
			printf("write cache disabled");
		}
		printf("\n");
		if (spec->queue_depth != 0) {
			printf("LU%d: LUN%d command queuing enabled, depth %d\n",
			    lu->num, i, spec->queue_depth);
		} else {
			printf("LU%d: LUN%d command queuing disabled\n",
			    lu->num, i);
		}
#if 0
		if (spec->write_cache && spec->wbufsize) {
			mb_size = (spec->wbufsize / ISTGT_LU_1MB);
			printf("LU%d: LUN%d write buffer %"PRIu64"MB\n",
			    lu->num, i, mb_size);
		}
#endif

		lu->lun[i].spec = spec;
	}

	return 0;
}

int
istgt_lu_disk_shutdown(ISTGT_Ptr istgt __attribute__((__unused__)), ISTGT_LU_Ptr lu)
{
	ISTGT_LU_DISK *spec;
	ISTGT_LU_PR_KEY *prkey;
	int rc;
	int i, j;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_disk_shutdown\n");

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d TargetName=%s\n",
	    lu->num, lu->name);
	for (i = 0; i < lu->maxlun; i++) {
		if (lu->lun[i].type == ISTGT_LU_LUN_TYPE_NONE) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d none\n",
			    lu->num, i);
			continue;
		}
		if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_STORAGE) {
			ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
			return -1;
		}
		spec = (ISTGT_LU_DISK *) lu->lun[i].spec;

		if (strcasecmp(spec->disktype, "VDI") == 0
		    || strcasecmp(spec->disktype, "VHD") == 0
		    || strcasecmp(spec->disktype, "VMDK") == 0
		    || strcasecmp(spec->disktype, "QCOW") == 0
		    || strcasecmp(spec->disktype, "QED") == 0
		    || strcasecmp(spec->disktype, "VHDX") == 0) {
			rc = istgt_lu_disk_vbox_lun_shutdown(spec, istgt, lu);
			if (rc < 0) {
				ISTGT_ERRLOG("LU%d: lu_disk_vbox_lun_shutdown() failed\n",
				    lu->num);
				/* ignore error */
			}
		} else if (strcasecmp(spec->disktype, "RAW") == 0) {
			if (!spec->lu->readonly) {
				rc = spec->sync(spec, 0, spec->size);
				if (rc < 0) {
					//ISTGT_ERRLOG("LU%d: lu_disk_sync() failed\n", lu->num);
					/* ignore error */
				}
			}
			rc = spec->close(spec);
			if (rc < 0) {
				//ISTGT_ERRLOG("LU%d: lu_disk_close() failed\n", lu->num);
				/* ignore error */
			}
		} else {
			ISTGT_ERRLOG("LU%d: LUN%d: unsupported format\n", lu->num, i);
			return -1;
		}

		for (j = 0; j < spec->npr_keys; j++) {
			prkey = &spec->pr_keys[j];
			istgt_lu_disk_free_pr_key(prkey);
		}
		if (spec->rsv_key != 0) {
			xfree(spec->rsv_port);
			spec->rsv_port = NULL;
		}

		rc = pthread_mutex_destroy(&spec->ats_mutex);
		if (rc != 0) {
			//ISTGT_ERRLOG("LU%d: mutex_destroy() failed\n", lu->num);
			/* ignore error */
		}

		istgt_queue_destroy(&spec->cmd_queue);
		rc = pthread_mutex_destroy(&spec->cmd_queue_mutex);
		if (rc != 0) {
			//ISTGT_ERRLOG("LU%d: mutex_destroy() failed\n", lu->num);
			/* ignore error */
		}
		rc = pthread_mutex_destroy(&spec->wait_lu_task_mutex);
		if (rc != 0) {
			//ISTGT_ERRLOG("LU%d: mutex_destroy() failed\n", lu->num);
			/* ignore error */
		}
		xfree(spec->watsbuf);
		xfree(spec->wbuf);
		xfree(spec);
		lu->lun[i].spec = NULL;
	}

	return 0;
}

void
istgt_scsi_dump_cdb(uint8_t *cdb)
{
	int group;
	int cdblen = 0;
	int i;

	if (cdb == NULL)
		return;

	group = (cdb[0] >> 5) & 0x07;
	switch (group) {
	case 0x00:
		/* 6byte commands */
		cdblen = 6;
		break;
	case 0x01:
		/* 10byte commands */
		cdblen = 10;
		break;
	case 0x02:
		/* 10byte commands */
		cdblen = 10;
		break;
	case 0x03:
		/* reserved */
		if (cdb[0] == 0x7f) {
			/* variable length */
			cdblen = 8 + (cdb[7] & 0xff);
		} else {
			/* XXX */
			cdblen = 6;
		}
		break;
	case 0x04:
		/* 16byte commands */
		cdblen = 16;
		break;
	case 0x05:
		/* 12byte commands */
		cdblen = 12;
		break;
	case 0x06:
	case 0x07:
		/* vendor specific */
		cdblen = 6;
		break;
	}

	printf("CDB=");
	for (i = 0; i < cdblen; i++) {
		printf("%2.2x ", cdb[i]);
	}
	printf("\n");
}

void
istgt_strcpy_pad(uint8_t *dst, size_t size, const char *src, int pad)
{
	size_t len;

	len = strlen(src);
	if (len < size) {
		memcpy(dst, src, len);
		memset(dst + len, pad, (size - len));
	} else {
		memcpy(dst, src, size);
	}
}

#ifdef HAVE_UUID_H
uint64_t
istgt_uuid2uint64(uuid_t *uuid)
{
	uint64_t low, mid, hi;
	uint64_t r;

	low = (uint64_t) uuid->time_low;
	mid = (uint64_t) uuid->time_mid;
	hi  = (uint64_t) uuid->time_hi_and_version;
	r = (hi & 0xffffULL) << 48;
	r |= (mid & 0xffffULL) << 32;
	r |= (low & 0xffffffffULL);
	return r;
}
#endif /* HAVE_UUID_H */

uint64_t
istgt_get_lui(const char *name, int lun)
{
	char buf[MAX_TMPBUF];
	uint32_t crc32c;
	uint64_t r;

	if (lun >= 0) {
		snprintf(buf, sizeof buf, "%s,%d",
		    name, lun);
	} else {
		snprintf(buf, sizeof buf, "%s",
		    name);
	}
	crc32c = istgt_crc32c((uint8_t *) buf, strlen(buf));
	r = (uint64_t) crc32c;
	return r;
}

uint64_t
istgt_get_rkey(const char *initiator_name, uint64_t lui)
{
	ISTGT_MD5CTX md5ctx;
	uint8_t rkeymd5[ISTGT_MD5DIGEST_LEN];
	char buf[MAX_TMPBUF];
	uint64_t rkey;
	int idx;
	int i;

	snprintf(buf, sizeof buf, "%s,%16.16" PRIx64,
	    initiator_name, lui);

	istgt_md5init(&md5ctx);
	istgt_md5update(&md5ctx, buf, strlen(buf));
	istgt_md5final(rkeymd5, &md5ctx);

	rkey = 0U;
	idx = ISTGT_MD5DIGEST_LEN - 8;
	if (idx < 0) {
		ISTGT_WARNLOG("missing MD5 length\n");
		idx = 0;
	}
	for (i = idx; i < ISTGT_MD5DIGEST_LEN; i++) {
		rkey |= (uint64_t) rkeymd5[i];
		rkey = rkey << 8;
	}
	return rkey;
}

/* XXX */
#define COMPANY_ID 0xACDE48U // 24bits

int
istgt_lu_set_lid(uint8_t *buf, uint64_t vid)
{
	uint64_t naa;
	uint64_t enc;
	int total;

	naa = 0x3; // Locally Assigned

	/* NAA + LOCALLY ADMINISTERED VALUE */
	enc = (naa & 0xfULL) << (64-4); // 4bits
	enc |= vid & 0xfffffffffffffffULL; //60bits
	DSET64(&buf[0], enc);

	total = 8;
	return total;
}

int
istgt_lu_set_id(uint8_t *buf, uint64_t vid)
{
	uint64_t naa;
	uint64_t cid;
	uint64_t enc;
	int total;

	naa = 0x5; // IEEE Registered
	cid = COMPANY_ID; //IEEE COMPANY_ID

	/* NAA + COMPANY_ID + VENDOR SPECIFIC IDENTIFIER */
	enc = (naa & 0xfULL) << (64-4); // 4bits
	enc |= (cid & 0xffffffULL) << (64-4-24); // 24bits
	enc |= vid & 0xfffffffffULL; //36bits
	DSET64(&buf[0], enc);

	total = 8;
	return total;
}

int
istgt_lu_set_extid(uint8_t *buf, uint64_t vid, uint64_t vide)
{
	uint64_t naa;
	uint64_t cid;
	uint64_t enc;
	int total;

	naa = 0x6; // IEEE Registered Extended
	cid = COMPANY_ID; //IEEE COMPANY_ID

	/* NAA + COMPANY_ID + VENDOR SPECIFIC IDENTIFIER */
	enc = (naa & 0xfULL) << (64-4); // 4bits
	enc |= (cid & 0xffffffULL) << (64-4-24); // 24bits
	enc |= vid & 0xfffffffffULL; //36bits
	DSET64(&buf[0], enc);
	/* VENDOR SPECIFIC IDENTIFIER EXTENSION */
	DSET64(&buf[8], vide);

	total = 16;
	return total;
}

static int
istgt_lu_disk_scsi_report_luns(ISTGT_LU_Ptr lu, CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), int sel, uint8_t *data, int alloc_len)
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
istgt_lu_disk_scsi_inquiry(ISTGT_LU_DISK *spec, CONN_Ptr conn, uint8_t *cdb, uint8_t *data, int alloc_len)
{
	uint64_t LUI;
	uint8_t *cp, *cp2;
	uint32_t blocks;
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
	pd = SPC_PERIPHERAL_DEVICE_TYPE_DISK;
	rmb = 0;

#if 0
	LUI = istgt_uuid2uint64(&spec->uuid);
#else
	LUI = istgt_get_lui(spec->lu->name, spec->lun & 0xffffU);
#endif

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
			data[11]= 0xb0; /* SBC Block Limits */
			data[12]= 0xb1; /* SBC Block Device Characteristics */
			len = 13 - hlen;
			if (spec->thin_provisioning) {
				data[13]= 0xb2; /* SBC Thin Provisioning */
				len++;
			}

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
			if (spec->lu->lun[spec->lun].serial != NULL) {
				len = strlen(spec->lu->lun[spec->lun].serial);
				if (len > MAX_LU_SERIAL_STRING) {
					len = MAX_LU_SERIAL_STRING;
				}
				istgt_strcpy_pad(&data[4], len,
				    spec->lu->lun[spec->lun].serial, ' ');
			} else {
				len = strlen(spec->lu->inq_serial);
				if (len > MAX_LU_SERIAL_STRING) {
					len = MAX_LU_SERIAL_STRING;
				}
				istgt_strcpy_pad(&data[4], len,
				    spec->lu->inq_serial, ' ');
			}

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
			if (spec->lu->lun[spec->lun].serial != NULL) {
				istgt_strcpy_pad(&cp[28], MAX_LU_SERIAL_STRING,
				    spec->lu->lun[spec->lun].serial, ' ');
			} else {
				istgt_strcpy_pad(&cp[28], MAX_LU_SERIAL_STRING,
				    spec->lu->inq_serial, ' ');
			}
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
			if (spec->queue_depth != 0) {
				BDADD8(&data[5], 1, 2);     /* HEADSUP */
				//BDADD8(&data[5], 1, 1);     /* ORDSUP */
				BDADD8(&data[5], 1, 0);     /* SIMPSUP */
			}
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

		case 0xb0: /* SBC Block Limits */
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* PAGE LENGTH */
			DSET16(&data[2], 0);
			hlen = 4;

			/* WSNZ(0) */
			BDSET8(&data[4], 0, 0); /* support zero length in WRITE SAME */
			/* MAXIMUM COMPARE AND WRITE LENGTH */
			blocks = ISTGT_LU_WORK_ATS_BLOCK_SIZE / (uint32_t) spec->blocklen;
			if (blocks > 0xff) {
				blocks = 0xff;
			}
			data[5] = (uint8_t) blocks;
			if (spec->lu->istgt->swmode == ISTGT_SWMODE_TRADITIONAL) {
				/* no support compare and write */
				data[5] = 0;
			}

			/* force align to 4KB */
			if (spec->blocklen < 4096) {
				blocks = 4096 / (uint32_t) spec->blocklen;
				/* OPTIMAL TRANSFER LENGTH GRANULARITY */
				DSET16(&data[6], blocks);
				/* MAXIMUM TRANSFER LENGTH */
				DSET32(&data[8], 0); /* no limit */
				/* OPTIMAL TRANSFER LENGTH */
				blocks = ISTGT_LU_WORK_BLOCK_SIZE / (uint32_t) spec->blocklen;
				DSET32(&data[12], blocks);
				/* MAXIMUM PREFETCH XDREAD XDWRITE TRANSFER LENGTH */
				DSET32(&data[16], 0);
			} else {
				blocks = 1;
				/* OPTIMAL TRANSFER LENGTH GRANULARITY */
				DSET16(&data[6], blocks);
				/* MAXIMUM TRANSFER LENGTH */
				DSET32(&data[8], 0); /* no limit */
				/* OPTIMAL TRANSFER LENGTH */
				blocks = ISTGT_LU_WORK_BLOCK_SIZE / (uint32_t) spec->blocklen;
				DSET32(&data[12], blocks);
				/* MAXIMUM PREFETCH XDREAD XDWRITE TRANSFER LENGTH */
				DSET32(&data[16], 0);
			}
			len = 20 - hlen;

			if (1 || spec->thin_provisioning) {
				/* MAXIMUM UNMAP LBA COUNT */
				DSET32(&data[20], 0); /* not implement UNMAP */
				/* MAXIMUM UNMAP BLOCK DESCRIPTOR COUNT */
				DSET32(&data[24], 0); /* not implement UNMAP */
				/* OPTIMAL UNMAP GRANULARITY */
				DSET32(&data[28], 0); /* not specified */
				/* UNMAP GRANULARITY ALIGNMENT */
				DSET32(&data[32], (0 & 0x7fffffffU));
				/* UGAVALID(7) */
				BDADD8(&data[32], 0, 7); /* not valid ALIGNMENT */
				/* MAXIMUM WRITE SAME LENGTH */
				DSET64(&data[36], 0); /* no limit */
				/* Reserved */
				memset(&data[44], 0x00, 64-44);
				len = 64 - hlen;
			}

			DSET16(&data[2], len);
			break;

		case 0xb1: /* SBC Block Device Characteristics */
			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* PAGE LENGTH */
			DSET16(&data[2], 0);
			hlen = 4;

			/* MEDIUM ROTATION RATE */
			//DSET16(&data[4], 0x0000); /* not reported */
			//DSET16(&data[4], 0x0001); /* Non-rotating medium (solid state) */
			//DSET16(&data[4], 5400); /* rotation rate (5400rpm) */
			//DSET16(&data[4], 7200); /* rotation rate (7200rpm) */
			//DSET16(&data[4], 10000); /* rotation rate (10000rpm) */
			//DSET16(&data[4], 15000); /* rotation rate (15000rpm) */
			DSET16(&data[4], spec->lu->lun[spec->lun].rotationrate);
			/* Reserved */
			data[6] = 0;
			/* NOMINAL FORM FACTOR(3-0) */
			//BDSET8W(&data[7], 0x00, 3, 4); /* not reported */
			//BDSET8W(&data[7], 0x01, 3, 4); /* 5.25 inch */
			//BDSET8W(&data[7], 0x02, 3, 4); /* 3.5 inch */
			//BDSET8W(&data[7], 0x03, 3, 4); /* 2.5 inch */
			//BDSET8W(&data[7], 0x04, 3, 4); /* 1.8 inch */
			//BDSET8W(&data[7], 0x05, 3, 4); /* less 1.8 inch */
			BDSET8W(&data[7], spec->lu->lun[spec->lun].formfactor, 3, 4);
			/* Reserved */
			memset(&data[8], 0x00, 64-8);

			len = 64 - hlen;
			DSET16(&data[2], len);
			break;

		case 0xb2: /* SBC Thin Provisioning */
			if (!spec->thin_provisioning) {
				ISTGT_ERRLOG("unsupported INQUIRY VPD page 0x%x\n", pc);
				return -1;
			}

			/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
			BDSET8W(&data[0], pq, 7, 3);
			BDADD8W(&data[0], pd, 4, 5);
			/* PAGE CODE */
			data[1] = pc;
			/* PAGE LENGTH */
			DSET16(&data[2], 0);
			hlen = 4;

			/* THRESHOLD EXPONENT */
			data[4] = 0;
			/* DP(0) */
			BDSET8(&data[5], 0, 0);
			/* Reserved */
			DSET16(&data[6], 0);
			len = 6 - hlen;
#if 0
			/* XXX not yet */
			/* PROVISIONING GROUP DESCRIPTOR ... */
			DSET16(&data[8], 0);
			len = 8 - hlen;
#endif

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
		//BDADD8W(&data[5], 1, 7, 1); /* storage array controller */
		BDADD8W(&data[5], 0x00, 5, 2); /* Not support TPGS */
		//BDADD8W(&data[5], 0x01, 5, 2); /* Only implicit */
		//BDADD8W(&data[5], 0x02, 5, 2); /* Only explicit */
		//BDADD8W(&data[5], 0x03, 5, 2); /* Both explicit and implicit */
		/* BQUE(7) ENCSERV(6) VS(5) MULTIP(4) MCHNGR(3) ADDR16(0) */
		data[6] = 0;
		BDADD8W(&data[6], 1, 4, 1); /* MULTIP */
		/* WBUS16(5) SYNC(4) LINKED(3) CMDQUE(1) VS(0) */
		data[7] = 0;
		if (spec->queue_depth != 0) {
			BDADD8(&data[7], 1, 1);     /* CMDQUE */
		}
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
		DSET16(&data[62], 0x0320); /* SBC-2 (no version claimed) */
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
istgt_lu_disk_scsi_mode_sense_page(ISTGT_LU_DISK *spec, CONN_Ptr conn, uint8_t *cdb, int pc, int page, int subpage, uint8_t *data, int alloc_len)
{
	uint8_t *cp;
	int len = 0;
	int plen;
	int rc;
	int i;

#if 0
	printf("pc=%d, page=%2.2x, subpage=%2.2x\n", pc, page, subpage);
#endif
#if 0
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE: pc=%d, page=%2.2x, subpage=%2.2x\n", pc, page, subpage);
#endif

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
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Read-Write Error Recovery\n");
		if (subpage != 0x00)
			break;
		plen = 0x0a + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		len += plen;
		break;
	case 0x02:
		/* Disconnect-Reconnect */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Disconnect-Reconnect\n");
		if (subpage != 0x00)
			break;
		plen = 0x0e + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		len += plen;
		break;
	case 0x03:
		/* Obsolete (Format Device) */
		break;
	case 0x04:
		/* Obsolete (Rigid Disk Geometry) */
		break;
	case 0x05:
		/* Obsolete (Rigid Disk Geometry) */
		break;
	case 0x06:
		/* Reserved */
		break;
	case 0x07:
		/* Verify Error Recovery */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Verify Error Recovery\n");
		if (subpage != 0x00)
			break;
		plen = 0x0a + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		len += plen;
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
		{
			int fd;
			fd = spec->fd;
			rc = fcntl(fd , F_GETFL, 0);
			if (rc != -1 && !(rc & O_FSYNC)) {
				BDADD8(&cp[2], 1, 2); /* WCE=1 */
			} else {
				BDADD8(&cp[2], 0, 2); /* WCE=0 */
			}
		}
		if (spec->read_cache == 0) {
			BDADD8(&cp[2], 1, 0); /* RCD=1 */
		} else {
			BDADD8(&cp[2], 0, 0); /* RCD=0 */
		}
		len += plen;
		break;
	case 0x09:
		/* Obsolete */
		break;
	case 0x0a:
		switch (subpage) {
		case 0x00:
			/* Control */
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Control\n");
			plen = 0x0a + 2;
			MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
			len += plen;
			break;
		case 0x01:
			/* Control Extension */
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Control Extension\n");
			plen = 0x1c + 4;
			MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
			len += plen;
			break;
		case 0xff:
			/* All subpages */
			len += istgt_lu_disk_scsi_mode_sense_page(spec, conn, cdb, pc, page, 0x00, &data[len], alloc_len);
			len += istgt_lu_disk_scsi_mode_sense_page(spec, conn, cdb, pc, page, 0x01, &data[len], alloc_len);
			break;
		default:
			/* 0x02-0x3e: Reserved */
			break;
		}
		break;
	case 0x0b:
		/* Obsolete (Medium Types Supported) */
		break;
	case 0x0c:
		/* Obsolete (Notch And Partitio) */
		break;
	case 0x0d:
		/* Obsolete */
		break;
	case 0x0e:
	case 0x0f:
		/* Reserved */
		break;
	case 0x10:
		/* XOR Control */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE XOR Control\n");
		if (subpage != 0x00)
			break;
		plen = 0x16 + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		len += plen;
		break;
	case 0x11:
	case 0x12:
	case 0x13:
		/* Reserved */
		break;
	case 0x14:
		/* Enclosure Services Management */
		break;
	case 0x15:
	case 0x16:
	case 0x17:
		/* Reserved */
		break;
	case 0x18:
		/* Protocol-Specific LUN */
#if 0
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Protocol-Specific LUN\n");
		if (subpage != 0x00)
			break;
		plen = 0x04 + 0x00 + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		len += plen;
#endif
		break;
	case 0x19:
		/* Protocol-Specific Port */
#if 0
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Protocol-Specific Port\n");
		if (subpage != 0x00)
			break;
		plen = 0x04 + 0x00 + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		len += plen;
#endif
		break;
	case 0x1a:
		/* Power Condition */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SENSE Power Condition\n");
		if (subpage != 0x00)
			break;
		plen = 0x0a + 2;
		MODE_SENSE_PAGE_INIT(cp, plen, page, subpage);
		len += plen;
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
				len += istgt_lu_disk_scsi_mode_sense_page(spec, conn, cdb, pc, i, 0x00, &cp[len], alloc_len);
			}
			break;
		case 0xff:
			/* All mode pages and subpages */
			for (i = 0x00; i < 0x3e; i ++) {
				len += istgt_lu_disk_scsi_mode_sense_page(spec, conn, cdb, pc, i, 0x00, &cp[len], alloc_len);
			}
			for (i = 0x00; i < 0x3e; i ++) {
				len += istgt_lu_disk_scsi_mode_sense_page(spec, conn, cdb, pc, i, 0xff, &cp[len], alloc_len);
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
istgt_lu_disk_scsi_mode_sense6(ISTGT_LU_DISK *spec, CONN_Ptr conn, uint8_t *cdb, int dbd, int pc, int page, int subpage, uint8_t *data, int alloc_len)
{
	uint8_t *cp;
	int hlen = 0, len = 0, plen;
	int total;
	int llbaa = 0;

	data[0] = 0;                    /* Mode Data Length */
	data[1] = 0;                    /* Medium Type */
	data[2] = 0;                    /* Device-Specific Parameter */
	if (spec->lu->readonly) {
		BDADD8(&data[2], 1, 7);     /* WP */
	}
	data[3] = 0;                    /* Block Descripter Length */
	hlen = 4;

	cp = &data[4];
	if (dbd) {                      /* Disable Block Descripters */
		len = 0;
	} else {
		if (llbaa) {
			/* Number of Blocks */
			DSET64(&cp[0], spec->blockcnt);
			/* Reserved */
			DSET32(&cp[8], 0);
			/* Block Length */
			DSET32(&cp[12], (uint32_t) spec->blocklen);
			len = 16;
		} else {
			/* Number of Blocks */
			if (spec->blockcnt > 0xffffffffULL) {
				DSET32(&cp[0], 0xffffffffUL);
			} else {
				DSET32(&cp[0], (uint32_t) spec->blockcnt);
			}
			/* Block Length */
			DSET32(&cp[4], (uint32_t) spec->blocklen);
			len = 8;
		}
		cp += len;
	}
	data[3] = len;                  /* Block Descripter Length */

	plen = istgt_lu_disk_scsi_mode_sense_page(spec, conn, cdb, pc, page, subpage, &cp[0], alloc_len);
	if (plen < 0) {
		return -1;
	}
	cp += plen;

	total = hlen + len + plen;
	data[0] = total - 1;            /* Mode Data Length */

	return total;
}

static int
istgt_lu_disk_scsi_mode_sense10(ISTGT_LU_DISK *spec, CONN_Ptr conn, uint8_t *cdb, int dbd, int llbaa, int pc, int page, int subpage, uint8_t *data, int alloc_len)
{
	uint8_t *cp;
	int hlen = 0, len = 0, plen;
	int total;

	DSET16(&data[0], 0);            /* Mode Data Length */
	data[2] = 0;                    /* Medium Type */
	data[3] = 0;                    /* Device-Specific Parameter */
	if (spec->lu->readonly) {
		BDADD8(&data[3], 1, 7);     /* WP */
	}
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
			/* Number of Blocks */
			DSET64(&cp[0], spec->blockcnt);
			/* Reserved */
			DSET32(&cp[8], 0);
			/* Block Length */
			DSET32(&cp[12], (uint32_t) spec->blocklen);
			len = 16;
		} else {
			/* Number of Blocks */
			if (spec->blockcnt > 0xffffffffULL) {
				DSET32(&cp[0], 0xffffffffUL);
			} else {
				DSET32(&cp[0], (uint32_t) spec->blockcnt);
			}
			/* Block Length */
			DSET32(&cp[4], (uint32_t) spec->blocklen);
			len = 8;
		}
		cp += len;
	}
	DSET16(&data[6], len);          /* Block Descripter Length */

	plen = istgt_lu_disk_scsi_mode_sense_page(spec, conn, cdb, pc, page, subpage, &cp[0], alloc_len);
	if (plen < 0) {
		return -1;
	}
	cp += plen;

	total = hlen + len + plen;
	DSET16(&data[0], total - 2);	/* Mode Data Length */

	return total;
}

static int
istgt_lu_disk_transfer_data(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint8_t *buf, size_t bufsize, size_t len)
{
	int rc;

	if (lu_cmd->lu->queue_depth == 0) {
		if (len > bufsize) {
			ISTGT_ERRLOG("bufsize(%zd) too small\n", bufsize);
			return -1;
		}
		rc = istgt_iscsi_transfer_out(conn, lu_cmd, buf, bufsize, len);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_transfer_out()\n");
			return -1;
		}
	}
	return 0;
}

static int
istgt_lu_disk_scsi_mode_select_page(ISTGT_LU_DISK *spec, CONN_Ptr conn, uint8_t *cdb, int pf, int sp, uint8_t *data, size_t len)
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

			{
				int fd;
				fd = spec->fd;
				rc = fcntl(fd , F_GETFL, 0);
				if (rc != -1) {
					if (wce) {
						ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MODE_SELECT Writeback cache enable\n");
						rc = fcntl(fd, F_SETFL, (rc & ~O_FSYNC));
						spec->write_cache = 1;
					} else {
						rc = fcntl(fd, F_SETFL, (rc | O_FSYNC));
						spec->write_cache = 0;
					}
					if (rc == -1) {
						/* XXX */
						//ISTGT_ERRLOG("fcntl(F_SETFL) failed\n");
					}
				}
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
		rc = istgt_lu_disk_scsi_mode_select_page(spec, conn, cdb,  pf, sp, &data[plen], len);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}

static int
istgt_lu_disk_scsi_read_defect10(ISTGT_LU_DISK *spec __attribute__((__unused__)), CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), int req_plist, int req_glist, int list_format, uint8_t *data, int alloc_len)
{
	uint8_t *cp;
	int hlen = 0, len = 0;
	int total;

	if (alloc_len < 4) {
		return -1;
	}

	data[0] = 0;				/* Reserved */
	data[1] = 0;
	if (req_plist) {
		BDADD8(&data[1], 1, 4);		/* PLISTV */
	}
	if (req_glist) {
		BDADD8(&data[1], 1, 3);		/* GLISTV */
	}
	BDADD8W(&data[1], list_format, 2, 3);	/* DEFECT LIST FORMAT */
	DSET16(&data[2], 0);			/* DEFECT LIST LENGTH */
	hlen = 4;

	cp = &data[4];
	/* defect list (if any) */
	len = 0;

	total = hlen + len;
	DSET16(&data[2], total - hlen);		/* DEFECT LIST LENGTH */
	return total;
}

static int
istgt_lu_disk_scsi_read_defect12(ISTGT_LU_DISK *spec __attribute__((__unused__)), CONN_Ptr conn __attribute__((__unused__)), uint8_t *cdb __attribute__((__unused__)), int req_plist, int req_glist, int list_format, uint8_t *data, int alloc_len)
{
	uint8_t *cp;
	int hlen = 0, len = 0;
	int total;

	if (alloc_len < 8) {
		return -1;
	}

	data[0] = 0;				/* Reserved */
	data[1] = 0;
	if (req_plist) {
		BDADD8(&data[1], 1, 4);		/* PLISTV */
	}
	if (req_glist) {
		BDADD8(&data[1], 1, 3);		/* GLISTV */
	}
	BDADD8W(&data[1], list_format, 2, 3);	/* DEFECT LIST FORMAT */
	data[2] = 0;				/* Reserved */
	data[3] = 0;				/* Reserved */
	DSET32(&data[4], 0);			/* DEFECT LIST LENGTH */
	hlen = 8;

	cp = &data[8];
	/* defect list (if any) */
	len = 0;

	total = hlen + len;
	DSET32(&data[4], total - hlen);		/* DEFECT LIST LENGTH */
	return total;
}

#if 0
static int
istgt_lu_disk_scsi_request_sense(ISTGT_LU_DISK *spec, CONN_Ptr conn, uint8_t *cdb, int desc, uint8_t *data, int alloc_len)
{
	int len = 0, plen;

	if (alloc_len < 18) {
		ISTGT_ERRLOG("alloc_len(%d) too small\n", alloc_len);
		return -1;
	}

	/* XXX TODO: fix */
	if (desc == 0) {
		/* fixed format */
		/* NO ADDITIONAL SENSE INFORMATION */
		/* BUILD_SENSE(NO_SENSE, 0x00, 0x00); */

		/* VALID(7) RESPONSE CODE(6-0) */
		BDSET8(&data[0], 0, 7);
		BDADD8W(&data[0], 0x70, 6, 7);
		/* Obsolete */
		data[1] = 0;
		/* FILEMARK(7) EOM(6) ILI(5) SENSE KEY(3-0) */
		BDSET8W(&data[2], ISTGT_SCSI_SENSE_NO_SENSE, 3, 4);
		/* INFORMATION */
		memset(&data[3], 0, 4);
		/* ADDITIONAL SENSE LENGTH */
		data[7] = 0;
		len = 8;

		/* COMMAND-SPECIFIC INFORMATION */
		memset(&data[8], 0, 4);
		/* ADDITIONAL SENSE CODE */
		data[12] = 0x00;
		/* ADDITIONAL SENSE CODE QUALIFIER */
		data[13] = 0x00;
		/* FIELD REPLACEABLE UNIT CODE */
		data[14] = 0;
		/* SKSV(7) SENSE KEY SPECIFIC(6-0,7-0,7-0) */
		data[15] = 0;
		data[16] = 0;
		data[17] = 0;
		plen = 18 - len;

		/* ADDITIONAL SENSE LENGTH */
		data[7] = plen;
	} else {
		/* descriptor format */
		/* NO ADDITIONAL SENSE INFORMATION */
		/* BUILD_SENSE(NO_SENSE, 0x00, 0x00); */

		/* RESPONSE CODE(6-0) */
		BDSET8W(&data[0], 0x72, 6, 7);
		/* SENSE KEY(3-0) */
		BDSET8W(&data[1], ISTGT_SCSI_SENSE_NO_SENSE, 3, 4);
		/* ADDITIONAL SENSE CODE */
		data[2] = 0x00;
		/* ADDITIONAL SENSE CODE QUALIFIER */
		data[3] = 0x00;
		/* Reserved */
		data[4] = 0;
		data[5] = 0;
		data[6] = 0;
		/* ADDITIONAL SENSE LENGTH */
		data[7] = 0;
		len = 8;

		/* Sense data descriptor(s) */
		plen = 8 - len;

		/* ADDITIONAL SENSE LENGTH */
		data[7] = plen;
	}
	return len;
}
#endif

static int
istgt_lu_disk_scsi_report_target_port_groups(ISTGT_LU_DISK *spec, CONN_Ptr conn, uint8_t *cdb __attribute__((__unused__)), uint8_t *data, int alloc_len)
{
	ISTGT_Ptr istgt;
	ISTGT_LU_Ptr lu;
	uint8_t *cp;
	uint8_t *cp_count;
	int hlen = 0, len = 0, plen;
	int total;
	int pg_tag;
	int nports;
	int i, j, k;
	int ridx;

	if (alloc_len < 0xfff) {
		return -1;
	}

	istgt = conn->istgt;
	lu = spec->lu;

	/* RETURN DATA LENGTH */
	DSET32(&data[0], 0);
	hlen = 4;

	MTX_LOCK(&istgt->mutex);
	for (i = 0; i < lu->maxmap; i++) {
		pg_tag = lu->map[i].pg_tag;
		/* skip same pg_tag */
		for (j = 0; j < i; j++) {
			if (lu->map[j].pg_tag == pg_tag) {
				goto skip_pg_tag;
			}
		}

		/* Target port group descriptor N */
		cp = &data[hlen + len];

		/* PREF(7) ASYMMETRIC ACCESS STATE(3-0) */
		cp[0] = 0;
		BDSET8(&cp[0], 1, 7); /* PREF */
		switch (lu->map[j].pg_aas & 0x0f) {
		case AAS_ACTIVE_OPTIMIZED:
			BDADD8W(&cp[0], AAS_ACTIVE_OPTIMIZED, 3, 4);
			break;
		case AAS_ACTIVE_NON_OPTIMIZED:
			BDADD8W(&cp[0], AAS_ACTIVE_NON_OPTIMIZED, 3, 4);
			break;
		case AAS_STANDBY:
			BDADD8W(&cp[0], AAS_STANDBY, 3, 4);
			break;
		case AAS_UNAVAILABLE:
			BDADD8W(&cp[0], AAS_UNAVAILABLE, 3, 4);
			break;
		case AAS_TRANSITIONING:
			BDADD8W(&cp[0], AAS_TRANSITIONING, 3, 4);
			break;
		default:
			ISTGT_ERRLOG("unsupported AAS\n");
			break;
		}
		/* T_SUP(7) U_SUP(3) S_SUP(2) S_SUP AN_SUP(1) AO_SUP(0) */
		cp[1] = 0;
		//BDADD8(&cp[1], 1, 7); /* transitioning supported */
		//BDADD8(&cp[1], 1, 3); /* unavailable supported */
		//BDADD8(&cp[1], 1, 2); /* standby supported */
		BDADD8(&cp[1], 1, 1); /* active/non-optimized supported */
		BDADD8(&cp[1], 1, 0); /* active/optimized supported */
		/* TARGET PORT GROUP */
		DSET16(&cp[2], pg_tag);
		/* Reserved */
		cp[4] = 0;
		/* STATUS CODE */
		if (lu->map[j].pg_aas & AAS_STATUS_IMPLICIT) {
			cp[5] = 0x02; /* by implicit */
		} else if (lu->map[j].pg_aas & AAS_STATUS_STPG) {
			cp[5] = 0x01; /* by SET TARGET PORT GROUPS */
		} else {
			cp[5] = 0;    /* No status */
		}
		/* Vendor specific */
		cp[6] = 0;
		/* TARGET PORT COUNT */
		cp[7] = 0;
		cp_count = &cp[7];
		plen = 8;
		len += plen;

		nports = 0;
		ridx = 0;
		MTX_LOCK(&istgt->mutex);
		for (j = 0; j < istgt->nportal_group; j++) {
			if (istgt->portal_group[j].tag == pg_tag) {
				for (k = 0; k < istgt->portal_group[j].nportals; k++) {
					/* Target port descriptor(s) */
					cp = &data[hlen + len];
					/* Obsolete */
					DSET16(&cp[0], 0);
					/* RELATIVE TARGET PORT IDENTIFIER */
					DSET16(&cp[2], (uint16_t) (1 + ridx));
					plen = 4;
					len += plen;
					nports++;
					ridx++;
				}
			} else {
				ridx += istgt->portal_group[j].nportals;
			}
		}
		MTX_UNLOCK(&istgt->mutex);

		if (nports > 0xff) {
			ISTGT_ERRLOG("too many portals in portal group\n");
			MTX_UNLOCK(&istgt->mutex);
			return -1;
		}

		/* TARGET PORT COUNT */
		cp_count[0] = nports;

	skip_pg_tag:
		;
	}
	MTX_UNLOCK(&istgt->mutex);

	total = hlen + len;
	if (total > alloc_len) {
		ISTGT_ERRLOG("alloc_len(%d) too small\n", alloc_len);
		return -1;
	}

	/* RETURN DATA LENGTH */
	DSET32(&data[0], total - 4);

	return total;
}

static int
istgt_lu_disk_scsi_set_target_port_groups(ISTGT_LU_DISK *spec, CONN_Ptr conn, uint8_t *cdb, uint8_t *data, int len)
{
	ISTGT_LU_Ptr lu;
	int pg_tag;
	int aas;
	int pg;
	int rc;
	int i;

	if (len < 4) {
		return -1;
	}

	lu = spec->lu;

	aas = BGET8W(&data[0], 3, 4);
	pg = DGET16(&data[2]);

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AAS=0x%x, PG=0x%4.4x\n", aas, pg);

	for (i = 0; i < lu->maxmap; i++) {
		pg_tag = lu->map[i].pg_tag;
		if (pg != pg_tag)
			continue;

		switch (aas) {
		case AAS_ACTIVE_OPTIMIZED:
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Active/optimized\n");
			break;
		case AAS_ACTIVE_NON_OPTIMIZED:
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Active/non-optimized\n");
			break;
#if 0
		case AAS_STANDBY:
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Standby\n");
			break;
		case AAS_UNAVAILABLE:
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Unavailable\n");
			break;
#endif
		case AAS_TRANSITIONING:
			return -1;
		default:
			ISTGT_ERRLOG("unsupported AAS 0x%x\n", aas);
			return -1;
		}
		lu->map[i].pg_aas = aas;
		lu->map[i].pg_aas |= AAS_STATUS_STPG;
	}

	len -=4;
	if (len != 0) {
		rc = istgt_lu_disk_scsi_set_target_port_groups(spec, conn, cdb, data, len);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}

static void
istgt_lu_disk_free_pr_key(ISTGT_LU_PR_KEY *prkey)
{
	int i;

	if (prkey == NULL)
		return;
	xfree(prkey->registered_initiator_port);
	prkey->registered_initiator_port = NULL;
	xfree(prkey->registered_target_port);
	prkey->registered_target_port = NULL;
	prkey->pg_idx = 0;
	prkey->pg_tag = 0;
	for (i = 0; i < prkey->ninitiator_ports; i++) {
		xfree(prkey->initiator_ports[i]);
		prkey->initiator_ports[i] = NULL;
	}
	xfree(prkey->initiator_ports);
	prkey->initiator_ports = NULL;
	prkey->all_tpg = 0;
}

static ISTGT_LU_PR_KEY *
istgt_lu_disk_find_pr_key(ISTGT_LU_DISK *spec, const char *initiator_port, const char *target_port, uint64_t key)
{
	ISTGT_LU_PR_KEY *prkey;
	int i;

	/* return pointer if I_T nexus is registered */
#ifdef ISTGT_TRACE_DISK
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "find prkey=0x%16.16"PRIx64", port=%s\n",
	    key, ((initiator_port != NULL) ? initiator_port : "N/A"));
#endif /* ISTGT_TRACE_DISK */

	if (initiator_port == NULL)
		return NULL;
	for (i = 0; i < spec->npr_keys; i++) {
		prkey = &spec->pr_keys[i];
		if (prkey == NULL)
			continue;
#ifdef ISTGT_TRACE_DISK
		if (key != 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "prkey=0x%16.16"PRIx64"\n",
			    prkey->key);
		}
#endif /* ISTGT_TRACE_DISK */
		if (key != 0 && prkey->key != key)
			continue;
#ifdef ISTGT_TRACE_DISK
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "pript=%s, ipt=%s\n",
		    prkey->registered_initiator_port,
		    initiator_port);
#endif /* ISTGT_TRACE_DISK */
		if (strcmp(prkey->registered_initiator_port,
			initiator_port) == 0) {
#ifdef ISTGT_TRACE_DISK
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "prtpt=%s, tpt=%s\n",
			    prkey->registered_target_port,
			    target_port);
#endif /* ISTGT_TRACE_DISK */
			if (prkey->all_tpg != 0
			    || target_port == NULL
			    || strcmp(prkey->registered_target_port,
				target_port) == 0) {
				return prkey;
			}
		}
	}
	return NULL;
}

static int
istgt_lu_disk_remove_other_pr_key(ISTGT_LU_DISK *spec, CONN_Ptr conn __attribute__((__unused__)), const char *initiator_port, const char *target_port, uint64_t key)
{
	ISTGT_LU_PR_KEY *prkey, *prkey1, *prkey2;
	int i, j;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "remove prkey=0x%16.16"PRIx64", iniport=%s, tgtport=%s\n",
	    key, ((initiator_port != NULL) ? initiator_port : "N/A"),
	    ((target_port != NULL) ? target_port : "N/A"));

	if (spec->npr_keys == 0)
		return 0;

	/* remove specified prkey from end of array */
	for (i = spec->npr_keys - 1; i >= 0; i--) {
		prkey = &spec->pr_keys[i];
		if (prkey == NULL)
			continue;
		if (key == 0 || prkey->key == key)
			continue;
		/* NULL means all initiator/target */
		if (initiator_port == NULL ||
		    strcasecmp(prkey->registered_initiator_port,
			initiator_port) == 0)
			continue;
		if (prkey->all_tpg != 0
		    || target_port == NULL
		    || strcasecmp(prkey->registered_target_port,
			target_port) == 0)
			continue;

		/* this prkey will remove */
		istgt_lu_disk_free_pr_key(prkey);
		/* move used array */
		for (j = i; j < spec->npr_keys - 1; j++) {
			prkey1 = &spec->pr_keys[j];
			prkey2 = &spec->pr_keys[j+1];
			*prkey1 = *prkey2;
		}
		/* last array is cleared */
		prkey1 = &spec->pr_keys[j];
		memset(prkey1, 0, sizeof(*prkey1));
		prkey1->registered_initiator_port = NULL;
		prkey1->registered_target_port = NULL;
		prkey1->initiator_ports = NULL;
		/* update counts */
		spec->npr_keys--;
	}
#ifdef ISTGT_TRACE_DISK
	if (g_trace_flag) {
		for (i = 0; i < spec->npr_keys; i++) {
			prkey = &spec->pr_keys[i];
			if (prkey == NULL)
				continue;
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "keylist: prkey=0x%16.16"PRIx64", iniport=%s, tgtport=%s\n",
			    prkey->key, prkey->registered_initiator_port,
			    prkey->registered_target_port);
		}
	}
#endif /* ISTGT_TRACE_DISK */
	return 0;
}

static int
istgt_lu_disk_remove_pr_key(ISTGT_LU_DISK *spec, CONN_Ptr conn __attribute__((__unused__)), const char *initiator_port, const char *target_port, uint64_t key)
{
	ISTGT_LU_PR_KEY *prkey, *prkey1, *prkey2;
	int i, j;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "remove prkey=0x%16.16"PRIx64", iniport=%s, tgtport=%s\n",
	    key, ((initiator_port != NULL) ? initiator_port : "N/A"),
	    ((target_port != NULL) ? target_port : "N/A"));

	if (spec->npr_keys == 0)
		return 0;

	/* remove specified prkey from end of array */
	for (i = spec->npr_keys - 1; i >= 0; i--) {
		prkey = &spec->pr_keys[i];
		if (prkey == NULL)
			continue;
		if (key != 0 && prkey->key != key)
			continue;
		/* NULL means all initiator/target */
		if (initiator_port != NULL
		    && strcasecmp(prkey->registered_initiator_port,
			initiator_port) != 0)
			continue;
		if (prkey->all_tpg == 0
		    && target_port != NULL
		    && strcasecmp(prkey->registered_target_port,
			target_port) != 0)
			continue;

		/* this prkey will remove */
		istgt_lu_disk_free_pr_key(prkey);
		/* move used array */
		for (j = i; j < spec->npr_keys - 1; j++) {
			prkey1 = &spec->pr_keys[j];
			prkey2 = &spec->pr_keys[j+1];
			*prkey1 = *prkey2;
		}
		/* last array is cleared */
		prkey1 = &spec->pr_keys[j];
		memset(prkey1, 0, sizeof(*prkey1));
		prkey1->registered_initiator_port = NULL;
		prkey1->registered_target_port = NULL;
		prkey1->initiator_ports = NULL;
		/* update counts */
		spec->npr_keys--;
	}
#ifdef ISTGT_TRACE_DISK
	if (g_trace_flag) {
		for (i = 0; i < spec->npr_keys; i++) {
			prkey = &spec->pr_keys[i];
			if (prkey == NULL)
				continue;
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "keylist: prkey=0x%16.16"PRIx64", iniport=%s, tgtport=%s\n",
			    prkey->key, prkey->registered_initiator_port,
			    prkey->registered_target_port);
		}
	}
#endif /* ISTGT_TRACE_DISK */
	return 0;
}

static int
istgt_lu_parse_transport_id(char **tid, uint8_t *data, int len)
{
	int fc, pi;
	int hlen, plen;

	if (tid == NULL)
		return -1;
	if (data == NULL)
		return -1;

	fc = BGET8W(&data[0], 7, 2);
	pi = BGET8W(&data[0], 3, 4);
	if (fc != 0) {
		ISTGT_ERRLOG("FORMAT CODE != 0\n");
		return -1;
	}
	if (pi != SPC_VPD_IDENTIFIER_TYPE_SCSI_NAME) {
		ISTGT_ERRLOG("PROTOCOL IDENTIFIER != ISCSI\n");
		return -1;
	}

	/* PROTOCOL IDENTIFIER = 0x05 */
	hlen = 4;
	/* ADDITIONAL LENGTH */
	plen = DGET16(&data[2]);
	if (plen > len) {
		ISTGT_ERRLOG("invalid length %d (expected %d)\n",
		    plen, len);
		return -1;
	}
	if (plen > MAX_ISCSI_NAME) {
		ISTGT_ERRLOG("invalid length %d (expected %d)\n",
		    plen, MAX_ISCSI_NAME);
		return -1;
	}

	/* ISCSI NAME */
	*tid = xmalloc(plen + 1);
	memcpy(*tid, data, plen);
	(*tid)[plen] = '\0';
	strlwr(*tid);

	return hlen + plen;
}

static int
istgt_lu_disk_scsi_persistent_reserve_in(ISTGT_LU_DISK *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd, int sa, uint8_t *data, int alloc_len __attribute__((__unused__)))
{
	ISTGT_LU_PR_KEY *prkey;
	size_t hlen = 0, len = 0, plen;
	uint8_t *sense_data;
	size_t *sense_len;
	uint8_t *cp;
	int total;
	int i;

	sense_data = lu_cmd->sense_data;
	sense_len = &lu_cmd->sense_data_len;
	*sense_len = 0;

	cp = &data[hlen + len];
	total = 0;
	switch (sa) {
	case 0x00: /* READ KEYS */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ KEYS\n");

		/* PRGENERATION */
		DSET32(&data[0], spec->pr_generation);
		/* ADDITIONAL LENGTH  */
		DSET32(&data[4], 0);
		hlen = 8;

		for (i = 0; i < spec->npr_keys; i++) {
			prkey = &spec->pr_keys[i];
			/* reservation key N */
			cp = &data[hlen + len];
			DSET64(&cp[0], prkey->key);
			len += 8;
		}
		total = hlen + len;
		/* ADDITIONAL LENGTH  */
		DSET32(&data[4], total - hlen);
		break;

	case 0x01: /* READ RESERVATION */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ RESERVATION\n");

		/* PRGENERATION */
		DSET32(&data[0], spec->pr_generation);
		/* ADDITIONAL LENGTH  */
		DSET32(&data[4], 0);
		hlen = 8;

		if (spec->rsv_key != 0) {
			/* RESERVATION KEY */
			DSET64(&data[8], spec->rsv_key);
			/* Obsolete */
			DSET32(&data[16], 0);
			/* Reserved */
			data[20] = 0;
			/* SCOPE(7-4) TYPE(3-0) */
			BDSET8W(&data[21], spec->rsv_scope, 7, 4);
			BDADD8W(&data[21], spec->rsv_type, 3, 4);
			/* Obsolete */
			DSET16(&data[22], 0);
			len = 24 - hlen;
		}

		total = hlen + len;
		/* ADDITIONAL LENGTH  */
		DSET32(&data[4], total - hlen);
		break;

	case 0x02: /* REPORT CAPABILITIES */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "REPORT CAPABILITIES\n");

		/* LENGTH */
		DSET16(&data[0], 0x0008);
		/* CRH(4) SIP_C(3) ATP_C(2) PTPL_C(0) */
		data[2] = 0;
		//BDADD8(&data[2], 1, 4); /* Compatible Reservation Handling */
		BDADD8(&data[2], 1, 3); /* Specify Initiator Ports Capable */
		BDADD8(&data[2], 1, 2); /* All Target Ports Capable */
		//BDADD8(&data[2], 1, 0); /* Persist Through Power Loss Capable */
		/* TMV(7) PTPL_A(0) */
		data[3] = 0;
		//BDADD8(&data[2], 1, 7); /* Type Mask Valid */
		//BDADD8(&data[2], 1, 0); /* Persist Through Power Loss Activated */
		/* PERSISTENT RESERVATION TYPE MASK */
		DSET16(&data[4], 0);
		/* Reserved */
		DSET16(&data[6], 0);
		hlen = 8;

		total = hlen + len;
		break;

	case 0x03: /* READ FULL STATUS */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ FULL STATUS\n");

		/* PRGENERATION */
		DSET32(&data[0], spec->pr_generation);
		/* ADDITIONAL LENGTH  */
		DSET32(&data[4], 0);
		hlen = 8;

		for (i = 0; i < spec->npr_keys; i++) {
			prkey = &spec->pr_keys[i];
			/* Full status descriptors N */
			cp = &data[hlen + len];

			/* RESERVATION KEY */
			DSET64(&cp[0], prkey->key);
			/* Reserved */
			DSET64(&cp[8], 0);
			/* ALL_TG_PT(1) R_HOLDER(0) */
			cp[12] = 0;
			if (prkey->all_tpg) {
				BDADD8(&cp[12], 1, 1);
			}
			/* SCOPE(7-4) TYPE(3-0) */
			cp[13] = 0;
			if (spec->rsv_key != 0) {
				if (spec->rsv_key == prkey->key) {
					BDADD8(&cp[12], 1, 0);
					BDADD8W(&cp[13], spec->rsv_scope & 0x0f, 7, 4);
					BDADD8W(&cp[13], spec->rsv_type & 0x0f, 3, 4);
				}
			}
			/* Reserved */
			DSET32(&cp[14], 0);
			/* RELATIVE TARGET PORT IDENTIFIER */
			DSET16(&cp[18], 1 + prkey->pg_idx);
			/* ADDITIONAL DESCRIPTOR LENGTH */
			DSET32(&cp[20], 0);

			/* TRANSPORTID */
			plen = snprintf((char *) &cp[24], MAX_INITIATOR_NAME,
			    "%s",
			    prkey->registered_initiator_port);
			
			/* ADDITIONAL DESCRIPTOR LENGTH */
			DSET32(&cp[20], plen);
			len += 24 + plen;
		}

		total = hlen + len;
		/* ADDITIONAL LENGTH  */
		DSET32(&data[4], total - hlen);
		break;

	default:
		ISTGT_ERRLOG("unsupported service action 0x%x\n", sa);
		/* INVALID FIELD IN CDB */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return total;
}

static int
istgt_lu_disk_scsi_persistent_reserve_out(ISTGT_LU_DISK *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, int sa, int scope, int type, uint8_t *data, int len)
{
	ISTGT_LU_PR_KEY *prkey;
	uint8_t *sense_data;
	size_t *sense_len;
	char *old_rsv_port = NULL;
	char **initiator_ports;
	int maxports, nports;
	int plen, total;
	uint64_t rkey;
	uint64_t sarkey;
	int spec_i_pt, all_tg_pt, aptpl;
	int task_abort;
	int idx;
	int rc;
	int i;

	sense_data = lu_cmd->sense_data;
	sense_len = &lu_cmd->sense_data_len;
	*sense_len = 0;

	rkey = DGET64(&data[0]);
	sarkey = DGET64(&data[8]);
	spec_i_pt = BGET8(&data[20], 3);
	all_tg_pt = BGET8(&data[20], 2);
	aptpl = BGET8(&data[20], 0);

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "sa=0x%2.2x, key=0x%16.16"PRIx64", sakey=0x%16.16"PRIx64
	    ", ipt=%d, tgpt=%d, aptpl=%d\n",
	    sa, rkey, sarkey, spec_i_pt, all_tg_pt, aptpl);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "port=%s\n",
	    conn->initiator_port);

	switch (sa) {
	case 0x00: /* REGISTER */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "REGISTER\n");

		if (aptpl != 0) {
			/* Activate Persist Through Power Loss */
			ISTGT_ERRLOG("unsupport Activate Persist Through Power Loss\n");
			/* INVALID FIELD IN PARAMETER LIST */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		/* lost reservations if daemon restart */

		prkey = istgt_lu_disk_find_pr_key(spec, conn->initiator_port,
		    conn->target_port, 0);
		if (prkey == NULL) {
			/* unregistered port */
			if (rkey != 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
				return -1;
			}
			if (sarkey != 0) {
				/* XXX check spec_i_pt */
			}
		} else {
			/* registered port */
			if (spec_i_pt) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			prkey = istgt_lu_disk_find_pr_key(spec,
			    conn->initiator_port, conn->target_port, rkey);
			if (prkey == NULL) {
				/* not found key */
				lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
				return -1;
			}
			/* remove existing keys */
			rc = istgt_lu_disk_remove_pr_key(spec, conn,
			    conn->initiator_port, conn->target_port, 0);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_remove_pr_key() failed\n");
				/* INTERNAL TARGET FAILURE */
				BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
		}

		/* unregister? */
		if (sarkey == 0) {
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			return 0;
		}

		goto do_register;

	case 0x01: /* RESERVE */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "RESERVE\n");

		prkey = istgt_lu_disk_find_pr_key(spec, conn->initiator_port,
		    conn->target_port, 0);
		if (prkey == NULL) {
			/* unregistered port */
			lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
			return -1;
		}

		prkey = istgt_lu_disk_find_pr_key(spec, conn->initiator_port,
		    conn->target_port, rkey);
		if (prkey == NULL) {
			/* not found key */
			lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
			return -1;
		}
		if (spec->rsv_key == 0) {
			/* no reservation */
		} else {
			if (prkey->key != spec->rsv_key) {
				lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
				return -1;
			}
			if (strcasecmp(spec->rsv_port, conn->initiator_port) != 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
				return -1;
			}
#if 0
			/* registrants can change the prkey */
			if (g_trace_flag) {
				ISTGT_WARNLOG("LU%d: duplicate reserve\n", spec->lu->num);
			}
#endif
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			return 0;
		}

		if (scope != 0x00) { // !LU_SCOPE
			/* INVALID FIELD IN CDB */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		if (type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE
		    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS
		    && type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_REGISTRANTS_ONLY
		    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_REGISTRANTS_ONLY
		    && type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS
		    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS) {
			ISTGT_ERRLOG("unsupported type 0x%x\n", type);
			/* INVALID FIELD IN CDB */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}

		/* establish reservation by key */
		xfree(spec->rsv_port);
		spec->rsv_port = xstrdup(conn->initiator_port);
		strlwr(spec->rsv_port);
		spec->rsv_key = rkey;
		spec->rsv_scope = scope;
		spec->rsv_type = type;

		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "LU%d: reserved (scope=%d, type=%d) by key=0x%16.16"
		    PRIx64"\n",
		    spec->lu->num, scope, type, rkey);
		break;

	case 0x02: /* RELEASE */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "RELEASE\n");

		prkey = istgt_lu_disk_find_pr_key(spec, conn->initiator_port,
		    conn->target_port, 0);
		if (prkey == NULL) {
			/* unregistered port */
			lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
			return -1;
		}

		prkey = istgt_lu_disk_find_pr_key(spec, conn->initiator_port,
		    conn->target_port, rkey);
		if (prkey == NULL) {
			/* not found key */
			lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
			return -1;
		}
		if (spec->rsv_key == 0) {
			/* no reservation */
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			return 0;
		}
		if (prkey->key != spec->rsv_key) {
			/* INVALID RELEASE OF PERSISTENT RESERVATION */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x04);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		if (strcasecmp(spec->rsv_port, conn->initiator_port) != 0) {
			/* INVALID RELEASE OF PERSISTENT RESERVATION */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x04);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}

		if (scope != 0x00) { // !LU_SCOPE
			/* INVALID FIELD IN CDB */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		if (type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE
		    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS
		    && type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_REGISTRANTS_ONLY
		    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_REGISTRANTS_ONLY
		    && type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS
		    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS) {
			ISTGT_ERRLOG("unsupported type 0x%x\n", type);
			/* INVALID FIELD IN CDB */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		if (spec->rsv_scope != scope || spec->rsv_type != type) {
			/* INVALID RELEASE OF PERSISTENT RESERVATION */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x04);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}

		/* release reservation by key */
		xfree(spec->rsv_port);
		spec->rsv_port = NULL;
		spec->rsv_key = 0;
		spec->rsv_scope = 0;
		spec->rsv_type = 0;

		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "LU%d: released (scope=%d, type=%d) by key=0x%16.16"
		    PRIx64"\n",
		    spec->lu->num, scope, type, rkey);
		break;

	case 0x03: /* CLEAR */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "CLEAR\n");

		prkey = istgt_lu_disk_find_pr_key(spec, conn->initiator_port,
		    conn->target_port, 0);
		if (prkey == NULL) {
			/* unregistered port */
			lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
			return -1;
		}

		/* release reservation */
		xfree(spec->rsv_port);
		spec->rsv_port = NULL;
		spec->rsv_key = 0;
		spec->rsv_scope = 0;
		spec->rsv_type = 0;

		/* remove all registrations */
		for (i = 0; i < spec->npr_keys; i++) {
			prkey = &spec->pr_keys[i];
			istgt_lu_disk_free_pr_key(prkey);
		}
		spec->npr_keys = 0;
		break;

	case 0x04: /* PREEMPT */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "PREEMPT\n");

		task_abort = 0;
	do_preempt:
		prkey = istgt_lu_disk_find_pr_key(spec, conn->initiator_port,
		    conn->target_port, 0);
		if (prkey == NULL) {
			/* unregistered port */
			lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
			return -1;
		}

		if (spec->rsv_key == 0) {
			/* no reservation */
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "no reservation\n");
			/* remove registration */
			rc = istgt_lu_disk_remove_pr_key(spec, conn,
			    NULL, NULL, sarkey);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_remove_pr_key() failed\n");
				/* INTERNAL TARGET FAILURE */
				BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			/* update generation */
			spec->pr_generation++;

			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "rsv_key=0x%16.16"PRIx64"\n",
		    spec->rsv_key);

		if (spec->rsv_type == ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS
		    || spec->rsv_type == ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS) {
			if (sarkey != 0) {
				/* remove registration */
				rc = istgt_lu_disk_remove_pr_key(spec, conn,
				    NULL, NULL, sarkey);
				if (rc < 0) {
					ISTGT_ERRLOG("lu_disk_remove_pr_key() failed\n");
					/* INTERNAL TARGET FAILURE */
					BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					return -1;
				}

				/* update generation */
				spec->pr_generation++;

				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				break;
			} else {
				/* remove other registrations */
				rc = istgt_lu_disk_remove_other_pr_key(spec, conn,
				    conn->initiator_port,
				    conn->target_port,
				    rkey);
				if (rc < 0) {
					ISTGT_ERRLOG("lu_disk_remove_other_pr_key() failed\n");
					/* INTERNAL TARGET FAILURE */
					BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					return -1;
				}

				if (scope != 0x00) { // !LU_SCOPE
					/* INVALID FIELD IN CDB */
					BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					return -1;
				}
				if (type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE
				    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS
				    && type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_REGISTRANTS_ONLY
				    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_REGISTRANTS_ONLY
				    && type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS
				    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS) {
					ISTGT_ERRLOG("unsupported type 0x%x\n", type);
					/* INVALID FIELD IN CDB */
					BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					return -1;
				}

				/* release reservation */
				//xfree(spec->rsv_port);
				old_rsv_port = spec->rsv_port;
				spec->rsv_port = NULL;
				spec->rsv_key = 0;
				spec->rsv_scope = 0;
				spec->rsv_type = 0;
				/* establish new reservation */
				spec->rsv_port = xstrdup(conn->initiator_port);
				strlwr(spec->rsv_port);
				spec->rsv_key = rkey;
				spec->rsv_scope = scope;
				spec->rsv_type = type;

				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "LU%d: reserved (scope=%d, type=%d)"
				    "by key=0x%16.16"PRIx64"\n",
				    spec->lu->num, scope, type, rkey);

				/* update generation */
				spec->pr_generation++;

				/* XXX TODO fix */
				if (task_abort) {
					/* abort all tasks for preempted I_T nexus */
					if (old_rsv_port != NULL) {
						rc = istgt_lu_disk_queue_abort_ITL(spec, old_rsv_port);
						xfree(old_rsv_port);
						old_rsv_port = NULL;
						if (rc < 0) {
							/* INTERNAL TARGET FAILURE */
							BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
							lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
							return -1;
						}
					}
				}
				if (old_rsv_port != NULL) {
					xfree(old_rsv_port);
					old_rsv_port = NULL;
				}

				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				break;
			}
		}

		prkey = istgt_lu_disk_find_pr_key(spec, conn->initiator_port,
		    conn->target_port, rkey);

		if (prkey == NULL) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "prkey == NULL\n");
		} else {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "prkey key=%16.16"PRIx64"\n",
			    prkey->key);
		}

		if (prkey == NULL
		    || sarkey != spec->rsv_key) {
			if (sarkey != 0) {
				/* remove registration */
				rc = istgt_lu_disk_remove_pr_key(spec, conn,
				    NULL, NULL, sarkey);
				if (rc < 0) {
					ISTGT_ERRLOG("lu_disk_remove_pr_key() failed\n");
					/* INTERNAL TARGET FAILURE */
					BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					return -1;
				}
				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				break;
			} else {
				/* INVALID FIELD IN PARAMETER LIST */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
		}

		/* remove registration */
		rc = istgt_lu_disk_remove_pr_key(spec, conn,
		    NULL, NULL, sarkey);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_disk_remove_pr_key() failed\n");
			/* INTERNAL TARGET FAILURE */
			BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}

		if (scope != 0x00) { // !LU_SCOPE
			/* INVALID FIELD IN CDB */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		if (type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE
		    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS
		    && type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_REGISTRANTS_ONLY
		    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_REGISTRANTS_ONLY
		    && type != ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS
		    && type != ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS) {
			ISTGT_ERRLOG("unsupported type 0x%x\n", type);
			/* INVALID FIELD IN CDB */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}

		/* release reservation */
		//xfree(spec->rsv_port);
		old_rsv_port = spec->rsv_port;
		spec->rsv_port = NULL;
		spec->rsv_key = 0;
		spec->rsv_scope = 0;
		spec->rsv_type = 0;
		/* establish new reservation */
		spec->rsv_port = xstrdup(conn->initiator_port);
		strlwr(spec->rsv_port);
		spec->rsv_key = rkey;
		spec->rsv_scope = scope;
		spec->rsv_type = type;

		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "LU%d: reserved (scope=%d, type=%d) by key=0x%16.16"
		    PRIx64"\n",
		    spec->lu->num, scope, type, rkey);

		/* update generation */
		spec->pr_generation++;

		/* XXX TODO fix */
		if (task_abort) {
			/* abort all tasks for preempted I_T nexus */
			if (old_rsv_port != NULL) {
				rc = istgt_lu_disk_queue_abort_ITL(spec, old_rsv_port);
				xfree(old_rsv_port);
				old_rsv_port = NULL;
				if (rc < 0) {
					/* INTERNAL TARGET FAILURE */
					BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					return -1;
				}
			}
		}
		if (old_rsv_port != NULL) {
			xfree(old_rsv_port);
			old_rsv_port = NULL;
		}

		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		break;

	case 0x05: /* PREEMPT AND ABORT */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "PREEMPT AND ABORT\n");

		task_abort = 1;
		goto do_preempt;

	case 0x06: /* REGISTER AND IGNORE EXISTING KEY */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "REGISTER AND IGNORE EXISTING KEY\n");

		if (aptpl != 0) {
			/* Activate Persist Through Power Loss */
			ISTGT_ERRLOG("unsupport Activate Persist Through Power Loss\n");
			/* INVALID FIELD IN PARAMETER LIST */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		/* lost reservations if daemon restart */

		prkey = istgt_lu_disk_find_pr_key(spec, conn->initiator_port,
		    conn->target_port, 0);
		if (prkey == NULL) {
			/* unregistered port */
			if (sarkey != 0) {
				if (spec_i_pt) {
					/* INVALID FIELD IN CDB */
					BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					return -1;
				}
			}
			/* unregister? */
			if (sarkey == 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				return 0;
			}
		} else {
			/* registered port */
			if (spec_i_pt) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
		}

		/* remove existing keys */
		rc = istgt_lu_disk_remove_pr_key(spec, conn,
		    conn->initiator_port,
		    conn->target_port, 0);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_disk_remove_pr_key() failed\n");
			/* INTERNAL TARGET FAILURE */
			BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}

		/* unregister? */
		if (sarkey == 0) {
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			return 0;
		}

	do_register:
		/* specified port? */
		nports = 0;
		initiator_ports = NULL;
		if (spec_i_pt) {
			if (len < 28) {
				/* INVALID FIELD IN PARAMETER LIST */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			/* TRANSPORTID PARAMETER DATA LENGTH */
			plen = DGET32(&data[24]);
			if (28 + plen > len) {
				ISTGT_ERRLOG("invalid length %d (expect %d)\n",
				    len, 28 + plen);
				/* INVALID FIELD IN PARAMETER LIST */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "TransportID parameter data length %d\n",
			    plen);
			if (plen != 0) {
				maxports = MAX_LU_RESERVE_IPT;
				initiator_ports = xmalloc(sizeof (char *) * maxports);
				memset(initiator_ports, 0, sizeof (char *) * maxports);
				nports = 0;
				total = 0;
				while (total < plen) {
					if (nports >= MAX_LU_RESERVE_IPT) {
						ISTGT_ERRLOG("maximum transport IDs\n");
						/* INSUFFICIENT REGISTRATION RESOURCES */
						BUILD_SENSE(ILLEGAL_REQUEST, 0x55, 0x04);
						lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
						return -1;
					}
					rc = istgt_lu_parse_transport_id
						(&initiator_ports[nports],
						 &data[24] + total, plen - total);
					if (rc < 0) {
						/* INVALID FIELD IN PARAMETER LIST */
						BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x00);
						lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
						return -1;
					}
					ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "got TransportID %s\n",
					    initiator_ports[nports]);
					total += rc;
					nports++;
				}
			}
			/* check all port unregistered? */
			for (i = 0; i < nports; i++) {
				prkey = istgt_lu_disk_find_pr_key(spec,
				    initiator_ports[i], NULL, 0);
				if (prkey != NULL) {
					/* registered port */
					/* INVALID FIELD IN CDB */
					BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
					return -1;
				}
			}
			/* OK, all port unregistered */
			idx = spec->npr_keys;
			if (idx + nports >= MAX_LU_RESERVE) {
				/* INSUFFICIENT REGISTRATION RESOURCES */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x55, 0x04);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			/* register each I_T nexus */
			for (i = 0; i < nports; i++) {
				prkey = &spec->pr_keys[idx + i];

				/* register new key */
				prkey->key = sarkey;

				/* command received port */
				prkey->registered_initiator_port
					= xstrdup(conn->initiator_port);
				strlwr(prkey->registered_initiator_port);
				prkey->registered_target_port
					= xstrdup(conn->target_port);
				strlwr(prkey->registered_target_port);
				prkey->pg_idx = conn->portal.idx;
				prkey->pg_tag = conn->portal.tag;

				/* specified ports */
				prkey->ninitiator_ports = 0;
				prkey->initiator_ports = NULL;
				prkey->all_tpg = (all_tg_pt) ? 1 : 0;
			}
			spec->npr_keys = idx + nports;
		}

		idx = spec->npr_keys;
		if (idx >= MAX_LU_RESERVE) {
			/* INSUFFICIENT REGISTRATION RESOURCES */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x55, 0x04);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		prkey = &spec->pr_keys[idx];

		/* register new key */
		prkey->key = sarkey;
		/* replace existing reservation */
		if (rkey != 0 && spec->rsv_key == rkey)
			spec->rsv_key = sarkey;

		/* command received port */
		prkey->registered_initiator_port = xstrdup(conn->initiator_port);
		strlwr(prkey->registered_initiator_port);
		prkey->registered_target_port = xstrdup(conn->target_port);
		strlwr(prkey->registered_target_port);
		prkey->pg_idx = conn->portal.idx;
		prkey->pg_tag = conn->portal.tag;

		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "Register Key:0x%16.16"PRIx64", InitiatorPort: %s, TargetPort: %s\n",
		    prkey->key, prkey->registered_initiator_port,
		    prkey->registered_target_port);

		/* specified ports */
		prkey->ninitiator_ports = nports;
		prkey->initiator_ports = initiator_ports;
		prkey->all_tpg = (all_tg_pt) ? 1 : 0;

		/* count up keys */
		idx++;
		spec->npr_keys = idx;

		/* update generation */
		spec->pr_generation++;
		break;

	case 0x07: /* REGISTER AND MOVE */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "REGISTER AND MOVE\n");
		/* INVALID FIELD IN CDB */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;

	default:
		ISTGT_ERRLOG("unsupported service action 0x%x\n", sa);
		/* INVALID FIELD IN CDB */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_disk_check_pr(ISTGT_LU_DISK *spec, CONN_Ptr conn, int pr_allow)
{
	ISTGT_LU_PR_KEY *prkey;

#ifdef ISTGT_TRACE_DISK
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "RSV_KEY=0x%16.16"PRIx64", RSV_TYPE=0x%x, PR_ALLOW=0x%x\n",
	    spec->rsv_key, spec->rsv_type, pr_allow);
#endif /* ISTGT_TRACE_DISK */

	prkey = istgt_lu_disk_find_pr_key(spec, conn->initiator_port,
	    conn->target_port, 0);
	if (prkey != NULL) {
#ifdef ISTGT_TRACE_DISK
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "PRKEY(0x%16.16"PRIx64") found for %s\n",
		    prkey->key, conn->initiator_port);
#endif /* ISTGT_TRACE_DISK */

		if (spec->rsv_key == prkey->key) {
			/* reservation holder */
			return 0;
		}

		switch (spec->rsv_type) {
		case ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS:
			if (pr_allow & PR_ALLOW_ALLRR)
				return 0;
			return -1;
		case ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS:
			if (pr_allow & PR_ALLOW_ALLRR)
				return 0;
			return -1;
		case ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_REGISTRANTS_ONLY:
			if (pr_allow & PR_ALLOW_ALLRR)
				return 0;
			return -1;
		case ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_REGISTRANTS_ONLY:
			if (pr_allow & PR_ALLOW_ALLRR)
				return 0;
			return -1;
		}
	} else {
#ifdef ISTGT_TRACE_DISK
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "PRKEY not found for %s\n",
		    conn->initiator_port);
#endif /* ISTGT_TRACE_DISK */

		switch (spec->rsv_type) {
		case ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS:
			if (pr_allow & PR_ALLOW_WERR)
				return 0;
			return -1;
		case ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE_REGISTRANTS_ONLY:
			if (pr_allow & PR_ALLOW_WERR)
				return 0;
			return -1;
		case ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS:
			if (pr_allow & PR_ALLOW_EARR)
				return 0;
			return -1;
		case ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS_REGISTRANTS_ONLY:
			if (pr_allow & PR_ALLOW_EARR)
				return 0;
			return -1;
		}
	}

#ifdef ISTGT_TRACE_DISK
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "non registrans type\n");
#endif /* ISTGT_TRACE_DISK */
	/* any I_T nexus */
	switch (spec->rsv_type) {
	case ISTGT_LU_PR_TYPE_WRITE_EXCLUSIVE:
		if (pr_allow & PR_ALLOW_WE)
			return 0;
		return -1;
	case ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS:
		if (pr_allow & PR_ALLOW_EA)
			return 0;
		return -1;
	}

	/* NG */
	return -1;
}

static int
istgt_lu_disk_scsi_release(ISTGT_LU_DISK *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	ISTGT_LU_CMD lu_cmd2;
	uint8_t *sense_data;
	size_t *sense_len;
	uint64_t LUI;
	uint64_t rkey;
	uint8_t cdb[10];
	uint8_t PRO_data[24];
	int parameter_len;
	int rc;

	sense_data = lu_cmd->sense_data;
	sense_len = &lu_cmd->sense_data_len;
	*sense_len = 0;

	memset(&lu_cmd2, 0, sizeof lu_cmd2);
	lu_cmd2.sense_data = lu_cmd->sense_data;
	lu_cmd2.sense_data_len = lu_cmd->sense_data_len;
	memset(&cdb, 0, sizeof cdb);
	parameter_len = sizeof PRO_data;

	LUI = istgt_get_lui(spec->lu->name, spec->lun & 0xffffU);
	rkey = istgt_get_rkey(conn->initiator_name, LUI);

	/* issue release action of PERSISTENT RESERVE OUT */
	cdb[0] = SPC_PERSISTENT_RESERVE_OUT;
	BDSET8W(&cdb[1], 0x02, 4, 5); /* RELEASE */
	BDSET8W(&cdb[2], 0x00, 7, 4); /* LU_SCOPE */
	BDADD8W(&cdb[2], 0x03, 3, 4); /* ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS */
	cdb[3] = 0;
	cdb[4] = 0;
	DSET32(&cdb[5], parameter_len);
	cdb[9] = 0;
	lu_cmd2.cdb = &cdb[0];

	memset(&PRO_data, 0, sizeof PRO_data);
	DSET64(&PRO_data[0], rkey); // RESERVATION KEY
	DSET64(&PRO_data[8], 0);

	rc = istgt_lu_disk_scsi_persistent_reserve_out(spec, conn, &lu_cmd2,
	    0x02, 0x00, 0x03,
	    PRO_data, parameter_len);
	if (rc < 0) {
		lu_cmd->status = lu_cmd2.status;
		if (lu_cmd->status == ISTGT_SCSI_STATUS_RESERVATION_CONFLICT) {
			return -1;
		}
		/* INTERNAL TARGET FAILURE */
		BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	/* issue unregister action of PERSISTENT RESERVE OUT */
	cdb[0] = SPC_PERSISTENT_RESERVE_OUT;
	BDSET8W(&cdb[1], 0x06, 4, 5); /* REGISTER AND IGNORE EXISTING KEY */
	cdb[2] = 0;
	cdb[3] = 0;
	cdb[4] = 0;
	DSET32(&cdb[5], parameter_len);
	cdb[9] = 0;
	lu_cmd2.cdb = &cdb[0];

	memset(&PRO_data, 0, sizeof PRO_data);
	DSET64(&PRO_data[0], rkey); // RESERVATION KEY
	DSET64(&PRO_data[8], 0); // unregister

	rc = istgt_lu_disk_scsi_persistent_reserve_out(spec, conn, &lu_cmd2,
	    0x06, 0, 0,
	    PRO_data, parameter_len);
	if (rc < 0) {
		lu_cmd->status = lu_cmd2.status;
		if (lu_cmd->status == ISTGT_SCSI_STATUS_RESERVATION_CONFLICT) {
			return -1;
		}
		/* INTERNAL TARGET FAILURE */
		BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_disk_scsi_reserve(ISTGT_LU_DISK *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	ISTGT_LU_CMD lu_cmd2;
	uint8_t *sense_data;
	size_t *sense_len;
	uint64_t LUI;
	uint64_t rkey;
	uint8_t cdb[10];
	uint8_t PRO_data[24];
	int parameter_len;
	int rc;

	sense_data = lu_cmd->sense_data;
	sense_len = &lu_cmd->sense_data_len;
	*sense_len = 0;

	memset(&lu_cmd2, 0, sizeof lu_cmd2);
	lu_cmd2.sense_data = lu_cmd->sense_data;
	lu_cmd2.sense_data_len = lu_cmd->sense_data_len;
	memset(&cdb, 0, sizeof cdb);
	parameter_len = sizeof PRO_data;

	LUI = istgt_get_lui(spec->lu->name, spec->lun & 0xffffU);
	rkey = istgt_get_rkey(conn->initiator_name, LUI);

	/* issue register action of PERSISTENT RESERVE OUT */
	cdb[0] = SPC_PERSISTENT_RESERVE_OUT;
	BDSET8W(&cdb[1], 0x06, 4, 5); /* REGISTER AND IGNORE EXISTING KEY */
	cdb[2] = 0;
	cdb[3] = 0;
	cdb[4] = 0;
	DSET32(&cdb[5], parameter_len);
	cdb[9] = 0;
	lu_cmd2.cdb = &cdb[0];

	memset(&PRO_data, 0, sizeof PRO_data);
	DSET64(&PRO_data[0], 0);
	DSET64(&PRO_data[8], rkey); // SERVICE ACTION RESERVATION KEY

	rc = istgt_lu_disk_scsi_persistent_reserve_out(spec, conn, &lu_cmd2,
	    0x06, 0, 0,
	    PRO_data, parameter_len);
	if (rc < 0) {
		lu_cmd->status = lu_cmd2.status;
		if (lu_cmd->status == ISTGT_SCSI_STATUS_RESERVATION_CONFLICT) {
			return -1;
		}
		/* INTERNAL TARGET FAILURE */
		BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	/* issue reserve action of PERSISTENT RESERVE OUT */
	cdb[0] = SPC_PERSISTENT_RESERVE_OUT;
	BDSET8W(&cdb[1], 0x01, 4, 5); /* RESERVE */
	BDSET8W(&cdb[2], 0x00, 7, 4); /* LU_SCOPE */
	BDADD8W(&cdb[2], 0x03, 3, 4); /* ISTGT_LU_PR_TYPE_EXCLUSIVE_ACCESS */
	cdb[3] = 0;
	cdb[4] = 0;
	DSET32(&cdb[5], parameter_len);
	cdb[9] = 0;
	lu_cmd2.cdb = &cdb[0];

	memset(&PRO_data, 0, sizeof PRO_data);
	DSET64(&PRO_data[0], rkey); // RESERVATION KEY
	DSET64(&PRO_data[8], 0);

	rc = istgt_lu_disk_scsi_persistent_reserve_out(spec, conn, &lu_cmd2,
	    0x01, 0x00, 0x03,
	    PRO_data, parameter_len);
	if (rc < 0) {
		lu_cmd->status = lu_cmd2.status;
		if (lu_cmd->status == ISTGT_SCSI_STATUS_RESERVATION_CONFLICT) {
			return -1;
		}
		/* INTERNAL TARGET FAILURE */
		BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_disk_lbread(ISTGT_LU_DISK *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lba, uint32_t len)
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

	rc = spec->seek(spec, offset);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_disk_seek() failed\n");
		return -1;
	}

	rc = spec->read(spec, data, nbytes);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_disk_read() failed\n");
		return -1;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "Read %"PRId64"/%"PRIu64" bytes\n",
	    rc, nbytes);

	lu_cmd->data = data;
	lu_cmd->data_len = rc;

	return 0;
}

static int
istgt_lu_disk_lbwrite(ISTGT_LU_DISK *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lba, uint32_t len)
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
		ISTGT_ERRLOG("nbytes(%zu) > iobufsize(%zu)\n",
		    (size_t) nbytes, lu_cmd->iobufsize);
		return -1;
	}
	data = lu_cmd->iobuf;

	rc = istgt_lu_disk_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
	    lu_cmd->iobufsize, nbytes);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_disk_transfer_data() failed\n");
		return -1;
	}

	if (spec->lu->readonly) {
		ISTGT_ERRLOG("LU%d: readonly unit\n", spec->lu->num);
		return -1;
	}

	spec->req_write_cache = 0;
	rc = spec->seek(spec, offset);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_disk_seek() failed\n");
		return -1;
	}

	rc = spec->write(spec, data, nbytes);
	if (rc < 0 || (uint64_t) rc != nbytes) {
		ISTGT_ERRLOG("lu_disk_write() failed\n");
		return -1;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "Wrote %"PRId64"/%"PRIu64" bytes\n",
	    rc, nbytes);

	lu_cmd->data_len = rc;

	return 0;
}

static int
istgt_lu_disk_lbwrite_same(ISTGT_LU_DISK *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lba, uint32_t len)
{
	uint8_t *data;
	uint64_t maxlba;
	uint64_t llen;
	uint64_t blen;
	uint64_t offset;
	uint64_t nbytes;
	uint64_t nblocks;
	uint64_t wblocks;
	int64_t rc;

	maxlba = spec->blockcnt;
	llen = (uint64_t) len;
	if (llen == 0) {
		if (lba >= maxlba) {
			ISTGT_ERRLOG("end of media\n");
			return -1;
		}
		llen = maxlba - lba;
	}
	blen = spec->blocklen;
	offset = lba * blen;
	nbytes = 1 * blen;

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
	    "Write Same: max=%"PRIu64", lba=%"PRIu64", len=%u\n",
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

	rc = istgt_lu_disk_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
	    lu_cmd->iobufsize, nbytes);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_disk_transfer_data() failed\n");
		return -1;
	}

	if (spec->lu->readonly) {
		ISTGT_ERRLOG("LU%d: readonly unit\n", spec->lu->num);
		return -1;
	}

	if (conn->workbuf == NULL) {
		conn->worksize = ISTGT_LU_WORK_BLOCK_SIZE;
		conn->workbuf = xmalloc(conn->worksize);
	}
	wblocks = (int64_t)conn->worksize / nbytes;
	if (wblocks == 0) {
		ISTGT_ERRLOG("work buffer is too small\n");
		return -1;
	}

	spec->req_write_cache = 0;
	rc = spec->seek(spec, offset);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_disk_seek() failed\n");
		return -1;
	}

#if 0
	nblocks = 0;
	while (nblocks < llen) {
		rc = spec->write(spec, data, nbytes);
		if (rc < 0 || rc != nbytes) {
			ISTGT_ERRLOG("lu_disk_write() failed\n");
			return -1;
		}
		nblocks++;
	}
#else
	nblocks = 0;
	while (nblocks < wblocks) {
		memcpy(conn->workbuf + (nblocks * nbytes), data, nbytes);
		nblocks++;
	}

	nblocks = 0;
	while (nblocks < llen) {
		uint64_t reqblocks = DMIN64(wblocks, (llen - nblocks));
		rc = spec->write(spec, conn->workbuf, (reqblocks * nbytes));
		if (rc < 0 || (uint64_t) rc != (reqblocks * nbytes)) {
			ISTGT_ERRLOG("lu_disk_write() failed\n");
			return -1;
		}
		nblocks += reqblocks;
	}
#endif
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "Wrote %"PRId64"/%"PRIu64" bytes\n",
	    (nblocks * nbytes), (llen * nbytes));

	lu_cmd->data_len = nbytes;

	return 0;
}

static int
istgt_lu_disk_lbwrite_ats(ISTGT_LU_DISK *spec, CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint64_t lba, uint32_t len)
{
	uint8_t *data;
	uint64_t maxlba;
	uint64_t llen;
	uint64_t blen;
	uint64_t offset;
	uint64_t nbytes;
	int64_t rc;
	uint8_t *sense_data;
	size_t *sense_len;

	if (len == 0) {
		lu_cmd->data_len = 0;
		return 0;
	}

	sense_data = lu_cmd->sense_data;
	sense_len = &lu_cmd->sense_data_len;
	*sense_len = 0;

	maxlba = spec->blockcnt;
	llen = (uint64_t) len;
	blen = spec->blocklen;
	offset = lba * blen;
	nbytes = llen * blen;

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
	    "Write ATS: max=%"PRIu64", lba=%"PRIu64", len=%u\n",
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

	rc = istgt_lu_disk_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
	    lu_cmd->iobufsize, nbytes * 2);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_disk_transfer_data() failed\n");
		return -1;
	}

	if (spec->lu->readonly) {
		ISTGT_ERRLOG("LU%d: readonly unit\n", spec->lu->num);
		return -1;
	}

	if (spec->watsbuf == NULL) {
		spec->watssize = ISTGT_LU_WORK_ATS_BLOCK_SIZE;
		spec->watsbuf = xmalloc(spec->watssize);
	}
	if (nbytes > (uint64_t) spec->watssize) {
		ISTGT_ERRLOG("nbytes(%zu) > watssize(%zu)\n",
		    (size_t) nbytes, (size_t) spec->watssize);
		return -1;
	}

	spec->req_write_cache = 0;
	/* start atomic test and set */
	MTX_LOCK(&spec->ats_mutex);

	rc = spec->seek(spec, offset);
	if (rc < 0) {
		MTX_UNLOCK(&spec->ats_mutex);
		ISTGT_ERRLOG("lu_disk_seek() failed\n");
		return -1;
	}

	rc = spec->read(spec, spec->watsbuf, nbytes);
	if (rc < 0 || (uint64_t) rc != nbytes) {
		MTX_UNLOCK(&spec->ats_mutex);
		ISTGT_ERRLOG("lu_disk_read() failed\n");
		return -1;
	}

#if 0
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "ATS VERIFY", data, nbytes);
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "ATS WRITE", data + nbytes, nbytes);
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "ATS DATA", spec->watsbuf, nbytes);
#endif
	if (memcmp(spec->watsbuf, data, nbytes) != 0) {
		MTX_UNLOCK(&spec->ats_mutex);
		//ISTGT_ERRLOG("compare failed\n");
		/* MISCOMPARE DURING VERIFY OPERATION */
		BUILD_SENSE(MISCOMPARE, 0x1d, 0x00);
		return -1;
	}

	rc = spec->seek(spec, offset);
	if (rc < 0) {
		MTX_UNLOCK(&spec->ats_mutex);
		ISTGT_ERRLOG("lu_disk_seek() failed\n");
		return -1;
	}
	rc = spec->write(spec, data + nbytes, nbytes);
	if (rc < 0 || (uint64_t) rc != nbytes) {
		MTX_UNLOCK(&spec->ats_mutex);
		ISTGT_ERRLOG("lu_disk_write() failed\n");
		return -1;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "Wrote %"PRId64"/%"PRIu64" bytes\n",
	    rc, nbytes);

	MTX_UNLOCK(&spec->ats_mutex);
	/* end atomic test and set */

	lu_cmd->data_len = nbytes * 2;

	return 0;
}

static int
istgt_lu_disk_lbsync(ISTGT_LU_DISK *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd __attribute__((__unused__)), uint64_t lba, uint32_t len)
{
	uint64_t maxlba;
	uint64_t llen;
	uint64_t blen;
	uint64_t offset;
	uint64_t nbytes;
	int64_t rc;

	maxlba = spec->blockcnt;
	if (len == 0 && lba < maxlba) {
		llen = maxlba - lba;
	} else {
		llen = (uint64_t) len;
	}
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

	rc = spec->sync(spec, offset, nbytes);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_disk_sync() failed\n");
		return -1;
	}

	return 0;
}

int
istgt_lu_scsi_build_sense_data(uint8_t *data, int sk, int asc, int ascq)
{
	uint8_t *cp;
	int resp_code;
	int hlen = 0, len = 0, plen;
	int total;

	resp_code = 0x70; /* Current + Fixed format */

	/* SenseLength */
	DSET16(&data[0], 0);
	hlen = 2;

	/* Sense Data */
	cp = &data[hlen + len];

	/* VALID(7) RESPONSE CODE(6-0) */
	BDSET8(&cp[0], 1, 7);
	BDADD8W(&cp[0], resp_code, 6, 7);
	/* Obsolete */
	cp[1] = 0;
	/* FILEMARK(7) EOM(6) ILI(5) SENSE KEY(3-0) */
	BDSET8W(&cp[2], sk, 3, 4);
	/* INFORMATION */
	memset(&cp[3], 0, 4);
	/* ADDITIONAL SENSE LENGTH */
	cp[7] = 0;
	len = 8;

	/* COMMAND-SPECIFIC INFORMATION */
	memset(&cp[8], 0, 4);
	/* ADDITIONAL SENSE CODE */
	cp[12] = asc;
	/* ADDITIONAL SENSE CODE QUALIFIER */
	cp[13] = ascq;
	/* FIELD REPLACEABLE UNIT CODE */
	cp[14] = 0;
	/* SKSV(7) SENSE KEY SPECIFIC(6-0,7-0,7-0) */
	cp[15] = 0;
	cp[16] = 0;
	cp[17] = 0;
	/* Additional sense bytes */
	//data[18] = 0;
	plen = 18 - len;

	/* ADDITIONAL SENSE LENGTH */
	cp[7] = plen;

	total = hlen + len + plen;

	/* SenseLength */
	DSET16(&data[0], total - 2);

	return total;
}

static int
istgt_lu_disk_build_sense_data(ISTGT_LU_DISK *spec __attribute__((__unused__)), uint8_t *data, int sk, int asc, int ascq)
{
	int rc;

	rc = istgt_lu_scsi_build_sense_data(data, sk, asc, ascq);
	if (rc < 0) {
		return -1;
	}
	return rc;
}

int
istgt_lu_scsi_build_sense_data2(uint8_t *data, int sk, int asc, int ascq)
{
	uint8_t *cp;
	int resp_code;
	int hlen = 0, len = 0, plen;
	int total;

	resp_code = 0x71; /* Deferred + Fixed format */

	/* SenseLength */
	DSET16(&data[0], 0);
	hlen = 2;

	/* Sense Data */
	cp = &data[hlen + len];

	/* VALID(7) RESPONSE CODE(6-0) */
	BDSET8(&cp[0], 1, 7);
	BDADD8W(&cp[0], resp_code, 6, 7);
	/* Obsolete */
	cp[1] = 0;
	/* FILEMARK(7) EOM(6) ILI(5) SENSE KEY(3-0) */
	BDSET8W(&cp[2], sk, 3, 4);
	/* INFORMATION */
	memset(&cp[3], 0, 4);
	/* ADDITIONAL SENSE LENGTH */
	cp[7] = 0;
	len = 8;

	/* COMMAND-SPECIFIC INFORMATION */
	memset(&cp[8], 0, 4);
	/* ADDITIONAL SENSE CODE */
	cp[12] = asc;
	/* ADDITIONAL SENSE CODE QUALIFIER */
	cp[13] = ascq;
	/* FIELD REPLACEABLE UNIT CODE */
	cp[14] = 0;
	/* SKSV(7) SENSE KEY SPECIFIC(6-0,7-0,7-0) */
	cp[15] = 0;
	cp[16] = 0;
	cp[17] = 0;
	/* Additional sense bytes */
	//data[18] = 0;
	plen = 18 - len;

	/* ADDITIONAL SENSE LENGTH */
	cp[7] = plen;

	total = hlen + len + plen;

	/* SenseLength */
	DSET16(&data[0], total - 2);

	return total;
}

static int
istgt_lu_disk_build_sense_data2(ISTGT_LU_DISK *spec __attribute__((__unused__)), uint8_t *data, int sk, int asc, int ascq)
{
	int rc;

	rc = istgt_lu_scsi_build_sense_data2(data, sk, asc, ascq);
	if (rc < 0) {
		return -1;
	}
	return rc;
}

int
istgt_lu_disk_reset(ISTGT_LU_Ptr lu, int lun)
{
	ISTGT_LU_DISK *spec;
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
	if (lu->lun[lun].type != ISTGT_LU_LUN_TYPE_STORAGE) {
		return -1;
	}
	spec = (ISTGT_LU_DISK *) lu->lun[lun].spec;

#if 0
	if (spec->lock) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "unlock by reset\n");
		spec->lock = 0;
	}
#endif

	if (lu->queue_depth != 0) {
		rc = istgt_lu_disk_queue_clear_all(lu, lun);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_disk_queue_clear_all() failed\n");
			return -1;
		}
	}

	/* re-open file */
	if (!spec->lu->readonly) {
		rc = spec->sync(spec, 0, spec->size);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: LUN%d: lu_disk_sync() failed\n",
			    lu->num, lun);
			/* ignore error */
		}
	}
	rc = spec->close(spec);
	if (rc < 0) {
		ISTGT_ERRLOG("LU%d: LUN%d: lu_disk_close() failed\n",
		    lu->num, lun);
		/* ignore error */
	}
	flags = lu->readonly ? O_RDONLY : O_RDWR;
	rc = spec->open(spec, flags, 0666);
	if (rc < 0) {
		ISTGT_ERRLOG("LU%d: LUN%d: lu_disk_open() failed\n",
		    lu->num, lun);
		return -1;
	}

	return 0;
}

static int
istgt_lu_disk_queue_clear_internal(ISTGT_LU_DISK *spec, const char *initiator_port, int all_cmds, uint32_t CmdSN)
{
	ISTGT_LU_TASK_Ptr lu_task;
	ISTGT_QUEUE saved_queue;
	time_t now;
	int rc;

	if (spec == NULL)
		return -1;

	if (all_cmds != 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "queue clear by port=%s\n",
		    initiator_port);
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "queue clear by port=%s, CmdSN=%u\n",
		    initiator_port, CmdSN);
	}

	istgt_queue_init(&saved_queue);

	now = time(NULL);
	MTX_LOCK(&spec->cmd_queue_mutex);
	while (1) {
		lu_task = istgt_queue_dequeue(&spec->cmd_queue);
		if (lu_task == NULL)
			break;
		if (((all_cmds != 0) || (lu_task->lu_cmd.CmdSN == CmdSN))
		    && (strcasecmp(lu_task->initiator_port,
			    initiator_port) == 0)) {
			ISTGT_LOG("CmdSN(%u), OP=0x%x, ElapsedTime=%lu cleared\n",
			    lu_task->lu_cmd.CmdSN,
			    lu_task->lu_cmd.cdb[0],
			    (unsigned long) (now - lu_task->create_time));
			rc = istgt_lu_destroy_task(lu_task);
			if (rc < 0) {
				MTX_UNLOCK(&spec->cmd_queue_mutex);
				ISTGT_ERRLOG("lu_destory_task() failed\n");
				goto error_return;
			}
			continue;
		}
		rc = istgt_queue_enqueue(&saved_queue, lu_task);
		if (rc < 0) {
			MTX_UNLOCK(&spec->cmd_queue_mutex);
			ISTGT_ERRLOG("queue_enqueue() failed\n");
			goto error_return;
		}
	}
	while (1) {
		lu_task = istgt_queue_dequeue(&saved_queue);
		if (lu_task == NULL)
			break;
		rc = istgt_queue_enqueue(&spec->cmd_queue, lu_task);
		if (rc < 0) {
			MTX_UNLOCK(&spec->cmd_queue_mutex);
			ISTGT_ERRLOG("queue_enqueue() failed\n");
			goto error_return;
		}
	}
	MTX_UNLOCK(&spec->cmd_queue_mutex);

	/* check wait task */
	MTX_LOCK(&spec->wait_lu_task_mutex);
	lu_task = spec->wait_lu_task;
	if (lu_task != NULL) {
		if (((all_cmds != 0) || (lu_task->lu_cmd.CmdSN == CmdSN))
		    && (strcasecmp(lu_task->initiator_port,
			    initiator_port) == 0)) {
			/* conn had gone? */
			rc = pthread_mutex_trylock(&lu_task->trans_mutex);
			if (rc == 0) {
				ISTGT_LOG("CmdSN(%u), OP=0x%x, ElapsedTime=%lu aborted\n",
				    lu_task->lu_cmd.CmdSN,
				    lu_task->lu_cmd.cdb[0],
				    (unsigned long) (now - lu_task->create_time));
				/* force error */
				lu_task->error = 1;
				lu_task->abort = 1;
				rc = pthread_cond_broadcast(&lu_task->trans_cond);
				if (rc != 0) {
					/* ignore error */
				}
				MTX_UNLOCK(&lu_task->trans_mutex);
			}
		}
	}
	MTX_UNLOCK(&spec->wait_lu_task_mutex);

	rc = istgt_queue_count(&saved_queue);
	if (rc != 0) {
		ISTGT_ERRLOG("temporary queue is not empty\n");
		goto error_return;
	}

	istgt_queue_destroy(&saved_queue);
	return 0;

 error_return:
	istgt_queue_destroy(&saved_queue);
	return -1;
}

static int
istgt_lu_disk_queue_abort_ITL(ISTGT_LU_DISK *spec, const char *initiator_port)
{
	int rc;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "queue abort by port=%s\n",
	    initiator_port);

	rc = istgt_lu_disk_queue_clear_internal(spec, initiator_port,
	    1, 0U); /* ALL, CmdSN=0 */
	return rc;
}

int
istgt_lu_disk_queue_clear_IT(CONN_Ptr conn, ISTGT_LU_Ptr lu)
{
	ISTGT_LU_DISK *spec;
	int rc;
	int i;

	if (lu == NULL)
		return -1;

	for (i = 0; i < lu->maxlun; i++) {
		if (lu->lun[i].type == ISTGT_LU_LUN_TYPE_NONE) {
#if 0
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d none\n",
						   lu->num, i);
#endif
			continue;
		}
		if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_STORAGE) {
			ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
			return -1;
		}
		spec = (ISTGT_LU_DISK *) lu->lun[i].spec;
		if (spec == NULL) {
			continue;
		}

		rc = istgt_lu_disk_queue_clear_ITL(conn, lu, i);
		if (rc < 0) {
			return -1;
		}
	}

	return 0;
}

int
istgt_lu_disk_queue_clear_ITL(CONN_Ptr conn, ISTGT_LU_Ptr lu, int lun)
{
	ISTGT_LU_DISK *spec;
	int rc;

	if (lu == NULL)
		return -1;
	if (lun >= lu->maxlun)
		return -1;

	spec = (ISTGT_LU_DISK *) lu->lun[lun].spec;
	if (spec == NULL)
		return -1;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "queue clear by name=%s, port=%s\n",
	    conn->initiator_name, conn->initiator_port);

	rc = istgt_lu_disk_queue_clear_internal(spec, conn->initiator_port,
	    1, 0U); /* ALL, CmdSN=0 */
	return rc;
}

int
istgt_lu_disk_queue_clear_ITLQ(CONN_Ptr conn, ISTGT_LU_Ptr lu, int lun, uint32_t CmdSN)
{
	ISTGT_LU_DISK *spec;
	int rc;

	if (lu == NULL)
		return -1;
	if (lun >= lu->maxlun)
		return -1;

	spec = (ISTGT_LU_DISK *) lu->lun[lun].spec;
	if (spec == NULL)
		return -1;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "queue clear by name=%s, port=%s\n",
	    conn->initiator_name, conn->initiator_port);

	rc = istgt_lu_disk_queue_clear_internal(spec, conn->initiator_port,
	    0, CmdSN);
	return rc;
}

int
istgt_lu_disk_queue_clear_all(ISTGT_LU_Ptr lu, int lun)
{
	ISTGT_LU_TASK_Ptr lu_task;
	ISTGT_LU_DISK *spec;
	time_t now;
	int rc;

	if (lu == NULL)
		return -1;
	if (lun >= lu->maxlun)
		return -1;

	if (lu->lun[lun].type == ISTGT_LU_LUN_TYPE_NONE) {
		return -1;
	}
	if (lu->lun[lun].type != ISTGT_LU_LUN_TYPE_STORAGE) {
		return -1;
	}
	spec = (ISTGT_LU_DISK *) lu->lun[lun].spec;
	if (spec == NULL)
		return -1;

	now = time(NULL);
	MTX_LOCK(&spec->cmd_queue_mutex);
	while (1) {
		lu_task = istgt_queue_dequeue(&spec->cmd_queue);
		if (lu_task == NULL)
			break;
		ISTGT_LOG("CmdSN(%u), OP=0x%x, ElapsedTime=%lu cleared\n",
		    lu_task->lu_cmd.CmdSN,
		    lu_task->lu_cmd.cdb[0],
		    (unsigned long) (now - lu_task->create_time));
		rc = istgt_lu_destroy_task(lu_task);
		if (rc < 0) {
			MTX_UNLOCK(&spec->cmd_queue_mutex);
			ISTGT_ERRLOG("lu_destory_task() failed\n");
			return -1;
		}
	}
	MTX_UNLOCK(&spec->cmd_queue_mutex);

	/* check wait task */
	MTX_LOCK(&spec->wait_lu_task_mutex);
	lu_task = spec->wait_lu_task;
	if (lu_task != NULL) {
		/* conn had gone? */
		rc = pthread_mutex_trylock(&lu_task->trans_mutex);
		if (rc == 0) {
			ISTGT_LOG("CmdSN(%u), OP=0x%x, ElapsedTime=%lu aborted\n",
			    lu_task->lu_cmd.CmdSN,
			    lu_task->lu_cmd.cdb[0],
			    (unsigned long) (now - lu_task->create_time));
			/* force error */
			lu_task->error = 1;
			lu_task->abort = 1;
			rc = pthread_cond_broadcast(&lu_task->trans_cond);
			if (rc != 0) {
				/* ignore error */
			}
			MTX_UNLOCK(&lu_task->trans_mutex);
		}
	}
	MTX_UNLOCK(&spec->wait_lu_task_mutex);

	MTX_LOCK(&spec->cmd_queue_mutex);
	rc = istgt_queue_count(&spec->cmd_queue);
	MTX_UNLOCK(&spec->cmd_queue_mutex);
	if (rc != 0) {
		ISTGT_ERRLOG("cmd queue is not empty\n");
		return -1;
	}

	return 0;
}

int
istgt_lu_disk_queue(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	ISTGT_LU_TASK_Ptr lu_task;
	ISTGT_LU_Ptr lu;
	ISTGT_LU_DISK *spec;
	uint8_t *data;
	uint8_t *cdb;
	uint32_t allocation_len;
	int data_len;
	int data_alloc_len;
	uint8_t *sense_data;
	size_t *sense_len;
	int lun_i;
	int maxq;
	int qcnt;
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

	lun_i = istgt_lu_islun2lun(lu_cmd->lun);
	if (lun_i >= lu->maxlun) {
#ifdef ISTGT_TRACE_DISK
		ISTGT_ERRLOG("LU%d: LUN%d invalid\n",
		    lu->num, lun_i);
#endif /* ISTGT_TRACE_DISK */
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
			return ISTGT_LU_TASK_RESULT_IMMEDIATE;
		} else {
			/* LOGICAL UNIT NOT SUPPORTED */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x25, 0x00);
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return ISTGT_LU_TASK_RESULT_IMMEDIATE;
		}
	}
	spec = (ISTGT_LU_DISK *) lu->lun[lun_i].spec;
	if (spec == NULL) {
		/* LOGICAL UNIT NOT SUPPORTED */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x25, 0x00);
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return ISTGT_LU_TASK_RESULT_IMMEDIATE;
	}
	/* ready to enqueue, spec is valid for LUN access */

	/* allocate task and copy LU_CMD(PDU) */
	lu_task = xmalloc(sizeof *lu_task);
	memset(lu_task, 0, sizeof *lu_task);
	rc = istgt_lu_create_task(conn, lu_cmd, lu_task, lun_i);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_create_task() failed\n");
		xfree(lu_task);
		return -1;
	}

	/* enqueue SCSI command */
	MTX_LOCK(&spec->cmd_queue_mutex);
	rc = istgt_queue_count(&spec->cmd_queue);
	maxq = spec->queue_depth * lu->istgt->MaxSessions;
	if (rc > maxq) {
		MTX_UNLOCK(&spec->cmd_queue_mutex);
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_TASK_SET_FULL;
		rc = istgt_lu_destroy_task(lu_task);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_destroy_task() failed\n");
			return -1;
		}
		return ISTGT_LU_TASK_RESULT_QUEUE_FULL;
	}
	qcnt = rc;
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
	    "Queue(%d), CmdSN=%u, OP=0x%x, LUN=0x%16.16"PRIx64"\n",
	    qcnt, lu_cmd->CmdSN, lu_cmd->cdb[0], lu_cmd->lun);

	/* enqueue task to LUN */
	switch (lu_cmd->Attr_bit) {
	case 0x03: /* Head of Queue */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "insert Head of Queue\n");
		rc = istgt_queue_enqueue_first(&spec->cmd_queue, lu_task);
		break;
	case 0x00: /* Untagged */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "insert Untagged\n");
		rc = istgt_queue_enqueue(&spec->cmd_queue, lu_task);
		break;
	case 0x01: /* Simple */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "insert Simple\n");
		rc = istgt_queue_enqueue(&spec->cmd_queue, lu_task);
		break;
	case 0x02: /* Ordered */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "insert Ordered\n");
		rc = istgt_queue_enqueue(&spec->cmd_queue, lu_task);
		break;
	case 0x04: /* ACA */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "insert ACA\n");
		rc = istgt_queue_enqueue(&spec->cmd_queue, lu_task);
		break;
	default: /* Reserved */
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "insert Reserved Attribute\n");
		rc = istgt_queue_enqueue(&spec->cmd_queue, lu_task);
		break;
	}
	MTX_UNLOCK(&spec->cmd_queue_mutex);
	if (rc < 0) {
		ISTGT_ERRLOG("queue_enqueue() failed\n");
	error_return:
		rc = istgt_lu_destroy_task(lu_task);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_destroy_task() failed\n");
			return -1;
		}
		return -1;
	}

	/* notify LUN thread */
	MTX_LOCK(&lu->queue_mutex);
	lu->queue_check = 1;
	rc = pthread_cond_broadcast(&lu->queue_cond);
	MTX_UNLOCK(&lu->queue_mutex);
	if (rc != 0) {
		ISTGT_ERRLOG("LU%d: cond_broadcast() failed\n", lu->num);
		goto error_return;
	}

	return ISTGT_LU_TASK_RESULT_QUEUE_OK;
}

int
istgt_lu_disk_queue_count(ISTGT_LU_Ptr lu, int *lun)
{
	ISTGT_LU_DISK *spec;
	int qcnt;
	int luns;
	int i;

	if (lun == NULL)
		return -1;

	i = *lun;
	if (i >= lu->maxlun) {
		*lun = 0;
		i = 0;
	}

	qcnt = 0;
	for (luns = lu->maxlun; luns >= 0 ; luns--) {
		if (lu->lun[i].type == ISTGT_LU_LUN_TYPE_NONE) {
			goto next_lun;
		}
		if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_STORAGE) {
			ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
			goto next_lun;
		}
		spec = (ISTGT_LU_DISK *) lu->lun[i].spec;
		if (spec == NULL) {
			goto next_lun;
		}

		MTX_LOCK(&spec->cmd_queue_mutex);
		qcnt = istgt_queue_count(&spec->cmd_queue);
		MTX_UNLOCK(&spec->cmd_queue_mutex);
		if (qcnt > 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "LU%d: LUN%d queue(%d)\n",
			    lu->num, i, qcnt);
			*lun = spec->lun;
			break;
		}

	next_lun:
		i++;
		if (i >= lu->maxlun) {
			i = 0;
		}
	}
	return qcnt;
}

int
istgt_lu_disk_queue_start(ISTGT_LU_Ptr lu, int lun)
{
	ISTGT_Ptr istgt;
	ISTGT_LU_DISK *spec;
	ISTGT_LU_TASK_Ptr lu_task;
	CONN_Ptr conn;
	ISTGT_LU_CMD_Ptr lu_cmd;
	struct timespec abstime;
	time_t start, now;
	uint8_t *iobuf;
	char tmp[1];
	int abort_task = 0;
	int rc;

	if (lun < 0 || lun >= lu->maxlun) {
		return -1;
	}

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "LU%d: LUN%d queue start\n",
	    lu->num, lun);
	spec = (ISTGT_LU_DISK *) lu->lun[lun].spec;
	if (spec == NULL)
		return -1;

	MTX_LOCK(&spec->cmd_queue_mutex);
	lu_task = istgt_queue_dequeue(&spec->cmd_queue);
	MTX_UNLOCK(&spec->cmd_queue_mutex);
	if (lu_task == NULL) {
		/* cleared or empty queue */
		return 0;
	}
	lu_task->thread = pthread_self();
	conn = lu_task->conn;
	istgt = conn->istgt;
	lu_cmd = &lu_task->lu_cmd;

	/* XXX need pre-allocate? */
#if 0
	/* allocated in istgt_lu_create_task() */
	lu_task->data = xmalloc(lu_cmd->alloc_len);
	lu_task->sense_data = xmalloc(lu_cmd->sense_alloc_len);
	lu_task->iobuf = NULL;
#endif
	lu_cmd->data = lu_task->data;
	lu_cmd->data_len = 0;
	lu_cmd->sense_data = lu_task->sense_data;
	lu_cmd->sense_data_len = 0;

	tmp[0] = 'Q';
	if (lu_cmd->W_bit) {
		if (lu_cmd->pdu->data_segment_len >= lu_cmd->transfer_len) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "LU%d: LUN%d Task Write Immediate Start\n",
			    lu->num, lun);
#if 0
			iobuf = xmalloc(lu_cmd->pdu->data_segment_len);
			memcpy(iobuf, lu_cmd->pdu->data,
			    lu_cmd->pdu->data_segment_len);
			lu_task->iobuf = iobuf;
#else
			iobuf = lu_cmd->pdu->data;
			lu_task->dup_iobuf = 1;
#endif
			lu_cmd->iobuf = iobuf;

			MTX_LOCK(&lu_cmd->lu->mutex);
			rc = istgt_lu_disk_execute(conn, lu_cmd);
			MTX_UNLOCK(&lu_cmd->lu->mutex);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_execute() failed\n");
			error_return:
				rc = istgt_lu_destroy_task(lu_task);
				if (rc < 0) {
					ISTGT_ERRLOG("lu_destroy_task() failed\n");
					return -1;
				}
				return -1;
			}
			lu_task->execute = 1;

			/* response */
			if (conn->use_sender == 0) {
				MTX_LOCK(&conn->task_queue_mutex);
				rc = istgt_queue_enqueue(&conn->task_queue, lu_task);
				MTX_UNLOCK(&conn->task_queue_mutex);
				if (rc < 0) {
					ISTGT_ERRLOG("queue_enqueue() failed\n");
					goto error_return;
				}
				rc = write(conn->task_pipe[1], tmp, 1);
				if(rc < 0 || rc != 1) {
					ISTGT_ERRLOG("write() failed\n");
					goto error_return;
				}
			} else {
				MTX_LOCK(&conn->result_queue_mutex);
				rc = istgt_queue_enqueue(&conn->result_queue, lu_task);
				if (rc < 0) {
					MTX_UNLOCK(&conn->result_queue_mutex);
					ISTGT_ERRLOG("queue_enqueue() failed\n");
					goto error_return;
				}
				rc = pthread_cond_broadcast(&conn->result_queue_cond);
				MTX_UNLOCK(&conn->result_queue_mutex);
				if (rc != 0) {
					ISTGT_ERRLOG("cond_broadcast() failed\n");
					goto error_return;
				}
			}

#if 0
			/* write cache */
			if (spec->req_write_cache) {
				MTX_LOCK(&lu->mutex);
				rc = istgt_lu_disk_write_cache(spec, conn);
				MTX_UNLOCK(&lu->mutex);
				if (rc < 0) {
					ISTGT_ERRLOG("disk_write_cache() failed\n");
					return -1;
				}
			}
#endif
		} else {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "LU%d: LUN%d Task Write Start\n",
			    lu->num, lun);

#if 0
			MTX_LOCK(&spec->wait_lu_task_mutex);
			spec->wait_lu_task = NULL;
			MTX_UNLOCK(&spec->wait_lu_task_mutex);
#endif
			rc = pthread_mutex_init(&lu_task->trans_mutex, NULL);
			if (rc != 0) {
				ISTGT_ERRLOG("mutex_init() failed\n");
				goto error_return;
			}
			rc = pthread_cond_init(&lu_task->trans_cond, NULL);
			if (rc != 0) {
				ISTGT_ERRLOG("cond_init() failed\n");
				goto error_return;
			}
			rc = pthread_cond_init(&lu_task->exec_cond, NULL);
			if (rc != 0) {
				ISTGT_ERRLOG("cond_init() failed\n");
				goto error_return;
			}
			lu_task->use_cond = 1;
#if 0
			lu_cmd->iobufsize = lu_cmd->transfer_len + 65536;
			iobuf = xmalloc(lu_cmd->iobufsize);
			lu_task->iobuf = iobuf;
#else
			lu_cmd->iobufsize = lu_task->lu_cmd.iobufsize;
			iobuf = lu_task->iobuf;
#endif
			lu_cmd->iobuf = iobuf;
			lu_task->req_transfer_out = 1;
			memset(&abstime, 0, sizeof abstime);
			abstime.tv_sec = 0;
			abstime.tv_nsec = 0;

			MTX_LOCK(&conn->task_queue_mutex);
			rc = istgt_queue_enqueue(&conn->task_queue, lu_task);
			MTX_UNLOCK(&conn->task_queue_mutex);
			if (rc < 0) {
				MTX_UNLOCK(&lu_task->trans_mutex);
				ISTGT_ERRLOG("queue_enqueue() failed\n");
				goto error_return;
			}
			rc = write(conn->task_pipe[1], tmp, 1);
			if(rc < 0 || rc != 1) {
				MTX_UNLOCK(&lu_task->trans_mutex);
				ISTGT_ERRLOG("write() failed\n");
				goto error_return;
			}

			start = now = time(NULL);
			abstime.tv_sec = now + (lu_task->condwait / 1000);
			abstime.tv_nsec = (lu_task->condwait % 1000) * 1000000;
#if 0
			ISTGT_LOG("wait CmdSN=%u\n", lu_task->lu_cmd.CmdSN);
#endif
			MTX_LOCK(&lu_task->trans_mutex);
			MTX_LOCK(&spec->wait_lu_task_mutex);
			spec->wait_lu_task = lu_task;
			MTX_UNLOCK(&spec->wait_lu_task_mutex);
			rc = 0;
			while (lu_task->req_transfer_out == 1) {
				rc = pthread_cond_timedwait(&lu_task->trans_cond,
				    &lu_task->trans_mutex,
				    &abstime);
				if (rc == ETIMEDOUT) {
					if (lu_task->req_transfer_out == 1) {
						lu_task->error = 1;
						MTX_LOCK(&spec->wait_lu_task_mutex);
						spec->wait_lu_task = NULL;
						MTX_UNLOCK(&spec->wait_lu_task_mutex);
						MTX_UNLOCK(&lu_task->trans_mutex);
						now = time(NULL);
						ISTGT_ERRLOG("timeout trans_cond CmdSN=%u "
						    "(time=%d)\n",
						    lu_task->lu_cmd.CmdSN,
						    istgt_difftime(now, start));
						/* timeout */
						return -1;
					}
					/* OK cond */
					rc = 0;
					break;
				}
				if (lu_task->error != 0) {
					rc = -1;
					break;
				}
				if (rc != 0) {
					break;
				}
			}
			MTX_LOCK(&spec->wait_lu_task_mutex);
			spec->wait_lu_task = NULL;
			MTX_UNLOCK(&spec->wait_lu_task_mutex);
			MTX_UNLOCK(&lu_task->trans_mutex);
			if (rc != 0) {
				if (rc < 0) {
					lu_task->error = 1;
					if (lu_task->abort) {
						ISTGT_WARNLOG("transfer abort CmdSN=%u\n",
						    lu_task->lu_cmd.CmdSN);
						return -2;
					} else {
						ISTGT_ERRLOG("transfer error CmdSN=%u\n",
						    lu_task->lu_cmd.CmdSN);
						return -1;
					}
				}
				if (rc == ETIMEDOUT) {
					lu_task->error = 1;
					now = time(NULL);
					ISTGT_ERRLOG("timeout trans_cond CmdSN=%u (time=%d)\n",
					    lu_task->lu_cmd.CmdSN, istgt_difftime(now, start));
					return -1;
				}
				lu_task->error = 1;
				ISTGT_ERRLOG("cond_timedwait rc=%d\n", rc);
				return -1;
			}

			if (lu_task->req_execute == 0) {
				ISTGT_ERRLOG("wrong request\n");
				goto error_return;
			}
			MTX_LOCK(&lu_cmd->lu->mutex);
			rc = istgt_lu_disk_execute(conn, lu_cmd);
			MTX_UNLOCK(&lu_cmd->lu->mutex);
			if (rc < 0) {
				lu_task->error = 1;
				ISTGT_ERRLOG("lu_disk_execute() failed\n");
				goto error_return;
			}
			lu_task->execute = 1;

			/* response */
			if (conn->use_sender == 0) {
				MTX_LOCK(&conn->task_queue_mutex);
				rc = istgt_queue_enqueue(&conn->task_queue, lu_task);
				MTX_UNLOCK(&conn->task_queue_mutex);
				if (rc < 0) {
					ISTGT_ERRLOG("queue_enqueue() failed\n");
					goto error_return;
				}
				rc = write(conn->task_pipe[1], tmp, 1);
				if(rc < 0 || rc != 1) {
					ISTGT_ERRLOG("write() failed\n");
					goto error_return;
				}
			} else {
				MTX_LOCK(&conn->result_queue_mutex);
				rc = istgt_queue_enqueue(&conn->result_queue, lu_task);
				if (rc < 0) {
					MTX_UNLOCK(&conn->result_queue_mutex);
					ISTGT_ERRLOG("queue_enqueue() failed\n");
					goto error_return;
				}
				rc = pthread_cond_broadcast(&conn->result_queue_cond);
				MTX_UNLOCK(&conn->result_queue_mutex);
				if (rc != 0) {
					ISTGT_ERRLOG("cond_broadcast() failed\n");
					goto error_return;
				}
			}

#if 0
			/* write cache */
			if (spec->req_write_cache) {
				MTX_LOCK(&lu->mutex);
				rc = istgt_lu_disk_write_cache(spec, conn);
				MTX_UNLOCK(&lu->mutex);
				if (rc < 0) {
					ISTGT_ERRLOG("disk_write_cache() failed\n");
					return -1;
				}
			}
#endif
		}
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "LU%d: LUN%d Task Read Start\n",
		    lu->num, lun);
#if 0
		lu_cmd->iobufsize = lu_cmd->transfer_len + 65536;
		iobuf = xmalloc(lu_cmd->iobufsize);
		lu_task->iobuf = iobuf;
#else
		lu_cmd->iobufsize = lu_task->lu_cmd.iobufsize;
		iobuf = lu_task->iobuf;
#endif
		lu_cmd->iobuf = iobuf;
		MTX_LOCK(&lu_cmd->lu->mutex);
		rc = istgt_lu_disk_execute(conn, lu_cmd);
		MTX_UNLOCK(&lu_cmd->lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_disk_execute() failed\n");
			goto error_return;
		}
		lu_task->execute = 1;

		/* response */
		if (conn->use_sender == 0) {
			MTX_LOCK(&conn->task_queue_mutex);
			rc = istgt_queue_enqueue(&conn->task_queue, lu_task);
			MTX_UNLOCK(&conn->task_queue_mutex);
			if (rc < 0) {
				ISTGT_ERRLOG("queue_enqueue() failed\n");
				goto error_return;
			}
			rc = write(conn->task_pipe[1], tmp, 1);
			if(rc < 0 || rc != 1) {
				ISTGT_ERRLOG("write() failed\n");
				goto error_return;
			}
		} else {
			MTX_LOCK(&conn->result_queue_mutex);
			rc = istgt_queue_enqueue(&conn->result_queue, lu_task);
			if (rc < 0) {
				MTX_UNLOCK(&conn->result_queue_mutex);
				ISTGT_ERRLOG("queue_enqueue() failed\n");
				goto error_return;
			}
			rc = pthread_cond_broadcast(&conn->result_queue_cond);
			MTX_UNLOCK(&conn->result_queue_mutex);
			if (rc != 0) {
				ISTGT_ERRLOG("cond_broadcast() failed\n");
				goto error_return;
			}
		}
	}

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "LU%d: LUN%d queue end\n",
	    lu->num, lun);

	if (abort_task) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Abort Task\n");
		return -1;
	}
	return 0;
}

int
istgt_lu_disk_execute(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	ISTGT_LU_Ptr lu;
	ISTGT_LU_DISK *spec;
	uint8_t *data;
	uint8_t *cdb;
	uint32_t allocation_len;
	int data_len;
	int data_alloc_len;
	uint64_t lba;
	uint32_t len;
	uint32_t transfer_len;
	uint32_t parameter_len;
	uint8_t *sense_data;
	size_t *sense_len;
	int lun_i;
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

	lun_i = istgt_lu_islun2lun(lu_cmd->lun);
	if (lun_i >= lu->maxlun) {
#ifdef ISTGT_TRACE_DISK
		ISTGT_ERRLOG("LU%d: LUN%d invalid\n",
		    lu->num, lun_i);
#endif /* ISTGT_TRACE_DISK */
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
	spec = (ISTGT_LU_DISK *) lu->lun[lun_i].spec;
	if (spec == NULL) {
		/* LOGICAL UNIT NOT SUPPORTED */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x25, 0x00);
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return 0;
	}

	if (spec->sense != 0) {
		int sk, asc, ascq;
		if (cdb[0] != SPC_INQUIRY
		    && cdb[0] != SPC_REPORT_LUNS) {
			sk = (spec->sense >> 16) & 0xffU;
			asc = (spec->sense >> 8) & 0xffU;
			ascq = (spec->sense >> 0) & 0xffU;
			spec->sense = 0;
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "Generate sk=0x%x, asc=0x%x, ascq=0x%x\n",
			    sk, asc, ascq);
			*sense_len
				= istgt_lu_disk_build_sense_data(spec, sense_data,
				    sk, asc, ascq);
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return 0;
		}
	}

	if (spec->err_write_cache) {
		/* WRITE ERROR - AUTO REALLOCATION FAILED */
		BUILD_SENSE2(MEDIUM_ERROR, 0x0c, 0x02);
#if 0
		/* WRITE ERROR - RECOMMEND REASSIGNMENT */
		BUILD_SENSE2(MEDIUM_ERROR, 0x0c, 0x03);
#endif
		spec->err_write_cache = 0;
		lba = spec->woffset / spec->blocklen;
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "Deferred error (write cache) at %"PRIu64"\n", lba);
		if (lba > 0xffffffffULL) {
			ISTGT_WARNLOG("lba > 0xffffffff\n");
		}
		/* COMMAND-SPECIFIC INFORMATION */
		DSET32(&sense_data[8], (uint32_t)(lba & 0xffffffffULL));
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return 0;
	}

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
	    "SCSI OP=0x%x, LUN=0x%16.16"PRIx64"\n",
	    cdb[0], lu_cmd->lun);
#ifdef ISTGT_TRACE_DISK
	if (cdb[0] != SPC_TEST_UNIT_READY) {
		istgt_scsi_dump_cdb(cdb);
	}
#endif /* ISTGT_TRACE_DISK */
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
		data_len = istgt_lu_disk_scsi_inquiry(spec, conn, cdb,
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
			data_len = istgt_lu_disk_scsi_report_luns(lu, conn, cdb, sel,
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
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		break;

	case SBC_START_STOP_UNIT:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "START_STOP_UNIT\n");
		{
			int pc, loej, start;

			pc = BGET8W(&cdb[4], 7, 4);
			loej = BGET8(&cdb[4], 1);
			start = BGET8(&cdb[4], 0);

			if (start != 0 || pc != 0) {
				if (spec->rsv_key) {
					rc = istgt_lu_disk_check_pr(spec, conn,
					    PR_ALLOW(0,0,1,0,0));
					if (rc != 0) {
						lu_cmd->status
							= ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
						break;
					}
				}
			}

			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		}
		break;

	case SBC_READ_CAPACITY_10:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ_CAPACITY_10\n");
		if (lu_cmd->R_bit == 0) {
			ISTGT_ERRLOG("R_bit == 0\n");
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
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
		ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG,
		    "SBC_READ_CAPACITY_10", data, data_len);
		break;

	case SPC_SERVICE_ACTION_IN_16:
		switch (BGET8W(&cdb[1], 4, 5)) { /* SERVICE ACTION */
		case SBC_SAI_READ_CAPACITY_16:
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "READ_CAPACITY_16\n");
			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			allocation_len = DGET32(&cdb[10]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);
			DSET64(&data[0], spec->blockcnt - 1);
			DSET32(&data[8], (uint32_t) spec->blocklen);
			data[12] = 0;                   /* RTO_EN(1) PROT_EN(0) */
			memset(&data[13], 0, 32 - (8 + 4 + 1));     /* Reserved */
			data_len = 32;
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		case SBC_SAI_READ_LONG_16:
		default:
			/* INVALID COMMAND OPERATION CODE */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			break;
		}
		break;

	case SPC_MODE_SELECT_6:
#if 0
		istgt_scsi_dump_cdb(cdb);
#endif
		{
			int pf, sp, pllen;
			int mdlen, mt, dsp, bdlen;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			pf = BGET8(&cdb[1], 4);
			sp = BGET8(&cdb[1], 0);
			pllen = cdb[4];             /* Parameter List Length */

			if (pllen == 0) {
				lu_cmd->data_len = 0;
				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				break;
			}
			/* Data-Out */
			rc = istgt_lu_disk_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
			    lu_cmd->iobufsize, pllen);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_transfer_data() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (pllen < 4) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
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
			data_len = istgt_lu_disk_scsi_mode_select_page(spec, conn, cdb, pf, sp, &data[4 + bdlen], pllen - (4 + bdlen));
			if (data_len != 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = pllen;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SPC_MODE_SELECT_10:
#if 0
		istgt_scsi_dump_cdb(cdb);
#endif
		{
			int pf, sp, pllen;
			int mdlen, mt, dsp, bdlen;
			int llba;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			pf = BGET8(&cdb[1], 4);
			sp = BGET8(&cdb[1], 0);
			pllen = DGET16(&cdb[7]);    /* Parameter List Length */

			if (pllen == 0) {
				lu_cmd->data_len = 0;
				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				break;
			}
			/* Data-Out */
			rc = istgt_lu_disk_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
			    lu_cmd->iobufsize, pllen);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_transfer_data() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (pllen < 4) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
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
			data_len = istgt_lu_disk_scsi_mode_select_page(spec, conn, cdb, pf, sp, &data[8 + bdlen], pllen - (8 + bdlen));
			if (data_len != 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = pllen;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SPC_MODE_SENSE_6:
#if 0
		istgt_scsi_dump_cdb(cdb);
#endif
		{
			int dbd, pc, page, subpage;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

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

			data_len = istgt_lu_disk_scsi_mode_sense6(spec, conn, cdb, dbd, pc, page, subpage, data, data_alloc_len);
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
#if 0
		istgt_scsi_dump_cdb(cdb);
#endif
		{
			int dbd, pc, page, subpage;
			int llbaa;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

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

			data_len = istgt_lu_disk_scsi_mode_sense10(spec, conn, cdb, llbaa, dbd, pc, page, subpage, data, data_alloc_len);
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
			data_len = istgt_lu_disk_build_sense_data(spec, sense_data,
			    sk, asc, ascq);
			if (data_len < 0 || data_len < 2) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			/* omit SenseLength */
			data_len -= 2;
			memcpy(data, sense_data + 2, data_len);
#if 0
			istgt_dump("REQUEST SENSE", data, data_len);
#endif
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_READ_6:
		{
			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(1,0,1,1,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			lba = (uint64_t) (DGET24(&cdb[1]) & 0x001fffffU);
			transfer_len = (uint32_t) DGET8(&cdb[4]);
			if (transfer_len == 0) {
				transfer_len = 256;
			}
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "READ_6(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_disk_lbread(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbread() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_READ_10:
		{
			int dpo, fua, fua_nv;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(1,0,1,1,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			dpo = BGET8(&cdb[1], 4);
			fua = BGET8(&cdb[1], 3);
			fua_nv = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET32(&cdb[2]);
			transfer_len = (uint32_t) DGET16(&cdb[7]);
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "READ_10(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_disk_lbread(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbread() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_READ_12:
		{
			int dpo, fua, fua_nv;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(1,0,1,1,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			dpo = BGET8(&cdb[1], 4);
			fua = BGET8(&cdb[1], 3);
			fua_nv = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET32(&cdb[2]);
			transfer_len = (uint32_t) DGET32(&cdb[6]);
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "READ_12(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_disk_lbread(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbread() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_READ_16:
		{
			int dpo, fua, fua_nv;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(1,0,1,1,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			dpo = BGET8(&cdb[1], 4);
			fua = BGET8(&cdb[1], 3);
			fua_nv = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET64(&cdb[2]);
			transfer_len = (uint32_t) DGET32(&cdb[10]);
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "READ_16(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_disk_lbread(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbread() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_WRITE_6:
		{
			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			if (lu_cmd->W_bit == 0) {
				ISTGT_ERRLOG("W_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			lba = (uint64_t) (DGET24(&cdb[1]) & 0x001fffffU);
			transfer_len = (uint32_t) DGET8(&cdb[4]);
			if (transfer_len == 0) {
				transfer_len = 256;
			}
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "WRITE_6(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_disk_lbwrite(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbwrite() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_WRITE_10:
	case SBC_WRITE_AND_VERIFY_10:
		{
			int dpo, fua, fua_nv;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			if (lu_cmd->W_bit == 0) {
				ISTGT_ERRLOG("W_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			dpo = BGET8(&cdb[1], 4);
			fua = BGET8(&cdb[1], 3);
			fua_nv = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET32(&cdb[2]);
			transfer_len = (uint32_t) DGET16(&cdb[7]);
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "WRITE_10(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_disk_lbwrite(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbwrite() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_WRITE_12:
	case SBC_WRITE_AND_VERIFY_12:
		{
			int dpo, fua, fua_nv;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			if (lu_cmd->W_bit == 0) {
				ISTGT_ERRLOG("W_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			dpo = BGET8(&cdb[1], 4);
			fua = BGET8(&cdb[1], 3);
			fua_nv = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET32(&cdb[2]);
			transfer_len = (uint32_t) DGET32(&cdb[6]);
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "WRITE_12(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_disk_lbwrite(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbwrite() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_WRITE_16:
	case SBC_WRITE_AND_VERIFY_16:
		{
			int dpo, fua, fua_nv;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			if (lu_cmd->W_bit == 0) {
				ISTGT_ERRLOG("W_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			dpo = BGET8(&cdb[1], 4);
			fua = BGET8(&cdb[1], 3);
			fua_nv = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET64(&cdb[2]);
			transfer_len = (uint32_t) DGET32(&cdb[10]);
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "WRITE_16(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_disk_lbwrite(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbwrite() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_VERIFY_10:
		{
			int dpo, bytchk;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(1,0,1,1,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			dpo = BGET8(&cdb[1], 4);
			bytchk = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET32(&cdb[2]);
			len = (uint32_t) DGET16(&cdb[7]);
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "VERIFY_10(lba %"PRIu64", len %u blocks)\n",
			    lba, len);
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_VERIFY_12:
		{
			int dpo, bytchk;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(1,0,1,1,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			dpo = BGET8(&cdb[1], 4);
			bytchk = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET32(&cdb[2]);
			len = (uint32_t) DGET32(&cdb[6]);
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "VERIFY_12(lba %"PRIu64", len %u blocks)\n",
			    lba, len);
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_VERIFY_16:
		{
			int dpo, bytchk;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(1,0,1,1,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			dpo = BGET8(&cdb[1], 4);
			bytchk = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET64(&cdb[2]);
			len = (uint32_t) DGET32(&cdb[10]);
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "VERIFY_16(lba %"PRIu64", len %u blocks)\n",
			    lba, len);
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_WRITE_SAME_10:
		{
			int wprotect, pbdata, lbdata, group_no;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			if (lu_cmd->W_bit == 0) {
				ISTGT_ERRLOG("W_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			wprotect = BGET8W(&cdb[1], 7, 3);
			pbdata = BGET8(&cdb[1], 2);
			lbdata = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET32(&cdb[2]);
			transfer_len = (uint32_t) DGET16(&cdb[7]);
			group_no = BGET8W(&cdb[6], 4, 5);

			/* only PBDATA=0 and LBDATA=0 support */
			if (pbdata || lbdata) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "WRITE_SAME_10(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_disk_lbwrite_same(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbwrite_same() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_WRITE_SAME_16:
		{
			int wprotect, anchor, unmap, pbdata, lbdata, group_no;

#if 0
			istgt_scsi_dump_cdb(cdb);
#endif
			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			if (lu_cmd->W_bit == 0) {
				ISTGT_ERRLOG("W_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			wprotect = BGET8W(&cdb[1], 7, 3);
			anchor = BGET8(&cdb[1], 4);
			unmap = BGET8(&cdb[1], 3);
			pbdata = BGET8(&cdb[1], 2);
			lbdata = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET64(&cdb[2]);
			transfer_len = (uint32_t) DGET32(&cdb[10]);
			group_no = BGET8W(&cdb[14], 4, 5);

			/* only PBDATA=0 and LBDATA=0 support */
			if (pbdata || lbdata) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (anchor) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "WRITE_SAME_16(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_disk_lbwrite_same(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbwrite_same() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_COMPARE_AND_WRITE:
		{
			int64_t maxlen;
			int wprotect, dpo, fua, fua_nv, group_no;

#if 0
			istgt_scsi_dump_cdb(cdb);
#endif
			if (spec->lu->istgt->swmode == ISTGT_SWMODE_TRADITIONAL) {
				/* INVALID COMMAND OPERATION CODE */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			if (lu_cmd->W_bit == 0) {
				ISTGT_ERRLOG("W_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			wprotect = BGET8W(&cdb[1], 7, 3);
			dpo = BGET8(&cdb[1], 4);
			fua = BGET8(&cdb[1], 3);
			fua_nv = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET64(&cdb[2]);
			transfer_len = (uint32_t) DGET8(&cdb[13]);
			group_no = BGET8W(&cdb[14], 4, 5);

			maxlen = ISTGT_LU_WORK_ATS_BLOCK_SIZE / spec->blocklen;
			if (maxlen > 0xff) {
				maxlen = 0xff;
			}
			if (transfer_len > maxlen) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "COMPARE_AND_WRITE(lba %"PRIu64", len %u blocks)\n",
			    lba, transfer_len);
			rc = istgt_lu_disk_lbwrite_ats(spec, conn, lu_cmd, lba, transfer_len);
			if (rc < 0) {
				//ISTGT_ERRLOG("lu_disk_lbwrite_ats() failed\n");
				/* sense data build by function */
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_SYNCHRONIZE_CACHE_10:
		{
			int sync_nv, immed;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			sync_nv = BGET8(&cdb[1], 2);
			immed = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET32(&cdb[2]);
			len = (uint32_t) DGET16(&cdb[7]);
			if (len == 0) {
				len = spec->blockcnt;
			}
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "SYNCHRONIZE_CACHE_10(lba %"PRIu64
			    ", len %u blocks)\n",
			    lba, len);
			rc = istgt_lu_disk_lbsync(spec, conn, lu_cmd, lba, len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbsync() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_SYNCHRONIZE_CACHE_16:
		{
			int sync_nv, immed;

			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}

			sync_nv = BGET8(&cdb[1], 2);
			immed = BGET8(&cdb[1], 1);
			lba = (uint64_t) DGET64(&cdb[2]);
			len = (uint32_t) DGET32(&cdb[10]);
			if (len == 0) {
				len = spec->blockcnt;
			}
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
			    "SYNCHRONIZE_CACHE_16(lba %"PRIu64
			    ", len %u blocks)\n",
			    lba, len);
			rc = istgt_lu_disk_lbsync(spec, conn, lu_cmd, lba, len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_lbsync() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = 0;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_READ_DEFECT_DATA_10:
		{
			int req_plist, req_glist, list_format;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			req_plist = BGET8(&cdb[2], 4);
			req_glist = BGET8(&cdb[2], 3);
			list_format = BGET8W(&cdb[2], 2, 3);

			allocation_len = (uint32_t) DGET16(&cdb[7]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			data_len = istgt_lu_disk_scsi_read_defect10(spec, conn, cdb,
			    req_plist, req_glist, list_format, data, data_alloc_len);
			if (data_len < 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SBC_READ_DEFECT_DATA_12:
		{
			int req_plist, req_glist, list_format;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			req_plist = BGET8(&cdb[2], 4);
			req_glist = BGET8(&cdb[2], 3);
			list_format = BGET8W(&cdb[2], 2, 3);

			allocation_len = DGET32(&cdb[6]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);

			data_len = istgt_lu_disk_scsi_read_defect12(spec, conn, cdb,
			    req_plist, req_glist, list_format, data, data_alloc_len);
			if (data_len < 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}

	case SCC_MAINTENANCE_IN:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MAINTENANCE_IN\n");
		switch (BGET8W(&cdb[1], 4, 5)) { /* SERVICE ACTION */
		case SPC_MI_REPORT_TARGET_PORT_GROUPS:
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "REPORT_TARGET_PORT_GROUPS\n");
			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			allocation_len = DGET32(&cdb[6]);
			if (allocation_len > (size_t) data_alloc_len) {
				ISTGT_ERRLOG("data_alloc_len(%d) too small\n",
				    data_alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			memset(data, 0, allocation_len);
			data_len = istgt_lu_disk_scsi_report_target_port_groups(spec, conn, cdb, data, data_alloc_len);
			if (data_len < 0) {
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG,
			    "REPORT_TARGET_PORT_GROUPS", data, data_len);
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		default:
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "SA=0x%2.2x\n",
			    BGET8W(&cdb[1], 4, 5));
			/* INVALID COMMAND OPERATION CODE */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			break;
		}
		break;

	case SCC_MAINTENANCE_OUT:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "MAINTENANCE_OUT\n");
		switch (BGET8W(&cdb[1], 4, 5)) { /* SERVICE ACTION */
		case SPC_MO_SET_TARGET_PORT_GROUPS:
			ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "SET_TARGET_PORT_GROUPS\n");
			if (spec->rsv_key) {
				rc = istgt_lu_disk_check_pr(spec, conn, PR_ALLOW(0,0,1,0,0));
				if (rc != 0) {
					lu_cmd->status = ISTGT_SCSI_STATUS_RESERVATION_CONFLICT;
					break;
				}
			}
			if (lu_cmd->W_bit == 0) {
				ISTGT_ERRLOG("W_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			parameter_len = DGET32(&cdb[6]);
			if (parameter_len == 0) {
				lu_cmd->data_len = 0;
				lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
				break;
			}
			/* Data-Out */
			rc = istgt_lu_disk_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
			    lu_cmd->iobufsize, parameter_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_transfer_data() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (parameter_len < 4) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG,
			    "SET_TARGET_PORT_GROUPS",
			    lu_cmd->iobuf, parameter_len);
			data = lu_cmd->iobuf;
			/* data[0]-data[3] Reserved */
			/* Set target port group descriptor(s) */
			data_len = istgt_lu_disk_scsi_set_target_port_groups(spec, conn, cdb, &data[4], parameter_len - 4);
			if (data_len < 0) {
				/* INVALID FIELD IN PARAMETER LIST */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x26, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			lu_cmd->data_len = parameter_len;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		default:
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "SA=0x%2.2x\n",
			    BGET8W(&cdb[1], 4, 5));
			/* INVALID COMMAND OPERATION CODE */
			BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			break;
		}
		break;

	case SPC_PERSISTENT_RESERVE_IN:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "PERSISTENT_RESERVE_IN\n");
		{
			int sa;

			if (lu_cmd->R_bit == 0) {
				ISTGT_ERRLOG("R_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
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

			data_len = istgt_lu_disk_scsi_persistent_reserve_in(spec, conn, lu_cmd, sa, data, allocation_len);
			if (data_len < 0) {
				/* status build by function */
				break;
			}
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG,
			    "PERSISTENT_RESERVE_IN", data, data_len);
			lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		}
		break;

	case SPC_PERSISTENT_RESERVE_OUT:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "PERSISTENT_RESERVE_OUT\n");
		{
			int sa, scope, type;

			if (lu_cmd->W_bit == 0) {
				ISTGT_ERRLOG("W_bit == 0\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}

			sa = BGET8W(&cdb[1], 4, 5);
			scope = BGET8W(&cdb[2], 7, 4);
			type = BGET8W(&cdb[2], 3, 4);
			parameter_len = DGET32(&cdb[5]);

			/* Data-Out */
			rc = istgt_lu_disk_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
			    lu_cmd->iobufsize, parameter_len);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_disk_transfer_data() failed\n");
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}
			if (parameter_len < 24) {
				/* INVALID FIELD IN CDB */
				BUILD_SENSE(ILLEGAL_REQUEST, 0x24, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				break;
			}

			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG,
			    "PERSISTENT_RESERVE_OUT",
			    lu_cmd->iobuf, parameter_len);
			data = lu_cmd->iobuf;

			data_len = istgt_lu_disk_scsi_persistent_reserve_out(spec, conn, lu_cmd, sa, scope, type, &data[0], parameter_len);
			if (data_len < 0) {
				/* status build by function */
				break;
			}
			lu_cmd->data_len = parameter_len;
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		}
		break;

	/* XXX TODO: fix */
	case 0x85: /* ATA PASS-THROUGH(16) */
	case 0xA1: /* ATA PASS-THROUGH(12) */
		/* INVALID COMMAND OPERATION CODE */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		break;
	case SPC_EXTENDED_COPY:
		/* INVALID COMMAND OPERATION CODE */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x20, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		break;
	case SPC2_RELEASE_6:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "RELEASE_6\n");
		rc = istgt_lu_disk_scsi_release(spec, conn, lu_cmd);
		if (rc < 0) {
			/* build by function */
			break;
		}
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		break;
	case SPC2_RELEASE_10:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "RELEASE_10\n");
		rc = istgt_lu_disk_scsi_release(spec, conn, lu_cmd);
		if (rc < 0) {
			/* build by function */
			break;
		}
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		break;
	case SPC2_RESERVE_6:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "RESERVE_6\n");
		rc = istgt_lu_disk_scsi_reserve(spec, conn, lu_cmd);
		if (rc < 0) {
			/* build by function */
			break;
		}
		lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
		break;
	case SPC2_RESERVE_10:
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "RESERVE_10\n");
		rc = istgt_lu_disk_scsi_reserve(spec, conn, lu_cmd);
		if (rc < 0) {
			/* build by function */
			break;
		}
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
