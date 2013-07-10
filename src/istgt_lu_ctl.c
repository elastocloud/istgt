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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#include <unistd.h>
#include <sys/param.h>

#include "istgt.h"
#include "istgt_ver.h"
#include "istgt_log.h"
#include "istgt_sock.h"
#include "istgt_misc.h"
#include "istgt_md5.h"
#include "istgt_lu.h"
#include "istgt_iscsi.h"
#include "istgt_proto.h"

#if !defined(__GNUC__)
#undef __attribute__
#define __attribute__(x)
#endif

#define TIMEOUT_RW 60
#define MAX_LINEBUF 4096

typedef struct istgt_uctl_t {
	int id;

	ISTGT_Ptr istgt;
	PORTAL portal;
	int sock;
	pthread_t thread;

	int family;
	char caddr[MAX_ADDRBUF];
	char saddr[MAX_ADDRBUF];

	ISTGT_CHAP_AUTH auth;
	int authenticated;

	int timeout;
	int auth_group;
	int no_auth;
	int req_auth;
	int req_mutual;

	char *mediadirectory;

	int recvtmpsize;
	int recvtmpcnt;
	int recvtmpidx;
	int recvbufsize;
	int sendbufsize;
	int worksize;
	char recvtmp[MAX_LINEBUF];
	char recvbuf[MAX_LINEBUF];
	char sendbuf[MAX_LINEBUF];
	char work[MAX_LINEBUF];
	char *cmd;
	char *arg;
} UCTL;
typedef UCTL *UCTL_Ptr;

typedef enum {
	UCTL_CMD_OK = 0,
	UCTL_CMD_ERR = 1,
	UCTL_CMD_EOF = 2,
	UCTL_CMD_QUIT = 3,
	UCTL_CMD_DISCON = 4,
} UCTL_CMD_STATUS;

#define ARGS_DELIM " \t"

static int
istgt_uctl_readline(UCTL_Ptr uctl)
{
	ssize_t total;

	total = istgt_readline_socket(uctl->sock, uctl->recvbuf, uctl->recvbufsize,
	    uctl->recvtmp, uctl->recvtmpsize,
	    &uctl->recvtmpidx, &uctl->recvtmpcnt,
	    uctl->timeout);
	if (total < 0) {
		return UCTL_CMD_DISCON;
	}
	if (total == 0) {
		return UCTL_CMD_EOF;
	}
	return UCTL_CMD_OK;
}

static int
istgt_uctl_writeline(UCTL_Ptr uctl)
{
	ssize_t total;
	ssize_t expect;

	expect = strlen(uctl->sendbuf);
	total = istgt_writeline_socket(uctl->sock, uctl->sendbuf, uctl->timeout);
	if (total < 0) {
		return UCTL_CMD_DISCON;
	}
	if (total != expect) {
		return UCTL_CMD_ERR;
	}
	return UCTL_CMD_OK;
}

static int istgt_uctl_snprintf(UCTL_Ptr uctl, const char *format, ...) __attribute__((__format__(__printf__, 2, 3)));

static int
istgt_uctl_snprintf(UCTL_Ptr uctl, const char *format, ...)
{
	va_list ap;
	int rc;

	va_start(ap, format);
	rc = vsnprintf(uctl->sendbuf, uctl->sendbufsize, format, ap);
	va_end(ap);
	return rc;
}

static int
istgt_uctl_get_media_present(ISTGT_LU_Ptr lu, int lun)
{
	int rc;

	switch (lu->type) {
	case ISTGT_LU_TYPE_DVD:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_dvd_media_present(lu->lun[lun].spec);
		MTX_UNLOCK(&lu->mutex);
		break;
	case ISTGT_LU_TYPE_TAPE:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_tape_media_present(lu->lun[lun].spec);
		MTX_UNLOCK(&lu->mutex);
		break;
	default:
		rc = 0;
	}
	return rc;
}

static int
istgt_uctl_get_media_lock(ISTGT_LU_Ptr lu, int lun)
{
	int rc;

	switch (lu->type) {
	case ISTGT_LU_TYPE_DVD:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_dvd_media_lock(lu->lun[lun].spec);
		MTX_UNLOCK(&lu->mutex);
		break;
	case ISTGT_LU_TYPE_TAPE:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_tape_media_lock(lu->lun[lun].spec);
		MTX_UNLOCK(&lu->mutex);
		break;
	default:
		rc = 0;
	}
	return rc;
}

static int
istgt_uctl_get_authinfo(UCTL_Ptr uctl, const char *authuser)
{
	char *authfile = NULL;
	int ag_tag;
	int rc;

	ag_tag = uctl->auth_group;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "ag_tag=%d\n", ag_tag);

	MTX_LOCK(&uctl->istgt->mutex);
	authfile = xstrdup(uctl->istgt->authfile);
	MTX_UNLOCK(&uctl->istgt->mutex);

	rc = istgt_chap_get_authinfo(&uctl->auth, authfile, authuser, ag_tag);
	if (rc < 0) {
		ISTGT_ERRLOG("chap_get_authinfo() failed\n");
		xfree(authfile);
		return -1;
	}
	xfree(authfile);
	return 0;
}

static int
istgt_uctl_cmd_auth(UCTL_Ptr uctl)
{
	const char *delim = ARGS_DELIM;
	char *arg;
	char *label;
	char *chap_a;
	char *chap_i;
	char *chap_c;
	char *chap_n;
	char *chap_r;
	int rc;

	arg = uctl->arg;
	label = strsepq(&arg, delim);

	if (label == NULL) {
		istgt_uctl_snprintf(uctl, "ERR invalid parameters\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}

	if (strcasecmp(label, "CHAP_A") == 0) {
		if (uctl->auth.chap_phase != ISTGT_CHAP_PHASE_WAIT_A) {
			istgt_uctl_snprintf(uctl, "ERR CHAP sequence error\n");
		error_return:
			uctl->auth.chap_phase = ISTGT_CHAP_PHASE_WAIT_A;
			rc = istgt_uctl_writeline(uctl);
			if (rc != UCTL_CMD_OK) {
				return rc;
			}
			return UCTL_CMD_ERR;
		}

		chap_a = strsepq(&arg, delim);
		if (chap_a == NULL  || strcasecmp(chap_a, "5") != 0) {
			istgt_uctl_snprintf(uctl, "ERR invalid algorithm\n");
			goto error_return;
		}

		/* Identifier is one octet */
		istgt_gen_random(uctl->auth.chap_id, 1);
		/* Challenge Value is a variable stream of octets */
		/* (binary length MUST not exceed 1024 bytes) */
		uctl->auth.chap_challenge_len = ISTGT_CHAP_CHALLENGE_LEN;
		istgt_gen_random(uctl->auth.chap_challenge,
		    uctl->auth.chap_challenge_len);

		istgt_bin2hex(uctl->work, uctl->worksize,
		    uctl->auth.chap_challenge,
		    uctl->auth.chap_challenge_len);

		istgt_uctl_snprintf(uctl, "%s CHAP_IC %d %s\n",
		    uctl->cmd, (int) uctl->auth.chap_id[0],
		    uctl->work);
		
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		uctl->auth.chap_phase = ISTGT_CHAP_PHASE_WAIT_NR;
		/* 3-way handshake */
		return UCTL_CMD_OK;
	} else if (strcasecmp(label, "CHAP_NR") == 0) {
		uint8_t resmd5[ISTGT_MD5DIGEST_LEN];
		uint8_t tgtmd5[ISTGT_MD5DIGEST_LEN];
		ISTGT_MD5CTX md5ctx;

		if (uctl->auth.chap_phase != ISTGT_CHAP_PHASE_WAIT_NR) {
			istgt_uctl_snprintf(uctl, "ERR CHAP sequence error\n");
			goto error_return;
		}

		chap_n = strsepq(&arg, delim);
		chap_r = strsepq(&arg, delim);
		if (chap_n == NULL || chap_r == NULL) {
			istgt_uctl_snprintf(uctl, "ERR no response\n");
			goto error_return;
		}
		//ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "N=%s, R=%s\n", chap_n, chap_r);

		rc = istgt_hex2bin(resmd5, ISTGT_MD5DIGEST_LEN, chap_r);
		if (rc < 0 || rc != ISTGT_MD5DIGEST_LEN) {
			istgt_uctl_snprintf(uctl, "ERR response format error\n");
			goto error_return;
		}

		rc = istgt_uctl_get_authinfo(uctl, chap_n);
		if (rc < 0) {
			ISTGT_ERRLOG("auth failed (user %.64s)\n", chap_n);
			istgt_uctl_snprintf(uctl, "ERR auth user or secret is missing\n");
			goto error_return;
		}
		if (uctl->auth.user == NULL || uctl->auth.secret == NULL) {
			ISTGT_ERRLOG("auth failed (user %.64s)\n", chap_n);
			istgt_uctl_snprintf(uctl, "ERR auth user or secret is missing\n");
			goto error_return;
		}

		istgt_md5init(&md5ctx);
		/* Identifier */
		istgt_md5update(&md5ctx, uctl->auth.chap_id, 1);
		/* followed by secret */
		istgt_md5update(&md5ctx, uctl->auth.secret,
		    strlen(uctl->auth.secret));
		/* followed by Challenge Value */
		istgt_md5update(&md5ctx, uctl->auth.chap_challenge,
		    uctl->auth.chap_challenge_len);
		/* tgtmd5 is expecting Response Value */
		istgt_md5final(tgtmd5, &md5ctx);

		/* compare MD5 digest */
		if (memcmp(tgtmd5, resmd5, ISTGT_MD5DIGEST_LEN) != 0) {
			/* not match */
			ISTGT_ERRLOG("auth failed (user %.64s)\n", chap_n);
			istgt_uctl_snprintf(uctl, "ERR auth user or secret is missing\n");
			goto error_return;
		}
		/* OK client's secret */
		uctl->authenticated = 1;

		/* mutual CHAP? */
		chap_i = strsepq(&arg, delim);
		chap_c = strsepq(&arg, delim);
		if (chap_i != NULL && chap_c != NULL) {
			/* Identifier */
			uctl->auth.chap_mid[0] = (uint8_t) strtol(chap_i, NULL, 10);
			/* Challenge Value */
			rc = istgt_hex2bin(uctl->auth.chap_mchallenge,
			    ISTGT_CHAP_CHALLENGE_LEN, chap_c);
			if (rc < 0) {
				istgt_uctl_snprintf(uctl, "ERR challenge format error\n");
				goto error_return;
			}
			uctl->auth.chap_mchallenge_len = rc;

			if (uctl->auth.muser == NULL || uctl->auth.msecret == NULL) {
				ISTGT_ERRLOG("auth failed (user %.64s)\n", chap_n);
				istgt_uctl_snprintf(uctl,
				    "ERR auth user or secret is missing\n");
				goto error_return;
			}

			istgt_md5init(&md5ctx);
			/* Identifier */
			istgt_md5update(&md5ctx, uctl->auth.chap_mid, 1);
			/* followed by secret */
			istgt_md5update(&md5ctx, uctl->auth.msecret,
			    strlen(uctl->auth.msecret));
			/* followed by Challenge Value */
			istgt_md5update(&md5ctx, uctl->auth.chap_mchallenge,
			    uctl->auth.chap_mchallenge_len);
			/* tgtmd5 is Response Value */
			istgt_md5final(tgtmd5, &md5ctx);

			istgt_bin2hex(uctl->work, uctl->worksize,
			    tgtmd5, ISTGT_MD5DIGEST_LEN);

			/* send NR for mutual CHAP */
			istgt_uctl_snprintf(uctl, "%s CHAP_NR \"%s\" %s\n",
			    uctl->cmd,
			    uctl->auth.muser,
			    uctl->work);
			rc = istgt_uctl_writeline(uctl);
			if (rc != UCTL_CMD_OK) {
				return rc;
			}
		} else {
			/* not mutual */
			if (uctl->req_mutual) {
				ISTGT_ERRLOG("required mutual CHAP\n");
				istgt_uctl_snprintf(uctl, "ERR CHAP sequence error\n");
				goto error_return;
			}
		}

		uctl->auth.chap_phase = ISTGT_CHAP_PHASE_END;
	} else {
		istgt_uctl_snprintf(uctl, "ERR CHAP sequence error\n");
		goto error_return;
	}

	/* auth succeeded (but mutual may fail) */
	istgt_uctl_snprintf(uctl, "OK %s\n", uctl->cmd);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		return rc;
	}
	return UCTL_CMD_OK;
}

static int
istgt_uctl_cmd_quit(UCTL_Ptr uctl)
{
	int rc;

	istgt_uctl_snprintf(uctl, "OK %s\n", uctl->cmd);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		return rc;
	}
	return UCTL_CMD_QUIT;
}

static int
istgt_uctl_cmd_noop(UCTL_Ptr uctl)
{
	int rc;

	istgt_uctl_snprintf(uctl, "OK %s\n", uctl->cmd);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		return rc;
	}
	return UCTL_CMD_OK;
}

static int
istgt_uctl_cmd_version(UCTL_Ptr uctl)
{
	int rc;

	istgt_uctl_snprintf(uctl, "%s %s (%s)\n", uctl->cmd,
	    ISTGT_VERSION, ISTGT_EXTRA_VERSION);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		return rc;
	}

	/* version succeeded */
	istgt_uctl_snprintf(uctl, "OK %s\n", uctl->cmd);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		return rc;
	}
	return UCTL_CMD_OK;
}

static int
istgt_uctl_cmd_list(UCTL_Ptr uctl)
{
	ISTGT_LU_Ptr lu;
	ISTGT_LU_LUN_Ptr llp;
	const char *delim = ARGS_DELIM;
	char *arg;
	char *iqn;
	char *lun;
	char *mflags;
	char *mfile;
	char *msize;
	char *mtype;
	char *workp;
	int lun_i;
	int worksize;
	int present;
	int lock;
	int rc;
	int i;

	arg = uctl->arg;
	iqn = strsepq(&arg, delim);
	lun = strsepq(&arg, delim);

	if (arg != NULL) {
		istgt_uctl_snprintf(uctl, "ERR invalid parameters\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}

	if (iqn == NULL) {
		/* all targets */
		MTX_LOCK(&uctl->istgt->mutex);
		for (i = 0; i < MAX_LOGICAL_UNIT; i++) {
			lu = uctl->istgt->logical_unit[i];
			if (lu == NULL)
				continue;
			istgt_uctl_snprintf(uctl, "%s %s\n", uctl->cmd, lu->name);
			rc = istgt_uctl_writeline(uctl);
			if (rc != UCTL_CMD_OK) {
				MTX_UNLOCK(&uctl->istgt->mutex);
				return rc;
			}
		}
		MTX_UNLOCK(&uctl->istgt->mutex);
	} else {
		/* specified target */
		MTX_LOCK(&uctl->istgt->mutex);
		if (lun == NULL) {
			lun_i = 0;
		} else {
			lun_i = (int) strtol(lun, NULL, 10);
		}
		lu = istgt_lu_find_target(uctl->istgt, iqn);
		if (lu == NULL) {
			MTX_UNLOCK(&uctl->istgt->mutex);
			istgt_uctl_snprintf(uctl, "ERR no target\n");
		error_return:
			rc = istgt_uctl_writeline(uctl);
			if (rc != UCTL_CMD_OK) {
				return rc;
			}
			return UCTL_CMD_ERR;
		}
		if (lun_i < 0 || lun_i >= lu->maxlun) {
			MTX_UNLOCK(&uctl->istgt->mutex);
			istgt_uctl_snprintf(uctl, "ERR no target\n");
			goto error_return;
		}
		llp = &lu->lun[lun_i];

		worksize = uctl->worksize;
		workp = uctl->work;

		switch (llp->type) {
		case ISTGT_LU_LUN_TYPE_REMOVABLE:
			mflags = istgt_lu_get_media_flags_string(llp->u.removable.flags,
			    workp, worksize);
			worksize -= strlen(mflags) + 1;
			workp += strlen(mflags) + 1;
			present = istgt_uctl_get_media_present(lu, lun_i);
			lock = istgt_uctl_get_media_lock(lu, lun_i);
			mfile = llp->u.removable.file;
			if (llp->u.removable.flags & ISTGT_LU_FLAG_MEDIA_AUTOSIZE) {
				snprintf(workp, worksize, "auto");
			} else {
				snprintf(workp, worksize, "%"PRIu64,
				    llp->u.removable.size);
			}
			msize = workp;
			worksize -= strlen(msize) + 1;
			workp += strlen(msize) + 1;
			snprintf(workp, worksize, "-");
			mtype = workp;
			worksize -= strlen(msize) + 1;
			workp += strlen(msize) + 1;

			istgt_uctl_snprintf(uctl, "%s lun%u %s %s %s %s %s \"%s\" %s\n",
			    uctl->cmd, lun_i,
			    "removable",
			    (present ? "present" : "absent"),
			    (lock ? "lock" : "unlock"),
			    mtype, mflags, mfile, msize);
			rc = istgt_uctl_writeline(uctl);
			break;
		case ISTGT_LU_LUN_TYPE_STORAGE:
			mfile = llp->u.storage.file;
			snprintf(workp, worksize, "%"PRIu64,
			    llp->u.storage.size);
			msize = workp;
			worksize -= strlen(msize) + 1;
			workp += strlen(msize) + 1;

			istgt_uctl_snprintf(uctl, "%s lun%u %s \"%s\" %s\n",
			    uctl->cmd, lun_i,
			    "storage",
			    mfile, msize);
			rc = istgt_uctl_writeline(uctl);
			break;
		case ISTGT_LU_LUN_TYPE_DEVICE:
			mfile = llp->u.device.file;

			istgt_uctl_snprintf(uctl, "%s lun%u %s \"%s\"\n",
			    uctl->cmd, lun_i,
			    "device",
			    mfile);
			rc = istgt_uctl_writeline(uctl);
			break;
		case ISTGT_LU_LUN_TYPE_SLOT:
		default:
			MTX_UNLOCK(&uctl->istgt->mutex);
			istgt_uctl_snprintf(uctl, "ERR unsupport LUN type\n");
			goto error_return;
		}

		if (rc != UCTL_CMD_OK) {
			MTX_UNLOCK(&uctl->istgt->mutex);
			return rc;
		}
		MTX_UNLOCK(&uctl->istgt->mutex);
	}

	/* list succeeded */
	istgt_uctl_snprintf(uctl, "OK %s\n", uctl->cmd);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		return rc;
	}
	return UCTL_CMD_OK;
}

static int
istgt_uctl_cmd_unload(UCTL_Ptr uctl)
{
	ISTGT_LU_Ptr lu;
	ISTGT_LU_LUN_Ptr llp;
	const char *delim = ARGS_DELIM;
	char *arg;
	char *iqn;
	char *lun;
	int lun_i;
	int rc;

	arg = uctl->arg;
	iqn = strsepq(&arg, delim);
	lun = strsepq(&arg, delim);

	if (iqn == NULL || arg != NULL) {
		istgt_uctl_snprintf(uctl, "ERR invalid parameters\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}

	if (lun == NULL) {
		lun_i = 0;
	} else {
		lun_i = (int) strtol(lun, NULL, 10);
	}
	lu = istgt_lu_find_target(uctl->istgt, iqn);
	if (lu == NULL) {
		istgt_uctl_snprintf(uctl, "ERR no target\n");
	error_return:
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}
	if (lun_i < 0 || lun_i >= lu->maxlun) {
		istgt_uctl_snprintf(uctl, "ERR no target\n");
		goto error_return;
	}
	llp = &lu->lun[lun_i];
	if (llp->type != ISTGT_LU_LUN_TYPE_REMOVABLE) {
		istgt_uctl_snprintf(uctl, "ERR not removable\n");
		goto error_return;
	}

	/* unload media from lun */
	switch (lu->type) {
	case ISTGT_LU_TYPE_DVD:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_dvd_unload_media(lu->lun[lun_i].spec);
		MTX_UNLOCK(&lu->mutex);
		break;
	case ISTGT_LU_TYPE_TAPE:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_tape_unload_media(lu->lun[lun_i].spec);
		MTX_UNLOCK(&lu->mutex);
		break;
	default:
		rc = -1;
	}

	if (rc < 0) {
		istgt_uctl_snprintf(uctl, "ERR unload\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}

	/* logging event */
	ISTGT_NOTICELOG("Media Unload %s lun%d from %s\n",
	    iqn, lun_i, uctl->caddr);

	/* unload succeeded */
	istgt_uctl_snprintf(uctl, "OK %s\n", uctl->cmd);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		return rc;
	}
	return UCTL_CMD_OK;
}

static int
istgt_uctl_cmd_load(UCTL_Ptr uctl)
{
	ISTGT_LU_Ptr lu;
	ISTGT_LU_LUN_Ptr llp;
	const char *delim = ARGS_DELIM;
	char *arg;
	char *iqn;
	char *lun;
	int lun_i;
	int rc;

	arg = uctl->arg;
	iqn = strsepq(&arg, delim);
	lun = strsepq(&arg, delim);

	if (iqn == NULL || arg != NULL) {
		istgt_uctl_snprintf(uctl, "ERR invalid parameters\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}

	if (lun == NULL) {
		lun_i = 0;
	} else {
		lun_i = (int) strtol(lun, NULL, 10);
	}
	lu = istgt_lu_find_target(uctl->istgt, iqn);
	if (lu == NULL) {
		istgt_uctl_snprintf(uctl, "ERR no target\n");
	error_return:
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}
	if (lun_i < 0 || lun_i >= lu->maxlun) {
		istgt_uctl_snprintf(uctl, "ERR no target\n");
		goto error_return;
	}
	llp = &lu->lun[lun_i];
	if (llp->type != ISTGT_LU_LUN_TYPE_REMOVABLE) {
		istgt_uctl_snprintf(uctl, "ERR not removable\n");
		goto error_return;
	}

	/* load media to lun */
	switch (lu->type) {
	case ISTGT_LU_TYPE_DVD:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_dvd_load_media(lu->lun[lun_i].spec);
		MTX_UNLOCK(&lu->mutex);
		break;
	case ISTGT_LU_TYPE_TAPE:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_tape_load_media(lu->lun[lun_i].spec);
		MTX_UNLOCK(&lu->mutex);
		break;
	default:
		rc = -1;
	}

	if (rc < 0) {
		istgt_uctl_snprintf(uctl, "ERR load\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}

	/* logging event */
	ISTGT_NOTICELOG("Media Load %s lun%d from %s\n",
	    iqn, lun_i, uctl->caddr);

	/* load succeeded */
	istgt_uctl_snprintf(uctl, "OK %s\n", uctl->cmd);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		return rc;
	}
	return UCTL_CMD_OK;
}

static int
istgt_uctl_cmd_change(UCTL_Ptr uctl)
{
	ISTGT_LU_Ptr lu;
	ISTGT_LU_LUN_Ptr llp;
	const char *delim = ARGS_DELIM;
	char empty_flags[] = "ro";
	char empty_size[] = "0";
	char *arg;
	char *iqn;
	char *lun;
	char *type;
	char *flags;
	char *file;
	char *size;
	char *safedir;
	char *fullpath;
	char *abspath;
	int lun_i;
	int len;
	int rc;

	arg = uctl->arg;
	iqn = strsepq(&arg, delim);
	lun = strsepq(&arg, delim);

	type = strsepq(&arg, delim);
	flags = strsepq(&arg, delim);
	file = strsepq(&arg, delim);
	size = strsepq(&arg, delim);

	if (iqn == NULL || lun == NULL || type == NULL || flags == NULL
	    || file == NULL || size == NULL || arg != NULL) {
		istgt_uctl_snprintf(uctl, "ERR invalid parameters\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}

	if (lun == NULL) {
		lun_i = 0;
	} else {
		lun_i = (int) strtol(lun, NULL, 10);
	}
	lu = istgt_lu_find_target(uctl->istgt, iqn);
	if (lu == NULL) {
		istgt_uctl_snprintf(uctl, "ERR no target\n");
	error_return:
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}
	if (lun_i < 0 || lun_i >= lu->maxlun) {
		istgt_uctl_snprintf(uctl, "ERR no target\n");
		goto error_return;
	}
	llp = &lu->lun[lun_i];
	if (llp->type != ISTGT_LU_LUN_TYPE_REMOVABLE) {
		istgt_uctl_snprintf(uctl, "ERR not removable\n");
		goto error_return;
	}

	/* make safe directory (start '/', end '/') */
	len = 1 + strlen(uctl->mediadirectory) + 1 + 1;
	safedir = xmalloc(len);
	if (uctl->mediadirectory[0] != '/') {
		ISTGT_WARNLOG("MediaDirectory is not starting with '/'\n");
		snprintf(safedir, len, "/%s", uctl->mediadirectory);
	} else {
		snprintf(safedir, len, "%s", uctl->mediadirectory);
	}
	if (strlen(safedir) > 1 && safedir[strlen(safedir) - 1] != '/') {
		safedir[strlen(safedir) + 1] = '\0';
		safedir[strlen(safedir)] = '/';
	}

	/* check abspath in mediadirectory? */
	len = strlen(safedir) + strlen(file) + 1;
	fullpath = xmalloc(len);
	if (file[0] != '/') {
		snprintf(fullpath, len, "%s%s", safedir, file);
	} else {
		snprintf(fullpath, len, "%s", file);
	}
#ifdef PATH_MAX
	abspath = xmalloc(len + PATH_MAX);
	file = realpath(fullpath, abspath);
#else
/*
	{
		long path_max;
		path_max = pathconf(fullpath, _PC_PATH_MAX);
		if (path_max != -1L) {
			abspath = xmalloc(path_max);
			file = realpath(fullpath, abspath);
		}
	}
*/
	file = abspath = realpath(fullpath, NULL);
#endif /* PATH_MAX */
	if (file == NULL) {
		ISTGT_ERRLOG("realpath(%s) failed\n", fullpath);
	internal_error:
		xfree(safedir);
		xfree(fullpath);
		xfree(abspath);
		istgt_uctl_snprintf(uctl, "ERR %s internal error\n", uctl->cmd);
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}
	if (strcasecmp(file, "/dev/null") == 0) {
		/* OK, empty slot */
		flags = empty_flags;
		size = empty_size;
	} else if (strncasecmp(file, safedir, strlen(safedir)) != 0) {
		ISTGT_ERRLOG("Realpath(%s) is not within MediaDirectory(%s)\n",
		    file, safedir);
		goto internal_error;
	}

	/* unload and load media from lun */
	switch (lu->type) {
	case ISTGT_LU_TYPE_DVD:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_dvd_change_media(lu->lun[lun_i].spec,
		    type, flags, file, size);
		MTX_UNLOCK(&lu->mutex);
		break;
	case ISTGT_LU_TYPE_TAPE:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_tape_change_media(lu->lun[lun_i].spec,
		    type, flags, file, size);
		MTX_UNLOCK(&lu->mutex);
		break;
	default:
		rc = -1;
	}

	if (rc < 0) {
		xfree(safedir);
		xfree(fullpath);
		xfree(abspath);
		istgt_uctl_snprintf(uctl, "ERR change\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}

	/* logging event */
	ISTGT_NOTICELOG("Media Change \"%s %s %s %s\" on %s lun%d from %s\n",
	    type, flags, file, size, iqn, lun_i, uctl->caddr);

	xfree(safedir);
	xfree(fullpath);
	xfree(abspath);

	/* change succeeded */
	istgt_uctl_snprintf(uctl, "OK %s\n", uctl->cmd);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		return rc;
	}
	return UCTL_CMD_OK;
}

static int
istgt_uctl_cmd_reset(UCTL_Ptr uctl)
{
	ISTGT_LU_Ptr lu;
	ISTGT_LU_LUN_Ptr llp;
	const char *delim = ARGS_DELIM;
	char *arg;
	char *iqn;
	char *lun;
	int lun_i;
	int rc;

	arg = uctl->arg;
	iqn = strsepq(&arg, delim);
	lun = strsepq(&arg, delim);

	if (iqn == NULL || arg != NULL) {
		istgt_uctl_snprintf(uctl, "ERR invalid parameters\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}

	if (lun == NULL) {
		lun_i = 0;
	} else {
		lun_i = (int) strtol(lun, NULL, 10);
	}
	lu = istgt_lu_find_target(uctl->istgt, iqn);
	if (lu == NULL) {
		istgt_uctl_snprintf(uctl, "ERR no target\n");
	error_return:
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}
	if (lun_i < 0 || lun_i >= lu->maxlun) {
		istgt_uctl_snprintf(uctl, "ERR no target\n");
		goto error_return;
	}
	llp = &lu->lun[lun_i];
	if (llp->type == ISTGT_LU_LUN_TYPE_NONE) {
		istgt_uctl_snprintf(uctl, "ERR no LUN\n");
		goto error_return;
	}

	/* reset lun */
	switch (lu->type) {
	case ISTGT_LU_TYPE_DISK:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_disk_reset(lu, lun_i);
		MTX_UNLOCK(&lu->mutex);
		break;
	case ISTGT_LU_TYPE_DVD:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_dvd_reset(lu, lun_i);
		MTX_UNLOCK(&lu->mutex);
		break;
	case ISTGT_LU_TYPE_TAPE:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_tape_reset(lu, lun_i);
		MTX_UNLOCK(&lu->mutex);
		break;
	case ISTGT_LU_TYPE_NONE:
	case ISTGT_LU_TYPE_PASS:
		rc = -1;
		break;
	default:
		rc = -1;
	}

	if (rc < 0) {
		istgt_uctl_snprintf(uctl, "ERR reset\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}

	/* logging event */
	ISTGT_NOTICELOG("Unit Reset %s lun%d from %s\n",
	    iqn, lun_i, uctl->caddr);

	/* reset succeeded */
	istgt_uctl_snprintf(uctl, "OK %s\n", uctl->cmd);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		return rc;
	}
	return UCTL_CMD_OK;
}

static int
istgt_uctl_cmd_info(UCTL_Ptr uctl)
{
	ISTGT_LU_Ptr lu;
	CONN_Ptr conn;
	SESS_Ptr sess;
	const char *delim = ARGS_DELIM;
	char *arg;
	char *iqn;
	int ncount;
	int rc;
	int i, j, k;

	arg = uctl->arg;
	iqn = strsepq(&arg, delim);

	if (arg != NULL) {
		istgt_uctl_snprintf(uctl, "ERR invalid parameters\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
		return UCTL_CMD_ERR;
	}

	ncount = 0;
	MTX_LOCK(&uctl->istgt->mutex);
	for (i = 0; i < MAX_LOGICAL_UNIT; i++) {
		lu = uctl->istgt->logical_unit[i];
		if (lu == NULL)
			continue;
		if (iqn != NULL && strcasecmp(iqn, lu->name) != 0)
			continue;

		istgt_lock_gconns();
		MTX_LOCK(&lu->mutex);
		for (j = 1; j < MAX_LU_TSIH; j++) {
			if (lu->tsih[j].initiator_port != NULL
				&& lu->tsih[j].tsih != 0) {
				conn = istgt_find_conn(lu->tsih[j].initiator_port,
				    lu->name, lu->tsih[j].tsih);
				if (conn == NULL || conn->sess == NULL)
					continue;

				sess = conn->sess;
				MTX_LOCK(&sess->mutex);
				for (k = 0; k < sess->connections; k++) {
					conn = sess->conns[k];
					if (conn == NULL)
						continue;

					istgt_uctl_snprintf(uctl, "%s Login from %s (%s) on %s LU%d"
					    " (%s:%s,%d), ISID=%"PRIx64", TSIH=%u,"
					    " CID=%u, HeaderDigest=%s, DataDigest=%s,"
					    " MaxConnections=%u,"
					    " FirstBurstLength=%u, MaxBurstLength=%u,"
					    " MaxRecvDataSegmentLength=%u,"
					    " InitialR2T=%s, ImmediateData=%s\n",
					    uctl->cmd,
					    conn->initiator_name,
					    conn->initiator_addr,
					    conn->target_name, lu->num,
					    conn->portal.host, conn->portal.port,
					    conn->portal.tag,
					    conn->sess->isid, conn->sess->tsih,
					    conn->cid,
					    (conn->header_digest ? "on" : "off"),
					    (conn->data_digest ? "on" : "off"),
					    conn->sess->MaxConnections,
					    conn->sess->FirstBurstLength,
					    conn->sess->MaxBurstLength,
					    conn->MaxRecvDataSegmentLength,
					    (conn->sess->initial_r2t ? "Yes" : "No"),
					    (conn->sess->immediate_data ? "Yes" : "No"));
					rc = istgt_uctl_writeline(uctl);
					if (rc != UCTL_CMD_OK) {
						MTX_UNLOCK(&sess->mutex);
						MTX_UNLOCK(&lu->mutex);
						istgt_unlock_gconns();
						MTX_UNLOCK(&uctl->istgt->mutex);
						return rc;
					}
					ncount++;
				}
				MTX_UNLOCK(&sess->mutex);
			}
		}
		MTX_UNLOCK(&lu->mutex);
		istgt_unlock_gconns();
	}
	MTX_UNLOCK(&uctl->istgt->mutex);
	if (ncount == 0) {
		istgt_uctl_snprintf(uctl, "%s no login\n", uctl->cmd);
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return rc;
		}
	}

	/* info succeeded */
	istgt_uctl_snprintf(uctl, "OK %s\n", uctl->cmd);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		return rc;
	}
	return UCTL_CMD_OK;
}


typedef struct istgt_uctl_cmd_table_t
{
	const char *name;
	int (*func) (UCTL_Ptr uctl);
} ISTGT_UCTL_CMD_TABLE;

static ISTGT_UCTL_CMD_TABLE istgt_uctl_cmd_table[] = 
{
	{ "AUTH",    istgt_uctl_cmd_auth },
	{ "QUIT",    istgt_uctl_cmd_quit },
	{ "NOOP",    istgt_uctl_cmd_noop },
	{ "VERSION", istgt_uctl_cmd_version },
	{ "LIST",    istgt_uctl_cmd_list },
	{ "UNLOAD",  istgt_uctl_cmd_unload },
	{ "LOAD",    istgt_uctl_cmd_load },
	{ "CHANGE",  istgt_uctl_cmd_change },
	{ "RESET",   istgt_uctl_cmd_reset },
	{ "INFO",    istgt_uctl_cmd_info },
	{ NULL,      NULL },
};

static int
istgt_uctl_cmd_execute(UCTL_Ptr uctl)
{
	int (*func) (UCTL_Ptr);
	const char *delim = ARGS_DELIM;
	char *arg;
	char *cmd;
	int rc;
	int i;

	arg = trim_string(uctl->recvbuf);
	cmd = strsepq(&arg, delim);
	uctl->arg = arg;
	uctl->cmd = strupr(cmd);

	func = NULL;
	for (i = 0; istgt_uctl_cmd_table[i].name != NULL; i++) {
		if (cmd[0] == istgt_uctl_cmd_table[i].name[0]
		    && strcmp(cmd, istgt_uctl_cmd_table[i].name) == 0) {
			func = istgt_uctl_cmd_table[i].func;
			break;
		}
	}
	if (func == NULL) {
		istgt_uctl_snprintf(uctl, "ERR unknown command\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return UCTL_CMD_DISCON;
		}
		return UCTL_CMD_ERR;
	}

	if (uctl->no_auth
	    && (strcasecmp(cmd, "AUTH") == 0)) {
		istgt_uctl_snprintf(uctl, "ERR auth not required\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return UCTL_CMD_DISCON;
		}
		return UCTL_CMD_ERR;
	}
	if (uctl->req_auth && uctl->authenticated == 0
	    && !(strcasecmp(cmd, "QUIT") == 0
		|| strcasecmp(cmd, "AUTH") == 0)) {
		istgt_uctl_snprintf(uctl, "ERR auth required\n");
		rc = istgt_uctl_writeline(uctl);
		if (rc != UCTL_CMD_OK) {
			return UCTL_CMD_DISCON;
		}
		return UCTL_CMD_ERR;
	}

	rc = func(uctl);
	return rc;
}

static void istgt_free_uctl(UCTL_Ptr uctl);

static void *
uctlworker(void *arg)
{
	UCTL_Ptr uctl = (UCTL_Ptr) arg;
	int rc;

	ISTGT_TRACELOG(ISTGT_TRACE_NET, "connect to %s:%s,%d\n",
	    uctl->portal.host, uctl->portal.port, uctl->portal.tag);

	istgt_uctl_snprintf(uctl, "iSCSI Target Controller version %s (%s)"
	    " on %s from %s\n",
	    ISTGT_VERSION, ISTGT_EXTRA_VERSION,
	    uctl->saddr, uctl->caddr);
	rc = istgt_uctl_writeline(uctl);
	if (rc != UCTL_CMD_OK) {
		ISTGT_ERRLOG("uctl_writeline() failed\n");
		return NULL;
	}

	while (1) {
		if (istgt_get_state(uctl->istgt) != ISTGT_STATE_RUNNING) {
			break;
		}

		/* read from socket */
		rc = istgt_uctl_readline(uctl);
		if (rc == UCTL_CMD_EOF) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "uctl_readline() EOF\n");
			break;
		}
		if (rc != UCTL_CMD_OK) {
			ISTGT_ERRLOG("uctl_readline() failed\n");
			break;
		}
		/* execute command */
		rc = istgt_uctl_cmd_execute(uctl);
		if (rc == UCTL_CMD_QUIT) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "receive QUIT\n");
			break;
		}
		if (rc == UCTL_CMD_DISCON) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "request disconnect\n");
			break;
		}
	}

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "exiting ctlworker\n");

	close(uctl->sock);
	uctl->sock = -1;
	istgt_free_uctl(uctl);
	return NULL;
}

static void
istgt_free_uctl(UCTL_Ptr uctl)
{
	if (uctl == NULL)
		return;
	xfree(uctl->mediadirectory);
	xfree(uctl->portal.label);
	xfree(uctl->portal.host);
	xfree(uctl->portal.port);
	xfree(uctl->auth.user);
	xfree(uctl->auth.secret);
	xfree(uctl->auth.muser);
	xfree(uctl->auth.msecret);
	xfree(uctl);
}

int
istgt_create_uctl(ISTGT_Ptr istgt, PORTAL_Ptr portal, int sock, struct sockaddr *sa, socklen_t salen __attribute__((__unused__)))
{
	char buf[MAX_TMPBUF];
	UCTL_Ptr uctl;
	int rc;
	int i;

	uctl = xmalloc(sizeof *uctl);
	memset(uctl, 0, sizeof *uctl);

	uctl->istgt = istgt;
	MTX_LOCK(&istgt->mutex);
	uctl->auth_group = istgt->uctl_auth_group;
	uctl->no_auth = istgt->no_uctl_auth;
	uctl->req_auth = istgt->req_uctl_auth;
	uctl->req_mutual = istgt->req_uctl_auth_mutual;
	uctl->mediadirectory = xstrdup(istgt->mediadirectory);
	MTX_UNLOCK(&istgt->mutex);

	uctl->portal.label = xstrdup(portal->label);
	uctl->portal.host = xstrdup(portal->host);
	uctl->portal.port = xstrdup(portal->port);
	uctl->portal.tag = portal->tag;
	uctl->portal.sock = -1;
	uctl->sock = sock;

	uctl->timeout = TIMEOUT_RW;
	uctl->auth.chap_phase = ISTGT_CHAP_PHASE_WAIT_A;
	uctl->auth.user = NULL;
	uctl->auth.secret = NULL;
	uctl->auth.muser = NULL;
	uctl->auth.msecret = NULL;
	uctl->authenticated = 0;

	uctl->recvtmpcnt = 0;
	uctl->recvtmpidx = 0;
	uctl->recvtmpsize = sizeof uctl->recvtmp;
	uctl->recvbufsize = sizeof uctl->recvbuf;
	uctl->sendbufsize = sizeof uctl->sendbuf;
	uctl->worksize = sizeof uctl->work;

	memset(uctl->caddr, 0, sizeof uctl->caddr);
	memset(uctl->saddr, 0, sizeof uctl->saddr);

	switch (sa->sa_family) {
	case AF_INET6:
		uctl->family = AF_INET6;
		rc = istgt_getaddr(sock, uctl->saddr, sizeof uctl->saddr,
		    uctl->caddr, sizeof uctl->caddr);
		if (rc < 0) {
			ISTGT_ERRLOG("istgt_getaddr() failed\n");
			goto error_return;
		}
		break;
	case AF_INET:
		uctl->family = AF_INET;
		rc = istgt_getaddr(sock, uctl->saddr, sizeof uctl->saddr,
		    uctl->caddr, sizeof uctl->caddr);
		if (rc < 0) {
			ISTGT_ERRLOG("istgt_getaddr() failed\n");
			goto error_return;
		}
		break;
	default:
		ISTGT_ERRLOG("unsupported family\n");
		goto error_return;
	}

	if (istgt->nuctl_netmasks != 0) {
		rc = -1;
		for (i = 0; i < istgt->nuctl_netmasks; i++) {
			rc = istgt_lu_allow_netmask(istgt->uctl_netmasks[i], uctl->caddr);
			if (rc > 0) {
				/* OK netmask */
				break;
			}
		}
		if (rc <= 0) {
			ISTGT_WARNLOG("UCTL access denied from %s to (%s:%s)\n",
			    uctl->caddr, uctl->portal.host, uctl->portal.port);
			goto error_return;
		}
	}

	printf("sock=%d, addr=%s, peer=%s\n",
	    sock, uctl->saddr,
	    uctl->caddr);

	/* wildcard? */
	if (strcasecmp(uctl->portal.host, "[::]") == 0
	    || strcasecmp(uctl->portal.host, "[*]") == 0) {
		if (uctl->family != AF_INET6) {
			ISTGT_ERRLOG("address family error\n");
			goto error_return;
		}
		snprintf(buf, sizeof buf, "[%s]", uctl->caddr);
		xfree(uctl->portal.host);
		uctl->portal.host = xstrdup(buf);
	} else if (strcasecmp(uctl->portal.host, "0.0.0.0") == 0
	    || strcasecmp(uctl->portal.host, "*") == 0) {
		if (uctl->family != AF_INET) {
			ISTGT_ERRLOG("address family error\n");
			goto error_return;
		}
		snprintf(buf, sizeof buf, "%s", uctl->caddr);
		xfree(uctl->portal.host);
		uctl->portal.host = xstrdup(buf);
	}

	/* set timeout msec. */
	rc = istgt_set_recvtimeout(uctl->sock, uctl->timeout * 1000);
	if (rc != 0) {
		ISTGT_ERRLOG("istgt_set_recvtimeo() failed\n");
		goto error_return;
	}
	rc = istgt_set_sendtimeout(uctl->sock, uctl->timeout * 1000);
	if (rc != 0) {
		ISTGT_ERRLOG("istgt_set_sendtimeo() failed\n");
		goto error_return;
	}

	/* create new thread */
#ifdef ISTGT_STACKSIZE
	rc = pthread_create(&uctl->thread, &istgt->attr, &uctlworker, (void *)uctl);
#else
	rc = pthread_create(&uctl->thread, NULL, &uctlworker, (void *)uctl);
#endif
	if (rc != 0) {
		ISTGT_ERRLOG("pthread_create() failed\n");
	error_return:
		xfree(uctl->portal.label);
		xfree(uctl->portal.host);
		xfree(uctl->portal.port);
		xfree(uctl);
		return -1;
	}
	rc = pthread_detach(uctl->thread);
	if (rc != 0) {
		ISTGT_ERRLOG("pthread_detach() failed\n");
		goto error_return;
	}
#ifdef HAVE_PTHREAD_SET_NAME_NP
	pthread_set_name_np(uctl->thread, "uctlthread");
#endif

	return 0;
}

int
istgt_uctl_init(ISTGT_Ptr istgt)
{
	CF_SECTION *sp;
	const char *val;
	const char *ag_tag;
	int alloc_len;
	int ag_tag_i;
	int masks;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_init_uctl_section\n");

	sp = istgt_find_cf_section(istgt->config, "UnitControl");
	if (sp == NULL) {
		ISTGT_ERRLOG("find_cf_section failed()\n");
		return -1;
	}

	val = istgt_get_val(sp, "Comment");
	if (val != NULL) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Comment %s\n", val);
	}

	for (i = 0; ; i++) {
		val = istgt_get_nval(sp, "Netmask", i);
		if (val == NULL)
			break;
	}
	masks = i;
	if (masks > MAX_NETMASK) {
		ISTGT_ERRLOG("%d > MAX_NETMASK\n", masks);
		return -1;
	}
	istgt->nuctl_netmasks = masks;
	alloc_len = sizeof (char *) * masks;
	istgt->uctl_netmasks = xmalloc(alloc_len);
	for (i = 0; i < masks; i++) {
		val = istgt_get_nval(sp, "Netmask", i);
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Netmask %s\n", val);
		istgt->uctl_netmasks[i] = xstrdup(val);
	}

	val = istgt_get_val(sp, "AuthMethod");
	if (val == NULL) {
		istgt->no_uctl_auth = 0;
		istgt->req_uctl_auth = 0;
	} else {
		istgt->no_uctl_auth = 0;
		for (i = 0; ; i++) {
			val = istgt_get_nmval(sp, "AuthMethod", 0, i);
			if (val == NULL)
				break;
			if (strcasecmp(val, "CHAP") == 0) {
				istgt->req_uctl_auth = 1;
			} else if (strcasecmp(val, "Mutual") == 0) {
				istgt->req_uctl_auth_mutual = 1;
			} else if (strcasecmp(val, "Auto") == 0) {
				istgt->req_uctl_auth = 0;
				istgt->req_uctl_auth_mutual = 0;
			} else if (strcasecmp(val, "None") == 0) {
				istgt->no_uctl_auth = 1;
				istgt->req_uctl_auth = 0;
				istgt->req_uctl_auth_mutual = 0;
			} else {
				ISTGT_ERRLOG("unknown auth\n");
				return -1;
			}
		}
	}
	if (istgt->no_uctl_auth == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AuthMethod None\n");
	} else if (istgt->req_uctl_auth == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AuthMethod Auto\n");
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AuthMethod %s %s\n",
		    istgt->req_uctl_auth ? "CHAP" : "",
		    istgt->req_uctl_auth_mutual ? "Mutual" : "");
	}

	val = istgt_get_val(sp, "AuthGroup");
	if (val == NULL) {
		istgt->uctl_auth_group = 0;
	} else {
		ag_tag = val;
		if (strcasecmp(ag_tag, "None") == 0) {
			ag_tag_i = 0;
		} else {
			if (strncasecmp(ag_tag, "AuthGroup",
				strlen("AuthGroup")) != 0
			    || sscanf(ag_tag, "%*[^0-9]%d", &ag_tag_i) != 1) {
				ISTGT_ERRLOG("auth group error\n");
				return -1;
			}
			if (ag_tag_i == 0) {
				ISTGT_ERRLOG("invalid auth group %d\n", ag_tag_i);
				return -1;
			}
		}
		istgt->uctl_auth_group = ag_tag_i;
	}
	if (istgt->uctl_auth_group == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AuthGroup None\n");
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AuthGroup AuthGroup%d\n",
		    istgt->uctl_auth_group);
	}

	return 0;
}

int
istgt_uctl_shutdown(ISTGT_Ptr istgt)
{
	int i;

	for (i = 0; i < istgt->nuctl_netmasks; i++) {
		xfree(istgt->uctl_netmasks[i]);
	}
	xfree(istgt->uctl_netmasks);
	return 0;
}
