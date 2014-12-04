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

#include <stdint.h>
#include <inttypes.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>

#include "istgt.h"
#include "istgt_ver.h"
#include "istgt_log.h"
#include "istgt_conf.h"
#include "istgt_sock.h"
#include "istgt_misc.h"
#include "istgt_crc32c.h"
#include "istgt_md5.h"
#include "istgt_iscsi.h"
#include "istgt_iscsi_param.h"
#include "istgt_lu.h"
#include "istgt_proto.h"
#include "istgt_scsi.h"
#include "istgt_queue.h"

#ifdef ISTGT_USE_KQUEUE
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#endif

#if !defined(__GNUC__)
#undef __attribute__
#define __attribute__(x)
#endif

/* according to RFC1982 */
#define SN32_CMPMAX (((uint32_t)1U) << (32 - 1))
#define SN32_LT(S1,S2) \
	(((uint32_t)(S1) != (uint32_t)(S2))				\
	    && (((uint32_t)(S1) < (uint32_t)(S2)			\
		    && ((uint32_t)(S2) - (uint32_t)(S1) < SN32_CMPMAX))	\
		|| ((uint32_t)(S1) > (uint32_t)(S2)			\
		    && ((uint32_t)(S1) - (uint32_t)(S2) > SN32_CMPMAX))))
#define SN32_GT(S1,S2) \
	(((uint32_t)(S1) != (uint32_t)(S2))				\
	    && (((uint32_t)(S1) < (uint32_t)(S2)			\
		    && ((uint32_t)(S2) - (uint32_t)(S1) > SN32_CMPMAX))	\
		|| ((uint32_t)(S1) > (uint32_t)(S2)			\
		    && ((uint32_t)(S1) - (uint32_t)(S2) < SN32_CMPMAX))))

#define POLLWAIT 5000
#define MAX_MCSREVWAIT (10 * 1000)
#define ISCMDQ 8

#define ISCSI_GETVAL(PARAMS,KEY) \
	istgt_iscsi_param_get_val((PARAMS),(KEY))
#define ISCSI_EQVAL(PARAMS,KEY,VAL) \
	istgt_iscsi_param_eq_val((PARAMS),(KEY),(VAL))
#define ISCSI_DELVAL(PARAMS,KEY) \
	istgt_iscsi_param_del((PARAMS),(KEY))
#define ISCSI_ADDVAL(PARAMS,KEY,VAL,LIST,TYPE) \
	istgt_iscsi_param_add((PARAMS),(KEY),(VAL), (LIST), (TYPE))

static int g_nconns;
static CONN_Ptr *g_conns;
static pthread_mutex_t g_conns_mutex;

static uint16_t g_last_tsih;
static pthread_mutex_t g_last_tsih_mutex;

static int istgt_add_transfer_task(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd);
static void istgt_clear_transfer_task(CONN_Ptr conn, uint32_t CmdSN);
static void istgt_clear_all_transfer_task(CONN_Ptr conn);
static int istgt_iscsi_send_r2t(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, int offset, int len, uint32_t transfer_tag, uint32_t *R2TSN);
static int istgt_append_sess(CONN_Ptr conn, uint64_t isid, uint16_t tsih, uint16_t cid);
static void istgt_remove_conn(CONN_Ptr conn);
static int istgt_iscsi_drop_all_conns(CONN_Ptr conn);
static int istgt_iscsi_drop_old_conns(CONN_Ptr conn);

/* Switch to use readv/writev (assume blocking) */
#define ISTGT_USE_IOVEC

#if defined (ISTGT_USE_IOVEC)
#include <sys/uio.h>
#endif

#if !defined (ISTGT_USE_IOVEC)
#if 0
#define ISTGT_USE_RECVBLOCK
#define ISTGT_USE_SENDBLOCK
#endif
#if 0
#define ISTGT_USE_RECVWAIT
#endif
static ssize_t
istgt_iscsi_read(CONN_Ptr conn, void *buf, size_t nbytes)
{
#ifndef ISTGT_USE_RECVBLOCK
	uint8_t padding[ISCSI_ALIGNMENT];
#endif
	uint8_t *cp;
	size_t pad_bytes;
	size_t total;
	ssize_t r;

	total = 0;
	cp = (uint8_t *) buf;
#ifdef ISTGT_USE_RECVBLOCK
	pad_bytes = ISCSI_ALIGN(nbytes) - nbytes;
	do {
#ifdef ISTGT_USE_RECVWAIT
		r = recv(conn->sock, cp + total, (nbytes + pad_bytes - total),
		    MSG_WAITALL);
#else
		r = recv(conn->sock, cp + total, (nbytes + pad_bytes - total),
		    0);
#endif
		if (r < 0) {
			/* error */
			ISTGT_TRACELOG(ISTGT_TRACE_NET,
			    "Read error (errno=%d)\n", errno);
			return r;
		}
		if (r == 0) {
			/* EOF */
			ISTGT_TRACELOG(ISTGT_TRACE_NET, "Read EOF\n");
			return r;
		}
		total += r;
	} while (total < nbytes);
	if (total != (nbytes + pad_bytes)) {
		/* incomplete bytes */
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "Read %zd/%zd+%zd bytes\n",
		    total, nbytes, pad_bytes);
		if (total > nbytes) {
			total = nbytes;
		}
		return total;
	}

	if (pad_bytes != 0) {
		/* complete padding */
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "Read %zd bytes (padding %zd)\n",
		    nbytes, pad_bytes);
	} else {
		/* just aligned */
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "Read %zd bytes (no padding)\n",
		    nbytes);
	}
#else /* !ISTGT_USE_RECVBLOCK */
	do {
		r = istgt_read_socket(conn->sock, cp + total, (nbytes - total),
		    conn->timeout);
		if (r < 0) {
			/* error */
			ISTGT_TRACELOG(ISTGT_TRACE_NET,
			    "Read error (errno=%d)\n", errno);
			return r;
		}
		if (r == 0) {
			/* EOF */
			ISTGT_TRACELOG(ISTGT_TRACE_NET, "Read EOF\n");
			return r;
		}
		total += r;
	} while (total < nbytes);
#if 0
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "RAW DATA", cp, total);
#endif

	if (total != nbytes) {
		/* incomplete bytes */
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "Read %zd/%zd bytes\n",
		    total, nbytes);
		return total;
	}

	/* need padding? */
	pad_bytes = ISCSI_ALIGN(nbytes) - nbytes;
	if (pad_bytes != 0) {
		total = 0;
		cp = (uint8_t *) &padding[0];
		do {
			r = istgt_read_socket(conn->sock, cp + total,
			    (pad_bytes - total), conn->timeout);
			if (r < 0) {
				/* error */
				ISTGT_TRACELOG(ISTGT_TRACE_NET,
				    "Read %zd bytes (padding error) (errno=%d)\n",
				    nbytes, errno);
				return nbytes;
			}
			if (r == 0) {
				/* EOF */
				ISTGT_TRACELOG(ISTGT_TRACE_NET,
				    "Read %zd bytes (padding EOF)\n",
				    nbytes);
				return nbytes;
			}
			total += r;
		} while (total < pad_bytes);

		if (total != pad_bytes) {
			/* incomplete padding */
			ISTGT_TRACELOG(ISTGT_TRACE_NET,
			    "Read %zd bytes (padding %zd)\n",
			    nbytes, total);
			return nbytes;
		}
		/* complete padding */
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "Read %zd bytes (padding %zd)\n",
		    nbytes, pad_bytes);
		return nbytes;
	}

	/* just aligned */
	ISTGT_TRACELOG(ISTGT_TRACE_NET, "Read %zd bytes (no padding)\n",
	    nbytes);
#endif /* ISTGT_USE_RECVBLOCK */
	return nbytes;
}

static ssize_t
istgt_iscsi_write(CONN_Ptr conn, const void *buf, size_t nbytes)
{
	uint8_t padding[ISCSI_ALIGNMENT];
	const uint8_t *cp;
	size_t pad_bytes;
	size_t total;
	ssize_t r;

	total = 0;
	cp = (const uint8_t *) buf;
#ifdef ISTGT_USE_SENDBLOCK
	pad_bytes = ISCSI_ALIGN(nbytes) - nbytes;
	do {
		r = send(conn->wsock, cp, nbytes, 0);
		if (r < 0) {
			/* error */
			ISTGT_TRACELOG(ISTGT_TRACE_NET,
			    "Write error (errno=%d)\n", errno);
			return r;
		}
		total += r;
	} while (total < nbytes);

	if (total != nbytes) {
		/* incomplete bytes */
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "Write %zd/%zd bytes\n",
		    total, nbytes);
		return total;
	}

	if (pad_bytes != 0) {
		memset(padding, 0, sizeof padding);
		total = 0;
		cp = (const uint8_t *) &padding[0];
		do {
			r = send(conn->wsock, cp, pad_bytes, 0);
			if (r < 0) {
				/* error */
				ISTGT_TRACELOG(ISTGT_TRACE_NET,
				    "Write %zd bytes (padding error) (errno=%d)\n",
				    nbytes, errno);
				return nbytes;
			}
			total += r;
		} while (total < pad_bytes);

		if (total != pad_bytes) {
			/* incomplete padding */
			ISTGT_TRACELOG(ISTGT_TRACE_NET,
			    "Write %zd bytes (padding %zd)\n",
			    nbytes, total);
			return nbytes;
		}

		/* complete padding */
		ISTGT_TRACELOG(ISTGT_TRACE_NET,
		    "Write %zd bytes (padding %zd)\n",
		    nbytes, pad_bytes);
	} else {
		/* just aligned */
		ISTGT_TRACELOG(ISTGT_TRACE_NET,
		    "Write %zd bytes (no padding)\n",
		    nbytes);
	}
#else /* !ISTGT_USE_SENDBLOCK */
	do {
		r = istgt_write_socket(conn->wsock, cp + total,
		    (nbytes - total), conn->timeout);
		if (r < 0) {
			/* error */
			ISTGT_TRACELOG(ISTGT_TRACE_NET,
			    "Write error (errno=%d)\n", errno);
			return r;
		}
		total += r;
	} while (total < nbytes);

	if (total != nbytes) {
		/* incomplete bytes */
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "Write %zd/%zd bytes\n",
		    total, nbytes);
		return r;
	}

	/* need padding? */
	pad_bytes = ISCSI_ALIGN(nbytes) - nbytes;
	if (pad_bytes != 0) {
		memset(padding, 0, sizeof padding);
		total = 0;
		cp = (const uint8_t *) &padding[0];
		do {
			r = istgt_write_socket(conn->wsock, cp + total,
			    (pad_bytes - total), conn->timeout);
			if (r < 0) {
				/* error */
				ISTGT_TRACELOG(ISTGT_TRACE_NET,
				    "Write %zd bytes (padding error) (errno=%d)\n",
				    nbytes, errno);
				return nbytes;
			}
			total += r;
		} while (total < pad_bytes);

		if (total != pad_bytes) {
			/* incomplete padding */
			ISTGT_TRACELOG(ISTGT_TRACE_NET,
			    "Write %zd bytes (padding %zd)\n",
			    nbytes, total);
			return nbytes;
		}
		/* complete padding */
		ISTGT_TRACELOG(ISTGT_TRACE_NET,
		    "Write %zd bytes (padding %zd)\n",
		    nbytes, pad_bytes);
		return nbytes;
	}

	/* just aligned */
	ISTGT_TRACELOG(ISTGT_TRACE_NET, "Write %zd bytes (no padding)\n",
	    nbytes);
#endif /* ISTGT_USE_SENDBLOCK */
	return nbytes;
}
#endif /* !defined (ISTGT_USE_IOVEC) */

#define MATCH_DIGEST_WORD(BUF, CRC32C) \
	(    ((((uint32_t) *((uint8_t *)(BUF)+0)) << 0)		\
	    | (((uint32_t) *((uint8_t *)(BUF)+1)) << 8)		\
	    | (((uint32_t) *((uint8_t *)(BUF)+2)) << 16)	\
	    | (((uint32_t) *((uint8_t *)(BUF)+3)) << 24))	\
	    == (CRC32C))

#define MAKE_DIGEST_WORD(BUF, CRC32C) \
	(   ((*((uint8_t *)(BUF)+0)) = (uint8_t)((uint32_t)(CRC32C) >> 0)), \
	    ((*((uint8_t *)(BUF)+1)) = (uint8_t)((uint32_t)(CRC32C) >> 8)), \
	    ((*((uint8_t *)(BUF)+2)) = (uint8_t)((uint32_t)(CRC32C) >> 16)), \
	    ((*((uint8_t *)(BUF)+3)) = (uint8_t)((uint32_t)(CRC32C) >> 24)))

#if 0
static int
istgt_match_digest_word(const uint8_t *buf, uint32_t crc32c)
{
	uint32_t l;

	l = (buf[0] & 0xffU) << 0;
	l |= (buf[1] & 0xffU) << 8;
	l |= (buf[2] & 0xffU) << 16;
	l |= (buf[3] & 0xffU) << 24;
	return (l == crc32c);
}

static uint8_t *
istgt_make_digest_word(uint8_t *buf, size_t len, uint32_t crc32c)
{
	if (len < ISCSI_DIGEST_LEN)
		return NULL;

	buf[0] = (crc32c >> 0) & 0xffU;
	buf[1] = (crc32c >> 8) & 0xffU;
	buf[2] = (crc32c >> 16) & 0xffU;
	buf[3] = (crc32c >> 24) & 0xffU;
	return buf;
}
#endif

#if !defined (ISTGT_USE_IOVEC)
static int
istgt_iscsi_read_pdu(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	uint32_t crc32c;
	int total_ahs_len;
	int data_len;
	int segment_len;
	int total;
	int rc;

	pdu->ahs = NULL;
	pdu->total_ahs_len = 0;
	pdu->data = NULL;
	pdu->data_segment_len = 0;
	total = 0;

	/* BHS */
	ISTGT_TRACELOG(ISTGT_TRACE_NET, "BHS read %d\n",
	    ISCSI_BHS_LEN);
	rc = istgt_iscsi_read(conn, &pdu->bhs, ISCSI_BHS_LEN);
	if (rc < 0) {
		if (errno == ECONNRESET) {
			ISTGT_WARNLOG("Connection reset by peer (%s)\n",
			    conn->initiator_name);
			conn->state = CONN_STATE_EXITING;
		} else if (errno == ETIMEDOUT) {
			ISTGT_WARNLOG("Operation timed out (%s)\n",
			    conn->initiator_name);
			conn->state = CONN_STATE_EXITING;
		} else {
			ISTGT_ERRLOG("iscsi_read() failed (errno=%d,%s)\n",
			    errno, conn->initiator_name);
		}
		return -1;
	}
	if (rc == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "iscsi_read() EOF (%s)\n",
		    conn->initiator_name);
		conn->state = CONN_STATE_EXITING;
		return -1;
	}
	if (rc != ISCSI_BHS_LEN) {
		ISTGT_ERRLOG("invalid BHS length (%d)\n", rc);
		return -1;
	}
	total += ISCSI_BHS_LEN;

	/* AHS */
	total_ahs_len = DGET8(&pdu->bhs.total_ahs_len);
	if (total_ahs_len != 0) {
		pdu->ahs = xmalloc(ISCSI_ALIGN((4 * total_ahs_len)));
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "AHS read %d\n",
		    (4 * total_ahs_len));
		rc = istgt_iscsi_read(conn, pdu->ahs, (4 * total_ahs_len));
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_read() failed (errno=%d,%s)\n",
			    errno, conn->initiator_name);
			return -1;
		}
		if (rc == 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_NET, "iscsi_read() EOF\n");
			conn->state = CONN_STATE_EXITING;
			return -1;
		}
		if (rc != (4 * total_ahs_len)) {
			ISTGT_ERRLOG("invalid AHS length (%d)\n", rc);
			return -1;
		}
		pdu->total_ahs_len = total_ahs_len;
		total += (4 * total_ahs_len);
	} else {
		pdu->ahs = NULL;
		pdu->total_ahs_len = 0;
	}

	/* Header Digest */
	if (conn->header_digest) {
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "HeaderDigest read %d\n",
		    ISCSI_DIGEST_LEN);
		rc = istgt_iscsi_read(conn, pdu->header_digest,
		    ISCSI_DIGEST_LEN);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_read() failed (errno=%d,%s)\n",
			    errno, conn->initiator_name);
			{
				int opcode = BGET8W(&pdu->bhs.opcode, 5, 6);
				ISTGT_ERRLOG("Header Digest read error (opcode = 0x%x)\n",
				    opcode);
			}
			return -1;
		}
		if (rc == 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_NET, "iscsi_read() EOF\n");
			conn->state = CONN_STATE_EXITING;
			return -1;
		}
		if (rc != ISCSI_DIGEST_LEN) {
			ISTGT_ERRLOG("invalid Header Digest length (%d)\n",
			    rc);
			return -1;
		}
		total += ISCSI_DIGEST_LEN;
	}

	/* Data Segment */
	data_len = DGET24(&pdu->bhs.data_segment_len[0]);
	if (data_len != 0) {
		if (conn->sess == NULL) {
			segment_len = DEFAULT_FIRSTBURSTLENGTH;
		} else {
			segment_len = conn->MaxRecvDataSegmentLength;
		}
		if (data_len > segment_len) {
			ISTGT_ERRLOG("Data(%d) > Segment(%d)\n",
			    data_len, segment_len);
			return -1;
		}
		if (ISCSI_ALIGN(data_len) <= ISTGT_SHORTDATASIZE) {
			pdu->data = pdu->shortdata;
		} else {
			pdu->data = xmalloc(ISCSI_ALIGN(segment_len));
		}
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "Data read %d\n",
		    data_len);
		rc = istgt_iscsi_read(conn, pdu->data, data_len);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_read() failed (%d,errno=%d,%s)\n",
			    rc, errno, conn->initiator_name);
			return -1;
		}
		if (rc == 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_NET, "iscsi_read() EOF\n");
			conn->state = CONN_STATE_EXITING;
			return -1;
		}
		if (rc != data_len) {
			ISTGT_ERRLOG("invalid Data Segment length (%d)\n", rc);
			return -1;
		}
		pdu->data_segment_len = data_len;
		total += data_len;

#if 0
		if (data_len > 512) {
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "DataSegment",
			    pdu->data, 512);
		} else {
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "DataSegment",
			    pdu->data, data_len);
		}
#endif
	} else {
		pdu->data = NULL;
		pdu->data_segment_len = 0;
	}

	/* Data Digest */
	if (conn->data_digest && data_len != 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "DataDigest read %d\n",
		    ISCSI_DIGEST_LEN);
		rc = istgt_iscsi_read(conn, pdu->data_digest,
		    ISCSI_DIGEST_LEN);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_read() failed (errno=%d,%s)\n",
			    errno, conn->initiator_name);
			return -1;
		}
		if (rc == 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_NET, "iscsi_read() EOF\n");
			conn->state = CONN_STATE_EXITING;
			return -1;
		}
		if (rc != ISCSI_DIGEST_LEN) {
			ISTGT_ERRLOG("invalid Data Digest length (%d)\n", rc);
			return -1;
		}
		total += ISCSI_DIGEST_LEN;
	}

	/* check digest */
	if (conn->header_digest) {
		if (total_ahs_len == 0) {
			crc32c = istgt_crc32c((uint8_t *) &pdu->bhs,
			    ISCSI_BHS_LEN);
		} else {
			int upd_total = 0;
			crc32c = ISTGT_CRC32C_INITIAL;
			crc32c = istgt_update_crc32c((uint8_t *) &pdu->bhs,
			    ISCSI_BHS_LEN, crc32c);
			upd_total += ISCSI_BHS_LEN;
			crc32c = istgt_update_crc32c((uint8_t *) pdu->ahs,
			    (4 * total_ahs_len), crc32c);
			upd_total += (4 * total_ahs_len);
			crc32c = istgt_fixup_crc32c(upd_total, crc32c);
			crc32c = crc32c ^ ISTGT_CRC32C_XOR;
		}
		rc = MATCH_DIGEST_WORD(pdu->header_digest, crc32c);
		if (rc == 0) {
			ISTGT_ERRLOG("header digest error (%s)\n", conn->initiator_name);
			return -1;
		}
	}
	if (conn->data_digest && data_len != 0) {
		crc32c = istgt_crc32c(pdu->data, data_len);
		rc = MATCH_DIGEST_WORD(pdu->data_digest, crc32c);
		if (rc == 0) {
			ISTGT_ERRLOG("data digest error (%s)\n", conn->initiator_name);
			return -1;
		}
	}

	return total;
}
#else /* defined (ISTGT_USE_IOVEC) */
static int
istgt_iscsi_read_pdu(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	struct iovec iovec[4]; /* AHS+HD+DATA+DD */
	uint32_t crc32c;
	time_t start, now;
	int nbytes;
	int total_ahs_len;
	int data_len;
	int segment_len;
	int total;
	int rc;
	int i;

	pdu->ahs = NULL;
	pdu->total_ahs_len = 0;
	pdu->data = NULL;
	pdu->data_segment_len = 0;
	total = 0;

	/* BHS (require for all PDU) */
	ISTGT_TRACELOG(ISTGT_TRACE_NET, "BHS read %d\n",
	    ISCSI_BHS_LEN);
	errno = 0;
	start = time(NULL);
	rc = recv(conn->sock, &pdu->bhs, ISCSI_BHS_LEN, MSG_WAITALL);
	if (rc < 0) {
		now = time(NULL);
		if (errno == ECONNRESET) {
			ISTGT_WARNLOG("Connection reset by peer (%s,time=%d)\n",
			    conn->initiator_name, istgt_difftime(now, start));
			conn->state = CONN_STATE_EXITING;
		} else if (errno == ETIMEDOUT) {
			ISTGT_WARNLOG("Operation timed out (%s,time=%d)\n",
			    conn->initiator_name, istgt_difftime(now, start));
			conn->state = CONN_STATE_EXITING;
		} else {
			ISTGT_ERRLOG("iscsi_read() failed (errno=%d,%s,time=%d)\n",
			    errno, conn->initiator_name, istgt_difftime(now, start));
		}
		return -1;
	}
	if (rc == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "recv() EOF (%s)\n",
		    conn->initiator_name);
		conn->state = CONN_STATE_EXITING;
		return -1;
	}
	if (rc != ISCSI_BHS_LEN) {
		ISTGT_ERRLOG("invalid BHS length (%d,%s)\n", rc, conn->initiator_name);
		return -1;
	}
	total += ISCSI_BHS_LEN;

	/* AHS */
	total_ahs_len = DGET8(&pdu->bhs.total_ahs_len);
	if (total_ahs_len != 0) {
		pdu->ahs = xmalloc(ISCSI_ALIGN((4 * total_ahs_len)));
		pdu->total_ahs_len = total_ahs_len;
		total += (4 * total_ahs_len);
	} else {
		pdu->ahs = NULL;
		pdu->total_ahs_len = 0;
	}
	iovec[0].iov_base = pdu->ahs;
	iovec[0].iov_len = 4 * pdu->total_ahs_len;

	/* Header Digest */
	iovec[1].iov_base = pdu->header_digest;
	if (conn->header_digest) {
		iovec[1].iov_len = ISCSI_DIGEST_LEN;
		total += ISCSI_DIGEST_LEN;
	} else {
		iovec[1].iov_len = 0;
	}

	/* Data Segment */
	data_len = DGET24(&pdu->bhs.data_segment_len[0]);
	if (data_len != 0) {
		if (conn->sess == NULL) {
			segment_len = DEFAULT_FIRSTBURSTLENGTH;
		} else {
			segment_len = conn->MaxRecvDataSegmentLength;
		}
		if (data_len > segment_len) {
			ISTGT_ERRLOG("Data(%d) > Segment(%d)\n",
			    data_len, segment_len);
			return -1;
		}
		if (ISCSI_ALIGN(data_len) <= ISTGT_SHORTDATASIZE) {
			pdu->data = pdu->shortdata;
		} else {
			pdu->data = xmalloc(ISCSI_ALIGN(segment_len));
		}
		pdu->data_segment_len = data_len;
		total += ISCSI_ALIGN(data_len);
	} else {
		pdu->data = NULL;
		pdu->data_segment_len = 0;
	}
	iovec[2].iov_base = pdu->data;
	iovec[2].iov_len = ISCSI_ALIGN(pdu->data_segment_len);

	/* Data Digest */
	iovec[3].iov_base = pdu->data_digest;
	if (conn->data_digest && data_len != 0) {
		iovec[3].iov_len = ISCSI_DIGEST_LEN;
		total += ISCSI_DIGEST_LEN;
	} else {
		iovec[3].iov_len = 0;
	}

	/* read all bytes to iovec */
	nbytes = total - ISCSI_BHS_LEN;
	ISTGT_TRACELOG(ISTGT_TRACE_NET, "PDU read %d\n", nbytes);
	errno = 0;
	start = time(NULL);
	while (nbytes > 0) {
		rc = readv(conn->sock, &iovec[0], 4);
		if (rc < 0) {
			now = time(NULL);
			ISTGT_ERRLOG("readv() failed (%d,errno=%d,%s,time=%d)\n",
			    rc, errno, conn->initiator_name, istgt_difftime(now, start));
			return -1;
		}
		if (rc == 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_NET, "readv() EOF (%s)\n",
			    conn->initiator_name);
			conn->state = CONN_STATE_EXITING;
			return -1;
		}
		nbytes -= rc;
		if (nbytes == 0)
			break;
		/* adjust iovec length */
		for (i = 0; i < 4; i++) {
			if (iovec[i].iov_len != 0 && iovec[i].iov_len > (size_t)rc) {
				iovec[i].iov_base
					= (void *) (((uintptr_t)iovec[i].iov_base) + rc);
				iovec[i].iov_len -= rc;
				break;
			} else {
				rc -= iovec[i].iov_len;
				iovec[i].iov_len = 0;
			}
		}
	}

	/* check digest */
	if (conn->header_digest) {
		if (total_ahs_len == 0) {
			crc32c = istgt_crc32c((uint8_t *) &pdu->bhs,
			    ISCSI_BHS_LEN);
		} else {
			int upd_total = 0;
			crc32c = ISTGT_CRC32C_INITIAL;
			crc32c = istgt_update_crc32c((uint8_t *) &pdu->bhs,
			    ISCSI_BHS_LEN, crc32c);
			upd_total += ISCSI_BHS_LEN;
			crc32c = istgt_update_crc32c((uint8_t *) pdu->ahs,
			    (4 * total_ahs_len), crc32c);
			upd_total += (4 * total_ahs_len);
			crc32c = istgt_fixup_crc32c(upd_total, crc32c);
			crc32c = crc32c ^ ISTGT_CRC32C_XOR;
		}
		rc = MATCH_DIGEST_WORD(pdu->header_digest, crc32c);
		if (rc == 0) {
			ISTGT_ERRLOG("header digest error (%s)\n", conn->initiator_name);
			return -1;
		}
	}
	if (conn->data_digest && data_len != 0) {
		crc32c = istgt_crc32c(pdu->data, ISCSI_ALIGN(data_len));
		rc = MATCH_DIGEST_WORD(pdu->data_digest, crc32c);
		if (rc == 0) {
			ISTGT_ERRLOG("data digest error (%s)\n", conn->initiator_name);
			return -1;
		}
	}

	return total;
}
#endif /* defined (ISTGT_USE_IOVEC) */

static int istgt_iscsi_write_pdu_internal(CONN_Ptr conn, ISCSI_PDU_Ptr pdu);
static int istgt_iscsi_write_pdu_queue(CONN_Ptr conn, ISCSI_PDU_Ptr pdu, int req_type, int I_bit);

static int istgt_update_pdu(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	uint8_t *rsp;
	uint32_t task_tag;
	int opcode;
	int I_bit;

	I_bit = lu_cmd->I_bit;
	rsp = (uint8_t *) &lu_cmd->pdu->bhs;
	opcode = BGET8W(&rsp[0], 5, 6);
	task_tag = DGET32(&rsp[16]);
	if ((opcode == ISCSI_OP_R2T)
	    || (opcode == ISCSI_OP_NOPIN && task_tag == 0xffffffffU)) {
		SESS_MTX_LOCK(conn);
		DSET32(&rsp[24], conn->StatSN);
		DSET32(&rsp[28], conn->sess->ExpCmdSN);
		DSET32(&rsp[32], conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);
	} else if ((opcode == ISCSI_OP_TASK_RSP)
	    || (opcode == ISCSI_OP_NOPIN && task_tag != 0xffffffffU)) {
		SESS_MTX_LOCK(conn);
		DSET32(&rsp[24], conn->StatSN);
		conn->StatSN++;
		if (I_bit == 0) {
			conn->sess->ExpCmdSN++;
			conn->sess->MaxCmdSN++;
		}
		DSET32(&rsp[28], conn->sess->ExpCmdSN);
		DSET32(&rsp[32], conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);
	}
	return 0;
}

static int
istgt_iscsi_write_pdu(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	int rc;

	if (conn->use_sender == 0) {
		rc = istgt_iscsi_write_pdu_internal(conn, pdu);
	} else {
		rc = istgt_iscsi_write_pdu_queue(conn, pdu, ISTGT_LU_TASK_REQPDU, 0);
	}
	return rc;
}

static int
istgt_iscsi_write_pdu_upd(CONN_Ptr conn, ISCSI_PDU_Ptr pdu, int I_bit)
{
	int rc;

	if (conn->use_sender == 0) {
		rc = istgt_iscsi_write_pdu_internal(conn, pdu);
	} else {
		rc = istgt_iscsi_write_pdu_queue(conn, pdu, ISTGT_LU_TASK_REQUPDPDU, I_bit);
	}
	return rc;
}

static int
istgt_iscsi_write_pdu_queue(CONN_Ptr conn, ISCSI_PDU_Ptr pdu, int req_type, int I_bit)
{
	int rc;

	if (conn->use_sender == 0) {
		rc = istgt_iscsi_write_pdu_internal(conn, pdu);
	} else {
		ISTGT_LU_TASK_Ptr lu_task;
		ISCSI_PDU_Ptr src_pdu, dst_pdu;
		uint8_t *cp;
		int total_ahs_len;
		int data_len;
		int alloc_len;
		int total;

		cp = (uint8_t *) &pdu->bhs;
		total_ahs_len = DGET8(&cp[4]);
		data_len = DGET24(&cp[5]);
		total = 0;

#if 0
		ISTGT_LOG("W:PDU OP=%x, tag=%x, ExpCmdSN=%u, MaxCmdSN=%u\n",
		    DGET8(&cp[0]), DGET32(&cp[32]), DGET32(&cp[28]), DGET32(&cp[32]));
#endif
		/* allocate for queued PDU */
		alloc_len = ISCSI_ALIGN(sizeof *lu_task);
		alloc_len += ISCSI_ALIGN(sizeof *lu_task->lu_cmd.pdu);
		alloc_len += ISCSI_ALIGN(4 * total_ahs_len);
		alloc_len += ISCSI_ALIGN(data_len);
		lu_task = xmalloc(alloc_len);
		memset(lu_task, 0, alloc_len);
		lu_task->lu_cmd.pdu = (ISCSI_PDU_Ptr) ((uintptr_t)lu_task
		    + ISCSI_ALIGN(sizeof *lu_task));
		lu_task->lu_cmd.pdu->ahs = (ISCSI_AHS *) ((uintptr_t)lu_task->lu_cmd.pdu
		    + ISCSI_ALIGN(sizeof *lu_task->lu_cmd.pdu));
		lu_task->lu_cmd.pdu->data = (uint8_t *) ((uintptr_t)lu_task->lu_cmd.pdu->ahs
		    + ISCSI_ALIGN(4 * total_ahs_len));

		/* specify type and self conn */
		//lu_task->type = ISTGT_LU_TASK_REQPDU;
		lu_task->type = req_type;
		lu_task->conn = conn;

		/* extra flags */
		lu_task->lu_cmd.I_bit = I_bit;

		/* copy PDU structure */
		src_pdu = pdu;
		dst_pdu = lu_task->lu_cmd.pdu;
		memcpy(&dst_pdu->bhs, &src_pdu->bhs, ISCSI_BHS_LEN);
		total += ISCSI_BHS_LEN;
		if (total_ahs_len != 0) {
			memcpy(dst_pdu->ahs, src_pdu->ahs, 4 * total_ahs_len);
			total += (4 * total_ahs_len);
		} else {
			dst_pdu->ahs = NULL;
		}
		if (conn->header_digest) {
			memcpy(dst_pdu->header_digest, src_pdu->header_digest,
			    ISCSI_DIGEST_LEN);
			total += ISCSI_DIGEST_LEN;
		}
		if (data_len != 0) {
			memcpy(dst_pdu->data, src_pdu->data, data_len);
			total += data_len;
		} else {
			dst_pdu->data = NULL;
		}
		if (conn->data_digest && data_len != 0) {
			memcpy(dst_pdu->data_digest, src_pdu->data_digest,
			    ISCSI_DIGEST_LEN);
			total += ISCSI_DIGEST_LEN;
		}

		/* insert to queue */
		MTX_LOCK(&conn->result_queue_mutex);
		rc = istgt_queue_enqueue(&conn->result_queue, lu_task);
		if (rc != 0) {
			MTX_UNLOCK(&conn->result_queue_mutex);
			ISTGT_ERRLOG("queue_enqueue() failed\n");
			return -1;
		}
		/* notify to thread */
		rc = pthread_cond_broadcast(&conn->result_queue_cond);
		MTX_UNLOCK(&conn->result_queue_mutex);
		if (rc != 0) {
			ISTGT_ERRLOG("cond_broadcast() failed\n");
			return -1;
		}

		/* total bytes should be sent in queue */
		rc = total;
	}
	return rc;
}

#if !defined (ISTGT_USE_IOVEC)
static int
istgt_iscsi_write_pdu_internal(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	uint8_t *cp;
	uint32_t crc32c;
	int enable_digest;
	int opcode;
	int total_ahs_len;
	int data_len;
	int total;
	int rc;

	cp = (uint8_t *) &pdu->bhs;
	total_ahs_len = DGET8(&cp[4]);
	data_len = DGET24(&cp[5]);
	total = 0;

	enable_digest = 1;
	opcode = BGET8W(&cp[0], 5, 6);
	if (opcode == ISCSI_OP_LOGIN_RSP) {
		/* this PDU should be sent without digest */
		enable_digest = 0;
	}

#define ISTGT_USE_SHORTPDU_WRITE
#ifdef ISTGT_USE_SHORTPDU_WRITE
	/* if short size, BHS + AHS + HD + DATA + DD */
	if (total_ahs_len == 0
		&& data_len <= ISTGT_SHORTDATASIZE) {
		uint8_t *spp = conn->shortpdu;
		int pad_len = 0;
		memcpy(spp, (uint8_t *) &pdu->bhs, ISCSI_BHS_LEN);
		total = ISCSI_BHS_LEN;
		if (enable_digest && conn->header_digest) {
			crc32c = istgt_crc32c(spp, total);
			MAKE_DIGEST_WORD(spp + total, crc32c);
			total += ISCSI_DIGEST_LEN;
		}
		memcpy(spp + total, pdu->data, data_len);
		total += data_len;
		if ((data_len % ISCSI_ALIGNMENT) != 0) {
			memset(spp + total, 0,
			    ISCSI_ALIGN(data_len) - data_len);
			total += ISCSI_ALIGN(data_len) - data_len;
			pad_len += ISCSI_ALIGN(data_len) - data_len;
		}
		if (enable_digest && conn->data_digest && data_len != 0) {
			crc32c = istgt_crc32c(pdu->data, data_len);
			MAKE_DIGEST_WORD(spp + total, crc32c);
			total += ISCSI_DIGEST_LEN;
		}

		ISTGT_TRACELOG(ISTGT_TRACE_NET, "PDU write %d\n",
		    total);
		rc = istgt_iscsi_write(conn, spp, total);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_write() failed (errno=%d,%s)\n",
			    errno, conn->initiator_name);
			return -1;
		}
		if (rc != total) {
			ISTGT_ERRLOG("incomplete PDU length (%d)\n", rc);
			return -1;
		}
		return total - pad_len;
	}
#endif /* ISTGT_USE_SHORTPDU_WRITE */

	/* BHS */
	ISTGT_TRACELOG(ISTGT_TRACE_NET, "BHS write %d\n",
	    ISCSI_BHS_LEN);
	rc = istgt_iscsi_write(conn, &pdu->bhs, ISCSI_BHS_LEN);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_write() failed (errno=%d,%s)\n", errno,
		    conn->initiator_name);
		return -1;
	}
	if (rc != ISCSI_BHS_LEN) {
		ISTGT_ERRLOG("incomplete BHS length (%d)\n", rc);
		return -1;
	}
	total += ISCSI_BHS_LEN;

	/* AHS */
	if (total_ahs_len != 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "AHS write %d\n",
		    (4 * total_ahs_len));
		rc = istgt_iscsi_write(conn, pdu->ahs, (4 * total_ahs_len));
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_write() failed (errno=%d,%s)\n",
			    errno, conn->initiator_name);
			return -1;
		}
		if (rc != (4 * total_ahs_len)) {
			ISTGT_ERRLOG("incomplete AHS length (%d)\n", rc);
			return -1;
		}
		total += (4 * total_ahs_len);
	}

	/* Header Digest */
	if (enable_digest && conn->header_digest) {
		if (total_ahs_len == 0) {
			crc32c = istgt_crc32c((uint8_t *) &pdu->bhs,
			    ISCSI_BHS_LEN);
		} else {
			int upd_total = 0;
			crc32c = ISTGT_CRC32C_INITIAL;
			crc32c = istgt_update_crc32c((uint8_t *) &pdu->bhs,
			    ISCSI_BHS_LEN, crc32c);
			upd_total += ISCSI_BHS_LEN;
			crc32c = istgt_update_crc32c((uint8_t *) pdu->ahs,
			    (4 * total_ahs_len), crc32c);
			upd_total += (4 * total_ahs_len);
			crc32c = istgt_fixup_crc32c(upd_total, crc32c);
			crc32c = crc32c ^ ISTGT_CRC32C_XOR;
		}
		MAKE_DIGEST_WORD(pdu->header_digest, crc32c);

		ISTGT_TRACELOG(ISTGT_TRACE_NET, "HeaderDigest write %d\n",
		    ISCSI_DIGEST_LEN);
		rc = istgt_iscsi_write(conn, pdu->header_digest,
		    ISCSI_DIGEST_LEN);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_write() failed (errno=%d,%s)\n",
			    errno, conn->initiator_name);
			return -1;
		}
		if (rc != ISCSI_DIGEST_LEN) {
			ISTGT_ERRLOG("incomplete Header Digest length (%d)\n",
			    rc);
			return -1;
		}
		total += ISCSI_DIGEST_LEN;
	}

	/* Data Segment */
	if (data_len != 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "Data write %d\n",
		    data_len);
		rc = istgt_iscsi_write(conn, pdu->data, data_len);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_write() failed (errno=%d,%s)\n",
			    errno, conn->initiator_name);
			return -1;
		}
		if (rc != data_len) {
			ISTGT_ERRLOG("incomplete Data Segment length (%d)\n",
			    rc);
			return -1;
		}
		total += data_len;
	}

	/* Data Digest */
	if (enable_digest && conn->data_digest && data_len != 0) {
		crc32c = istgt_crc32c(pdu->data, data_len);
		MAKE_DIGEST_WORD(pdu->data_digest, crc32c);

		ISTGT_TRACELOG(ISTGT_TRACE_NET, "DataDigest write %d\n",
		    ISCSI_DIGEST_LEN);
		ISTGT_TRACELOG(ISTGT_TRACE_NET, "DataDigest %x\n",
		    crc32c);
		rc = istgt_iscsi_write(conn, pdu->data_digest,
		    ISCSI_DIGEST_LEN);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_write() failed (errno=%d,%s)\n",
			    errno, conn->initiator_name);
			return -1;
		}
		if (rc != ISCSI_DIGEST_LEN) {
			ISTGT_ERRLOG("incomplete Data Digest length (%d)\n",
			    rc);
			return -1;
		}
		total += ISCSI_DIGEST_LEN;
	}

	return total;
}
#else /* defined (ISTGT_USE_IOVEC) */
static int
istgt_iscsi_write_pdu_internal(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	struct iovec iovec[5]; /* BHS+AHS+HD+DATA+DD */
	uint8_t *cp;
	uint32_t crc32c;
	time_t start, now;
	int nbytes;
	int enable_digest;
	int opcode;
	int total_ahs_len;
	int data_len;
	int total;
	int rc;
	int i;

	cp = (uint8_t *) &pdu->bhs;
	total_ahs_len = DGET8(&cp[4]);
	data_len = DGET24(&cp[5]);
	total = 0;

	enable_digest = 1;
	opcode = BGET8W(&cp[0], 5, 6);
	if (opcode == ISCSI_OP_LOGIN_RSP) {
		/* this PDU should be sent without digest */
		enable_digest = 0;
	}

	/* BHS */
	iovec[0].iov_base = &pdu->bhs;
	iovec[0].iov_len = ISCSI_BHS_LEN;
	total += ISCSI_BHS_LEN;

	/* AHS */
	iovec[1].iov_base = pdu->ahs;
	iovec[1].iov_len = 4 * total_ahs_len;
	total += (4 * total_ahs_len);

	/* Header Digest */
	iovec[2].iov_base = pdu->header_digest;
	if (enable_digest && conn->header_digest) {
		if (total_ahs_len == 0) {
			crc32c = istgt_crc32c((uint8_t *) &pdu->bhs,
			    ISCSI_BHS_LEN);
		} else {
			int upd_total = 0;
			crc32c = ISTGT_CRC32C_INITIAL;
			crc32c = istgt_update_crc32c((uint8_t *) &pdu->bhs,
			    ISCSI_BHS_LEN, crc32c);
			upd_total += ISCSI_BHS_LEN;
			crc32c = istgt_update_crc32c((uint8_t *) pdu->ahs,
			    (4 * total_ahs_len), crc32c);
			upd_total += (4 * total_ahs_len);
			crc32c = istgt_fixup_crc32c(upd_total, crc32c);
			crc32c = crc32c ^ ISTGT_CRC32C_XOR;
		}
		MAKE_DIGEST_WORD(pdu->header_digest, crc32c);

		iovec[2].iov_len = ISCSI_DIGEST_LEN;
		total += ISCSI_DIGEST_LEN;
	} else {
		iovec[2].iov_len = 0;
	}

	/* Data Segment */
	iovec[3].iov_base = pdu->data;
	iovec[3].iov_len = ISCSI_ALIGN(data_len);
	total += ISCSI_ALIGN(data_len);

	/* Data Digest */
	iovec[4].iov_base = pdu->data_digest;
	if (enable_digest && conn->data_digest && data_len != 0) {
		crc32c = istgt_crc32c(pdu->data, ISCSI_ALIGN(data_len));
		MAKE_DIGEST_WORD(pdu->data_digest, crc32c);

		iovec[4].iov_len = ISCSI_DIGEST_LEN;
		total += ISCSI_DIGEST_LEN;
	} else {
		iovec[4].iov_len = 0;
	}

	/* write all bytes from iovec */
	nbytes = total;
	ISTGT_TRACELOG(ISTGT_TRACE_NET, "PDU write %d\n", nbytes);
	errno = 0;
	start = time(NULL);
	while (nbytes > 0) {
		rc = writev(conn->sock, &iovec[0], 5);
		if (rc < 0) {
			now = time(NULL);
			ISTGT_ERRLOG("writev() failed (errno=%d,%s,time=%d)\n",
			    errno, conn->initiator_name, istgt_difftime(now, start));
			return -1;
		}
		nbytes -= rc;
		if (nbytes == 0)
			break;
		/* adjust iovec length */
		for (i = 0; i < 5; i++) {
			if (iovec[i].iov_len != 0 && iovec[i].iov_len > (size_t)rc) {
				iovec[i].iov_base
					= (void *) (((uintptr_t)iovec[i].iov_base) + rc);
				iovec[i].iov_len -= rc;
				break;
			} else {
				rc -= iovec[i].iov_len;
				iovec[i].iov_len = 0;
			}
		}
	}

	return total;
}
#endif /* defined (ISTGT_USE_IOVEC) */

int
istgt_iscsi_copy_pdu(ISCSI_PDU_Ptr dst_pdu, ISCSI_PDU_Ptr src_pdu)
{
	memcpy(&dst_pdu->bhs, &src_pdu->bhs, ISCSI_BHS_LEN);
	dst_pdu->ahs = src_pdu->ahs;
	memcpy(dst_pdu->header_digest, src_pdu->header_digest,
	    ISCSI_DIGEST_LEN);
	if (src_pdu->data == src_pdu->shortdata) {
		memcpy(dst_pdu->shortdata, src_pdu->shortdata,
		    sizeof src_pdu->shortdata);
		dst_pdu->data = dst_pdu->shortdata;
	} else {
		dst_pdu->data = src_pdu->data;
	}
	memcpy(dst_pdu->data_digest, src_pdu->data_digest, ISCSI_DIGEST_LEN);
	dst_pdu->total_ahs_len = src_pdu->total_ahs_len;
	dst_pdu->data_segment_len = src_pdu->data_segment_len;
	dst_pdu->copy_pdu = 0;
	src_pdu->copy_pdu = 1;
	return 0;
}

typedef struct iscsi_param_table_t
{
	const char *key;
	const char *val;
	const char *list;
	int type;
} ISCSI_PARAM_TABLE;

static ISCSI_PARAM_TABLE conn_param_table[] =
{
	{ "HeaderDigest", "None", "CRC32C,None", ISPT_LIST },
	{ "DataDigest", "None", "CRC32C,None", ISPT_LIST },
	{ "MaxRecvDataSegmentLength", "8192", "512,16777215", ISPT_NUMERICAL },
	{ "OFMarker", "No", "Yes,No", ISPT_BOOLEAN_AND },
	{ "IFMarker", "No", "Yes,No", ISPT_BOOLEAN_AND },
	{ "OFMarkInt", "1", "1,65535", ISPT_NUMERICAL },
	{ "IFMarkInt", "1", "1,65535", ISPT_NUMERICAL },
	{ "AuthMethod", "None", "CHAP,None", ISPT_LIST },
	{ "CHAP_A", "5", "5", ISPT_LIST },
	{ "CHAP_N", "", "", ISPT_DECLARATIVE },
	{ "CHAP_R", "", "", ISPT_DECLARATIVE },
	{ "CHAP_I", "", "", ISPT_DECLARATIVE },
	{ "CHAP_C", "", "", ISPT_DECLARATIVE },
	{ NULL, NULL, NULL, ISPT_INVALID },
};

static ISCSI_PARAM_TABLE sess_param_table[] =
{
	{ "MaxConnections", "1", "1,65535", ISPT_NUMERICAL },
#if 0
	/* need special handling */
	{ "SendTargets", "", "", ISPT_DECLARATIVE },
#endif
	{ "TargetName", "", "", ISPT_DECLARATIVE },
	{ "InitiatorName", "", "", ISPT_DECLARATIVE },
	{ "TargetAlias", "", "", ISPT_DECLARATIVE },
	{ "InitiatorAlias", "", "", ISPT_DECLARATIVE },
	{ "TargetAddress", "", "", ISPT_DECLARATIVE },
	{ "TargetPortalGroupTag", "1", "1,65535", ISPT_NUMERICAL },
	{ "InitialR2T", "Yes", "Yes,No", ISPT_BOOLEAN_OR },
	{ "ImmediateData", "Yes", "Yes,No", ISPT_BOOLEAN_AND },
	{ "MaxBurstLength", "262144", "512,16777215", ISPT_NUMERICAL },
	{ "FirstBurstLength", "65536", "512,16777215", ISPT_NUMERICAL },
	{ "DefaultTime2Wait", "2", "0,3600", ISPT_NUMERICAL_MAX },
	{ "DefaultTime2Retain", "20", "0,3600", ISPT_NUMERICAL },
	{ "MaxOutstandingR2T", "1", "1,65536", ISPT_NUMERICAL },
	{ "DataPDUInOrder", "Yes", "Yes,No", ISPT_BOOLEAN_OR },
	{ "DataSequenceInOrder", "Yes", "Yes,No", ISPT_BOOLEAN_OR },
	{ "ErrorRecoveryLevel", "0", "0,2", ISPT_NUMERICAL },
	{ "SessionType", "Normal", "Normal,Discovery", ISPT_DECLARATIVE },
	{ NULL, NULL, NULL, ISPT_INVALID },
};

static int
istgt_iscsi_params_init_internal(ISCSI_PARAM **params, ISCSI_PARAM_TABLE *table)
{
	int rc;
	int i;

	for (i = 0; table[i].key != NULL; i++) {
		rc = istgt_iscsi_param_add(params, table[i].key, table[i].val,
		    table[i].list, table[i].type);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_param_add() failed\n");
			return -1;
		}
	}

	return 0;
}

static int
istgt_iscsi_conn_params_init(ISCSI_PARAM **params)
{
	return istgt_iscsi_params_init_internal(params, &conn_param_table[0]);
}

static int
istgt_iscsi_sess_params_init(ISCSI_PARAM **params)
{
	return istgt_iscsi_params_init_internal(params, &sess_param_table[0]);
}

static char *
istgt_iscsi_param_get_val(ISCSI_PARAM *params, const char *key)
{
	ISCSI_PARAM *param;

	param = istgt_iscsi_param_find(params, key);
	if (param == NULL)
		return NULL;
	return param->val;
}

static int
istgt_iscsi_param_eq_val(ISCSI_PARAM *params, const char *key, const char *val)
{
	ISCSI_PARAM *param;

	param = istgt_iscsi_param_find(params, key);
	if (param == NULL)
		return 0;
	if (strcasecmp(param->val, val) == 0)
		return 1;
	return 0;
}

#if 0
static int
istgt_iscsi_print_params(ISCSI_PARAM *params)
{
	ISCSI_PARAM *param;

	for (param = params; param != NULL; param = param->next) {
		printf("key=[%s] val=[%s] list=[%s] type=%d\n",
		    param->key, param->val, param->list, param->type);
	}
	return 0;
}
#endif

static int
istgt_iscsi_negotiate_params(CONN_Ptr conn, ISCSI_PARAM *params, uint8_t *data, int alloc_len, int data_len)
{
	ISCSI_PARAM *param;
	ISCSI_PARAM *cur_param;
	char *valid_list, *in_val;
	char *valid_next, *in_next;
	char *cur_val;
	char *new_val;
	char *valid_val;
	char *min_val, *max_val;
	int discovery;
	int cur_type;
	int val_i, cur_val_i;
	int min_i, max_i;
	int total;
	int len;
	int sw;

	total = data_len;
	if (alloc_len < 1) {
		return 0;
	}
	if (total > alloc_len) {
		total = alloc_len;
		data[total - 1] = '\0';
		return total;
	}

	if (params == NULL) {
		/* no input */
		return total;
	}

	/* discovery? */
	discovery = 0;
	cur_param = istgt_iscsi_param_find(params, "SessionType");
	if (cur_param == NULL) {
		SESS_MTX_LOCK(conn);
		cur_param = istgt_iscsi_param_find(conn->sess->params, "SessionType");
		if (cur_param == NULL) {
			/* no session type */
		} else {
			if (strcasecmp(cur_param->val, "Discovery") == 0) {
				discovery = 1;
			}
		}
		SESS_MTX_UNLOCK(conn);
	} else {
		if (strcasecmp(cur_param->val, "Discovery") == 0) {
			discovery = 1;
		}
	}

	/* for temporary store */
	valid_list = xmalloc(ISCSI_TEXT_MAX_VAL_LEN + 1);
	in_val = xmalloc(ISCSI_TEXT_MAX_VAL_LEN + 1);
	cur_val = xmalloc(ISCSI_TEXT_MAX_VAL_LEN + 1);

	for (param = params; param != NULL; param = param->next) {
		/* sendtargets is special */
		if (strcasecmp(param->key, "SendTargets") == 0) {
			continue;
		}
		/* CHAP keys */
		if (strcasecmp(param->key, "CHAP_A") == 0
		    || strcasecmp(param->key, "CHAP_N") == 0
		    || strcasecmp(param->key, "CHAP_R") == 0
		    || strcasecmp(param->key, "CHAP_I") == 0
		    || strcasecmp(param->key, "CHAP_C") == 0) {
			continue;
		}

		if (discovery) {
			/* 12.2, 12.10, 12.11, 12.13, 12.14, 12.17, 12.18, 12.19 */
			if (strcasecmp(param->key, "MaxConnections") == 0
			    || strcasecmp(param->key, "InitialR2T") == 0
			    || strcasecmp(param->key, "ImmediateData") == 0
			    || strcasecmp(param->key, "MaxBurstLength") == 0
			    || strcasecmp(param->key, "FirstBurstLength") == 0
			    || strcasecmp(param->key, "MaxOutstandingR2T") == 0
			    || strcasecmp(param->key, "DataPDUInOrder") == 0
			    || strcasecmp(param->key, "DataSequenceInOrder") == 0) {
				strlcpy(in_val, "Irrelevant",
				    ISCSI_TEXT_MAX_VAL_LEN);
				new_val = in_val;
				cur_type = -1;
				goto add_val;
			}
		}

		/* get current param */
		sw = 0;
		cur_param = istgt_iscsi_param_find(conn->params, param->key);
		if (cur_param == NULL) {
			sw = 1;
			SESS_MTX_LOCK(conn);
			cur_param = istgt_iscsi_param_find(conn->sess->params,
			    param->key);
			if (cur_param == NULL) {
				SESS_MTX_UNLOCK(conn);
				if (strncasecmp(param->key, "X-", 2) == 0
				    || strncasecmp(param->key, "X#", 2) == 0) {
					/* Extension Key */
					ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
					    "extension key %.64s\n",
					    param->key);
				} else {
					ISTGT_ERRLOG("unknown key %.64s\n",
					    param->key);
				}
				strlcpy(in_val, "NotUnderstood",
				    ISCSI_TEXT_MAX_VAL_LEN);
				new_val = in_val;
				cur_type = -1;
				goto add_val;
			}
			strlcpy(valid_list, cur_param->list,
			    ISCSI_TEXT_MAX_VAL_LEN);
			strlcpy(cur_val, cur_param->val,
			    ISCSI_TEXT_MAX_VAL_LEN);
			cur_type = cur_param->type;
			SESS_MTX_UNLOCK(conn);
		} else {
			strlcpy(valid_list, cur_param->list,
			    ISCSI_TEXT_MAX_VAL_LEN);
			strlcpy(cur_val, cur_param->val,
			    ISCSI_TEXT_MAX_VAL_LEN);
			cur_type = cur_param->type;
		}

		/* negotiate value */
		switch (cur_type) {
		case ISPT_LIST:
			strlcpy(in_val, param->val, ISCSI_TEXT_MAX_VAL_LEN);
			in_next = in_val;
			while ((new_val = strsepq(&in_next, ",")) != NULL) {
				valid_next = valid_list;
				while ((valid_val = strsepq(&valid_next, ",")) != NULL) {
					if (strcasecmp(new_val, valid_val) == 0) {
						ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "match %s\n",
						    new_val);
						goto update_val;
					}
				}
			}
			if (new_val == NULL) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "key %.64s reject\n",
				    param->key);
				strlcpy(in_val, "Reject",
				    ISCSI_TEXT_MAX_VAL_LEN);
				new_val = in_val;
				goto add_val;
			}
			break;

		case ISPT_NUMERICAL:
			val_i = (int) strtol(param->val, NULL, 10);
			cur_val_i = (int) strtol(cur_val, NULL, 10);
			valid_next = valid_list;
			min_val = strsepq(&valid_next, ",");
			max_val = strsepq(&valid_next, ",");
			if (min_val != NULL) {
				min_i = (int) strtol(min_val, NULL, 10);
			} else {
				min_i = 0;
			}
			if (max_val != NULL) {
				max_i = (int) strtol(max_val, NULL, 10);
			} else {
				max_i = 0;
			}
			if (val_i < min_i || val_i > max_i) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "key %.64s reject\n",
				    param->key);
				strlcpy(in_val, "Reject",
				    ISCSI_TEXT_MAX_VAL_LEN);
				new_val = in_val;
				goto add_val;
			}
			if (strcasecmp(param->key, "MaxRecvDataSegmentLength") == 0) {
				/* Declarative, but set as same value */
				cur_val_i = conn->TargetMaxRecvDataSegmentLength;
			}
			if (val_i > cur_val_i) {
				val_i = cur_val_i;
			}
			snprintf(in_val, ISCSI_TEXT_MAX_VAL_LEN, "%d", val_i);
			new_val = in_val;
			break;

		case ISPT_NUMERICAL_MAX:
			val_i = (int) strtol(param->val, NULL, 10);
			cur_val_i = (int) strtol(cur_val, NULL, 10);
			valid_next = valid_list;
			min_val = strsepq(&valid_next, ",");
			max_val = strsepq(&valid_next, ",");
			if (min_val != NULL) {
				min_i = (int) strtol(min_val, NULL, 10);
			} else {
				min_i = 0;
			}
			if (max_val != NULL) {
				max_i = (int) strtol(max_val, NULL, 10);
			} else {
				max_i = 0;
			}
			if (val_i < min_i || val_i > max_i) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "key %.64s reject\n",
				    param->key);
				strlcpy(in_val, "Reject",
				    ISCSI_TEXT_MAX_VAL_LEN);
				new_val = in_val;
				goto add_val;
			}
			if (val_i < cur_val_i) {
				val_i = cur_val_i;
			}
			snprintf(in_val, ISCSI_TEXT_MAX_VAL_LEN, "%d", val_i);
			new_val = in_val;
			break;

		case ISPT_BOOLEAN_OR:
			if (strcasecmp(cur_val, "Yes") == 0) {
				/* YES || XXX */
				strlcpy(in_val, "Yes", ISCSI_TEXT_MAX_VAL_LEN);
				new_val = in_val;
			} else {
				if (strcasecmp(param->val, "Yes") == 0
				    || strcasecmp(param->val, "No") == 0) {
					new_val = param->val;
				} else {
					/* unknown value */
					strlcpy(in_val, "Reject",
					    ISCSI_TEXT_MAX_VAL_LEN);
					new_val = in_val;
					goto add_val;
				}
			}
			break;

		case ISPT_BOOLEAN_AND:
			if (strcasecmp(cur_val, "No") == 0) {
				/* No && XXX */
				strlcpy(in_val, "No", ISCSI_TEXT_MAX_VAL_LEN);
				new_val = in_val;
			} else {
				if (strcasecmp(param->val, "Yes") == 0
				    || strcasecmp(param->val, "No") == 0) {
					new_val = param->val;
				} else {
					/* unknown value */
					strlcpy(in_val, "Reject",
					    ISCSI_TEXT_MAX_VAL_LEN);
					new_val = in_val;
					goto add_val;
				}
			}
			break;

		case ISPT_DECLARATIVE:
			strlcpy(in_val, param->val, ISCSI_TEXT_MAX_VAL_LEN);
			new_val = in_val;
			break;

		default:
			strlcpy(in_val, param->val, ISCSI_TEXT_MAX_VAL_LEN);
			new_val = in_val;
			break;
		}

	update_val:
		if (sw) {
			/* update session wide */
			SESS_MTX_LOCK(conn);
			istgt_iscsi_param_set(conn->sess->params, param->key,
			    new_val);
			SESS_MTX_UNLOCK(conn);
		} else {
			/* update connection only */
			istgt_iscsi_param_set(conn->params, param->key,
			    new_val);
		}
	add_val:
		if (cur_type != ISPT_DECLARATIVE) {
			if (alloc_len - total < 1) {
				ISTGT_ERRLOG("data space small %d\n",
				    alloc_len);
				return total;
			}
			ISTGT_TRACELOG(ISTGT_TRACE_ISCSI, "negotiated %s=%s\n",
			    param->key, new_val);
			len = snprintf((char *) data + total,
			    alloc_len - total, "%s=%s",
			    param->key, new_val);
			total += len + 1;
		}
	}

	xfree(valid_list);
	xfree(in_val);
	xfree(cur_val);

	return total;
}

static int
istgt_iscsi_append_text(CONN_Ptr conn __attribute__((__unused__)), const char *key, const char *val, uint8_t *data, int alloc_len, int data_len)
{
	int total;
	int len;

	total = data_len;
	if (alloc_len < 1) {
		return 0;
	}
	if (total > alloc_len) {
		total = alloc_len;
		data[total - 1] = '\0';
		return total;
	}

	if (alloc_len - total < 1) {
		ISTGT_ERRLOG("data space small %d\n", alloc_len);
		return total;
	}
	len = snprintf((char *) data + total, alloc_len - total, "%s=%s",
	    key, val);
	total += len + 1;

	return total;
}

static int
istgt_iscsi_append_param(CONN_Ptr conn, const char *key, uint8_t *data, int alloc_len, int data_len)
{
	ISCSI_PARAM *param;
	int rc;

	param = istgt_iscsi_param_find(conn->params, key);
	if (param == NULL) {
		param = istgt_iscsi_param_find(conn->sess->params, key);
		if (param == NULL) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "no key %.64s\n",
			    key);
			return data_len;
		}
	}
	rc = istgt_iscsi_append_text(conn, param->key, param->val, data,
	    alloc_len, data_len);
	return rc;
}

int
istgt_chap_get_authinfo(ISTGT_CHAP_AUTH *auth, const char *authfile, const char *authuser, int ag_tag)
{
	CONFIG *config = NULL;
	CF_SECTION *sp;
	const char *val;
	const char *user, *muser;
	const char *secret, *msecret;
	int rc;
	int i;

	if (auth->user != NULL) {
		xfree(auth->user);
		xfree(auth->secret);
		xfree(auth->muser);
		xfree(auth->msecret);
		auth->user = auth->secret = NULL;
		auth->muser = auth->msecret = NULL;
	}

	/* read config files */
	config = istgt_allocate_config();
	rc = istgt_read_config(config, authfile);
	if (rc < 0) {
		ISTGT_ERRLOG("auth conf error\n");
		istgt_free_config(config);
		return -1;
	}
	//istgt_print_config(config);

	sp = config->section;
	while (sp != NULL) {
		if (sp->type == ST_AUTHGROUP) {
			if (sp->num == 0) {
				ISTGT_ERRLOG("Group 0 is invalid\n");
				istgt_free_config(config);
				return -1;
			}
			if (ag_tag != sp->num) {
				goto skip_ag_tag;
			}

			val = istgt_get_val(sp, "Comment");
			if (val != NULL) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "Comment %s\n", val);
			}
			for (i = 0; ; i++) {
				val = istgt_get_nval(sp, "Auth", i);
				if (val == NULL)
					break;
				user = istgt_get_nmval(sp, "Auth", i, 0);
				secret = istgt_get_nmval(sp, "Auth", i, 1);
				muser = istgt_get_nmval(sp, "Auth", i, 2);
				msecret = istgt_get_nmval(sp, "Auth", i, 3);
				if (strcasecmp(authuser, user) == 0) {
					/* match user */
					auth->user = xstrdup(user);
					auth->secret = xstrdup(secret);
					auth->muser = xstrdup(muser);
					auth->msecret = xstrdup(msecret);
					istgt_free_config(config);
					return 0;
				}
			}
		}
	skip_ag_tag:
		sp = sp->next;
	}

	istgt_free_config(config);
	return 0;
}

static int
istgt_iscsi_get_authinfo(CONN_Ptr conn, const char *authuser)
{
	char *authfile = NULL;
	int ag_tag;
	int rc;

	SESS_MTX_LOCK(conn);
	if (conn->sess->lu != NULL) {
		ag_tag = conn->sess->lu->auth_group;
	} else {
		ag_tag = -1;
	}
	SESS_MTX_UNLOCK(conn);
	if (ag_tag < 0) {
		MTX_LOCK(&conn->istgt->mutex);
		ag_tag = conn->istgt->discovery_auth_group;
		MTX_UNLOCK(&conn->istgt->mutex);
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "ag_tag=%d\n", ag_tag);

	MTX_LOCK(&conn->istgt->mutex);
	authfile = xstrdup(conn->istgt->authfile);
	MTX_UNLOCK(&conn->istgt->mutex);

	rc = istgt_chap_get_authinfo(&conn->auth, authfile, authuser, ag_tag);
	if (rc < 0) {
		ISTGT_ERRLOG("chap_get_authinfo() failed\n");
		xfree(authfile);
		return -1;
	}
	xfree(authfile);
	return 0;
}

static int
istgt_iscsi_auth_params(CONN_Ptr conn, ISCSI_PARAM *params, const char *method, uint8_t *data, int alloc_len, int data_len)
{
	char *in_val;
	char *in_next;
	char *new_val;
	const char *val;
	const char *user;
	const char *response;
	const char *challenge;
	int total;
	int rc;

	if (conn == NULL || params == NULL || method == NULL) {
		return -1;
	}
	if (strcasecmp(method, "CHAP") == 0) {
		/* method OK */
	} else {
		ISTGT_ERRLOG("unsupported AuthMethod %.64s\n", method);
		return -1;
	}

	total = data_len;
	if (alloc_len < 1) {
		return 0;
	}
	if (total > alloc_len) {
		total = alloc_len;
		data[total - 1] = '\0';
		return total;
	}

	/* for temporary store */
	in_val = xmalloc(ISCSI_TEXT_MAX_VAL_LEN + 1);

	/* CHAP method (RFC1994) */
	if ((val = ISCSI_GETVAL(params, "CHAP_A")) != NULL) {
		if (conn->auth.chap_phase != ISTGT_CHAP_PHASE_WAIT_A) {
			ISTGT_ERRLOG("CHAP sequence error\n");
			goto error_return;
		}

		/* CHAP_A is LIST type */
		strlcpy(in_val, val, ISCSI_TEXT_MAX_VAL_LEN);
		in_next = in_val;
		while ((new_val = strsepq(&in_next, ",")) != NULL) {
			if (strcasecmp(new_val, "5") == 0) {
				/* CHAP with MD5 */
				break;
			}
		}
		if (new_val == NULL) {
			strlcpy(in_val, "Reject", ISCSI_TEXT_MAX_VAL_LEN);
			new_val = in_val;
			total = istgt_iscsi_append_text(conn, "CHAP_A",
			    new_val, data, alloc_len, total);
			goto error_return;
		}
		/* selected algorithm is 5 (MD5) */
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "got CHAP_A=%s\n", new_val);
		total = istgt_iscsi_append_text(conn, "CHAP_A", new_val,
		    data, alloc_len, total);

		/* Identifier is one octet */
		istgt_gen_random(conn->auth.chap_id, 1);
		snprintf(in_val, ISCSI_TEXT_MAX_VAL_LEN, "%d",
		    (int) conn->auth.chap_id[0]);
		total = istgt_iscsi_append_text(conn, "CHAP_I", in_val,
		    data, alloc_len, total);

		/* Challenge Value is a variable stream of octets */
		/* (binary length MUST not exceed 1024 bytes) */
		conn->auth.chap_challenge_len = ISTGT_CHAP_CHALLENGE_LEN;
		istgt_gen_random(conn->auth.chap_challenge,
		    conn->auth.chap_challenge_len);
		istgt_bin2hex(in_val, ISCSI_TEXT_MAX_VAL_LEN,
		    conn->auth.chap_challenge,
		    conn->auth.chap_challenge_len);
		total = istgt_iscsi_append_text(conn, "CHAP_C", in_val,
		    data, alloc_len, total);

		conn->auth.chap_phase = ISTGT_CHAP_PHASE_WAIT_NR;
	} else if ((val = ISCSI_GETVAL(params, "CHAP_N")) != NULL) {
		uint8_t resmd5[ISTGT_MD5DIGEST_LEN];
		uint8_t tgtmd5[ISTGT_MD5DIGEST_LEN];
		ISTGT_MD5CTX md5ctx;

		user = val;
		if (conn->auth.chap_phase != ISTGT_CHAP_PHASE_WAIT_NR) {
			ISTGT_ERRLOG("CHAP sequence error\n");
			goto error_return;
		}

		response = ISCSI_GETVAL(params, "CHAP_R");
		if (response == NULL) {
			ISTGT_ERRLOG("no response\n");
			goto error_return;
		}
		rc = istgt_hex2bin(resmd5, ISTGT_MD5DIGEST_LEN, response);
		if (rc < 0 || rc != ISTGT_MD5DIGEST_LEN) {
			ISTGT_ERRLOG("response format error\n");
			goto error_return;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "got CHAP_N/CHAP_R\n");

		rc = istgt_iscsi_get_authinfo(conn, val);
		if (rc < 0) {
			//ISTGT_ERRLOG("auth user or secret is missing\n");
			ISTGT_ERRLOG("iscsi_get_authinfo() failed\n");
			goto error_return;
		}
		if (conn->auth.user == NULL || conn->auth.secret == NULL) {
			//ISTGT_ERRLOG("auth user or secret is missing\n");
			ISTGT_ERRLOG("auth failed (user %.64s)\n", user);
			goto error_return;
		}

		istgt_md5init(&md5ctx);
		/* Identifier */
		istgt_md5update(&md5ctx, conn->auth.chap_id, 1);
		/* followed by secret */
		istgt_md5update(&md5ctx, conn->auth.secret,
		    strlen(conn->auth.secret));
		/* followed by Challenge Value */
		istgt_md5update(&md5ctx, conn->auth.chap_challenge,
		    conn->auth.chap_challenge_len);
		/* tgtmd5 is expecting Response Value */
		istgt_md5final(tgtmd5, &md5ctx);

		istgt_bin2hex(in_val, ISCSI_TEXT_MAX_VAL_LEN,
		    tgtmd5, ISTGT_MD5DIGEST_LEN);

#if 0
		printf("tgtmd5=%s, resmd5=%s\n", in_val, response);
		istgt_dump("tgtmd5", tgtmd5, ISTGT_MD5DIGEST_LEN);
		istgt_dump("resmd5", resmd5, ISTGT_MD5DIGEST_LEN);
#endif

		/* compare MD5 digest */
		if (memcmp(tgtmd5, resmd5, ISTGT_MD5DIGEST_LEN) != 0) {
			/* not match */
			//ISTGT_ERRLOG("auth user or secret is missing\n");
			ISTGT_ERRLOG("auth failed (user %.64s)\n", user);
			goto error_return;
		}
		/* OK initiator's secret */
		conn->authenticated = 1;

		/* mutual CHAP? */
		val = ISCSI_GETVAL(params, "CHAP_I");
		if (val != NULL) {
			conn->auth.chap_mid[0] = (uint8_t) strtol(val, NULL, 10);
			challenge = ISCSI_GETVAL(params, "CHAP_C");
			if (challenge == NULL) {
				ISTGT_ERRLOG("CHAP sequence error\n");
				goto error_return;
			}
			rc = istgt_hex2bin(conn->auth.chap_mchallenge,
			    ISTGT_CHAP_CHALLENGE_LEN,
			    challenge);
			if (rc < 0) {
				ISTGT_ERRLOG("challenge format error\n");
				goto error_return;
			}
			conn->auth.chap_mchallenge_len = rc;
#if 0
			istgt_dump("MChallenge", conn->auth.chap_mchallenge,
			    conn->auth.chap_mchallenge_len);
#endif
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "got CHAP_I/CHAP_C\n");

			if (conn->auth.muser == NULL || conn->auth.msecret == NULL) {
				//ISTGT_ERRLOG("mutual auth user or secret is missing\n");
				ISTGT_ERRLOG("auth failed (user %.64s)\n",
				    user);
				goto error_return;
			}

			istgt_md5init(&md5ctx);
			/* Identifier */
			istgt_md5update(&md5ctx, conn->auth.chap_mid, 1);
			/* followed by secret */
			istgt_md5update(&md5ctx, conn->auth.msecret,
			    strlen(conn->auth.msecret));
			/* followed by Challenge Value */
			istgt_md5update(&md5ctx, conn->auth.chap_mchallenge,
			    conn->auth.chap_mchallenge_len);
			/* tgtmd5 is Response Value */
			istgt_md5final(tgtmd5, &md5ctx);

			istgt_bin2hex(in_val, ISCSI_TEXT_MAX_VAL_LEN,
			    tgtmd5, ISTGT_MD5DIGEST_LEN);

			total = istgt_iscsi_append_text(conn, "CHAP_N",
			    conn->auth.muser, data, alloc_len, total);
			total = istgt_iscsi_append_text(conn, "CHAP_R",
			    in_val, data, alloc_len, total);
		} else {
			/* not mutual */
			if (conn->req_mutual) {
				ISTGT_ERRLOG("required mutual CHAP\n");
				goto error_return;
			}
		}

		conn->auth.chap_phase = ISTGT_CHAP_PHASE_END;
	} else {
		/* not found CHAP keys */
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "start CHAP\n");
		conn->auth.chap_phase = ISTGT_CHAP_PHASE_WAIT_A;
	}

	xfree(in_val);
	return total;

 error_return:
	conn->auth.chap_phase = ISTGT_CHAP_PHASE_WAIT_A;
	xfree(in_val);
	return -1;
}

static int
istgt_iscsi_reject(CONN_Ptr conn, ISCSI_PDU_Ptr pdu, int reason)
{
	ISCSI_PDU rsp_pdu;
	uint8_t *rsp;
	uint8_t *data;
	int total_ahs_len;
	int data_len;
	int alloc_len;
	int rc;

	total_ahs_len = DGET8(&pdu->bhs.total_ahs_len);
	data_len = 0;
	alloc_len = ISCSI_BHS_LEN + (4 * total_ahs_len);
	if (conn->header_digest) {
		alloc_len += ISCSI_DIGEST_LEN;
	}
	data = xmalloc(alloc_len);
	memset(data, 0, alloc_len);

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "Reject PDU reason=%d\n",
	    reason);
	if (conn->sess != NULL) {
		SESS_MTX_LOCK(conn);
		ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
		    "StatSN=%u, ExpCmdSN=%u, MaxCmdSN=%u\n",
		    conn->StatSN, conn->sess->ExpCmdSN,
		    conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
		    "StatSN=%u\n",
		    conn->StatSN);
	}

	memcpy(data, &pdu->bhs, ISCSI_BHS_LEN);
	data_len += ISCSI_BHS_LEN;
	if (total_ahs_len != 0) {
		memcpy(data + data_len, pdu->ahs, (4 * total_ahs_len));
		data_len += (4 * total_ahs_len);
	}
	if (conn->header_digest) {
		memcpy(data + data_len, pdu->header_digest, ISCSI_DIGEST_LEN);
		data_len += ISCSI_DIGEST_LEN;
	}

	rsp = (uint8_t *) &rsp_pdu.bhs;
	rsp_pdu.data = data;
	memset(rsp, 0, ISCSI_BHS_LEN);
	rsp[0] = ISCSI_OP_REJECT;
	BDADD8W(&rsp[1], 1, 7, 1);
	rsp[2] = reason;
	rsp[4] = 0; // TotalAHSLength
	DSET24(&rsp[5], data_len); // DataSegmentLength

	DSET32(&rsp[16], 0xffffffffU);

	if (conn->sess != NULL) {
		SESS_MTX_LOCK(conn);
		DSET32(&rsp[24], conn->StatSN);
		conn->StatSN++;
		DSET32(&rsp[28], conn->sess->ExpCmdSN);
		DSET32(&rsp[32], conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);
	} else {
		DSET32(&rsp[24], conn->StatSN);
		conn->StatSN++;
		DSET32(&rsp[28], 1);
		DSET32(&rsp[32], 1);
	}
	DSET32(&rsp[36], 0); // DataSN/R2TSN

	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "PDU", rsp, ISCSI_BHS_LEN);

	rc = istgt_iscsi_write_pdu(conn, &rsp_pdu);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_write_pdu() failed\n");
		xfree(data);
		return -1;
	}

	xfree(data);
	return 0;
}

static void
istgt_iscsi_copy_param2var(CONN_Ptr conn)
{
	const char *val;

	val = ISCSI_GETVAL(conn->params, "MaxRecvDataSegmentLength");
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "copy MaxRecvDataSegmentLength=%s\n", val);
	conn->MaxRecvDataSegmentLength = (int) strtol(val, NULL, 10);
	if (conn->sendbufsize != conn->MaxRecvDataSegmentLength) {
		xfree(conn->recvbuf);
		xfree(conn->sendbuf);
		if (conn->MaxRecvDataSegmentLength < 8192) {
			conn->recvbufsize = 8192;
			conn->sendbufsize = 8192;
		} else {
			conn->recvbufsize = conn->MaxRecvDataSegmentLength;
			conn->sendbufsize = conn->MaxRecvDataSegmentLength;
		}
		conn->recvbuf = xmalloc(conn->recvbufsize);
		conn->sendbuf = xmalloc(conn->sendbufsize);
	}
	val = ISCSI_GETVAL(conn->params, "HeaderDigest");
	if (strcasecmp(val, "CRC32C") == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "set HeaderDigest=1\n");
		conn->header_digest = 1;
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "set HeaderDigest=0\n");
		conn->header_digest = 0;
	}
	val = ISCSI_GETVAL(conn->params, "DataDigest");
	if (strcasecmp(val, "CRC32C") == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "set DataDigest=1\n");
		conn->data_digest = 1;
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "set DataDigest=0\n");
		conn->data_digest = 0;
	}

	SESS_MTX_LOCK(conn);
	val = ISCSI_GETVAL(conn->sess->params, "MaxConnections");
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "copy MaxConnections=%s\n", val);
	conn->sess->MaxConnections = (int) strtol(val, NULL, 10);
	val = ISCSI_GETVAL(conn->sess->params, "MaxOutstandingR2T");
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "copy MaxOutstandingR2T=%s\n", val);
	conn->sess->MaxOutstandingR2T = (int) strtol(val, NULL, 10);
	conn->MaxOutstandingR2T = conn->sess->MaxOutstandingR2T;
	val = ISCSI_GETVAL(conn->sess->params, "FirstBurstLength");
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "copy FirstBurstLength=%s\n", val);
	conn->sess->FirstBurstLength = (int) strtol(val, NULL, 10);
	conn->FirstBurstLength = conn->sess->FirstBurstLength;
	val = ISCSI_GETVAL(conn->sess->params, "MaxBurstLength");
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "copy MaxBurstLength=%s\n", val);
	conn->sess->MaxBurstLength = (int) strtol(val, NULL, 10);
	conn->MaxBurstLength = conn->sess->MaxBurstLength;
	val = ISCSI_GETVAL(conn->sess->params, "InitialR2T");
	if (strcasecmp(val, "Yes") == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "set InitialR2T=1\n");
		conn->sess->initial_r2t = 1;
	} else{
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "set InitialR2T=0\n");
		conn->sess->initial_r2t = 0;
	}
	val = ISCSI_GETVAL(conn->sess->params, "ImmediateData");
	if (strcasecmp(val, "Yes") == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "set ImmediateData=1\n");
		conn->sess->immediate_data = 1;
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "set ImmediateData=0\n");
		conn->sess->immediate_data = 0;
	}
	SESS_MTX_UNLOCK(conn);
}

static int
istgt_iscsi_check_values(CONN_Ptr conn)
{
	SESS_MTX_LOCK(conn);
	if (conn->sess->FirstBurstLength > conn->sess->MaxBurstLength) {
		ISTGT_ERRLOG("FirstBurstLength(%d) > MaxBurstLength(%d)\n",
		    conn->sess->FirstBurstLength,
		    conn->sess->MaxBurstLength);
		SESS_MTX_UNLOCK(conn);
		return -1;
	}
	if (conn->sess->MaxBurstLength > 0x00ffffff) {
		ISTGT_ERRLOG("MaxBurstLength(%d) > 0x00ffffff\n",
		    conn->sess->MaxBurstLength);
		SESS_MTX_UNLOCK(conn);
		return -1;
	}
	if (conn->TargetMaxRecvDataSegmentLength < 512) {
		ISTGT_ERRLOG("MaxRecvDataSegmentLength(%d) < 512\n",
		    conn->TargetMaxRecvDataSegmentLength);
		return -1;
	}
	if (conn->TargetMaxRecvDataSegmentLength > 0x00ffffff) {
		ISTGT_ERRLOG("MaxRecvDataSegmentLength(%d) > 0x00ffffff\n",
		    conn->TargetMaxRecvDataSegmentLength);
		SESS_MTX_UNLOCK(conn);
		return -1;
	}
	if (conn->MaxRecvDataSegmentLength < 512) {
		ISTGT_ERRLOG("MaxRecvDataSegmentLength(%d) < 512\n",
		    conn->MaxRecvDataSegmentLength);
		return -1;
	}
	if (conn->MaxRecvDataSegmentLength > 0x00ffffff) {
		ISTGT_ERRLOG("MaxRecvDataSegmentLength(%d) > 0x00ffffff\n",
		    conn->MaxRecvDataSegmentLength);
		SESS_MTX_UNLOCK(conn);
		return -1;
	}
	SESS_MTX_UNLOCK(conn);
	return 0;
}

static int
istgt_iscsi_op_login(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	char buf[MAX_TMPBUF];
	ISTGT_LU_Ptr lu = NULL;
	ISCSI_PARAM *params = NULL;
	ISCSI_PDU rsp_pdu;
	uint8_t *rsp;
	uint8_t *cp;
	uint8_t *data;
	const char *session_type;
	const char *auth_method;
	const char *val;
	uint64_t isid;
	uint16_t tsih;
	uint16_t cid;
	uint32_t task_tag;
	uint32_t CmdSN;
	uint32_t ExpStatSN;
	int T_bit, C_bit;
	int CSG, NSG;
	int VersionMin, VersionMax;
	int StatusClass, StatusDetail;
	int data_len;
	int alloc_len;
	int rc;

	/* Login is proceeding OK */
	StatusClass = 0x00;
	StatusDetail = 0x00;

	data_len = 0;

	if (conn->MaxRecvDataSegmentLength < 8192) {
		// Default MaxRecvDataSegmentLength - RFC3720(12.12)
		alloc_len = 8192;
	} else {
		alloc_len = conn->MaxRecvDataSegmentLength;
	}
	data = xmalloc(alloc_len);
	memset(data, 0, alloc_len);

	cp = (uint8_t *) &pdu->bhs;
	T_bit = BGET8(&cp[1], 7);
	C_bit = BGET8(&cp[1], 6);
	CSG = BGET8W(&cp[1], 3, 2);
	NSG = BGET8W(&cp[1], 1, 2);
	VersionMin = cp[2];
	VersionMax = cp[3];

	isid = DGET48(&cp[8]);
	tsih = DGET16(&cp[14]);
	cid = DGET16(&cp[20]);
	task_tag = DGET32(&cp[16]);
	CmdSN = DGET32(&cp[24]);
	ExpStatSN = DGET32(&cp[28]);

#if 1
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "PDU", cp, ISCSI_BHS_LEN);
#endif

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "T=%d, C=%d, CSG=%d, NSG=%d, Min=%d, Max=%d, ITT=%x\n",
	    T_bit, C_bit, CSG, NSG, VersionMin, VersionMax, task_tag);
	if (conn->sess != NULL) {
		SESS_MTX_LOCK(conn);
		ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
		    "CmdSN=%u, ExpStatSN=%u, StatSN=%u, ExpCmdSN=%u, MaxCmdSN=%u\n",
		    CmdSN, ExpStatSN, conn->StatSN, conn->sess->ExpCmdSN,
		    conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
		    "CmdSN=%u, ExpStatSN=%u, StatSN=%u\n",
		    CmdSN, ExpStatSN, conn->StatSN);
	}

	if (T_bit && C_bit) {
		ISTGT_ERRLOG("transit error\n");
		xfree(data);
		return -1;
	}
	if (VersionMin > ISCSI_VERSION || VersionMax < ISCSI_VERSION) {
		ISTGT_ERRLOG("unsupported version %d/%d\n", VersionMin, VersionMax);
		/* Unsupported version */
		StatusClass = 0x02;
		StatusDetail = 0x05;
		goto response;
	}

	/* store incoming parameters */
	rc = istgt_iscsi_parse_params(&params, pdu->data, pdu->data_segment_len);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_parse_params() failed\n");
	error_return:
		istgt_iscsi_param_free(params);
		xfree(data);
		return -1;
	}

	/* set port identifiers and parameters */
	if (conn->login_phase == ISCSI_LOGIN_PHASE_NONE) {
		/* Initiator Name and Port */
		val = ISCSI_GETVAL(params, "InitiatorName");
		if (val == NULL) {
			ISTGT_ERRLOG("InitiatorName is empty\n");
			/* Missing parameter */
			StatusClass = 0x02;
			StatusDetail = 0x07;
			goto response;
		}
		snprintf(conn->initiator_name, sizeof conn->initiator_name,
		    "%s", val);
		snprintf(conn->initiator_port, sizeof conn->initiator_port,
		    "%s" ",i,0x" "%12.12" PRIx64, val, isid);
		strlwr(conn->initiator_name);
		strlwr(conn->initiator_port);
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Initiator name: %s\n",
		    conn->initiator_name);
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Initiator port: %s\n",
		    conn->initiator_port);

		/* Session Type */
		session_type = ISCSI_GETVAL(params, "SessionType");
		if (session_type == NULL) {
			if (tsih != 0) {
				session_type = "Normal";
			} else {
				ISTGT_ERRLOG("SessionType is empty\n");
				/* Missing parameter */
				StatusClass = 0x02;
				StatusDetail = 0x07;
				goto response;
			}
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Session Type: %s\n",
		    session_type);

		/* Target Name and Port */
		if (strcasecmp(session_type, "Normal") == 0) {
			val = ISCSI_GETVAL(params, "TargetName");
			if (val == NULL) {
				ISTGT_ERRLOG("TargetName is empty\n");
				/* Missing parameter */
				StatusClass = 0x02;
				StatusDetail = 0x07;
				goto response;
			}
			snprintf(conn->target_name, sizeof conn->target_name,
			    "%s", val);
			snprintf(conn->target_port, sizeof conn->target_port,
			    "%s" ",t,0x" "%4.4x", val, conn->portal.tag);
			strlwr(conn->target_name);
			strlwr(conn->target_port);

			MTX_LOCK(&conn->istgt->mutex);
			lu = istgt_lu_find_target(conn->istgt,
			    conn->target_name);
			if (lu == NULL) {
				MTX_UNLOCK(&conn->istgt->mutex);
				ISTGT_ERRLOG("lu_find_target() failed\n");
				/* Not found */
				StatusClass = 0x02;
				StatusDetail = 0x03;
				goto response;
			}
			rc = istgt_lu_access(conn, lu, conn->initiator_name,
			    conn->initiator_addr);
			if (rc < 0) {
				MTX_UNLOCK(&conn->istgt->mutex);
				ISTGT_ERRLOG("lu_access() failed\n");
				/* Not found */
				StatusClass = 0x02;
				StatusDetail = 0x03;
				goto response;
			}
			if (rc == 0) {
				MTX_UNLOCK(&conn->istgt->mutex);
				ISTGT_ERRLOG("access denied\n");
				/* Not found */
				StatusClass = 0x02;
				StatusDetail = 0x03;
				goto response;
			}
			MTX_UNLOCK(&conn->istgt->mutex);

			/* check existing session */
			ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
			    "isid=%"PRIx64", tsih=%u, cid=%u\n",
			    isid, tsih, cid);
			if (tsih != 0) {
				/* multiple connections */
				rc = istgt_append_sess(conn, isid, tsih, cid);
				if (rc < 0) {
					ISTGT_ERRLOG("isid=%"PRIx64", tsih=%u, cid=%u: "
					    "append_sess() failed\n",
					    isid, tsih, cid);
					/* Can't include in session */
					StatusClass = 0x02;
					StatusDetail = 0x08;
					goto response;
				}
			} else {
				/* new session, drop old sess by the initiator */
				istgt_iscsi_drop_old_conns(conn);
			}

			/* force target flags */
			MTX_LOCK(&lu->mutex);
			if (lu->no_auth_chap) {
				conn->req_auth = 0;
				rc = istgt_iscsi_param_del(&conn->params,
				    "AuthMethod");
				if (rc < 0) {
					MTX_UNLOCK(&lu->mutex);
					ISTGT_ERRLOG("iscsi_param_del() failed\n");
					goto error_return;
				}
				rc = istgt_iscsi_param_add(&conn->params,
				    "AuthMethod", "None", "None", ISPT_LIST);
				if (rc < 0) {
					MTX_UNLOCK(&lu->mutex);
					ISTGT_ERRLOG("iscsi_param_add() failed\n");
					goto error_return;
				}
			} else if (lu->auth_chap) {
				conn->req_auth = 1;
				rc = istgt_iscsi_param_del(&conn->params,
				    "AuthMethod");
				if (rc < 0) {
					MTX_UNLOCK(&lu->mutex);
					ISTGT_ERRLOG("iscsi_param_del() failed\n");
					goto error_return;
				}
				rc = istgt_iscsi_param_add(&conn->params,
				    "AuthMethod", "CHAP", "CHAP", ISPT_LIST);
				if (rc < 0) {
					MTX_UNLOCK(&lu->mutex);
					ISTGT_ERRLOG("iscsi_param_add() failed\n");
					goto error_return;
				}
			}
			if (lu->auth_chap_mutual) {
				conn->req_mutual = 1;
			}
			if (lu->header_digest) {
				rc = istgt_iscsi_param_del(&conn->params,
				    "HeaderDigest");
				if (rc < 0) {
					MTX_UNLOCK(&lu->mutex);
					ISTGT_ERRLOG("iscsi_param_del() failed\n");
					goto error_return;
				}
				rc = istgt_iscsi_param_add(&conn->params,
				    "HeaderDigest", "CRC32C", "CRC32C",
				    ISPT_LIST);
				if (rc < 0) {
					MTX_UNLOCK(&lu->mutex);
					ISTGT_ERRLOG("iscsi_param_add() failed\n");
					goto error_return;
				}
			}
			if (lu->data_digest) {
				rc = istgt_iscsi_param_del(&conn->params,
				    "DataDigest");
				if (rc < 0) {
					MTX_UNLOCK(&lu->mutex);
					ISTGT_ERRLOG("iscsi_param_del() failed\n");
					goto error_return;
				}
				rc = istgt_iscsi_param_add(&conn->params,
				    "DataDigest", "CRC32C", "CRC32C",
				    ISPT_LIST);
				if (rc < 0) {
					MTX_UNLOCK(&lu->mutex);
					ISTGT_ERRLOG("iscsi_param_add() failed\n");
					goto error_return;
				}
			}
			MTX_UNLOCK(&lu->mutex);
		} else if (strcasecmp(session_type, "Discovery") == 0) {
			snprintf(conn->target_name, sizeof conn->target_name,
			    "%s", "dummy");
			snprintf(conn->target_port, sizeof conn->target_port,
			    "%s" ",t,0x" "%4.4x", "dummy", conn->portal.tag);
			lu = NULL;
			tsih = 0;

			/* force target flags */
			MTX_LOCK(&conn->istgt->mutex);
			if (conn->istgt->no_discovery_auth) {
				conn->req_auth = 0;
				rc = istgt_iscsi_param_del(&conn->params,
				    "AuthMethod");
				if (rc < 0) {
					MTX_UNLOCK(&conn->istgt->mutex);
					ISTGT_ERRLOG("iscsi_param_del() failed\n");
					goto error_return;
				}
				rc = istgt_iscsi_param_add(&conn->params,
				    "AuthMethod", "None", "None", ISPT_LIST);
				if (rc < 0) {
					MTX_UNLOCK(&conn->istgt->mutex);
					ISTGT_ERRLOG("iscsi_param_add() failed\n");
					goto error_return;
				}
			} else if (conn->istgt->req_discovery_auth) {
				conn->req_auth = 1;
				rc = istgt_iscsi_param_del(&conn->params,
				    "AuthMethod");
				if (rc < 0) {
					MTX_UNLOCK(&conn->istgt->mutex);
					ISTGT_ERRLOG("iscsi_param_del() failed\n");
					goto error_return;
				}
				rc = istgt_iscsi_param_add(&conn->params,
				    "AuthMethod", "CHAP", "CHAP", ISPT_LIST);
				if (rc < 0) {
					MTX_UNLOCK(&conn->istgt->mutex);
					ISTGT_ERRLOG("iscsi_param_add() failed\n");
					goto error_return;
				}
			}
			if (conn->istgt->req_discovery_auth_mutual) {
				conn->req_mutual = 1;
			}
			MTX_UNLOCK(&conn->istgt->mutex);
		} else {
			ISTGT_ERRLOG("unknown session type\n");
			/* Missing parameter */
			StatusClass = 0x02;
			StatusDetail = 0x07;
			goto response;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Target name: %s\n",
		    conn->target_name);
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Target port: %s\n",
		    conn->target_port);

		conn->authenticated = 0;
		conn->auth.chap_phase = ISTGT_CHAP_PHASE_WAIT_A;
		conn->cid = cid;
		if (lu == NULL || lu->queue_depth == 0) {
			conn->queue_depth = ISCMDQ;
		} else {
			conn->queue_depth = lu->queue_depth;
		}
		conn->max_pending = (conn->queue_depth + 1) * 2;
#if 0
		/* override config setting */
		MTX_LOCK(&conn->r2t_mutex);
		if ((conn->max_r2t > 0)
		    && (conn->max_r2t < conn->max_pending)) {
			int i;
			xfree(conn->r2t_tasks);
			conn->max_r2t = conn->max_pending;
			conn->r2t_tasks = xmalloc (sizeof *conn->r2t_tasks
			    * (conn->max_r2t + 1));
			for (i = 0; i < (conn->max_r2t + 1); i++) {
				conn->r2t_tasks[i] = NULL;
			}
		}
		MTX_UNLOCK(&conn->r2t_mutex);
#endif
		if (conn->sess == NULL) {
			/* new session */
			rc = istgt_create_sess(conn->istgt, conn, lu);
			if (rc < 0) {
				ISTGT_ERRLOG("create_sess() failed\n");
				goto error_return;
			}

			/* initialize parameters */
			SESS_MTX_LOCK(conn);
			conn->StatSN = ExpStatSN;
			conn->MaxOutstandingR2T
				= conn->sess->MaxOutstandingR2T;
			conn->sess->isid = isid;
			conn->sess->tsih = tsih;
			conn->sess->lu = lu;
			conn->sess->ExpCmdSN = CmdSN;
			conn->sess->MaxCmdSN = CmdSN + conn->queue_depth - 1;
			SESS_MTX_UNLOCK(conn);
		}

		/* limit conns on discovery session */
		if (strcasecmp(session_type, "Discovery") == 0) {
			SESS_MTX_LOCK(conn);
			conn->sess->MaxConnections = 1;
			rc = istgt_iscsi_param_set_int(conn->sess->params,
			    "MaxConnections", conn->sess->MaxConnections);
			SESS_MTX_UNLOCK(conn);
			if (rc < 0) {
				ISTGT_ERRLOG("iscsi_param_set_int() failed\n");
				goto error_return;
			}
		}

		/* declarative parameters */
		if (lu != NULL) {
			MTX_LOCK(&lu->mutex);
			if (lu->alias != NULL) {
				snprintf(buf, sizeof buf, "%s", lu->alias);
			} else {
				snprintf(buf, sizeof buf, "%s", "");
			}
			MTX_UNLOCK(&lu->mutex);
			SESS_MTX_LOCK(conn);
			rc = istgt_iscsi_param_set(conn->sess->params,
			    "TargetAlias", buf);
			SESS_MTX_UNLOCK(conn);
			if (rc < 0) {
				ISTGT_ERRLOG("iscsi_param_set() failed\n");
				goto error_return;
			}
		}
		snprintf(buf, sizeof buf, "%s:%s,%d",
		    conn->portal.host, conn->portal.port, conn->portal.tag);
		SESS_MTX_LOCK(conn);
		rc = istgt_iscsi_param_set(conn->sess->params,
		    "TargetAddress", buf);
		SESS_MTX_UNLOCK(conn);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_param_set() failed\n");
			goto error_return;
		}
		snprintf(buf, sizeof buf, "%d", conn->portal.tag);
		SESS_MTX_LOCK(conn);
		rc = istgt_iscsi_param_set(conn->sess->params,
		    "TargetPortalGroupTag", buf);
		SESS_MTX_UNLOCK(conn);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_param_set() failed\n");
			goto error_return;
		}

		/* write in response */
		if (lu != NULL) {
			SESS_MTX_LOCK(conn);
			val = ISCSI_GETVAL(conn->sess->params, "TargetAlias");
			if (val != NULL && strlen(val) != 0) {
				data_len = istgt_iscsi_append_param(conn,
				    "TargetAlias", data, alloc_len, data_len);
			}
			if (strcasecmp(session_type, "Discovery") == 0) {
				data_len = istgt_iscsi_append_param(conn,
				    "TargetAddress", data, alloc_len, data_len);
			}
			data_len = istgt_iscsi_append_param(conn,
			    "TargetPortalGroupTag", data, alloc_len, data_len);
			SESS_MTX_UNLOCK(conn);
		}

		/* start login phase */
		conn->login_phase = ISCSI_LOGIN_PHASE_START;
	}

	/* negotiate parameters */
	data_len = istgt_iscsi_negotiate_params(conn, params,
	    data, alloc_len, data_len);
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "Negotiated Params",
	    data, data_len);

	switch (CSG) {
	case 0:
		/* SecurityNegotiation */
		auth_method = ISCSI_GETVAL(conn->params, "AuthMethod");
		if (auth_method == NULL) {
			ISTGT_ERRLOG("AuthMethod is empty\n");
			/* Missing parameter */
			StatusClass = 0x02;
			StatusDetail = 0x07;
			goto response;
		}
		if (strcasecmp(auth_method, "None") == 0) {
			conn->authenticated = 1;
		} else {
			rc = istgt_iscsi_auth_params(conn, params, auth_method,
			    data, alloc_len, data_len);
			if (rc < 0) {
				ISTGT_ERRLOG("iscsi_auth_params() failed\n");
				/* Authentication failure */
				StatusClass = 0x02;
				StatusDetail = 0x01;
				goto response;
			}
			data_len = rc;
			if (conn->authenticated == 0) {
				/* not complete */
				T_bit = 0;
			} else {
				if (conn->auth.chap_phase != ISTGT_CHAP_PHASE_END) {
					ISTGT_WARNLOG("CHAP phase not complete");
				}
			}
#if 0
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG,
			    "Negotiated Auth Params", data, data_len);
#endif
		}
		break;
	case 1:
		/* LoginOperationalNegotiation */
		if (conn->login_phase == ISCSI_LOGIN_PHASE_START) {
			if (conn->req_auth) {
				/* Authentication failure */
				StatusClass = 0x02;
				StatusDetail = 0x01;
				goto response;
			} else {
				/* AuthMethod=None */
				conn->authenticated = 1;
			}
		}
		if (conn->authenticated == 0) {
			ISTGT_ERRLOG("authentication error\n");
			/* Authentication failure */
			StatusClass = 0x02;
			StatusDetail = 0x01;
			goto response;
		}
		break;
	case 3:
		/* FullFeaturePhase */
		ISTGT_ERRLOG("XXX Login in FullFeaturePhase\n");
		/* Initiator error */
		StatusClass = 0x02;
		StatusDetail = 0x00;
		goto response;
	default:
		ISTGT_ERRLOG("unknown stage\n");
		/* Initiator error */
		StatusClass = 0x02;
		StatusDetail = 0x00;
		goto response;
	}

	if (T_bit) {
		switch (NSG) {
		case 0:
			/* SecurityNegotiation */
			conn->login_phase = ISCSI_LOGIN_PHASE_SECURITY;
			break;
		case 1:
			/* LoginOperationalNegotiation */
			conn->login_phase = ISCSI_LOGIN_PHASE_OPERATIONAL;
			break;
		case 3:
			/* FullFeaturePhase */
			conn->login_phase = ISCSI_LOGIN_PHASE_FULLFEATURE;

			SESS_MTX_LOCK(conn);
			if (ISCSI_EQVAL(conn->sess->params, "SessionType", "Normal")) {
				/* normal session */
				tsih = conn->sess->tsih;
				/* new tsih? */
				if (tsih == 0) {
					tsih = istgt_lu_allocate_tsih(conn->sess->lu,
					    conn->initiator_port,
					    conn->portal.tag);
					if (tsih == 0) {
						SESS_MTX_UNLOCK(conn);
						ISTGT_ERRLOG("lu_allocate_tsih() failed\n");
						goto error_return;
					}
					conn->sess->tsih = tsih;
				} else {
					/* multiple connection */
				}

				snprintf(buf, sizeof buf, "Login from %s (%s) on %s LU%d"
				    " (%s:%s,%d), ISID=%"PRIx64", TSIH=%u,"
				    " CID=%u, HeaderDigest=%s, DataDigest=%s\n",
				    conn->initiator_name, conn->initiator_addr,
				    conn->target_name, conn->sess->lu->num,
				    conn->portal.host, conn->portal.port,
				    conn->portal.tag,
				    conn->sess->isid, conn->sess->tsih, conn->cid,
				    (ISCSI_EQVAL(conn->params, "HeaderDigest", "CRC32C")
					? "on" : "off"),
				    (ISCSI_EQVAL(conn->params, "DataDigest", "CRC32C")
					? "on" : "off"));
				ISTGT_NOTICELOG("%s", buf);
			} else if (ISCSI_EQVAL(conn->sess->params, "SessionType", "Discovery")) {
				/* discovery session */
				/* new tsih */
				MTX_LOCK(&g_last_tsih_mutex);
				tsih = conn->sess->tsih;
				g_last_tsih++;
				tsih = g_last_tsih;
				if (tsih == 0) {
					g_last_tsih++;
					tsih = g_last_tsih;
				}
				conn->sess->tsih = tsih;
				MTX_UNLOCK(&g_last_tsih_mutex);

				snprintf(buf, sizeof buf, "Login(discovery) from %s (%s) on"
				    " (%s:%s,%d), ISID=%"PRIx64", TSIH=%u,"
				    " CID=%u, HeaderDigest=%s, DataDigest=%s\n",
				    conn->initiator_name, conn->initiator_addr,
				    conn->portal.host, conn->portal.port,
				    conn->portal.tag,
				    conn->sess->isid, conn->sess->tsih, conn->cid,
				    (ISCSI_EQVAL(conn->params, "HeaderDigest", "CRC32C")
					? "on" : "off"),
				    (ISCSI_EQVAL(conn->params, "DataDigest", "CRC32C")
					? "on" : "off"));
				ISTGT_NOTICELOG("%s", buf);
			} else {
				ISTGT_ERRLOG("unknown session type\n");
				SESS_MTX_UNLOCK(conn);
				/* Initiator error */
				StatusClass = 0x02;
				StatusDetail = 0x00;
				goto response;
			}
			SESS_MTX_UNLOCK(conn);

			conn->full_feature = 1;
			break;
		default:
			ISTGT_ERRLOG("unknown stage\n");
			/* Initiator error */
			StatusClass = 0x02;
			StatusDetail = 0x00;
			goto response;
		}
	}

 response:
	/* response PDU */
	rsp = (uint8_t *) &rsp_pdu.bhs;
	rsp_pdu.data = data;
	memset(rsp, 0, ISCSI_BHS_LEN);
	rsp[0] = ISCSI_OP_LOGIN_RSP;
	BDADD8(&rsp[1], T_bit, 7);
	BDADD8(&rsp[1], C_bit, 6);
	BDADD8W(&rsp[1], CSG, 3, 2);
	BDADD8W(&rsp[1], NSG, 1, 2);
	rsp[2] = ISCSI_VERSION; // Version-max
	rsp[3] = ISCSI_VERSION; // Version-active
	rsp[4] = 0; // TotalAHSLength
	DSET24(&rsp[5], data_len); // DataSegmentLength

	DSET48(&rsp[8], isid);
	DSET16(&rsp[14], tsih);
	DSET32(&rsp[16], task_tag);

	if (conn->sess != NULL) {
		SESS_MTX_LOCK(conn);
		DSET32(&rsp[24], conn->StatSN);
		conn->StatSN++;
		DSET32(&rsp[28], conn->sess->ExpCmdSN);
		DSET32(&rsp[32], conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);
	} else {
		DSET32(&rsp[24], conn->StatSN);
		conn->StatSN++;
		DSET32(&rsp[28], CmdSN);
		DSET32(&rsp[32], CmdSN);
	}

	rsp[36] = StatusClass;
	rsp[37] = StatusDetail;

#if 1
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "PDU", rsp, ISCSI_BHS_LEN);
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "DATA", data, data_len);
#endif
	rc = istgt_iscsi_write_pdu(conn, &rsp_pdu);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_write_pdu() failed\n");
		istgt_iscsi_param_free(params);
		xfree(data);
		return -1;
	}

	/* after send PDU digest on/off */
	if (conn->full_feature) {
		/* update internal variables */
		istgt_iscsi_copy_param2var(conn);
		/* check value */
		rc = istgt_iscsi_check_values(conn);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_check_values() failed\n");
			istgt_iscsi_param_free(params);
			xfree(data);
			return -1;
		}
	}

	istgt_iscsi_param_free(params);
	xfree(data);
	return 0;
}

static int
istgt_iscsi_op_text(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	ISCSI_PARAM *params = NULL;
	ISCSI_PDU rsp_pdu;
	uint8_t *rsp;
	uint8_t *cp;
	uint8_t *data;
	uint64_t lun;
	uint32_t task_tag;
	uint32_t transfer_tag;
	uint32_t CmdSN;
	uint32_t ExpStatSN;
	const char *iiqn;
	const char *val;
	int I_bit, F_bit, C_bit;
	int data_len;
	int alloc_len;
	int rc;

	if (!conn->full_feature) {
		ISTGT_ERRLOG("before Full Feature\n");
		return -1;
	}

	data_len = 0;
	alloc_len = conn->sendbufsize;
	data = (uint8_t *) conn->sendbuf;
	memset(data, 0, alloc_len);

	cp = (uint8_t *) &pdu->bhs;
	I_bit = BGET8(&cp[0], 7);
	F_bit = BGET8(&cp[1], 7);
	C_bit = BGET8(&cp[1], 6);

	lun = DGET64(&cp[8]);
	task_tag = DGET32(&cp[16]);
	transfer_tag = DGET32(&cp[20]);
	CmdSN = DGET32(&cp[24]);
	ExpStatSN = DGET32(&cp[28]);

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "I=%d, F=%d, C=%d, ITT=%x, TTT=%x\n",
	    I_bit, F_bit, C_bit, task_tag, transfer_tag);
	SESS_MTX_LOCK(conn);
	ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
	    "CmdSN=%u, ExpStatSN=%u, StatSN=%u, ExpCmdSN=%u, MaxCmdSN=%u\n",
	    CmdSN, ExpStatSN, conn->StatSN, conn->sess->ExpCmdSN,
	    conn->sess->MaxCmdSN);
	if (I_bit == 0) {
		if (SN32_LT(CmdSN, conn->sess->ExpCmdSN)
		    || SN32_GT(CmdSN, conn->sess->MaxCmdSN)) {
			ISTGT_ERRLOG("CmdSN(%u) ignore (ExpCmdSN=%u, MaxCmdSN=%u)\n",
			    CmdSN, conn->sess->ExpCmdSN,
			    conn->sess->MaxCmdSN);
			SESS_MTX_UNLOCK(conn);
			return -1;
		}
	} else if (CmdSN != conn->sess->ExpCmdSN) {
		SESS_MTX_UNLOCK(conn);
		ISTGT_ERRLOG("CmdSN(%u) error\n", CmdSN);
		return -1;
	}
	if (SN32_GT(ExpStatSN, conn->StatSN)) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "StatSN(%u) advanced\n",
		    ExpStatSN);
		conn->StatSN = ExpStatSN;
	}
	if (ExpStatSN != conn->StatSN) {
#if 0
		ISTGT_ERRLOG("StatSN(%u) error\n", ExpStatSN);
		SESS_MTX_UNLOCK(conn);
		return -1;
#else
		/* StarPort have a bug */
		ISTGT_WARNLOG("StatSN(%u) rewound\n", ExpStatSN);
		conn->StatSN = ExpStatSN;
#endif
	}
	SESS_MTX_UNLOCK(conn);

	if (F_bit && C_bit) {
		ISTGT_ERRLOG("final and continue\n");
		return -1;
	}

	/* store incoming parameters */
	rc = istgt_iscsi_parse_params(&params, pdu->data,
	    pdu->data_segment_len);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_parse_params() failed\n");
		istgt_iscsi_param_free(params);
		return -1;
	}

	/* negotiate parameters */
	data_len = istgt_iscsi_negotiate_params(conn, params,
	    data, alloc_len, data_len);
	/* sendtargets is special case */
	val = ISCSI_GETVAL(params, "SendTargets");
	if (val != NULL) {
		if (strcasecmp(val, "") == 0) {
			val = conn->target_name;
		}
		SESS_MTX_LOCK(conn);
		iiqn = ISCSI_GETVAL(conn->sess->params,
		    "InitiatorName");
		if (ISCSI_EQVAL(conn->sess->params,
			"SessionType", "Discovery")) {
			data_len = istgt_lu_sendtargets(conn,
			    conn->initiator_name,
			    conn->initiator_addr,
			    val, data, alloc_len, data_len);
		} else {
			if (strcasecmp(val, "ALL") == 0) {
				/* not in discovery session */
				data_len = istgt_iscsi_append_text(conn, "SendTargets",
				    "Reject", data, alloc_len, data_len);
			} else {
				data_len = istgt_lu_sendtargets(conn,
				    conn->initiator_name,
				    conn->initiator_addr,
				    val, data, alloc_len, data_len);
			}
		}
		SESS_MTX_UNLOCK(conn);
	}
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "Negotiated Params",
	    data, data_len);

	/* response PDU */
	rsp = (uint8_t *) &rsp_pdu.bhs;
	rsp_pdu.data = data;
	memset(rsp, 0, ISCSI_BHS_LEN);
	rsp[0] = ISCSI_OP_TEXT_RSP;
	BDADD8(&rsp[1], F_bit, 7);
	BDADD8(&rsp[1], C_bit, 6);
	rsp[4] = 0; // TotalAHSLength
	DSET24(&rsp[5], data_len); // DataSegmentLength

	DSET64(&rsp[8], lun);
	DSET32(&rsp[16], task_tag);
	if (F_bit) {
		DSET32(&rsp[20], 0xffffffffU);
	} else {
		transfer_tag = 1 + conn->id;
		DSET32(&rsp[20], transfer_tag);
	}

	SESS_MTX_LOCK(conn);
	DSET32(&rsp[24], conn->StatSN);
	conn->StatSN++;
	if (I_bit == 0) {
		conn->sess->ExpCmdSN++;
		conn->sess->MaxCmdSN++;
	}
	DSET32(&rsp[28], conn->sess->ExpCmdSN);
	DSET32(&rsp[32], conn->sess->MaxCmdSN);
	SESS_MTX_UNLOCK(conn);

	rc = istgt_iscsi_write_pdu(conn, &rsp_pdu);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_write_pdu() failed\n");
		istgt_iscsi_param_free(params);
		return -1;
	}

	/* update internal variables */
	istgt_iscsi_copy_param2var(conn);
	/* check value */
	rc = istgt_iscsi_check_values(conn);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_check_values() failed\n");
		istgt_iscsi_param_free(params);
		return -1;
	}

	istgt_iscsi_param_free(params);
	return 0;
}

static int
istgt_iscsi_op_logout(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	char buf[MAX_TMPBUF];
	ISCSI_PDU rsp_pdu;
	uint8_t *rsp;
	uint8_t *cp;
	uint8_t *data;
	uint32_t task_tag;
	uint16_t cid;
	uint32_t CmdSN;
	uint32_t ExpStatSN;
	int reason;
	int response;
	int data_len;
	int alloc_len;
	int rc;

	data_len = 0;
	alloc_len = conn->sendbufsize;
	data = (uint8_t *) conn->sendbuf;
	memset(data, 0, alloc_len);

	cp = (uint8_t *) &pdu->bhs;
	reason = BGET8W(&cp[1], 6, 7);

	task_tag = DGET32(&cp[16]);
	cid = DGET16(&cp[20]);
	CmdSN = DGET32(&cp[24]);
	ExpStatSN = DGET32(&cp[28]);

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "reason=%d, ITT=%x, cid=%d\n",
	    reason, task_tag, cid);
	if (conn->sess != NULL) {
		SESS_MTX_LOCK(conn);
		ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
		    "CmdSN=%u, ExpStatSN=%u, StatSN=%u, ExpCmdSN=%u, MaxCmdSN=%u\n",
		    CmdSN, ExpStatSN, conn->StatSN, conn->sess->ExpCmdSN,
		    conn->sess->MaxCmdSN);
		if (CmdSN != conn->sess->ExpCmdSN) {
			ISTGT_WARNLOG("CmdSN(%u) might have dropped\n", CmdSN);
			/* ignore error */
		}
		SESS_MTX_UNLOCK(conn);
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
		    "CmdSN=%u, ExpStatSN=%u, StatSN=%u\n",
		    CmdSN, ExpStatSN, conn->StatSN);
	}
	if (conn->sess != NULL) {
		SESS_MTX_LOCK(conn);
	}
	if (SN32_GT(ExpStatSN, conn->StatSN)) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "StatSN(%u) advanced\n",
		    ExpStatSN);
		conn->StatSN = ExpStatSN;
	}
	if (ExpStatSN != conn->StatSN) {
		ISTGT_WARNLOG("StatSN(%u/%u) might have dropped\n",
		    ExpStatSN, conn->StatSN);
		/* ignore error */
	}
	if (conn->sess != NULL) {
		SESS_MTX_UNLOCK(conn);
	}

	response = 0; // connection or session closed successfully

	/* response PDU */
	rsp = (uint8_t *) &rsp_pdu.bhs;
	rsp_pdu.data = data;
	memset(rsp, 0, ISCSI_BHS_LEN);
	rsp[0] = ISCSI_OP_LOGOUT_RSP;
	BDADD8W(&rsp[1], 1, 7, 1);
	rsp[2] = response;
	rsp[4] = 0; // TotalAHSLength
	DSET24(&rsp[5], data_len); // DataSegmentLength

	DSET32(&rsp[16], task_tag);

	if (conn->sess != NULL) {
		SESS_MTX_LOCK(conn);
		DSET32(&rsp[24], conn->StatSN);
		conn->StatSN++;
		if (conn->sess->connections == 1) {
			conn->sess->ExpCmdSN++;
			conn->sess->MaxCmdSN++;
		}
		DSET32(&rsp[28], conn->sess->ExpCmdSN);
		DSET32(&rsp[32], conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);
	} else {
		DSET32(&rsp[24], conn->StatSN);
		conn->StatSN++;
		DSET32(&rsp[28], CmdSN);
		DSET32(&rsp[32], CmdSN);
	}

	DSET16(&rsp[40], 0); // Time2Wait
	DSET16(&rsp[42], 0); // Time2Retain

	rc = istgt_iscsi_write_pdu(conn, &rsp_pdu);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_write_pdu() failed\n");
		return -1;
	}

	SESS_MTX_LOCK(conn);
	if (ISCSI_EQVAL(conn->sess->params, "SessionType", "Normal")) {
		snprintf(buf, sizeof buf, "Logout from %s (%s) on %s LU%d"
		    " (%s:%s,%d), ISID=%"PRIx64", TSIH=%u,"
		    " CID=%u, HeaderDigest=%s, DataDigest=%s\n",
		    conn->initiator_name, conn->initiator_addr,
		    conn->target_name, conn->sess->lu->num,
		    conn->portal.host, conn->portal.port, conn->portal.tag,
		    conn->sess->isid, conn->sess->tsih, conn->cid,
		    (ISCSI_EQVAL(conn->params, "HeaderDigest", "CRC32C")
			? "on" : "off"),
		    (ISCSI_EQVAL(conn->params, "DataDigest", "CRC32C")
			? "on" : "off"));
		ISTGT_NOTICELOG("%s", buf);
	} else {
		/* discovery session */
		snprintf(buf, sizeof buf, "Logout(discovery) from %s (%s) on"
		    " (%s:%s,%d), ISID=%"PRIx64", TSIH=%u,"
		    " CID=%u, HeaderDigest=%s, DataDigest=%s\n",
		    conn->initiator_name, conn->initiator_addr,
		    conn->portal.host, conn->portal.port, conn->portal.tag,
		    conn->sess->isid, conn->sess->tsih, conn->cid,
		    (ISCSI_EQVAL(conn->params, "HeaderDigest", "CRC32C")
			? "on" : "off"),
		    (ISCSI_EQVAL(conn->params, "DataDigest", "CRC32C")
			? "on" : "off"));
		ISTGT_NOTICELOG("%s", buf);
	}
	SESS_MTX_UNLOCK(conn);

	conn->exec_logout = 1;
	return 0;
}

static int istgt_iscsi_transfer_in_internal(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd);

static int
istgt_iscsi_transfer_in(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	int rc;

	//MTX_LOCK(&conn->wpdu_mutex);
	rc = istgt_iscsi_transfer_in_internal(conn, lu_cmd);
	//MTX_UNLOCK(&conn->wpdu_mutex);
	return rc;
}

static int
istgt_iscsi_transfer_in_internal(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	ISCSI_PDU rsp_pdu;
	uint8_t *rsp;
	uint8_t *data;
	uint32_t task_tag;
	uint32_t transfer_tag;
	uint32_t DataSN;
	int transfer_len;
	int data_len;
	int segment_len;
	int offset;
	int F_bit, O_bit, U_bit, S_bit;
	int residual_len;
	int sent_status;
	int len;
	int rc;

	data = lu_cmd->data;
	transfer_len = lu_cmd->transfer_len;
	data_len = lu_cmd->data_len;
	segment_len = conn->MaxRecvDataSegmentLength;

	F_bit = O_bit = U_bit = S_bit = 0;
	if (data_len < transfer_len) {
		/* underflow */
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Underflow %u/%u\n",
		    data_len, transfer_len);
		residual_len = transfer_len - data_len;
		transfer_len = data_len;
		U_bit = 1;
	} else if (data_len > transfer_len) {
		/* overflow */
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Overflow %u/%u\n",
		    data_len, transfer_len);
		residual_len = data_len - transfer_len;
		O_bit = 1;
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Transfer %u\n",
		    transfer_len);
		residual_len = 0;
	}

	task_tag = lu_cmd->task_tag;
	transfer_tag = 0xffffffffU;
	DataSN = 0;
	sent_status = 0;

	/* send data splitted by segment_len */
	for (offset = 0; offset < transfer_len; offset += segment_len) {
		len = DMIN32(segment_len, (transfer_len - offset));

		if (offset + len > transfer_len) {
			ISTGT_ERRLOG("transfer missing\n");
			return -1;
		} else if (offset + len == transfer_len) {
			/* final PDU */
			F_bit = 1;
			S_bit = 0;
			if (lu_cmd->sense_data_len == 0
			    && (lu_cmd->status == ISTGT_SCSI_STATUS_GOOD
				|| lu_cmd->status == ISTGT_SCSI_STATUS_CONDITION_MET
				|| lu_cmd->status == ISTGT_SCSI_STATUS_INTERMEDIATE
				|| lu_cmd->status == ISTGT_SCSI_STATUS_INTERMEDIATE_CONDITION_MET)) {
				S_bit = 1;
				sent_status = 1;
			}
		} else {
			F_bit = 0;
			S_bit = 0;
		}

		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "Transfer=%d, Offset=%d, Len=%d\n",
		    transfer_len, offset, len);
		ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
		    "StatSN=%u, DataSN=%u, Offset=%u, Len=%d\n",
		    conn->StatSN, DataSN, offset, len);

		/* DATA PDU */
		rsp = (uint8_t *) &rsp_pdu.bhs;
		rsp_pdu.data = data + offset;
		memset(rsp, 0, ISCSI_BHS_LEN);
		rsp[0] = ISCSI_OP_SCSI_DATAIN;
		BDADD8(&rsp[1], F_bit, 7);
		BDADD8(&rsp[1], 0, 6); // A_bit Acknowledge
		if (F_bit && S_bit)  {
			BDADD8(&rsp[1], O_bit, 2);
			BDADD8(&rsp[1], U_bit, 1);
		} else {
			BDADD8(&rsp[1], 0, 2);
			BDADD8(&rsp[1], 0, 1);
		}
		BDADD8(&rsp[1], S_bit, 0);
		if (S_bit) {
			rsp[3] = lu_cmd->status;
		} else {
			rsp[3] = 0; // Status or Rsvd
		}
		rsp[4] = 0; // TotalAHSLength
		DSET24(&rsp[5], len); // DataSegmentLength

		DSET32(&rsp[16], task_tag);
		DSET32(&rsp[20], transfer_tag);

		SESS_MTX_LOCK(conn);
		if (S_bit) {
			DSET32(&rsp[24], conn->StatSN);
			conn->StatSN++;
		} else {
			DSET32(&rsp[24], 0); // StatSN or Reserved
		}
		if (F_bit && S_bit && lu_cmd->I_bit == 0) {
			conn->sess->MaxCmdSN++;
		}
		DSET32(&rsp[28], conn->sess->ExpCmdSN);
		DSET32(&rsp[32], conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);

		DSET32(&rsp[36], DataSN);
		DataSN++;

		DSET32(&rsp[40], (uint32_t) offset);
		if (F_bit && S_bit)  {
			DSET32(&rsp[44], residual_len);
		} else {
			DSET32(&rsp[44], 0);
		}

		rc = istgt_iscsi_write_pdu_internal(conn, &rsp_pdu);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_write_pdu() failed\n");
			return -1;
		}
	}

	if (sent_status) {
		return 1;
	}
	return 0;
}

static int
istgt_iscsi_op_scsi(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	ISTGT_LU_CMD lu_cmd;
	ISCSI_PDU rsp_pdu;
	uint8_t *rsp;
	uint8_t *cp;
	uint8_t *data;
	uint8_t *cdb;
	uint64_t lun;
	uint32_t task_tag;
	uint32_t transfer_len;
	uint32_t CmdSN;
	uint32_t ExpStatSN;
	size_t bidi_residual_len;
	size_t residual_len;
	size_t data_len;
	size_t alloc_len;
	int I_bit, F_bit, R_bit, W_bit, Attr_bit;
	int o_bit, u_bit, O_bit, U_bit;
	int rc;

	if (!conn->full_feature) {
		ISTGT_ERRLOG("before Full Feature\n");
		return -1;
	}

	data_len = 0;
	alloc_len = conn->sendbufsize;
	data = (uint8_t *) conn->sendbuf;
	memset(data, 0, alloc_len);
	memset(&lu_cmd, 0, sizeof lu_cmd);

	cp = (uint8_t *) &pdu->bhs;
	I_bit = BGET8(&cp[0], 6);
	F_bit = BGET8(&cp[1], 7);
	R_bit = BGET8(&cp[1], 6);
	W_bit = BGET8(&cp[1], 5);
	Attr_bit = BGET8W(&cp[1], 2, 3);

	lun = DGET64(&cp[8]);
	task_tag = DGET32(&cp[16]);
	transfer_len = DGET32(&cp[20]);
	CmdSN = DGET32(&cp[24]);
	ExpStatSN = DGET32(&cp[28]);

	cdb = &cp[32];
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "CDB", cdb, 16);
#if 0
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "PDU", cp, ISCSI_BHS_LEN);
#endif

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "I=%d, F=%d, R=%d, W=%d, Attr=%d, ITT=%x, TL=%u\n",
	    I_bit, F_bit, R_bit, W_bit, Attr_bit,
	    task_tag, transfer_len);
	SESS_MTX_LOCK(conn);
	ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
	    "CmdSN=%u, ExpStatSN=%u, StatSN=%u, ExpCmdSN=%u, MaxCmdSN=%u\n",
	    CmdSN, ExpStatSN, conn->StatSN, conn->sess->ExpCmdSN,
	    conn->sess->MaxCmdSN);
	if (I_bit == 0) {
		/* XXX MCS reverse order? */
		if (SN32_GT(CmdSN, conn->sess->ExpCmdSN)) {
			if (conn->sess->connections > 1) {
				struct timespec abstime;
				time_t start, now;

				SESS_MTX_UNLOCK(conn);
				start = now = time(NULL);
				memset(&abstime, 0, sizeof abstime);
				abstime.tv_sec = now + (MAX_MCSREVWAIT / 1000);
				abstime.tv_nsec = (MAX_MCSREVWAIT % 1000) * 1000000;

				rc = 0;
				SESS_MTX_LOCK(conn);
				while (SN32_GT(CmdSN, conn->sess->ExpCmdSN)) {
					conn->sess->req_mcs_cond++;
					rc = pthread_cond_timedwait(&conn->sess->mcs_cond,
					    &conn->sess->mutex,
					    &abstime);
					if (rc == ETIMEDOUT) {
						if (SN32_GT(CmdSN, conn->sess->ExpCmdSN)) {
							rc = -1;
							/* timeout */
							break;
						}
						/* OK cond */
						rc = 0;
						break;
					}
					if (rc != 0) {
						break;
					}
				}
				if (rc < 0) {
					now = time(NULL);
					ISTGT_ERRLOG("MCS: CmdSN(%u) error ExpCmdSN=%u "
					    "(time=%d)\n",
					    CmdSN, conn->sess->ExpCmdSN,
					    istgt_difftime(now, start));
					SESS_MTX_UNLOCK(conn);
					return -1;
				}
#if 0
				ISTGT_WARNLOG("MCS: reverse CmdSN=%u(retry=%d, yields=%d)\n",
				    CmdSN, retry, try_yields);
#endif
			}
		}
	}

	if (I_bit == 0) {
		if (SN32_LT(CmdSN, conn->sess->ExpCmdSN)
		    || SN32_GT(CmdSN, conn->sess->MaxCmdSN)) {
			ISTGT_ERRLOG("CmdSN(%u) ignore (ExpCmdSN=%u, MaxCmdSN=%u)\n",
			    CmdSN, conn->sess->ExpCmdSN,
			    conn->sess->MaxCmdSN);
			SESS_MTX_UNLOCK(conn);
			return -1;
		}
		if (SN32_GT(CmdSN, conn->sess->ExpCmdSN)) {
			ISTGT_WARNLOG("CmdSN(%u) > ExpCmdSN(%u)\n",
			    CmdSN, conn->sess->ExpCmdSN);
			conn->sess->ExpCmdSN = CmdSN;
		}
	} else if (CmdSN != conn->sess->ExpCmdSN) {
		SESS_MTX_UNLOCK(conn);
		ISTGT_ERRLOG("CmdSN(%u) error ExpCmdSN=%u\n",
		    CmdSN, conn->sess->ExpCmdSN);
		return -1;
	}
	if (SN32_GT(ExpStatSN, conn->StatSN)) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "StatSN(%u) advanced\n",
		    ExpStatSN);
		conn->StatSN = ExpStatSN;
	}
	{
		uint32_t QCmdSN;
		//SESS_MTX_LOCK(conn);
		QCmdSN = conn->sess->MaxCmdSN - conn->sess->ExpCmdSN + 1;
		//SESS_MTX_UNLOCK(conn);
		QCmdSN += conn->queue_depth;
		if (SN32_LT(ExpStatSN + QCmdSN, conn->StatSN)) {
			ISTGT_ERRLOG("StatSN(%u/%u) QCmdSN(%u) error\n",
			    ExpStatSN, conn->StatSN, QCmdSN);
			SESS_MTX_UNLOCK(conn);
			return -1;
		}
	}
	SESS_MTX_UNLOCK(conn);

	lu_cmd.pdu = pdu;
	SESS_MTX_LOCK(conn);
	lu_cmd.lu = conn->sess->lu;
	if (I_bit == 0) {
		conn->sess->ExpCmdSN++;
		if (conn->sess->req_mcs_cond > 0) {
			conn->sess->req_mcs_cond--;
			rc = pthread_cond_broadcast(&conn->sess->mcs_cond);
			if (rc != 0) {
				SESS_MTX_UNLOCK(conn);
				ISTGT_ERRLOG("cond_broadcast() failed\n");
				return -1;
			}
		}
	}
	SESS_MTX_UNLOCK(conn);

	if (R_bit != 0 && W_bit != 0) {
		ISTGT_ERRLOG("Bidirectional CDB is not supported\n");
		return -1;
	}

	lu_cmd.I_bit = I_bit;
	lu_cmd.F_bit = F_bit;
	lu_cmd.R_bit = R_bit;
	lu_cmd.W_bit = W_bit;
	lu_cmd.Attr_bit = Attr_bit;
	lu_cmd.lun = lun;
	lu_cmd.task_tag = task_tag;
	lu_cmd.transfer_len = transfer_len;
	lu_cmd.CmdSN = CmdSN;
	lu_cmd.cdb = cdb;

	lu_cmd.iobuf = conn->iobuf;
	lu_cmd.iobufsize = conn->iobufsize;
	lu_cmd.data = data;
	lu_cmd.data_len = 0;
	lu_cmd.alloc_len = alloc_len;
	lu_cmd.sense_data = conn->snsbuf;
	lu_cmd.sense_data_len = 0;
	lu_cmd.sense_alloc_len = conn->snsbufsize;

	/* need R2T? */
	if ((W_bit && F_bit) && (conn->max_r2t > 0)) {
		if (lu_cmd.pdu->data_segment_len < transfer_len) {
			rc = istgt_add_transfer_task(conn, &lu_cmd);
			if (rc < 0) {
				ISTGT_ERRLOG("add_transfer_task() failed\n");
				return -1;
			}
		}
	}

	/* execute SCSI command */
	rc = istgt_lu_execute(conn, &lu_cmd);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_execute() failed\n");
		return -1;
	}
	switch (rc) {
	case ISTGT_LU_TASK_RESULT_QUEUE_OK:
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Queue OK\n");
		return 0;
	case ISTGT_LU_TASK_RESULT_QUEUE_FULL:
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Queue Full\n");
		ISTGT_WARNLOG("Queue Full\n");
		break;
	case ISTGT_LU_TASK_RESULT_IMMEDIATE:
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Immediate\n");
		break;
	default:
		ISTGT_ERRLOG("lu_execute() unknown rc=%d\n", rc);
		return -1;
	}

	/* transfer data from logical unit */
	/* (direction is view of initiator side) */
	if (lu_cmd.R_bit
		&& (lu_cmd.status == ISTGT_SCSI_STATUS_GOOD
		    || lu_cmd.sense_data_len != 0)) {
		rc = istgt_iscsi_transfer_in(conn, &lu_cmd);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_transfer_in() failed\n");
			return -1;
		}
		if (rc > 0) {
			/* sent status by last DATAIN PDU */
			return 0;
		}
	}

	o_bit = u_bit = O_bit = U_bit = 0;
	bidi_residual_len = residual_len = 0;
	data_len = lu_cmd.data_len;
	if (transfer_len != 0
		&& lu_cmd.status == ISTGT_SCSI_STATUS_GOOD) {
		if (data_len < transfer_len) {
			/* underflow */
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Underflow %zu/%u\n",
			    data_len, transfer_len);
			residual_len = transfer_len - data_len;
			U_bit = 1;
		} else if (data_len > transfer_len) {
			/* overflow */
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Overflow %zu/%u\n",
			    data_len, transfer_len);
			residual_len = data_len - transfer_len;
			O_bit = 1;
		} else {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Transfer %u\n",
			    transfer_len);
		}
	}

	/* response PDU */
	rsp = (uint8_t *) &rsp_pdu.bhs;
	rsp_pdu.data = lu_cmd.sense_data;
	memset(rsp, 0, ISCSI_BHS_LEN);
	rsp[0] = ISCSI_OP_SCSI_RSP;
	BDADD8(&rsp[1], 1, 7);
	BDADD8(&rsp[1], o_bit, 4);
	BDADD8(&rsp[1], u_bit, 3);
	BDADD8(&rsp[1], O_bit, 2);
	BDADD8(&rsp[1], U_bit, 1);
	rsp[2] = 0x00; // Command Completed at Target
	//rsp[2] = 0x01; // Target Failure
	rsp[3] = lu_cmd.status;
	rsp[4] = 0; // TotalAHSLength
	DSET24(&rsp[5], lu_cmd.sense_data_len); // DataSegmentLength

	DSET32(&rsp[16], task_tag);
	DSET32(&rsp[20], 0); // SNACK Tag

	SESS_MTX_LOCK(conn);
	DSET32(&rsp[24], conn->StatSN);
	conn->StatSN++;
	if (I_bit == 0) {
		conn->sess->MaxCmdSN++;
	}
	DSET32(&rsp[28], conn->sess->ExpCmdSN);
	DSET32(&rsp[32], conn->sess->MaxCmdSN);
	SESS_MTX_UNLOCK(conn);

	DSET32(&rsp[36], 0); // ExpDataSN
	DSET32(&rsp[40], bidi_residual_len);
	DSET32(&rsp[44], residual_len);

	rc = istgt_iscsi_write_pdu(conn, &rsp_pdu);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_write_pdu() failed\n");
		return -1;
	}

	return 0;
}

static int
istgt_iscsi_task_transfer_out(CONN_Ptr conn, ISTGT_LU_TASK_Ptr lu_task)
{
	ISTGT_LU_CMD_Ptr lu_cmd;
	uint32_t transfer_len;
	int rc;

	lu_cmd = &lu_task->lu_cmd;
	transfer_len = lu_cmd->transfer_len;

	rc = istgt_iscsi_transfer_out(conn, lu_cmd, lu_cmd->iobuf,
	    lu_cmd->iobufsize, transfer_len);
	return rc;
}

static int
istgt_iscsi_task_response(CONN_Ptr conn, ISTGT_LU_TASK_Ptr lu_task)
{
	ISTGT_LU_CMD_Ptr lu_cmd;
	ISCSI_PDU rsp_pdu;
	uint8_t *rsp;
	uint32_t task_tag;
	uint32_t transfer_len;
	uint32_t CmdSN;
	size_t residual_len;
	size_t data_len;
	int I_bit;
	int o_bit, u_bit, O_bit, U_bit;
	int bidi_residual_len;
	int rc;

	lu_cmd = &lu_task->lu_cmd;
	transfer_len = lu_cmd->transfer_len;
	task_tag = lu_cmd->task_tag;
	I_bit = lu_cmd->I_bit;
	CmdSN = lu_cmd->CmdSN;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "SCSI response CmdSN=%u\n", CmdSN);

	/* transfer data from logical unit */
	/* (direction is view of initiator side) */
	if (lu_cmd->R_bit
	    && (lu_cmd->status == ISTGT_SCSI_STATUS_GOOD
		|| lu_cmd->sense_data_len != 0)) {
		if (lu_task->lock) {
			rc = istgt_iscsi_transfer_in_internal(conn, lu_cmd);
		} else {
			rc = istgt_iscsi_transfer_in(conn, lu_cmd);
		}
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_transfer_in() failed\n");
			return -1;
		}
		if (rc > 0) {
			/* sent status by last DATAIN PDU */
			return 0;
		}
	}

	o_bit = u_bit = O_bit = U_bit = 0;
	bidi_residual_len = residual_len = 0;
	data_len = lu_cmd->data_len;
	if (transfer_len != 0
	    && lu_cmd->status == ISTGT_SCSI_STATUS_GOOD) {
		if (data_len < transfer_len) {
			/* underflow */
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Underflow %zu/%u\n",
			    data_len, transfer_len);
			residual_len = transfer_len - data_len;
			U_bit = 1;
		} else if (data_len > transfer_len) {
			/* overflow */
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Overflow %zu/%u\n",
			    data_len, transfer_len);
			residual_len = data_len - transfer_len;
			O_bit = 1;
		} else {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Transfer %u\n",
			    transfer_len);
		}
	}

	/* response PDU */
	rsp = (uint8_t *) &rsp_pdu.bhs;
	rsp_pdu.data = lu_cmd->sense_data;
	memset(rsp, 0, ISCSI_BHS_LEN);
	rsp[0] = ISCSI_OP_SCSI_RSP;
	BDADD8(&rsp[1], 1, 7);
	BDADD8(&rsp[1], o_bit, 4);
	BDADD8(&rsp[1], u_bit, 3);
	BDADD8(&rsp[1], O_bit, 2);
	BDADD8(&rsp[1], U_bit, 1);
	rsp[2] = 0x00; // Command Completed at Target
	//rsp[2] = 0x01; // Target Failure
	rsp[3] = lu_cmd->status;
	rsp[4] = 0; // TotalAHSLength
	DSET24(&rsp[5], lu_cmd->sense_data_len); // DataSegmentLength

	DSET32(&rsp[16], task_tag);
	DSET32(&rsp[20], 0); // SNACK Tag

	SESS_MTX_LOCK(conn);
	DSET32(&rsp[24], conn->StatSN);
	conn->StatSN++;
	if (I_bit == 0) {
		conn->sess->MaxCmdSN++;
	}
	DSET32(&rsp[28], conn->sess->ExpCmdSN);
	DSET32(&rsp[32], conn->sess->MaxCmdSN);
	SESS_MTX_UNLOCK(conn);

	DSET32(&rsp[36], 0); // ExpDataSN
	DSET32(&rsp[40], bidi_residual_len);
	DSET32(&rsp[44], residual_len);

	if (lu_task->lock) {
		rc = istgt_iscsi_write_pdu_internal(conn, &rsp_pdu);
	} else {
		rc = istgt_iscsi_write_pdu(conn, &rsp_pdu);
	}
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_write_pdu() failed\n");
		return -1;
	}

	return 0;
}

static int
istgt_iscsi_op_task(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	ISCSI_PDU rsp_pdu;
	uint8_t *rsp;
	uint8_t *cp;
	uint64_t lun;
	uint32_t task_tag;
	uint32_t ref_task_tag;
	uint32_t CmdSN;
	uint32_t ExpStatSN;
	uint32_t ref_CmdSN;
	uint32_t ExpDataSN;
	int I_bit;
	int function;
	int response;
	int rc;

	if (!conn->full_feature) {
		ISTGT_ERRLOG("before Full Feature\n");
		return -1;
	}

	cp = (uint8_t *) &pdu->bhs;
	I_bit = BGET8(&cp[0], 6);
	function = BGET8W(&cp[1], 6, 7);

	lun = DGET64(&cp[8]);
	task_tag = DGET32(&cp[16]);
	ref_task_tag = DGET32(&cp[20]);
	CmdSN = DGET32(&cp[24]);
	ExpStatSN = DGET32(&cp[28]);
	ref_CmdSN = DGET32(&cp[32]);
	ExpDataSN = DGET32(&cp[36]);

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "I=%d, func=%d, ITT=%x, ref TT=%x, LUN=0x%16.16"PRIx64"\n",
	    I_bit, function, task_tag, ref_task_tag, lun);
	SESS_MTX_LOCK(conn);
	ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
	    "CmdSN=%u, ExpStatSN=%u, StatSN=%u, ExpCmdSN=%u, MaxCmdSN=%u\n",
	    CmdSN, ExpStatSN, conn->StatSN, conn->sess->ExpCmdSN,
	    conn->sess->MaxCmdSN);
	if (CmdSN != conn->sess->ExpCmdSN) {
		ISTGT_WARNLOG("CmdSN(%u) might have dropped\n",
		    conn->sess->ExpCmdSN);
		conn->sess->ExpCmdSN = CmdSN;
	}
	if (SN32_GT(ExpStatSN, conn->StatSN)) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "StatSN(%u) advanced\n",
		    ExpStatSN);
		conn->StatSN = ExpStatSN;
	}
#if 0
	/* not need */
	if (ExpStatSN != conn->StatSN) {
		ISTGT_WARNLOG("StatSN(%u/%u) might have dropped\n",
		    ExpStatSN, conn->StatSN);
		conn->StatSN = ExpStatSN;
	}
#endif
	SESS_MTX_UNLOCK(conn);

	response = 0; // Function complete.
	switch (function) {
	case ISCSI_TASK_FUNC_ABORT_TASK:
		ISTGT_LOG("ABORT_TASK\n");
		SESS_MTX_LOCK(conn);
		rc = istgt_lu_clear_task_ITLQ(conn, conn->sess->lu, lun,
		    ref_CmdSN);
		SESS_MTX_UNLOCK(conn);
		if (rc < 0) {
			ISTGT_ERRLOG("LU reset failed\n");
		}
		istgt_clear_transfer_task(conn, ref_CmdSN);
		break;
	case ISCSI_TASK_FUNC_ABORT_TASK_SET:
		ISTGT_LOG("ABORT_TASK_SET\n");
		SESS_MTX_LOCK(conn);
		rc = istgt_lu_clear_task_ITL(conn, conn->sess->lu, lun);
		SESS_MTX_UNLOCK(conn);
		if (rc < 0) {
			ISTGT_ERRLOG("LU reset failed\n");
		}
		istgt_clear_all_transfer_task(conn);
		break;
	case ISCSI_TASK_FUNC_CLEAR_ACA:
		ISTGT_LOG("CLEAR_ACA\n");
		break;
	case ISCSI_TASK_FUNC_CLEAR_TASK_SET:
		ISTGT_LOG("CLEAR_TASK_SET\n");
		SESS_MTX_LOCK(conn);
		rc = istgt_lu_clear_task_ITL(conn, conn->sess->lu, lun);
		SESS_MTX_UNLOCK(conn);
		if (rc < 0) {
			ISTGT_ERRLOG("LU reset failed\n");
		}
		istgt_clear_all_transfer_task(conn);
		break;
	case ISCSI_TASK_FUNC_LOGICAL_UNIT_RESET:
		ISTGT_LOG("LOGICAL_UNIT_RESET\n");
		istgt_iscsi_drop_all_conns(conn);
		SESS_MTX_LOCK(conn);
		rc = istgt_lu_reset(conn->sess->lu, lun);
		SESS_MTX_UNLOCK(conn);
		if (rc < 0) {
			ISTGT_ERRLOG("LU reset failed\n");
		}
		//conn->state = CONN_STATE_EXITING;
		break;
	case ISCSI_TASK_FUNC_TARGET_WARM_RESET:
		ISTGT_LOG("TARGET_WARM_RESET\n");
		istgt_iscsi_drop_all_conns(conn);
		SESS_MTX_LOCK(conn);
		rc = istgt_lu_reset(conn->sess->lu, lun);
		SESS_MTX_UNLOCK(conn);
		if (rc < 0) {
			ISTGT_ERRLOG("LU reset failed\n");
		}
		//conn->state = CONN_STATE_EXITING;
		break;
	case ISCSI_TASK_FUNC_TARGET_COLD_RESET:
		ISTGT_LOG("TARGET_COLD_RESET\n");
		istgt_iscsi_drop_all_conns(conn);
		SESS_MTX_LOCK(conn);
		rc = istgt_lu_reset(conn->sess->lu, lun);
		SESS_MTX_UNLOCK(conn);
		if (rc < 0) {
			ISTGT_ERRLOG("LU reset failed\n");
		}
		conn->state = CONN_STATE_EXITING;
		break;
	case ISCSI_TASK_FUNC_TASK_REASSIGN:
		ISTGT_LOG("TASK_REASSIGN\n");
		break;
	default:
		ISTGT_ERRLOG("unsupported function %d\n", function);
		response = 255; // Function rejected.
		break;
	}

	/* response PDU */
	rsp = (uint8_t *) &rsp_pdu.bhs;
	rsp_pdu.data = NULL;
	memset(rsp, 0, ISCSI_BHS_LEN);
	rsp[0] = ISCSI_OP_TASK_RSP;
	BDADD8(&rsp[1], 1, 7);
	rsp[2] = response;
	rsp[4] = 0; // TotalAHSLength
	DSET24(&rsp[5], 0); // DataSegmentLength

	DSET32(&rsp[16], task_tag);

	if (conn->use_sender == 0) {
		SESS_MTX_LOCK(conn);
		DSET32(&rsp[24], conn->StatSN);
		conn->StatSN++;
		if (I_bit == 0) {
			conn->sess->ExpCmdSN++;
			conn->sess->MaxCmdSN++;
		}
		DSET32(&rsp[28], conn->sess->ExpCmdSN);
		DSET32(&rsp[32], conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);
	} else {
		// update by sender
	}

	rc = istgt_iscsi_write_pdu_upd(conn, &rsp_pdu, I_bit);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_write_pdu() failed\n");
		return -1;
	}

	return 0;
}

static int
istgt_iscsi_op_nopout(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	ISCSI_PDU rsp_pdu;
	uint8_t *rsp;
	uint8_t *cp;
	uint8_t *data;
	uint64_t lun;
	uint32_t task_tag;
	uint32_t transfer_tag;
	uint32_t CmdSN;
	uint32_t ExpStatSN;
	int I_bit;
	int ping_len;
	int data_len;
	int alloc_len;
	int rc;

	if (!conn->full_feature) {
		ISTGT_ERRLOG("before Full Feature\n");
		return -1;
	}

	data_len = 0;
	alloc_len = conn->sendbufsize;
	data = (uint8_t *) conn->sendbuf;
	memset(data, 0, alloc_len);

	cp = (uint8_t *) &pdu->bhs;
	I_bit = BGET8(&cp[0], 6);
	ping_len = DGET24(&cp[5]);

	lun = DGET64(&cp[8]);
	task_tag = DGET32(&cp[16]);
	transfer_tag = DGET32(&cp[20]);
	CmdSN = DGET32(&cp[24]);
	ExpStatSN = DGET32(&cp[28]);

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "I=%d, ITT=%x, TTT=%x\n",
	    I_bit, task_tag, transfer_tag);
	SESS_MTX_LOCK(conn);
	ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
	    "CmdSN=%u, ExpStatSN=%u, StatSN=%u, ExpCmdSN=%u, MaxCmdSN=%u\n",
	    CmdSN, ExpStatSN, conn->StatSN, conn->sess->ExpCmdSN,
	    conn->sess->MaxCmdSN);
	if (I_bit == 0) {
		if (SN32_LT(CmdSN, conn->sess->ExpCmdSN)
		    || SN32_GT(CmdSN, conn->sess->MaxCmdSN)) {
			ISTGT_ERRLOG("CmdSN(%u) ignore (ExpCmdSN=%u, MaxCmdSN=%u)\n",
			    CmdSN, conn->sess->ExpCmdSN,
			    conn->sess->MaxCmdSN);
			SESS_MTX_UNLOCK(conn);
			return -1;
		}
	} else if (CmdSN != conn->sess->ExpCmdSN) {
		SESS_MTX_UNLOCK(conn);
		ISTGT_ERRLOG("CmdSN(%u) error ExpCmdSN=%u\n",
		    CmdSN, conn->sess->ExpCmdSN);
		return -1;
	}
	if (SN32_GT(ExpStatSN, conn->StatSN)) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "StatSN(%u) advanced\n",
		    ExpStatSN);
		conn->StatSN = ExpStatSN;
	}
	{
		uint32_t QCmdSN;
		//SESS_MTX_LOCK(conn);
		QCmdSN = conn->sess->MaxCmdSN - conn->sess->ExpCmdSN + 1;
		//SESS_MTX_UNLOCK(conn);
		QCmdSN += conn->queue_depth;
		if (SN32_LT(ExpStatSN + QCmdSN, conn->StatSN)) {
			ISTGT_ERRLOG("StatSN(%u/%u) QCmdSN(%u) error\n",
			    ExpStatSN, conn->StatSN, QCmdSN);
			SESS_MTX_UNLOCK(conn);
			return -1;
		}
	}
	SESS_MTX_UNLOCK(conn);

	if (task_tag == 0xffffffffU) {
		if (I_bit == 1) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "got NOPOUT ITT=0xffffffff\n");
			return 0;
		} else {
			ISTGT_ERRLOG("got NOPOUT ITT=0xffffffff, I=0\n");
			return -1;
		}
	}

	/* response of NOPOUT */
	if (ping_len != 0) {
		if (ping_len > alloc_len) {
			data_len = DMIN32(alloc_len,
			    conn->MaxRecvDataSegmentLength);
		} else {
			data_len = DMIN32(ping_len,
			    conn->MaxRecvDataSegmentLength);
		}
		/* ping data */
		memcpy(data, pdu->data, data_len);
	}
	transfer_tag = 0xffffffffU;

	/* response PDU */
	rsp = (uint8_t *) &rsp_pdu.bhs;
	rsp_pdu.data = data;
	memset(rsp, 0, ISCSI_BHS_LEN);
	rsp[0] = ISCSI_OP_NOPIN;
	BDADD8(&rsp[1], 1, 7);
	rsp[4] = 0; // TotalAHSLength
	DSET24(&rsp[5], data_len); // DataSegmentLength

	DSET64(&rsp[8], lun);
	DSET32(&rsp[16], task_tag);
	DSET32(&rsp[20], transfer_tag);

	if (conn->use_sender == 0) {
		SESS_MTX_LOCK(conn);
		DSET32(&rsp[24], conn->StatSN);
		conn->StatSN++;
		if (I_bit == 0) {
			conn->sess->ExpCmdSN++;
			conn->sess->MaxCmdSN++;
		}
		DSET32(&rsp[28], conn->sess->ExpCmdSN);
		DSET32(&rsp[32], conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);
	} else {
		// update by sender
	}

	rc = istgt_iscsi_write_pdu_upd(conn, &rsp_pdu, I_bit);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_write_pdu() failed\n");
		return -1;
	}

	return 0;
}

static ISTGT_R2T_TASK_Ptr
istgt_allocate_transfer_task(void)
{
	ISTGT_R2T_TASK_Ptr r2t_task;

	r2t_task = xmalloc(sizeof *r2t_task);
	memset(r2t_task, 0, sizeof *r2t_task);
	r2t_task->conn = NULL;
	r2t_task->lu = NULL;
	r2t_task->iobuf = NULL;
	return r2t_task;
}

static void
istgt_free_transfer_task(ISTGT_R2T_TASK_Ptr r2t_task)
{
	if (r2t_task == NULL)
		return;
	xfree(r2t_task->iobuf);
	xfree(r2t_task);
}

static ISTGT_R2T_TASK_Ptr
istgt_get_transfer_task(CONN_Ptr conn, uint32_t transfer_tag)
{
	ISTGT_R2T_TASK_Ptr r2t_task;
	int i;

	MTX_LOCK(&conn->r2t_mutex);
	if (conn->pending_r2t == 0) {
		MTX_UNLOCK(&conn->r2t_mutex);
		return NULL;
	}
	for (i = 0; i < conn->pending_r2t; i++) {
		r2t_task = conn->r2t_tasks[i];
#if 0
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "CmdSN=%d, TransferTag=%x/%x\n",
		    r2t_task->CmdSN, r2t_task->transfer_tag, transfer_tag);
#endif
		if (r2t_task->transfer_tag == transfer_tag) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "Match index=%d, CmdSN=%d, TransferTag=%x\n",
			    i, r2t_task->CmdSN, r2t_task->transfer_tag);
			MTX_UNLOCK(&conn->r2t_mutex);
			return r2t_task;
		}
	}
	MTX_UNLOCK(&conn->r2t_mutex);
	return NULL;
}

static int
istgt_add_transfer_task(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	ISTGT_R2T_TASK_Ptr r2t_task;
	uint32_t transfer_len;
	uint32_t transfer_tag;
	size_t first_burst_len;
	size_t max_burst_len;
	size_t data_len;
	size_t offset = 0;
	int len;
	int idx;
	int rc;

	MTX_LOCK(&conn->r2t_mutex);
	if (conn->pending_r2t >= conn->max_r2t) {
		// no slot available, skip now...
		//ISTGT_WARNLOG("No R2T space available (%d/%d)\n",
		//    conn->pending_r2t, conn->max_r2t);
		MTX_UNLOCK(&conn->r2t_mutex);
		return 0;
	}
	MTX_UNLOCK(&conn->r2t_mutex);

	transfer_len = lu_cmd->transfer_len;
	transfer_tag = lu_cmd->task_tag;
	data_len = lu_cmd->pdu->data_segment_len;
	first_burst_len = conn->FirstBurstLength;
	max_burst_len = conn->MaxBurstLength;
	offset += data_len;
	if (offset >= first_burst_len) {
		len = DMIN32(max_burst_len, (transfer_len - offset));

		r2t_task = istgt_allocate_transfer_task();
		r2t_task->conn = conn;
		r2t_task->lu = lu_cmd->lu;
		r2t_task->lun = lu_cmd->lun;
		r2t_task->CmdSN = lu_cmd->CmdSN;
		r2t_task->task_tag = lu_cmd->task_tag;
		r2t_task->transfer_len = transfer_len;
		r2t_task->transfer_tag = transfer_tag;

		r2t_task->iobufsize = lu_cmd->transfer_len + 65536;
		r2t_task->iobuf = xmalloc(r2t_task->iobufsize);
		memcpy(r2t_task->iobuf, lu_cmd->pdu->data, data_len);
		r2t_task->offset = offset;
		r2t_task->R2TSN = 0;
		r2t_task->DataSN = 0;
		r2t_task->F_bit = lu_cmd->F_bit;

		MTX_LOCK(&conn->r2t_mutex);
		idx = conn->pending_r2t++;
		conn->r2t_tasks[idx] = r2t_task;
		MTX_UNLOCK(&conn->r2t_mutex);

		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "Send R2T(Offset=%d, Tag=%x)\n",
		    r2t_task->offset, r2t_task->transfer_tag);
		rc = istgt_iscsi_send_r2t(conn, lu_cmd,
		    r2t_task->offset, len, r2t_task->transfer_tag,
		    &r2t_task->R2TSN);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_send_r2t() failed\n");
			return -1;
		}
	}
	return 0;
}

static void
istgt_del_transfer_task(CONN_Ptr conn, ISTGT_R2T_TASK_Ptr r2t_task)
{
	int found = 0;
	int i;

	if (r2t_task == NULL)
		return;

	MTX_LOCK(&conn->r2t_mutex);
	if (conn->pending_r2t == 0) {
		MTX_UNLOCK(&conn->r2t_mutex);
		return;
	}
	for (i = 0; i < conn->pending_r2t; i++) {
		if (conn->r2t_tasks[i] == r2t_task) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "Remove R2T task conn id=%d, index=%d\n",
			    conn->id, i);
			found = 1;
			break;
		}
	}
	if (found) {
		for ( ; i < conn->pending_r2t; i++) {
			conn->r2t_tasks[i] = conn->r2t_tasks[i + 1];
		}
		conn->pending_r2t--;
		conn->r2t_tasks[conn->pending_r2t] = NULL;
	}
	MTX_UNLOCK(&conn->r2t_mutex);
}

static void
istgt_clear_transfer_task(CONN_Ptr conn, uint32_t CmdSN)
{
	int found = 0;
	int i;

	MTX_LOCK(&conn->r2t_mutex);
	if (conn->pending_r2t == 0) {
		MTX_UNLOCK(&conn->r2t_mutex);
		return;
	}
	for (i = 0; i < conn->pending_r2t; i++) {
		if (conn->r2t_tasks[i]->CmdSN == CmdSN) {
			istgt_free_transfer_task(conn->r2t_tasks[i]);
			conn->r2t_tasks[i] = NULL;
			found = 1;
			break;
		}
	}
	if (found) {
		for ( ; i < conn->pending_r2t; i++) {
			conn->r2t_tasks[i] = conn->r2t_tasks[i + 1];
		}
		conn->pending_r2t--;
		conn->r2t_tasks[conn->pending_r2t] = NULL;
	}
	MTX_UNLOCK(&conn->r2t_mutex);
}

static void
istgt_clear_all_transfer_task(CONN_Ptr conn)
{
	int i;

	MTX_LOCK(&conn->r2t_mutex);
	if (conn->pending_r2t == 0) {
		MTX_UNLOCK(&conn->r2t_mutex);
		return;
	}
	for (i = 0; i < conn->pending_r2t; i++) {
		istgt_free_transfer_task(conn->r2t_tasks[i]);
		conn->r2t_tasks[i] = NULL;
	}
	conn->pending_r2t = 0;
	MTX_UNLOCK(&conn->r2t_mutex);
}

static int
istgt_iscsi_op_data(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	ISTGT_R2T_TASK_Ptr r2t_task;
	uint8_t *cp;
	uint8_t *data;
	uint64_t lun;
	uint64_t current_lun;
	uint32_t current_task_tag;
	uint32_t current_transfer_tag;
	uint32_t ExpStatSN;
	uint32_t task_tag;
	uint32_t transfer_tag;
	uint32_t ExpDataSN;
	uint32_t DataSN;
	uint32_t buffer_offset;
	size_t data_len;
	size_t alloc_len;
	size_t offset;
	int F_bit;
	int rc;

	if (!conn->full_feature) {
		ISTGT_ERRLOG("before Full Feature\n");
		return -1;
	}
	MTX_LOCK(&conn->r2t_mutex);
	if (conn->pending_r2t == 0) {
		ISTGT_ERRLOG("No R2T task\n");
		MTX_UNLOCK(&conn->r2t_mutex);
	reject_return:
		rc = istgt_iscsi_reject(conn, pdu, 0x09);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_reject() failed\n");
			return -1;
		}
		return 0;
	}
	MTX_UNLOCK(&conn->r2t_mutex);

	cp = (uint8_t *) &pdu->bhs;
	F_bit = BGET8(&cp[1], 7);
	data_len = DGET24(&cp[5]);

	lun = DGET64(&cp[8]);
	task_tag = DGET32(&cp[16]);
	transfer_tag = DGET32(&cp[20]);
	ExpStatSN = DGET32(&cp[28]);
	DataSN = DGET32(&cp[36]);
	buffer_offset = DGET32(&cp[40]);

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "pending R2T = %d\n", conn->pending_r2t);

	r2t_task = istgt_get_transfer_task(conn, transfer_tag);
	if (r2t_task == NULL) {
		ISTGT_ERRLOG("Not found R2T task for transfer_tag=%x\n",
			transfer_tag);
		goto reject_return;
	}

	current_lun = r2t_task->lun;
	current_task_tag = r2t_task->task_tag;
	current_transfer_tag = r2t_task->transfer_tag;
	offset = r2t_task->offset;
	data = r2t_task->iobuf;
	alloc_len = r2t_task->iobufsize;
	ExpDataSN = r2t_task->DataSN;

	ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
	    "StatSN=%u, ExpStatSN=%u, DataSN=%u, Offset=%u, Data=%zd\n",
	    conn->StatSN, ExpStatSN, DataSN, buffer_offset, data_len);
	if (DataSN != ExpDataSN) {
		ISTGT_ERRLOG("DataSN(%u) error\n", DataSN);
		return -1;
	}
	if (task_tag != current_task_tag) {
		ISTGT_ERRLOG("task_tag(%x/%x) error\n",
		    task_tag, current_task_tag);
		return -1;
	}
	if (transfer_tag != current_transfer_tag) {
		ISTGT_ERRLOG("transfer_tag(%x/%x) error\n",
		    transfer_tag, current_transfer_tag);
		return -1;
	}
	if (buffer_offset != offset) {
		ISTGT_ERRLOG("offset(%u) error\n", buffer_offset);
		return -1;
	}
	if (buffer_offset + data_len > alloc_len) {
		ISTGT_ERRLOG("offset error\n");
		return -1;
	}

	memcpy(data + buffer_offset, pdu->data, data_len);
	offset += data_len;
	ExpDataSN++;

	r2t_task->offset = offset;
	r2t_task->DataSN = ExpDataSN;
	r2t_task->F_bit = F_bit;
	return 0;
}

static int
istgt_iscsi_send_r2t(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, int offset, int len, uint32_t transfer_tag, uint32_t *R2TSN)
{
	ISCSI_PDU rsp_pdu;
	uint8_t *rsp;
	int rc;

	/* R2T PDU */
	rsp = (uint8_t *) &rsp_pdu.bhs;
	rsp_pdu.data = NULL;
	memset(rsp, 0, ISCSI_BHS_LEN);
	rsp[0] = ISCSI_OP_R2T;
	BDADD8(&rsp[1], 1, 7);
	rsp[4] = 0; // TotalAHSLength
	DSET24(&rsp[5], 0); // DataSegmentLength

	DSET64(&rsp[8], lu_cmd->lun);
	DSET32(&rsp[16], lu_cmd->task_tag);
	DSET32(&rsp[20], transfer_tag);

	if (conn->use_sender == 0) {
		SESS_MTX_LOCK(conn);
		DSET32(&rsp[24], conn->StatSN);
		DSET32(&rsp[28], conn->sess->ExpCmdSN);
		DSET32(&rsp[32], conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);
	} else {
		// update by sender
	}

	DSET32(&rsp[36], *R2TSN);
	*R2TSN += 1;
	DSET32(&rsp[40], (uint32_t) offset);
	DSET32(&rsp[44], (uint32_t) len);

	rc = istgt_iscsi_write_pdu_upd(conn, &rsp_pdu, 0);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_write_pdu() failed\n");
		return -1;
	}

	return 0;
}

int
istgt_iscsi_transfer_out(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint8_t *data, size_t alloc_len, size_t transfer_len)
{
	ISTGT_R2T_TASK_Ptr r2t_task;
	ISCSI_PDU data_pdu;
	uint8_t *cp;
	uint64_t current_lun;
	uint64_t lun;
	uint32_t current_task_tag;
	uint32_t current_transfer_tag;
	uint32_t ExpDataSN;
	uint32_t task_tag;
	uint32_t transfer_tag;
	uint32_t ExpStatSN;
	uint32_t DataSN;
	uint32_t buffer_offset;
	uint32_t R2TSN;
	size_t data_len;
	size_t segment_len;
	size_t first_burst_len;
	size_t max_burst_len;
	size_t offset;
	int immediate, opcode;
	int F_bit;
	int len;
	int r2t_flag;
	int r2t_offset;
	int r2t_sent;
	int rc;

	current_lun = lu_cmd->lun;
	current_task_tag = lu_cmd->task_tag;
	current_transfer_tag = lu_cmd->task_tag;
	ExpDataSN = 0;
	segment_len = conn->MaxRecvDataSegmentLength;
	first_burst_len = conn->FirstBurstLength;
	max_burst_len = conn->MaxBurstLength;
	offset = 0;
	r2t_flag = 0;
	r2t_offset = 0;
	r2t_sent = 0;
	R2TSN = 0;

	cp = (uint8_t *) &lu_cmd->pdu->bhs;
	data_len = DGET24(&cp[5]);

	if (transfer_len > alloc_len) {
		ISTGT_ERRLOG("transfer_len > alloc_len\n");
		return -1;
	}

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, 
	    "Transfer=%zd, First=%zd, Max=%zd, Segment=%zd\n",
	    transfer_len, data_len, max_burst_len, segment_len);

	r2t_task = istgt_get_transfer_task(conn, current_transfer_tag);
	if (r2t_task != NULL) {
		current_lun = r2t_task->lun;
		current_task_tag = r2t_task->task_tag;
		current_transfer_tag = r2t_task->transfer_tag;
		offset = r2t_task->offset;
		R2TSN = r2t_task->R2TSN;
		ExpDataSN = r2t_task->DataSN;
		F_bit = r2t_task->F_bit;
		r2t_flag = 1;
		data_len = 0;

		memcpy(data, r2t_task->iobuf, offset);
		istgt_del_transfer_task(conn, r2t_task);
		istgt_free_transfer_task(r2t_task);

		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "Using R2T(%d) offset=%zd, DataSN=%d\n",
		    conn->pending_r2t, offset, ExpDataSN);

		rc = istgt_queue_count(&conn->pending_pdus);
		if (rc > 0) {
			if (g_trace_flag) {
				ISTGT_WARNLOG("pending_pdus > 0\n");
			}
		}
		if (offset < transfer_len) {
			if (offset >= (first_burst_len + max_burst_len)) {
				/* need more data */
				r2t_flag = 0;
			}
			len = DMIN32(max_burst_len,
			    (transfer_len - offset));
			memset(&data_pdu.bhs, 0, ISCSI_BHS_LEN);
			data_pdu.ahs = NULL;
			data_pdu.data = NULL;
			data_pdu.copy_pdu = 0;
			goto r2t_retry;
		} else if (offset == transfer_len) {
			if (F_bit == 0) {
				ISTGT_ERRLOG("F_bit not set on the last PDU\n");
				return -1;
			}
		}
		goto r2t_return;
	}

	if (data_len != 0) {
		if (data_len > first_burst_len) {
			ISTGT_ERRLOG("data_len > first_burst_len\n");
			return -1;
		}
		if (offset + data_len > alloc_len) {
			ISTGT_ERRLOG("offset + data_len > alloc_len\n");
			return -1;
		}
		memcpy(data + offset, lu_cmd->pdu->data, data_len);
		offset += data_len;
		r2t_offset = offset;
	}

	if (offset < transfer_len) {
		len = DMIN32(first_burst_len, (transfer_len - offset));
		memset(&data_pdu.bhs, 0, ISCSI_BHS_LEN);
		data_pdu.ahs = NULL;
		data_pdu.data = NULL;
		data_pdu.copy_pdu = 0;
		do {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "Transfer=%zd, Offset=%zd, Len=%d\n",
			    transfer_len, offset, len);
			/* send R2T if required */
			if (r2t_flag == 0
			    && (conn->sess->initial_r2t || offset >= first_burst_len)) {
				len = DMIN32(max_burst_len,
				    (transfer_len - offset));
				rc = istgt_iscsi_send_r2t(conn, lu_cmd,
				    offset, len, current_transfer_tag, &R2TSN);
				if (rc < 0) {
					ISTGT_ERRLOG("iscsi_send_r2t() failed\n");
				error_return:
					if (data_pdu.copy_pdu == 0) {
						xfree(data_pdu.ahs);
						data_pdu.ahs = NULL;
						if (data_pdu.data
						    != data_pdu.shortdata) {
							xfree(data_pdu.data);
						}
						data_pdu.data = NULL;
					}
					return -1;
				}
				r2t_flag = 1;
				r2t_offset = offset;
				r2t_sent = 1;
				ExpDataSN = 0;
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, 
				    "R2T, Transfer=%zd, Offset=%zd, Len=%d\n",
				    transfer_len, offset, len);
			} else {
				r2t_sent = 0;
			}

			/* transfer by segment_len */
			rc = istgt_iscsi_read_pdu(conn, &data_pdu);
			if (rc < 0) {
				//ISTGT_ERRLOG("iscsi_read_pdu() failed\n");
				ISTGT_ERRLOG("iscsi_read_pdu() failed, r2t_sent=%d\n",
				    r2t_sent);
				goto error_return;
			}
			immediate = BGET8W(&data_pdu.bhs.opcode, 6, 1);
			opcode = BGET8W(&data_pdu.bhs.opcode, 5, 6);

			cp = (uint8_t *) &data_pdu.bhs;
			F_bit = BGET8(&cp[1], 7);
			data_len = DGET24(&cp[5]);

			lun = DGET64(&cp[8]);
			task_tag = DGET32(&cp[16]);
			transfer_tag = DGET32(&cp[20]);
			ExpStatSN = DGET32(&cp[28]);
			DataSN = DGET32(&cp[36]);
			buffer_offset = DGET32(&cp[40]);

			/* current tag DATA? */
			if (opcode == ISCSI_OP_SCSI_DATAOUT) {
				if (task_tag != current_task_tag) {
				not_current_tag:
					//ISTGT_LOG("not task_tag received\n");
					ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
					    "not task_tag received\n");
					rc = istgt_iscsi_op_data(conn,
					    &data_pdu);
					if (rc < 0) {
						ISTGT_ERRLOG("iscsi_op_data() failed\n");
						goto error_return;
					}
					if (data_pdu.data != data_pdu.shortdata) {
						xfree(data_pdu.data);
					}
					data_pdu.ahs = NULL;
					data_pdu.data = NULL;
					data_pdu.copy_pdu = 0;
					continue;
				}
				if (transfer_tag != current_transfer_tag) {
					ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
					    "not transfer_tag received\n");
					goto not_current_tag;
				}
			}

			if (opcode != ISCSI_OP_SCSI_DATAOUT) {
				ISCSI_PDU_Ptr save_pdu;

				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "non DATAOUT PDU received and pending"
				    " (OP=0x%x)\n",
				    opcode);

				rc = istgt_queue_count(&conn->pending_pdus);
				if (rc > conn->max_pending) {
					ISTGT_ERRLOG("pending queue(%d) is full\n",
					    conn->max_pending);
					goto error_return;
				}
				save_pdu = xmalloc(sizeof *save_pdu);
				memset(save_pdu, 0, sizeof *save_pdu);
				rc = istgt_iscsi_copy_pdu(save_pdu, &data_pdu);
				if (rc < 0) {
					ISTGT_ERRLOG("iscsi_copy_pdu() failed\n");
					xfree(save_pdu);
					save_pdu = NULL;
					goto error_return;
				}
				rc = istgt_queue_enqueue(&conn->pending_pdus,
				    save_pdu);
				if (rc < 0) {
					ISTGT_ERRLOG("queue_enqueue() failed\n");
					xfree(save_pdu->ahs);
					save_pdu->ahs = NULL;
					if (save_pdu->data
					    != save_pdu->shortdata) {
						xfree(save_pdu->data);
					}
					save_pdu->data = NULL;
					xfree(save_pdu);
					save_pdu = NULL;
					goto error_return;
				}
				data_pdu.ahs = NULL;
				data_pdu.data = NULL;
				data_pdu.copy_pdu = 0;
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "non DATAOUT PDU pending\n");
				continue;
			}

			ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
			    "StatSN=%u, "
			    "ExpStatSN=%u, DataSN=%u, Offset=%u, Data=%zd\n",
			    conn->StatSN,
			    ExpStatSN, DataSN, buffer_offset, data_len);
			if (DataSN != ExpDataSN) {
				ISTGT_ERRLOG("DataSN(%u) error\n", DataSN);
				goto error_return;
			}
#if 0
			/* not check in DATAOUT */
			if (ExpStatSN != conn->StatSN) {
				ISTGT_ERRLOG("StatSN(%u) error\n",
				    conn->StatSN);
				goto error_return;
			}
#endif

#if 0
			/* not check in DATAOUT */
			if (lun != current_lun) {
#if 0
				ISTGT_ERRLOG("lun(0x%16.16"PRIx64") error\n",
				    lun);
				goto error_return;
#else
				ISTGT_WARNLOG("lun(0x%16.16"PRIx64")\n", lun);
#endif
			}
#endif
			if (task_tag != current_task_tag) {
				ISTGT_ERRLOG("task_tag(%x/%x) error\n",
				    task_tag, current_task_tag);
				goto error_return;
			}
			if (transfer_tag != current_transfer_tag) {
				ISTGT_ERRLOG("transfer_tag(%x/%x) error\n",
				    transfer_tag, current_transfer_tag);
				goto error_return;
			}
			if (buffer_offset != offset) {
				ISTGT_ERRLOG("offset(%u) error\n",
				    buffer_offset);
				goto error_return;
			}
			if (buffer_offset + data_len > alloc_len) {
				ISTGT_ERRLOG("offset error\n");
				goto error_return;
			}

			memcpy(data + buffer_offset, data_pdu.data, data_len);
			offset += data_len;
			len -= data_len;
			ExpDataSN++;

			if (r2t_flag == 0 && (offset > first_burst_len)) {
				ISTGT_ERRLOG("data_len(%zd) > first_burst_length(%zd)",
				    offset, first_burst_len);
				goto error_return;
			}
			if (F_bit != 0 && len != 0) {
				if (offset < transfer_len) {
					r2t_flag = 0;
					goto r2t_retry;
				}
				ISTGT_ERRLOG("Expecting more data %d\n", len);
				goto error_return;
			}
			if (F_bit == 0 && len == 0) {
				ISTGT_ERRLOG("F_bit not set on the last PDU\n");
				goto error_return;
			}
			if (len == 0) {
				r2t_flag = 0;
			}
		r2t_retry:
			if (data_pdu.copy_pdu == 0) {
				xfree(data_pdu.ahs);
				data_pdu.ahs = NULL;
				if (data_pdu.data != data_pdu.shortdata) {
					xfree(data_pdu.data);
				}
				data_pdu.data = NULL;
			}
		} while (offset < transfer_len);

		cp = (uint8_t *) &data_pdu.bhs;
		F_bit = BGET8(&cp[1], 7);
		if (F_bit == 0) {
			ISTGT_ERRLOG("F_bit not set on the last PDU\n");
			return -1;
		}
	} else {
		cp = (uint8_t *) &lu_cmd->pdu->bhs;
		F_bit = BGET8(&cp[1], 7);
		if (F_bit == 0) {
			ISTGT_ERRLOG("F_bit not set on the last PDU\n");
			return -1;
		}
	}

r2t_return:
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Transfered=%zd, Offset=%zd\n",
	    transfer_len, offset);

	return 0;
}

static int
istgt_iscsi_send_nopin(CONN_Ptr conn)
{
	ISCSI_PDU rsp_pdu;
	uint8_t *rsp;
	uint64_t lun;
	uint32_t task_tag;
	uint32_t transfer_tag;
	int rc;

	if (conn->sess == NULL) {
		return 0;
	}
	if (!conn->full_feature) {
		ISTGT_ERRLOG("before Full Feature\n");
		return -1;
	}

	SESS_MTX_LOCK(conn);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "send NOPIN isid=%"PRIx64", tsih=%u, cid=%u\n",
	    conn->sess->isid, conn->sess->tsih, conn->cid);
	ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
	    "StatSN=%u, ExpCmdSN=%u, MaxCmdSN=%u\n",
	    conn->StatSN, conn->sess->ExpCmdSN,
	    conn->sess->MaxCmdSN);
	SESS_MTX_UNLOCK(conn);

	/* without wanting NOPOUT */
	lun = 0;
	task_tag = 0xffffffffU;
	transfer_tag = 0xffffffffU;

	/* response PDU */
	rsp = (uint8_t *) &rsp_pdu.bhs;
	rsp_pdu.data = NULL;
	memset(rsp, 0, ISCSI_BHS_LEN);
	rsp[0] = ISCSI_OP_NOPIN;
	BDADD8(&rsp[1], 1, 7);
	rsp[4] = 0; // TotalAHSLength
	DSET24(&rsp[5], 0); // DataSegmentLength

	DSET64(&rsp[8], lun);
	DSET32(&rsp[16], task_tag);
	DSET32(&rsp[20], transfer_tag);

	if (conn->use_sender == 0) {
		SESS_MTX_LOCK(conn);
		DSET32(&rsp[24], conn->StatSN);
		DSET32(&rsp[28], conn->sess->ExpCmdSN);
		DSET32(&rsp[32], conn->sess->MaxCmdSN);
		SESS_MTX_UNLOCK(conn);
	} else {
		// update by sender
	}

	rc = istgt_iscsi_write_pdu_upd(conn, &rsp_pdu, 0);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_write_pdu() failed\n");
		return -1;
	}

	return 0;
}

static int
istgt_iscsi_execute(CONN_Ptr conn, ISCSI_PDU_Ptr pdu)
{
	int immediate, opcode;
	int rc;

	if (pdu == NULL)
		return -1;

	immediate = BGET8W(&conn->pdu.bhs.opcode, 6, 1);
	opcode = BGET8W(&conn->pdu.bhs.opcode, 5, 6);

	ISTGT_TRACELOG(ISTGT_TRACE_ISCSI, "opcode %x\n", opcode);
	switch(opcode) {
	case ISCSI_OP_NOPOUT:
		rc = istgt_iscsi_op_nopout(conn, pdu);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_op_nopout() failed\n");
			return -1;
		}
		break;

	case ISCSI_OP_SCSI:
		rc = istgt_iscsi_op_scsi(conn, pdu);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_op_scsi() failed\n");
			return -1;
		}
		break;

	case ISCSI_OP_TASK:
		rc = istgt_iscsi_op_task(conn, pdu);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_op_task() failed\n");
			return -1;
		}
		break;

	case ISCSI_OP_LOGIN:
		rc = istgt_iscsi_op_login(conn, pdu);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_op_login() failed\n");
			return -1;
		}
		break;

	case ISCSI_OP_TEXT:
		rc = istgt_iscsi_op_text(conn, pdu);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_op_text() failed\n");
			return -1;
		}
		break;

	case ISCSI_OP_LOGOUT:
		rc = istgt_iscsi_op_logout(conn, pdu);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_op_logout() failed\n");
			return -1;
		}
		break;

	case ISCSI_OP_SCSI_DATAOUT:
		rc = istgt_iscsi_op_data(conn, pdu);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_op_data() failed\n");
			return -1;
		}
		break;

	case ISCSI_OP_SNACK:
		ISTGT_ERRLOG("got SNACK\n");
		goto error_out;
	default:
	error_out:
		ISTGT_ERRLOG("unsupported opcode %x\n", opcode);
		rc = istgt_iscsi_reject(conn, pdu, 0x04);
		if (rc < 0) {
			ISTGT_ERRLOG("iscsi_reject() failed\n");
			return -1;
		}
		break;
	}

	return 0;
}

static void
wait_all_task(CONN_Ptr conn)
{
	ISTGT_LU_TASK_Ptr lu_task;
#ifdef ISTGT_USE_KQUEUE
	int kq;
	struct kevent kev;
	struct timespec kev_timeout;
#else
	struct pollfd fds[1];
#endif /* ISTGT_USE_KQUEUE */
	int msec = 30 * 1000;
	int rc;

	if (conn->running_tasks == 0)
		return;

#ifdef ISTGT_USE_KQUEUE
	kq = kqueue();
	if (kq == -1) {
		ISTGT_ERRLOG("kqueue() failed\n");
		return;
	}
	ISTGT_EV_SET(&kev, conn->task_pipe[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
	rc = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (rc == -1) {
		ISTGT_ERRLOG("kevent() failed\n");
		close(kq);
		return;
	}
#else
	fds[0].fd = conn->task_pipe[0];
	fds[0].events = POLLIN;
#endif /* ISTGT_USE_KQUEUE */

	/* wait all running tasks */
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "waiting task start (%d) (left %d tasks)\n",
	    conn->id, conn->running_tasks);
	while (1) {
#ifdef ISTGT_USE_KQUEUE
		kev_timeout.tv_sec = msec / 1000;
		kev_timeout.tv_nsec = (msec % 1000) * 1000000;
		rc = kevent(kq, NULL, 0, &kev, 1, &kev_timeout);
		if (rc == -1 && errno == EINTR) {
			continue;
		}
		if (rc == -1) {
			ISTGT_ERRLOG("kevent() failed\n");
			break;
		}
		if (rc == 0) {
			ISTGT_ERRLOG("waiting task timeout (left %d tasks)\n",
			    conn->running_tasks);
			break;
		}
#else
		rc = poll(fds, 1, msec);
		if (rc == -1 && errno == EINTR) {
			continue;
		}
		if (rc == -1) {
			ISTGT_ERRLOG("poll() failed\n");
			break;
		}
		if (rc == 0) {
			ISTGT_ERRLOG("waiting task timeout (left %d tasks)\n",
			    conn->running_tasks);
			break;
		}
#endif /* ISTGT_USE_KQUEUE */

#ifdef ISTGT_USE_KQUEUE
		if (kev.ident == (uintptr_t)conn->task_pipe[0]) {
			if (kev.flags & (EV_EOF|EV_ERROR)) {
				break;
			}
#else
		if (fds[0].revents & POLLHUP) {
			break;
		}
		if (fds[0].revents & POLLIN) {
#endif /* ISTGT_USE_KQUEUE */
			char tmp[1];

			rc = read(conn->task_pipe[0], tmp, 1);
			if (rc < 0 || rc == 0 || rc != 1) {
				ISTGT_ERRLOG("read() failed\n");
				break;
			}

			MTX_LOCK(&conn->task_queue_mutex);
			lu_task = istgt_queue_dequeue(&conn->task_queue);
			MTX_UNLOCK(&conn->task_queue_mutex);
			if (lu_task != NULL) {
				if (lu_task->lu_cmd.W_bit) {
					/* write */
					if (lu_task->req_transfer_out != 0) {
						/* error transfer */
						lu_task->error = 1;
						lu_task->abort = 1;
						rc = pthread_cond_broadcast(&lu_task->trans_cond);
						if (rc != 0) {
							ISTGT_ERRLOG("cond_broadcast() failed\n");
							/* ignore error */
						}
					} else {
						if (lu_task->req_execute) {
							conn->running_tasks--;
							if (conn->running_tasks == 0) {
								ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
								    "task cleanup finished\n");
								break;
							}
						}
						/* ignore response */
						rc = istgt_lu_destroy_task(lu_task);
						if (rc < 0) {
							ISTGT_ERRLOG("lu_destroy_task() failed\n");
							/* ignore error */
						}
					}
				} else {
					/* read or no data */
					/* ignore response */
					rc = istgt_lu_destroy_task(lu_task);
					if (rc < 0) {
						ISTGT_ERRLOG("lu_destroy_task() failed\n");
						/* ignore error */
					}
				}
			} else {
				ISTGT_ERRLOG("lu_task is NULL\n");
				break;
			}
		}
	}

	istgt_clear_all_transfer_task(conn);
#ifdef ISTGT_USE_KQUEUE
	close(kq);
#endif /* ISTGT_USE_KQUEUE */
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "waiting task end (%d) (left %d tasks)\n",
	    conn->id, conn->running_tasks);
}

static void
worker_cleanup(void *arg)
{
	CONN_Ptr conn = (CONN_Ptr) arg;
	ISTGT_LU_Ptr lu;
	int rc;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "worker_cleanup\n");
	ISTGT_WARNLOG("force cleanup execute\n");

	/* cleanup */
	pthread_mutex_unlock(&conn->task_queue_mutex);
	pthread_mutex_unlock(&conn->result_queue_mutex);
	if (conn->sess != NULL) {
		if (conn->sess->lu != NULL) {
			pthread_mutex_unlock(&conn->sess->lu->mutex);
		}
		pthread_mutex_unlock(&conn->sess->mutex);
	}
	if (conn->exec_lu_task != NULL) {
		conn->exec_lu_task->error = 1;
		pthread_cond_broadcast(&conn->exec_lu_task->trans_cond);
		pthread_mutex_unlock(&conn->exec_lu_task->trans_mutex);
	}
	pthread_mutex_unlock(&conn->wpdu_mutex);
	pthread_mutex_unlock(&conn->r2t_mutex);
	pthread_mutex_unlock(&conn->istgt->mutex);
	pthread_mutex_unlock(&g_conns_mutex);
	pthread_mutex_unlock(&g_last_tsih_mutex);

	conn->state = CONN_STATE_EXITING;
	if (conn->sess != NULL) {
		SESS_MTX_LOCK(conn);
		lu = conn->sess->lu;
		if (lu != NULL && lu->queue_depth != 0) {
			rc = istgt_lu_clear_task_IT(conn, lu);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_clear_task_IT() failed\n");
			}
			istgt_clear_all_transfer_task(conn);
		}
		SESS_MTX_UNLOCK(conn);
	}
	if (conn->pdu.copy_pdu == 0) {
		xfree(conn->pdu.ahs);
		conn->pdu.ahs = NULL;
		if (conn->pdu.data != conn->pdu.shortdata) {
			xfree(conn->pdu.data);
		}
		conn->pdu.data = NULL;
	}
	wait_all_task(conn);
	if (conn->use_sender) {
		pthread_cond_broadcast(&conn->result_queue_cond);
		pthread_join(conn->sender_thread, NULL);
	}
	close(conn->sock);
#ifdef ISTGT_USE_KQUEUE
	close(conn->kq);
	conn->kq = -1;
#endif /* ISTGT_USE_KQUEUE */
	sleep(1);

	/* cleanup conn & sess */
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "cancel cleanup LOCK\n");
	MTX_LOCK(&g_conns_mutex);
	g_conns[conn->id] = NULL;
	istgt_remove_conn(conn);
	MTX_UNLOCK(&g_conns_mutex);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "cancel cleanup UNLOCK\n");

	return;
}

static void *
sender(void *arg)
{
	CONN_Ptr conn = (CONN_Ptr) arg;
	ISTGT_LU_TASK_Ptr lu_task;
	struct timespec abstime;
	time_t now;
	int rc;

#ifdef HAVE_PTHREAD_SET_NAME_NP
	{
		char buf[MAX_TMPBUF];
		snprintf(buf, sizeof buf, "sendthread #%d", conn->id);
		pthread_set_name_np(conn->sender_thread, buf);
	}
#endif
	memset(&abstime, 0, sizeof abstime);
	/* handle DATA-IN/SCSI status */
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "sender loop start (%d)\n", conn->id);
	//MTX_LOCK(&conn->sender_mutex);
	while (1) {
		if (conn->state != CONN_STATE_RUNNING) {
			break;
		}
		MTX_LOCK(&conn->result_queue_mutex);
		lu_task = istgt_queue_dequeue(&conn->result_queue);
		if (lu_task == NULL) {
			now = time(NULL);
			abstime.tv_sec = now + conn->timeout;
			abstime.tv_nsec = 0;
			rc = pthread_cond_timedwait(&conn->result_queue_cond,
			    &conn->result_queue_mutex, &abstime);
			if (rc == ETIMEDOUT) {
				/* nothing */
			}
			lu_task = istgt_queue_dequeue(&conn->result_queue);
			if (lu_task == NULL) {
				MTX_UNLOCK(&conn->result_queue_mutex);
				continue;
			}
		}
		MTX_UNLOCK(&conn->result_queue_mutex);
		/* send all responses */
//		MTX_LOCK(&conn->wpdu_mutex);
		do {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "task response CmdSN=%u\n", lu_task->lu_cmd.CmdSN);
			lu_task->lock = 1;
			if (lu_task->type == ISTGT_LU_TASK_RESPONSE) {
				/* send DATA-IN, SCSI status */
				rc = istgt_iscsi_task_response(conn, lu_task);
				if (rc < 0) {
					lu_task->error = 1;
					ISTGT_ERRLOG(
						"iscsi_task_response() CmdSN=%u failed"
						" on %s(%s)\n", lu_task->lu_cmd.CmdSN,
						conn->target_port, conn->initiator_port);
					rc = write(conn->task_pipe[1], "E", 1);
					if(rc < 0 || rc != 1) {
						ISTGT_ERRLOG("write() failed\n");
					}
					break;
				}
				rc = istgt_lu_destroy_task(lu_task);
				if (rc < 0) {
					ISTGT_ERRLOG("lu_destroy_task() failed\n");
					break;
				}
			} else if (lu_task->type == ISTGT_LU_TASK_REQPDU) {
			reqpdu:
				/* send PDU */
				rc = istgt_iscsi_write_pdu_internal(lu_task->conn,
				    lu_task->lu_cmd.pdu);
				if (rc < 0) {
					lu_task->error = 1;
					ISTGT_ERRLOG(
						"iscsi_write_pdu() failed on %s(%s)\n",
						lu_task->conn->target_port,
						lu_task->conn->initiator_port);
					rc = write(conn->task_pipe[1], "E", 1);
					if(rc < 0 || rc != 1) {
						ISTGT_ERRLOG("write() failed\n");
					}
					break;
				}
				/* free allocated memory by caller */
				xfree(lu_task);
			} else if (lu_task->type == ISTGT_LU_TASK_REQUPDPDU) {
				rc = istgt_update_pdu(lu_task->conn, &lu_task->lu_cmd);
				if (rc < 0) {
					lu_task->error = 1;
					ISTGT_ERRLOG(
						"update_pdu() failed on %s(%s)\n",
						lu_task->conn->target_port,
						lu_task->conn->initiator_port);
					rc = write(conn->task_pipe[1], "E", 1);
					if(rc < 0 || rc != 1) {
						ISTGT_ERRLOG("write() failed\n");
					}
					break;
				}
				goto reqpdu;
			} else {
				ISTGT_ERRLOG("Unknown task type %x\n", lu_task->type);
				rc = -1;
			}
			// conn is running?
			if (conn->state != CONN_STATE_RUNNING) {
				//ISTGT_WARNLOG("exit thread\n");
				break;
			}
			MTX_LOCK(&conn->result_queue_mutex);
			lu_task = istgt_queue_dequeue(&conn->result_queue);
			MTX_UNLOCK(&conn->result_queue_mutex);
		} while (lu_task != NULL);
//		MTX_UNLOCK(&conn->wpdu_mutex);
	}
	//MTX_UNLOCK(&conn->sender_mutex);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "sender loop ended (%d)\n", conn->id);
	return NULL;
}

static void *
worker(void *arg)
{
	CONN_Ptr conn = (CONN_Ptr) arg;
	ISTGT_LU_TASK_Ptr lu_task;
	ISTGT_LU_Ptr lu;
	ISCSI_PDU_Ptr pdu;
	sigset_t signew, sigold;
#ifdef ISTGT_USE_KQUEUE
	int kq;
	struct kevent kev;
	struct timespec kev_timeout;
#else
	struct pollfd fds[2];
	int nopin_timer;
#endif /* ISTGT_USE_KQUEUE */
	int opcode;
	int rc;

	ISTGT_TRACELOG(ISTGT_TRACE_NET, "connect to %s:%s,%d\n",
	    conn->portal.host, conn->portal.port, conn->portal.tag);
#if 0
	ISTGT_NOTICELOG("connect to %s:%s,%d\n",
	    conn->portal.host, conn->portal.port, conn->portal.tag);
#endif

#ifdef ISTGT_USE_KQUEUE
	kq = kqueue();
	if (kq == -1) {
		ISTGT_ERRLOG("kqueue() failed\n");
		return NULL;
	}
	conn->kq = kq;
#if defined (ISTGT_USE_IOVEC) && defined (NOTE_LOWAT)
	ISTGT_EV_SET(&kev, conn->sock, EVFILT_READ, EV_ADD, NOTE_LOWAT, ISCSI_BHS_LEN, NULL);
#else
	ISTGT_EV_SET(&kev, conn->sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
#endif
	rc = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (rc == -1) {
		ISTGT_ERRLOG("kevent() failed\n");
		close(kq);
		return NULL;
	}
	ISTGT_EV_SET(&kev, conn->task_pipe[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
	rc = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (rc == -1) {
		ISTGT_ERRLOG("kevent() failed\n");
		close(kq);
		return NULL;
	}

	if (!conn->istgt->daemon) {
		ISTGT_EV_SET(&kev, SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
		rc = kevent(kq, &kev, 1, NULL, 0, NULL);
		if (rc == -1) {
			ISTGT_ERRLOG("kevent() failed\n");
			close(kq);
			return NULL;
		}
		ISTGT_EV_SET(&kev, SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
		rc = kevent(kq, &kev, 1, NULL, 0, NULL);
		if (rc == -1) {
			ISTGT_ERRLOG("kevent() failed\n");
			close(kq);
			return NULL;
		}
	}
#else
	memset(&fds, 0, sizeof fds);
	fds[0].fd = conn->sock;
	fds[0].events = POLLIN;
	fds[1].fd = conn->task_pipe[0];
	fds[1].events = POLLIN;
#endif /* ISTGT_USE_KQUEUE */

	conn->pdu.ahs = NULL;
	conn->pdu.data = NULL;
	conn->pdu.copy_pdu = 0;
	conn->state = CONN_STATE_RUNNING;
	conn->exec_lu_task = NULL;
	lu_task = NULL;

	pthread_cleanup_push(worker_cleanup, conn);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	conn->use_sender = 0;
	if (conn->istgt->swmode >= ISTGT_SWMODE_NORMAL) {
		/* create sender thread */
#ifdef ISTGT_STACKSIZE
		rc = pthread_create(&conn->sender_thread, &conn->istgt->attr,
		    &sender, (void *)conn);
#else
		rc = pthread_create(&conn->sender_thread, NULL, &sender,
		    (void *)conn);
#endif
		if (rc != 0) {
			ISTGT_ERRLOG("pthread_create() failed\n");
			goto cleanup_exit;
		}
		conn->use_sender = 1;
	}
	conn->wsock = conn->sock;

	sigemptyset(&signew);
	sigemptyset(&sigold);
	sigaddset(&signew, ISTGT_SIGWAKEUP);
	pthread_sigmask(SIG_UNBLOCK, &signew, &sigold);

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "loop start (%d)\n", conn->id);
#ifndef ISTGT_USE_KQUEUE
	nopin_timer = conn->nopininterval;
#endif /* !ISTGT_USE_KQUEUE */
	while (1) {
		/* check exit request */
		if (conn->sess != NULL) {
			SESS_MTX_LOCK(conn);
			lu = conn->sess->lu;
			SESS_MTX_UNLOCK(conn);
		} else {
			lu = NULL;
		}
		if (lu != NULL) {
			if (istgt_lu_get_state(lu) != ISTGT_STATE_RUNNING) {
				conn->state = CONN_STATE_EXITING;
				break;
			}
		} else {
			if (istgt_get_state(conn->istgt) != ISTGT_STATE_RUNNING) {
				conn->state = CONN_STATE_EXITING;
				break;
			}
		}

		pthread_testcancel();
		if (conn->state != CONN_STATE_RUNNING) {
			break;
		}

#ifdef ISTGT_USE_KQUEUE
		ISTGT_TRACELOG(ISTGT_TRACE_NET,
		    "kevent sock %d (timeout %dms)\n",
		    conn->sock, conn->nopininterval);
		if (conn->nopininterval != 0) {
			kev_timeout.tv_sec = conn->nopininterval / 1000;
			kev_timeout.tv_nsec = (conn->nopininterval % 1000) * 1000000;
		} else {
			kev_timeout.tv_sec = DEFAULT_NOPININTERVAL;
			kev_timeout.tv_nsec = 0;
		}
		rc = kevent(kq, NULL, 0, &kev, 1, &kev_timeout);
		if (rc == -1 && errno == EINTR) {
			//ISTGT_ERRLOG("EINTR kevent\n");
			continue;
		}
		if (rc == -1) {
			ISTGT_ERRLOG("kevent() failed\n");
			break;
		}
		if (rc == 0) {
			/* idle timeout, send diagnosis packet */
			if (conn->nopininterval != 0) {
				rc = istgt_iscsi_send_nopin(conn);
				if (rc < 0) {
					ISTGT_ERRLOG("iscsi_send_nopin() failed\n");
					break;
				}
			}
			continue;
		}
		if (kev.filter == EVFILT_SIGNAL) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "kevent SIGNAL\n");
			if (kev.ident == SIGINT || kev.ident == SIGTERM) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "kevent SIGNAL SIGINT/SIGTERM\n");
				break;
			}
			continue;
		}
#else
		//ISTGT_TRACELOG(ISTGT_TRACE_NET, "poll sock %d\n", conn->sock);
		rc = poll(fds, 2, POLLWAIT);
		if (rc == -1 && errno == EINTR) {
			//ISTGT_ERRLOG("EINTR poll\n");
			continue;
		}
		if (rc == -1) {
			ISTGT_ERRLOG("poll() failed\n");
			break;
		}
		if (rc == 0) {
			/* no fds */
			//ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "poll TIMEOUT\n");
			if (nopin_timer > 0) {
				nopin_timer -= POLLWAIT;
				if (nopin_timer <= 0) {
					nopin_timer = conn->nopininterval;
					rc = istgt_iscsi_send_nopin(conn);
					if (rc < 0) {
						ISTGT_ERRLOG("iscsi_send_nopin() failed\n");
						break;
					}
				}
			}
			continue;
		}
		nopin_timer = conn->nopininterval;
#endif /* ISTGT_USE_KQUEUE */

		/* on socket */
#ifdef ISTGT_USE_KQUEUE
		if (kev.ident == (uintptr_t)conn->sock) {
			if (kev.flags & (EV_EOF|EV_ERROR)) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "kevent EOF/ERROR\n");
				break;
			}
#else
		if (fds[0].revents & POLLHUP) {
			break;
		}
		if (fds[0].revents & POLLIN) {
#endif /* ISTGT_USE_KQUEUE */
			conn->pdu.copy_pdu = 0;
			rc = istgt_iscsi_read_pdu(conn, &conn->pdu);
			if (rc < 0) {
				if (conn->state != CONN_STATE_EXITING) {
					ISTGT_ERRLOG("conn->state = %d\n", conn->state);
				}
				if (conn->state != CONN_STATE_RUNNING) {
					if (errno == EINPROGRESS) {
						sleep(1);
						continue;
					}
					if (errno == ECONNRESET
					    || errno == ETIMEDOUT) {
						ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
						    "iscsi_read_pdu() RESET/TIMEOUT\n");
					} else {
						ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
						    "iscsi_read_pdu() EOF\n");
					}
					break;
				}
				ISTGT_ERRLOG("iscsi_read_pdu() failed\n");
				break;
			}
		execute_pdu:
			opcode = BGET8W(&conn->pdu.bhs.opcode, 5, 6);

#if 0
			pthread_testcancel();
#endif
			if (conn->state != CONN_STATE_RUNNING) {
				break;
			}

			if (g_trace_flag) {
				if (conn->sess != NULL) {
					SESS_MTX_LOCK(conn);
					ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
					    "isid=%"PRIx64", tsih=%u, cid=%u, op=%x\n",
					    conn->sess->isid, conn->sess->tsih,
					    conn->cid, opcode);
					SESS_MTX_UNLOCK(conn);
				} else {
					ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
					    "isid=xxx, tsih=xxx, cid=%u, op=%x\n",
					    conn->cid, opcode);
				}
			}
			rc = istgt_iscsi_execute(conn, &conn->pdu);
			if (rc < 0) {
				ISTGT_ERRLOG("iscsi_execute() failed on %s(%s)\n",
				    conn->target_port, conn->initiator_port);
				break;
			}
			if (g_trace_flag) {
				if (conn->sess != NULL) {
					SESS_MTX_LOCK(conn);
					ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
					    "isid=%"PRIx64", tsih=%u, cid=%u, op=%x complete\n",
					    conn->sess->isid, conn->sess->tsih,
					    conn->cid, opcode);
					SESS_MTX_UNLOCK(conn);
				} else {
					ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
					    "isid=xxx, tsih=xxx, cid=%u, op=%x complete\n",
					    conn->cid, opcode);
				}
			}

#if 0
			if (opcode == ISCSI_OP_LOGIN) {
				//ISTGT_NOTICELOG("OP LOGIN: %s\n", conn->initiator_port);
				istgt_yield();
				if (conn->full_feature) {
					//ISTGT_NOTICELOG("full_feature %s\n", conn->initiator_port);
				}
			}
#endif
			if (opcode == ISCSI_OP_LOGOUT) {
				ISTGT_TRACELOG(ISTGT_TRACE_ISCSI, "logout received\n");
				break;
			}

			if (conn->pdu.copy_pdu == 0) {
				xfree(conn->pdu.ahs);
				conn->pdu.ahs = NULL;
				if (conn->pdu.data != conn->pdu.shortdata) {
					xfree(conn->pdu.data);
				}
				conn->pdu.data = NULL;
			}

			/* execute pending PDUs */
			pdu = istgt_queue_dequeue(&conn->pending_pdus);
			if (pdu != NULL) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "execute pending PDU\n");
				rc = istgt_iscsi_copy_pdu(&conn->pdu, pdu);
				conn->pdu.copy_pdu = 0;
				xfree(pdu);
				goto execute_pdu;
			}

#if 0
			/* retry read/PDUs */
			continue;
#endif
		}

		/* execute on task queue */
#ifdef ISTGT_USE_KQUEUE
		if (kev.ident == (uintptr_t)conn->task_pipe[0]) {
			if (kev.flags & (EV_EOF|EV_ERROR)) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "kevent EOF/ERROR\n");
				break;
			}
#else
		if (fds[1].revents & POLLHUP) {
			break;
		}
		if (fds[1].revents & POLLIN) {
#endif /* ISTGT_USE_KQUEUE */
			char tmp[1];

			//ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "Queue Task START\n");

			rc = read(conn->task_pipe[0], tmp, 1);
			if (rc < 0 || rc == 0 || rc != 1) {
				ISTGT_ERRLOG("read() failed\n");
				break;
			}
			if (tmp[0] == 'E') {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "exit request (%d)\n",
				    conn->id);
				break;
			}

			/* DATA-IN/OUT */
			MTX_LOCK(&conn->task_queue_mutex);
			rc = istgt_queue_count(&conn->task_queue);
			lu_task = istgt_queue_dequeue(&conn->task_queue);
			MTX_UNLOCK(&conn->task_queue_mutex);
			if (lu_task != NULL) {
				if (conn->exec_lu_task != NULL) {
					ISTGT_ERRLOG("task is overlapped (CmdSN=%u, %u)\n",
					    conn->exec_lu_task->lu_cmd.CmdSN,
					    lu_task->lu_cmd.CmdSN);
					break;
				}
				conn->exec_lu_task = lu_task;
				if (lu_task->lu_cmd.W_bit) {
					/* write */
					if (lu_task->req_transfer_out == 0) {
						if (lu_task->req_execute) {
							if (conn->running_tasks > 0) {
								conn->running_tasks--;
							} else {
								ISTGT_ERRLOG("running no task\n");
							}
						}
						rc = istgt_iscsi_task_response(conn, lu_task);
						if (rc < 0) {
							lu_task->error = 1;
							ISTGT_ERRLOG("iscsi_task_response() failed on %s(%s)\n",
							    conn->target_port,
							    conn->initiator_port);
							break;
						}
						rc = istgt_lu_destroy_task(lu_task);
						if (rc < 0) {
							ISTGT_ERRLOG("lu_destroy_task() failed\n");
							break;
						}
						lu_task = NULL;
						conn->exec_lu_task = NULL;
					} else {
						//ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
						//    "Task Write Trans START\n");
						rc = istgt_iscsi_task_transfer_out(conn, lu_task);
						if (rc < 0) {
							lu_task->error = 1;
							ISTGT_ERRLOG("iscsi_task_transfer_out() failed on %s(%s)\n",
							    conn->target_port,
							    conn->initiator_port);
							break;
						}
						//ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
						//    "Task Write Trans END\n");

						MTX_LOCK(&lu_task->trans_mutex);
						lu_task->req_transfer_out = 0;

						/* need response after execution */
						lu_task->req_execute = 1;
						if (conn->use_sender == 0) {
							conn->running_tasks++;
						}

						rc = pthread_cond_broadcast(&lu_task->trans_cond);
						MTX_UNLOCK(&lu_task->trans_mutex);
						if (rc != 0) {
							ISTGT_ERRLOG("cond_broadcast() failed\n");
							break;
						}
						lu_task = NULL;
						conn->exec_lu_task = NULL;
					}
				} else {
					/* read or no data */
					rc = istgt_iscsi_task_response(conn, lu_task);
					if (rc < 0) {
						lu_task->error = 1;
						ISTGT_ERRLOG("iscsi_task_response() failed on %s(%s)\n",
						    conn->target_port,
						    conn->initiator_port);
						break;
					}
					rc = istgt_lu_destroy_task(lu_task);
					if (rc < 0) {
						ISTGT_ERRLOG("lu_destroy_task() failed\n");
						break;
					}
					lu_task = NULL;
					conn->exec_lu_task = NULL;
				}
			}
			/* XXX PDUs in DATA-OUT? */
			pdu = istgt_queue_dequeue(&conn->pending_pdus);
			if (pdu != NULL) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "pending in task\n");
				rc = istgt_iscsi_copy_pdu(&conn->pdu, pdu);
				conn->pdu.copy_pdu = 0;
				xfree(pdu);
#ifdef ISTGT_USE_KQUEUE
				kev.ident = -1;
#else
				fds[1].revents &= ~POLLIN;
#endif /* ISTGT_USE_KQUEUE */
				goto execute_pdu;
			}
		}
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "loop ended (%d)\n", conn->id);

    cleanup_exit:
	;
	pthread_cleanup_pop(0);
	conn->state = CONN_STATE_EXITING;
	if (conn->sess != NULL) {
		SESS_MTX_LOCK(conn);
		lu = conn->sess->lu;
		if (lu != NULL && lu->queue_depth != 0) {
			rc = istgt_lu_clear_task_IT(conn, lu);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_clear_task_IT() failed\n");
			}
			istgt_clear_all_transfer_task(conn);
		}
		SESS_MTX_UNLOCK(conn);
	}
	if (conn->pdu.copy_pdu == 0) {
		xfree(conn->pdu.ahs);
		conn->pdu.ahs = NULL;
		if (conn->pdu.data != conn->pdu.shortdata) {
			xfree(conn->pdu.data);
		}
		conn->pdu.data = NULL;
	}
	wait_all_task(conn);

	if (conn->use_sender) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "stop sender thread (%d)\n", conn->id);
		/* stop sender thread */
		MTX_LOCK(&conn->result_queue_mutex);
		rc = pthread_cond_broadcast(&conn->result_queue_cond);
		MTX_UNLOCK(&conn->result_queue_mutex);
		if (rc != 0) {
			ISTGT_ERRLOG("cond_broadcast() failed\n");
			/* ignore errors */
		}
		rc = pthread_join(conn->sender_thread, NULL);
		if (rc != 0) {
			ISTGT_ERRLOG("pthread_join() failed\n");
			/* ignore errors */
		}
	}

	close(conn->sock);
#ifdef ISTGT_USE_KQUEUE
	close(kq);
	conn->kq = -1;
#endif /* ISTGT_USE_KQUEUE */
	sleep(1);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "worker %d end\n", conn->id);

	/* cleanup conn & sess */
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "cleanup LOCK\n");
	MTX_LOCK(&g_conns_mutex);
	g_conns[conn->id] = NULL;
	istgt_remove_conn(conn);
	MTX_UNLOCK(&g_conns_mutex);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "cleanup UNLOCK\n");

	return NULL;
}

int
istgt_create_conn(ISTGT_Ptr istgt, PORTAL_Ptr portal, int sock, struct sockaddr *sa, socklen_t salen __attribute__((__unused__)))
{
	char buf[MAX_TMPBUF];
	CONN_Ptr conn;
	int rc;
	int i;

	conn = xmalloc(sizeof *conn);
	memset(conn, 0, sizeof *conn);

	conn->istgt = istgt;
	MTX_LOCK(&istgt->mutex);
	conn->timeout = istgt->timeout;
	conn->nopininterval = istgt->nopininterval;
	conn->nopininterval *= 1000; /* sec. to msec. */
	conn->max_r2t = istgt->maxr2t;
	conn->TargetMaxRecvDataSegmentLength = istgt->MaxRecvDataSegmentLength;
	MTX_UNLOCK(&istgt->mutex);
	conn->MaxRecvDataSegmentLength = 8192; // RFC3720(12.12)
	if (conn->TargetMaxRecvDataSegmentLength
		< conn->MaxRecvDataSegmentLength) {
		conn->TargetMaxRecvDataSegmentLength
			= conn->MaxRecvDataSegmentLength;
	}
	conn->MaxOutstandingR2T = 1;
	conn->FirstBurstLength = DEFAULT_FIRSTBURSTLENGTH;
	conn->MaxBurstLength = DEFAULT_MAXBURSTLENGTH;

	conn->portal.label = xstrdup(portal->label);
	conn->portal.host = xstrdup(portal->host);
	conn->portal.port = xstrdup(portal->port);
	conn->portal.idx = portal->idx;
	conn->portal.tag = portal->tag;
	conn->portal.sock = -1;
	conn->sock = sock;
	conn->wsock = -1;
#ifdef ISTGT_USE_KQUEUE
	conn->kq = -1;
#endif /* ISTGT_USE_KQUEUE */
	conn->use_sender = 0;

	conn->sess = NULL;
	conn->params = NULL;
	conn->state = CONN_STATE_INVALID;
	conn->exec_logout = 0;
	conn->max_pending = 0;
	conn->queue_depth = 0;
	conn->pending_r2t = 0;
	conn->header_digest = 0;
	conn->data_digest = 0;
	conn->full_feature = 0;
	conn->login_phase = ISCSI_LOGIN_PHASE_NONE;
	conn->auth.user = NULL;
	conn->auth.secret = NULL;
	conn->auth.muser = NULL;
	conn->auth.msecret = NULL;
	conn->authenticated = 0;
	conn->req_auth = 0;
	conn->req_mutual = 0;
	istgt_queue_init(&conn->pending_pdus);
	conn->r2t_tasks = xmalloc (sizeof *conn->r2t_tasks
	    * (conn->max_r2t + 1));
	for (i = 0; i < (conn->max_r2t + 1); i++) {
		conn->r2t_tasks[i] = NULL;
	}
	conn->task_pipe[0] = -1;
	conn->task_pipe[1] = -1;
	conn->max_task_queue = MAX_LU_QUEUE_DEPTH;
	istgt_queue_init(&conn->task_queue);
	istgt_queue_init(&conn->result_queue);
	conn->exec_lu_task = NULL;
	conn->running_tasks = 0;

	memset(conn->initiator_addr, 0, sizeof conn->initiator_addr);
	memset(conn->target_addr, 0, sizeof conn->target_addr);

	switch (sa->sa_family) {
	case AF_INET6:
		conn->initiator_family = AF_INET6;
		rc = istgt_getaddr(sock, conn->target_addr,
		    sizeof conn->target_addr,
		    conn->initiator_addr, sizeof conn->initiator_addr);
		if (rc < 0) {
			ISTGT_ERRLOG("istgt_getaddr() failed\n");
			goto error_return;
		}
		break;
	case AF_INET:
		conn->initiator_family = AF_INET;
		rc = istgt_getaddr(sock, conn->target_addr,
		    sizeof conn->target_addr,
		    conn->initiator_addr, sizeof conn->initiator_addr);
		if (rc < 0) {
			ISTGT_ERRLOG("istgt_getaddr() failed\n");	
			goto error_return;
		}
		break;
	default:
		ISTGT_ERRLOG("unsupported family\n");
		goto error_return;
	}
	printf("sock=%d, addr=%s, peer=%s\n",
		   sock, conn->target_addr,
		   conn->initiator_addr);

	/* wildcard? */
	if (strcasecmp(conn->portal.host, "[::]") == 0
		|| strcasecmp(conn->portal.host, "[*]") == 0) {
		if (conn->initiator_family != AF_INET6) {
			ISTGT_ERRLOG("address family error\n");
			goto error_return;
		}
		snprintf(buf, sizeof buf, "[%s]", conn->target_addr);
		xfree(conn->portal.host);
		conn->portal.host = xstrdup(buf);
	} else if (strcasecmp(conn->portal.host, "0.0.0.0") == 0
			   || strcasecmp(conn->portal.host, "*") == 0) {
		if (conn->initiator_family != AF_INET) {
			ISTGT_ERRLOG("address family error\n");
			goto error_return;
		}
		snprintf(buf, sizeof buf, "%s", conn->target_addr);
		xfree(conn->portal.host);
		conn->portal.host = xstrdup(buf);
	}

	memset(conn->initiator_name, 0, sizeof conn->initiator_name);
	memset(conn->target_name, 0, sizeof conn->target_name);
	memset(conn->initiator_port, 0, sizeof conn->initiator_port);
	memset(conn->target_port, 0, sizeof conn->target_port);

	/* set timeout msec. */
	rc = istgt_set_recvtimeout(conn->sock, conn->timeout * 1000);
	if (rc != 0) {
		ISTGT_ERRLOG("istgt_set_recvtimeo() failed\n");
		goto error_return;
	}
	rc = istgt_set_sendtimeout(conn->sock, conn->timeout * 1000);
	if (rc != 0) {
		ISTGT_ERRLOG("istgt_set_sendtimeo() failed\n");
		goto error_return;
	}
#if defined (ISTGT_USE_IOVEC)
	/* set low water mark */
	rc = istgt_set_recvlowat(conn->sock, ISCSI_BHS_LEN);
	if (rc != 0) {
		ISTGT_ERRLOG("istgt_set_recvlowat() failed\n");
		goto error_return;
	}
#endif

	rc = pipe(conn->task_pipe);
	if (rc != 0) {
		ISTGT_ERRLOG("pipe() failed\n");
		conn->task_pipe[0] = -1;
		conn->task_pipe[1] = -1;
		goto error_return;
	}
	rc = pthread_mutex_init(&conn->task_queue_mutex, &istgt->mutex_attr);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_init() failed\n");
		goto error_return;
	}
	rc = pthread_mutex_init(&conn->result_queue_mutex, &istgt->mutex_attr);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_init() failed\n");
		goto error_return;
	}
	rc = pthread_cond_init(&conn->result_queue_cond, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("cond_init() failed\n");
		goto error_return;
	}
	rc = pthread_mutex_init(&conn->wpdu_mutex, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_init() failed\n");
		goto error_return;
	}
	rc = pthread_cond_init(&conn->wpdu_cond, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("cond_init() failed\n");
		goto error_return;
	}
	rc = pthread_mutex_init(&conn->r2t_mutex, &istgt->mutex_attr);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_init() failed\n");
		goto error_return;
	}
	rc = pthread_mutex_init(&conn->sender_mutex, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_init() failed\n");
		goto error_return;
	}
	rc = pthread_cond_init(&conn->sender_cond, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("cond_init() failed\n");
		goto error_return;
	}

	/* set default params */
	rc = istgt_iscsi_conn_params_init(&conn->params);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_conn_params_init() failed\n");
		goto error_return;
	}
	/* replace with config value */
	rc = istgt_iscsi_param_set_int(conn->params,
	    "MaxRecvDataSegmentLength",
	    conn->MaxRecvDataSegmentLength);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set_int() failed\n");
		goto error_return;
	}

	conn->shortpdusize = ISTGT_SHORTPDUSIZE;
	conn->shortpdu = xmalloc(conn->shortpdusize);

	conn->iobufsize = ISTGT_IOBUFSIZE;
	conn->iobuf = xmalloc(conn->iobufsize);
	conn->snsbufsize = ISTGT_SNSBUFSIZE;
	conn->snsbuf = xmalloc(conn->snsbufsize);

	if (conn->MaxRecvDataSegmentLength < 8192) {
		conn->recvbufsize = 8192;
		conn->sendbufsize = 8192;
	} else {
		conn->recvbufsize = conn->MaxRecvDataSegmentLength;
		conn->sendbufsize = conn->MaxRecvDataSegmentLength;
	}
	conn->recvbuf = xmalloc(conn->recvbufsize);
	conn->sendbuf = xmalloc(conn->sendbufsize);

	conn->worksize = 0;
	conn->workbuf = NULL;

	/* register global */
	rc = -1;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "register global LOCK\n");
	MTX_LOCK(&g_conns_mutex);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "register global LOCKED\n");
	for (i = 0; i < g_nconns; i++) {
		if (g_conns[i] == NULL) {
			g_conns[i] = conn;
			conn->id = i;
			rc = 0;
			break;
		}
	}
	MTX_UNLOCK(&g_conns_mutex);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "register global UNLOCK\n");
	if (rc < 0) {
		ISTGT_ERRLOG("no free conn slot available\n");
	error_return:
		if (conn->task_pipe[0] != -1)
			close(conn->task_pipe[0]);
		if (conn->task_pipe[1] != -1)
			close(conn->task_pipe[1]);
		istgt_iscsi_param_free(conn->params);
		istgt_queue_destroy(&conn->pending_pdus);
		istgt_queue_destroy(&conn->task_queue);
		istgt_queue_destroy(&conn->result_queue);
		xfree(conn->portal.label);
		xfree(conn->portal.host);
		xfree(conn->portal.port);
		xfree(conn->iobuf);
		xfree(conn->snsbuf);
		xfree(conn->recvbuf);
		xfree(conn->sendbuf);
		xfree(conn);
		return -1;
	}

	/* create new thread */
#ifdef ISTGT_STACKSIZE
	rc = pthread_create(&conn->thread, &istgt->attr, &worker, (void *)conn);
#else
	rc = pthread_create(&conn->thread, NULL, &worker, (void *)conn);
#endif /* ISTGT_STACKSIZE */
	if (rc != 0) {
		ISTGT_ERRLOG("pthread_create() failed\n");
		goto error_return;
	}
	rc = pthread_detach(conn->thread);
	if (rc != 0) {
		ISTGT_ERRLOG("pthread_detach() failed\n");
		goto error_return;
	}
#ifdef HAVE_PTHREAD_SET_NAME_NP
	snprintf(buf, sizeof buf, "connthread #%d", conn->id);
	pthread_set_name_np(conn->thread, buf);
#endif

	/* XXX should use sleep loop? */
	sleep(1);
#if 0
	/* wait the thread is running */
	while (conn->state == CONN_STATE_INVALID) {
		istgt_yield();
	}
#endif

	return 0;
}

int
istgt_create_sess(ISTGT_Ptr istgt, CONN_Ptr conn, ISTGT_LU_Ptr lu)
{
	SESS_Ptr sess;
	int rc;

	sess = xmalloc(sizeof *sess);
	memset(sess, 0, sizeof *sess);

	/* configuration values */
	MTX_LOCK(&istgt->mutex);
	if (lu != NULL) {
		MTX_LOCK(&lu->mutex);
	}
	sess->MaxConnections = istgt->MaxConnections;
	if (lu != NULL) {
		sess->MaxOutstandingR2T = lu->MaxOutstandingR2T;
	} else {
		sess->MaxOutstandingR2T = istgt->MaxOutstandingR2T;
	}
#if 0
	if (sess->MaxOutstandingR2T > conn->max_r2t) {
		if (conn->max_r2t > 0) {
			sess->MaxOutstandingR2T = conn->max_r2t;
		} else {
			sess->MaxOutstandingR2T = 1;
		}
	}
#else
	if (sess->MaxOutstandingR2T < 1) {
		sess->MaxOutstandingR2T = 1;
	}
	/* limit up to MaxOutstandingR2T */
	if (sess->MaxOutstandingR2T < conn->max_r2t) {
		conn->max_r2t = sess->MaxOutstandingR2T;
	}
#endif
	if (lu != NULL) {
		sess->DefaultTime2Wait = lu->DefaultTime2Wait;
		sess->DefaultTime2Retain = lu->DefaultTime2Retain;
		sess->FirstBurstLength = lu->FirstBurstLength;
		sess->MaxBurstLength = lu->MaxBurstLength;
		conn->MaxRecvDataSegmentLength
			= lu->MaxRecvDataSegmentLength;
		sess->InitialR2T = lu->InitialR2T;
		sess->ImmediateData = lu->ImmediateData;
		sess->DataPDUInOrder = lu->DataPDUInOrder;
		sess->DataSequenceInOrder = lu->DataSequenceInOrder;
		sess->ErrorRecoveryLevel = lu->ErrorRecoveryLevel;
	} else {
		sess->DefaultTime2Wait = istgt->DefaultTime2Wait;
		sess->DefaultTime2Retain = istgt->DefaultTime2Retain;
		sess->FirstBurstLength = istgt->FirstBurstLength;
		sess->MaxBurstLength = istgt->MaxBurstLength;
		conn->MaxRecvDataSegmentLength
			= istgt->MaxRecvDataSegmentLength;
		sess->InitialR2T = istgt->InitialR2T;
		sess->ImmediateData = istgt->ImmediateData;
		sess->DataPDUInOrder = istgt->DataPDUInOrder;
		sess->DataSequenceInOrder = istgt->DataSequenceInOrder;
		sess->ErrorRecoveryLevel = istgt->ErrorRecoveryLevel;
	}
	if (lu != NULL) {
		MTX_UNLOCK(&lu->mutex);
	}
	MTX_UNLOCK(&istgt->mutex);

	sess->initiator_port = xstrdup(conn->initiator_port);
	sess->target_name = xstrdup(conn->target_name);
	sess->tag = conn->portal.tag;

	sess->max_conns = sess->MaxConnections;
	sess->conns = xmalloc(sizeof *sess->conns * sess->max_conns);
	memset(sess->conns, 0, sizeof *sess->conns * sess->max_conns);
	sess->connections = 0;

	sess->conns[sess->connections] = conn;
	sess->connections++;

	sess->req_mcs_cond = 0;
	sess->params = NULL;
	sess->lu = NULL;
	sess->isid = 0;
	sess->tsih = 0;

	sess->initial_r2t = 0;
	sess->immediate_data = 0;

	rc = pthread_mutex_init(&sess->mutex, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_init() failed\n");
	error_return:
		istgt_iscsi_param_free(sess->params);
		xfree(sess->initiator_port);
		xfree(sess->target_name);
		xfree(sess->conns);
		xfree(sess);
		conn->sess = NULL;
		return -1;
	}
	rc = pthread_cond_init(&sess->mcs_cond, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("cond_init() failed\n");
		goto error_return;
	}

	/* set default params */
	rc = istgt_iscsi_sess_params_init(&sess->params);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_sess_params_init() failed\n");
		goto error_return;
	}
	/* replace with config value */
	rc = istgt_iscsi_param_set_int(sess->params,
	    "MaxConnections",
	    sess->MaxConnections);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set_int() failed\n");
		goto error_return;
	}
	rc = istgt_iscsi_param_set_int(sess->params,
	    "MaxOutstandingR2T",
	    sess->MaxOutstandingR2T);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set_int() failed\n");
		goto error_return;
	}
	rc = istgt_iscsi_param_set_int(sess->params,
	    "DefaultTime2Wait",
	    sess->DefaultTime2Wait);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set_int() failed\n");
		goto error_return;
	}
	rc = istgt_iscsi_param_set_int(sess->params,
	    "DefaultTime2Retain",
	    sess->DefaultTime2Retain);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set_int() failed\n");
		goto error_return;
	}
	rc = istgt_iscsi_param_set_int(sess->params,
	    "FirstBurstLength",
	    sess->FirstBurstLength);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set_int() failed\n");
		goto error_return;
	}
	rc = istgt_iscsi_param_set_int(sess->params,
	    "MaxBurstLength",
	    sess->MaxBurstLength);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set_int() failed\n");
		goto error_return;
	}
	rc = istgt_iscsi_param_set(sess->params,
	    "InitialR2T",
	    sess->InitialR2T ? "Yes" : "No");
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set() failed\n");
		goto error_return;
	}
	rc = istgt_iscsi_param_set(sess->params,
	    "ImmediateData",
	    sess->ImmediateData ? "Yes" : "No");
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set() failed\n");
		goto error_return;
	}
	rc = istgt_iscsi_param_set(sess->params,
	    "DataPDUInOrder",
	    sess->DataPDUInOrder ? "Yes" : "No");
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set() failed\n");
		goto error_return;
	}
	rc = istgt_iscsi_param_set(sess->params,
	    "DataSequenceInOrder",
	    sess->DataSequenceInOrder ? "Yes" : "No");
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set() failed\n");
		goto error_return;
	}
	rc = istgt_iscsi_param_set_int(sess->params,
	    "ErrorRecoveryLevel",
	    sess->ErrorRecoveryLevel);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set_int() failed\n");
		goto error_return;
	}

	/* realloc buffer */
	rc = istgt_iscsi_param_set_int(conn->params,
	    "MaxRecvDataSegmentLength",
	    conn->MaxRecvDataSegmentLength);
	if (rc < 0) {
		ISTGT_ERRLOG("iscsi_param_set_int() failed\n");
		goto error_return;
	}
	if (conn->MaxRecvDataSegmentLength != conn->recvbufsize) {
		xfree(conn->recvbuf);
		xfree(conn->sendbuf);
		if (conn->MaxRecvDataSegmentLength < 8192) {
			conn->recvbufsize = 8192;
			conn->sendbufsize = 8192;
		} else {
			conn->recvbufsize = conn->MaxRecvDataSegmentLength;
			conn->sendbufsize = conn->MaxRecvDataSegmentLength;
		}
		conn->recvbuf = xmalloc(conn->recvbufsize);
		conn->sendbuf = xmalloc(conn->sendbufsize);
	}

	/* sess for first connection of session */
	conn->sess = sess;
	return 0;
}

static int
istgt_append_sess(CONN_Ptr conn, uint64_t isid, uint16_t tsih, uint16_t cid)
{
	SESS_Ptr sess;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_ISCSI,
	    "append session: isid=%"PRIx64", tsih=%u, cid=%u\n",
	    isid, tsih, cid);

	sess = NULL;
	rc = -1;
	MTX_LOCK(&g_conns_mutex);
	for (i = 0; i < g_nconns; i++) {
		if (g_conns[i] == NULL || g_conns[i]->sess == NULL)
			continue;
		sess = g_conns[i]->sess;
		MTX_LOCK(&sess->mutex);
		if (conn->portal.tag == sess->tag
		    && strcasecmp(conn->initiator_port, sess->initiator_port) == 0
		    && strcasecmp(conn->target_name, sess->target_name) == 0
		    && (isid == sess->isid && tsih == sess->tsih)) {
			/* match tag and initiator port and target */
			rc = 0;
			break;
		}
		MTX_UNLOCK(&sess->mutex);
	}
	if (rc < 0) {
		/* no match */
		MTX_UNLOCK(&g_conns_mutex);
		ISTGT_ERRLOG("no MCS session for isid=%"PRIx64", tsih=%d, cid=%d\n",
		    isid, tsih, cid);
		return -1;
	}
	/* sess is LOCK by loop */
	if (sess->connections >= sess->max_conns
	    || sess->connections >= sess->MaxConnections) {
		/* no slot for connection */
		MTX_UNLOCK(&sess->mutex);
		MTX_UNLOCK(&g_conns_mutex);
		ISTGT_ERRLOG("too many connections for isid=%"PRIx64
		    ", tsih=%d, cid=%d\n",
		    isid, tsih, cid);
		return -1;
	}
	printf("Connections(tsih %d): %d\n", sess->tsih, sess->connections);
	conn->sess = sess;
	sess->conns[sess->connections] = conn;
	sess->connections++;
	MTX_UNLOCK(&sess->mutex);
	MTX_UNLOCK(&g_conns_mutex);

	return 0;
}

static void
istgt_free_sess(SESS_Ptr sess)
{
	if (sess == NULL)
		return;
	(void) pthread_mutex_destroy(&sess->mutex);
	(void) pthread_cond_destroy(&sess->mcs_cond);
	istgt_iscsi_param_free(sess->params);
	xfree(sess->initiator_port);
	xfree(sess->target_name);
	xfree(sess->conns);
	xfree(sess);
}

static void
istgt_free_conn(CONN_Ptr conn)
{
	if (conn == NULL)
		return;
	if (conn->task_pipe[0] != -1)
		close(conn->task_pipe[0]);
	if (conn->task_pipe[1] != -1)
		close(conn->task_pipe[1]);
	(void) pthread_mutex_destroy(&conn->task_queue_mutex);
	(void) pthread_mutex_destroy(&conn->result_queue_mutex);
	(void) pthread_cond_destroy(&conn->result_queue_cond);
	(void) pthread_mutex_destroy(&conn->wpdu_mutex);
	(void) pthread_cond_destroy(&conn->wpdu_cond);
	(void) pthread_mutex_destroy(&conn->r2t_mutex);
	(void) pthread_mutex_destroy(&conn->sender_mutex);
	(void) pthread_cond_destroy(&conn->sender_cond);
	istgt_iscsi_param_free(conn->params);
	istgt_queue_destroy(&conn->pending_pdus);
	istgt_queue_destroy(&conn->task_queue);
	istgt_queue_destroy(&conn->result_queue);
	xfree(conn->r2t_tasks);
	xfree(conn->portal.label);
	xfree(conn->portal.host);
	xfree(conn->portal.port);
	xfree(conn->auth.user);
	xfree(conn->auth.secret);
	xfree(conn->auth.muser);
	xfree(conn->auth.msecret);
	xfree(conn->shortpdu);
	xfree(conn->iobuf);
	xfree(conn->snsbuf);
	xfree(conn->recvbuf);
	xfree(conn->sendbuf);
	xfree(conn->workbuf);
	xfree(conn);
}

static void
istgt_remove_conn(CONN_Ptr conn)
{
	SESS_Ptr sess;
	int idx;
	int i, j;

	idx = -1;
	sess = conn->sess;
	conn->sess = NULL;
	if (sess == NULL) {
		istgt_free_conn(conn);
		return;
	}

	MTX_LOCK(&sess->mutex);
	for (i = 0; i < sess->connections; i++) {
		if (sess->conns[i] == conn) {
			idx = i;
			break;
		}
	}
	if (sess->connections < 1) {
		ISTGT_ERRLOG("zero connection\n");
		sess->connections = 0;
	} else {
		if (idx < 0) {
			ISTGT_ERRLOG("remove conn not found\n");
		} else {
			for (j = idx; j < sess->connections - 1; j++) {
				sess->conns[j] = sess->conns[j + 1];
			}
			sess->conns[sess->connections - 1] = NULL;
		}
		sess->connections--;
	}
	printf("Connections(tsih %d): %d\n", sess->tsih, sess->connections);
	if (sess->connections == 1) {
		/* cleanup for multiple connecsions */
		MTX_UNLOCK(&sess->mutex);
	} else if (sess->connections == 0) {
		/* cleanup last connection */ 
		MTX_UNLOCK(&sess->mutex);
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "cleanup last conn free tsih\n");
		istgt_lu_free_tsih(sess->lu, sess->tsih, conn->initiator_port);
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "cleanup last conn free sess\n");
		istgt_free_sess(sess);
	} else {
		MTX_UNLOCK(&sess->mutex);
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "cleanup free conn\n");
	istgt_free_conn(conn);
}

static int
istgt_iscsi_drop_all_conns(CONN_Ptr conn)
{
	CONN_Ptr xconn;
	int max_conns;
	int num;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_iscsi_drop_all_conns\n");

	printf("drop all connections %s by %s\n",
	    conn->target_name, conn->initiator_name);

	MTX_LOCK(&conn->istgt->mutex);
	max_conns = conn->istgt->MaxConnections;
	MTX_UNLOCK(&conn->istgt->mutex);
	num = 0;
	MTX_LOCK(&g_conns_mutex);
	for (i = 0; i < g_nconns; i++) {
		xconn = g_conns[i];
		if (xconn == NULL)
			continue;
		if (xconn == conn)
			continue;
		if (strcasecmp(conn->initiator_name, xconn->initiator_name) != 0) {
			continue;
		}
		if (strcasecmp(conn->target_name, xconn->target_name) == 0) {
			if (xconn->sess != NULL) {
				printf("exiting conn by %s(%s), TSIH=%u, CID=%u\n",
				    xconn->initiator_name,
				    xconn->initiator_addr,
				    xconn->sess->tsih, xconn->cid);
			} else {
				printf("exiting conn by %s(%s), TSIH=xx, CID=%u\n",
				    xconn->initiator_name,
				    xconn->initiator_addr,
				    xconn->cid);
			}
			xconn->state = CONN_STATE_EXITING;
			num++;
		}
	}
	istgt_yield();
	sleep(1);
	if (num > max_conns + 1) {
		printf("try pthread_cancel\n");
		for (i = 0; i < g_nconns; i++) {
			xconn = g_conns[i];
			if (xconn == NULL)
				continue;
			if (xconn == conn)
				continue;
			if (strcasecmp(conn->initiator_port, xconn->initiator_port) != 0) {
				continue;
			}
			if (strcasecmp(conn->target_name, xconn->target_name) == 0) {
				if (xconn->sess != NULL) {
					printf("exiting conn by %s(%s), TSIH=%u, CID=%u\n",
					    xconn->initiator_port,
					    xconn->initiator_addr,
					    xconn->sess->tsih, xconn->cid);
				} else {
					printf("exiting conn by %s(%s), TSIH=xx, CID=%u\n",
					    xconn->initiator_port,
					    xconn->initiator_addr,
					    xconn->cid);
				}
				rc = pthread_cancel(xconn->thread);
				if (rc != 0) {
					ISTGT_ERRLOG("pthread_cancel() failed rc=%d\n", rc);
				}
			}
		}
	}
	MTX_UNLOCK(&g_conns_mutex);

	if (num != 0) {
		printf("exiting %d conns\n", num);
	}
	return 0;
}

static int
istgt_iscsi_drop_old_conns(CONN_Ptr conn)
{
	CONN_Ptr xconn;
	int max_conns;
	int num;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_iscsi_drop_old_conns\n");

	printf("drop old connections %s by %s\n",
	    conn->target_name, conn->initiator_port);

	MTX_LOCK(&conn->istgt->mutex);
	max_conns = conn->istgt->MaxConnections;
	MTX_UNLOCK(&conn->istgt->mutex);
	num = 0;
	MTX_LOCK(&g_conns_mutex);
	for (i = 0; i < g_nconns; i++) {
		xconn = g_conns[i];
		if (xconn == NULL)
			continue;
		if (xconn == conn)
			continue;
		if (strcasecmp(conn->initiator_port, xconn->initiator_port) != 0) {
			continue;
		}
		if (strcasecmp(conn->target_name, xconn->target_name) == 0) {
			if (xconn->sess != NULL) {
				printf("exiting conn by %s(%s), TSIH=%u, CID=%u\n",
				    xconn->initiator_port,
				    xconn->initiator_addr,
				    xconn->sess->tsih, xconn->cid);
			} else {
				printf("exiting conn by %s(%s), TSIH=xx, CID=%u\n",
				    xconn->initiator_port,
				    xconn->initiator_addr,
				    xconn->cid);
			}
			xconn->state = CONN_STATE_EXITING;
			num++;
		}
	}
	istgt_yield();
	sleep(1);
	if (num > max_conns + 1) {
		printf("try pthread_cancel\n");
		for (i = 0; i < g_nconns; i++) {
			xconn = g_conns[i];
			if (xconn == NULL)
				continue;
			if (xconn == conn)
				continue;
			if (strcasecmp(conn->initiator_port, xconn->initiator_port) != 0) {
				continue;
			}
			if (strcasecmp(conn->target_name, xconn->target_name) == 0) {
				if (xconn->sess != NULL) {
					printf("exiting conn by %s(%s), TSIH=%u, CID=%u\n",
					    xconn->initiator_port,
					    xconn->initiator_addr,
					    xconn->sess->tsih, xconn->cid);
				} else {
					printf("exiting conn by %s(%s), TSIH=xx, CID=%u\n",
					    xconn->initiator_port,
					    xconn->initiator_addr,
					    xconn->cid);
				}
				rc = pthread_cancel(xconn->thread);
				if (rc != 0) {
					ISTGT_ERRLOG("pthread_cancel() failed rc=%d\n", rc);
				}
			}
		}
	}
	MTX_UNLOCK(&g_conns_mutex);

	if (num != 0) {
		printf("exiting %d conns\n", num);
	}
	return 0;
}

void
istgt_lock_gconns(void)
{
	MTX_LOCK(&g_conns_mutex);
}

void
istgt_unlock_gconns(void)
{
	MTX_UNLOCK(&g_conns_mutex);
}

int
istgt_get_gnconns(void)
{
	return g_nconns;
}

CONN_Ptr
istgt_get_gconn(int idx)
{
	if (idx >= g_nconns)
		return NULL;
	return g_conns[idx];
}

int
istgt_get_active_conns(void)
{
	CONN_Ptr conn;
	int num = 0;
	int i;

	MTX_LOCK(&g_conns_mutex);
	for (i = 0; i < g_nconns; i++) {
		conn = g_conns[i];
		if (conn == NULL)
			continue;
		num++;
	}
	MTX_UNLOCK(&g_conns_mutex);
	return num;
}

int
istgt_stop_conns(void)
{
	CONN_Ptr conn;
	char tmp[1];
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_stop_conns\n");
	tmp[0] = 'E';
	MTX_LOCK(&g_conns_mutex);
	for (i = 0; i < g_nconns; i++) {
		conn = g_conns[i];
		if (conn == NULL)
			continue;
		rc = write(conn->task_pipe[1], tmp, 1);
		if(rc < 0 || rc != 1) {
			ISTGT_ERRLOG("write() failed\n");
			/* ignore error */
		}
	}
	MTX_UNLOCK(&g_conns_mutex);
	return 0;
}

CONN_Ptr
istgt_find_conn(const char *initiator_port, const char *target_name, uint16_t tsih)
{
	CONN_Ptr conn;
	SESS_Ptr sess;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "initiator_port=%s, target=%s, TSIH=%u",
	    initiator_port, target_name, tsih);
	sess = NULL;
	rc = -1;
	//MTX_LOCK(&g_conns_mutex);
	for (i = 0; i < g_nconns; i++) {
		conn = g_conns[i];
		if (conn == NULL || conn->sess == NULL)
			continue;
		sess = conn->sess;
		MTX_LOCK(&sess->mutex);
		if (strcasecmp(initiator_port, sess->initiator_port) == 0
		    && strcasecmp(target_name, sess->target_name) == 0
		    && (tsih == sess->tsih)) {
			/* match initiator port and target */
			rc = 0;
			break;
		}
		MTX_UNLOCK(&sess->mutex);
	}
	if (rc < 0) {
		//MTX_UNLOCK(&g_conns_mutex);
		return NULL;
	}
	MTX_UNLOCK(&sess->mutex);
	//MTX_UNLOCK(&g_conns_mutex);
	return conn;
}

int
istgt_iscsi_init(ISTGT_Ptr istgt)
{
	CF_SECTION *sp;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_iscsi_init\n");
	sp = istgt_find_cf_section(istgt->config, "Global");
	if (sp == NULL) {
		ISTGT_ERRLOG("find_cf_section failed()\n");
		return -1;
	}

	rc = pthread_mutex_init(&g_conns_mutex, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_init() failed\n");
		return -1;
	}
	rc = pthread_mutex_init(&g_last_tsih_mutex, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_init() failed\n");
		return -1;
	}

	g_nconns = MAX_LOGICAL_UNIT * istgt->MaxSessions * istgt->MaxConnections;
	g_nconns += MAX_LOGICAL_UNIT * istgt->MaxConnections;
	g_conns = xmalloc(sizeof *g_conns * g_nconns);
	for (i = 0; i < g_nconns; i++) {
		g_conns[i] = NULL;
	}
	g_last_tsih = 0;

	return 0;
}

int
istgt_iscsi_shutdown(ISTGT_Ptr istgt __attribute__((__unused__)))
{
	CONN_Ptr conn;
	int retry = 10;
	int num;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_iscsi_shutdown\n");

	num = 0;
	MTX_LOCK(&g_conns_mutex);
	for (i = 0; i < g_nconns; i++) {
		conn = g_conns[i];
		if (conn == NULL)
			continue;
		conn->state = CONN_STATE_EXITING;
		num++;
	}
	MTX_UNLOCK(&g_conns_mutex);

	if (num != 0) {
		/* check threads */
		while (retry > 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "check thread retry=%d\n",
			    retry);
			sleep(1);
			num = 0;
			MTX_LOCK(&g_conns_mutex);
			for (i = 0; i < g_nconns; i++) {
				conn = g_conns[i];
				if (conn == NULL)
					continue;
				num++;
			}
			MTX_UNLOCK(&g_conns_mutex);
			if (num == 0)
				break;
			retry--;
		}
	}

	rc = pthread_mutex_destroy(&g_last_tsih_mutex);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_destroy() failed\n");
		return -1;
	}
	rc = pthread_mutex_destroy(&g_conns_mutex);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_destroy() failed\n");
		return -1;
	}

	if (num == 0) {
		xfree(g_conns);
		g_conns = NULL;
	}

	return 0;
}
