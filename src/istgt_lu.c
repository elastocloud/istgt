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

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_DISK_H
#include <sys/disk.h>
#endif
#ifdef HAVE_SYS_DISKLABEL_H
#include <sys/disklabel.h>
#endif
#ifdef __linux__
#include <linux/fs.h>
#endif

#include "istgt.h"
#include "istgt_ver.h"
#include "istgt_log.h"
#include "istgt_conf.h"
#include "istgt_sock.h"
#include "istgt_misc.h"
#include "istgt_md5.h"
#include "istgt_iscsi.h"
#include "istgt_lu.h"
#include "istgt_proto.h"
#include "istgt_scsi.h"

#define MAX_MASKBUF 128
static int
istgt_lu_allow_ipv6(const char *netmask, const char *addr)
{
	struct in6_addr in6_mask;
	struct in6_addr in6_addr;
	char mask[MAX_MASKBUF];
	const char *p;
	size_t n;
	int bits, bmask;
	int i;

	if (netmask[0] != '[')
		return 0;
	p = strchr(netmask, ']');
	if (p == NULL)
		return 0;
	n = p - (netmask + 1);
	if (n + 1 > sizeof mask)
		return 0;

	memcpy(mask, netmask + 1, n);
	mask[n] = '\0';
	p++;

	if (p[0] == '/') {
		bits = (int) strtol(p + 1, NULL, 10);
		if (bits < 0 || bits > 128)
			return 0;
	} else {
		bits = 128;
	}

#if 0
	printf("input %s\n", addr);
	printf("mask  %s / %d\n", mask, bits);
#endif

	/* presentation to network order binary */
	if (inet_pton(AF_INET6, mask, &in6_mask) <= 0
		|| inet_pton(AF_INET6, addr, &in6_addr) <= 0) {
		return 0;
	}

	/* check 128bits */
	for (i = 0; i < (bits / 8); i++) {
		if (in6_mask.s6_addr[i] != in6_addr.s6_addr[i])
			return 0;
	}
	if (bits % 8) {
		bmask = (0xffU << (8 - (bits % 8))) & 0xffU;
		if ((in6_mask.s6_addr[i] & bmask) != (in6_addr.s6_addr[i] & bmask))
			return 0;
	}

	/* match */
	return 1;
}

static int
istgt_lu_allow_ipv4(const char *netmask, const char *addr)
{
	struct in_addr in4_mask;
	struct in_addr in4_addr;
	char mask[MAX_MASKBUF];
	const char *p;
	uint32_t bmask;
	size_t n;
	int bits;

	p = strchr(netmask, '/');
	if (p == NULL) {
		p = netmask + strlen(netmask);
	}
	n = p - netmask;
	if (n + 1 > sizeof mask)
		return 0;

	memcpy(mask, netmask, n);
	mask[n] = '\0';

	if (p[0] == '/') {
		bits = (int) strtol(p + 1, NULL, 10);
		if (bits < 0 || bits > 32)
			return 0;
	} else {
		bits = 32;
	}

#if 0
	printf("input %s\n", addr);
	printf("mask  %s / %d\n", mask, bits);
#endif

	/* presentation to network order binary */
	if (inet_pton(AF_INET, mask, &in4_mask) <= 0
		|| inet_pton(AF_INET, addr, &in4_addr) <= 0) {
		return 0;
	}

	/* check 32bits */
	bmask = (0xffffffffU << (32 - bits)) & 0xffffffffU;
	if ((ntohl(in4_mask.s_addr) & bmask) != (ntohl(in4_addr.s_addr) & bmask))
		return 0;

	/* match */
	return 1;
}

int
istgt_lu_allow_netmask(const char *netmask, const char *addr)
{
	if (netmask == NULL || addr == NULL)
		return 0;
	if (strcasecmp(netmask, "ALL") == 0)
		return 1;
	if (netmask[0] == '[') {
		/* IPv6 */
		if (istgt_lu_allow_ipv6(netmask, addr))
			return 1;
	} else {
		/* IPv4 */
		if (istgt_lu_allow_ipv4(netmask, addr))
			return 1;
	}
	return 0;
}

int
istgt_lu_access(CONN_Ptr conn, ISTGT_LU_Ptr lu, const char *iqn, const char *addr)
{
	ISTGT_Ptr istgt;
	INITIATOR_GROUP *igp;
	int pg_tag;
	int ig_tag;
	int rc;
	int i, j, k;

	if (conn == NULL || lu == NULL || iqn == NULL || addr == NULL)
		return 0;
	istgt = conn->istgt;
	pg_tag = conn->portal.tag;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "pg=%d, iqn=%s, addr=%s\n",
				  pg_tag, iqn, addr);
	for (i = 0; i < lu->maxmap; i++) {
		/* skip excluding self portal group tag */
		if (pg_tag != lu->map[i].pg_tag)
			continue;
		/* iqn is initiator group? */
		ig_tag = lu->map[i].ig_tag;
		igp = istgt_lu_find_initiatorgroup(istgt, ig_tag);
		if (igp == NULL) {
			ISTGT_ERRLOG("LU%d: ig_tag not found\n", lu->num);
			continue;
		}
		for (j = 0; j < igp->ninitiators; j++) {
			/* deny initiators */
			if (igp->initiators[j][0] == '!'
			    && (strcasecmp(&igp->initiators[j][1], "ALL") == 0
				|| strcasecmp(&igp->initiators[j][1], iqn) == 0)) {
				/* NG */
				ISTGT_WARNLOG("access denied from %s (%s) to %s (%s:%s,%d)\n",
				    iqn, addr, conn->target_name, conn->portal.host,
				    conn->portal.port, conn->portal.tag);
				return 0;
			}
			/* allow initiators */
			if (strcasecmp(igp->initiators[j], "ALL") == 0
			    || strcasecmp(igp->initiators[j], iqn) == 0) {
				/* OK iqn, check netmask */
				if (igp->nnetmasks == 0) {
					/* OK, empty netmask as ALL */
					return 1;
				}
				for (k = 0; k < igp->nnetmasks; k++) {
					ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
					    "netmask=%s, addr=%s\n",
					    igp->netmasks[k], addr);
					rc = istgt_lu_allow_netmask(igp->netmasks[k], addr);
					if (rc > 0) {
						/* OK netmask */
						return 1;
					}
				}
				/* NG netmask in this group */
			}
		}
	}

	/* NG */
	ISTGT_WARNLOG("access denied from %s (%s) to %s (%s:%s,%d)\n",
	    iqn, addr, conn->target_name, conn->portal.host,
	    conn->portal.port, conn->portal.tag);
	return 0;
}

int
istgt_lu_visible(ISTGT_Ptr istgt, ISTGT_LU_Ptr lu, const char *iqn, int pg_tag)
{
	INITIATOR_GROUP *igp;
	int match_pg_tag;
	int ig_tag;
	int i, j;

	if (istgt == NULL || lu == NULL || iqn == NULL)
		return 0;
	/* pg_tag exist map? */
	match_pg_tag = 0;
	for (i = 0; i < lu->maxmap; i++) {
		if (lu->map[i].pg_tag == pg_tag) {
			match_pg_tag = 1;
			break;
		}
	}
	if (match_pg_tag == 0) {
		/* cat't access from pg_tag */
		return 0;
	}
	for (i = 0; i < lu->maxmap; i++) {
		/* iqn is initiator group? */
		ig_tag = lu->map[i].ig_tag;
		igp = istgt_lu_find_initiatorgroup(istgt, ig_tag);
		if (igp == NULL) {
			ISTGT_ERRLOG("LU%d: ig_tag not found\n", lu->num);
			continue;
		}
		for (j = 0; j < igp->ninitiators; j++) {
			if (igp->initiators[j][0] == '!'
			    && (strcasecmp(&igp->initiators[j][1], "ALL") == 0
				|| strcasecmp(&igp->initiators[j][1], iqn) == 0)) {
				/* NG */
				return 0;
			}
			if (strcasecmp(igp->initiators[j], "ALL") == 0
			    || strcasecmp(igp->initiators[j], iqn) == 0) {
				/* OK iqn, no check addr */
				return 1;
			}
		}
	}

	/* NG */
	return 0;
}

static int
istgt_pg_visible(ISTGT_Ptr istgt, ISTGT_LU_Ptr lu, const char *iqn, int pg_tag)
{
	INITIATOR_GROUP *igp;
	int match_idx;
	int ig_tag;
	int i, j;

	if (istgt == NULL || lu == NULL || iqn == NULL)
		return 0;
	match_idx = -1;
	for (i = 0; i < lu->maxmap; i++) {
		if (lu->map[i].pg_tag == pg_tag) {
			match_idx = i;
			break;
		}
	}
	if (match_idx < 0) {
		/* cant't find pg_tag */
		return 0;
	}

	/* iqn is initiator group? */
	ig_tag = lu->map[match_idx].ig_tag;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "iqn=%s, pg=%d, ig=%d\n", iqn, pg_tag, ig_tag);
	igp = istgt_lu_find_initiatorgroup(istgt, ig_tag);
	if (igp == NULL) {
		ISTGT_ERRLOG("LU%d: ig_tag not found\n", lu->num);
		return 0;
	}
	for (j = 0; j < igp->ninitiators; j++) {
		if (igp->initiators[j][0] == '!'
		    && (strcasecmp(&igp->initiators[j][1], "ALL") == 0
			|| strcasecmp(&igp->initiators[j][1], iqn) == 0)) {
			/* NG */
			return 0;
		}
		if (strcasecmp(igp->initiators[j], "ALL") == 0
		    || strcasecmp(igp->initiators[j], iqn) == 0) {
			/* OK iqn, no check addr */
			return 1;
		}
	}

	/* NG */
	return 0;
}

int
istgt_lu_sendtargets(CONN_Ptr conn, const char *iiqn, const char *iaddr, const char *tiqn, uint8_t *data, int alloc_len, int data_len)
{
	char buf[MAX_TMPBUF];
	ISTGT_Ptr istgt;
	ISTGT_LU_Ptr lu;
	char *host;
	int total;
	int len;
	int rc;
	int pg_tag;
	int i, j, k, l;

	if (conn == NULL)
		return 0;
	istgt = conn->istgt;

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

	MTX_LOCK(&istgt->mutex);
	for (i = 0; i < MAX_LOGICAL_UNIT; i++) {
		lu = istgt->logical_unit[i];
		if (lu == NULL)
			continue;
		if (strcasecmp(tiqn, "ALL") != 0
			&& strcasecmp(tiqn, lu->name) != 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "SKIP iqn=%s for %s from %s (%s)\n",
			    tiqn, lu->name, iiqn, iaddr);
			continue;
		}
		rc = istgt_lu_visible(istgt, lu, iiqn, conn->portal.tag);
		if (rc == 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "SKIP iqn=%s for %s from %s (%s)\n",
			    tiqn, lu->name, iiqn, iaddr);
			continue;
		}

		/* DO SENDTARGETS */
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "OK iqn=%s for %s from %s (%s)\n",
		    tiqn, lu->name, iiqn, iaddr);

		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "TargetName=%s\n", lu->name);
		len = snprintf((char *) data + total, alloc_len - total,
		    "TargetName=%s", lu->name);
		total += len + 1;

		for (j = 0; j < lu->maxmap; j++) {
			pg_tag = lu->map[j].pg_tag;
			/* skip same pg_tag */
			for (k = 0; k < j; k++) {
				if (lu->map[k].pg_tag == pg_tag) {
					goto skip_pg_tag;
				}
			}
			rc = istgt_pg_visible(istgt, lu, iiqn, pg_tag);
			if (rc == 0) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "SKIP pg=%d, iqn=%s for %s from %s (%s)\n",
				    pg_tag, tiqn, lu->name, iiqn, iaddr);
				goto skip_pg_tag;
			}

			/* write to data */
			for (k = 0; k < istgt->nportal_group; k++) {
				if (istgt->portal_group[k].tag != pg_tag)
					continue;
				for (l = 0; l < istgt->portal_group[k].nportals; l++) {
					if (alloc_len - total < 1) {
						MTX_UNLOCK(&istgt->mutex);
						ISTGT_ERRLOG("data space small %d\n",
						    alloc_len);
						return total;
					}
					host = istgt->portal_group[k].portals[l]->host;
					/* wildcard? */
					if (strcasecmp(host, "[::]") == 0
					    || strcasecmp(host, "[*]") == 0
					    || strcasecmp(host, "0.0.0.0") == 0
					    || strcasecmp(host, "*") == 0) {
						if ((strcasecmp(host, "[::]") == 0
							|| strcasecmp(host, "[*]") == 0)
						    && conn->initiator_family == AF_INET6) {
							snprintf(buf, sizeof buf, "[%s]",
							    conn->target_addr);
							host = buf;
						} else if ((strcasecmp(host, "0.0.0.0") == 0
							|| strcasecmp(host, "*") == 0)
						    && conn->initiator_family == AF_INET) {
							snprintf(buf, sizeof buf, "%s",
							    conn->target_addr);
							host = buf;
						} else {
							/* skip portal for the family */
							continue;
						}
					}
					ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
					    "TargetAddress=%s:%s,%d\n",
					    host,
					    istgt->portal_group[k].portals[l]->port,
					    istgt->portal_group[k].portals[l]->tag);
					len = snprintf((char *) data + total,
					    alloc_len - total,
					    "TargetAddress=%s:%s,%d",
					    host,
					    istgt->portal_group[k].portals[l]->port,
					    istgt->portal_group[k].portals[l]->tag);
					total += len + 1;
				}
			}
		skip_pg_tag:
			;
		}
	}
	MTX_UNLOCK(&istgt->mutex);

	return total;
}

ISTGT_LU_Ptr
istgt_lu_find_target(ISTGT_Ptr istgt, const char *target_name)
{
	ISTGT_LU_Ptr lu;
	int i;

	if (istgt == NULL || target_name == NULL)
		return NULL;
	for (i = 0; i < MAX_LOGICAL_UNIT; i++) {
		lu = istgt->logical_unit[i];
		if (lu == NULL)
			continue;
		if (strcasecmp(target_name, lu->name) == 0) {
			return lu;
		}
	}
	ISTGT_WARNLOG("can't find target %s\n",
	    target_name);
	return NULL;
}

uint16_t
istgt_lu_allocate_tsih(ISTGT_LU_Ptr lu, const char *initiator_port, int tag)
{
	uint16_t tsih;
	int retry = 10;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_allocate_tsih\n");
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "initiator_port=%s, tag=%d\n",
	    initiator_port, tag);
	if (lu == NULL || initiator_port == NULL || tag == 0)
		return 0;
	/* tsih 0 is reserved */
	tsih = 0;
	MTX_LOCK(&lu->mutex);
#if 0
	for (i = 1; i < MAX_LU_TSIH; i++) {
		if (lu->tsih[i].initiator_port == NULL)
			continue;
		if (tag != lu->tsih[i].tag)
			continue;
		if (strcasecmp(initiator_port, lu->tsih[i].initiator_port) == 0) {
			tsih = lu->tsih[i].tsih;
			break;
		}
	}
#endif
	if (tsih == 0) {
		if (lu->maxtsih >= MAX_LU_TSIH) {
			ISTGT_ERRLOG("LU%d: tsih is maximum\n", lu->num);
			MTX_UNLOCK(&lu->mutex);
			return 0;
		}
	retry:
		lu->last_tsih++;
		tsih = lu->last_tsih;
		if (tsih == 0) {
			if (retry > 0) {
				retry--;
				goto retry;
			}
			ISTGT_ERRLOG("LU%d: retry error\n", lu->num);
			MTX_UNLOCK(&lu->mutex);
			return 0;
		}
		for (i = 1; i < MAX_LU_TSIH; i++) {
			if (lu->tsih[i].initiator_port != NULL
				&& lu->tsih[i].tsih == tsih) {
				ISTGT_ERRLOG("tsih is found in list\n");
				if (retry > 0) {
					retry--;
					goto retry;
				}
				ISTGT_ERRLOG("LU%d: retry error\n", lu->num);
				MTX_UNLOCK(&lu->mutex);
				return 0;
			}
		}
		for (i = 1; i < MAX_LU_TSIH; i++) {
			if (lu->tsih[i].initiator_port == NULL) {
				lu->tsih[i].tag = tag;
				lu->tsih[i].tsih = tsih;
				lu->tsih[i].initiator_port = xstrdup(initiator_port);
				lu->maxtsih++;
				break;
			}
		}
	}
	MTX_UNLOCK(&lu->mutex);
	return tsih;
}

void
istgt_lu_free_tsih(ISTGT_LU_Ptr lu, uint16_t tsih, char *initiator_port)
{
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_free_tsih\n");
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "tsih=%u, initiator_port=%s\n",
	    tsih, initiator_port);
	if (lu == NULL || initiator_port == NULL)
		return;
	if (tsih == 0)
		return;

	MTX_LOCK(&lu->mutex);
	for (i = 1; i < MAX_LU_TSIH; i++) {
		if (lu->tsih[i].initiator_port == NULL)
			continue;
		if (lu->tsih[i].tsih != tsih)
			continue;

		if (strcasecmp(initiator_port, lu->tsih[i].initiator_port) == 0) {
			lu->tsih[i].tag = 0;
			lu->tsih[i].tsih = 0;
			xfree(lu->tsih[i].initiator_port);
			lu->tsih[i].initiator_port = NULL;
			lu->maxtsih--;
			break;
		}
	}
	MTX_UNLOCK(&lu->mutex);
	return;
}

char *
istgt_lu_get_media_flags_string(int flags, char *buf, size_t len)
{
	char *p;
	size_t rest;

	p = buf;
	rest = len;
	if (flags & ISTGT_LU_FLAG_MEDIA_READONLY) {
		snprintf(p, rest, "%s", "ro");
	} else {
		snprintf(p, rest, "%s", "rw");
	}
	p = buf + strlen(buf);
	rest = len - strlen(buf);
	if (flags & ISTGT_LU_FLAG_MEDIA_EXTEND) {
		snprintf(p, rest, ",%s", "extend");
	}
	p = buf + strlen(buf);
	rest = len - strlen(buf);
	if (flags & ISTGT_LU_FLAG_MEDIA_DYNAMIC) {
		snprintf(p, rest, ",%s", "dynamic");
	}
	return buf;
}

uint64_t
istgt_lu_get_devsize(const char *file)
{
	uint64_t val;
	struct stat st;
	int fd;
	int rc;

	val = 0ULL;
#ifdef ALLOW_SYMLINK_DEVICE
	rc = stat(file, &st);
#else
	rc = lstat(file, &st);
#endif /* ALLOW_SYMLINK_DEVICE */
	if (rc != 0)
		return val;
	if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode))
		return val;

	fd = open(file, O_RDONLY, 0);
	if (fd >= 0) {
#ifdef DIOCGMEDIASIZE
		if (val == 0) {
			off_t offset;
			rc = ioctl(fd, DIOCGMEDIASIZE, &offset);
			if (rc != -1) {
				val = (uint64_t) offset;
			}
		}
#endif /* DIOCGMEDIASIZE */
#ifdef DIOCGDINFO
		if (val == 0) {
			struct disklabel dl;
			rc = ioctl(fd, DIOCGDINFO, &dl);
			if (rc != -1) {
				val = (uint64_t) dl.d_secperunit;
				val *= (uint64_t) dl.d_secsize;
			}
		}
#endif /* DIOCGDINFO */
#if defined(DKIOCGETBLOCKSIZE) && defined(DKIOCGETBLOCKCOUNT)
		if (val == 0) {
			uint32_t blocklen;
			uint64_t blockcnt;
			rc = ioctl(fd, DKIOCGETBLOCKSIZE, &blocklen);
			if (rc != -1) {
				rc = ioctl(fd, DKIOCGETBLOCKCOUNT, &blockcnt);
				if (rc != -1) {
					val = (uint64_t) blocklen;
					val *= (uint64_t) blockcnt;
				}
			}
		}
#endif /* DKIOCGETBLOCKSIZE && DKIOCGETBLOCKCOUNT */
#ifdef __linux__
#ifdef BLKGETSIZE64
		if (val == 0) {
			uint64_t blocksize;
			rc = ioctl(fd, BLKGETSIZE64, &blocksize);
			if (rc != -1) {
				val = (uint64_t) blocksize;
			}
		}
#endif /* BLKGETSIZE64 */
#ifdef BLKGETSIZE
		if (val == 0) {
			uint32_t blocksize;
			rc = ioctl(fd, BLKGETSIZE, &blocksize);
			if (rc != -1) {
				val = (uint64_t) 512;
				val *= (uint64_t) blocksize;
			}
		}
#endif /* BLKGETSIZE */
#endif /* __linux__ */
		if (val == 0) {
			ISTGT_ERRLOG("unknown device size\n");
		}
		(void) close(fd);
	} else {
		if (g_trace_flag) {
			ISTGT_WARNLOG("open error %s (errno=%d)\n", file, errno);
		}
		val = 0ULL;
	}
	return val;
}

uint64_t
istgt_lu_get_filesize(const char *file)
{
	uint64_t val;
	struct stat st;
	int rc;

	val = 0ULL;
#ifdef ALLOW_SYMLINK_DEVICE
	rc = stat(file, &st);
#else
	rc = lstat(file, &st);
#endif /* ALLOW_SYMLINK_DEVICE */

	if (rc < 0)
		return val;
#ifndef ALLOW_SYMLINK_DEVICE
	if (S_ISLNK(st.st_mode))
		return val;
#endif /* ALLOW_SYMLINK_DEVICE */

	if (S_ISCHR(st.st_mode)) {
		val = istgt_lu_get_devsize(file);
	} else if (S_ISBLK(st.st_mode)) {
		val = istgt_lu_get_devsize(file);
	} else if (S_ISREG(st.st_mode)) {
		val = st.st_size;
	} else {
#ifdef ALLOW_SYMLINK_DEVICE
		ISTGT_ERRLOG("stat is neither REG, CHR nor BLK\n");
#else
		ISTGT_ERRLOG("lstat is neither REG, CHR nor BLK\n");
#endif /* ALLOW_SYMLINK_DEVICE */
		val = 0ULL;
	}
	return val;
}

uint64_t
istgt_lu_parse_size(const char *size)
{
	uint64_t val, val1, val2;
	char *endp, *p;
	size_t idx;
	int sign;

	val1 = (uint64_t) strtoull(size, &endp, 10);
	val = val1;
	val2 = 0;
	if (endp != NULL) {
		p = endp;
		switch (toupper((int) *p)) {
		case 'Z': val1 *= (uint64_t) 1024ULL;
		case 'E': val1 *= (uint64_t) 1024ULL;
		case 'P': val1 *= (uint64_t) 1024ULL;
		case 'T': val1 *= (uint64_t) 1024ULL;
		case 'G': val1 *= (uint64_t) 1024ULL;
		case 'M': val1 *= (uint64_t) 1024ULL;
		case 'K': val1 *= (uint64_t) 1024ULL;
			break;
		}
		val = val1;
		p++;
		idx = strspn(p, "Bb \t");
		p += idx;
		if (*p == '-' || *p == '+') {
			sign = (int) *p++;
			idx = strspn(p, " \t");
			p += idx;
			val2 = (uint64_t) strtoull(p, &endp, 10);
			if (endp != NULL) {
				p = endp;
				switch (toupper((int) *p)) {
				case 'Z': val2 *= (uint64_t) 1024ULL;
				case 'E': val2 *= (uint64_t) 1024ULL;
				case 'P': val2 *= (uint64_t) 1024ULL;
				case 'T': val2 *= (uint64_t) 1024ULL;
				case 'G': val2 *= (uint64_t) 1024ULL;
				case 'M': val2 *= (uint64_t) 1024ULL;
				case 'K': val2 *= (uint64_t) 1024ULL;
					break;
				}
			}
			if (sign == '-') {
				if (val2 > val1) {
					/* underflow */
					val = (uint64_t) 0ULL;
				} else {
					val = val1 - val2;
				}
			} else {
				if (val2 > (UINT64_MAX - val1)) {
					/* overflow */
					val = UINT64_MAX;
				} else {
					val = val1 + val2;
				}
			}
		}
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "size=%s, val=%"PRIu64", val1=%"PRIu64", val2=%"PRIu64"\n",
	    size, val, val1, val2);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "size=%s, val=%"PRIx64", val1=%"PRIx64", val2=%"PRIx64"\n",
	    size, val, val1, val2);

	return val;
}

int
istgt_lu_parse_media_flags(const char *flags)
{
	char buf[MAX_TMPBUF];
	const char *delim = ",";
	char *next_p;
	char *p;
	int mflags;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "mflags=%s\n", flags);
	mflags = 0;
	strlcpy(buf, flags, MAX_TMPBUF);
	next_p = buf;
	while ((p = strsep(&next_p, delim)) != NULL) {
		if (strcasecmp(p, "ro") == 0) {
			mflags |= ISTGT_LU_FLAG_MEDIA_READONLY;
		} else if (strcasecmp(p, "rw") == 0) {
			mflags &= ~ISTGT_LU_FLAG_MEDIA_READONLY;
		} else if (strcasecmp(p, "extend") == 0) {
			mflags |= ISTGT_LU_FLAG_MEDIA_EXTEND;
		} else if (strcasecmp(p, "dynamic") == 0) {
			mflags |= ISTGT_LU_FLAG_MEDIA_DYNAMIC;
		} else {
			ISTGT_ERRLOG("unknown media flag %.64s\n", p);
		}
	}

	return mflags;
}

uint64_t
istgt_lu_parse_media_size(const char *file, const char *size, int *flags)
{
	uint64_t msize, fsize;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "msize=%s\n", size);
	if (strcasecmp(file, "/dev/null") == 0) {
		return 0;
	}
	if (strcasecmp(size, "Auto") == 0
	    || strcasecmp(size, "Size") == 0) {
		msize = istgt_lu_get_filesize(file);
		if (msize == 0) {
			msize = ISTGT_LU_MEDIA_SIZE_MIN;
		}
		*flags |= ISTGT_LU_FLAG_MEDIA_AUTOSIZE;
	} else {
		msize = istgt_lu_parse_size(size);
		if (*flags & ISTGT_LU_FLAG_MEDIA_EXTEND) {
			fsize = istgt_lu_get_filesize(file);
			if (fsize > msize) {
				msize = fsize;
			}
		}
	}

	if (*flags & ISTGT_LU_FLAG_MEDIA_DYNAMIC) {
		if (msize < ISTGT_LU_MEDIA_SIZE_MIN) {
			msize = ISTGT_LU_MEDIA_SIZE_MIN;
		}
	} else {
		if (msize < ISTGT_LU_MEDIA_SIZE_MIN) {
			ISTGT_ERRLOG("media size too small\n");
			return 0ULL;
		}
	}

	return msize;
}

PORTAL_GROUP *
istgt_lu_find_portalgroup(ISTGT_Ptr istgt, int tag)
{
	PORTAL_GROUP *pgp;
	int i;

	for (i = 0; i < istgt->nportal_group; i++) {
		if (istgt->portal_group[i].tag == tag) {
			pgp = &istgt->portal_group[i];
			return pgp;
		}
	}
	return NULL;
}

INITIATOR_GROUP *
istgt_lu_find_initiatorgroup(ISTGT_Ptr istgt, int tag)
{
	INITIATOR_GROUP *igp;
	int i;

	for (i = 0; i < istgt->ninitiator_group; i++) {
		if (istgt->initiator_group[i].tag == tag) {
			igp = &istgt->initiator_group[i];
			return igp;
		}
	}
	return NULL;
}

static int
istgt_lu_check_iscsi_name(const char *name)
{
	const unsigned char *up = (const unsigned char *) name;
	size_t n;

	/* valid iSCSI name? */
	for (n = 0; up[n] != 0; n++) {
		if (up[n] > 0x00U && up[n] <= 0x2cU)
			return -1;
		if (up[n] == 0x2fU)
			return -1;
		if (up[n] >= 0x3bU && up[n] <= 0x40U)
			return -1;
		if (up[n] >= 0x5bU && up[n] <= 0x60U)
			return -1;
		if (up[n] >= 0x7bU && up[n] <= 0x7fU)
			return -1;
		if (isspace(up[n]))
			return -1;
	}
	/* valid format? */
	if (strncasecmp(name, "iqn.", 4) == 0) {
		/* iqn.YYYY-MM.reversed.domain.name */
		if (!isdigit(up[4]) || !isdigit(up[5]) || !isdigit(up[6])
		    || !isdigit(up[7]) || up[8] != '-' || !isdigit(up[9])
		    || !isdigit(up[10]) || up[11] != '.') {
			ISTGT_ERRLOG("invalid iqn format. "
			    "expect \"iqn.YYYY-MM.reversed.domain.name\"\n");
			return -1;
		}
	} else if (strncasecmp(name, "eui.", 4) == 0) {
		/* EUI-64 -> 16bytes */
		/* XXX */
	} else if (strncasecmp(name, "naa.", 4) == 0) {
		/* 64bit -> 16bytes, 128bit -> 32bytes */
		/* XXX */
	}
	/* OK */
	return 0;
}

#if 0
static uint64_t
istgt_lu_get_nbserial(const char *nodebase)
{
	ISTGT_MD5CTX md5ctx;
	uint8_t nbsmd5[ISTGT_MD5DIGEST_LEN];
	char buf[MAX_TMPBUF];
	uint64_t nbs;
	int idx;
	int i;

	snprintf(buf, sizeof buf, "%s", nodebase);
	if (strcasecmp(buf, "iqn.2007-09.jp.ne.peach.istgt") == 0
	    || strcasecmp(buf, "iqn.2007-09.jp.ne.peach") == 0) {
		/* always zero */
		return 0;
	}

	istgt_md5init(&md5ctx);
	istgt_md5update(&md5ctx, buf, strlen(buf));
	istgt_md5final(nbsmd5, &md5ctx);

	nbs = 0U;
	idx = ISTGT_MD5DIGEST_LEN - 8;
	if (idx < 0) {
		ISTGT_WARNLOG("missing MD5 length\n");
		idx = 0;
	}
	for (i = idx; i < ISTGT_MD5DIGEST_LEN; i++) {
		nbs |= (uint64_t) nbsmd5[i];
		nbs = nbs << 8;
	}
	return nbs;
}
#endif

static int
istgt_lu_set_local_settings(ISTGT_Ptr istgt, CF_SECTION *sp, ISTGT_LU_Ptr lu)
{
	const char *val;

	val = istgt_get_val(sp, "MaxOutstandingR2T");
	if (val == NULL) {
		lu->MaxOutstandingR2T = lu->istgt->MaxOutstandingR2T;
	} else {
		lu->MaxOutstandingR2T = (int)strtol(val, NULL, 10);
		if (lu->MaxOutstandingR2T < 1) {
			lu->MaxOutstandingR2T = DEFAULT_MAXOUTSTANDINGR2T;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "MaxOutstandingR2T %d\n",
		    lu->MaxOutstandingR2T);
	}

	val = istgt_get_val(sp, "DefaultTime2Wait");
	if (val == NULL) {
		lu->DefaultTime2Wait = lu->istgt->DefaultTime2Wait;
	} else {
		lu->DefaultTime2Wait = (int)strtol(val, NULL, 10);
		if (lu->DefaultTime2Wait < 0) {
			lu->DefaultTime2Wait = DEFAULT_DEFAULTTIME2WAIT;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "DefaultTime2Wait %d\n",
		    lu->DefaultTime2Wait);
	}

	val = istgt_get_val(sp, "DefaultTime2Retain");
	if (val == NULL) {
		lu->DefaultTime2Retain = lu->istgt->DefaultTime2Retain;
	} else {
		lu->DefaultTime2Retain = (int)strtol(val, NULL, 10);
		if (lu->DefaultTime2Retain < 0) {
			lu->DefaultTime2Retain = DEFAULT_DEFAULTTIME2RETAIN;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "DefaultTime2Retain %d\n",
		    lu->DefaultTime2Retain);
	}

	/* check size limit - RFC3720(12.15, 12.16, 12.17) */
	if (lu->MaxOutstandingR2T > 65535) {
		ISTGT_ERRLOG("MaxOutstandingR2T(%d) > 65535\n",
		    lu->MaxOutstandingR2T);
		return -1;
	}
	if (lu->DefaultTime2Wait > 3600) {
		ISTGT_ERRLOG("DefaultTime2Wait(%d) > 3600\n",
		    lu->DefaultTime2Wait);
		return -1;
	}
	if (lu->DefaultTime2Retain > 3600) {
		ISTGT_ERRLOG("DefaultTime2Retain(%d) > 3600\n",
		    lu->DefaultTime2Retain);
		return -1;
	}

	val = istgt_get_val(sp, "FirstBurstLength");
	if (val == NULL) {
		lu->FirstBurstLength = lu->istgt->FirstBurstLength;
	} else {
		lu->FirstBurstLength = (int)strtol(val, NULL, 10);
		if (lu->FirstBurstLength < 0) {
			lu->FirstBurstLength = DEFAULT_FIRSTBURSTLENGTH;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "FirstBurstLength %d\n",
		    lu->FirstBurstLength);
	}

	val = istgt_get_val(sp, "MaxBurstLength");
	if (val == NULL) {
		lu->MaxBurstLength = lu->istgt->MaxBurstLength;
	} else {
		lu->MaxBurstLength = (int)strtol(val, NULL, 10);
		if (lu->MaxBurstLength < 0) {
			lu->MaxBurstLength = DEFAULT_MAXBURSTLENGTH;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "MaxBurstLength %d\n",
		    lu->MaxBurstLength);
	}

	val = istgt_get_val(sp, "MaxRecvDataSegmentLength");
	if (val == NULL) {
		lu->MaxRecvDataSegmentLength
			= lu->istgt->MaxRecvDataSegmentLength;
	} else {
		lu->MaxRecvDataSegmentLength = (int)strtol(val, NULL, 10);
		if (lu->MaxRecvDataSegmentLength < 0) {
			lu->MaxRecvDataSegmentLength
				= DEFAULT_MAXRECVDATASEGMENTLENGTH;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "MaxRecvDataSegmentLength %d\n",
		    lu->MaxRecvDataSegmentLength);
	}

	/* check size limit (up to 24bits - RFC3720(12.12)) */
	if (lu->MaxBurstLength < 512) {
		ISTGT_ERRLOG("MaxBurstLength(%d) < 512\n",
		    lu->MaxBurstLength);
		return -1;
	}
	if (lu->FirstBurstLength < 512) {
		ISTGT_ERRLOG("FirstBurstLength(%d) < 512\n",
		    lu->FirstBurstLength);
		return -1;
	}
	if (lu->FirstBurstLength > lu->MaxBurstLength) {
		ISTGT_ERRLOG("FirstBurstLength(%d) > MaxBurstLength(%d)\n",
		    lu->FirstBurstLength, istgt->MaxBurstLength);
		return -1;
	}
	if (lu->MaxBurstLength > 0x00ffffff) {
		ISTGT_ERRLOG("MaxBurstLength(%d) > 0x00ffffff\n",
		    lu->MaxBurstLength);
		return -1;
	}
	if (lu->MaxRecvDataSegmentLength < 512) {
		ISTGT_ERRLOG("MaxRecvDataSegmentLength(%d) < 512\n",
		    lu->MaxRecvDataSegmentLength);
		return -1;
	}
	if (lu->MaxRecvDataSegmentLength > 0x00ffffff) {
		ISTGT_ERRLOG("MaxRecvDataSegmentLength(%d) > 0x00ffffff\n",
		    lu->MaxRecvDataSegmentLength);
		return -1;
	}

	val = istgt_get_val(sp, "InitialR2T");
	if (val == NULL) {
		lu->InitialR2T = lu->istgt->InitialR2T;
	} else {
		if (strcasecmp(val, "Yes") == 0) {
			lu->InitialR2T = 1;
		} else if (strcasecmp(val, "No") == 0) {
#if 0
			lu->InitialR2T = 0;
#else
			ISTGT_ERRLOG("not supported value %s\n", val);
			return -1;
#endif
		} else {
			ISTGT_ERRLOG("unknown value %s\n", val);
			return -1;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "InitialR2T %s\n",
		    lu->InitialR2T ? "Yes" : "No");
	}

	val = istgt_get_val(sp, "ImmediateData");
	if (val == NULL) {
		lu->ImmediateData = lu->istgt->ImmediateData;
	} else {
		if (strcasecmp(val, "Yes") == 0) {
			lu->ImmediateData = 1;
		} else if (strcasecmp(val, "No") == 0) {
			lu->ImmediateData = 0;
		} else {
			ISTGT_ERRLOG("unknown value %s\n", val);
			return -1;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "ImmediateData %s\n",
		    lu->ImmediateData ? "Yes" : "No");
	}

	val = istgt_get_val(sp, "DataPDUInOrder");
	if (val == NULL) {
		lu->DataPDUInOrder = lu->istgt->DataPDUInOrder;
	} else {
		if (strcasecmp(val, "Yes") == 0) {
			lu->DataPDUInOrder = 1;
		} else if (strcasecmp(val, "No") == 0) {
#if 0
			lu->DataPDUInOrder = 0;
#else
			ISTGT_ERRLOG("not supported value %s\n", val);
			return -1;
#endif
		} else {
			ISTGT_ERRLOG("unknown value %s\n", val);
			return -1;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "DataPDUInOrder %s\n",
		    lu->DataPDUInOrder ? "Yes" : "No");
	}

	val = istgt_get_val(sp, "DataSequenceInOrder");
	if (val == NULL) {
		lu->DataSequenceInOrder = lu->istgt->DataSequenceInOrder;
	} else {
		if (strcasecmp(val, "Yes") == 0) {
			lu->DataSequenceInOrder = 1;
		} else if (strcasecmp(val, "No") == 0) {
#if 0
			lu->DataSequenceInOrder = 0;
#else
			ISTGT_ERRLOG("not supported value %s\n", val);
			return -1;
#endif
		} else {
			ISTGT_ERRLOG("unknown value %s\n", val);
			return -1;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "DataSequenceInOrder %s\n",
		    lu->DataSequenceInOrder ? "Yes" : "No");
	}

	val = istgt_get_val(sp, "ErrorRecoveryLevel");
	if (val == NULL) {
		lu->ErrorRecoveryLevel = lu->istgt->ErrorRecoveryLevel;
	} else {
		lu->ErrorRecoveryLevel = (int)strtol(val, NULL, 10);
		if (lu->ErrorRecoveryLevel < 0) {
			lu->ErrorRecoveryLevel = DEFAULT_ERRORRECOVERYLEVEL;
		} else if (lu->ErrorRecoveryLevel == 0) {
			lu->ErrorRecoveryLevel = 0;
		} else if (lu->ErrorRecoveryLevel == 1) {
#if 0
			lu->ErrorRecoveryLevel = 1;
#else
			ISTGT_ERRLOG("not supported value %d\n",
			    lu->ErrorRecoveryLevel);
			return -1;
#endif
		} else if (lu->ErrorRecoveryLevel == 2) {
#if 0
			lu->ErrorRecoveryLevel = 2;
#else
			ISTGT_ERRLOG("not supported value %d\n",
			    lu->ErrorRecoveryLevel);
			return -1;
#endif
		} else {
			ISTGT_ERRLOG("not supported value %d\n",
			    lu->ErrorRecoveryLevel);
			return -1;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "ErrorRecoveryLevel %d\n",
		    istgt->ErrorRecoveryLevel);
	}

	return 0;
}

static int
istgt_lu_add_unit(ISTGT_Ptr istgt, CF_SECTION *sp)
{
	char buf[MAX_TMPBUF], buf2[MAX_TMPBUF];
	ISTGT_LU_Ptr lu;
	PORTAL_GROUP *pgp;
	INITIATOR_GROUP *igp;
	const char *vendor, *product, *revision, *serial;
	const char *pg_tag, *ig_tag;
	const char *ag_tag;
	const char *flags, *file, *size;
	const char *key, *val;
	uint64_t msize;
	//uint64_t nbs64;
	int pg_tag_i, ig_tag_i;
	int ag_tag_i;
	int rpm, formfactor;
	int mflags;
	int slot;
	int nbs;
	int i, j, k;
	int rc;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "add unit %d\n", sp->num);

	if (sp->num >= MAX_LOGICAL_UNIT) {
		ISTGT_ERRLOG("LU%d: over maximum unit number\n", sp->num);
		return -1;
	}
	if (istgt->logical_unit[sp->num] != NULL) {
		ISTGT_ERRLOG("LU%d: duplicate unit\n", sp->num);
		return -1;
	}

	lu = xmalloc(sizeof *lu);
	memset(lu, 0, sizeof *lu);
	lu->num = sp->num;
	lu->istgt = istgt;
	lu->state = ISTGT_STATE_INVALID;
#if 0
	/* disabled now */
	nbs64 = istgt_lu_get_nbserial(istgt->nodebase);
	nbs = (int) (nbs64 % 900) * 100000;
#else
	nbs = 0;
#endif

	val = istgt_get_val(sp, "Comment");
	if (val != NULL) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Comment %s\n", val);
	}

	val = istgt_get_val(sp, "TargetName");
	if (val == NULL) {
		ISTGT_ERRLOG("LU%d: TargetName not found\n", lu->num);
		goto error_return;
	}
	if (strncasecmp(val, "iqn.", 4) != 0
		&& strncasecmp(val, "eui.", 4) != 0
		&& strncasecmp(val, "naa.", 4) != 0) {
		snprintf(buf, sizeof buf, "%s:%s", istgt->nodebase, val);
	} else {
		snprintf(buf, sizeof buf, "%s", val);
	}
	if (istgt_lu_check_iscsi_name(buf) != 0) {
		ISTGT_ERRLOG("TargetName %s contains an invalid character or format.\n",
		    buf);
#if 0
		goto error_return;
#endif
	}
	lu->name = xstrdup(buf);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "TargetName %s\n",
				   lu->name);

	val = istgt_get_val(sp, "TargetAlias");
	if (val == NULL) {
		lu->alias = NULL;
	} else {
		lu->alias = xstrdup(val);
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "TargetAlias %s\n",
	    lu->alias);

	val = istgt_get_val(sp, "Mapping");
	if (val == NULL) {
		/* no map */
		lu->maxmap = 0;
	} else {
		lu->maxmap = 0;
		for (i = 0; ; i++) {
			val = istgt_get_nmval(sp, "Mapping", i, 0);
			if (val == NULL)
				break;
			if (lu->maxmap >= MAX_LU_MAP) {
				ISTGT_ERRLOG("LU%d: too many mapping\n", lu->num);
				goto error_return;
			}
			pg_tag = istgt_get_nmval(sp, "Mapping", i, 0);
			ig_tag = istgt_get_nmval(sp, "Mapping", i, 1);
			if (pg_tag == NULL || ig_tag == NULL) {
				ISTGT_ERRLOG("LU%d: mapping error\n", lu->num);
				goto error_return;
			}
			if (strncasecmp(pg_tag, "PortalGroup",
				strlen("PortalGroup")) != 0
			    || sscanf(pg_tag, "%*[^0-9]%d", &pg_tag_i) != 1) {
				ISTGT_ERRLOG("LU%d: mapping portal error\n", lu->num);
				goto error_return;
			}
			if (strncasecmp(ig_tag, "InitiatorGroup",
				strlen("InitiatorGroup")) != 0
			    || sscanf(ig_tag, "%*[^0-9]%d", &ig_tag_i) != 1) {
				ISTGT_ERRLOG("LU%d: mapping initiator error\n", lu->num);
				goto error_return;
			}
			if (pg_tag_i < 1 || ig_tag_i < 1) {
				ISTGT_ERRLOG("LU%d: invalid group tag\n", lu->num);
				goto error_return;
			}
			MTX_LOCK(&istgt->mutex);
			pgp = istgt_lu_find_portalgroup(istgt, pg_tag_i);
			if (pgp == NULL) {
				MTX_UNLOCK(&istgt->mutex);
				ISTGT_ERRLOG("LU%d: PortalGroup%d not found\n",
							 lu->num, pg_tag_i);
				goto error_return;
			}
			igp = istgt_lu_find_initiatorgroup(istgt, ig_tag_i);
			if (igp == NULL) {
				MTX_UNLOCK(&istgt->mutex);
				ISTGT_ERRLOG("LU%d: InitiatorGroup%d not found\n",
				    lu->num, ig_tag_i);
				goto error_return;
			}
			pgp->ref++;
			igp->ref++;
			MTX_UNLOCK(&istgt->mutex);
			lu->map[i].pg_tag = pg_tag_i;
			lu->map[i].pg_aas = AAS_ACTIVE_OPTIMIZED;
			//lu->map[i].pg_aas = AAS_ACTIVE_NON_OPTIMIZED;
			lu->map[i].pg_aas |= AAS_STATUS_IMPLICIT;
			lu->map[i].ig_tag = ig_tag_i;
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "Mapping PortalGroup%d InitiatorGroup%d\n",
			    lu->map[i].pg_tag, lu->map[i].ig_tag);
			lu->maxmap = i + 1;
		}
	}
	if (lu->maxmap == 0) {
		ISTGT_ERRLOG("LU%d: no Mapping\n", lu->num);
		goto error_return;
	}

	val = istgt_get_val(sp, "AuthMethod");
	if (val == NULL) {
		/* none */
		lu->no_auth_chap = 0;
		lu->auth_chap = 0;
		lu->auth_chap_mutual = 0;
	} else {
		lu->no_auth_chap = 0;
		for (i = 0; ; i++) {
			val = istgt_get_nmval(sp, "AuthMethod", 0, i);
			if (val == NULL)
				break;
			if (strcasecmp(val, "CHAP") == 0) {
				lu->auth_chap = 1;
			} else if (strcasecmp(val, "Mutual") == 0) {
				lu->auth_chap_mutual = 1;
			} else if (strcasecmp(val, "Auto") == 0) {
				lu->auth_chap = 0;
				lu->auth_chap_mutual = 0;
			} else if (strcasecmp(val, "None") == 0) {
				lu->no_auth_chap = 1;
				lu->auth_chap = 0;
				lu->auth_chap_mutual = 0;
			} else {
				ISTGT_ERRLOG("LU%d: unknown auth\n", lu->num);
				goto error_return;
			}
		}
		if (lu->auth_chap_mutual && !lu->auth_chap) {
			ISTGT_ERRLOG("LU%d: Mutual but not CHAP\n", lu->num);
			goto error_return;
		}
	}
	if (lu->no_auth_chap != 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AuthMethod None\n");
	} else if (lu->auth_chap == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AuthMethod Auto\n");
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AuthMethod %s %s\n",
		    lu->auth_chap ? "CHAP" : "",
		    lu->auth_chap_mutual ? "Mutual" : "");
	}

	val = istgt_get_val(sp, "AuthGroup");
	if (val == NULL) {
		lu->auth_group = 0;
	} else {
		ag_tag = val;
		if (strcasecmp(ag_tag, "None") == 0) {
			ag_tag_i = 0;
		} else {
			if (strncasecmp(ag_tag, "AuthGroup",
				strlen("AuthGroup")) != 0
			    || sscanf(ag_tag, "%*[^0-9]%d", &ag_tag_i) != 1) {
				ISTGT_ERRLOG("LU%d: auth group error\n", lu->num);
				goto error_return;
			}
			if (ag_tag_i == 0) {
				ISTGT_ERRLOG("LU%d: invalid auth group %d\n", lu->num,
				    ag_tag_i);
				goto error_return;
			}
		}
		lu->auth_group = ag_tag_i;
	}
	if (lu->auth_group == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AuthGroup None\n");
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AuthGroup AuthGroup%d\n",
		    lu->auth_group);
	}

	val = istgt_get_val(sp, "UseDigest");
	if (val != NULL) {
		for (i = 0; ; i++) {
			val = istgt_get_nmval(sp, "UseDigest", 0, i);
			if (val == NULL)
				break;
			if (strcasecmp(val, "Header") == 0) {
				lu->header_digest = 1;
			} else if (strcasecmp(val, "Data") == 0) {
				lu->data_digest = 1;
			} else if (strcasecmp(val, "Auto") == 0) {
				lu->header_digest = 0;
				lu->data_digest = 0;
			} else {
				ISTGT_ERRLOG("LU%d: unknown digest\n", lu->num);
				goto error_return;
			}
		}
	}
	if (lu->header_digest == 0 && lu->data_digest == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "UseDigest Auto\n");
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "UseDigest %s %s\n",
		    lu->header_digest ? "Header" : "",
		    lu->data_digest ? "Data" : "");
	}

	val = istgt_get_val(sp, "ReadOnly");
	if (val == NULL) {
		lu->readonly = 0;
	} else if (strcasecmp(val, "Yes") == 0) {
		lu->readonly = 1;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "ReadOnly %s\n",
	    lu->readonly ? "Yes" : "No");

	val = istgt_get_val(sp, "UnitType");
	if (val == NULL) {
		ISTGT_ERRLOG("LU%d: unknown unit type\n", lu->num);
		goto error_return;
	}
	if (strcasecmp(val, "Pass") == 0) {
		lu->type = ISTGT_LU_TYPE_PASS;
	} else if (strcasecmp(val, "Disk") == 0) {
		lu->type = ISTGT_LU_TYPE_DISK;
	} else if (strcasecmp(val, "DVD") == 0) {
		lu->type = ISTGT_LU_TYPE_DVD;
	} else if (strcasecmp(val, "Tape") == 0) {
		lu->type = ISTGT_LU_TYPE_TAPE;
	} else {
		ISTGT_ERRLOG("LU%d: unknown unit type\n", lu->num);
		goto error_return;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "UnitType %d (%s)\n",
	    lu->type, val);

	val = istgt_get_val(sp, "UnitOnline");
	if (val == NULL) {
		lu->online = 1;
	} else if (strcasecmp(val, "Yes") == 0) {
		lu->online = 1;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "UnitOnline %s\n",
	    lu->online ? "Yes" : "No");

	vendor = istgt_get_nmval(sp, "UnitInquiry", 0, 0);
	product = istgt_get_nmval(sp, "UnitInquiry", 0, 1);
	revision = istgt_get_nmval(sp, "UnitInquiry", 0, 2);
	serial = istgt_get_nmval(sp, "UnitInquiry", 0, 3);
	switch (lu->type) {
	case ISTGT_LU_TYPE_DISK:
		if (vendor == NULL || strlen(vendor) == 0)
			vendor = DEFAULT_LU_VENDOR_DISK;
		if (product == NULL || strlen(product) == 0)
			product = DEFAULT_LU_PRODUCT_DISK;
		if (revision == NULL || strlen(revision) == 0)
			revision = DEFAULT_LU_REVISION_DISK;
		if (serial == NULL || strlen(serial) == 0) {
			snprintf(buf, sizeof buf, "%.8d", 10000000 + nbs + lu->num);
			serial = (const char *) &buf[0];
		}
		break;
	case ISTGT_LU_TYPE_DVD:
		if (vendor == NULL || strlen(vendor) == 0)
			vendor = DEFAULT_LU_VENDOR_DVD;
		if (product == NULL || strlen(product) == 0)
			product = DEFAULT_LU_PRODUCT_DVD;
		if (revision == NULL || strlen(revision) == 0)
			revision = DEFAULT_LU_REVISION_DVD;
		if (serial == NULL || strlen(serial) == 0) {
			snprintf(buf, sizeof buf, "%.8d", 10000000 + nbs + lu->num);
			serial = (const char *) &buf[0];
		}
		break;
	case ISTGT_LU_TYPE_TAPE:
		if (vendor == NULL || strlen(vendor) == 0)
			vendor = DEFAULT_LU_VENDOR_TAPE;
		if (product == NULL || strlen(product) == 0)
			product = DEFAULT_LU_PRODUCT_TAPE;
		if (revision == NULL || strlen(revision) == 0)
			revision = DEFAULT_LU_REVISION_TAPE;
		if (serial == NULL || strlen(serial) == 0) {
#ifdef USE_LU_TAPE_DLT8000
			snprintf(buf, sizeof buf, "CX%.8d", 10000000 + nbs + lu->num);
#else
			snprintf(buf, sizeof buf, "%.8d", 10000000 + nbs + lu->num);
#endif /* USE_LU_TAPE_DLT8000 */
			serial = (const char *) &buf[0];
		}
		break;
	default:
		if (vendor == NULL || strlen(vendor) == 0)
			vendor = DEFAULT_LU_VENDOR;
		if (product == NULL || strlen(product) == 0)
			product = DEFAULT_LU_PRODUCT;
		if (revision == NULL || strlen(revision) == 0)
			revision = DEFAULT_LU_REVISION;
		if (serial == NULL || strlen(serial) == 0) {
			snprintf(buf, sizeof buf, "%.8d", 10000000 + nbs + lu->num);
			serial = (const char *) &buf[0];
		}
		break;
	}
	lu->inq_vendor = xstrdup(vendor);
	lu->inq_product = xstrdup(product);
	lu->inq_revision = xstrdup(revision);
	lu->inq_serial = xstrdup(serial);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "UnitInquiry %s %s %s %s\n",
	    lu->inq_vendor, lu->inq_product, lu->inq_revision,
	    lu->inq_serial);

	val = istgt_get_val(sp, "BlockLength");
	if (val == NULL) {
		switch (lu->type) {
		case ISTGT_LU_TYPE_DISK:
			lu->blocklen = DEFAULT_LU_BLOCKLEN_DISK;
			break;
		case ISTGT_LU_TYPE_DVD:
			lu->blocklen = DEFAULT_LU_BLOCKLEN_DVD;
			break;
		case ISTGT_LU_TYPE_TAPE:
			lu->blocklen = DEFAULT_LU_BLOCKLEN_TAPE;
			break;
		default:
			lu->blocklen = DEFAULT_LU_BLOCKLEN;
			break;
		}
	} else {
		lu->blocklen = (int) strtol(val, NULL, 10);
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "BlockLength %d\n",
	    lu->blocklen);

	val = istgt_get_val(sp, "QueueDepth");
	if (val == NULL) {
		switch (lu->type) {
		case ISTGT_LU_TYPE_DISK:
			lu->queue_depth = DEFAULT_LU_QUEUE_DEPTH;
			//lu->queue_depth = 0;
			break;
		case ISTGT_LU_TYPE_DVD:
		case ISTGT_LU_TYPE_TAPE:
		default:
			lu->queue_depth = 0;
			break;
		}
	} else {
		lu->queue_depth = (int) strtol(val, NULL, 10);
	}
	if (lu->queue_depth < 0 || lu->queue_depth >= MAX_LU_QUEUE_DEPTH) {
		ISTGT_ERRLOG("LU%d: queue depth range error\n", lu->num);
		goto error_return;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "QueueDepth %d\n",
	    lu->queue_depth);

	lu->maxlun = 0;
	for (i = 0; i < MAX_LU_LUN; i++) {
		lu->lun[i].type = ISTGT_LU_LUN_TYPE_NONE;
		lu->lun[i].rotationrate = DEFAULT_LU_ROTATIONRATE;
		lu->lun[i].formfactor = DEFAULT_LU_FORMFACTOR;
		lu->lun[i].readcache = 1;
		lu->lun[i].writecache = 1;
		lu->lun[i].serial = NULL;
		lu->lun[i].spec = NULL;
		snprintf(buf, sizeof buf, "LUN%d", i);
		val = istgt_get_val(sp, buf);
		if (val == NULL)
			continue;
		if (i != 0) {
			/* default LUN serial (except LUN0) */
			snprintf(buf2, sizeof buf2, "%sL%d", lu->inq_serial, i);
			lu->lun[i].serial = xstrdup(buf2);
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LUN%d Serial %s (default)\n",
			    i, buf2);
		}
		for (j = 0; ; j++) {
			val = istgt_get_nmval(sp, buf, j, 0);
			if (val == NULL)
				break;
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LUN%d\n", i);
			if (strcasecmp(val, "Device") == 0) {
				if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_NONE) {
					ISTGT_ERRLOG("LU%d: duplicate LUN%d\n", lu->num, i);
					goto error_return;
				}
				lu->lun[i].type = ISTGT_LU_LUN_TYPE_DEVICE;

				file = istgt_get_nmval(sp, buf, j, 1);
				if (file == NULL) {
					ISTGT_ERRLOG("LU%d: LUN%d: format error\n", lu->num, i);
					goto error_return;
				}
				lu->lun[i].u.device.file = xstrdup(file);
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Device file=%s\n",
							   lu->lun[i].u.device.file);
			} else if (strcasecmp(val, "Storage") == 0) {
				if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_NONE) {
					ISTGT_ERRLOG("LU%d: duplicate LUN%d\n", lu->num, i);
					goto error_return;
				}
				lu->lun[i].type = ISTGT_LU_LUN_TYPE_STORAGE;

				file = istgt_get_nmval(sp, buf, j, 1);
				size = istgt_get_nmval(sp, buf, j, 2);
				if (file == NULL || size == NULL) {
					ISTGT_ERRLOG("LU%d: LUN%d: format error\n", lu->num, i);
					goto error_return;
				}
				if (strcasecmp(size, "Auto") == 0
				    || strcasecmp(size, "Size") == 0) {
					lu->lun[i].u.storage.size = istgt_lu_get_filesize(file);
				} else {
					lu->lun[i].u.storage.size = istgt_lu_parse_size(size);
				}
				if (lu->lun[i].u.storage.size == 0) {
					ISTGT_ERRLOG("LU%d: LUN%d: Auto size error (%s)\n", lu->num, i, file);
					goto error_return;
				}
				lu->lun[i].u.storage.fd = -1;
				lu->lun[i].u.storage.file = xstrdup(file);
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "Storage file=%s, size=%"PRIu64"\n",
				    lu->lun[i].u.storage.file,
				    lu->lun[i].u.storage.size);
			} else if (strcasecmp(val, "Removable") == 0) {
				if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_NONE) {
					ISTGT_ERRLOG("LU%d: duplicate LUN%d\n", lu->num, i);
					goto error_return;
				}
				lu->lun[i].type = ISTGT_LU_LUN_TYPE_REMOVABLE;

				flags = istgt_get_nmval(sp, buf, j, 1);
				file = istgt_get_nmval(sp, buf, j, 2);
				size = istgt_get_nmval(sp, buf, j, 3);
				if (flags == NULL || file == NULL || size == NULL) {
					ISTGT_ERRLOG("LU%d: LUN%d: format error\n", lu->num, i);
					goto error_return;
				}
				mflags = istgt_lu_parse_media_flags(flags);
				msize = istgt_lu_parse_media_size(file, size, &mflags);
				if (msize == 0 && strcasecmp(file, "/dev/null") == 0) {
					/* empty media */
				} else if (msize == 0) {
					ISTGT_ERRLOG("LU%d: LUN%d: format error\n", lu->num, i);
					goto error_return;
				}
				lu->lun[i].u.removable.type = 0;
				lu->lun[i].u.removable.id = 0;
				lu->lun[i].u.removable.fd = -1;
				lu->lun[i].u.removable.flags = mflags;
				lu->lun[i].u.removable.file = xstrdup(file);
				lu->lun[i].u.removable.size = msize;
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "Removable file=%s, size=%"PRIu64", flags=%x\n",
				    lu->lun[i].u.removable.file,
				    lu->lun[i].u.removable.size,
				    lu->lun[i].u.removable.flags);
			} else if (strncasecmp(val, "Slot", 4) == 0) {
				if (lu->lun[i].type == ISTGT_LU_LUN_TYPE_NONE) {
					lu->lun[i].u.slot.maxslot = 0;
					for (k = 0; k < MAX_LU_LUN_SLOT; k++) {
						lu->lun[i].u.slot.present[k] = 0;
						lu->lun[i].u.slot.flags[k] = 0;
						lu->lun[i].u.slot.file[k] = NULL;
						lu->lun[i].u.slot.size[k] = 0;
					}
				} else if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_SLOT) {
					ISTGT_ERRLOG("LU%d: duplicate LUN%d\n", lu->num, i);
					goto error_return;
				}
				lu->lun[i].type = ISTGT_LU_LUN_TYPE_SLOT;
				if (sscanf(val, "%*[^0-9]%d", &slot) != 1) {
					ISTGT_ERRLOG("LU%d: slot number error\n", lu->num);
					goto error_return;
				}
				if (slot < 0 || slot >= MAX_LU_LUN_SLOT) {
					ISTGT_ERRLOG("LU%d: slot number range error\n", lu->num);
					goto error_return;
				}
				if (lu->lun[i].u.slot.present[slot]) {
					ISTGT_ERRLOG("LU%d: duplicate slot %d\n", lu->num, slot);
					goto error_return;
				}
				lu->lun[i].u.slot.present[slot] = 1;
				if (slot + 1 > lu->lun[i].u.slot.maxslot) {
					lu->lun[i].u.slot.maxslot = slot + 1;
				}

				flags = istgt_get_nmval(sp, buf, j, 1);
				file = istgt_get_nmval(sp, buf, j, 2);
				size = istgt_get_nmval(sp, buf, j, 3);
				if (flags == NULL || file == NULL || size == NULL) {
					ISTGT_ERRLOG("LU%d: LUN%d: format error\n", lu->num, i);
					goto error_return;
				}
				mflags = istgt_lu_parse_media_flags(flags);
				msize = istgt_lu_parse_media_size(file, size, &mflags);
				if (msize == 0) {
					ISTGT_ERRLOG("LU%d: LUN%d: format error\n", lu->num, i);
					goto error_return;
				}
				lu->lun[i].u.slot.flags[slot] = mflags;
				lu->lun[i].u.slot.file[slot] = xstrdup(file);
				lu->lun[i].u.slot.size[slot] = msize;
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "Slot%d file=%s, size=%"PRIu64", flags=%x\n",
				    slot,
				    lu->lun[i].u.slot.file[slot],
				    lu->lun[i].u.slot.size[slot],
				    lu->lun[i].u.slot.flags[slot]);
			} else if (strncasecmp(val, "Option", 6) == 0) {
				key = istgt_get_nmval(sp, buf, j, 1);
				val = istgt_get_nmval(sp, buf, j, 2);
				if (key == NULL || val == NULL) {
					ISTGT_ERRLOG("LU%d: LUN%d: format error\n", lu->num, i);
					goto error_return;
				}
				if (strcasecmp(key, "Serial") == 0) {
					/* set LUN serial */
					if (strlen(val) == 0) {
						ISTGT_ERRLOG("LU%d: LUN%d: no serial\n",
						    lu->num, i);
						goto error_return;
					}
					xfree(lu->lun[i].serial);
					lu->lun[i].serial = xstrdup(val);
				} else if (strcasecmp(key, "RPM") == 0) {
					rpm = (int)strtol(val, NULL, 10);
					if (rpm < 0) {
						rpm = 0;
					} else if (rpm > 0xfffe) {
						rpm = 0xfffe;
					}
					lu->lun[i].rotationrate = rpm;
				} else if (strcasecmp(key, "FormFactor") == 0) {
					formfactor = (int)strtol(val, NULL, 10);
					if (formfactor < 0) {
						formfactor = 0;
					} else if (formfactor > 0x0f) {
						formfactor = 0xf;
					}
					lu->lun[i].formfactor = formfactor;
				} else if (strcasecmp(key, "ReadCache") == 0) {
					if (strcasecmp(val, "Enable") == 0) {
						lu->lun[i].readcache = 1;
					} else if (strcasecmp(val, "Disable") == 0) {
						lu->lun[i].readcache = 0;
					} else {
						ISTGT_ERRLOG("LU%d: LUN%d: unknown val(%s)\n",
						    lu->num, i, val);
					}
				} else if (strcasecmp(key, "WriteCache") == 0) {
					if (strcasecmp(val, "Enable") == 0) {
						lu->lun[i].writecache = 1;
					} else if (strcasecmp(val, "Disable") == 0) {
						lu->lun[i].writecache = 0;
					} else {
						ISTGT_ERRLOG("LU%d: LUN%d: unknown val(%s)\n",
						    lu->num, i, val);
					}
				} else {
					ISTGT_WARNLOG("LU%d: LUN%d: unknown key(%s)\n",
					    lu->num, i, key);
					continue;
				}
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LUN%d Option %s => %s\n",
				    i, key, val);
				continue;
			} else {
				ISTGT_ERRLOG("LU%d: unknown lun type\n", lu->num);
				goto error_return;
			}
		}
		if (lu->lun[i].type == ISTGT_LU_LUN_TYPE_SLOT) {
			if (lu->lun[i].u.slot.maxslot == 0) {
				ISTGT_ERRLOG("LU%d: no slot\n", lu->num);
				goto error_return;
			}
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "maxslot=%d\n",
			    lu->lun[i].u.slot.maxslot);
		}
		lu->maxlun = i + 1;
	}
	if (lu->maxlun == 0) {
		ISTGT_ERRLOG("LU%d: no LUN\n", lu->num);
		goto error_return;
	}
	if (lu->lun[0].type == ISTGT_LU_LUN_TYPE_NONE) {
		ISTGT_ERRLOG("LU%d: no LUN0\n", lu->num);
		goto error_return;
	}

	/* set local values if any */
	rc = istgt_lu_set_local_settings(istgt, sp, lu);
	if (rc < 0) {
		ISTGT_ERRLOG("LU%d: local setting error\n", lu->num);
		goto error_return;
	}

	/* tsih 0 is reserved */
	for (i = 0; i < MAX_LU_TSIH; i++) {
		lu->tsih[i].tag = 0;
		lu->tsih[i].tsih = 0;
		lu->tsih[i].initiator_port = NULL;
	}
	lu->maxtsih = 1;
	lu->last_tsih = 0;

	MTX_LOCK(&istgt->mutex);
	istgt->nlogical_unit++;
	istgt->logical_unit[lu->num] = lu;
	MTX_UNLOCK(&istgt->mutex);
	return 0;

 error_return:
	xfree(lu->name);
	xfree(lu->alias);
	xfree(lu->inq_vendor);
	xfree(lu->inq_product);
	xfree(lu->inq_revision);
	for (i = 0; i < MAX_LU_LUN; i++) {
		switch (lu->lun[i].type) {
		case ISTGT_LU_LUN_TYPE_DEVICE:
			xfree(lu->lun[i].u.device.file);
			break;
		case ISTGT_LU_LUN_TYPE_STORAGE:
			xfree(lu->lun[i].u.storage.file);
			break;
		case ISTGT_LU_LUN_TYPE_REMOVABLE:
			xfree(lu->lun[i].u.removable.file);
			break;
		case ISTGT_LU_LUN_TYPE_SLOT:
			for (j = 0; j < lu->lun[i].u.slot.maxslot; j++) {
				xfree(lu->lun[i].u.slot.file[j]);
			}
			break;
		case ISTGT_LU_LUN_TYPE_NONE:
		default:
			break;
		}
	}
	for (i = 0; i < MAX_LU_TSIH; i++) {
		xfree(lu->tsih[i].initiator_port);
	}
	for (i = 0; i < lu->maxmap; i++) {
		pg_tag_i = lu->map[i].pg_tag;
		ig_tag_i = lu->map[i].ig_tag;
		MTX_LOCK(&istgt->mutex);
		pgp = istgt_lu_find_portalgroup(istgt, pg_tag_i);
		igp = istgt_lu_find_initiatorgroup(istgt, ig_tag_i);
		if (pgp != NULL && igp != NULL) {
			pgp->ref--;
			igp->ref--;
		}
		MTX_UNLOCK(&istgt->mutex);
	}

	xfree(lu);
	return -1;
}

static int
istgt_lu_del_unit(ISTGT_Ptr istgt, ISTGT_LU_Ptr lu)
{
	PORTAL_GROUP *pgp;
	INITIATOR_GROUP *igp;
	int pg_tag_i, ig_tag_i;
	int i, j;

	if (lu ==NULL)
		return 0;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "del unit %d\n", lu->num);

	//MTX_LOCK(&istgt->mutex);
	istgt->nlogical_unit--;
	istgt->logical_unit[lu->num] = NULL;
	//MTX_UNLOCK(&istgt->mutex);

	xfree(lu->name);
	xfree(lu->alias);
	xfree(lu->inq_vendor);
	xfree(lu->inq_product);
	xfree(lu->inq_revision);
	xfree(lu->inq_serial);
	for (i = 0; i < MAX_LU_LUN; i++) {
		xfree(lu->lun[i].serial);
		switch (lu->lun[i].type) {
		case ISTGT_LU_LUN_TYPE_DEVICE:
			xfree(lu->lun[i].u.device.file);
			break;
		case ISTGT_LU_LUN_TYPE_STORAGE:
			xfree(lu->lun[i].u.storage.file);
			break;
		case ISTGT_LU_LUN_TYPE_REMOVABLE:
			xfree(lu->lun[i].u.removable.file);
			break;
		case ISTGT_LU_LUN_TYPE_SLOT:
			for (j = 0; j < lu->lun[i].u.slot.maxslot; j++) {
				xfree(lu->lun[i].u.slot.file[j]);
			}
			break;
		case ISTGT_LU_LUN_TYPE_NONE:
		default:
			break;
		}
	}
	for (i = 0; i < MAX_LU_TSIH; i++) {
		xfree(lu->tsih[i].initiator_port);
	}
	for (i = 0; i < lu->maxmap; i++) {
		pg_tag_i = lu->map[i].pg_tag;
		ig_tag_i = lu->map[i].ig_tag;
		//MTX_LOCK(&istgt->mutex);
		pgp = istgt_lu_find_portalgroup(istgt, pg_tag_i);
		igp = istgt_lu_find_initiatorgroup(istgt, ig_tag_i);
		if (pgp != NULL && igp != NULL) {
			pgp->ref--;
			igp->ref--;
		}
		//MTX_UNLOCK(&istgt->mutex);
	}

	return 0;
}

static void *luworker(void *arg);

static int istgt_lu_init_unit(ISTGT_Ptr istgt, ISTGT_LU_Ptr lu)
{
	int rc;

	rc = pthread_mutex_init(&lu->mutex, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("LU%d: mutex_init() failed\n", lu->num);
		return -1;
	}
	rc = pthread_mutex_init(&lu->state_mutex, &istgt->mutex_attr);
	if (rc != 0) {
		ISTGT_ERRLOG("LU%d: mutex_init() failed\n", lu->num);
		return -1;
	}
	rc = pthread_mutex_init(&lu->queue_mutex, &istgt->mutex_attr);
	if (rc != 0) {
		ISTGT_ERRLOG("LU%d: mutex_init() failed\n", lu->num);
		return -1;
	}
	rc = pthread_cond_init(&lu->queue_cond, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("LU%d: cond_init() failed\n", lu->num);
		return -1;
	}

	switch (lu->type) {
	case ISTGT_LU_TYPE_PASS:
		rc = istgt_lu_pass_init(istgt, lu);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_pass_init() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_DISK:
		rc = istgt_lu_disk_init(istgt, lu);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_disk_init() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_DVD:
		rc = istgt_lu_dvd_init(istgt, lu);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_dvd_init() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_TAPE:
		rc = istgt_lu_tape_init(istgt, lu);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_tape_init() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_NONE:
		//ISTGT_ERRLOG("LU%d: dummy type\n", lu->num);
		break;
	default:
		ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
		return -1;
	}

	return 0;
}

int
istgt_lu_init(ISTGT_Ptr istgt)
{
	ISTGT_LU_Ptr lu;
	CF_SECTION *sp;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_init\n");
	sp = istgt_find_cf_section(istgt->config, "Global");
	if (sp == NULL) {
		ISTGT_ERRLOG("find_cf_section failed()\n");
		return -1;
	}

	sp = istgt->config->section;
	while (sp != NULL) {
		if (sp->type == ST_LOGICAL_UNIT) {
			if (sp->num == 0) {
				ISTGT_ERRLOG("Unit 0 is invalid\n");
				return -1;
			}
			if (sp->num > ISTGT_LU_TAG_MAX) {
				ISTGT_ERRLOG("tag %d is invalid\n", sp->num);
				return -1;
			}
			rc = istgt_lu_add_unit(istgt, sp);
			if (rc < 0) {
				ISTGT_ERRLOG("lu_add_unit() failed\n");
				return -1;
			}
		}
		sp = sp->next;
	}

	MTX_LOCK(&istgt->mutex);
	for (i = 0; i < MAX_LOGICAL_UNIT; i++) {
		lu = istgt->logical_unit[i];
		if (lu == NULL)
			continue;
		rc = istgt_lu_init_unit(istgt, lu);
		if (rc < 0) {
			MTX_UNLOCK(&istgt->mutex);
			ISTGT_ERRLOG("LU%d: lu_init_unit() failed\n", lu->num);
			return -1;
		}
		istgt_lu_set_state(lu, ISTGT_STATE_INITIALIZED);
	}
	MTX_UNLOCK(&istgt->mutex);

	return 0;
}

static int
istgt_lu_exist_num(CONFIG *config, int num)
{
	CF_SECTION *sp;

	sp = config->section;
	while (sp != NULL) {
		if (sp->type == ST_LOGICAL_UNIT) {
			if (sp->num == num) {
				return 1;
			}
		}
		sp = sp->next;
	}
	return -1;
}

static int istgt_lu_shutdown_unit(ISTGT_Ptr istgt, ISTGT_LU_Ptr lu);

int
istgt_lu_reload_delete(ISTGT_Ptr istgt)
{
	ISTGT_LU_Ptr lu;
	int warn_num, warn_msg;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_reload_delete\n");
	warn_num = warn_msg = 0;
retry:
	MTX_LOCK(&istgt->mutex);
	for (i = 0; i < MAX_LOGICAL_UNIT; i++) {
		lu = istgt->logical_unit[i];
		if (lu == NULL)
			continue;
		rc = istgt_lu_exist_num(istgt->config, lu->num);
		if (rc < 0) {
			istgt_lu_set_state(lu, ISTGT_STATE_SHUTDOWN);
			MTX_LOCK(&lu->mutex);
			if (lu->maxtsih > 1) {
				if (!warn_msg) {
					warn_msg = 1;
					ISTGT_WARNLOG("It is recommended that you disconnect the target before deletion.\n");
				}
				if (warn_num != lu->num) {
					warn_num = lu->num;
					ISTGT_WARNLOG("delete request for active LU%d\n",
					    lu->num);
				}
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "reload retry for LU%d\n",
				    lu->num);
				MTX_UNLOCK(&lu->mutex);
				MTX_UNLOCK(&istgt->mutex);
				istgt_yield();
				sleep(1);
				goto retry;
			}
			MTX_UNLOCK(&lu->mutex);
			rc = istgt_lu_shutdown_unit(istgt, lu);
			if (rc < 0) {
				ISTGT_ERRLOG("LU%d: lu_shutdown_unit() failed\n", lu->num);
				/* ignore error */
			}
			ISTGT_NOTICELOG("delete LU%d: Name=%s\n", lu->num, lu->name);
			xfree(lu);
			istgt->logical_unit[i] = NULL;
		}
	}
	MTX_UNLOCK(&istgt->mutex);
	return 0;
}

static int
istgt_lu_match_all(CF_SECTION *sp, CONFIG *config_old)
{
	CF_ITEM *ip, *ip_old;
	CF_VALUE *vp, *vp_old;
	CF_SECTION *sp_old;

	sp_old = istgt_find_cf_section(config_old, sp->name);
	if (sp_old == NULL)
		return 0;

	ip = sp->item;
	ip_old = sp_old->item;
	while (ip != NULL && ip_old != NULL) {
		vp = ip->val;
		vp_old = ip_old->val;
		while (vp != NULL && vp_old != NULL) {
			if (vp->value != NULL && vp_old->value != NULL) {
				if (strcmp(vp->value, vp_old->value) != 0)
					return 0;
			} else {
				return 0;
			}
			vp = vp->next;
			vp_old = vp_old->next;
		}
		if (vp != NULL || vp_old != NULL)
			return 0;
		ip = ip->next;
		ip_old = ip_old->next;
	}
	if (ip != NULL || ip_old != NULL)
		return 0;
	return 1;
}

static int
istgt_lu_copy_sp(CF_SECTION *sp, CONFIG *config_old)
{
	CF_SECTION *sp_old;

	sp_old = istgt_find_cf_section(config_old, sp->name);
	if (sp_old == NULL)
		return -1;
	istgt_copy_cf_item(sp, sp_old);
	return 0;
}

static int istgt_lu_create_thread(ISTGT_Ptr istgt, ISTGT_LU_Ptr lu);

int
istgt_lu_reload_update(ISTGT_Ptr istgt)
{
	ISTGT_LU_Ptr lu;
	ISTGT_LU_Ptr lu_old;
	CF_SECTION *sp;
	int rc;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_reload_update\n");

	sp = istgt->config->section;
	while (sp != NULL) {
		if (sp->type == ST_LOGICAL_UNIT) {
			if (sp->num == 0) {
				ISTGT_ERRLOG("Unit 0 is invalid\n");
				goto skip_lu;
			}
			if (sp->num > ISTGT_LU_TAG_MAX) {
				ISTGT_ERRLOG("tag %d is invalid\n", sp->num);
				goto skip_lu;
			}
#if 0
			rc = istgt_lu_exist_num(istgt->config_old, sp->num);
#else
			rc = -1;
			MTX_LOCK(&istgt->mutex);
			lu = istgt->logical_unit[sp->num];
			if (lu != NULL)
				rc = 1;
			MTX_UNLOCK(&istgt->mutex);
#endif
			if (rc < 0) {
				rc = istgt_lu_add_unit(istgt, sp);
				if (rc < 0) {
					ISTGT_ERRLOG("lu_add_unit() failed\n");
					goto skip_lu;
				}
				MTX_LOCK(&istgt->mutex);
				lu = istgt->logical_unit[sp->num];
				if (lu == NULL) {
					MTX_UNLOCK(&istgt->mutex);
					ISTGT_ERRLOG("can't find new LU%d\n", sp->num);
					goto skip_lu;
				}
				rc = istgt_lu_init_unit(istgt, lu);
				if (rc < 0) {
					MTX_UNLOCK(&istgt->mutex);
					ISTGT_ERRLOG("LU%d: lu_init_unit() failed\n", sp->num);
					goto skip_lu;
				}
				istgt_lu_set_state(lu, ISTGT_STATE_INITIALIZED);

				rc = istgt_lu_create_thread(istgt, lu);
				if (rc < 0) {
					MTX_UNLOCK(&istgt->mutex);
					ISTGT_ERRLOG("lu_create_thread() failed\n");
					goto skip_lu;
				}
				istgt_lu_set_state(lu, ISTGT_STATE_RUNNING);
				ISTGT_NOTICELOG("add LU%d: Name=%s\n", lu->num, lu->name);
				MTX_UNLOCK(&istgt->mutex);
			} else {
				if (istgt_lu_match_all(sp, istgt->config_old)) {
					ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
					    "skip LU%d: Name=%s\n", lu->num, lu->name);
				} else {
					MTX_LOCK(&istgt->mutex);
					lu = istgt->logical_unit[sp->num];
					if (lu == NULL) {
						MTX_UNLOCK(&istgt->mutex);
						ISTGT_ERRLOG("can't find LU%d\n", sp->num);
						goto skip_lu;
					}
					MTX_LOCK(&lu->mutex);
					if (lu->maxtsih > 1) {
						ISTGT_ERRLOG("update active LU%d: Name=%s, "
						    "# of TSIH=%d\n",
						    lu->num, lu->name, lu->maxtsih - 1);
						rc = istgt_lu_copy_sp(sp, istgt->config_old);
						if (rc < 0) {
							/* ignore error */
						}
						MTX_UNLOCK(&lu->mutex);
						MTX_UNLOCK(&istgt->mutex);
						goto skip_lu;
					} else {
						istgt->logical_unit[sp->num] = NULL;
						MTX_UNLOCK(&lu->mutex);
						MTX_UNLOCK(&istgt->mutex);

						/* add new LU */
						rc = istgt_lu_add_unit(istgt, sp);
						if (rc < 0) {
							ISTGT_ERRLOG("lu_add_unit() failed\n");
							MTX_LOCK(&istgt->mutex);
							istgt->logical_unit[sp->num] = lu;
							MTX_UNLOCK(&istgt->mutex);
							goto skip_lu;
						} else {
							/* delete old LU */
							lu_old = lu;
							MTX_LOCK(&istgt->mutex);
							lu = istgt->logical_unit[sp->num];
							istgt_lu_set_state(lu_old,
							    ISTGT_STATE_SHUTDOWN);
							rc = istgt_lu_shutdown_unit(istgt,
							    lu_old);
							if (rc < 0) {
								ISTGT_ERRLOG(
									"LU%d: lu_shutdown_unit() "
									"failed\n", lu->num);
								/* ignore error */
							}
							xfree(lu_old);
							istgt->logical_unit[sp->num] = lu;
							MTX_UNLOCK(&istgt->mutex);
						}
						MTX_LOCK(&istgt->mutex);
						lu = istgt->logical_unit[sp->num];
						if (lu == NULL) {
							MTX_UNLOCK(&istgt->mutex);
							ISTGT_ERRLOG("can't find new LU%d\n",
							    sp->num);
							goto skip_lu;
						}
						rc = istgt_lu_init_unit(istgt, lu);
						if (rc < 0) {
							MTX_UNLOCK(&istgt->mutex);
							ISTGT_ERRLOG("LU%d: lu_init_unit() "
							    "failed\n", sp->num);
							goto skip_lu;
						}
						istgt_lu_set_state(lu,
						    ISTGT_STATE_INITIALIZED);

						rc = istgt_lu_create_thread(istgt, lu);
						if (rc < 0) {
							MTX_UNLOCK(&istgt->mutex);
							ISTGT_ERRLOG("lu_create_thread "
							    "failed\n");
							goto skip_lu;
						}
						istgt_lu_set_state(lu, ISTGT_STATE_RUNNING);
						ISTGT_NOTICELOG("update LU%d: Name=%s\n",
						    lu->num, lu->name);
					}
					MTX_UNLOCK(&istgt->mutex);
				}
			}
		}
	skip_lu:
		sp = sp->next;
	}
	return 0;
}

int
istgt_lu_set_all_state(ISTGT_Ptr istgt, ISTGT_STATE state)
{
	ISTGT_LU_Ptr lu;
	int i;

	for (i = 0; i < MAX_LOGICAL_UNIT; i++) {
		lu = istgt->logical_unit[i];
		if (lu == NULL)
			continue;

		istgt_lu_set_state(lu, state);
	}

	return 0;
}

static int
istgt_lu_create_thread(ISTGT_Ptr istgt, ISTGT_LU_Ptr lu)
{
#ifdef HAVE_PTHREAD_SET_NAME_NP
	char buf[MAX_TMPBUF];
#endif
	int rc;

	if (lu->queue_depth != 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "thread for LU%d\n", lu->num);
		/* create LU thread */
#ifdef ISTGT_STACKSIZE
		rc = pthread_create(&lu->thread, &istgt->attr, &luworker, (void *)lu);
#else
		rc = pthread_create(&lu->thread, NULL, &luworker, (void *)lu);
#endif
		if (rc != 0) {
			ISTGT_ERRLOG("pthread_create() failed\n");
			return -1;
		}
#if 0
		rc = pthread_detach(lu->thread);
		if (rc != 0) {
			ISTGT_ERRLOG("pthread_detach() failed\n");
			return -1;
		}
#endif
#ifdef HAVE_PTHREAD_SET_NAME_NP
		snprintf(buf, sizeof buf, "luthread #%d", lu->num);
		pthread_set_name_np(lu->thread, buf);
#endif
	}

	return 0;
}

int
istgt_lu_create_threads(ISTGT_Ptr istgt)
{
	ISTGT_LU_Ptr lu;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_create_threads\n");

	for (i = 0; i < MAX_LOGICAL_UNIT; i++) {
		lu = istgt->logical_unit[i];
		if (lu == NULL)
			continue;
		rc = istgt_lu_create_thread(istgt, lu);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_create_thread() failed\n");
			return -1;
		}
	}

	return 0;
}

static int
istgt_lu_shutdown_unit(ISTGT_Ptr istgt, ISTGT_LU_Ptr lu)
{
	int rc;

	switch (lu->type) {
	case ISTGT_LU_TYPE_PASS:
		rc = istgt_lu_pass_shutdown(istgt, lu);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_pass_shutdown() failed\n", lu->num);
			/* ignore error */
		}
		break;

	case ISTGT_LU_TYPE_DISK:
		rc = istgt_lu_disk_shutdown(istgt, lu);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_disk_shutdown() failed\n", lu->num);
			/* ignore error */
		}
		break;

	case ISTGT_LU_TYPE_DVD:
		rc = istgt_lu_dvd_shutdown(istgt, lu);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_dvd_shutdown() failed\n", lu->num);
			/* ignore error */
		}
		break;

	case ISTGT_LU_TYPE_TAPE:
		rc = istgt_lu_tape_shutdown(istgt, lu);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_tape_shutdown() failed\n", lu->num);
			/* ignore error */
		}
		break;

	case ISTGT_LU_TYPE_NONE:
		//ISTGT_ERRLOG("LU%d: dummy type\n", lu->num);
		break;
	default:
		ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
		return -1;
	}

	rc = istgt_lu_del_unit(istgt, lu);
	if (rc < 0) {
		ISTGT_ERRLOG("LU%d: lu_del_unit() failed\n", lu->num);
		/* ignore error */
	}

	if (lu->queue_depth != 0) {
		rc = pthread_cond_broadcast(&lu->queue_cond);
		if (rc != 0) {
			ISTGT_ERRLOG("LU%d: cond_broadcast() failed\n", lu->num);
		}
		rc = pthread_join(lu->thread, NULL);
		if (rc != 0) {
			ISTGT_ERRLOG("LU%d: pthread_join() failed\n", lu->num);
		}
	}
	rc = pthread_cond_destroy(&lu->queue_cond);
	if (rc != 0) {
		ISTGT_ERRLOG("LU%d: cond_destroy() failed\n", lu->num);
		/* ignore error */
	}
	rc = pthread_mutex_destroy(&lu->queue_mutex);
	if (rc != 0) {
		ISTGT_ERRLOG("LU%d: mutex_destroy() failed\n", lu->num);
		/* ignore error */
	}
	rc = pthread_mutex_destroy(&lu->state_mutex);
	if (rc != 0) {
		ISTGT_ERRLOG("LU%d: mutex_destroy() failed\n", lu->num);
		/* ignore error */
	}
	rc = pthread_mutex_destroy(&lu->mutex);
	if (rc != 0) {
		ISTGT_ERRLOG("LU%d: mutex_destroy() failed\n", lu->num);
		/* ignore error */
	}

	return 0;
}

int
istgt_lu_shutdown(ISTGT_Ptr istgt)
{
	ISTGT_LU_Ptr lu;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_shutdown\n");
	MTX_LOCK(&istgt->mutex);
	for (i = 0; i < MAX_LOGICAL_UNIT; i++) {
		lu = istgt->logical_unit[i];
		if (lu == NULL)
			continue;
		istgt_lu_set_state(lu, ISTGT_STATE_SHUTDOWN);
		rc = istgt_lu_shutdown_unit(istgt, lu);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_shutdown_unit() failed\n", lu->num);
			/* ignore error */
		}
		xfree(lu);
		istgt->logical_unit[i] = NULL;
	}
	MTX_UNLOCK(&istgt->mutex);

	return 0;
}

int
istgt_lu_islun2lun(uint64_t islun)
{
	uint64_t fmt_lun;
	uint64_t method;
	int lun_i;

	fmt_lun = islun;
	method = (fmt_lun >> 62) & 0x03U;
	fmt_lun = fmt_lun >> 48;
	if (method == 0x00U) {
		lun_i = (int) (fmt_lun & 0x00ffU);
	} else if (method == 0x01U) {
		lun_i = (int) (fmt_lun & 0x3fffU);
	} else {
		lun_i = 0xffffU;
	}
	return lun_i;
}

uint64_t
istgt_lu_lun2islun(int lun, int maxlun)
{
	uint64_t fmt_lun;
	uint64_t method;
	uint64_t islun;

	islun = (uint64_t) lun;
	if (maxlun <= 0x0100) {
		/* below 256 */
		method = 0x00U;
		fmt_lun = (method & 0x03U) << 62;
		fmt_lun |= (islun & 0x00ffU) << 48;
	} else if (maxlun <= 0x4000) {
		/* below 16384 */
		method = 0x01U;
		fmt_lun = (method & 0x03U) << 62;
		fmt_lun |= (islun & 0x3fffU) << 48;
	} else {
		/* XXX */
		fmt_lun = ~((uint64_t) 0);
	}
	return fmt_lun;
}

int
istgt_lu_reset(ISTGT_LU_Ptr lu, uint64_t lun)
{
	int lun_i;
	int rc;

	if (lu == NULL)
		return -1;

	lun_i = istgt_lu_islun2lun(lun);

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: Name=%s, LUN=%d\n",
	    lu->num, lu->name, lun_i);

	switch (lu->type) {
	case ISTGT_LU_TYPE_PASS:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_pass_reset(lu, lun_i);
		MTX_UNLOCK(&lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_pass_reset() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_DISK:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_disk_reset(lu, lun_i);
		MTX_UNLOCK(&lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_disk_reset() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_DVD:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_dvd_reset(lu, lun_i);
		MTX_UNLOCK(&lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_dvd_reset() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_TAPE:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_tape_reset(lu, lun_i);
		MTX_UNLOCK(&lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_tape_reset() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_NONE:
		//ISTGT_ERRLOG("LU%d: dummy type\n", lu->num);
		break;
	default:
		ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
		return -1;
	}

	return 0;
}

int
istgt_lu_execute(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	ISTGT_LU_Ptr lu;
	int rc;

	if (lu_cmd == NULL)
		return -1;
	lu = lu_cmd->lu;
	if (lu == NULL)
		return -1;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "LU%d: PG=0x%4.4x, Name=%s, LUN=0x%16.16"PRIx64"\n",
	    lu->num, conn->portal.tag, lu->name, lu_cmd->lun);

	if (lu->online == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "LU%d: offline\n", lu->num);
		/* LOGICAL UNIT NOT READY, CAUSE NOT REPORTABLE */
		lu_cmd->sense_data_len
			= istgt_lu_scsi_build_sense_data(lu_cmd->sense_data,
			    ISTGT_SCSI_SENSE_NOT_READY,
			    0x04, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return 0;
	}

	rc = 0;
	switch (lu->type) {
	case ISTGT_LU_TYPE_PASS:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_pass_execute(conn, lu_cmd);
		MTX_UNLOCK(&lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_pass_execute() failed\n",
			    lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_DISK:
		if (lu->queue_depth != 0) {
			rc = istgt_lu_disk_queue(conn, lu_cmd);
			if (rc < 0) {
				ISTGT_ERRLOG("LU%d: lu_disk_queue() failed\n",
				    lu->num);
				return -1;
			}
		} else {
			MTX_LOCK(&lu->mutex);
			rc = istgt_lu_disk_execute(conn, lu_cmd);
			MTX_UNLOCK(&lu->mutex);
			if (rc < 0) {
				ISTGT_ERRLOG("LU%d: lu_disk_execute() failed\n",
				    lu->num);
				return -1;
			}
		}
		break;

	case ISTGT_LU_TYPE_DVD:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_dvd_execute(conn, lu_cmd);
		MTX_UNLOCK(&lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_dvd_execute() failed\n",
			    lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_TAPE:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_tape_execute(conn, lu_cmd);
		MTX_UNLOCK(&lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_tape_execute() failed\n",
			    lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_NONE:
		//ISTGT_ERRLOG("LU%d: dummy type\n", lu->num);
		break;
	default:
		ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
		return -1;
	}

	return rc;
}

int
istgt_lu_create_task(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, ISTGT_LU_TASK_Ptr lu_task, int lun)
{
	ISCSI_PDU_Ptr dst_pdu, src_pdu;
	uint8_t *cdb;
	int alloc_len;
#if 0
	int rc;
#endif

	if (lu_task == NULL)
		return -1;

	lu_task->type = ISTGT_LU_TASK_RESPONSE;
	lu_task->conn = conn;
	strncpy(lu_task->initiator_name, conn->initiator_name,
	    sizeof lu_task->initiator_name);
	strncpy(lu_task->initiator_port, conn->initiator_port,
	    sizeof lu_task->initiator_port);

	lu_task->lun = (int) lun;
	lu_task->use_cond = 0;
	lu_task->dup_iobuf = 0;
	lu_task->iobuf = NULL;
	lu_task->data = NULL;
	lu_task->sense_data = NULL;
	lu_task->alloc_len = 0;
	lu_task->create_time = 0;
	lu_task->condwait = 0;
	lu_task->offset = 0;
	lu_task->req_execute = 0;
	lu_task->req_transfer_out = 0;
	lu_task->error = 0;
	lu_task->abort = 0;
	lu_task->execute = 0;
	lu_task->complete = 0;
	lu_task->lock = 0;

#if 0
	rc = pthread_mutex_init(&lu_task->trans_mutex, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_init() failed\n");
		return -1;
	}
	rc = pthread_cond_init(&lu_task->trans_cond, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("cond_init() failed\n");
		return -1;
	}
	rc = pthread_cond_init(&lu_task->exec_cond, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("cond_init() failed\n");
		return -1;
	}
#endif

	lu_task->lu_cmd.pdu = xmalloc(sizeof *lu_task->lu_cmd.pdu);
	memset(lu_task->lu_cmd.pdu, 0, sizeof *lu_task->lu_cmd.pdu);

	/* copy PDU */
	dst_pdu = lu_task->lu_cmd.pdu;
	src_pdu = lu_cmd->pdu;
	memcpy(&dst_pdu->bhs, &src_pdu->bhs, ISCSI_BHS_LEN);
	dst_pdu->ahs = src_pdu->ahs;
	memcpy(dst_pdu->header_digest, src_pdu->header_digest, ISCSI_DIGEST_LEN);
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

	/* copy other lu_cmd */
	lu_task->lu_cmd.lu = lu_cmd->lu;
	cdb = ((uint8_t *) &lu_task->lu_cmd.pdu->bhs) + 32;
	lu_task->lu_cmd.I_bit = lu_cmd->I_bit;
	lu_task->lu_cmd.F_bit = lu_cmd->F_bit;
	lu_task->lu_cmd.R_bit = lu_cmd->R_bit;
	lu_task->lu_cmd.W_bit = lu_cmd->W_bit;
	lu_task->lu_cmd.Attr_bit = lu_cmd->Attr_bit;
	lu_task->lu_cmd.lun = lu_cmd->lun;
	lu_task->lu_cmd.task_tag = lu_cmd->task_tag;
	lu_task->lu_cmd.transfer_len = lu_cmd->transfer_len;
	//lu_task->lu_cmd.cdb = lu_cmd->cdb;
	lu_task->lu_cmd.cdb = cdb;
	lu_task->lu_cmd.CmdSN = lu_cmd->CmdSN;

	//lu_task->lu_cmd.iobuf = lu_cmd->iobuf;
	lu_task->lu_cmd.iobuf = NULL;
	lu_task->lu_cmd.iobufsize = lu_cmd->iobufsize;
	lu_task->lu_cmd.data = lu_cmd->data;
	lu_task->lu_cmd.data_len = lu_cmd->data_len;
	lu_task->lu_cmd.alloc_len = lu_cmd->alloc_len;

	lu_task->lu_cmd.status = lu_cmd->status;
	lu_task->lu_cmd.sense_data = lu_cmd->sense_data;
	lu_task->lu_cmd.sense_data_len = lu_cmd->sense_data_len;
	lu_task->lu_cmd.sense_alloc_len = lu_cmd->sense_alloc_len;

	/* pre allocate buffer */
	lu_task->lu_cmd.iobufsize = lu_cmd->transfer_len + 65536;
#if 0
	lu_task->data = xmalloc(lu_cmd->alloc_len);
	lu_task->sense_data = xmalloc(lu_cmd->sense_alloc_len);
	lu_task->iobuf = xmalloc(lu_task->lu_cmd.iobufsize);
#else
	alloc_len = ISCSI_ALIGN(lu_cmd->alloc_len);
	alloc_len += ISCSI_ALIGN(lu_cmd->sense_alloc_len);
	alloc_len += ISCSI_ALIGN(lu_task->lu_cmd.iobufsize);
	lu_task->data = xmalloc(alloc_len);
	lu_task->sense_data = lu_task->data + ISCSI_ALIGN(lu_cmd->alloc_len);
	lu_task->iobuf = lu_task->sense_data + ISCSI_ALIGN(lu_cmd->sense_alloc_len);
	lu_task->alloc_len = alloc_len;
#endif

	/* creation time */
	lu_task->create_time = time(NULL);
	/* wait time */
	lu_task->condwait = conn->timeout * 1000;
	if (lu_task->condwait < ISTGT_CONDWAIT_MIN) {
		lu_task->condwait = ISTGT_CONDWAIT_MIN;
	}

	return 0;
}

int
istgt_lu_destroy_task(ISTGT_LU_TASK_Ptr lu_task)
{
	int rc;

	if (lu_task == NULL)
		return -1;

	if (lu_task->use_cond != 0) {
		rc = pthread_mutex_destroy(&lu_task->trans_mutex);
		if (rc != 0) {
			ISTGT_ERRLOG("mutex_destroy() failed\n");
			return -1;
		}
		rc = pthread_cond_destroy(&lu_task->trans_cond);
		if (rc != 0) {
			ISTGT_ERRLOG("cond_destroy() failed\n");
			return -1;
		}
		rc = pthread_cond_destroy(&lu_task->exec_cond);
		if (rc != 0) {
			ISTGT_ERRLOG("cond_destroy() failed\n");
			return -1;
		}
	}
	if (lu_task->lu_cmd.pdu != NULL) {
		if (lu_task->lu_cmd.pdu->copy_pdu == 0) {
			xfree(lu_task->lu_cmd.pdu->ahs);
			if (lu_task->lu_cmd.pdu->data
			    != lu_task->lu_cmd.pdu->shortdata) {
				xfree(lu_task->lu_cmd.pdu->data);
			}
		}
		xfree(lu_task->lu_cmd.pdu);
	}
#if 0
	if (lu_task->dup_iobuf == 0) {
		xfree(lu_task->iobuf);
	}
	xfree(lu_task->data);
	xfree(lu_task->sense_data);
#else
	xfree(lu_task->data);
#endif
	xfree(lu_task);
	return 0;
}

int
istgt_lu_clear_task_IT(CONN_Ptr conn, ISTGT_LU_Ptr lu)
{
	int rc;

	if (lu == NULL)
		return -1;

	if (lu->queue_depth == 0)
		return 0;

	rc = 0;
	switch (lu->type) {
	case ISTGT_LU_TYPE_DISK:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_disk_queue_clear_IT(conn, lu);
		MTX_UNLOCK(&lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_disk_queue_clear_IT() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_DVD:
	case ISTGT_LU_TYPE_TAPE:
	case ISTGT_LU_TYPE_NONE:
	default:
		ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
		return -1;
	}

	return 0;
}

int
istgt_lu_clear_task_ITL(CONN_Ptr conn, ISTGT_LU_Ptr lu, uint64_t lun)
{
	int lun_i;
	int rc;

	if (lu == NULL)
		return -1;

	if (lu->queue_depth == 0)
		return 0;

	lun_i = istgt_lu_islun2lun(lun);

	rc = 0;
	switch (lu->type) {
	case ISTGT_LU_TYPE_DISK:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_disk_queue_clear_ITL(conn, lu, lun_i);
		MTX_UNLOCK(&lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_disk_queue_clear_ITL() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_DVD:
	case ISTGT_LU_TYPE_TAPE:
	case ISTGT_LU_TYPE_NONE:
	default:
		ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
		return -1;
	}

	return 0;
}

int
istgt_lu_clear_task_ITLQ(CONN_Ptr conn, ISTGT_LU_Ptr lu, uint64_t lun, uint32_t CmdSN)
{
	int lun_i;
	int rc;

	if (lu == NULL)
		return -1;

	if (lu->queue_depth == 0)
		return 0;

	lun_i = istgt_lu_islun2lun(lun);

	rc = 0;
	switch (lu->type) {
	case ISTGT_LU_TYPE_DISK:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_disk_queue_clear_ITLQ(conn, lu, lun_i, CmdSN);
		MTX_UNLOCK(&lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_disk_queue_clear_ITLQ() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_DVD:
	case ISTGT_LU_TYPE_TAPE:
	case ISTGT_LU_TYPE_NONE:
	default:
		ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
		return -1;
	}

	return 0;
}

int
istgt_lu_clear_all_task(ISTGT_LU_Ptr lu, uint64_t lun)
{
	int rc;

	if (lu == NULL)
		return -1;

	if (lu->queue_depth == 0)
		return 0;

	rc = 0;
	switch (lu->type) {
	case ISTGT_LU_TYPE_DISK:
		MTX_LOCK(&lu->mutex);
		rc = istgt_lu_disk_queue_clear_all(lu, lun);
		MTX_UNLOCK(&lu->mutex);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: lu_disk_queue_clear_all() failed\n", lu->num);
			return -1;
		}
		break;

	case ISTGT_LU_TYPE_DVD:
	case ISTGT_LU_TYPE_TAPE:
	case ISTGT_LU_TYPE_NONE:
	default:
		ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
		return -1;
	}

	return 0;
}

static void *
luworker(void *arg)
{
	ISTGT_LU_Ptr lu = (ISTGT_LU_Ptr) arg;
	sigset_t signew, sigold;
#if 0
	struct timespec abstime;
	time_t now;
	int timeout = 20; /* XXX */
#endif
	int qcnt;
	int lun;
	int rc;

	sigemptyset(&signew);
	sigemptyset(&sigold);
	sigaddset(&signew, ISTGT_SIGWAKEUP);
	pthread_sigmask(SIG_UNBLOCK, &signew, &sigold);

	while (istgt_get_state(lu->istgt) != ISTGT_STATE_RUNNING) {
		if (istgt_get_state(lu->istgt) == ISTGT_STATE_EXITING
		    || istgt_get_state(lu->istgt) == ISTGT_STATE_SHUTDOWN) {
			ISTGT_ERRLOG("exit before running\n");
			return NULL;
		}
		//ISTGT_WARNLOG("Wait for running\n");
		sleep(1);
		continue;
	}

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d loop start\n", lu->num);
	lun = 0;
	qcnt = 0;
#if 0
	memset(&abstime, 0, sizeof abstime);
#endif
	while (1) {
		switch (lu->type) {
		case ISTGT_LU_TYPE_DISK:
			while (1) {
				if (istgt_lu_get_state(lu) != ISTGT_STATE_RUNNING) {
					goto loop_exit;
				}
				qcnt = istgt_lu_disk_queue_count(lu, &lun);
				if (qcnt == 0) {
					MTX_LOCK(&lu->queue_mutex);
					if (lu->queue_check != 0) {
						lu->queue_check = 0;
						MTX_UNLOCK(&lu->queue_mutex);
						continue;
					}
#if 0
					now = time(NULL);
					abstime.tv_sec = now + timeout;
					abstime.tv_nsec = 0;
					rc = pthread_cond_timedwait(&lu->queue_cond,
					    &lu->queue_mutex, &abstime);
					if (rc == ETIMEDOUT) {
						/* nothing */
					}
#else
					pthread_cond_wait(&lu->queue_cond,
					    &lu->queue_mutex);
#endif
					lu->queue_check = 0;
					MTX_UNLOCK(&lu->queue_mutex);
					qcnt = istgt_lu_disk_queue_count(lu, &lun);
					if (qcnt == 0) {
						continue;
					}
				}
				break;
			}
			if (qcnt < 0) {
				ISTGT_ERRLOG("LU%d: lu_disk_queue_count() failed\n",
				    lu->num);
				break;
			}
			rc = istgt_lu_disk_queue_start(lu, lun);
			if (rc == 0 && qcnt >= 2) {
				qcnt--;
				rc = istgt_lu_disk_queue_start(lu, lun);
			}
			lun++;
			if (rc == -2) {
				ISTGT_WARNLOG("LU%d: lu_disk_queue_start() aborted\n",
				    lu->num);
				break;
			}
			if (rc < 0) {
				ISTGT_ERRLOG("LU%d: lu_disk_queue_start() failed\n",
				    lu->num);
				break;
			}
			break;

		case ISTGT_LU_TYPE_DVD:
		case ISTGT_LU_TYPE_TAPE:
		case ISTGT_LU_TYPE_NONE:
		default:
			ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
			return NULL;
		}

#if 0
		/* still running? */
		if (qcnt <= 1) {
			if (istgt_lu_get_state(lu) != ISTGT_STATE_RUNNING) {
				goto loop_exit;
			}
		}
#endif
	}
 loop_exit:
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d loop ended\n", lu->num);

	return NULL;
}
