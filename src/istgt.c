/*
 * Copyright (C) 2008-2011 Daisuke Aoyama <aoyama@peach.ne.jp>.
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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "istgt.h"
#include "istgt_ver.h"
#include "istgt_log.h"
#include "istgt_conf.h"
#include "istgt_sock.h"
#include "istgt_misc.h"
#include "istgt_crc32c.h"
#include "istgt_iscsi.h"
#include "istgt_lu.h"
#include "istgt_proto.h"

#ifdef ISTGT_USE_KQUEUE
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#endif

#define POLLWAIT 3000
#define PORTNUMLEN 32

ISTGT g_istgt;

#if 0
void
fatal(const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}
#endif

static int
istgt_parse_portal(const char *portal, char **host, char **port)
{
	const char *p;
	int n;

	if (portal == NULL) {
		ISTGT_ERRLOG("portal error\n");
		return -1;
	}

	if (portal[0] == '[') {
		/* IPv6 */
		p = strchr(portal + 1, ']');
		if (p == NULL) {
			ISTGT_ERRLOG("portal error\n");
			return -1;
		}
#if 0
		n = p - (portal + 1);
		*host = xmalloc(n + 1);
		memcpy(*host, portal + 1, n);
		(*host)[n] = '\0';
		p++;
#else
		p++;
		n = p - portal;
		*host = xmalloc(n + 1);
		memcpy(*host, portal, n);
		(*host)[n] = '\0';
#endif
		if (p[0] == '\0') {
			*port = xmalloc(PORTNUMLEN);
			snprintf(*port, PORTNUMLEN, "%d", DEFAULT_PORT);
		} else {
			if (p[0] != ':') {
				ISTGT_ERRLOG("portal error\n");
				xfree(*host);
				return -1;
			}
			*port = xstrdup(p + 1);
		}
	} else {
		/* IPv4 */
		p = strchr(portal, ':');
		if (p == NULL) {
			p = portal + strlen(portal);
		}
		n = p - portal;
		*host = xmalloc(n + 1);
		memcpy(*host, portal, n);
		(*host)[n] = '\0';
		if (p[0] == '\0') {
			*port = xmalloc(PORTNUMLEN);
			snprintf(*port, PORTNUMLEN, "%d", DEFAULT_PORT);
		} else {
			if (p[0] != ':') {
				ISTGT_ERRLOG("portal error\n");
				xfree(*host);
				return -1;
			}
			*port = xstrdup(p + 1);
		}
	}
	return 0;
}

static int
istgt_add_portal(ISTGT_Ptr istgt, CF_SECTION *sp, int idx1)
{
	char *label, *portal, *host, *port;
	int idx;
	int rc;

	label = istgt_get_nmval(sp, "Portal", idx1, 0);
	portal = istgt_get_nmval(sp, "Portal", idx1, 1);
	if (label == NULL || portal == NULL) {
		ISTGT_ERRLOG("portal error\n");
		return -1;
	}

	rc = istgt_parse_portal(portal, &host, &port);
	if (rc < 0) {
		ISTGT_ERRLOG("parse portal error\n");
		return -1;
	}

	idx = istgt->nportal;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "Index=%d, Host=%s, Port=%s, Tag=%d\n",
	    idx, host, port, sp->num);
	if (idx < MAX_PORTAL) {
		istgt->portal[idx].label = xstrdup(label);
		istgt->portal[idx].host = host;
		istgt->portal[idx].port = port;
		istgt->portal[idx].idx = idx;
		istgt->portal[idx].tag = sp->num;
		istgt->portal[idx].sock = -1;
		idx++;
		istgt->nportal = idx;
	} else {
		ISTGT_ERRLOG("nportal(%d) >= MAX_PORTAL\n", idx);
		xfree(host);
		xfree(port);
		return -1;
	}
	return 0;
}

static int
istgt_build_portal_array(ISTGT_Ptr istgt)
{
	CF_SECTION *sp;
	const char *val;
	int rc;
	int i;

	sp = istgt->config->section;
	while (sp != NULL) {
		if (sp->type == ST_PORTALGROUP) {
			if (sp->num == 0) {
				ISTGT_ERRLOG("Group 0 is invalid\n");
				return -1;
			}
			if (sp->num > ISTGT_PG_TAG_MAX) {
				ISTGT_ERRLOG("tag %d is invalid\n", sp->num);
				return -1;
			}

			val = istgt_get_val(sp, "Comment");
			if (val != NULL) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "Comment %s\n", val);
			}
			for (i = 0; ; i++) {
				val = istgt_get_nval(sp, "Portal", i);
				if (val == NULL)
					break;
				rc = istgt_add_portal(istgt, sp, i);
				if (rc < 0) {
					ISTGT_ERRLOG("add_portal() failed\n");
					return -1;
				}
			}
		}
		sp = sp->next;
	}
	return 0;
}

static void
istgt_destroy_portal_array(ISTGT_Ptr istgt)
{
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_destroy_portal_array\n");
	for (i = 0; i < istgt->nportal; i++) {
		xfree(istgt->portal[i].label);
		xfree(istgt->portal[i].host);
		xfree(istgt->portal[i].port);

		istgt->portal[i].label = NULL;
		istgt->portal[i].host = NULL;
		istgt->portal[i].port = NULL;
		istgt->portal[i].idx = i;
		istgt->portal[i].tag = 0;
	}
	istgt->nportal = 0;
}

static int
istgt_open_portal(ISTGT_Ptr istgt)
{
	int port;
	int sock;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_open_portal\n");
	for (i = 0; i < istgt->nportal; i++) {
		if (istgt->portal[i].sock < 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_NET,
			    "open host %s, port %s, tag %d\n",
			    istgt->portal[i].host, istgt->portal[i].port,
			    istgt->portal[i].tag);
			port = (int)strtol(istgt->portal[i].port, NULL, 0);
			sock = istgt_listen(istgt->portal[i].host, port);
			if (sock < 0) {
				ISTGT_ERRLOG("listen error %.64s:%d\n",
				    istgt->portal[i].host, port);
				return -1;
			}
			istgt->portal[i].sock = sock;
		}
	}
	return 0;
}

static int
istgt_close_portal(ISTGT_Ptr istgt)
{
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_close_portal\n");
	for (i = 0; i < istgt->nportal; i++) {
		if (istgt->portal[i].sock >= 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_NET,
			    "close host %s, port %s, tag %d\n",
			    istgt->portal[i].host, istgt->portal[i].port,
			    istgt->portal[i].tag);
			close(istgt->portal[i].sock);
			istgt->portal[i].sock = -1;
		}
	}
	return 0;
}

static int
istgt_add_initiator_group(ISTGT_Ptr istgt, CF_SECTION *sp)
{
	const char *val;
	int alloc_len;
	int idx;
	int names;
	int masks;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "add initiator group %d\n", sp->num);

	val = istgt_get_val(sp, "Comment");
	if (val != NULL) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Comment %s\n", val);
	}

	/* counts number of definition */
	for (i = 0; ; i++) {
		val = istgt_get_nval(sp, "InitiatorName", i);
		if (val == NULL)
			break;
	}
	names = i;
	if (names > MAX_INITIATOR) {
		ISTGT_ERRLOG("%d > MAX_INITIATOR\n", names);
		return -1;
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

	idx = istgt->ninitiator_group;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
	    "Index=%d, Tag=%d, Names=%d, Masks=%d\n",
	    idx, sp->num, names, masks);
	if (idx < MAX_INITIATOR_GROUP) {
		istgt->initiator_group[idx].ninitiators = names;
		alloc_len = sizeof (char *) * names;
		istgt->initiator_group[idx].initiators = xmalloc(alloc_len);
		istgt->initiator_group[idx].nnetmasks = masks;
		alloc_len = sizeof (char *) * masks;
		istgt->initiator_group[idx].netmasks = xmalloc(alloc_len);
		istgt->initiator_group[idx].idx = idx;
		istgt->initiator_group[idx].tag = sp->num;

		for (i = 0; i < names; i++) {
			val = istgt_get_nval(sp, "InitiatorName", i);
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "InitiatorName %s\n", val);
			istgt->initiator_group[idx].initiators[i] = xstrdup(val);
		}
		for (i = 0; i < masks; i++) {
			val = istgt_get_nval(sp, "Netmask", i);
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Netmask %s\n", val);
			istgt->initiator_group[idx].netmasks[i] = xstrdup(val);
		}

		idx++;
		istgt->ninitiator_group = idx;
	} else {
		ISTGT_ERRLOG("ninitiator_group(%d) >= MAX_INITIATOR_GROUP\n", idx);
		return -1;
	}
	return 0;
}

static int
istgt_build_initiator_group_array(ISTGT_Ptr istgt)
{
	CF_SECTION *sp;
	int rc;

	sp = istgt->config->section;
	while (sp != NULL) {
		if (sp->type == ST_INITIATORGROUP) {
			if (sp->num == 0) {
				ISTGT_ERRLOG("Group 0 is invalid\n");
				return -1;
			}
			rc = istgt_add_initiator_group(istgt, sp);
			if (rc < 0) {
				ISTGT_ERRLOG("add_initiator_group() failed\n");
				return -1;
			}
		}
		sp = sp->next;
	}
	return 0;
}

static void
istgt_destory_initiator_group_array(ISTGT_Ptr istgt)
{
	int i, j;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_destory_initiator_group_array\n");
	for (i = 0; i < istgt->ninitiator_group; i++) {
		for (j = 0; j < istgt->initiator_group[i].ninitiators; j++) {
			xfree(istgt->initiator_group[i].initiators[j]);
		}
		xfree(istgt->initiator_group[i].initiators);
		for (j = 0; j < istgt->initiator_group[i].nnetmasks; j++) {
			xfree(istgt->initiator_group[i].netmasks[j]);
		}
		xfree(istgt->initiator_group[i].netmasks);

		istgt->initiator_group[i].ninitiators = 0;
		istgt->initiator_group[i].initiators = NULL;
		istgt->initiator_group[i].nnetmasks = 0;
		istgt->initiator_group[i].netmasks = NULL;
		istgt->initiator_group[i].idx = i;
		istgt->initiator_group[i].tag = 0;
	}
	istgt->ninitiator_group = 0;
}

static int
istgt_build_uctl_portal(ISTGT_Ptr istgt)
{
	CF_SECTION *sp;
	const char *val;
	char *label, *portal, *host, *port;
	int tag;
	int idx;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_build_uctl_portal\n");

	sp = istgt_find_cf_section(istgt->config, "UnitControl");
	if (sp == NULL) {
		ISTGT_ERRLOG("find_cf_section failed()\n");
		return -1;
	}

	for (i = 0; ; i++) {
		val = istgt_get_nval(sp, "Portal", i);
		if (val == NULL)
			break;

		label = istgt_get_nmval(sp, "Portal", i, 0);
		portal = istgt_get_nmval(sp, "Portal", i, 1);
		if (label == NULL || portal == NULL) {
			ISTGT_ERRLOG("uctl portal error\n");
			return -1;
		}

		rc = istgt_parse_portal(portal, &host, &port);
		if (rc < 0) {
			ISTGT_ERRLOG("parse uctl portal error\n");
			return -1;
		}

		idx = istgt->nuctl_portal;
		tag = ISTGT_UC_TAG;
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "Index=%d, Host=%s, Port=%s, Tag=%d\n",
		    idx, host, port, tag);
		if (idx < MAX_UCPORTAL) {
			istgt->uctl_portal[idx].label = xstrdup(label);
			istgt->uctl_portal[idx].host = host;
			istgt->uctl_portal[idx].port = port;
			istgt->uctl_portal[idx].idx = idx;
			istgt->uctl_portal[idx].tag = tag;
			istgt->uctl_portal[idx].sock = -1;
			idx++;
			istgt->nuctl_portal = idx;
		} else {
			ISTGT_ERRLOG("nportal(%d) >= MAX_UCPORTAL\n", idx);
			xfree(host);
			xfree(port);
			return -1;
		}
	}

	return 0;
}

static void
istgt_destroy_uctl_portal(ISTGT_Ptr istgt)
{
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_destroy_uctl_portal\n");
	for (i = 0; i < istgt->nportal; i++) {
		xfree(istgt->uctl_portal[i].label);
		xfree(istgt->uctl_portal[i].host);
		xfree(istgt->uctl_portal[i].port);

		istgt->uctl_portal[i].label = NULL;
		istgt->uctl_portal[i].host = NULL;
		istgt->uctl_portal[i].port = NULL;
		istgt->uctl_portal[i].idx = i;
		istgt->uctl_portal[i].tag = 0;
	}
	istgt->nuctl_portal = 0;
}

static int
istgt_open_uctl_portal(ISTGT_Ptr istgt)
{
	int port;
	int sock;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_open_uctl_portal\n");
	for (i = 0; i < istgt->nuctl_portal; i++) {
		if (istgt->uctl_portal[i].sock < 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_NET,
			    "open host %s, port %s, tag %d\n",
			    istgt->uctl_portal[i].host,
			    istgt->uctl_portal[i].port,
			    istgt->uctl_portal[i].tag);
			port = (int)strtol(istgt->uctl_portal[i].port, NULL, 0);
			sock = istgt_listen(istgt->uctl_portal[i].host, port);
			if (sock < 0) {
				ISTGT_ERRLOG("listen error %.64s:%d\n",
				    istgt->uctl_portal[i].host, port);
				return -1;
			}
			istgt->uctl_portal[i].sock = sock;
		}
	}
	return 0;
}

static int
istgt_close_uctl_portal(ISTGT_Ptr istgt)
{
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_close_uctl_portal\n");
	for (i = 0; i < istgt->nuctl_portal; i++) {
		if (istgt->uctl_portal[i].sock >= 0) {
			ISTGT_TRACELOG(ISTGT_TRACE_NET,
			    "close host %s, port %s, tag %d\n",
			    istgt->uctl_portal[i].host,
			    istgt->uctl_portal[i].port,
			    istgt->uctl_portal[i].tag);
			close(istgt->uctl_portal[i].sock);
			istgt->uctl_portal[i].sock = -1;
		}
	}
	return 0;
}

static int
istgt_write_pidfile(ISTGT_Ptr istgt)
{
	FILE *fp;
	pid_t pid;
	int rc;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_write_pidfile\n");
	rc = remove(istgt->pidfile);
	if (rc != 0) {
		if (errno != ENOENT) {
			ISTGT_ERRLOG("pidfile remove error %d\n", errno);
			return -1;
		}
	}
	fp = fopen(istgt->pidfile, "w");
	if (fp == NULL) {
		ISTGT_ERRLOG("pidfile open error %d\n", errno);
		return -1;
	}
	pid = getpid();
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	return 0;
}

static void
istgt_remove_pidfile(ISTGT_Ptr istgt)
{
	int rc;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_remove_pidfile\n");
	rc = remove(istgt->pidfile);
	if (rc != 0) {
		ISTGT_ERRLOG("pidfile remove error %d\n", errno);
		/* ignore error */
	}
}

char *
istgt_get_nmval(CF_SECTION *sp, const char *key, int idx1, int idx2)
{
	CF_ITEM *ip;
	CF_VALUE *vp;
	int i;

	ip = istgt_find_cf_nitem(sp, key, idx1);
	if (ip == NULL)
		return NULL;
	vp = ip->val;
	if (vp == NULL)
		return NULL;
	for (i = 0; vp != NULL; vp = vp->next) {
		if (i == idx2)
			return vp->value;
		i++;
	}
	return NULL;
}

char *
istgt_get_nval(CF_SECTION *sp, const char *key, int idx)
{
	CF_ITEM *ip;
	CF_VALUE *vp;

	ip = istgt_find_cf_nitem(sp, key, idx);
	if (ip == NULL)
		return NULL;
	vp = ip->val;
	if (vp == NULL)
		return NULL;
	return vp->value;
}

char *
istgt_get_val(CF_SECTION *sp, const char *key)
{
	return istgt_get_nval(sp, key, 0);
}

int
istgt_get_nintval(CF_SECTION *sp, const char *key, int idx)
{
	const char *v;
	int value;

	v = istgt_get_nval(sp, key, idx);
	if (v == NULL)
		return -1;
	value = (int)strtol(v, NULL, 10);
	return value;
}

int
istgt_get_intval(CF_SECTION *sp, const char *key)
{
	return istgt_get_nintval(sp, key, 0);
}

static const char *
istgt_get_log_facility(CONFIG *config)
{
	CF_SECTION *sp;
	const char *logfacility;

	sp = istgt_find_cf_section(config, "Global");
	if (sp == NULL) {
		return NULL;
	}
	logfacility = istgt_get_val(sp, "LogFacility");
	if (logfacility == NULL) {
		logfacility = DEFAULT_LOG_FACILITY;
	}
#if 0
	if (g_trace_flag & ISTGT_TRACE_DEBUG) {
		fprintf(stderr, "LogFacility %s\n", logfacility);
	}
#endif

	return logfacility;
}

static int
istgt_init(ISTGT_Ptr istgt)
{
	CF_SECTION *sp;
	const char *ag_tag;
	const char *val;
	size_t stacksize;
	int ag_tag_i;
	int MaxSessions;
	int MaxConnections;
	int MaxOutstandingR2T;
	int DefaultTime2Wait;
	int DefaultTime2Retain;
	int FirstBurstLength;
	int MaxBurstLength;
	int MaxRecvDataSegmentLength;
	int InitialR2T;
	int ImmediateData;
	int DataPDUInOrder;
	int DataSequenceInOrder;
	int ErrorRecoveryLevel;
	int timeout;
	int nopininterval;
	int maxr2t;
	int rc;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_init\n");
	sp = istgt_find_cf_section(istgt->config, "Global");
	if (sp == NULL) {
		ISTGT_ERRLOG("find_cf_section failed()\n");
		return -1;
	}

	val = istgt_get_val(sp, "Comment");
	if (val != NULL) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Comment %s\n", val);
	}

	val = istgt_get_val(sp, "PidFile");
	if (val == NULL) {
		val = DEFAULT_PIDFILE;
	}
	istgt->pidfile = xstrdup(val);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "PidFile %s\n",
	    istgt->pidfile);

	val = istgt_get_val(sp, "AuthFile");
	if (val == NULL) {
		val = DEFAULT_AUTHFILE;
	}
	istgt->authfile = xstrdup(val);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "AuthFile %s\n",
	    istgt->authfile);

#if 0
	val = istgt_get_val(sp, "MediaFile");
	if (val == NULL) {
		val = DEFAULT_MEDIAFILE;
	}
	istgt->mediafile = xstrdup(val);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "MediaFile %s\n",
	    istgt->mediafile);
#endif

#if 0
	val = istgt_get_val(sp, "LiveFile");
	if (val == NULL) {
		val = DEFAULT_LIVEFILE;
	}
	istgt->livefile = xstrdup(val);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LiveFile %s\n",
	    istgt->livefile);
#endif

	val = istgt_get_val(sp, "MediaDirectory");
	if (val == NULL) {
		val = DEFAULT_MEDIADIRECTORY;
	}
	istgt->mediadirectory = xstrdup(val);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "MediaDirectory %s\n",
	    istgt->mediadirectory);

	val = istgt_get_val(sp, "NodeBase");
	if (val == NULL) {
		val = DEFAULT_NODEBASE;
	}
	istgt->nodebase = xstrdup(val);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "NodeBase %s\n",
	    istgt->nodebase);

	MaxSessions = istgt_get_intval(sp, "MaxSessions");
	if (MaxSessions < 1) {
		MaxSessions = DEFAULT_MAX_SESSIONS;
	}
	istgt->MaxSessions = MaxSessions;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "MaxSessions %d\n",
	    istgt->MaxSessions);

	MaxConnections = istgt_get_intval(sp, "MaxConnections");
	if (MaxConnections < 1) {
		MaxConnections = DEFAULT_MAX_CONNECTIONS;
	}
	istgt->MaxConnections = MaxConnections;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "MaxConnections %d\n",
	    istgt->MaxConnections);

	/* limited to 16bits - RFC3720(12.2) */
	if (MaxSessions > 0xffff) {
		ISTGT_ERRLOG("over 65535 sessions are not supported\n");
		return -1;
	}
	if (MaxConnections > 0xffff) {
		ISTGT_ERRLOG("over 65535 connections are not supported\n");
		return -1;
	}

	MaxOutstandingR2T = istgt_get_intval(sp, "MaxOutstandingR2T");
	if (MaxOutstandingR2T < 1) {
		MaxOutstandingR2T = DEFAULT_MAXOUTSTANDINGR2T;
	}
	istgt->MaxOutstandingR2T = MaxOutstandingR2T;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "MaxOutstandingR2T %d\n",
	    istgt->MaxOutstandingR2T);

	DefaultTime2Wait = istgt_get_intval(sp, "DefaultTime2Wait");
	if (DefaultTime2Wait < 0) {
		DefaultTime2Wait = DEFAULT_DEFAULTTIME2WAIT;
	}
	istgt->DefaultTime2Wait = DefaultTime2Wait;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "DefaultTime2Wait %d\n",
	    istgt->DefaultTime2Wait);

	DefaultTime2Retain = istgt_get_intval(sp, "DefaultTime2Retain");
	if (DefaultTime2Retain < 0) {
		DefaultTime2Retain = DEFAULT_DEFAULTTIME2RETAIN;
	}
	istgt->DefaultTime2Retain = DefaultTime2Retain;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "DefaultTime2Retain %d\n",
	    istgt->DefaultTime2Retain);

	/* check size limit - RFC3720(12.15, 12.16, 12.17) */
	if (istgt->MaxOutstandingR2T > 65535) {
		ISTGT_ERRLOG("MaxOutstandingR2T(%d) > 65535\n",
		    istgt->MaxOutstandingR2T);
		return -1;
	}
	if (istgt->DefaultTime2Wait > 3600) {
		ISTGT_ERRLOG("DefaultTime2Wait(%d) > 3600\n",
		    istgt->DefaultTime2Wait);
		return -1;
	}
	if (istgt->DefaultTime2Retain > 3600) {
		ISTGT_ERRLOG("DefaultTime2Retain(%d) > 3600\n",
		    istgt->DefaultTime2Retain);
		return -1;
	}

	FirstBurstLength = istgt_get_intval(sp, "FirstBurstLength");
	if (FirstBurstLength < 0) {
		FirstBurstLength = DEFAULT_FIRSTBURSTLENGTH;
	}
	istgt->FirstBurstLength = FirstBurstLength;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "FirstBurstLength %d\n",
	    istgt->FirstBurstLength);

	MaxBurstLength = istgt_get_intval(sp, "MaxBurstLength");
	if (MaxBurstLength < 0) {
		MaxBurstLength = DEFAULT_MAXBURSTLENGTH;
	}
	istgt->MaxBurstLength = MaxBurstLength;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "MaxBurstLength %d\n",
	    istgt->MaxBurstLength);

	MaxRecvDataSegmentLength
		= istgt_get_intval(sp, "MaxRecvDataSegmentLength");
	if (MaxRecvDataSegmentLength < 0) {
		MaxRecvDataSegmentLength = DEFAULT_MAXRECVDATASEGMENTLENGTH;
	}
	istgt->MaxRecvDataSegmentLength = MaxRecvDataSegmentLength;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "MaxRecvDataSegmentLength %d\n",
	    istgt->MaxRecvDataSegmentLength);

	/* check size limit (up to 24bits - RFC3720(12.12)) */
	if (istgt->MaxBurstLength < 512) {
		ISTGT_ERRLOG("MaxBurstLength(%d) < 512\n",
		    istgt->MaxBurstLength);
		return -1;
	}
	if (istgt->FirstBurstLength < 512) {
		ISTGT_ERRLOG("FirstBurstLength(%d) < 512\n",
		    istgt->FirstBurstLength);
		return -1;
	}
	if (istgt->FirstBurstLength > istgt->MaxBurstLength) {
		ISTGT_ERRLOG("FirstBurstLength(%d) > MaxBurstLength(%d)\n",
		    istgt->FirstBurstLength, istgt->MaxBurstLength);
		return -1;
	}
	if (istgt->MaxBurstLength > 0x00ffffff) {
		ISTGT_ERRLOG("MaxBurstLength(%d) > 0x00ffffff\n",
		    istgt->MaxBurstLength);
		return -1;
	}
	if (istgt->MaxRecvDataSegmentLength < 512) {
		ISTGT_ERRLOG("MaxRecvDataSegmentLength(%d) < 512\n",
		    istgt->MaxRecvDataSegmentLength);
		return -1;
	}
	if (istgt->MaxRecvDataSegmentLength > 0x00ffffff) {
		ISTGT_ERRLOG("MaxRecvDataSegmentLength(%d) > 0x00ffffff\n",
		    istgt->MaxRecvDataSegmentLength);
		return -1;
	}

	val = istgt_get_val(sp, "InitialR2T");
	if (val == NULL) {
		InitialR2T = DEFAULT_INITIALR2T;
	} else if (strcasecmp(val, "Yes") == 0) {
		InitialR2T = 1;
	} else if (strcasecmp(val, "No") == 0) {
#if 0
		InitialR2T = 0;
#else
		ISTGT_ERRLOG("not supported value %s\n", val);
		return -1;
#endif
	} else {
		ISTGT_ERRLOG("unknown value %s\n", val);
		return -1;
	}
	istgt->InitialR2T = InitialR2T;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "InitialR2T %s\n",
	    istgt->InitialR2T ? "Yes" : "No");

	val = istgt_get_val(sp, "ImmediateData");
	if (val == NULL) {
		ImmediateData = DEFAULT_IMMEDIATEDATA;
	} else if (strcasecmp(val, "Yes") == 0) {
		ImmediateData = 1;
	} else if (strcasecmp(val, "No") == 0) {
		ImmediateData = 0;
	} else {
		ISTGT_ERRLOG("unknown value %s\n", val);
		return -1;
	}
	istgt->ImmediateData = ImmediateData;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "ImmediateData %s\n",
	    istgt->ImmediateData ? "Yes" : "No");

	val = istgt_get_val(sp, "DataPDUInOrder");
	if (val == NULL) {
		DataPDUInOrder = DEFAULT_DATAPDUINORDER;
	} else if (strcasecmp(val, "Yes") == 0) {
		DataPDUInOrder = 1;
	} else if (strcasecmp(val, "No") == 0) {
#if 0
		DataPDUInOrder = 0;
#else
		ISTGT_ERRLOG("not supported value %s\n", val);
		return -1;
#endif
	} else {
		ISTGT_ERRLOG("unknown value %s\n", val);
		return -1;
	}
	istgt->DataPDUInOrder = DataPDUInOrder;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "DataPDUInOrder %s\n",
	    istgt->DataPDUInOrder ? "Yes" : "No");

	val = istgt_get_val(sp, "DataSequenceInOrder");
	if (val == NULL) {
		DataSequenceInOrder = DEFAULT_DATASEQUENCEINORDER;
	} else if (strcasecmp(val, "Yes") == 0) {
		DataSequenceInOrder = 1;
	} else if (strcasecmp(val, "No") == 0) {
#if 0
		DataSequenceInOrder = 0;
#else
		ISTGT_ERRLOG("not supported value %s\n", val);
		return -1;
#endif
	} else {
		ISTGT_ERRLOG("unknown value %s\n", val);
		return -1;
	}
	istgt->DataSequenceInOrder = DataSequenceInOrder;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "DataSequenceInOrder %s\n",
	    istgt->DataSequenceInOrder ? "Yes" : "No");

	ErrorRecoveryLevel = istgt_get_intval(sp, "ErrorRecoveryLevel");
	if (ErrorRecoveryLevel < 0) {
		ErrorRecoveryLevel = DEFAULT_ERRORRECOVERYLEVEL;
	} else if (ErrorRecoveryLevel == 0) {
		ErrorRecoveryLevel = 0;
	} else if (ErrorRecoveryLevel == 1) {
#if 0
		ErrorRecoveryLevel = 1;
#else
		ISTGT_ERRLOG("not supported value %d\n", ErrorRecoveryLevel);
		return -1;
#endif
	} else if (ErrorRecoveryLevel == 2) {
#if 0
		ErrorRecoveryLevel = 2;
#else
		ISTGT_ERRLOG("not supported value %d\n", ErrorRecoveryLevel);
		return -1;
#endif
	} else {
		ISTGT_ERRLOG("not supported value %d\n", ErrorRecoveryLevel);
		return -1;
	}
	istgt->ErrorRecoveryLevel = ErrorRecoveryLevel;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "ErrorRecoveryLevel %d\n",
	    istgt->ErrorRecoveryLevel);

	timeout = istgt_get_intval(sp, "Timeout");
	if (timeout < 0) {
		timeout = DEFAULT_TIMEOUT;
	}
	istgt->timeout = timeout;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "Timeout %d\n",
	    istgt->timeout);

	nopininterval = istgt_get_intval(sp, "NopInInterval");
	if (nopininterval < 0) {
		nopininterval = DEFAULT_NOPININTERVAL;
	}
	istgt->nopininterval = nopininterval;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "NopInInterval %d\n",
	    istgt->nopininterval);

	maxr2t = istgt_get_intval(sp, "MaxR2T");
	if (maxr2t < 0) {
		maxr2t = DEFAULT_MAXR2T;
	}
	if (maxr2t > MAX_R2T) {
		ISTGT_ERRLOG("MaxR2T(%d) > %d\n",
		    maxr2t, MAX_R2T);
		return -1;
	}
	istgt->maxr2t = maxr2t;
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "MaxR2T %d\n",
	    istgt->maxr2t);

	val = istgt_get_val(sp, "DiscoveryAuthMethod");
	if (val == NULL) {
		istgt->no_discovery_auth = 0;
		istgt->req_discovery_auth = 0;
		istgt->req_discovery_auth_mutual = 0;
	} else {
		istgt->no_discovery_auth = 0;
		for (i = 0; ; i++) {
			val = istgt_get_nmval(sp, "DiscoveryAuthMethod", 0, i);
			if (val == NULL)
				break;
			if (strcasecmp(val, "CHAP") == 0) {
				istgt->req_discovery_auth = 1;
			} else if (strcasecmp(val, "Mutual") == 0) {
				istgt->req_discovery_auth_mutual = 1;
			} else if (strcasecmp(val, "Auto") == 0) {
				istgt->req_discovery_auth = 0;
				istgt->req_discovery_auth_mutual = 0;
			} else if (strcasecmp(val, "None") == 0) {
				istgt->no_discovery_auth = 1;
				istgt->req_discovery_auth = 0;
				istgt->req_discovery_auth_mutual = 0;
			} else {
				ISTGT_ERRLOG("unknown auth\n");
				return -1;
			}
		}
		if (istgt->req_discovery_auth_mutual && !istgt->req_discovery_auth) {
			ISTGT_ERRLOG("Mutual but not CHAP\n");
			return -1;
		}
	}
	if (istgt->no_discovery_auth != 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "DiscoveryAuthMethod None\n");
	} else if (istgt->req_discovery_auth == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "DiscoveryAuthMethod Auto\n");
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "DiscoveryAuthMethod %s %s\n",
		    istgt->req_discovery_auth ? "CHAP" : "",
		    istgt->req_discovery_auth_mutual ? "Mutual" : "");
	}

	val = istgt_get_val(sp, "DiscoveryAuthGroup");
	if (val == NULL) {
		istgt->discovery_auth_group = 0;
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
				ISTGT_ERRLOG("invalid auth group %d\n",
				    ag_tag_i);
				return -1;
			}
		}
		istgt->discovery_auth_group = ag_tag_i;
	}
	if (istgt->discovery_auth_group == 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "DiscoveryAuthGroup None\n");
	} else {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "DiscoveryAuthGroup AuthGroup%d\n",
		    istgt->discovery_auth_group);
	}

	rc = istgt_init_uctl(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("istgt_init_uctl() failed\n");
		return -1;
	}
	rc = istgt_build_uctl_portal(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("istgt_build_uctl_portal() failed\n");
		return -1;
	}
	rc = istgt_build_portal_array(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("istgt_build_portal_array() failed\n");
		return -1;
	}
	rc = istgt_build_initiator_group_array(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("build_initiator_group_array() failed\n");
		return -1;
	}

	rc = pthread_attr_init(&istgt->attr);
	if (rc != 0) {
		ISTGT_ERRLOG("pthread_attr_init() failed\n");
		return -1;
	}
	rc = pthread_attr_getstacksize(&istgt->attr, &stacksize);
	if (rc != 0) {
		ISTGT_ERRLOG("pthread_attr_getstacksize() failed\n");
		return -1;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "current thread stack = %zd\n", stacksize);
	if (stacksize < ISTGT_STACKSIZE) {
		stacksize = ISTGT_STACKSIZE;
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "new thread stack = %zd\n", stacksize);
		rc = pthread_attr_setstacksize(&istgt->attr, stacksize);
		if (rc != 0) {
			ISTGT_ERRLOG("pthread_attr_setstacksize() failed\n");
			return -1;
		}
	}

	rc = pthread_mutex_init(&istgt->mutex, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("mutex_init() failed\n");
		return -1;
	}

	/* XXX TODO: add initializer */

	istgt_set_state(istgt, ISTGT_STATE_INITIALIZED);

	return 0;
}

#ifdef SIGINFO
static void
istgt_siginfo(int signo)
{
	/* nothing */
}
#endif

static void
istgt_sigwakeup(int signo)
{
}

#ifdef SIGIO
static void
istgt_sigio(int signo)
{
}
#endif

static void *
istgt_sighandler(void *arg)
{
	ISTGT_Ptr istgt = (ISTGT_Ptr) arg;
	sigset_t signew;
	int signo;

	sigemptyset(&signew);
	sigaddset(&signew, SIGINT);
	sigaddset(&signew, SIGTERM);
	sigaddset(&signew, SIGQUIT);
	sigaddset(&signew, SIGHUP);
#ifdef SIGINFO
	sigaddset(&signew, SIGINFO);
#endif
	sigaddset(&signew, SIGUSR1);
	sigaddset(&signew, SIGUSR2);
#ifdef SIGIO
	sigaddset(&signew, SIGIO);
#endif

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "loop start\n");
	while (1) {
		if (istgt_get_state(istgt) == ISTGT_STATE_EXITING
		    || istgt_get_state(istgt) == ISTGT_STATE_SHUTDOWN) {
			break;
		}
		sigwait(&signew, &signo);
		switch (signo) {
		case SIGINT:
			printf("SIGINT catch\n");
			istgt_set_state(istgt, ISTGT_STATE_EXITING);
			istgt_lu_set_all_state(istgt, ISTGT_STATE_EXITING);
			break;
		case SIGTERM:
			printf("SIGTERM catch\n");
			istgt_set_state(istgt, ISTGT_STATE_EXITING);
			istgt_lu_set_all_state(istgt, ISTGT_STATE_EXITING);
			break;
		case SIGQUIT:
			printf("SIGQUIT catch\n");
			exit(EXIT_SUCCESS);
			break;
		case SIGHUP:
			printf("SIGHUP catch\n");
			break;
#ifdef SIGINFO
		case SIGINFO:
			printf("SIGINFO catch\n");
			istgt_set_trace_flag(ISTGT_TRACE_ISCSI);
			break;
#endif
		case SIGUSR1:
			printf("SIGUSR1 catch\n");
			istgt_set_trace_flag(ISTGT_TRACE_NONE);
			break;
		case SIGUSR2:
			printf("SIGUSR2 catch\n");
			//istgt_set_trace_flag(ISTGT_TRACE_SCSI);
			istgt_set_trace_flag(ISTGT_TRACE_ALL);
			break;
#ifdef SIGIO
		case SIGIO:
			//printf("SIGIO catch\n");
			break;
#endif
		default:
			break;
		}
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "loop ended\n");

	return NULL;
}

static int
istgt_acceptor(ISTGT_Ptr istgt)
{
#ifdef ISTGT_USE_KQUEUE
	int kq;
	struct kevent kev;
	struct timespec kev_timeout;
#else
	struct pollfd fds[MAX_PORTAL + MAX_UCPORTAL];
#endif /* ISTGT_USE_KQUEUE */
	struct sockaddr_storage sa;
	socklen_t salen;
	int sock;
	int rc, n;
	int ucidx;
	int nidx;
	int i;

	if (istgt_get_state(istgt) != ISTGT_STATE_INITIALIZED) {
		ISTGT_ERRLOG("not initialized\n");
		return -1;
	}
	/* now running main thread */
	istgt_set_state(istgt, ISTGT_STATE_RUNNING);

#ifdef ISTGT_USE_KQUEUE
	kq = kqueue();
	if (kq == -1) {
		ISTGT_ERRLOG("kqueue() failed\n");
		return -1;
	}
	for (i = 0; i < istgt->nportal; i++) {
		EV_SET(&kev, istgt->portal[i].sock,
		    EVFILT_READ, EV_ADD, 0, 0, NULL);
		rc = kevent(kq, &kev, 1, NULL, 0, NULL);
		if (rc == -1) {
			ISTGT_ERRLOG("kevent() failed\n");
			close(kq);
			return -1;
		}
	}
	ucidx = istgt->nportal;
	for (i = 0; i < istgt->nuctl_portal; i++) {
		EV_SET(&kev, istgt->uctl_portal[i].sock,
		    EVFILT_READ, EV_ADD, 0, 0, NULL);
		rc = kevent(kq, &kev, 1, NULL, 0, NULL);
		if (rc == -1) {
			ISTGT_ERRLOG("kevent() failed\n");
			close(kq);
			return -1;
		}
	}
	nidx = istgt->nportal + istgt->nuctl_portal;

	EV_SET(&kev, SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	rc = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (rc == -1) {
		ISTGT_ERRLOG("kevent() failed\n");
		close(kq);
		return -1;
	}
	EV_SET(&kev, SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	rc = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (rc == -1) {
		ISTGT_ERRLOG("kevent() failed\n");
		close(kq);
		return -1;
	}
#else
	memset(&fds, 0, sizeof fds);
	for (i = 0; i < istgt->nportal; i++) {
		fds[i].fd = istgt->portal[i].sock;
		fds[i].events = POLLIN;
	}
	ucidx = istgt->nportal;
	for (i = 0; i < istgt->nuctl_portal; i++) {
		fds[ucidx + i].fd = istgt->uctl_portal[i].sock;
		fds[ucidx + i].events = POLLIN;
	}
	nidx = istgt->nportal + istgt->nuctl_portal;
#endif /* ISTGT_USE_KQUEUE */

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "loop start\n");
	while (1) {
		if (istgt_get_state(istgt) != ISTGT_STATE_RUNNING) {
			break;
		}
#ifdef ISTGT_USE_KQUEUE
		//ISTGT_TRACELOG(ISTGT_TRACE_NET, "kevent %d\n", nidx);
		kev_timeout.tv_sec = 10;
		kev_timeout.tv_nsec = 0;
		rc = kevent(kq, NULL, 0, &kev, 1, &kev_timeout);
		if (rc == -1 && errno == EINTR) {
			continue;
		}
		if (rc == -1) {
			ISTGT_ERRLOG("kevent() failed\n");
			break;
		}
		if (rc == 0) {
			/* idle timeout */
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
		//ISTGT_TRACELOG(ISTGT_TRACE_NET, "poll %d\n", nidx);
		rc = poll(fds, nidx, POLLWAIT);
		if (rc == -1 && errno == EINTR) {
			continue;
		}
		if (rc == -1) {
			ISTGT_ERRLOG("poll() failed\n");
			break;
		}
		if (rc == 0) {
			/* no fds */
			continue;
		}
#endif /* ISTGT_USE_KQUEUE */

		n = rc;
		for (i = 0; n != 0 && i < istgt->nportal; i++) {
#ifdef ISTGT_USE_KQUEUE
			if (kev.ident == istgt->portal[i].sock) {
				if (kev.flags) {
					ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
					    "flags %x\n",
					    kev.flags);
				}
#else
			if (fds[i].revents) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "events %x\n",
				    fds[i].revents);
			}
			if (fds[i].revents & POLLIN) {
#endif /* ISTGT_USE_KQUEUE */
				n--;
				memset(&sa, 0, sizeof(sa));
				salen = sizeof(sa);
#ifdef ISTGT_USE_KQUEUE
				ISTGT_TRACELOG(ISTGT_TRACE_NET, "accept %d\n",
				    kev.ident);
				rc = accept(kev.ident, (struct sockaddr *) &sa, &salen);
#else
				ISTGT_TRACELOG(ISTGT_TRACE_NET, "accept %d\n",
				    fds[i].fd);
				rc = accept(fds[i].fd, (struct sockaddr *) &sa, &salen);
#endif /* ISTGT_USE_KQUEUE */
				if (rc < 0) {
					ISTGT_ERRLOG("accept error: %d\n", rc);
					continue;
				}
				sock = rc;
#if 0
				rc = fcntl(sock, F_GETFL, 0);
				if (rc == -1) {
					ISTGT_ERRLOG("fcntl() failed\n");
					continue;
				}
				rc = fcntl(sock, F_SETFL, (rc | O_NONBLOCK));
				if (rc == -1) {
					ISTGT_ERRLOG("fcntl() failed\n");
					continue;
				}
#endif
				rc = istgt_create_conn(istgt,
				    &istgt->portal[i], sock,
				    (struct sockaddr *) &sa, salen);
				if (rc < 0) {
					close(sock);
					ISTGT_ERRLOG("istgt_create_conn() failed\n");
					continue;
				}
			}
		}

		/* check for control */
		for (i = 0; n != 0 && i < istgt->nuctl_portal; i++) {
#ifdef ISTGT_USE_KQUEUE
			if (kev.ident == istgt->uctl_portal[i].sock) {
				if (kev.flags) {
					ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
					    "flags %x\n",
					    kev.flags);
				}
#else
			if (fds[ucidx + i].revents) {
				ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
				    "events %x\n",
				    fds[ucidx + i].revents);
			}
			if (fds[ucidx + i].revents & POLLIN) {
#endif /* ISTGT_USE_KQUEUE */
				n--;
				memset(&sa, 0, sizeof(sa));
				salen = sizeof(sa);
#ifdef ISTGT_USE_KQUEUE
				ISTGT_TRACELOG(ISTGT_TRACE_NET,
				    "accept %d\n", kev.ident);
				rc = accept(kev.ident,
				    (struct sockaddr *) &sa, &salen);
#else
				ISTGT_TRACELOG(ISTGT_TRACE_NET,
				    "accept %d\n", fds[ucidx + i].fd);
				rc = accept(fds[ucidx + i].fd,
				    (struct sockaddr *) &sa, &salen);
#endif /* ISTGT_USE_KQUEUE */
				if (rc < 0) {
					ISTGT_ERRLOG("accept error: %d\n", rc);
					continue;
				}
				sock = rc;
				rc = istgt_create_uctl(istgt,
				    &istgt->uctl_portal[i], sock,
				    (struct sockaddr *) &sa, salen);
				if (rc < 0) {
					close(sock);
					ISTGT_ERRLOG("istgt_create_uctl() failed\n");
					continue;
				}
			}
		}
	}
#ifdef ISTGT_USE_KQUEUE
	close(kq);
#endif /* ISTGT_USE_KQUEUE */
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "loop ended\n");
	istgt_set_state(istgt, ISTGT_STATE_EXITING);

	return 0;
}

static void
usage(void)
{
	printf("istgt [options]\n");
	printf("options:\n");
	printf(" -c config  config file (default %s)\n", DEFAULT_CONFIG);
	printf(" -p pidfile use specific file\n");
	printf(" -l facility use specific syslog facility (default %s)\n",
	    DEFAULT_LOG_FACILITY);
	printf(" -m mode    operational mode (default %d, 0=traditional, "
	    "1=normal, 2=experimental)\n", DEFAULT_ISTGT_SWMODE);
	printf(" -t flag    trace flag (all, net, iscsi, scsi, lu)\n");
	printf(" -q         quiet warnings\n");
	printf(" -D         don't detach from tty\n");
	printf(" -H         show this usage\n");
	printf(" -V         show version\n");
}

int
main(int argc, char **argv)
{
	ISTGT_Ptr istgt;
	const char *config_file = DEFAULT_CONFIG;
	const char *pidfile = NULL;
	const char *logfacility = NULL;
	const char *logpriority = NULL;
	CONFIG *config;
	pthread_t sigthread;
	struct sigaction sigact, sigoldact_pipe, sigoldact_info;
	struct sigaction sigoldact_wakeup, sigoldact_io;
	sigset_t signew, sigold;
	int retry = 10;
	int detach = 1;
	int swmode;
	int ch;
	int rc;

	if (sizeof (ISCSI_BHS) != ISCSI_BHS_LEN) {
		fprintf(stderr, "Internal Error\n");
		exit(EXIT_FAILURE);
	}

	memset(&g_istgt, 0, sizeof g_istgt);
	istgt = &g_istgt;
	istgt_set_state(istgt, ISTGT_STATE_INVALID);
	istgt->swmode = DEFAULT_ISTGT_SWMODE;

	while ((ch = getopt(argc, argv, "c:p:l:m:t:qDHV")) != -1) {
		switch (ch) {
		case 'c':
			config_file = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'l':
			logfacility = optarg;
			break;
		case 'm':
			swmode = strtol(optarg, NULL, 10);
			if (swmode == ISTGT_SWMODE_TRADITIONAL
			    || swmode == ISTGT_SWMODE_NORMAL
			    || swmode == ISTGT_SWMODE_EXPERIMENTAL) {
				istgt->swmode = swmode;
			} else {
				fprintf(stderr, "unknown mode %x\n", swmode);
				usage();
				exit(EXIT_FAILURE);
			}
			break;
		case 't':
			if (strcasecmp(optarg, "NET") == 0) {
				istgt_set_trace_flag(ISTGT_TRACE_NET);
			} else if (strcasecmp(optarg, "ISCSI") == 0) {
				istgt_set_trace_flag(ISTGT_TRACE_ISCSI);
			} else if (strcasecmp(optarg, "SCSI") == 0) {
				istgt_set_trace_flag(ISTGT_TRACE_SCSI);
			} else if (strcasecmp(optarg, "LU") == 0) {
				istgt_set_trace_flag(ISTGT_TRACE_LU);
			} else if (strcasecmp(optarg, "ALL") == 0) {
				istgt_set_trace_flag(ISTGT_TRACE_ALL);
			} else if (strcasecmp(optarg, "NONE") == 0) {
				istgt_set_trace_flag(ISTGT_TRACE_NONE);
			} else {
				fprintf(stderr, "unknown flag\n");
				usage();
				exit(EXIT_FAILURE);
			}
			break;
		case 'q':
			g_warn_flag = 0;
			break;
		case 'D':
			detach = 0;
			break;
		case 'V':
			printf("istgt version %s\n", ISTGT_VERSION);
			printf("istgt extra version %s\n", ISTGT_EXTRA_VERSION);
			exit(EXIT_SUCCESS);
		case 'H':
		default:
			usage();
			exit(EXIT_SUCCESS);
		}
	}

	/* read config files */
	config = istgt_allocate_config();
	rc = istgt_read_config(config, config_file);
	if (rc < 0) {
		fprintf(stderr, "config error\n");
		exit(EXIT_FAILURE);
	}
	if (config->section == NULL) {
		fprintf(stderr, "empty config\n");
		istgt_free_config(config);
		exit(EXIT_FAILURE);
	}
	istgt->config = config;
	//istgt_print_config(config);

	/* open log files */
	if (logfacility == NULL) {
		logfacility = istgt_get_log_facility(config);
	}
	rc = istgt_set_log_facility(logfacility);
	if (rc < 0) {
		fprintf(stderr, "log facility error\n");
		istgt_free_config(config);
		exit(EXIT_FAILURE);
	}
	if (logpriority == NULL) {
		logpriority = DEFAULT_LOG_PRIORITY;
	}
	rc = istgt_set_log_priority(logpriority);
	if (rc < 0) {
		fprintf(stderr, "log priority error\n");
		istgt_free_config(config);
		exit(EXIT_FAILURE);
	}
	istgt_open_log();

	ISTGT_NOTICELOG("istgt version %s (%s)\n", ISTGT_VERSION,
	    ISTGT_EXTRA_VERSION);
	switch (istgt->swmode) {
	case ISTGT_SWMODE_TRADITIONAL:
		ISTGT_NOTICELOG("traditional mode\n");
		break;
	case ISTGT_SWMODE_NORMAL:
		ISTGT_NOTICELOG("normal mode\n");
		break;
	case ISTGT_SWMODE_EXPERIMENTAL:
		ISTGT_NOTICELOG("experimental mode\n");
		break;
	default:
		break;
	}

#ifdef ISTGT_USE_CRC32C_TABLE
	/* build crc32c table */
	istgt_init_crc32c_table();
#endif /* ISTGT_USE_CRC32C_TABLE */

	/* initialize sub modules */
	rc = istgt_init(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("istgt_init() failed\n");
	initialize_error:
		istgt_close_log();
		istgt_free_config(config);
		exit(EXIT_FAILURE);
	}
	rc = istgt_lu_init(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("istgt_lu_init() failed\n");
		goto initialize_error;
	}
	rc = istgt_iscsi_init(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("istgt_iscsi_init() failed\n");
		goto initialize_error;
	}

	/* override by command line */
	if (pidfile != NULL) {
		xfree(istgt->pidfile);
		istgt->pidfile = xstrdup(pidfile);
	}

	/* detach from tty and run background */
	fflush(stdout);
	if (detach) {
		rc = daemon(0, 0);
		if (rc < 0) {
			ISTGT_ERRLOG("daemon() failed\n");
			goto initialize_error;
		}
	}

	/* setup signal handler thread */
	memset(&sigact, 0, sizeof sigact);
	memset(&sigoldact_pipe, 0, sizeof sigoldact_pipe);
	memset(&sigoldact_info, 0, sizeof sigoldact_info);
	memset(&sigoldact_wakeup, 0, sizeof sigoldact_wakeup);
	memset(&sigoldact_io, 0, sizeof sigoldact_io);
	sigact.sa_handler = SIG_IGN;
	sigemptyset(&sigact.sa_mask);
	rc = sigaction(SIGPIPE, &sigact, &sigoldact_pipe);
	if (rc < 0) {
		ISTGT_ERRLOG("sigaction(SIGPIPE) failed\n");
		goto initialize_error;
	}
#ifdef SIGINFO
	sigact.sa_handler = istgt_siginfo;
	sigemptyset(&sigact.sa_mask);
	rc = sigaction(SIGINFO, &sigact, &sigoldact_info);
	if (rc < 0) {
		ISTGT_ERRLOG("sigaction(SIGINFO) failed\n");
		goto initialize_error;
	}
#endif
#ifdef ISTGT_USE_SIGRT
	if (ISTGT_SIGWAKEUP < SIGRTMIN
		|| ISTGT_SIGWAKEUP > SIGRTMAX) {
		ISTGT_ERRLOG("SIGRT error\n");
		goto initialize_error;
	}
#endif /* ISTGT_USE_SIGRT */
	sigact.sa_handler = istgt_sigwakeup;
	sigemptyset(&sigact.sa_mask);
	rc = sigaction(ISTGT_SIGWAKEUP, &sigact, &sigoldact_wakeup);
	if (rc < 0) {
		ISTGT_ERRLOG("sigaction(ISTGT_SIGWAKEUP) failed\n");
		goto initialize_error;
	}
#ifdef SIGIO
	sigact.sa_handler = istgt_sigio;
	sigemptyset(&sigact.sa_mask);
	rc = sigaction(SIGIO, &sigact, &sigoldact_io);
	if (rc < 0) {
		ISTGT_ERRLOG("sigaction(SIGIO) failed\n");
		goto initialize_error;
	}
#endif
	pthread_sigmask(SIG_SETMASK, NULL, &signew);
	sigaddset(&signew, SIGINT);
	sigaddset(&signew, SIGTERM);
	sigaddset(&signew, SIGQUIT);
	sigaddset(&signew, SIGHUP);
#ifdef SIGINFO
	sigaddset(&signew, SIGINFO);
#endif
	sigaddset(&signew, SIGUSR1);
	sigaddset(&signew, SIGUSR2);
#ifdef SIGIO
	sigaddset(&signew, SIGIO);
#endif
	sigaddset(&signew, ISTGT_SIGWAKEUP);
	pthread_sigmask(SIG_SETMASK, &signew, &sigold);
#ifdef ISTGT_STACKSIZE
	rc = pthread_create(&sigthread, &istgt->attr, &istgt_sighandler,
#else
	rc = pthread_create(&sigthread, NULL, &istgt_sighandler,
#endif
	    (void *) istgt);
	if (rc != 0) {
		ISTGT_ERRLOG("pthread_create() failed\n");
		goto initialize_error;
	}
#if 0
	rc = pthread_detach(sigthread);
	if (rc != 0) {
		ISTGT_ERRLOG("pthread_detach() failed\n");
		goto initialize_error;
	}
#endif
#ifdef HAVE_PTHREAD_SET_NAME_NP
	pthread_set_name_np(sigthread, "sigthread");
	pthread_set_name_np(pthread_self(), "mainthread");
#endif

	/* create LUN threads for command queuing */
	rc = istgt_lu_create_threads(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_create_threads() failed\n");
		goto initialize_error;
	}
	rc = istgt_lu_set_all_state(istgt, ISTGT_STATE_RUNNING);
	if (rc < 0) {
		ISTGT_ERRLOG("lu_set_all_state() failed\n");
		goto initialize_error;
	}

	/* open portals */
	rc = istgt_open_uctl_portal(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("istgt_open_uctl_portal() failed\n");
		goto initialize_error;
	}
	rc = istgt_open_portal(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("istgt_open_portal() failed\n");
		goto initialize_error;
	}

	/* write pid */
	rc = istgt_write_pidfile(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("istgt_write_pid() failed\n");
		goto initialize_error;
	}

	/* accept loop */
	rc = istgt_acceptor(istgt);
	if (rc < 0) {
		ISTGT_ERRLOG("istgt_acceptor() failed\n");
		istgt_close_portal(istgt);
		istgt_close_uctl_portal(istgt);
		istgt_iscsi_shutdown(istgt);
		istgt_lu_shutdown(istgt);
		istgt_destory_initiator_group_array(istgt);
		istgt_destroy_portal_array(istgt);
		istgt_destroy_uctl_portal(istgt);
		istgt_remove_pidfile(istgt);
		istgt_close_log();
		istgt->config = NULL;
		istgt_free_config(config);
		exit(EXIT_FAILURE);
	}

	/* wait threads */
	while (retry > 0) {
		if (istgt_get_active_conns() == 0) {
			break;
		}
		sleep(1);
		retry--;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "retry=%d\n", retry);

	ISTGT_NOTICELOG("istgt version %s (%s) exiting\n", ISTGT_VERSION,
	    ISTGT_EXTRA_VERSION);

	/* cleanup */
	istgt_close_portal(istgt);
	istgt_close_uctl_portal(istgt);
	istgt_iscsi_shutdown(istgt);
	istgt_lu_shutdown(istgt);
	istgt_destory_initiator_group_array(istgt);
	istgt_destroy_portal_array(istgt);
	istgt_destroy_uctl_portal(istgt);
	istgt_remove_pidfile(istgt);
	istgt_close_log();
	istgt->config = NULL;
	istgt_free_config(config);
	istgt_set_state(istgt, ISTGT_STATE_SHUTDOWN);

	/* stop signal thread */
	rc = pthread_join(sigthread, NULL);
	if (rc != 0) {
		ISTGT_ERRLOG("pthread_join() failed\n");
		exit (EXIT_FAILURE);
	}

	return 0;
}
