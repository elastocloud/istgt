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

#include <stdlib.h>
#include <string.h>

#include "istgt_misc.h"
#include "istgt_queue.h"

int
istgt_queue_init(ISTGT_QUEUE_Ptr head)
{
	if (head == NULL)
		return -1;
	head->prev = NULL;
	head->next = NULL;
	head->elem = NULL;
	head->num = 0;
	return 0;
}

void
istgt_queue_destroy(ISTGT_QUEUE_Ptr head)
{
	ISTGT_QUEUE_Ptr qp;
	ISTGT_QUEUE_Ptr next;

	if (head == NULL)
		return;
	for (qp = head->next; qp != NULL && qp != head; qp = next) {
		next = qp->next;
		free(qp);
	}
	head->next = NULL;
	head->prev = NULL;
}

int
istgt_queue_count(ISTGT_QUEUE_Ptr head)
{
#if 0
	ISTGT_QUEUE_Ptr qp;
	int num;

	if (head == NULL)
		return 0;
	num = 0;
	for (qp = head->next; qp != NULL && qp != head; qp = qp->next) {
		num++;
	}
	return num;
#else
	if (head == NULL)
		return 0;
	return head->num;
#endif
}

int
istgt_queue_enqueue(ISTGT_QUEUE_Ptr head, void *elem)
{
	ISTGT_QUEUE_Ptr qp;
	ISTGT_QUEUE_Ptr tail;

	if (head == NULL)
		return -1;
	qp = xmalloc(sizeof *qp);
	memset(qp, 0, sizeof *qp);

	qp->elem = elem;

	tail = head->prev;
	if (tail == NULL) {
		head->next = qp;
		head->prev = qp;
		qp->next = head;
		qp->prev = head;
	} else {
		tail->next = qp;
		head->prev = qp;
		qp->next = head;
		qp->prev = tail;
	}
	head->num++;
	return 0;
}

void *
istgt_queue_dequeue(ISTGT_QUEUE_Ptr head)
{
	ISTGT_QUEUE_Ptr first;
	ISTGT_QUEUE_Ptr next;
	void *elem;

	if (head == NULL)
		return NULL;
	first = head->next;
	if (first == NULL || first == head) {
		return NULL;
	} else {
		elem = first->elem;
		next = first->next;
		xfree(first);
		if (next == NULL) {
			head->next = NULL;
			head->prev = NULL;
		} else {
			head->next = next;
			next->prev = head;
		}
	}
	head->num--;
	return elem;
}

int
istgt_queue_enqueue_first(ISTGT_QUEUE_Ptr head, void *elem)
{
	ISTGT_QUEUE_Ptr qp;
	ISTGT_QUEUE_Ptr first;

	if (head == NULL)
		return -1;
	qp = xmalloc(sizeof *qp);
	memset(qp, 0, sizeof *qp);

	qp->elem = elem;

	first = head->next;
	if (first == NULL || first == head) {
		head->next = qp;
		head->prev = qp;
		qp->next = head;
		qp->prev = head;
	} else {
		head->next = qp;
		first->prev = qp;
		qp->next = first;
		qp->prev = head;
	}
	head->num++;
	return 0;
}
