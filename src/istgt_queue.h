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

#ifndef ISTGT_QUEUE_H
#define ISTGT_QUEUE_H

#include <stddef.h>

typedef struct istgt_queue_t {
	struct istgt_queue_t *prev;
	struct istgt_queue_t *next;
	void *elem;
	int num;
} ISTGT_QUEUE;
typedef ISTGT_QUEUE *ISTGT_QUEUE_Ptr;

int istgt_queue_init(ISTGT_QUEUE_Ptr head);
void istgt_queue_destroy(ISTGT_QUEUE_Ptr head);
int istgt_queue_count(ISTGT_QUEUE_Ptr head);
int istgt_queue_enqueue(ISTGT_QUEUE_Ptr head, void *elem);
void *istgt_queue_dequeue(ISTGT_QUEUE_Ptr head);
int istgt_queue_enqueue_first(ISTGT_QUEUE_Ptr head, void *elem);

#endif /* ISTGT_QUEUE_H */
