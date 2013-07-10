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

#ifndef ISTGT_LU_H
#define ISTGT_LU_H

#include <pthread.h>
#include <time.h>
#ifdef HAVE_UUID_H
#include <uuid.h>
#endif
#include "istgt.h"
#include "istgt_queue.h"

#define MAX_LU_LUN 64
#define MAX_LU_LUN_SLOT 8
#define MAX_LU_TSIH 256
#define MAX_LU_MAP 256
#define MAX_LU_SERIAL_STRING 32
#define MAX_LU_RESERVE 256
#define MAX_LU_RESERVE_IPT 256
#define MAX_LU_QUEUE_DEPTH 256

#define USE_LU_TAPE_DLT8000

#define DEFAULT_LU_BLOCKLEN 512
#define DEFAULT_LU_BLOCKLEN_DISK DEFAULT_LU_BLOCKLEN
#define DEFAULT_LU_BLOCKLEN_DVD 2048
#define DEFAULT_LU_BLOCKLEN_TAPE DEFAULT_LU_BLOCKLEN
#define DEFAULT_LU_QUEUE_DEPTH 32
#define DEFAULT_LU_ROTATIONRATE 7200	/* 7200 rpm */
#define DEFAULT_LU_FORMFACTOR 0x02	/* 3.5 inch */

#if defined (__FreeBSD__)
#define DEFAULT_LU_VENDOR "FreeBSD"
#elif defined (__NetBSD__)
#define DEFAULT_LU_VENDOR "NetBSD"
#elif defined (__OpenBSD__)
#define DEFAULT_LU_VENDOR "OpenBSD"
#else
//#define DEFAULT_LU_VENDOR "PEACHNW"
#define DEFAULT_LU_VENDOR "FreeBSD"
#endif

#define DEFAULT_LU_VENDOR_DISK DEFAULT_LU_VENDOR
#define DEFAULT_LU_VENDOR_DVD  DEFAULT_LU_VENDOR
#ifndef USE_LU_TAPE_DLT8000
#define DEFAULT_LU_VENDOR_TAPE DEFAULT_LU_VENDOR
#else
#define DEFAULT_LU_VENDOR_TAPE "QUANTUM"
#endif /* !USE_LU_TAPE_DLT8000 */
#define DEFAULT_LU_PRODUCT      "iSCSI UNIT"
#define DEFAULT_LU_PRODUCT_DISK "iSCSI DISK"
#define DEFAULT_LU_PRODUCT_DVD  "iSCSI DVD"
#ifndef USE_LU_TAPE_DLT8000
#define DEFAULT_LU_PRODUCT_TAPE "iSCSI TAPE"
#else
#define DEFAULT_LU_PRODUCT_TAPE "DLT8000"
#endif /* !USE_LU_TAPE_DLT8000 */
#define DEFAULT_LU_REVISION "0001"
#define DEFAULT_LU_REVISION_DISK DEFAULT_LU_REVISION
#define DEFAULT_LU_REVISION_DVD  DEFAULT_LU_REVISION
#ifndef USE_LU_TAPE_DLT8000
#define DEFAULT_LU_REVISION_TAPE DEFAULT_LU_REVISION
#else
#define DEFAULT_LU_REVISION_TAPE "C001"
#endif /* !USE_LU_TAPE_DLT8000 */
#define MAX_INQUIRY_SERIAL 16

#define ISTGT_LU_WORK_BLOCK_SIZE (1ULL * 1024ULL * 1024ULL)
#define ISTGT_LU_WORK_ATS_BLOCK_SIZE (1ULL * 1024ULL * 1024ULL)
#define ISTGT_LU_MAX_WRITE_CACHE_SIZE (8ULL * 1024ULL * 1024ULL)
#define ISTGT_LU_MEDIA_SIZE_MIN (1ULL * 1024ULL * 1024ULL)
#define ISTGT_LU_MEDIA_EXTEND_UNIT (256ULL * 1024ULL * 1024ULL)
#define ISTGT_LU_1GB (1ULL * 1024ULL * 1024ULL * 1024ULL)
#define ISTGT_LU_1MB (1ULL * 1024ULL * 1024ULL)

typedef enum {
	ISTGT_LU_FLAG_MEDIA_READONLY = 0x00000001,
	ISTGT_LU_FLAG_MEDIA_AUTOSIZE = 0x00000002,
	ISTGT_LU_FLAG_MEDIA_EXTEND   = 0x00000010,
	ISTGT_LU_FLAG_MEDIA_DYNAMIC  = 0x00000020,
} ISTGT_LU_FLAG;

typedef enum {
	ISTGT_LU_TYPE_NONE = 0,
	ISTGT_LU_TYPE_PASS = 1,
	ISTGT_LU_TYPE_DISK = 2,
	ISTGT_LU_TYPE_DVD = 3,
	ISTGT_LU_TYPE_TAPE = 4,
} ISTGT_LU_TYPE;

typedef enum {
	ISTGT_LU_LUN_TYPE_NONE = 0,
	ISTGT_LU_LUN_TYPE_DEVICE = 1,
	ISTGT_LU_LUN_TYPE_STORAGE = 2,
	ISTGT_LU_LUN_TYPE_REMOVABLE = 3,
	ISTGT_LU_LUN_TYPE_SLOT = 4,
} ISTGT_LU_LUN_TYPE;

typedef struct istgt_lu_device_t {
	char *file;
} ISTGT_LU_DEVICE;

typedef struct istgt_lu_storage_t {
	int fd;
	char *file;
	uint64_t size;
} ISTGT_LU_STORAGE;

typedef struct istgt_lu_removable_t {
	int type;
	int id;
	int flags;
	int fd;
	char *file;
	uint64_t size;
} ISTGT_LU_REMOVABLE;

typedef struct istgt_lu_slot_t {
	int maxslot;
	int present[MAX_LU_LUN_SLOT];
	int flags[MAX_LU_LUN_SLOT];
	char *file[MAX_LU_LUN_SLOT];
	uint64_t size[MAX_LU_LUN_SLOT];
} ISTGT_LU_SLOT;

typedef struct istgt_lu_lun_t {
	int type;
	union {
		ISTGT_LU_DEVICE device;
		ISTGT_LU_STORAGE storage;
		ISTGT_LU_REMOVABLE removable;
		ISTGT_LU_SLOT slot;
	} u;
	int rotationrate;
	int formfactor;
	int readcache;
	int writecache;
	char *serial;
	void *spec;
} ISTGT_LU_LUN;
typedef ISTGT_LU_LUN *ISTGT_LU_LUN_Ptr;

typedef struct istgt_lu_tsih_t {
	int tag;
	uint16_t tsih;
	char *initiator_port;
} ISTGT_LU_TSIH;

typedef enum {
	AAS_ACTIVE_OPTIMIZED = 0x00,
	AAS_ACTIVE_NON_OPTIMIZED = 0x01,
	AAS_STANDBY = 0x02,
	AAS_UNAVAILABLE = 0x03,
	AAS_TRANSITIONING = 0x0F,

	AAS_STATUS_NO = 0x0000,
	AAS_STATUS_STPG = 0x0100,
	AAS_STATUS_IMPLICIT = 0x0200,
} ISTGT_LU_AAS;

typedef struct istgt_lu_map_t {
	int pg_tag;
	int pg_aas;
	int ig_tag;
} ISTGT_LU_MAP;

typedef struct istgt_lu_t {
	int num;
	char *name;
	char *alias;

	char *inq_vendor;
	char *inq_product;
	char *inq_revision;
	char *inq_serial;

	ISTGT_Ptr istgt;
	ISTGT_STATE state;
	pthread_mutex_t mutex;
	pthread_mutex_t state_mutex;
	pthread_mutex_t queue_mutex;
	pthread_cond_t queue_cond;
	pthread_t thread;

	uint16_t last_tsih;

	int no_auth_chap;
	int auth_chap;
	int auth_chap_mutual;
	int auth_group;
	int header_digest;
	int data_digest;

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

	int type;
	int online;
	int readonly;
	int blocklen;
	int queue_depth;
	int queue_check;

	int maxlun;
	ISTGT_LU_LUN lun[MAX_LU_LUN];
	int maxtsih;
	ISTGT_LU_TSIH tsih[MAX_LU_TSIH];
	int maxmap;
	ISTGT_LU_MAP map[MAX_LU_MAP];
} ISTGT_LU;
typedef ISTGT_LU *ISTGT_LU_Ptr;

typedef struct istgt_lu_cmd_t {
	struct iscsi_pdu_t *pdu;
	ISTGT_LU_Ptr lu;

	int I_bit;
	int F_bit;
	int R_bit;
	int W_bit;
	int Attr_bit;
	uint64_t lun;
	uint32_t task_tag;
	uint32_t transfer_len;
	uint32_t CmdSN;
	uint8_t *cdb;

	uint8_t *iobuf;
	size_t iobufsize;
	uint8_t *data;
	size_t data_len;
	size_t alloc_len;

	int status;
	uint8_t *sense_data;
	size_t sense_data_len;
	size_t sense_alloc_len;
} ISTGT_LU_CMD;
typedef ISTGT_LU_CMD *ISTGT_LU_CMD_Ptr;

enum {
	ISTGT_LU_TASK_RESULT_IMMEDIATE = 0,
	ISTGT_LU_TASK_RESULT_QUEUE_OK = 1,
	ISTGT_LU_TASK_RESULT_QUEUE_FULL = 2,
} ISTGT_LU_TASK_RESULT;

enum {
	ISTGT_LU_TASK_RESPONSE = 0,
	ISTGT_LU_TASK_REQPDU = 1,
	ISTGT_LU_TASK_REQUPDPDU = 2,
} ISTGT_LU_TASK_TYPE;

typedef struct istgt_lu_task_t {
	int type;

	struct istgt_conn_t *conn;
	char initiator_name[MAX_INITIATOR_NAME];
	char initiator_port[MAX_INITIATOR_NAME];
	ISTGT_LU_CMD lu_cmd;
	int lun;
	pthread_t thread;
	int use_cond;
	pthread_mutex_t trans_mutex;
	pthread_cond_t trans_cond;
	pthread_cond_t exec_cond;

	time_t create_time;
	int condwait;

	int dup_iobuf;
	uint8_t *iobuf;
	uint8_t *data;
	uint8_t *sense_data;
	size_t alloc_len;

	int offset;
	int req_execute;
	int req_transfer_out;
	int error;
	int abort;
	int execute;
	int complete;
	int lock;
} ISTGT_LU_TASK;
typedef ISTGT_LU_TASK *ISTGT_LU_TASK_Ptr;

/* lu_disk.c */
typedef struct istgt_lu_pr_key_t {
	uint64_t key;

	/* transport IDs */
	char *registered_initiator_port;
	char *registered_target_port;
	/* PERSISTENT RESERVE OUT received from */
	int pg_idx; /* relative target port */
	int pg_tag; /* target port group */

	int ninitiator_ports;
	char **initiator_ports;
	int all_tpg;
} ISTGT_LU_PR_KEY;

typedef struct istgt_lu_disk_t {
	ISTGT_LU_Ptr lu;
	int num;
	int lun;

	int fd;
	const char *file;
	const char *disktype;
	void *exspec;
	uint64_t fsize;
	uint64_t foffset;
	uint64_t size;
	uint64_t blocklen;
	uint64_t blockcnt;

#ifdef HAVE_UUID_H
	uuid_t uuid;
#endif /* HAVE_UUID_H */

	/* cache flags */
	int read_cache;
	int write_cache;
	/* parts for cache */
	int wbufsize;
	uint8_t *wbuf;
	uint64_t woffset;
	uint64_t wnbytes;
	int req_write_cache;
	int err_write_cache;

	/* thin provisioning */
	int thin_provisioning;

	/* for ats */
	pthread_mutex_t ats_mutex;
	int watssize;
	uint8_t *watsbuf;

	int queue_depth;
	pthread_mutex_t cmd_queue_mutex;
	ISTGT_QUEUE cmd_queue;
	pthread_mutex_t wait_lu_task_mutex;
	ISTGT_LU_TASK_Ptr wait_lu_task;

	/* PERSISTENT RESERVE */
	int npr_keys;
	ISTGT_LU_PR_KEY pr_keys[MAX_LU_RESERVE];
	uint32_t pr_generation;

	char *rsv_port;
	uint64_t rsv_key;
	int rsv_scope;
	int rsv_type;

	/* SCSI sense code */
	volatile int sense;

	/* entry */
	int (*open)(struct istgt_lu_disk_t *spec, int flags, int mode);
	int (*close)(struct istgt_lu_disk_t *spec);
	int64_t (*seek)(struct istgt_lu_disk_t *spec, uint64_t offset);
	int64_t (*read)(struct istgt_lu_disk_t *spec, void *buf, uint64_t nbytes);
	int64_t (*write)(struct istgt_lu_disk_t *spec, const void *buf, uint64_t nbytes);
	int64_t (*sync)(struct istgt_lu_disk_t *spec, uint64_t offset, uint64_t nbytes);
	int (*allocate)(struct istgt_lu_disk_t *spec);
	int (*setcache)(struct istgt_lu_disk_t *spec);
} ISTGT_LU_DISK;

#endif /* ISTGT_LU_H */
