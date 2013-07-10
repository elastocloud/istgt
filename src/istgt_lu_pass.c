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

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include <fcntl.h>
#include <unistd.h>

#ifdef HAVE_LIBCAM
#include <camlib.h>
#include <cam/cam.h>
#include <cam/cam_ccb.h>
#include <cam/scsi/scsi_message.h>

#include "istgt.h"
#include "istgt_ver.h"
#include "istgt_log.h"
#include "istgt_misc.h"
#include "istgt_lu.h"
#include "istgt_proto.h"
#include "istgt_scsi.h"

#if !defined(__GNUC__)
#undef __attribute__
#define __attribute__(x)
#endif

//#define ISTGT_TRACE_PASS

#define ISTGT_LU_CAM_TIMEOUT 60000 /* 60sec. */

typedef struct istgt_lu_pass_t {
	ISTGT_LU_Ptr lu;
	int num;
	int lun;

	const char *file;
	uint64_t size;
	uint64_t blocklen;
	uint64_t blockcnt;

	char *device;
	int unit;
	struct cam_device *cam_dev;
	union ccb *ccb;

	int timeout;

	uint8_t *inq_standard;
	int inq_standard_len;
	int inq_pd;
	int inq_rmb;
	int inq_ver;
	int inq_fmt;
	uint64_t ms_blocklen;
	uint64_t ms_blockcnt;
} ISTGT_LU_PASS;

#define BUILD_SENSE(SK,ASC,ASCQ)					\
	do {								\
		*sense_len =						\
			istgt_lu_pass_build_sense_data(spec, sense_data, \
			    ISTGT_SCSI_SENSE_ ## SK,			\
			    (ASC), (ASCQ));				\
	} while (0)

static int istgt_lu_pass_build_sense_data(ISTGT_LU_PASS *spec, uint8_t *data, int sk, int asc, int ascq);

static void
istgt_lu_pass_parse_sense_key(uint8_t *sense_data, int *skp, int *ascp, int *ascqp)
{
	int rsp;
	int sk, asc, ascq;

	if (sense_data == NULL) {
		if (skp != NULL)
			*skp = -1;
		if (ascp != NULL)
			*ascp = -1;
		if (ascqp != NULL)
			*ascqp = -1;
		return;
	}

	rsp = BGET8W(&sense_data[0], 6, 7);
	switch (rsp) {
	case 0x70: /* Current Fixed */
		sk = BGET8W(&sense_data[2], 3, 4);
		asc = sense_data[12];
		ascq = sense_data[13];
		break;
	case 0x71: /* Deferred Fixed */
		sk = BGET8W(&sense_data[2], 3, 4);
		asc = sense_data[12];
		ascq = sense_data[13];
		break;
	case 0x72: /* Current Descriptor */
		sk = BGET8W(&sense_data[2], 3, 4);
		asc = sense_data[2];
		ascq = sense_data[3];
		break;
	case 0x73: /* Deferred Descriptor */
		sk = BGET8W(&sense_data[2], 3, 4);
		asc = sense_data[2];
		ascq = sense_data[3];
		break;
	default:
		sk = asc = ascq = -1;
		break;
	}

	if (skp != NULL)
		*skp = sk;
	if (ascp != NULL)
		*ascp = asc;
	if (ascqp != NULL)
		*ascqp = ascq;
}

static void
istgt_lu_pass_print_sense_key(uint8_t *sense_data)
{
	int sk, asc, ascq;

	istgt_lu_pass_parse_sense_key(sense_data, &sk, &asc, &ascq);
	if (sk >= 0) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "SK=0x%x, ASC=0x%x, ASCQ=0x%x\n",
		    sk, asc, ascq);
	}
}

static int
istgt_lu_pass_set_inquiry(ISTGT_LU_PASS *spec)
{
	uint8_t buf[MAX_TMPBUF];
	uint8_t cdb[16];
	uint32_t flags;
	uint8_t *data;
	int cdb_len;
	int data_len;
	int data_alloc_len;
	int retry = 1;
	int rc;

	memset(buf, 0, sizeof buf);
	memset(cdb, 0, sizeof cdb);
	data = buf;
	if (sizeof buf > 0xff) {
		data_alloc_len = 0xff;
	} else {
		data_alloc_len = sizeof buf;
	}

	/* issue standard INQUIRY */
	cdb[0] = SPC_INQUIRY;
	cdb[1] = 0;
	cdb[2] = 0;
	DSET16(&cdb[3], data_alloc_len); /* ALLOCATION LENGTH */
	cdb[5] = 0;
	cdb_len = 6;
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "CDB", cdb, cdb_len);

	memcpy(spec->ccb->csio.cdb_io.cdb_bytes, cdb, cdb_len);
	flags = CAM_DIR_IN;
	flags |= CAM_DEV_QFRZDIS;
	cam_fill_csio(&spec->ccb->csio, retry, NULL, flags, MSG_SIMPLE_Q_TAG,
	    data, data_alloc_len, SSD_FULL_SIZE, cdb_len,
	    spec->timeout);
	rc = cam_send_ccb(spec->cam_dev, spec->ccb);
	if (rc < 0) {
		ISTGT_ERRLOG("cam_send_ccb() failed\n");
		return -1;
	}

	if ((spec->ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "request error CAM=0x%x, SCSI=0x%x\n",
		    spec->ccb->ccb_h.status,
		    spec->ccb->csio.scsi_status);
		ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "SENSE",
		    (uint8_t *) &spec->ccb->csio.sense_data,
		    SSD_FULL_SIZE);
		istgt_lu_pass_print_sense_key((uint8_t *) &spec->ccb->csio.sense_data);
		return -1;
	}
	data_len = spec->ccb->csio.dxfer_len;
	data_len -= spec->ccb->csio.resid;

	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "INQUIRY", data, data_len);
	spec->inq_standard = xmalloc(data_len);
	spec->inq_standard_len = data_len;
	memcpy(spec->inq_standard, data, data_len);

	return 0;
}

static int
istgt_lu_pass_set_modesense(ISTGT_LU_PASS *spec)
{
	uint8_t buf[MAX_TMPBUF];
	uint8_t cdb[16];
	uint32_t flags;
	uint8_t *data;
	int cdb_len;
	int data_len;
	int data_alloc_len;
	int req_len;
	int retry = 1;
	int sk, asc, ascq;
	int rc;

	memset(buf, 0, sizeof buf);
	memset(cdb, 0, sizeof cdb);
	data = buf;
	if (sizeof buf > 0xff) {
		data_alloc_len = 0xff;
	} else {
		data_alloc_len = sizeof buf;
	}

	if (spec->inq_pd == SPC_PERIPHERAL_DEVICE_TYPE_DVD) {
		/* MMC have only 10 */
		goto retry_sense10;
	}
 retry_sense6:
	spec->ms_blockcnt = 0;
	spec->ms_blocklen = 0;
	memset(cdb, 0, sizeof cdb);
	/* issue MODE SENSE(6) */
	data_alloc_len = 4 + 8;         /* only block descriptor */
	req_len = 4 + 8;
	cdb[0] = SPC_MODE_SENSE_6;
	BDADD8(&cdb[1], 0, 3);          /* DBD */
	BDSET8W(&cdb[2], 0x00, 7, 2);   /* PC */
	//BDADD8W(&cdb[2], 0x00, 5, 6);   /* PAGE CODE */
	BDADD8W(&cdb[2], 0x3f, 5, 6);   /* PAGE CODE */
	cdb[3] = 0x00;                  /* SUBPAGE CODE */
	cdb[4] = data_alloc_len;        /* ALLOCATION LENGTH */
	cdb_len = 6;
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "CDB", cdb, cdb_len);

	memcpy(spec->ccb->csio.cdb_io.cdb_bytes, cdb, cdb_len);
	flags = CAM_DIR_IN;
	flags |= CAM_DEV_QFRZDIS;
	cam_fill_csio(&spec->ccb->csio, retry, NULL, flags, MSG_SIMPLE_Q_TAG,
	    data, data_alloc_len, SSD_FULL_SIZE, cdb_len,
	    spec->timeout);
	rc = cam_send_ccb(spec->cam_dev, spec->ccb);
	if (rc < 0) {
		ISTGT_ERRLOG("cam_send_ccb() failed\n");
		return -1;
	}

	if ((spec->ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "request error CAM=0x%x, SCSI=0x%x\n",
		    spec->ccb->ccb_h.status,
		    spec->ccb->csio.scsi_status);
		ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "SENSE",
		    (uint8_t *) &spec->ccb->csio.sense_data,
		    SSD_FULL_SIZE);
		istgt_lu_pass_print_sense_key((uint8_t *) &spec->ccb->csio.sense_data);
		istgt_lu_pass_parse_sense_key((uint8_t *) &spec->ccb->csio.sense_data,
		    &sk, &asc, &ascq);
		if (sk == ISTGT_SCSI_SENSE_ILLEGAL_REQUEST) {
			if (asc == 0x20 && ascq == 0x00) {
				/* INVALID COMMAND OPERATION CODE */
				goto retry_sense10;
			} else if (asc == 0x24 && ascq == 0x00) {
				/* INVALID FIELD IN CDB */
				goto retry_sense10;
			}
		}
		if (sk == ISTGT_SCSI_SENSE_UNIT_ATTENTION) {
			if (asc == 0x28 && ascq == 0x00) {
				/* NOT READY TO READY CHANGE, MEDIUM MAY HAVE CHANGED */
				goto retry_sense6;
			}
			if (asc == 0x29 && ascq == 0x00) {
				/* POWER ON, RESET, OR BUS DEVICE RESET OCCURRED */
				goto retry_sense6;
			} else if (asc == 0x29 && ascq == 0x01) {
				/* POWER ON OCCURRED */
				goto retry_sense6;
			} else if (asc == 0x29 && ascq == 0x02) {
				/* SCSI BUS RESET OCCURRED */
				goto retry_sense6;
			} else if (asc == 0x29 && ascq == 0x03) {
				/* BUS DEVICE RESET FUNCTION OCCURRED */
				goto retry_sense6;
			} else if (asc == 0x29 && ascq == 0x04) {
				/* DEVICE INTERNAL RESET */
				goto retry_sense6;
			} else if (asc == 0x29 && ascq == 0x05) {
				/* TRANSCEIVER MODE CHANGED TO SINGLE-ENDED */
				goto retry_sense6;
			} else if (asc == 0x29 && ascq == 0x06) {
				/* TRANSCEIVER MODE CHANGED TO LVD */
				goto retry_sense6;
			} else if (asc == 0x29 && ascq == 0x07) {
				/* I_T NEXUS LOSS OCCURRED */
				goto retry_sense6;
			}
		}
		return -1;
	}
	data_len = spec->ccb->csio.dxfer_len;
	data_len -= spec->ccb->csio.resid;
	if (data_len < req_len) {
		ISTGT_ERRLOG("result is short\n");
		return -1;		
	}

	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "MODE SENSE(6)", data, data_len);
	if (DGET8(&data[3]) != 0) { /* BLOCK DESCRIPTOR LENGTH */
		if (spec->inq_pd == SPC_PERIPHERAL_DEVICE_TYPE_DISK) {
			spec->ms_blockcnt = DGET32(&data[4+0]);
			spec->ms_blocklen = DGET24(&data[4+5]);
		} else {
			spec->ms_blockcnt = DGET24(&data[4+1]);
			spec->ms_blocklen = DGET24(&data[4+5]);
		}
	} else {
		goto retry_sense10;
	}

	if ((spec->inq_pd == SPC_PERIPHERAL_DEVICE_TYPE_DISK
		 && spec->ms_blockcnt == 0xffffffffU)
		|| (spec->inq_pd != SPC_PERIPHERAL_DEVICE_TYPE_DISK
			&& spec->ms_blockcnt == 0x00ffffffU)) {
	retry_sense10:
		spec->ms_blockcnt = 0;
		spec->ms_blocklen = 0;
		memset(cdb, 0, sizeof cdb);
		/* issue MODE SENSE(10) */
		data_alloc_len = 8 + 16;        /* only block descriptor */
		req_len = 8 + 16;
		cdb[0] = SPC_MODE_SENSE_10;
		BDSET8(&cdb[1], 1, 4);          /* LLBAA */
		BDADD8(&cdb[1], 0, 3);          /* DBD */
		BDSET8W(&cdb[2], 0x00, 7, 2);   /* PC */
		//BDADD8W(&cdb[2], 0x00, 5, 6);   /* PAGE CODE */
		BDADD8W(&cdb[2], 0x3f, 5, 6);   /* PAGE CODE */
		cdb[3] = 0x00;                  /* SUBPAGE CODE */
		DSET16(&cdb[7], data_alloc_len); /* ALLOCATION LENGTH */
		cdb_len = 10;
		ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "CDB", cdb, cdb_len);

		memcpy(spec->ccb->csio.cdb_io.cdb_bytes, cdb, cdb_len);
		flags = CAM_DIR_IN;
		flags |= CAM_DEV_QFRZDIS;
		cam_fill_csio(&spec->ccb->csio, retry, NULL, flags, MSG_SIMPLE_Q_TAG,
		    data, data_alloc_len, SSD_FULL_SIZE, cdb_len,
		    spec->timeout);
		rc = cam_send_ccb(spec->cam_dev, spec->ccb);
		if (rc < 0) {
			ISTGT_ERRLOG("cam_send_ccb() failed\n");
			return -1;
		}

		if ((spec->ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "request error CAM=0x%x, SCSI=0x%x\n",
			    spec->ccb->ccb_h.status,
			    spec->ccb->csio.scsi_status);
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "SENSE",
			    (uint8_t *) &spec->ccb->csio.sense_data,
			    SSD_FULL_SIZE);
			istgt_lu_pass_print_sense_key((uint8_t *) &spec->ccb->csio.sense_data);
			istgt_lu_pass_parse_sense_key((uint8_t *) &spec->ccb->csio.sense_data,
			    &sk, &asc, &ascq);
			if (sk == ISTGT_SCSI_SENSE_ILLEGAL_REQUEST) {
				if (spec->inq_ver < SPC_VERSION_SPC3) {
					//ISTGT_WARNLOG("MODE SENSE was not supported\n");
					return 0;
				}
				if (asc == 0x20 && ascq == 0x00) {
					/* INVALID COMMAND OPERATION CODE */
					return 0;
				} else if (asc == 0x24 && ascq == 0x00) {
					/* INVALID FIELD IN CDB */
					return 0;
				}
			}
			if (sk == ISTGT_SCSI_SENSE_UNIT_ATTENTION) {
				if (asc == 0x28 && ascq == 0x00) {
					/* NOT READY TO READY CHANGE, MEDIUM MAY HAVE CHANGED */
					goto retry_sense10;
				}
				if (asc == 0x29 && ascq == 0x00) {
					/* POWER ON, RESET, OR BUS DEVICE RESET OCCURRED */
					goto retry_sense10;
				} else if (asc == 0x29 && ascq == 0x01) {
					/* POWER ON OCCURRED */
					goto retry_sense10;
				} else if (asc == 0x29 && ascq == 0x02) {
					/* SCSI BUS RESET OCCURRED */
					goto retry_sense10;
				} else if (asc == 0x29 && ascq == 0x03) {
					/* BUS DEVICE RESET FUNCTION OCCURRED */
					goto retry_sense10;
				} else if (asc == 0x29 && ascq == 0x04) {
					/* DEVICE INTERNAL RESET */
					goto retry_sense10;
				} else if (asc == 0x29 && ascq == 0x05) {
					/* TRANSCEIVER MODE CHANGED TO SINGLE-ENDED */
					goto retry_sense10;
				} else if (asc == 0x29 && ascq == 0x06) {
					/* TRANSCEIVER MODE CHANGED TO LVD */
					goto retry_sense10;
				} else if (asc == 0x29 && ascq == 0x07) {
					/* I_T NEXUS LOSS OCCURRED */
					goto retry_sense10;
				}
			}
			return -1;
		}
		data_len = spec->ccb->csio.dxfer_len;
		data_len -= spec->ccb->csio.resid;
		if (data_len < req_len) {
			ISTGT_ERRLOG("result is short\n");
			return -1;		
		}

		ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "MODE SENSE(10)", data, data_len);
		if (DGET16(&data[6]) != 0) { /* BLOCK DESCRIPTOR LENGTH */
			spec->ms_blockcnt = DGET64(&data[8+0]);
			spec->ms_blocklen = DGET32(&data[8+12]);
		}
	}

	return 0;
}

static int
istgt_lu_pass_set_capacity(ISTGT_LU_PASS *spec)
{
	uint8_t buf[MAX_TMPBUF];
	uint8_t cdb[16];
	uint32_t flags;
	uint8_t *data;
	int cdb_len;
	int data_len;
	int data_alloc_len;
	int req_len;
	int retry = 1;
	int sk, asc, ascq;
	int rc;

	memset(buf, 0, sizeof buf);
	memset(cdb, 0, sizeof cdb);
	data = buf;
	if (sizeof buf > 0xff) {
		data_alloc_len = 0xff;
	} else {
		data_alloc_len = sizeof buf;
	}

	/* issue READ CAPACITY (10) */
 retry_capacity10:
	memset(cdb, 0, sizeof cdb);
	data_alloc_len = 8;
	req_len = 8;
	if (spec->inq_pd == SPC_PERIPHERAL_DEVICE_TYPE_DISK) {
		cdb[0] = SBC_READ_CAPACITY_10;
		cdb_len = 10;
	} else if (spec->inq_pd == SPC_PERIPHERAL_DEVICE_TYPE_DVD) {
		cdb[0] = MMC_READ_CAPACITY;
		cdb_len = 10;
	} else {
		ISTGT_ERRLOG("unsupported device\n");
		return -1;
	}
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "CDB", cdb, cdb_len);

	memcpy(spec->ccb->csio.cdb_io.cdb_bytes, cdb, cdb_len);
	flags = CAM_DIR_IN;
	flags |= CAM_DEV_QFRZDIS;
	cam_fill_csio(&spec->ccb->csio, retry, NULL, flags, MSG_SIMPLE_Q_TAG,
	    data, data_alloc_len, SSD_FULL_SIZE, cdb_len,
	    spec->timeout);
	rc = cam_send_ccb(spec->cam_dev, spec->ccb);
	if (rc < 0) {
		ISTGT_ERRLOG("cam_send_ccb() failed\n");
		return -1;
	}

	if ((spec->ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "request error CAM=0x%x, SCSI=0x%x\n",
		    spec->ccb->ccb_h.status,
		    spec->ccb->csio.scsi_status);
		ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "SENSE",
		    (uint8_t *) &spec->ccb->csio.sense_data,
		    SSD_FULL_SIZE);
		istgt_lu_pass_print_sense_key((uint8_t *) &spec->ccb->csio.sense_data);
		istgt_lu_pass_parse_sense_key((uint8_t *) &spec->ccb->csio.sense_data,
		    &sk, &asc, &ascq);
		if (sk == ISTGT_SCSI_SENSE_NOT_READY) {
			if (asc == 0x04 && ascq == 0x01) {
				/* LOGICAL UNIT IS IN PROCESS OF BECOMING READY */
				sleep(2);
				goto retry_capacity10;
			}
			if (asc == 0x3a && ascq == 0x00) {
				/* MEDIUM NOT PRESENT */
				goto medium_not_present;
			} else if (asc == 0x3a && ascq == 0x01) {
				/* MEDIUM NOT PRESENT - TRAY CLOSED */
				goto medium_not_present;
			} else if (asc == 0x3a && ascq == 0x02) {
				/* MEDIUM NOT PRESENT - TRAY OPEN */
				goto medium_not_present;
			} else if (asc == 0x3a && ascq == 0x03) {
				/* MEDIUM NOT PRESENT - LOADABLE */
				goto medium_not_present;
			} else if (asc == 0x3a && ascq == 0x04) {
				/* MEDIUM NOT PRESENT - MEDIUM AUXILIARY MEMORY ACCESSIBLE */
				goto medium_not_present;
			}
			ISTGT_ERRLOG("device not ready\n");
			return -1;
		}
		if (sk == ISTGT_SCSI_SENSE_UNIT_ATTENTION) {
			if (asc == 0x28 && ascq == 0x00) {
				/* NOT READY TO READY CHANGE, MEDIUM MAY HAVE CHANGED */
				goto retry_capacity10;
			}
			if (asc == 0x29 && ascq == 0x00) {
				/* POWER ON, RESET, OR BUS DEVICE RESET OCCURRED */
				goto retry_capacity10;
			} else if (asc == 0x29 && ascq == 0x01) {
				/* POWER ON OCCURRED */
				goto retry_capacity10;
			} else if (asc == 0x29 && ascq == 0x02) {
				/* SCSI BUS RESET OCCURRED */
				goto retry_capacity10;
			} else if (asc == 0x29 && ascq == 0x03) {
				/* BUS DEVICE RESET FUNCTION OCCURRED */
				goto retry_capacity10;
			} else if (asc == 0x29 && ascq == 0x04) {
				/* DEVICE INTERNAL RESET */
				goto retry_capacity10;
			} else if (asc == 0x29 && ascq == 0x05) {
				/* TRANSCEIVER MODE CHANGED TO SINGLE-ENDED */
				goto retry_capacity10;
			} else if (asc == 0x29 && ascq == 0x06) {
				/* TRANSCEIVER MODE CHANGED TO LVD */
				goto retry_capacity10;
			} else if (asc == 0x29 && ascq == 0x07) {
				/* I_T NEXUS LOSS OCCURRED */
				goto retry_capacity10;
			}
		}
		return -1;
	}
	data_len = spec->ccb->csio.dxfer_len;
	data_len -= spec->ccb->csio.resid;
	if (data_len < req_len) {
		ISTGT_ERRLOG("result is short\n");
		return -1;		
	}

	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "READ CAPACITY(10)", data, data_len);
	spec->blockcnt = (uint64_t) DGET32(&data[0]); // last LBA
	spec->blocklen = (uint64_t) DGET32(&data[4]);

	if (spec->blockcnt == 0xffffffffU) {
	retry_capacity16:
		memset(cdb, 0, sizeof cdb);
		/* issue READ CAPACITY(16) */
		data_alloc_len = 32;
		req_len = 32;
		if (spec->inq_pd == SPC_PERIPHERAL_DEVICE_TYPE_DISK) {
			cdb[0] = SPC_SERVICE_ACTION_IN_16;
			/* SERVICE ACTION */
			BDSET8W(&cdb[1], SBC_SAI_READ_CAPACITY_16, 4, 5);
			/* ALLOCATION LENGTH */
			DSET16(&cdb[10], data_alloc_len);
			cdb_len = 16;
		} else if (spec->inq_pd == SPC_PERIPHERAL_DEVICE_TYPE_DVD) {
			ISTGT_ERRLOG("unsupported device\n");
			return -1;
		} else {
			ISTGT_ERRLOG("unsupported device\n");
			return -1;
		}
		ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "CDB", cdb, cdb_len);

		memcpy(spec->ccb->csio.cdb_io.cdb_bytes, cdb, cdb_len);
		flags = CAM_DIR_IN;
		flags |= CAM_DEV_QFRZDIS;
		cam_fill_csio(&spec->ccb->csio, retry, NULL, flags, MSG_SIMPLE_Q_TAG,
		    data, data_alloc_len, SSD_FULL_SIZE, cdb_len,
		    spec->timeout);
		rc = cam_send_ccb(spec->cam_dev, spec->ccb);
		if (rc < 0) {
			ISTGT_ERRLOG("cam_send_ccb() failed\n");
			return -1;
		}

		if ((spec->ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "request error CAM=0x%x, SCSI=0x%x\n",
			    spec->ccb->ccb_h.status,
			    spec->ccb->csio.scsi_status);
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "SENSE",
			    (uint8_t *) &spec->ccb->csio.sense_data,
			    SSD_FULL_SIZE);
			istgt_lu_pass_print_sense_key((uint8_t *) &spec->ccb->csio.sense_data);
			istgt_lu_pass_parse_sense_key((uint8_t *) &spec->ccb->csio.sense_data,
			    &sk, &asc, &ascq);
			if (sk == ISTGT_SCSI_SENSE_NOT_READY) {
				if (asc == 0x04 && ascq == 0x01) {
					/* LOGICAL UNIT IS IN PROCESS OF BECOMING READY */
					sleep(2);
					goto retry_capacity16;
				}
				if (asc == 0x3a && ascq == 0x00) {
					/* MEDIUM NOT PRESENT */
					goto medium_not_present;
				} else if (asc == 0x3a && ascq == 0x01) {
					/* MEDIUM NOT PRESENT - TRAY CLOSED */
					goto medium_not_present;
				} else if (asc == 0x3a && ascq == 0x02) {
					/* MEDIUM NOT PRESENT - TRAY OPEN */
					goto medium_not_present;
				} else if (asc == 0x3a && ascq == 0x03) {
					/* MEDIUM NOT PRESENT - LOADABLE */
					goto medium_not_present;
				} else if (asc == 0x3a && ascq == 0x04) {
					/* MEDIUM NOT PRESENT - MEDIUM AUXILIARY MEMORY ACCESSIBLE */
					goto medium_not_present;
				}
				ISTGT_ERRLOG("device not ready\n");
				return -1;
			}
			if (sk == ISTGT_SCSI_SENSE_UNIT_ATTENTION) {
				if (asc == 0x28 && ascq == 0x00) {
					/* NOT READY TO READY CHANGE, MEDIUM MAY HAVE CHANGED */
					goto retry_capacity16;
				}
				if (asc == 0x29 && ascq == 0x00) {
					/* POWER ON, RESET, OR BUS DEVICE RESET OCCURRED */
					goto retry_capacity16;
				} else if (asc == 0x29 && ascq == 0x01) {
					/* POWER ON OCCURRED */
					goto retry_capacity16;
				} else if (asc == 0x29 && ascq == 0x02) {
					/* SCSI BUS RESET OCCURRED */
					goto retry_capacity16;
				} else if (asc == 0x29 && ascq == 0x03) {
					/* BUS DEVICE RESET FUNCTION OCCURRED */
					goto retry_capacity16;
				} else if (asc == 0x29 && ascq == 0x04) {
					/* DEVICE INTERNAL RESET */
					goto retry_capacity16;
				} else if (asc == 0x29 && ascq == 0x05) {
					/* TRANSCEIVER MODE CHANGED TO SINGLE-ENDED */
					goto retry_capacity16;
				} else if (asc == 0x29 && ascq == 0x06) {
					/* TRANSCEIVER MODE CHANGED TO LVD */
					goto retry_capacity16;
				} else if (asc == 0x29 && ascq == 0x07) {
					/* I_T NEXUS LOSS OCCURRED */
					goto retry_capacity16;
				}
			}
			return -1;
		}
		data_len = spec->ccb->csio.dxfer_len;
		data_len -= spec->ccb->csio.resid;
		if (data_len < req_len) {
			ISTGT_ERRLOG("result is short\n");
			return -1;		
		}

		ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "READ CAPACITY(16)",
		    data, data_len);
		spec->blockcnt = DGET64(&data[0]); // last LBA
		spec->blocklen = (uint64_t) DGET32(&data[8]);
	}

	spec->blockcnt++;
	spec->size = spec->blockcnt * spec->blocklen;
	return 0;

 medium_not_present:
	spec->blockcnt = 0;
	spec->blocklen = 0;
	spec->size = 0;
	return 0;
}

int
istgt_lu_pass_init(ISTGT_Ptr istgt __attribute__((__unused__)), ISTGT_LU_Ptr lu)
{
	char buf[MAX_TMPBUF];
	ISTGT_LU_PASS *spec;
	uint64_t gb_size;
	uint64_t mb_size;
	int mb_digit;
	int flags;
	int rc;
	int pq, pd, rmb;
	int ver, fmt;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_pass_init\n");

	printf("LU%d PASS-THROUGH UNIT\n", lu->num);
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d TargetName=%s\n",
				   lu->num, lu->name);
	for (i = 0; i < lu->maxlun; i++) {
		if (lu->lun[i].type == ISTGT_LU_LUN_TYPE_NONE) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d none\n",
			    lu->num, i);
			lu->lun[i].spec = NULL;
			continue;
		}
		if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_DEVICE) {
			ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
			return -1;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d device\n",
		    lu->num, i);

		spec = xmalloc(sizeof *spec);
		memset(spec, 0, sizeof *spec);
		spec->lu = lu;
		spec->num = lu->num;
		spec->lun = i;

		spec->timeout = ISTGT_LU_CAM_TIMEOUT;
		spec->inq_standard = NULL;
		spec->inq_standard_len = 0;
		spec->inq_pd = 0;
		spec->inq_rmb = 0;
		spec->inq_ver = 0;

		spec->file = lu->lun[i].u.device.file;
		spec->size = 0;
		spec->blocklen = 0;
		spec->blockcnt = 0;

		printf("LU%d: LUN%d file=%s\n",
		    lu->num, i, spec->file);

		flags = lu->readonly ? O_RDONLY : O_RDWR;
		rc = cam_get_device(spec->file, buf, sizeof buf,
		    &spec->unit);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: LUN%d: cam_get_device() failed\n", lu->num, i);
			xfree(spec);
			return -1;
		}
		spec->device = xstrdup(buf);
		spec->cam_dev = cam_open_spec_device(spec->device, spec->unit,
		    flags, NULL);
		if (spec->cam_dev == NULL) {
			ISTGT_ERRLOG("LU%d: LUN%d: cam_open() failed\n", lu->num, i);
			xfree(spec->device);
			xfree(spec);
			return -1;
		}
		spec->ccb = cam_getccb(spec->cam_dev);
		if (spec->ccb == NULL) {
			ISTGT_ERRLOG("LU%d: LUN%d: cam_getccb() failed\n", lu->num, i);
			cam_close_spec_device(spec->cam_dev);
			xfree(spec->device);
			xfree(spec);
			return -1;
		}
		memset((uint8_t *) spec->ccb + sizeof(struct ccb_hdr), 0,
			   sizeof(struct ccb_scsiio) - sizeof(struct ccb_hdr));

		rc = istgt_lu_pass_set_inquiry(spec);
		if (rc < 0) {
			ISTGT_ERRLOG("LU%d: LUN%d: lu_pass_set_inquiry() failed\n",
			    lu->num, i);
		error_return:
			cam_freeccb(spec->ccb);
			cam_close_spec_device(spec->cam_dev);
			xfree(spec->device);
			xfree(spec);
			return -1;
		}

		/* PERIPHERAL QUALIFIER(7-5) PERIPHERAL DEVICE TYPE(4-0) */
		pq = BGET8W(&spec->inq_standard[0], 7, 3);
		pd = BGET8W(&spec->inq_standard[0], 4, 5);
		/* RMB(7) */
		rmb = BGET8W(&spec->inq_standard[1], 7, 1);
		/* VERSION ANSI(2-0) */
		ver = BGET8W(&spec->inq_standard[2], 2, 3);
		/* NORMACA(5) HISUP(4) RESPONSE DATA FORMAT(3-0) */
		fmt = BGET8W(&spec->inq_standard[3], 3, 4);

		printf("LU%d: LUN%d pq=0x%x, pd=0x%x, rmb=%d, ver=%d, fmt=%d\n",
			   lu->num, i,
			   pq, pd, rmb, ver, fmt);

		if (pq != 0x00) {
			ISTGT_ERRLOG("unsupported peripheral qualifier (%x)\n", pq);
			goto error_return;
		}

		switch (pd) {
		case SPC_PERIPHERAL_DEVICE_TYPE_DISK:
			printf("LU%d: LUN%d Direct access block device\n", lu->num, i);
			break;
		case SPC_PERIPHERAL_DEVICE_TYPE_TAPE:
			printf("LU%d: LUN%d Sequential-access device\n", lu->num, i);
			break;
		case SPC_PERIPHERAL_DEVICE_TYPE_DVD:
			printf("LU%d: LUN%d CD/DVD device\n", lu->num, i);
			break;
		case SPC_PERIPHERAL_DEVICE_TYPE_CHANGER:
			printf("LU%d: LUN%d Medium changer device\n", lu->num, i);
			break;
		default:
			ISTGT_ERRLOG("unsupported peripheral device type (%x)\n", pd);
			goto error_return;
		}

		switch (ver) {
		case SPC_VERSION_NONE:
			printf("LU%d: LUN%d version NONE\n", lu->num, i);
			break;
		case SPC_VERSION_SPC:
			printf("LU%d: LUN%d version SPC\n", lu->num, i);
			break;
		case SPC_VERSION_SPC2:
			printf("LU%d: LUN%d version SPC2\n", lu->num, i);
			break;
		case SPC_VERSION_SPC3:
			printf("LU%d: LUN%d version SPC3\n", lu->num, i);
			break;
		case SPC_VERSION_SPC4:
			printf("LU%d: LUN%d version SPC4\n", lu->num, i);
			break;
		case 0x01:
			printf("LU%d: LUN%d version SCSI1\n", lu->num, i);
			break;
		case 0x02:
			printf("LU%d: LUN%d version SCSI2\n", lu->num, i);
			break;
		default:
			ISTGT_ERRLOG("LU%d: LUN%d: unsupported version(%d)\n",
			    lu->num, i, ver);
			goto error_return;
		}
		switch (fmt) {
		case 0x00:
			printf("LU%d: LUN%d format SCSI1\n", lu->num, i);
			break;
		case 0x01:
			printf("LU%d: LUN%d format CCS\n", lu->num, i);
			break;
		case 0x02:
			printf("LU%d: LUN%d format SCSI2/SPC\n", lu->num, i);
			break;
		default:
			ISTGT_ERRLOG("LU%d: LUN%d: unsupported format(%d)\n",
			    lu->num, i, fmt);
			goto error_return;
		}

		spec->inq_pd = pd;
		spec->inq_rmb = rmb;
		spec->inq_ver = ver;
		spec->inq_fmt = fmt;

		if (pd != SPC_PERIPHERAL_DEVICE_TYPE_CHANGER) {
			rc = istgt_lu_pass_set_modesense(spec);
			if (rc < 0) {
#if 0
				ISTGT_ERRLOG("LU%d: LUN%d: lu_pass_set_modesense() failed\n",
				    lu->num, i);
				goto error_return;
#else
				spec->ms_blockcnt = 0;
				spec->ms_blocklen = 0;
#endif
			}
		} else {
			spec->ms_blockcnt = 0;
			spec->ms_blocklen = 0;
		}

		if (pd == SPC_PERIPHERAL_DEVICE_TYPE_TAPE
			|| pd == SPC_PERIPHERAL_DEVICE_TYPE_CHANGER) {
			spec->timeout *= 10;
		}
		if (pd == SPC_PERIPHERAL_DEVICE_TYPE_DISK
			|| pd == SPC_PERIPHERAL_DEVICE_TYPE_DVD) {
			rc = istgt_lu_pass_set_capacity(spec);
			if (rc < 0) {
				ISTGT_ERRLOG("LU%d: LUN%d: lu_pass_set_capacity() failed\n",
				    lu->num, i);
				goto error_return;
			}
		} else {
			spec->blockcnt = 0;
			spec->blocklen = 0;
			spec->size = 0;
		}
		if (spec->ms_blocklen == 0) {
			if (spec->blocklen == 0) {
				if (pd == SPC_PERIPHERAL_DEVICE_TYPE_DVD) {
					spec->ms_blocklen = 2048;
				} else {
					spec->ms_blocklen = 512;
				}
			} else {
				spec->ms_blocklen = spec->blocklen;
			}
		}

		if (pd != SPC_PERIPHERAL_DEVICE_TYPE_CHANGER) {
			printf("LU%d: LUN%d block descriptor\n", lu->num, i);
			printf("LU%d: LUN%d %"PRIu64" blocks, %"PRIu64" bytes/block\n",
			    lu->num, i, spec->ms_blockcnt, spec->ms_blocklen);

			if (spec->inq_rmb && spec->blockcnt == 0) {
				printf("LU%d: LUN%d medium not present\n", lu->num, i);
			} else {
				printf("LU%d: LUN%d medium capacity\n", lu->num, i);
				printf("LU%d: LUN%d %"PRIu64" blocks, %"PRIu64" bytes/block\n",
					   lu->num, i, spec->blockcnt, spec->blocklen);
				
				gb_size = spec->size / ISTGT_LU_1GB;
				mb_size = (spec->size % ISTGT_LU_1GB) / ISTGT_LU_1MB;
				if (gb_size > 0) {
					mb_digit = (int) (((mb_size * 100) / 1024) / 10);
					printf("LU%d: LUN%d %"PRIu64".%dGB\n",
					    lu->num, i, gb_size, mb_digit);
				} else {
					printf("LU%d: LUN%d %"PRIu64"MB\n",
					    lu->num, i, mb_size);
				}
			}
		}

		printf("LU%d: LUN%d %spass through for %s\n",
			   lu->num, i,
			   lu->readonly ? "readonly " : "", lu->name);

		lu->lun[i].spec = spec;
	}

	return 0;
}

int
istgt_lu_pass_shutdown(ISTGT_Ptr istgt __attribute__((__unused__)), ISTGT_LU_Ptr lu)
{
	ISTGT_LU_PASS *spec;
	int i;

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "istgt_lu_pass_shutdown\n");

	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d TargetName=%s\n",
				   lu->num, lu->name);
	for (i = 0; i < lu->maxlun; i++) {
		if (lu->lun[i].type == ISTGT_LU_LUN_TYPE_NONE) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "LU%d: LUN%d none\n",
			    lu->num, i);
			continue;
		}
		if (lu->lun[i].type != ISTGT_LU_LUN_TYPE_DEVICE) {
			ISTGT_ERRLOG("LU%d: unsupported type\n", lu->num);
			return -1;
		}
		spec = (ISTGT_LU_PASS *) lu->lun[i].spec;

		if (spec->ccb != NULL) {
			cam_freeccb(spec->ccb);
			spec->ccb = NULL;
		}
		if (spec->cam_dev != NULL) {
			cam_close_spec_device(spec->cam_dev);
			spec->cam_dev = NULL;
		}
		if (spec->device != NULL) {
			xfree(spec->device);
			spec->device = NULL;
		}
		xfree(spec);
		lu->lun[i].spec = NULL;
	}

	return 0;
}

static int
istgt_scsi_get_cdb_len(uint8_t *cdb)
{
	int group;
	int cdblen = 0;

	if (cdb == NULL)
		return 0;

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
	return cdblen;
}

static int
istgt_lu_pass_transfer_data(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd, uint8_t *buf, size_t bufsize, size_t len)
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
istgt_lu_pass_do_cam(ISTGT_LU_PASS *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd)
{
	uint32_t flags;
	uint8_t *cdb;
	uint8_t *data;
	int cdb_len;
	int data_len;
	uint8_t *sense_data;
	size_t *sense_len;
	size_t len;
	int R_bit, W_bit;
	int transfer_len;
	int retry = 1;
	int sk, asc, ascq;
	int rc;

	cdb = lu_cmd->cdb;
	data = lu_cmd->data;
	//data_alloc_len = lu_cmd->alloc_len;
	sense_data = lu_cmd->sense_data;
	sense_len = &lu_cmd->sense_data_len;
	*sense_len = 0;
	R_bit = lu_cmd->R_bit;
	W_bit = lu_cmd->W_bit;
	transfer_len = lu_cmd->transfer_len;

	cdb_len = istgt_scsi_get_cdb_len(cdb);
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "CDB", cdb, cdb_len);

	memcpy(spec->ccb->csio.cdb_io.cdb_bytes, cdb, cdb_len);
	flags = CAM_DIR_NONE;
	if (R_bit != 0) {
		flags = CAM_DIR_IN;
	} else if (W_bit != 0) {
		flags = CAM_DIR_OUT;
	}
	flags |= CAM_DEV_QFRZDIS;
	cam_fill_csio(&spec->ccb->csio, retry, NULL, flags, MSG_SIMPLE_Q_TAG,
	    data, transfer_len, SSD_FULL_SIZE, cdb_len,
	    spec->timeout);
	rc = cam_send_ccb(spec->cam_dev, spec->ccb);
	if (rc < 0) {
		ISTGT_ERRLOG("cam_send_ccb() failed\n");
		/* INTERNAL TARGET FAILURE */
		BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return -1;
	}

	if ((spec->ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
		    "request error CAM=0x%x, SCSI=0x%x\n",
		    spec->ccb->ccb_h.status,
		    spec->ccb->csio.scsi_status);
		ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "SENSE",
		    (uint8_t *) &spec->ccb->csio.sense_data,
		    SSD_FULL_SIZE);
		if ((spec->ccb->ccb_h.status & CAM_STATUS_MASK)
			== CAM_SCSI_STATUS_ERROR) {
			memcpy(sense_data + 2, &spec->ccb->csio.sense_data, SSD_FULL_SIZE);
			DSET16(&sense_data[0], SSD_FULL_SIZE);
			*sense_len = SSD_FULL_SIZE + 2;
			lu_cmd->status = spec->ccb->csio.scsi_status;
#if 0
			if (lu_cmd->status == 0) {
				/* INTERNAL TARGET FAILURE */
				BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			}
#endif
			/* adjust fixed format length */
			if (BGET8W(&sense_data[2+0], 6, 7) == 0x70
				|| BGET8W(&sense_data[2+0], 6, 7) == 0x71) {
				len = DGET8(&sense_data[2+7]);
				len += 8;
				if (len < SSD_FULL_SIZE) {
					*sense_len = len + 2;
					DSET16(&sense_data[0], len);
				}
			}
			istgt_lu_pass_print_sense_key(sense_data + 2);
			istgt_lu_pass_parse_sense_key(sense_data + 2,
			    &sk, &asc, &ascq);
		} else {
#if 0
			/* INTERNAL TARGET FAILURE */
			BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
#endif
			memcpy(sense_data + 2, &spec->ccb->csio.sense_data, SSD_FULL_SIZE);
			DSET16(&sense_data[0], SSD_FULL_SIZE);
			*sense_len = SSD_FULL_SIZE + 2;
			lu_cmd->status = spec->ccb->csio.scsi_status;
			/* adjust fixed format length */
			if (BGET8W(&sense_data[2+0], 6, 7) == 0x70
				|| BGET8W(&sense_data[2+0], 6, 7) == 0x71) {
				len = DGET8(&sense_data[2+7]);
				len += 8;
				if (len < SSD_FULL_SIZE) {
					*sense_len = len + 2;
					DSET16(&sense_data[0], len);
				}
			}
			istgt_lu_pass_print_sense_key(sense_data + 2);
			istgt_lu_pass_parse_sense_key(sense_data + 2,
			    &sk, &asc, &ascq);
		}
		return -1;
	}
	ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "dxfer=%d, resid=%d, sense=%d\n",
	    spec->ccb->csio.dxfer_len,
	    spec->ccb->csio.resid,
	    spec->ccb->csio.sense_resid);
	data_len = spec->ccb->csio.dxfer_len;
	data_len -= spec->ccb->csio.resid;

	if (R_bit != 0 || W_bit != 0) {
#if 0
		if (data_len > 256) {
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "DOCAM", data, 256);
		} else {
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "DOCAM", data, data_len);
		}
#endif
		lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
	} else {
		lu_cmd->data_len = 0;
	}

	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_pass_do_cam_seg(ISTGT_LU_PASS *spec, CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd)
{
	uint64_t llba;
	uint32_t lcnt;
	uint32_t flags;
	uint8_t fixcdb[16];
	uint8_t *cdb;
	uint8_t *data;
	int pad_len;
	int cdb_len;
	int data_len;
	int data_alloc_len;
	uint8_t *sense_data;
	size_t *sense_len;
	size_t len, cnt;
	int R_bit, W_bit;
	int transfer_len;
	int retry = 1;
	int offset;
	int seglen;
	int sk, asc, ascq;
	int rc;

	cdb = lu_cmd->cdb;
	data = lu_cmd->data;
	data_alloc_len = lu_cmd->alloc_len;
	sense_data = lu_cmd->sense_data;
	sense_len = &lu_cmd->sense_data_len;
	*sense_len = 0;
	R_bit = lu_cmd->R_bit;
	W_bit = lu_cmd->W_bit;
	transfer_len = lu_cmd->transfer_len;

	cdb_len = istgt_scsi_get_cdb_len(cdb);
	ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "CDB", cdb, cdb_len);

	memcpy(spec->ccb->csio.cdb_io.cdb_bytes, cdb, cdb_len);
	flags = CAM_DIR_NONE;
	if (R_bit != 0) {
		flags = CAM_DIR_IN;
	} else if (W_bit != 0) {
		flags = CAM_DIR_OUT;
	}
	flags |= CAM_DEV_QFRZDIS;

//#define MAX_SEGLEN (65536-4096)
#define MAX_SEGLEN (65536)
	pad_len = (int) ((uintptr_t) data & (4096 - 1));
	if (pad_len != 0) {
		pad_len = 4096 - pad_len;
		data += pad_len;
		data_alloc_len -= pad_len;
	}
	data_len = 0;
	seglen = MAX_SEGLEN;
	seglen -= MAX_SEGLEN % (int) spec->ms_blocklen;
	len = 0;
	for (offset = 0; offset < transfer_len; offset += seglen) {
		len = DMIN32(seglen, (transfer_len - offset));
		cnt = len / (int) spec->ms_blocklen;
		switch(cdb[0]) {
		case SBC_READ_6:
			memcpy(fixcdb, cdb, cdb_len);
			llba = (uint64_t) DGET16(&cdb[2]);
			lcnt = (uint32_t) DGET8(&cdb[4]);
			llba += offset / spec->ms_blocklen;
			lcnt = (uint64_t) cnt;
			DSET16(&fixcdb[2], (uint16_t) llba);
			DSET8(&fixcdb[4], (uint8_t) lcnt);
			memcpy(spec->ccb->csio.cdb_io.cdb_bytes, fixcdb, cdb_len);
			break;

		case SBC_READ_10:
			memcpy(fixcdb, cdb, cdb_len);
			llba = (uint64_t) DGET32(&cdb[2]);
			lcnt = (uint32_t) DGET16(&cdb[7]);
			llba += offset / spec->ms_blocklen;
			lcnt = (uint64_t) cnt;
			DSET32(&fixcdb[2], (uint32_t) llba);
			DSET16(&fixcdb[7], (uint16_t) lcnt);
			memcpy(spec->ccb->csio.cdb_io.cdb_bytes, fixcdb, cdb_len);
			break;

		case SBC_READ_12:
			memcpy(fixcdb, cdb, cdb_len);
			llba = (uint64_t) DGET32(&cdb[2]);
			lcnt = (uint32_t) DGET32(&cdb[6]);
			llba += offset / spec->ms_blocklen;
			lcnt = (uint64_t) cnt;
			DSET32(&fixcdb[2], (uint32_t) llba);
			DSET32(&fixcdb[6], (uint32_t) lcnt);
			memcpy(spec->ccb->csio.cdb_io.cdb_bytes, fixcdb, cdb_len);
			break;

		case SBC_READ_16:
			memcpy(fixcdb, cdb, cdb_len);
			llba = (uint64_t) DGET64(&cdb[2]);
			lcnt = (uint32_t) DGET32(&cdb[10]);
			llba += offset / spec->ms_blocklen;
			lcnt = (uint64_t) cnt;
			DSET64(&fixcdb[2], (uint64_t) llba);
			DSET32(&fixcdb[10], (uint32_t) lcnt);
			memcpy(spec->ccb->csio.cdb_io.cdb_bytes, fixcdb, cdb_len);
			break;

		case SBC_WRITE_6:
			memcpy(fixcdb, cdb, cdb_len);
			llba = (uint64_t) DGET16(&cdb[2]);
			lcnt = (uint32_t) DGET8(&cdb[4]);
			llba += offset / spec->ms_blocklen;
			lcnt = (uint64_t) cnt;
			DSET16(&fixcdb[2], (uint16_t) llba);
			DSET8(&fixcdb[4], (uint8_t) lcnt);
			memcpy(spec->ccb->csio.cdb_io.cdb_bytes, fixcdb, cdb_len);
			break;

		case SBC_WRITE_10:
		case SBC_WRITE_AND_VERIFY_10:
			memcpy(fixcdb, cdb, cdb_len);
			llba = (uint64_t) DGET32(&cdb[2]);
			lcnt = (uint32_t) DGET16(&cdb[7]);
			llba += offset / spec->ms_blocklen;
			lcnt = (uint64_t) cnt;
			DSET32(&fixcdb[2], (uint32_t) llba);
			DSET16(&fixcdb[7], (uint16_t) lcnt);
			memcpy(spec->ccb->csio.cdb_io.cdb_bytes, fixcdb, cdb_len);
			break;

		case SBC_WRITE_12:
		case SBC_WRITE_AND_VERIFY_12:
			memcpy(fixcdb, cdb, cdb_len);
			llba = (uint64_t) DGET32(&cdb[2]);
			lcnt = (uint32_t) DGET32(&cdb[6]);
			llba += offset / spec->ms_blocklen;
			lcnt = (uint64_t) cnt;
			DSET32(&fixcdb[2], (uint32_t) llba);
			DSET32(&fixcdb[6], (uint32_t) lcnt);
			memcpy(spec->ccb->csio.cdb_io.cdb_bytes, fixcdb, cdb_len);
			break;

		case SBC_WRITE_16:
		case SBC_WRITE_AND_VERIFY_16:
			memcpy(fixcdb, cdb, cdb_len);
			llba = (uint64_t) DGET64(&cdb[2]);
			lcnt = (uint32_t) DGET32(&cdb[10]);
			llba += offset / spec->ms_blocklen;
			lcnt = (uint64_t) cnt;
			DSET64(&fixcdb[2], (uint64_t) llba);
			DSET32(&fixcdb[10], (uint32_t) lcnt);
			memcpy(spec->ccb->csio.cdb_io.cdb_bytes, fixcdb, cdb_len);
			break;

		default:
			ISTGT_ERRLOG("unsupported OP=0x%x\n", cdb[0]);
			/* INTERNAL TARGET FAILURE */
			BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}

		cam_fill_csio(&spec->ccb->csio, retry, NULL, flags, MSG_SIMPLE_Q_TAG,
		    data + offset, len, SSD_FULL_SIZE, cdb_len,
		    spec->timeout);
		rc = cam_send_ccb(spec->cam_dev, spec->ccb);
		if (rc < 0) {
			ISTGT_ERRLOG("cam_send_ccb() failed\n");
			/* INTERNAL TARGET FAILURE */
			BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}

		if ((spec->ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP) {
			ISTGT_TRACELOG(ISTGT_TRACE_DEBUG,
			    "request error CAM=0x%x, SCSI=0x%x\n",
			    spec->ccb->ccb_h.status,
			    spec->ccb->csio.scsi_status);
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "SENSE",
			    (uint8_t *) &spec->ccb->csio.sense_data,
			    SSD_FULL_SIZE);
			if ((spec->ccb->ccb_h.status & CAM_STATUS_MASK)
			    == CAM_SCSI_STATUS_ERROR) {
				memcpy(sense_data + 2, &spec->ccb->csio.sense_data, SSD_FULL_SIZE);
				DSET16(&sense_data[0], SSD_FULL_SIZE);
				*sense_len = SSD_FULL_SIZE + 2;
				lu_cmd->status = spec->ccb->csio.scsi_status;
#if 0
				if (lu_cmd->status == 0) {
					/* INTERNAL TARGET FAILURE */
					BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
					lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				}
#endif
				/* adjust fixed format length */
				if (BGET8W(&sense_data[2+0], 6, 7) == 0x70
				    || BGET8W(&sense_data[2+0], 6, 7) == 0x71) {
					len = DGET8(&sense_data[2+7]);
					len += 8;
					if (len < SSD_FULL_SIZE) {
						*sense_len = len + 2;
						DSET16(&sense_data[0], len);
					}
				}
				istgt_lu_pass_print_sense_key(sense_data + 2);
				istgt_lu_pass_parse_sense_key(sense_data + 2,
				    &sk, &asc, &ascq);
			} else {
#if 0
				/* INTERNAL TARGET FAILURE */
				BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
#endif
				memcpy(sense_data + 2, &spec->ccb->csio.sense_data, SSD_FULL_SIZE);
				DSET16(&sense_data[0], SSD_FULL_SIZE);
				*sense_len = SSD_FULL_SIZE + 2;
				lu_cmd->status = spec->ccb->csio.scsi_status;
				/* adjust fixed format length */
				if (BGET8W(&sense_data[2+0], 6, 7) == 0x70
				    || BGET8W(&sense_data[2+0], 6, 7) == 0x71) {
					len = DGET8(&sense_data[2+7]);
					len += 8;
					if (len < SSD_FULL_SIZE) {
						*sense_len = len + 2;
						DSET16(&sense_data[0], len);
					}
				}
				istgt_lu_pass_print_sense_key(sense_data + 2);
				istgt_lu_pass_parse_sense_key(sense_data + 2,
				    &sk, &asc, &ascq);
			}
			return -1;
		}
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "dxfer=%d, resid=%d, sense=%d\n",
		    spec->ccb->csio.dxfer_len,
		    spec->ccb->csio.resid,
		    spec->ccb->csio.sense_resid);
		if (spec->ccb->csio.resid != 0) {
			/* INTERNAL TARGET FAILURE */
			BUILD_SENSE(HARDWARE_ERROR, 0x44, 0x00);
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		data_len += spec->ccb->csio.dxfer_len;
		data_len -= spec->ccb->csio.resid;
	}

	if (pad_len != 0) {
		memcpy(lu_cmd->data, lu_cmd->data + pad_len, data_len);
	}
	if (R_bit !=0 || W_bit != 0) {
#if 0
		if (data_len > 256) {
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "DOCAM", data, 256);
		} else {
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "DOCAM", data, data_len);
		}
#endif
		lu_cmd->data_len = DMIN32((size_t)data_len, lu_cmd->transfer_len);
	} else {
		lu_cmd->data_len = 0;
	}

	lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
	return 0;
}

static int
istgt_lu_pass_build_sense_data(ISTGT_LU_PASS *spec __attribute__((__unused__)), uint8_t *data, int sk, int asc, int ascq)
{
	int rc;

	rc = istgt_lu_scsi_build_sense_data(data, sk, asc, ascq);
	if (rc < 0) {
		return -1;
	}
	return rc;
}

int
istgt_lu_pass_reset(ISTGT_LU_Ptr lu, int lun)
{
	ISTGT_LU_PASS *spec;

	if (lun >= lu->maxlun) {
		return -1;
	}
	if (lu->lun[lun].type == ISTGT_LU_LUN_TYPE_NONE) {
		return -1;
	}
	spec = (ISTGT_LU_PASS *) lu->lun[lun].spec;

#if 0
	if (spec->lock) {
		ISTGT_TRACELOG(ISTGT_TRACE_DEBUG, "unlock by reset\n");
		spec->lock = 0;
	}
#endif

	return 0;
}

int
istgt_lu_pass_execute(CONN_Ptr conn, ISTGT_LU_CMD_Ptr lu_cmd)
{
	ISTGT_LU_Ptr lu;
	ISTGT_LU_PASS *spec;
	uint8_t *data;
	uint8_t *cdb;
	uint64_t fmt_lun;
	uint64_t lun;
	uint64_t method;
	uint32_t allocation_len;
	int data_len;
	int data_alloc_len;
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
#ifdef ISTGT_TRACE_PASS
		ISTGT_ERRLOG("LU%d: LUN%4.4"PRIx64" invalid\n",
		    lu->num, lun);
#endif /* ISTGT_TRACE_PASS */
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
	spec = (ISTGT_LU_PASS *) lu->lun[lun].spec;
	if (spec == NULL) {
		/* LOGICAL UNIT NOT SUPPORTED */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x25, 0x00);
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		return 0;
	}

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "SCSI OP=0x%x, LUN=0x%16.16"PRIx64"\n",
	    cdb[0], lu_cmd->lun);
#ifdef ISTGT_TRACE_PASS
	if (cdb[0] != SPC_TEST_UNIT_READY) {
		istgt_scsi_dump_cdb(cdb);
	}
#endif /* ISTGT_TRACE_DISK */

	if (lu_cmd->W_bit != 0) {
		transfer_len = lu_cmd->transfer_len;
		rc = istgt_lu_pass_transfer_data(conn, lu_cmd, lu_cmd->iobuf,
		    lu_cmd->iobufsize, transfer_len);
		if (rc < 0) {
			ISTGT_ERRLOG("lu_pass_transfer_data() failed\n");
			lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
			return -1;
		}
		lu_cmd->data = lu_cmd->iobuf;
		lu_cmd->alloc_len = lu_cmd->iobufsize;
	}

	switch (spec->inq_pd) {
	case SPC_PERIPHERAL_DEVICE_TYPE_DISK:
		switch (cdb[0]) {
		case SBC_READ_6:
		case SBC_READ_10:
		case SBC_READ_12:
		case SBC_READ_16:
		case SBC_WRITE_6:
		case SBC_WRITE_12:
		case SBC_WRITE_AND_VERIFY_12:
		case SBC_WRITE_10:
		case SBC_WRITE_AND_VERIFY_10:
		case SBC_WRITE_16:
		case SBC_WRITE_AND_VERIFY_16:
			lu_cmd->data = lu_cmd->iobuf;
			lu_cmd->alloc_len = lu_cmd->iobufsize;
			if (lu_cmd->transfer_len > lu_cmd->alloc_len) {
				ISTGT_ERRLOG("alloc_len(%zd) too small\n", lu_cmd->alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			rc = istgt_lu_pass_do_cam_seg(spec, conn, lu_cmd);
			if (rc < 0) {
				/* build by function */
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		default:
			rc = istgt_lu_pass_do_cam(spec, conn, lu_cmd);
			if (rc < 0) {
				/* build by function */
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}
		break;
	case SPC_PERIPHERAL_DEVICE_TYPE_TAPE:
		switch (cdb[0]) {
		default:
			rc = istgt_lu_pass_do_cam(spec, conn, lu_cmd);
			if (rc < 0) {
				/* build by function */
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}
		break;
	case SPC_PERIPHERAL_DEVICE_TYPE_DVD:
		switch (cdb[0]) {
		case MMC_READ_10:
		case MMC_READ_12:
		case MMC_WRITE_10:
		case MMC_WRITE_AND_VERIFY_10:
		case MMC_WRITE_12:
			lu_cmd->data = lu_cmd->iobuf;
			lu_cmd->alloc_len = lu_cmd->iobufsize;
			if (lu_cmd->transfer_len > lu_cmd->alloc_len) {
				ISTGT_ERRLOG("alloc_len(%zd) too small\n", lu_cmd->alloc_len);
				lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
				return -1;
			}
			rc = istgt_lu_pass_do_cam_seg(spec, conn, lu_cmd);
			if (rc < 0) {
				/* build by function */
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
#ifdef ISTGT_TRACE_PASS
		case MMC_GET_EVENT_STATUS_NOTIFICATION:
			rc = istgt_lu_pass_do_cam(spec, conn, lu_cmd);
			if (rc < 0) {
				/* build by function */
				break;
			}
			ISTGT_TRACEDUMP(ISTGT_TRACE_DEBUG, "EVENT",
			    lu_cmd->data, lu_cmd->data_len);
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
#endif /* ISTGT_TRACE_PASS */
		default:
			rc = istgt_lu_pass_do_cam(spec, conn, lu_cmd);
			if (rc < 0) {
				/* build by function */
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}
		break;
	case SPC_PERIPHERAL_DEVICE_TYPE_CHANGER:
		switch (cdb[0]) {
		default:
			rc = istgt_lu_pass_do_cam(spec, conn, lu_cmd);
			if (rc < 0) {
				/* build by function */
				break;
			}
			lu_cmd->status = ISTGT_SCSI_STATUS_GOOD;
			break;
		}
		break;
	default:
		ISTGT_ERRLOG("unsupported peripheral device type (%x)\n",
		    spec->inq_pd);
		/* LOGICAL UNIT NOT SUPPORTED */
		BUILD_SENSE(ILLEGAL_REQUEST, 0x25, 0x00);
		lu_cmd->data_len = 0;
		lu_cmd->status = ISTGT_SCSI_STATUS_CHECK_CONDITION;
		break;
	}

	ISTGT_TRACELOG(ISTGT_TRACE_SCSI,
	    "SCSI OP=0x%x, LUN=0x%16.16"PRIx64" status=0x%x,"
	    " complete\n",
	    cdb[0], lu_cmd->lun, lu_cmd->status);
	return 0;
}
#else /* HAVE_LIBCAM */
#include "istgt.h"
#include "istgt_ver.h"
#include "istgt_log.h"
#include "istgt_misc.h"
#include "istgt_lu.h"
#include "istgt_proto.h"
#include "istgt_scsi.h"

int
istgt_lu_pass_init(ISTGT_Ptr istgt __attribute__((__unused__)), ISTGT_LU_Ptr lu __attribute__((__unused__)))
{
	return 0;
}

int
istgt_lu_pass_shutdown(ISTGT_Ptr istgt __attribute__((__unused__)), ISTGT_LU_Ptr lu __attribute__((__unused__)))
{
	return 0;
}

int
istgt_lu_pass_reset(ISTGT_LU_Ptr lu __attribute__((__unused__)), int lun __attribute__((__unused__)))
{
	return 0;
}

int
istgt_lu_pass_execute(CONN_Ptr conn __attribute__((__unused__)), ISTGT_LU_CMD_Ptr lu_cmd __attribute__((__unused__)))
{
	ISTGT_TRACELOG(ISTGT_TRACE_SCSI, "unsupported unit\n");
	return -1;
}
#endif /* HAVE_LIBCAM */
