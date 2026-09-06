/*
 *
 *  Copyright (C) 2007 Mindspeed Technologies, Inc.
 *  Copyright 2014-2016 Freescale Semiconductor, Inc.
 *  Copyright 2017,2021 NXP
 *
 * SPDX-License-Identifier:    GPL-2.0+
 * The GPL-2.0+ license for this file can be found in the COPYING.GPL file
 * included with this distribution or at http://www.gnu.org/licenses/gpl-2.0.html
 *
 *
 */

#ifndef __CLIENT_DAEMON_H__
#define __CLIENT_DAEMON_H__

	static __inline unsigned short cmmDaemonCmdRC(void *rspbuf)
	{
	  return *( (unsigned short *) rspbuf);
	}

static inline void setbit_in_array(u_int8_t *pbits, u_int32_t bitindex, u_int32_t bitval)
{
	if (bitval)
		pbits[bitindex >> 3] |= 1 << (bitindex & 0x07);
	else
		pbits[bitindex >> 3] &= ~(1 << (bitindex & 0x07));
}

static inline u_int32_t testbit_in_array(u_int8_t *pbits, u_int32_t bitindex)
{
	u_int8_t x;
	u_int32_t bitmask;
	x = pbits[bitindex >> 3];
	bitmask = 1 << (bitindex & 0x07);
	return (x & bitmask);
}

#define ERRMSG_SOURCE_FPP		(0)
#define ERRMSG_SOURCE_CMMD		(1)

/* cmmClientProcessCmd()/cmmClient() return value that opts a subcommand into
 * process-exit-code propagation: cmm.c maps ONLY this to a nonzero exit. A
 * plain -1 (usage/help/other command errors) keeps the historical "cmm -c
 * always exits 0" behaviour, so exit-code reporting stays limited to the
 * commands that ask for it (qm-config and set qm). */
#define CMM_CLIENT_EXIT_FAIL		(2)

	int cmmClient(char * command, int argc, char **argv);
	int cmmSendToDaemon(daemon_handle_t daemon_handle, unsigned short commandCode, void * dataToSend, int dataSize, void* dataToRcv);

	struct cmm_daemon;

	char * getErrorString(unsigned short error);
	void showErrorMsg(char *commandCodeString, unsigned int source, char *rxBuffer);
	
	int cmmDaemonInit(struct cmm_daemon *ctx);
	void cmmDaemonExit(struct cmm_daemon *ctx);

	int parse_value(char *p, u_int32_t *value, u_int32_t maxval);
	int parse_range(char *p, u_int32_t *from, u_int32_t *to, u_int32_t maxval);

#endif

