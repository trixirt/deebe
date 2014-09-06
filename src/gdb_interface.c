/*
   This file is derrived from the gdbproxy project's gdbproxy.c
   The changes to this file are
   Copyright (C) 2012-2014 Juniper Networks, Inc

   The original copyright is

   Copyright (C) 1999-2001 Quality Quorum, Inc.
   Copyright (C) 2002 Chris Liechti and Steve Underwood
     2005 Martin Strubel (fixed pNN packet bug)

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

     1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     3. The name of the author may not be used to endorse or promote products
       derived from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
   EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
   OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
   OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   QQI can be contacted as qqi@world.std.com


   Main remote proxy unit.

   Exported Data:
     None

   Imported Data:
     None

   Static Data:

   Global Functions:

   Static Functions:
     rp_putpkt          - send packet to debugger
     rp_console_output  - send output to debugger console
     rp_data_output     - send data to debugger (used remcmd)
     rp_decode_xxxxx    - various decode functions
     rp_encode_xxxxx    - various encode functions
     rp_usage           - usage/help
     rp_write_xxxxx     - encode result of operation


   $Id: gdbproxy.c,v 1.12 2010/02/10 12:45:50 vapier Exp $ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#if defined(WIN32)
#include <windows.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "gdb_interface.h"
#include "network.h"
#include "global.h"
#include "util.h"
#include "target.h"

static void dbg_sock_putchar(int c)
{
	if (network_out_buffer_total < network_out_buffer_size) {
		network_out_buffer[network_out_buffer_total] =
			(uint8_t)(0xff & c);
		network_out_buffer_total++;
	} else {
		DBG_PRINT("gdb_interface : error out overflow\n");
	}
}
static uint16_t dbg_sock_readchar()
{
	/* Initialize to 0xffff so error is encoded in the high byte */
	uint16_t ret = 0xffff;
	if (network_in_buffer_current < network_in_buffer_total) {
		/* Assignment of single, valid byte clear the high error byte */
		ret = (uint16_t) network_in_buffer[network_in_buffer_current];
		network_in_buffer_current++;
	} else {
		DBG_PRINT("gdb_interface : error out underflow read %zu\n",
			  network_in_buffer_current);
	}
	return ret;
}
static size_t dbg_sock_write(unsigned char *b, size_t l)
{
	size_t ret = 0;
	if (l < network_out_buffer_size - network_out_buffer_total) {
		memcpy(&network_out_buffer[network_out_buffer_total], b, l);
		network_out_buffer_total += l;
		ret = l;
	}
	return ret;
}

/* Return values for readchar: either character
   code or one of the following*/
#define RP_VAL_MISCREADCHARRET_TMOUT (-2)
#define RP_VAL_MISCREADCHARRET_ERR   (-1)

static const char hex[] = "0123456789abcdef";
static char status_string[RP_PARAM_INOUTBUF_SIZE];
#define status_string_len sizeof(status_string)

/* Flag to catch unexpected output from target */
static int rp_target_out_valid = FALSE;

static void gdb_interface_log_local(int level, const char *fmt, ...)
{
	va_list args;

	/* Convert our log level values to system ones */
	switch (level) {
	case GDB_INTERFACE_LOGLEVEL_EMERG:
		DBG_PRINT("emergency: ");
		break;
	case GDB_INTERFACE_LOGLEVEL_ALERT:
		DBG_PRINT("alert:     ");
		break;
	case GDB_INTERFACE_LOGLEVEL_CRIT:
		DBG_PRINT("critical:  ");
		break;
	case GDB_INTERFACE_LOGLEVEL_ERR:
		DBG_PRINT("error:     ");
		break;
	case GDB_INTERFACE_LOGLEVEL_WARNING:
		DBG_PRINT("warning:   ");
		break;
	case GDB_INTERFACE_LOGLEVEL_NOTICE:
		DBG_PRINT("notice:    ");
		break;
	case GDB_INTERFACE_LOGLEVEL_INFO:
		DBG_PRINT("info:      ");
		break;
	case GDB_INTERFACE_LOGLEVEL_DEBUG:
		if (gdb_interface_debug_level < 1)
			return;
		DBG_PRINT("debug:     ");
		break;
	case GDB_INTERFACE_LOGLEVEL_DEBUG2:
		if (gdb_interface_debug_level < 2)
			return;
		DBG_PRINT("debug:     ");
		break;
	case GDB_INTERFACE_LOGLEVEL_DEBUG3:
		if (gdb_interface_debug_level < 3)
			return;
		DBG_PRINT("debug:     ");
		break;
	default:
		ASSERT(0);
		DBG_PRINT("debug:     ");
		break;
	}

	if (fp_log) {
		va_start(args, fmt);
		vfprintf (fp_log, fmt, args);
		va_end(args);
	}

	DBG_PRINT("\n");
}

/* Connection to debugger */
static void rp_console_output(const char *buf);
static void rp_data_output(const char *buf);

/* Decode/encode functions */
static int gdb_decode_reg(char *in, unsigned int *reg_no);

static int gdb_decode_reg_assignment(char *in,
				     unsigned int *reg_no,
				     unsigned char *out,
				     size_t out_size,
				     size_t *len);
static int gdb_decode_mem(char *in,
			  uint64_t *addr,
			  size_t *len);
static int rp_decode_process_query(const char *in,
				   unsigned int *mask,
				   gdb_thread_ref *ref);

static int rp_decode_list_query(const char *in,
				int *first,
				size_t *max,
				gdb_thread_ref *arg);
static int gdb_encode_regs(const unsigned char *data,
			   const unsigned char *avail,
			   size_t data_len,
			   char *out,
			   size_t out_size);
static int rp_encode_data(const unsigned char *data,
			  size_t data_len,
			  char *out,
			  size_t out_size);
static int rp_encode_process_query_response(unsigned int mask,
					    const gdb_thread_ref *ref,
					    const rp_thread_info *info,
					    char *out,
					    size_t out_size);
static int rp_encode_list_query_response(size_t count,
					 int done,
					 const gdb_thread_ref *arg,
					 const gdb_thread_ref *found,
					 char *out,
					 size_t out_size);
static int rp_decode_4bytes(const char *in, uint32_t *val);
static int rp_decode_8bytes(const char *in, uint64_t *val);
static int gdb_decode_uint32(char **in, uint32_t *val, char break_char);
static int gdb_decode_uint64(char **in, uint64_t *val, char break_char);
static int gdb_decode_int64(char const **in, int64_t *val, char break_char);
static void rp_encode_byte(unsigned int val, char *out);

/* Funcions to stuff output value */
static void gdb_interface_write_retval(int ret, char *buf);

static int extended_protocol;


/* Remote command */
#define RP_RCMD(name, hlp) {#name, rp_rcmd_##name, hlp}

/* Table entry definition */
typedef struct {
	/* command name */
	const char *name;
	/* command function */
	int (*function)(int, char **, out_func, data_func, gdb_target *);
	/* one line of help text */
	const char *help;
} RP_RCMD_TABLE;


static void gdb_interface_ack()
{
	int do_ack = 1;
	if (gdb_interface_target && gdb_interface_target->no_ack) {
		do_ack = gdb_interface_target->no_ack();
	}
	if (do_ack) {
		char *str = "+";
		dbg_sock_write((unsigned char *)str, strlen(str));
	}
}

static void gdb_interface_nak()
{
	int do_ack = 1;
	if (gdb_interface_target && gdb_interface_target->no_ack) {
		do_ack = gdb_interface_target->no_ack();
	}
	if (do_ack) {
		char *str = "-";
		dbg_sock_write((unsigned char *)str, strlen(str));
	}
}

/*
 * Send packet to debugger
 * For normal text packets, buf is null teminated and size = 0
 * For binary packets, size must be use
 */
static int gdb_interface_put_packet(const char *buf, size_t size)
{
	int i;
	int ret = 1;
	size_t len;
	uint8_t csum;
	uint8_t *d;
	const char *s;
	uint8_t buf2[RP_PARAM_INOUTBUF_SIZE + 4];

	ASSERT(buf != NULL);

	/* Copy the packet into buf2, encapsulate it, and give
	   it a checksum. */

	d = buf2;
	*d++ = '$';

	csum = 0;
	/* Normal text packet */
	if (size == 0) {
		for (s = buf, i = 0; *s && i < RP_PARAM_INOUTBUF_SIZE; i++) {
			csum += *s;
			*d++ = *s++;
		}
		ASSERT(*s == '\0');
	} else {
		/* Binary packet */
		for (s = buf, i = 0;
		     i < size && i < RP_PARAM_INOUTBUF_SIZE;
		     i++) {
			csum += *s;
			*d++ = *s++;
		}
	}

	/* Add the sumcheck to the end of the message */
	*d++ = '#';
	*d++ = hex[(csum >> 4) & 0xf];
	*d++ = hex[(csum & 0xf)];

	/* Do not null terminate binary transfers */
	if (0 == size) {
		*d = '\0';
	}

	/* Send it over and over until we get a positive ack. */
	len = d - buf2;

	gdb_interface_log(GDB_INTERFACE_LOGLEVEL_DEBUG2,
			  ": sending packet: %d bytes: %s...",
			  len,
			  buf2);

	ret = dbg_sock_write(buf2, len);
	if (ret == 0) {
		/* Something went wrong */
		gdb_interface_log(GDB_INTERFACE_LOGLEVEL_DEBUG,
				  ": write failed");
	} else {
		ret = 0;
	}

	return ret;
}

void dbg_ack_packet_received(bool seq_valid, char *seq)
{
	/* Acknowledge this good packet */
	dbg_sock_putchar('+');
	if (seq_valid) {
		dbg_sock_putchar(seq[0]);
		dbg_sock_putchar(seq[1]);
	}
}

#define STATE_INIT               0
#define STATE_CMD                4
#define STATE_TEXT               5
#define STATE_BINARY_RAW         6
#define STATE_PRE_BINARY_ENCODED 7
#define STATE_BINARY_ENCODED     8
#define STATE_HASHMARK           9
#define STATE_CSUM               10


/* Read a packet from the remote machine, with error checking,
   and store it in buf. */
static int gdb_interface_getpacket(char *buf, size_t buf_len,
				   size_t *len, bool ret_ack)
{
	int ret = -1;
	char seq[2];
	bool seq_valid = false;
	unsigned char rx_csum;
	unsigned char calc_csum;
	int nib;
	size_t pkt_len;
	bool esc_found = false;
	int state;

	ASSERT(buf != NULL);
	ASSERT(buf_len > 6);
	ASSERT(len != NULL);

	seq[0] = 0;
	seq[1] = 0;
	seq_valid = false;
	rx_csum = 0;
	calc_csum = 0;
	pkt_len = 0;
	state = STATE_INIT;
	esc_found = false;

	for (;;) {
		uint16_t sc = dbg_sock_readchar();
		/* Check for underflow */
		if (!(sc & 0xff00)) {
			uint8_t c = (uint8_t) sc;

			if (c == '$'  &&  state != STATE_INIT) {
				/*
				 * Unexpected start of packet marker
				 * in mid-packet.
				 */
				gdb_interface_log(
					GDB_INTERFACE_LOGLEVEL_DEBUG,
					": unexpected new packet");
				seq[0] = 0;
				seq[1] = 0;
				seq_valid = false;
				rx_csum = 0;
				calc_csum = 0;
				pkt_len = 0;
				state = 1;
			}

			if (state == STATE_INIT) {

				/* Waiting for a start of packet marker */
				if (c == '$') {
					/* Start of packet */
					seq[0] = 0;
					seq[1] = 0;
					seq_valid = false;
					rx_csum = 0;
					calc_csum = 0;
					pkt_len = 0;
					state = 1;
				} else if (c == '\3') {

					/* A control C */
					gdb_interface_log(
						GDB_INTERFACE_LOGLEVEL_DEBUG,
						": Control-C received");
					ret = '\3';
					break;
				} else if (c == '+') {
					/* An ACK to one of our packets */
					/*
					 * We don't use sequence numbers,
					 * so we shouldn't expect a
					 * sequence number after this
					 * character.
					 */
					gdb_interface_log(
						GDB_INTERFACE_LOGLEVEL_DEBUG2,
						": ACK received");
					ret = ACK;
					break;
				} else if (c == '-') {
					/* A NAK to one of our packets */
					/*
					 * We don't use sequence numbers,
					 * so we shouldn't expect a
					 * sequence number after this
					 character.
					*/
					gdb_interface_log(
						GDB_INTERFACE_LOGLEVEL_DEBUG2,
						": NAK received");
					ret = NAK;
					break;
				} else {
					gdb_interface_log(
						GDB_INTERFACE_LOGLEVEL_DEBUG,
						": we got junk - 0x%X",
						c & 0xFF);
				}
			} else if ((state == 1) ||
				   (state == 2)) {
				/*
				 * We might be in the two character
				 * sequence number preceeding a ':'.
				 * Then again, we might not!
				 */
				if (c == '#') {
					state = STATE_HASHMARK;
				} else {
					buf[pkt_len++] = c;
					rx_csum += c;
					state++;
				}
			} else if (state == 3) {

				if (c == '#') {
					state = STATE_HASHMARK;
				} else {
					if (c == ':') {
						/*
						 * A ':' at this position
						 * means the previous 2
						 * characters form a sequence
						 * number for the packet.
						 * This must be saved,
						 * and used when
						 * ack'ing the packet
						 */
						seq[0] = buf[0];
						seq[1] = buf[1];
						seq_valid = true;
						pkt_len = 0;
					} else {
						buf[pkt_len++] = c;
						rx_csum += c;
					}
					state = STATE_CMD;
				}
			} else if (state == STATE_CMD) {
				if (c == '#') {
					state = STATE_HASHMARK;
				} else {
					buf[pkt_len++] = c;
					rx_csum += c;
					if (buf[0] == 'X') {
						/*
						 * Special case: binary data.
						 * Format X<addr>,<len>:<data>.
						 * Note: we have not reached
						 * the ':' yet.
						 *
						 * Translate this packet, so
						 * it looks like a non-binary
						 * format memory write command.
						 */
						buf[0] = 'M';
						esc_found = false;
						/* Have to save extra space */
						buf_len--;
						state =	STATE_PRE_BINARY_ENCODED;
					} else if (buf[0] == 'v') {
						/*
						 * This case can have binary
						 * data as part of a
						 * file write. Go directly
						 * to binary data state
						 */
						state = STATE_BINARY_RAW;
					} else {
						state = STATE_TEXT;
					}
				}
			} else if (state == STATE_TEXT) {
				/* Normal, non-binary mode */
				if (c == '#') {
					state = STATE_HASHMARK;
				} else {
					if (pkt_len >= buf_len) {
						gdb_interface_log(GDB_INTERFACE_LOGLEVEL_DEBUG,
								  ": received excessive length packet");
						break;
					}
					buf[pkt_len++] = c;
					rx_csum += c;
				}
			} else if (state == STATE_BINARY_RAW) {
				if (pkt_len >= buf_len) {
					gdb_interface_log(GDB_INTERFACE_LOGLEVEL_DEBUG,
							  ": received a packet that is too long");
					break;
				}
				if (esc_found) {
					rx_csum += c;
					esc_found = false;
					c |= 0x20;
					buf[pkt_len++] = c;
					continue;
				}

				if (c == 0x7D) {
					rx_csum += c;
					esc_found = true;
					continue;
				} else if (c == '#') {
					/* Unescaped '#' means end of packet */
					state = STATE_HASHMARK;
				} else {
					rx_csum += c;
					buf[pkt_len++] = c;
				}
			} else if (state == STATE_PRE_BINARY_ENCODED) {
				/* Escaped binary data mode - pre ':' */
				buf[pkt_len++] = c;
				rx_csum += c;
				if (c == ':') {
					/*
					 * From now on the packet will
					 * be in escaped binary.
					 */
					state = STATE_BINARY_ENCODED;
				}
			} else if (state == STATE_BINARY_ENCODED) {
				/* Escaped binary data mode - post ':' */
				if (pkt_len >= buf_len) {
					gdb_interface_log(GDB_INTERFACE_LOGLEVEL_DEBUG,
							  ": received a packet that is too long");
					break;
				}
				if (esc_found) {
					rx_csum += c;
					esc_found = false;
					c ^= 0x20;
					buf[pkt_len++] = hex[(c >> 4) & 0xf];
					buf[pkt_len++] = hex[c & 0xf];
					continue;
				}

				if (c == 0x7D) {
					rx_csum += c;
					esc_found = true;
					continue;
				} else if (c == '#') {
					/* Unescaped '#' means end of packet */
					state = STATE_HASHMARK;
				} else {
					rx_csum += c;
					buf[pkt_len++] = hex[(c >> 4) & 0xf];
					buf[pkt_len++] = hex[c & 0xf];
				}
			} else if (state == STATE_HASHMARK) {
				/*
				 * Now get the first byte of the two
				 * byte checksum
				 */
				nib = rp_hex_nibble(c);
				if (nib < 0) {
					gdb_interface_log(GDB_INTERFACE_LOGLEVEL_DEBUG,
							  ": bad checksum character %c",
							  c);
					state = STATE_INIT;
					break;
				}
				calc_csum = (calc_csum << 4) | nib;
				state = STATE_CSUM;
			} else if (state == STATE_CSUM) {
				/* Now get the second byte of the checksum, and
				   check it. */
				nib = rp_hex_nibble(c);
				if (nib < 0) {
					gdb_interface_log(GDB_INTERFACE_LOGLEVEL_DEBUG,
							  ": bad checksum character %c",
							  c);
					state = STATE_INIT;
					break;
				}
				calc_csum = (calc_csum << 4) | nib;
				if (rx_csum == calc_csum) {
					buf[pkt_len] = '\0';
					*len = pkt_len;

					/*
					 * Normally, we want to ack
					 * But in 'quick' mode, all the
					 * packets but ^C are dropped.
					 */
					if (ret_ack)
						dbg_ack_packet_received(seq_valid, seq);

					gdb_interface_log(GDB_INTERFACE_LOGLEVEL_DEBUG2, ": packet received: %s", buf);
					ret = 0;
					break;
				}
				gdb_interface_log(GDB_INTERFACE_LOGLEVEL_DEBUG,
						  ": bad checksum calculated=0x%x received=0x%x",
						  rx_csum,
						  calc_csum);
				state = STATE_INIT;
				break;
			} else {
				/* Unreachable */
				DBG_PRINT("gdb_interface : error scanner state\n");
				break;
			}

		} else {
			/* Failure */
			DBG_PRINT("gdb_interface : error in underflow\n");
			break;
		}
	}
	return ret;
}

void handle_search_memory_command(char *in_buf,
				  int in_len,
				  char *out_buf,
				  int out_buf_len,
				  gdb_target *t)
{
	uint64_t addr;
	uint32_t pattern;
	uint32_t mask;
	char *in;

	/* Format: taddr:PP,MM
	   Search backwards starting at address addr for a match with the
	   supplied pattern PP and mask MM. PP and MM are 4 bytes. addr
	   must be at least 3 digits. */

	in = &in_buf[1];
	if (!gdb_decode_uint64(&in, &addr, ':')) {
		gdb_interface_write_retval(RET_ERR, out_buf);
		return;
	}
	if (!gdb_decode_uint32(&in, &pattern, ',')) {
		gdb_interface_write_retval(RET_ERR, out_buf);
		return;
	}
	if (!gdb_decode_uint32(&in, &mask, '\0')) {
		gdb_interface_write_retval(RET_ERR, out_buf);
		return;
	}
	gdb_interface_write_retval(RET_NOSUPP, out_buf);
}

static int _decode_thread_id(const char *in_buf, int64_t *process_id, int64_t *thread_id) {
	int ret = 0; /* assume ok */
	const char *in;
	*process_id = 0; /* Any process */
	*thread_id  = 0; /* Any thread */
	/* Check for 'p' for input in the form 'p<pid>.<tid>' */
	if (in_buf[0] == 'p') {
		in = &in_buf[1];
		if (!gdb_decode_int64(&in, process_id, '.')) {
			ret = 1;
		} else {
			if (!gdb_decode_int64(&in, thread_id, '\0')) {
				ret = 1;
			}
		}
	} else {
		in = &in_buf[0];
		if (!gdb_decode_int64(&in, process_id, '\0')) {
			ret = 1;
		}
	}
	return ret;
}

void handle_thread_commands(char * const in_buf,
			    int in_len,
			    char *out_buf,
			    int out_buf_len,
			    gdb_target *target)
{
	int ret;
	if (in_len == 1) {
		/* Either short or an obsolete form */
		return;
	}
	if ((in_buf[1] == 'c') ||
	    (in_buf[1] == 'g')) {
		int cmd_type = cmd_type = in_buf[1];
		int64_t p, t;
		if (_decode_thread_id(&in_buf[2], &p, &t)) {
			gdb_interface_write_retval(RET_ERR, out_buf);		
		} else {
			/* Thread is ignored for now */
			if (cmd_type == 'c') {
				ret = target->set_ctrl_thread(p, t);
			} else { /* 'g' */
				ret = target->set_gen_thread(p, t);
			}
			gdb_interface_write_retval(ret, out_buf);
		}
	} else {
		gdb_interface_write_retval(RET_ERR, out_buf);
		gdb_interface_log(GDB_INTERFACE_LOGLEVEL_ERR,
				  ": Bad H command");
	}
}


void handle_query_current_signal(char *out_buf, int out_buf_len, gdb_target *t)
{
	if (t && t->query_current_signal) {
		int s = 0;
		int ret;
		ret = t->query_current_signal(&s);
		if (RET_OK == ret) {
			uint8_t v = 0xff & s;
			sprintf(&out_buf[0], "S%2.2x", v);
		} else {
			gdb_interface_write_retval(RET_NOSUPP, out_buf);
		}
	} else {
		gdb_interface_write_retval(RET_NOSUPP, out_buf);
	}
}

void handle_read_registers_command(char * const in_buf,
				   int in_len,
				   char *out_buf,
				   int out_buf_len,
				   gdb_target *t)
{
	int ret;
	size_t len;
	unsigned char data_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];
	unsigned char avail_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];

	/* Get all registers. Format: 'g'. Note we do not do any
	   data caching - all caching is done by the debugger */
	ret = t->read_registers(CURRENT_PROCESS_TID,
				data_buf,
				avail_buf,
				sizeof(data_buf),
				&len);
	switch (ret) {
	case RET_OK:
		ASSERT(len <= GDB_INTERFACE_PARAM_DATABYTES_MAX);
		gdb_encode_regs(data_buf,
				avail_buf,
				len,
				out_buf,
				out_buf_len);
		break;
	case RET_ERR:
	case RET_NOSUPP:
		gdb_interface_write_retval(RET_ERR, out_buf);
		/* This should not happen */
		ASSERT(0);
		break;
	}
}

/* Decode a single nibble */
static bool gdb_decode_nibble(const char *in, uint8_t *nibble)
{
	bool ret = false;
	int nib;

	nib = rp_hex_nibble(*in);
	if (nib >= 0) {
		*nibble = nib;
		ret = true;
	}

	return ret;
}

/* Decode byte */
static bool gdb_decode_byte(const char *in, uint8_t *byte_ptr)
{
	bool ret = false;

	uint8_t ls_nibble;
	uint8_t ms_nibble;

	if (gdb_decode_nibble(in, &ms_nibble)) {
		if (gdb_decode_nibble(in + 1, &ls_nibble)) {
			*byte_ptr = (ms_nibble << 4) + ls_nibble;
			ret = true;
		}
	}
	return  ret;
}

/* Convert stream of chars into data */
static int gdb_decode_data(const char *in,
			   unsigned char *out,
			   size_t out_size,
			   size_t *len)
{
	size_t count;
	uint8_t bytex;

	ASSERT(in != NULL);
	ASSERT(out != NULL);
	ASSERT(out_size > 0);
	ASSERT(len != NULL);

	for (count = 0;  *in  &&  count < out_size;  count++, in += 2, out++) {
		if (*(in + 1) == '\0') {
			/* Odd number of nibbles. Discard the last one */
			gdb_interface_log(GDB_INTERFACE_LOGLEVEL_WARNING,
					  ": odd number of nibbles");
			if (count == 0)
				return  FALSE;
			*len = count;
			return  TRUE;
		}

		if (!gdb_decode_byte(in, &bytex))
			return  FALSE;

		*out = bytex & 0xff;
	}

	if (*in) {
		/* Input too long */
		return  FALSE;
	}

	*len = count;

	return  TRUE;
}


void handle_write_registers_command(char * const in_buf,
				    int in_len,
				    char *out_buf,
				    int out_buf_len,
				    gdb_target *t)
{
	int ret;
	size_t len;
	unsigned char data_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];

	/* Write all registers. Format: 'GXXXXXXXXXX' */
	ret = gdb_decode_data(&in_buf[1], data_buf, sizeof(data_buf), &len);
	if (!ret) {
		gdb_interface_write_retval(RET_ERR, out_buf);
		return;
	}

	ret = t->write_registers(CURRENT_PROCESS_TID, data_buf, len);
	gdb_interface_write_retval(ret, out_buf);
}

void handle_read_single_register_command(char * const in_buf,
					 int in_len,
					 char *out_buf,
					 int out_buf_len,
					 gdb_target *t)
{
	int ret;
	unsigned int reg_no;
	size_t len;
	unsigned char data_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];
	unsigned char avail_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];

	/* Get a single register. Format 'pNN' */
	ret = gdb_decode_reg(&in_buf[1], &reg_no);
	if (!ret) {
		gdb_interface_write_retval(RET_ERR, out_buf);
		return;
	}

	ret = t->read_single_register(CURRENT_PROCESS_TID,
				      reg_no,
				      data_buf,
				      avail_buf,
				      sizeof(data_buf),
				      &len);
	switch (ret) {
	case RET_OK:
		ASSERT(len <= GDB_INTERFACE_PARAM_DATABYTES_MAX);
		gdb_encode_regs(data_buf,
				avail_buf,
				len,
				out_buf,
				out_buf_len);
		break;
	case RET_ERR:
		gdb_interface_write_retval(RET_ERR, out_buf);
		break;
		/* handle targets non supporting single register read */
	case RET_NOSUPP:
		break;
	default:
		/* This should not happen */
		ASSERT(0);
		break;
	}
}

void handle_write_single_register_command(char * const in_buf,
					  int in_len,
					  char *out_buf,
					  int out_buf_len,
					  gdb_target *t)
{
	int ret;
	unsigned int reg_no;
	size_t len;
	unsigned char data_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];

	/* Write a single register. Format: 'PNN=XXXXX' */
	ret = gdb_decode_reg_assignment(&in_buf[1],
					&reg_no,
					data_buf,
					sizeof(data_buf),
					&len);
	if (!ret) {
		gdb_interface_write_retval(RET_ERR, out_buf);
		return;
	}
	ASSERT(len < GDB_INTERFACE_PARAM_DATABYTES_MAX);

	ret = t->write_single_register(CURRENT_PROCESS_TID, reg_no, data_buf, len);
	gdb_interface_write_retval(ret, out_buf);
}

void handle_read_memory_command(char * const in_buf,
				int in_len,
				char *out_buf,
				int out_buf_len,
				gdb_target *t)
{
	int ret;
	size_t len, read_len;
	uint64_t addr;
	unsigned char data_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];

	/* Read memory format: 'mAA..A,LL..LL' */
	ret = gdb_decode_mem(&in_buf[1], &addr, &len);
	if (!ret) {
		gdb_interface_write_retval(RET_ERR, out_buf);
		return;
	}

	/* Limit it so buggy gdbs will not complain */
	if (len > ((RP_VAL_DBG_PBUFSIZ - 32)/2))
		len = (RP_VAL_DBG_PBUFSIZ - 32)/2;

	ret = t->read_mem(CURRENT_PROCESS_TID, addr, data_buf, len, &read_len);
	switch (ret) {
	case RET_OK:
		ASSERT(len <= GDB_INTERFACE_PARAM_DATABYTES_MAX);
		rp_encode_data(data_buf, len, out_buf, out_buf_len);
		break;
	case RET_ERR:
		if (cmdline_silence_memory_read_errors) {
			gdb_interface_log(GDB_INTERFACE_LOGLEVEL_WARNING,
					  " : silencing memory read error\n");
			memset(data_buf, 0, len);
			rp_encode_data(data_buf, len, out_buf, out_buf_len);
		} else {
			gdb_interface_write_retval(RET_ERR, out_buf);
		}
		break;
	default:
		/* This should not happen */
		ASSERT(0);
		break;
	}
}

void handle_write_memory_command(char * const in_buf,
				 int in_len,
				 char *out_buf,
				 int out_buf_len,
				 gdb_target *t)
{
	int ret;
	char *cp;
	size_t len;
	size_t len1;
	uint64_t addr;
	unsigned char data_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];

	/* Write memory format: 'mAA..A,LL..LL:XX..XX' */
	cp = strchr(&in_buf[1], ':');
	if (cp == NULL) {
		gdb_interface_write_retval(RET_ERR, out_buf);
		return;
	}
	*cp = '\0';

	ret = gdb_decode_mem(&in_buf[1], &addr, &len);
	if (!ret  ||  len > GDB_INTERFACE_PARAM_DATABYTES_MAX) {
		gdb_interface_write_retval(RET_ERR, out_buf);
		return;
	}

	ret = gdb_decode_data(cp + 1, data_buf, sizeof(data_buf), &len1);
	if (!ret  ||  len != len1) {
		gdb_interface_write_retval(RET_ERR, out_buf);
		return;
	}

	ret = t->write_mem(CURRENT_PROCESS_TID, addr, data_buf, len);
	gdb_interface_write_retval(ret, out_buf);
}



void handle_running_commands(char * const in_buf,
			     int in_len,
			     char *out_buf,
			     int out_buf_len,
			     gdb_target *t)
{
	int step;
	uint32_t sig;
	int go;
	int more;
	int implemented;
	char *addr_ptr;
	uint64_t addr;
	int ret;
	char *in;

	/* 'w' go from address
	 * 'W' go from address with signal
	 * 's' step from address
	 * 'S' step from address with signal
	 * 'c' continue from address
	 * 'C' continue from address with signal
	 */

	step = (in_buf[0] == 'S'  ||  in_buf[0] == 's');
	go = (in_buf[0] == 'W'  ||  in_buf[0] == 'w');

	addr_ptr = NULL;

	if (in_buf[0] == 'C'  ||  in_buf[0] == 'S'  ||  in_buf[0] == 'W') {
		/*
		 * Resume with signal.
		 * Format Csig[;AA..AA], Ssig[;AA..AA], or Wsig[;AA..AA]
		 */

		in = &in_buf[1];
		if (strchr(in, ';')) {
			if (!gdb_decode_uint32(&in, &sig, ';'))	{
				gdb_interface_write_retval(RET_ERR, out_buf);
				return;
			}
			addr_ptr = in;
		} else {
			if (!gdb_decode_uint32(&in, &sig, '\0')) {
				gdb_interface_write_retval(RET_ERR, out_buf);
				return;
			}
		}
	} else {
		sig = RP_VAL_TARGETSIG_0;
		if (in_buf[1] != '\0')
			addr_ptr = &in_buf[1];
	}

	if (go) {
		ret = t->go_waiting(sig);
	} else if (addr_ptr) {
		if (!gdb_decode_uint64(&addr_ptr, &addr, '\0'))	{
			gdb_interface_write_retval(RET_ERR, out_buf);
			return;
		} /* XXX */
		ret = t->resume_from_addr(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID, step, sig, addr);
	} else { /* XXX */
	    ret = t->resume_from_current(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID, step, sig);
	}

	if (ret != RET_OK) {
		gdb_interface_write_retval(ret, out_buf);
		return;
	}

	/* Try a partial wait first */
	ret = t->wait_partial(TRUE,
			      status_string,
			      status_string_len,
			      &implemented,
			      &more);
	if (ret != RET_OK) {
		gdb_interface_write_retval(ret, out_buf);
		return;
	}
	if (!implemented) {
		/* There is no pertial wait facility for this target, so use a
		   blocking wait */
		if (t->wait) {
			ret = t->wait(status_string,
				      status_string_len, step);
		} else {
			ret = RET_NOSUPP;
		}

		if (ret == RET_OK) {
			/* Cast to size_t to make compiler happy */
			ASSERT(strlen(status_string) <
			       (size_t)status_string_len);
			strcpy(out_buf, status_string);
		} else {
			gdb_interface_write_retval(ret, out_buf);
		}
		return;
	}
	if (!more) {
		/* We are done. The program has already stopped */
		/* Cast to size_t to make compiler happy */
		ASSERT(strlen(status_string) < (size_t) status_string_len);
		strcpy(out_buf, status_string);
	}
}

int handle_kill_command(char * const in_buf,
			int in_len,
			char *out_buf,
			int out_buf_len,
			gdb_target *t)
{
	int ret;

	t->kill(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID);

	if (!extended_protocol)	{
		if (cmdline_once) {
			/*
			 * If the current target cannot restart,
			 * we have little choice but
			 * to exit right now.
			 */
			gdb_interface_log(GDB_INTERFACE_LOGLEVEL_INFO,
					  ": session killed. Exiting");
		} else {
			gdb_interface_log(GDB_INTERFACE_LOGLEVEL_INFO,
					  ": session killed. Will wait for a new connection");
		}
		return  FALSE;
	}

	gdb_interface_log(GDB_INTERFACE_LOGLEVEL_INFO,
			  ": remote proxy restarting");

	/* Let us do our best while starting system */
	if (cmdline_once) {
		/*
		 * Even if restart is not supported it is
		 * still worth calling connect
		 */
		return -1;
	}

	ret = t->restart();

	ASSERT(ret != RET_NOSUPP);

	if (ret != RET_OK) {
		/* There is no point in continuing */
		gdb_interface_log(GDB_INTERFACE_LOGLEVEL_ERR,
				  ": unable to restart target %s",
				  t->name);
		gdb_interface_write_retval(RET_ERR, out_buf);
		gdb_interface_put_packet(out_buf, 0);

		gdb_interface_log(GDB_INTERFACE_LOGLEVEL_INFO,
				  ": will wait for a new connection");
		return  FALSE;
	}
	return  TRUE;
}

void handle_thread_alive_command(char * const in_buf,
				 int in_len,
				 char *out_buf,
				 int out_buf_len,
				 gdb_target *target)
{
	int ret;
	int alive;

	/* Is thread alive? */
	/* This is a deprecated feature of the remote debug protocol */
	int64_t p, t;
	if (_decode_thread_id(&in_buf[1], &p, &t)) {
		gdb_interface_write_retval(RET_ERR, out_buf);		
	} else {
		ret = target->is_thread_alive(p, t, &alive);
		if ((ret != RET_OK) || !alive) {
			gdb_interface_write_retval(RET_ERR, out_buf);
		} else {
			gdb_interface_write_retval(RET_OK, out_buf);
		}
	}
}

int handle_restart_target_command(char * const in_buf,
				  int in_len,
				  char *out_buf,
				  int out_buf_len,
				  gdb_target *t)
{
	int ret;

	/* Restarting the target is only supported in the extended protocol. */
	if (!extended_protocol)
		return  FALSE;

	/* Let us do our best to restart the system */
	ret = t->restart();
	if (ret != RET_OK) {
		/* There is no point to continuing */
		gdb_interface_log(GDB_INTERFACE_LOGLEVEL_ERR,
				  ": unable to restart target %s",
				  t->name);
		gdb_interface_write_retval(RET_ERR, out_buf);
		gdb_interface_put_packet(out_buf, 0);

		if (cmdline_once) {
			/*
			 * If the current target cannot restart,
			 * we have little choice but
			   to exit right now.
			*/
			gdb_interface_log(GDB_INTERFACE_LOGLEVEL_INFO,
					  ": target is not restartable. Exiting");
		}

		gdb_interface_log(GDB_INTERFACE_LOGLEVEL_INFO,
				  ": will wait for a new connection");
		return  -1;
	}
	return  TRUE;
}

void handle_detach_command(char * const in_buf,
			   int in_len,
			   char *out_buf,
			   int out_buf_len,
			   gdb_target *t)
{
	int ret = RET_NOSUPP;

	if (t->detach) {
		ret = t->detach(CURRENT_PROCESS_TID);
	} else {
		t->disconnect();
	}

	gdb_interface_write_retval(ret, out_buf);

	/* Note: The current GDB does not expect a reply */
	gdb_interface_put_packet(out_buf, 0);

	gdb_interface_log(GDB_INTERFACE_LOGLEVEL_INFO, ": debugger detached");

	if (cmdline_once) {
		/*
		 * If the current target cannot restart,
		 * we have little choice but
		 * to exit right now.
		 */
		gdb_interface_log(GDB_INTERFACE_LOGLEVEL_INFO,
				  ": target is not restartable. Exiting");
	}

	gdb_interface_log(GDB_INTERFACE_LOGLEVEL_INFO,
			  ": will wait for a new connection");
}

static size_t _escape_binary(uint8_t *dst, uint8_t *src, size_t size)
{
	size_t i, j;
	for (i = 0, j = 0; i < size; i++) {
		uint8_t c = src[i];
		if ((0x23 == c) ||
		    (0x24 == c) ||
		    (0x2a == c) ||
		    (0x7d == c)) {
			dst[j++] = 0x7d;
			dst[j++] = c & ~0x20;
		} else {
			dst[j++] = c;
		}
	}
	return j;
}

void handle_query_command(char * const in_buf,
			  int in_len,
			  char *out_buf,
			  int out_buf_len,
			  gdb_target *t)
{
	int  ret;
	int64_t process, thread;
	gdb_thread_ref ref;
	rp_thread_info info;
	unsigned int mask;
	gdb_thread_ref arg;
	gdb_thread_ref *found;
	size_t max_found;
	size_t count;
	int done;
	int first;
	unsigned int len;
	uint32_t val;
	uint64_t addr;
	char *cp;
	char str[128];
	char *n = in_buf + 1;

	if (in_len == 1) {
		gdb_interface_log(GDB_INTERFACE_LOGLEVEL_ERR,
				  ": bad 'q' command received");
		return;
	}
	if (strncmp(n, "Offsets", 7) == 0) {
		uint64_t text;
		uint64_t data;
		uint64_t bss;

		/* Get the program segment offsets */
		ret = t->offsets_query(&text, &data, &bss);
		if (ret == RET_OK) {
			sprintf(out_buf,
				"Text=%016"PRIu64";Data=%016"PRIu64";Bss=%016"PRIu64"",
				text,
				data,
				bss);
		} else {
			gdb_interface_write_retval(ret, out_buf);
		}
		return;
	}

	if (strncmp(in_buf + 1, "CRC:", 4) == 0) {
		/* Find the CRC32 value of the specified memory area */
		cp = &in_buf[5];
		if (!gdb_decode_uint64(&cp, &addr, ',')) {
			gdb_interface_write_retval(RET_ERR, out_buf);
			return;
		}

		if (!gdb_decode_uint32(&cp, &len, '\0')) {
			gdb_interface_write_retval(RET_ERR, out_buf);
			return;
		}
		ret = t->crc_query(addr, len, &val);
		if (ret == RET_OK)
			sprintf(out_buf, "C%x", val);
		else
			gdb_interface_write_retval(ret, out_buf);
		return;
	}


	if (strncmp(in_buf + 1, "Symbol::", 8) == 0) {
		gdb_interface_write_retval(RET_OK, out_buf);
		return;
	}


	if (strncmp(in_buf + 1, "Symbol:", 7) == 0) {
		gdb_interface_write_retval(RET_NOSUPP, out_buf);
		return;
	}

	sprintf(str, "TStatus");
	if (strncmp(n, str, strlen(str)) == 0) {
		/* sprintf(out_buf, "T0"); */
		gdb_interface_write_retval(RET_NOSUPP, out_buf);
		return;
	}

	if (strncmp(in_buf + 1, "ThreadExtraInfo,", 16) == 0) {
		char data_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];
		const char *in;
		int64_t thread_id;

		if (t->threadextrainfo_query == NULL) {
			gdb_interface_write_retval(RET_NOSUPP, out_buf);
			return;
		}

		in = &in_buf[17];
		ret = gdb_decode_int64(&in, &thread_id, '\0');
		if (!ret) {
			gdb_interface_write_retval(RET_ERR, out_buf);
			return;
		}

		ret = t->threadextrainfo_query(
			thread_id, data_buf,
			GDB_INTERFACE_PARAM_DATABYTES_MAX);
		switch (ret) {
		case RET_OK:
			rp_encode_data(
				(unsigned char *)data_buf, strlen(data_buf),
				out_buf, out_buf_len);
			break;
		case RET_ERR:
		case RET_NOSUPP:
			gdb_interface_write_retval(ret, out_buf);
			break;
		default:
			ASSERT(0);
			break;
		}
		return;
	}

	if (strncmp(in_buf + 1, "fThreadInfo", 11) == 0) {
		if (t->threadinfo_query == NULL) {
			gdb_interface_write_retval(RET_NOSUPP, out_buf);
			return;
		}

		ret = t->threadinfo_query(1, out_buf, out_buf_len);
		switch (ret) {
		case RET_OK:
			break;
		case RET_NOSUPP:
		case RET_ERR:
			gdb_interface_write_retval(ret, out_buf);
			break;
		default:
			/* This should not happen */
			ASSERT(0);
		}
		return;
	}

	if (strncmp(in_buf + 1, "sThreadInfo", 11) == 0) {
		if (t->threadinfo_query == NULL) {
			gdb_interface_write_retval(RET_NOSUPP, out_buf);
			return;
		}

		ret = t->threadinfo_query(0, out_buf, out_buf_len);
		switch (ret) {
		case RET_OK:
			break;
		case RET_NOSUPP:
		case RET_ERR:
			gdb_interface_write_retval(ret, out_buf);
			break;
		default:
			/* This should not happen */
			ASSERT(0);
		}
		return;
	}

	if (strncmp(in_buf + 1, "fProcessInfo", 12) == 0) {
		/* Get first string of process info */
		gdb_interface_write_retval(RET_NOSUPP, out_buf);
		return;
	}

	if (strncmp(in_buf + 1, "sProcessInfo", 12) == 0) {
		/* Get subsequent string of process info */
		gdb_interface_write_retval(RET_NOSUPP, out_buf);
		return;
	}

	if (strncmp(in_buf + 1, "Rcmd,", 5) == 0) {
		/* Remote command */
		rp_target_out_valid = TRUE;
		ret = handle_rcmd_command(&in_buf[6],
					  rp_console_output,
					  rp_data_output,
					  t);
		rp_target_out_valid = FALSE;
		gdb_interface_write_retval(ret, out_buf);
		return;
	}

	sprintf(str, "Supported");
	if (strncmp(n, str, strlen(str)) == 0) {

		/* Features supported */
		if (t->supported_features_query == NULL) {
			gdb_interface_write_retval(RET_NOSUPP, out_buf);
			return;
		}

		ret = t->supported_features_query(out_buf, out_buf_len);
		switch (ret) {
		case RET_OK:
			break;
		case RET_NOSUPP:
		case RET_ERR:
			gdb_interface_write_retval(ret, out_buf);
			break;
		default:
			/* This should not happen */
			ASSERT(0);
		}
		return;
	}

	sprintf(str, "Attached:");
	if (strncmp(n, str, strlen(str)) == 0) {
		gdb_interface_write_retval(RET_NOSUPP, out_buf);
		return;
	}
	sprintf(str, "Attached");
	if (strncmp(n, str, strlen(str)) == 0) {
		/* Only single process */
		sprintf(out_buf, "0");
		return;
	}

	sprintf(str, "Search:memory:");
	if (strncmp(n, str, strlen(str)) == 0) {
		n += strlen(str);
		/* Look for addr */
		uint64_t addr;
		if (gdb_decode_uint64(&n, &addr, ';')) {
			uint32_t len;
			if (gdb_decode_uint32(&n, &len, ';')) {
				size_t bmax = in_len - (n - in_buf);
				uint8_t *pattern =
					(uint8_t *) malloc(bmax *
							   sizeof(uint8_t));
				if (pattern) {
					size_t pattern_len = 0;
					pattern_len = _escape_binary(
						pattern, (uint8_t *)n, bmax);
					if (pattern_len > 0) {
						if (pattern_len <= len) {
							uint8_t *read_buf = (uint8_t *) malloc(len);
							if (read_buf) {
								if (t->read_mem) {
									size_t bytes_read;
									if (RET_OK == t->read_mem(CURRENT_PROCESS_TID, addr, read_buf, len, &bytes_read)) {
										if (bytes_read == len) {
											void *found = NULL;
											found = memmem(read_buf, len, pattern, pattern_len);
											if (NULL != found) {
												uint64_t loc = addr;
												loc += (found - (void *)read_buf);
												sprintf(out_buf, "1,%016"PRIx64"", loc);
											} else {
												/* Not found */
												sprintf(out_buf, "0");
											}
										} else {
											/* Expected to read what was fed in */
											gdb_interface_write_retval(RET_ERR, out_buf);
										}
									} else {
										/* A memory read error */
										gdb_interface_write_retval(RET_ERR, out_buf);
									}
								} else {
									/* Had to check.. */
									gdb_interface_write_retval(RET_ERR, out_buf);
								}
								free(read_buf);
								read_buf = NULL;
							} else {
								/* An internal error */
								gdb_interface_write_retval(RET_ERR, out_buf);
							}
						} else {
							/* Impossible to find pattern is greater than read length */
							sprintf(out_buf, "0");
						}
					} else {
						/* Pattern is 0 length ?!? */
						gdb_interface_write_retval(RET_ERR, out_buf);
					}
					free(pattern);
					pattern = NULL;
				} else {
					/* A memory alloc error */
					gdb_interface_write_retval(RET_ERR, out_buf);
				}
			} else {
				/* Decoding len error */
				gdb_interface_write_retval(RET_ERR, out_buf);
			}
		} else {
			/* Decoding addr arror */
			gdb_interface_write_retval(RET_ERR, out_buf);
		}
		return;
	}


	switch (in_buf[1]) {
	case 'C':
		/* Current thread query */
		ret = t->current_thread_query(&process, &thread);

		if (ret == RET_OK)
			sprintf(out_buf, "QC%"PRIx64".%"PRIx64, process, thread);
		else
			gdb_interface_write_retval(ret, out_buf);
		break;
	case 'L':
		/* Thread list query */
		ret = rp_decode_list_query(&in_buf[2],
					   &first,
					   &max_found,
					   &arg);
		if (!ret  ||  max_found > 255) {
			gdb_interface_write_retval(RET_ERR, out_buf);
			break;
		}

		found = malloc(max_found * sizeof(gdb_thread_ref));
		if (found == NULL) {
			gdb_interface_write_retval(RET_ERR, out_buf);
			break;
		}

		ret = t->list_query(first,
				    &arg,
				    found,
				    max_found,
				    &count,
				    &done);
		if (ret != RET_OK  ||  count > max_found) {
			free(found);
			gdb_interface_write_retval(ret, out_buf);
			break;
		}

		ret = rp_encode_list_query_response(count,
						    done,
						    &arg,
						    found,
						    out_buf,
						    out_buf_len);

		free(found);

		if (!ret)
			gdb_interface_write_retval(RET_ERR, out_buf);
		break;
	case 'P':
		/* Thread info query */
		ret = rp_decode_process_query(&in_buf[2], &mask, &ref);
		if (!ret) {
			gdb_interface_write_retval(RET_ERR, out_buf);
			break;
		}

		info.thread_id.val = 0;
		info.display[0] = 0;
		info.thread_name[0] = 0;
		info.more_display[0] = 0;

		ret = t->process_query(&mask, &ref, &info);
		if (ret != RET_OK) {
			gdb_interface_write_retval(ret, out_buf);
			break;
		}

		ret = rp_encode_process_query_response(mask,
						       &ref,
						       &info,
						       out_buf,
						       out_buf_len);
		if (!ret)
			gdb_interface_write_retval(RET_ERR, out_buf);
		break;
	default:
		/* Raw Query is a universal fallback */
		ret = t->raw_query(in_buf, out_buf, out_buf_len);
		if (ret != RET_OK)
			gdb_interface_write_retval(ret, out_buf);
		break;
	}
}

/* Decode a breakpoint (z or Z) packet */
static int gdb_decode_break(char *in,
			    int *type,
			    uint64_t *addr,
			    unsigned int *len)
{
	uint8_t val;

	ASSERT(in != NULL);
	ASSERT(*in != '\0');
	ASSERT(type != NULL);
	ASSERT(addr != NULL);
	ASSERT(len != NULL);

	in++;
	if (!gdb_decode_nibble(in, &val))
		return  FALSE;
	in++;

	if (*in++ != ',')
		return  FALSE;

	*type = val;

	if (!gdb_decode_uint64(&in, addr, ','))
		return  FALSE;

	if (!gdb_decode_uint32(&in, len, '\0'))
		return  FALSE;

	return  TRUE;
}

static void handle_breakpoint_command(char * const in_buf,
				      int in_len,
				      char *out_buf,
				      int out_buf_len,
				      gdb_target *t)
{
	uint64_t addr;
	unsigned int len;
	int type;
	int ret;

	ret = gdb_decode_break(in_buf, &type, &addr, &len);
	if (!ret) {
		gdb_interface_write_retval(RET_ERR, out_buf);
		return;
	}

	if (in_buf[0] == 'Z')
		ret = t->add_break(CURRENT_PROCESS_TID, type, addr, len);
	else
		ret = t->remove_break(CURRENT_PROCESS_TID, type, addr, len);

	gdb_interface_write_retval(ret, out_buf);
}


#define GDB_OPEN_RDONLY        0x0
#define GDB_OPEN_WRONLY        0x1
#define GDB_OPEN_RDWR          0x2
#define GDB_OPEN_APPEND        0x8
#define GDB_OPEN_CREAT       0x200
#define GDB_OPEN_TRUNC       0x400
#define GDB_OPEN_EXCL        0x800

/* Logic does not work for RDONLY */
#define GDB_OPEN_FLAG(f, g, N)				\
	if ((GDB_OPEN_##N) == ((g) & (GDB_OPEN_##N)))	\
		f |= (O_##N)
/* Special REDONLY */
#define GDB_OPEN_FLAG_RDONLY(g) (!(g & 0xf))

#define GDB_OPEN_IFREG       0100000
#define GDB_OPEN_IFDIR        040000
#define GDB_OPEN_IRUSR          0400
#define GDB_OPEN_IWUSR          0200
#define GDB_OPEN_IXUSR          0100
#define GDB_OPEN_IRGRP           040
#define GDB_OPEN_IWGRP           020
#define GDB_OPEN_IXGRP           010
#define GDB_OPEN_IROTH            04
#define GDB_OPEN_IWOTH            02
#define GDB_OPEN_IXOTH            01

#define GDB_OPEN_MODE(m, g, N)				\
	if (GDB_OPEN_##N == ((g) & (GDB_OPEN_##N)))	\
		m |= S_##N

static int handle_v_command(char * const in_buf,
			    int in_len,
			    char *out_buf,
			    int out_buf_len,
			    gdb_target *target)
{
	int ret = RET_ERR;
	char str[128];
	char *n = in_buf;
	bool handled = false;
	bool binary_cmd = false;

	sprintf(str, "vCont");
	if (strncmp(str, n, strlen(str)) == 0) {
		n += strlen(str);

		if (n[0] == '?') {
			/*
			 * Normally this would be ok to handle
			 * But in dealing with missing signals,
			 * if the normal processing is waiting on
			 * a signal, a second and third reqest
			 * can be see on the 'quick' network.
			 * In order to respond to these fallback
			 * requests, do not support this aggregate
			 * request and force the requests to be
			 * broken up so only the requests that are
			 * known to be waiting can be serviced
			 *
			 * If signal are known to not be lost, uncomment
			 *
			 * sprintf (out_buf, "vCont;c;C;s;S");
			 * handled = true;
			 *
			 * If multiprocess is support, vCont must be supported
			 *
			 * If threading is supported, (it is), vCont must be supported
			 */
		  sprintf (out_buf, "vCont;c;C;s;S");
		  handled = true;

		} else if (n[0] == ';') {
			n++;

			int step  = ((n[0] == 'S') || (n[0] == 's')) ? 1 : 0;
			uint32_t sig = 0;
			bool err = false;
			int64_t p, t;
			p = t = -1;

			char *in = &n[1];
			if ((n[0] == 'C') ||
			    (n[0] == 'S')) {
				if (!gdb_decode_uint32(&in, &sig, '\0')) {
					err = true;
				}
			}

			/* 
			 * Handle the case where the continue applies to a specific thread 
			 * Look for ':<thread-id> '
			 */
			if (strlen(in) > 2) {
			    if (in[0] == ':') {
				if (0 == _decode_thread_id(&in[1], &p, &t)) {
				    target->set_gen_thread(p, t);
				}
			    }
			}

			if (!err) {
			    ret = target->resume_from_current(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID, step, sig);
			    if (RET_OK == ret) {
				if (target->wait) {
				    /* 
				     * Sometimes 'wait' is used internally  
				     * If wait returns an ignore status, do not send 
				     * update to gdb, continue and go back to waiting
				     */
				    do {
					ret = target->wait(out_buf,
							   out_buf_len, step);
					
					if (ret == RET_IGNORE) {
					    target->resume_from_current(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID, step, sig);
					}
				    } while ((ret == RET_IGNORE) || (ret == RET_CONTINUE_WAIT));
				    handled = true;
				}
			    }
			}
		}
	}

	sprintf(str, "vFile:");
	if (strncmp(str, n, strlen(str)) == 0) {
		static int s_fd = -1;
		char *end = NULL;
		n += strlen(str);
		sprintf(str, "open:");
		if (strncmp(str, n, strlen(str)) == 0) {
			n += strlen(str);
			handled = true;

			/*
			 * Looking for
			 * PATHNAME, FLAGS, MODE
			 */
			char *fs, *ms;
			fs = ms = NULL;
			fs = strchr(n, ',');
			if (fs && strlen(fs)) {
				fs++;
				ms = strchr(fs+1, ',');
				if (ms && strlen(ms)) {
					char *t;
					bool status = true;
					ms++;
					/*
					 * -1 to back up to ','
					 * +1 for the null
					 * 1/2 for the nibble to byte reduction
					 *
					 * filepath used by open needs to
					 * be char * used by decode byte
					 * needs to be uint8_t *
					 * cast from char * to uint8_t *
					 * with the temp pointer
					 * 'tp' that is passed to decode byte
					 *
					 */
					char *filepath = (char *)
						malloc((fs - n) / 2);
					if (filepath) {
						uint8_t *tp;
						for (t = n, tp = (uint8_t *) filepath; t < fs - 1 && status; t += 2, tp++) {
							status = gdb_decode_byte(t, tp);
						}
						if (status) {
							int gdb_flag;
							tp[0] = 0; /* null terminate */
							end = NULL;
							gdb_flag = strtol(fs, &end, 16);
							if (end != fs) {
								int gdb_mode;
								end = NULL;
								gdb_mode = strtol(ms, &end, 16);
								if (end != ms) {
									int flag = 0;
									mode_t mode = 0;
									if (s_fd > 0) {
										close(s_fd);
										s_fd = -1;
									}
									if (GDB_OPEN_FLAG_RDONLY(gdb_flag)) {
										flag = O_RDONLY;
									} else {
										GDB_OPEN_FLAG(flag, gdb_flag, WRONLY);
										GDB_OPEN_FLAG(flag, gdb_flag, RDWR);
										GDB_OPEN_FLAG(flag, gdb_flag, APPEND);
										GDB_OPEN_FLAG(flag, gdb_flag, CREAT);
										GDB_OPEN_FLAG(flag, gdb_flag, TRUNC);
										GDB_OPEN_FLAG(flag, gdb_flag, EXCL);
									}

									GDB_OPEN_MODE(mode, gdb_mode, IXOTH);
									GDB_OPEN_MODE(mode, gdb_mode, IWOTH);
									GDB_OPEN_MODE(mode, gdb_mode, IROTH);
									GDB_OPEN_MODE(mode, gdb_mode, IXGRP);
									GDB_OPEN_MODE(mode, gdb_mode, IWGRP);
									GDB_OPEN_MODE(mode, gdb_mode, IRGRP);
									GDB_OPEN_MODE(mode, gdb_mode, IXUSR);
									GDB_OPEN_MODE(mode, gdb_mode, IWUSR);
									GDB_OPEN_MODE(mode, gdb_mode, IRUSR);
									GDB_OPEN_MODE(mode, gdb_mode, IFDIR);
									GDB_OPEN_MODE(mode, gdb_mode, IFREG);
									s_fd = open(filepath, flag, mode);
									if (s_fd > 0) {
										/* Success */
										ret = RET_OK;
									}

									/* Good or ill, send the fd as the response */
									sprintf(out_buf, "F%x", s_fd);
								} else {
									/* Error */
									sprintf(out_buf, "F%d", -1);
								}
							} else {
								/* Error */
								sprintf(out_buf, "F%d", -1);
							}
						} else {
							/* Error */
							sprintf(out_buf, "F%d", -1);
						}

						free(filepath);
						filepath = NULL;
					} else {
						/* Error */
						sprintf(out_buf, "F%d", -1);
					}

				} else {
					/* Error */
					sprintf(out_buf, "F%d", -1);
				}
			} else {
				/* Error */
				sprintf(out_buf, "F%d", -1);
			}
		}


		sprintf(str, "unlink:");
		if (strncmp(str, n, strlen(str)) == 0) {
			n += strlen(str);
			handled = true;

			/* Looking for PATHNAME */
			char *fe;
			fe = NULL;
			fe = n + strlen(n);

			if (fe && 0 < fe - n) {

				/*
				 * Add 1 for null
				 * Divide by 2 to go from encoded to raw
				 */
				char *filepath = (char *)
					malloc(1 + (fe - n) / 2);

				if (filepath) {
					uint8_t *tp = NULL;
					char *t = NULL;
					int status = -1;

					for (t = n, tp = (uint8_t *) filepath;
					     t < fe && status; t += 2, tp++) {
						status = gdb_decode_byte(t, tp);
					}
					tp[0] = 0; /* null terminate */
					if (status) {
						status = unlink(filepath);

						/*
						 * Good or ill, send the
						 * status as the response
						 */
						sprintf(out_buf, "F%d", status);
					} else {
						/* Error */
						sprintf(out_buf, "F%d", -1);
					}

					free(filepath);
					filepath = NULL;
				} else {
					/* Error */
					sprintf(out_buf, "F%d", -1);
				}

			} else {
				/* Error */
				sprintf(out_buf, "F%d", -1);
			}
		}


		sprintf(str, "pwrite:");
		if (strncmp(str, n, strlen(str)) == 0) {
			int try_fd = -1;
			n += strlen(str);
			handled = true;

			/*
			 * Looking for
			 * FD, OFFSET, DATA
			 */
			end = NULL;
			try_fd = strtol(n, &end, 10);
			if (end != n) {
				if (try_fd == s_fd) {
					/* Move past comma */
					n = end + 1;
					off_t off;
					end = NULL;
					/*
					 * WARNING
					 * This will only handle 31 bit offsets
					 */
					off = strtol(n, &end, 16);
					if (end != n && off >= 0) {
						/* Move past comma */
						n = end + 1;
						/*
						 * No 'size' as part of argument
						 * Have to infer from the size of the input
						 * And how much has already been read
						 *
						 * n - in_buf is how much has already been read
						 * -3 for end of buffer #XY crc check
						 */
						if ((n - in_buf) < in_len) {

							if (off != lseek(s_fd, off, SEEK_SET)) {
								/* Error */
								sprintf(out_buf, "F%d", -1);
							} else {
								size_t bytes_to_write = 0;
								size_t bytes_written = 0;
								bytes_to_write = in_len - (n - in_buf);

								/* Data is binary, no need to decode */
								bytes_written = write(s_fd, n, bytes_to_write);
								sprintf(out_buf, "F%zx", bytes_written);
							}
						} else {
							/* Error */
							sprintf(out_buf, "F%d", -1);
						}
					} else {
						/* Error */
						sprintf(out_buf, "F%d", -1);
					}
				} else {
					/* Error */
					sprintf(out_buf, "F%d", -1);
				}
			} else {
				/* Error */
				sprintf(out_buf, "F%d", -1);
			}
		}

		sprintf(str, "pread:");
		if (strncmp(str, n, strlen(str)) == 0) {
			int try_fd = -1;
			n += strlen(str);
			handled = true;

			/*
			 * Looking for
			 * FD, SIZE, OFFSET
			 */
			end = NULL;
			try_fd = strtol(n, &end, 10);
			if (end != n) {
				if (try_fd == s_fd) {
					/* Move past comma */
					n = end + 1;

					size_t size;
					end = NULL;
					size = strtol(n, &end, 16);
					if (end != n && size > 1) {
						/* Move past comma */
						n = end + 1;

						off_t off;
						end = NULL;
						/*
						 * WARNING
						 * This will only handle
						 * 31 bit offsets
						 */
						off = strtol(n, &end, 16);
						if (end != n && off >= 0) {
							/* Move past comma */
							n = end + 1;

							if (off != lseek(s_fd, off, SEEK_SET)) {
								/* Error */
								sprintf(out_buf, "F%d", -1);
							} else {
								size_t bytes_read = 0;
								uint8_t *buf = (uint8_t *) malloc(size);
								if (buf) {
									size_t preamble_size = 0;
									size_t escaped_size = 0;
									uint8_t *dst = NULL;

									/* The fs read */
									bytes_read = read(s_fd, buf, size);
									/* The preamble size */
									sprintf(out_buf, "F%zx;", bytes_read);
									preamble_size = strlen(out_buf);
									/* this is binary data, need to escape special chars */
									dst = (uint8_t *)out_buf + preamble_size;
									escaped_size = _escape_binary(dst, buf, bytes_read);
									/* send packet out here because being binary, can not use upstream packet put */
									ret = gdb_interface_put_packet(out_buf, escaped_size + preamble_size);
									/* Make sure upstream doesn't push again */
									out_buf[0] = 0; /* null terminated */
									binary_cmd = true;
									free(buf);
									buf = NULL;

								} else {
									/* Error */
									sprintf(out_buf, "F%d", -1);
								}
							}
						} else {
							/* Error */
							sprintf(out_buf, "F%d", -1);
						}
					} else {
						/* Error */
						sprintf(out_buf, "F%d", -1);
					}
				} else {
					/* Error */
					sprintf(out_buf, "F%d", -1);
				}
			} else {
				/* Error */
				sprintf(out_buf, "F%d", -1);
			}
		}


		sprintf(str, "close:");
		if (strncmp(str, n, strlen(str)) == 0) {
			int try_fd = -1;
			n += strlen(str);
			handled = true;

			end = NULL;
			try_fd = strtol(n, &end, 10);
			if (end != n) {
				if (try_fd == s_fd) {
					int status = close(s_fd);
					s_fd = -1;

					sprintf(out_buf, "F%d", status);
					if (0 == status) {
						ret = RET_OK;
					}
				} else {
					/* Error */
					sprintf(out_buf, "F%d", -1);
				}
			} else {
				/* Error */
				sprintf(out_buf, "F%d", -1);
			}
		}
	}

	if (!handled) {
		/* Error */
		gdb_interface_write_retval(RET_NOSUPP, out_buf);
	}

	if (!binary_cmd) {
		gdb_interface_ack();
		gdb_interface_put_packet(out_buf, 0);
	}

	return ret;
}



static void handle_general_set_command(char * const in_buf,
				       int in_len,
				       char *out_buf,
				       int out_buf_len,
				       gdb_target *t)
{
	int ret = RET_ERR;
	if (t->general_set) {
		ret = t->general_set(in_buf, out_buf, out_buf_len);
	}

	gdb_interface_write_retval(ret, out_buf);
}

/* Send an 'O' packet (console output) to GDB */
static void rp_console_output(const char *s)
{
	int ret;
	char *d;
	size_t count;
	size_t lim;
	static char buf[RP_VAL_DBG_PBUFSIZ - 6];

#if RP_VAL_DBG_PBUFSIZ < 10
#error "Unexpected value of RP_VAL_DBG_PBUFSIZ"
#endif /* RP_VAL_DBG_PBUFSIZ < 10 */

	if (!rp_target_out_valid) {
		gdb_interface_log(GDB_INTERFACE_LOGLEVEL_DEBUG,
				  ": unexpected output from target: %s",
				  s);
		return;
	}

	lim = sizeof(buf) - 1;
	if ((lim & 1) == 0) {
		/* We can split on any byte boundary */
		lim--;
	}

	do {
		d = buf;
		*d++ = 'O';
		for (count = 1;  *s  &&  count < lim;  s++, d++, count++)
			*d = *s;
		*d = '\0';
		ret = gdb_interface_put_packet(buf, 0);
	} while (*s  &&  ret);
}

/* Send hex data to GDB */
static void rp_data_output(const char *s)
{
	int ret;
	char *d;
	size_t count;
	size_t lim;
	static char buf[RP_VAL_DBG_PBUFSIZ - 6];

#if RP_VAL_DBG_PBUFSIZ < 10
#error "Unexpected value for RP_VAL_DBG_PBUFSIZ"
#endif /* RP_VAL_DBG_PBUFSIZ < 10 */

	if (!rp_target_out_valid) {
		gdb_interface_log(GDB_INTERFACE_LOGLEVEL_DEBUG,
				  ": unexpected output from target: %s",
				  s);
		return;
	}

	lim = sizeof(buf) - 1;

	if ((lim & 1)) {
		/* We can split on any byte boundary */
		lim--;
	}

	do {
		for (d = buf, count = 0;
		     *s != 0  &&  count < lim;  s++, d++, count++)
			*d = *s;
		*d = '\0';
		ret = gdb_interface_put_packet(buf, 0);
	} while (*s  &&  ret);
}

static int gdb_decode_reg(char *in, unsigned int *reg_no)
{
	if (!gdb_decode_uint32(&in, reg_no, '\0'))
		return  FALSE;

	return  TRUE;
}

/* Decode reg_no=XXXXXX */
static int gdb_decode_reg_assignment(char *in,
				     unsigned int *reg_no,
				     unsigned char *out,
				     size_t out_size,
				     size_t *out_len)
{
	ASSERT(in != NULL);
	ASSERT(reg_no != NULL);
	ASSERT(out != NULL);
	ASSERT(out_size > 0);
	ASSERT(out_len != NULL);

	if (!gdb_decode_uint32(&in, reg_no, '='))
		return  FALSE;

	out_size -= 8;

	return gdb_decode_data(in, out, out_size - 1, out_len);
}

/* Decode memory transfer parameter in the form of AA..A,LL..L */
static int gdb_decode_mem(char *in, uint64_t *addr, size_t *len)
{
	int ret = FALSE;
	ASSERT(in != NULL);
	ASSERT(addr != NULL);
	ASSERT(len != 0);

	*len = 0;

	if (FALSE != gdb_decode_uint64(&in, addr, ',')) {
		/* On 64 bit, size_t != uint32_t */
		uint32_t l = 0;

		if (FALSE != gdb_decode_uint32(&in, &l, '\0')) {
			*len = l;
			ret = TRUE;
		}
	}
	return  ret;
}

/* Decode process query. Format: 'MMMMMMMMRRRRRRRRRRRRRRRR'
   where:
   M represents mask
   R represents thread reference */
static int rp_decode_process_query(const char *in,
				   unsigned int *mask,
				   gdb_thread_ref *ref)
{
	unsigned int tmp_mask;
	uint64_t tmp_val;

	ASSERT(in != NULL);
	ASSERT(mask != NULL);
	ASSERT(ref != NULL);

	if (!rp_decode_4bytes(in, &tmp_mask))
		return  FALSE;
	in += 8;

	if (!rp_decode_8bytes(in, &tmp_val))
		return  FALSE;

	*mask = tmp_mask;
	ref->val = tmp_val;

	return  TRUE;
}

/* Decode thread list list query. Format 'FMMAAAAAAAAAAAAAAAA'
   where:
   F represents first flag
   M represents max count
   A represents argument thread reference */
static int rp_decode_list_query(const char *in,
				int *first,
				size_t *max,
				gdb_thread_ref *arg)
{
	uint8_t first_flag;
	uint8_t tmp_max;
	uint64_t tmp_val;

	ASSERT(in != NULL);
	ASSERT(first != NULL);
	ASSERT(max != NULL);
	ASSERT(arg != NULL);

	if (!gdb_decode_nibble(in, &first_flag))
		return  FALSE;
	in++;

	if (!gdb_decode_byte(in, &tmp_max))
		return  FALSE;
	in += 2;

	if (!rp_decode_8bytes(in, &tmp_val))
		return  FALSE;

	*first = (first_flag)  ?  TRUE  :  FALSE;
	*max = tmp_max;
	arg->val = tmp_val;

	return  TRUE;
}


/* If a byte of avail is 0 then the corresponding data byte is
   encoded as 'xx', otherwise it is encoded in normal way */
static int gdb_encode_regs(const unsigned char *data,
			   const unsigned char *avail,
			   size_t data_len,
			   char *out,
			   size_t out_size)
{
	size_t i;

	ASSERT(data != NULL);
	ASSERT(avail != NULL);
	ASSERT(data_len > 0);
	ASSERT(out != NULL);
	ASSERT(out_size > 0);

	if ((data_len*2) >= out_size) {
		/* We do not have enough space to encode the data */
		return  FALSE;
	}

	for (i = 0;  i < data_len;  i++, data++, avail++, out += 2) {
		if (*avail) {
			rp_encode_byte(*data, out);
		} else {
			*out = 'x';
			*(out + 1) = 'x';
		}
	}

	*out = 0;

	return  TRUE;
}

/* Convert an array of bytes into an array of characters */
static int rp_encode_data(const unsigned char *data,
			  size_t data_len,
			  char *out,
			  size_t out_size)
{
	size_t i;

	ASSERT(data != NULL);
	ASSERT(data_len > 0);
	ASSERT(out != NULL);
	ASSERT(out_size > 0);

	if ((data_len*2) >= out_size) {
		/* We do not have enough space to encode the data */
		return  FALSE;
	}

	for (i = 0;  i < data_len;  i++, data++, out += 2)
		rp_encode_byte(*data, out);

	*out = 0;

	return  TRUE;
}

/* Encode string into an array of characters */
int rp_encode_string(const char *s, char *out, size_t out_size)
{
	int i;

	ASSERT(s != NULL);
	ASSERT(out != NULL);
	ASSERT(out_size > 0);

	if (strlen(s) * 2 >= out_size) {
		/* We do not have enough space to encode the data */
		return  FALSE;
	}

	i = 0;
	while (*s) {
		*out++ = hex[(*s >> 4) & 0x0f];
		*out++ = hex[*s & 0x0f];
		s++;
		i++;
	}
	*out = '\0';
	return i;
}

/* Encode result of process query:
   qQMMMMMMMMRRRRRRRRRRRRRRRR(TTTTTTTTLLVV..V)*,
   where
   M   represents mask
   R   represents ref
   T   represents tag
   L   represents length
   V   represents value */
static int rp_encode_process_query_response(unsigned int mask,
					    const gdb_thread_ref *ref,
					    const rp_thread_info *info,
					    char *out,
					    size_t out_size)
{
	size_t len;
	unsigned int tag;
	int i;

	ASSERT(ref != NULL);
	ASSERT(info != NULL);
	ASSERT(out != NULL);
	ASSERT(out_size > 0);

	/* In all cases we will have at least mask and reference thread */
	if (out_size <= 26)
		return 0;

	/* Encode header */
	*out++ = 'q';
	*out++ = 'Q';
	out_size -= 2;

	/* Encode mask */
	sprintf(out, "%08x", mask);
	out += 8;
	out_size -= 8;

	/* Encode reference thread */
	sprintf(out, "%016"PRIu64"x", ref->val);

	out += 16;
	out_size -= 16;

	for (i = 0, tag = 0;  i < 32;  i++, tag <<= 1) {
		if ((mask & tag) == 0)
			continue;

		if (out_size <= 10) {
			/* We have no place to put even tag and length */
			return 0;
		}

		/* Encode tag */
		sprintf(out, "%08x", tag);
		out += 8;
		out_size -= 8;

		switch (tag) {
		case RP_BIT_PROCQMASK_THREADID:
			if (out_size <= 18)
				return 0;

			/* Encode length - it is 16 */
			rp_encode_byte(16, out);
			out += 2;
			out_size -= 2;

			/* Encode value */
			sprintf(out, "%016"PRIu64"x", info->thread_id.val);

			out += 16;
			out_size -= 16;
			break;
		case RP_BIT_PROCQMASK_EXISTS:
			/* One nibble is enough */
			if (out_size <= 3)
				return 0;

			/* Encode Length */
			rp_encode_byte(1, out);
			out += 2;
			out_size -= 2;

			/* Encode value */
			*out++    = (info->exists) ? '1' : '0';
			out_size-- ;
			*out      = 0;
			break;
		case RP_BIT_PROCQMASK_DISPLAY:
			/* Encode length */
			len = strlen(info->display);
			ASSERT(len <= 255);

			if (out_size <= (len + 2))
				return 0;

			rp_encode_byte(len, out);
			out += 2;
			out_size -= 2;

			/* Encode value */
			strcpy(out, info->display);
			out      += len;
			out_size -= len;
			break;
		case RP_BIT_PROCQMASK_THREADNAME:
			/* Encode length */
			len = strlen(info->thread_name);
			ASSERT(len <= 255);

			if (out_size <= (len + 2))
				return 0;

			rp_encode_byte(len, out);
			out += 2;
			out_size -= 2;

			/* Encode value */
			strcpy(out, info->thread_name);
			out      += len;
			out_size -= len;
			break;
		case RP_BIT_PROCQMASK_MOREDISPLAY:
			/* Encode length */
			len = strlen(info->more_display);
			ASSERT(len <= 255);

			if (out_size <= (len + 2))
				return 0;

			rp_encode_byte(len, out);
			out += 2;
			out_size -= 2;

			/* Encode value */
			strcpy(out, info->more_display);
			out += len;
			out_size -= len;
			break;
		default:
			/* Unexpected tag value */
			ASSERT(0);
			return 0;
		}
	}

	return 1;
}

/* Encode result of list query:
   qMCCDAAAAAAAAAAAAAAAA(FFFFFFFFFFFFFFFF)*,
   where
   C   reprsents  count
   D   represents done
   A   represents arg thread reference
   F   represents found thread reference(s) */
static int rp_encode_list_query_response(size_t count,
					 int done,
					 const gdb_thread_ref *arg,
					 const gdb_thread_ref *found,
					 char *out,
					 size_t out_size)
{
	size_t i;

	ASSERT(arg != NULL);
	ASSERT(found != NULL  ||  count == 0);
	ASSERT(count <= 255);

	/* Encode header, count, done and arg */
	if (out_size <= 21)
		return  FALSE;

	*out++ = 'q';
	*out++ = 'M';
	out_size -= 2;

	rp_encode_byte(count, out);
	out += 2;
	out_size -= 2;

	*out++ = (done)  ?  '1'  :  '0';
	out_size--;

	sprintf(out, "%016"PRIu64"x", arg->val);

	out += 16;
	out_size -= 16;

	/* Encode found */
	for (i = 0;  i < count;  i++, found++) {
		if (out_size <= 16)
			return  FALSE;

		sprintf(out, "%016"PRIu64"x", found->val);

		out += 16;
		out_size -= 16;
	}

	return  TRUE;
}

int rp_hex_nibble(char in)
{
	int c;

	c = in & 0xff;

	if (c >= '0'  &&  c <= '9')
		return  c - '0';

	if (c >= 'A'  &&  c <= 'F')
		return  c - 'A' + 10;

	if (c >= 'a'  &&  c <= 'f')
		return  c - 'a' + 10;

	return  -1;
}



/* Decode exactly 4 bytes of hex from a longer string, and return the result
   as an unsigned 32-bit value */
static int rp_decode_4bytes(const char *in, uint32_t *val)
{
	uint8_t nibble;
	uint32_t tmp;
	int count;

	for (tmp = 0, count = 0;  count < 8;  count++, in++) {
		if (!gdb_decode_nibble(in, &nibble))
			break;
		tmp = (tmp << 4) + nibble;
	}
	*val = tmp;
	return  TRUE;
}

/* Decode exactly 8 bytes of hex from a longer string, and return the result
   as an unsigned 64-bit value */
static int rp_decode_8bytes(const char *in, uint64_t *val)
{
	uint8_t nibble;
	uint64_t tmp;
	int count;

	for (tmp = 0, count = 0;  count < 16;  count++, in++) {
		if (!gdb_decode_nibble(in, &nibble))
			break;
		tmp = (tmp << 4) + nibble;
	}
	*val = tmp;
	return  TRUE;
}

/* Decode a hex string to an unsigned 32-bit value */
static int gdb_decode_uint32(char **in, uint32_t *val, char break_char)
{
	uint8_t nibble;
	uint32_t tmp;
	int count;

	ASSERT(in != NULL);
	ASSERT(val != NULL);

	if (**in == '\0') {
		/* We are expecting at least one character */
		return  FALSE;
	}

	for (tmp = 0, count = 0;  **in  &&  count < 8;  count++, (*in)++) {
		if (!gdb_decode_nibble(*in, &nibble))
			break;
		tmp = (tmp << 4) + nibble;
	}

	if (**in != break_char)	{
		DBG_PRINT("ERROR wrong terminator expecting %d and got %d\n",
			  break_char, **in);
		/* Wrong terminating character */
		return  FALSE;
	}
	if (**in)
		(*in)++;
	*val = tmp;
	return  TRUE;
}

/* Decode a hex string to an unsigned 64-bit value */
static int gdb_decode_uint64(char **in, uint64_t *val, char break_char)
{
	uint8_t nibble;
	uint64_t tmp;
	int count;

	ASSERT(in != NULL);
	ASSERT(val != NULL);

	if (**in == '\0') {
		/* We are expecting at least one character */
		return  FALSE;
	}

	for (tmp = 0, count = 0;  **in  &&  count < 16;  count++, (*in)++) {
		if (!gdb_decode_nibble(*in, &nibble))
			break;
		tmp = (tmp << 4) + nibble;
	}

	if (**in != break_char)	{
		/* Wrong terminating character */
		return  FALSE;
	}
	if (**in)
		(*in)++;
	*val = tmp;
	return  TRUE;
}

/* Decode a hex string to an unsigned 64-bit value */
static int gdb_decode_int64(char const **in, int64_t *val, char break_char)
{
	uint8_t nibble;
	int64_t tmp = 0;
	int count;
	int sign = 1;

	ASSERT(in != NULL);
	ASSERT(val != NULL);

	if (**in == '-') {
		sign = -1;
		(*in)++;
	}

	if (**in == '\0') {
		/* We are expecting at least one character */
		return  FALSE;
	}

	for (count = 0;  **in  &&  count < 16;  count++, (*in)++) {
		if (!gdb_decode_nibble(*in, &nibble))
			break;
		/* Overflow */
		if ((count == 0) && (sign == -1) && (nibble & 0x8))
			return FALSE;
		tmp = (tmp << 4) + nibble;
	}

	if (**in != break_char)	{
		/* Wrong terminating character */
		return  FALSE;
	}
	if (**in)
		(*in)++;
	*val = sign * tmp;
	return  TRUE;
}

/* Encode byte */
static void rp_encode_byte(unsigned int val, char *out)
{
	ASSERT(val <= 0xff);
	ASSERT(out != NULL);

	*out = hex[(val >> 4) & 0xf];
	*(out + 1) = hex[val & 0xf];
}


/* Encode return value */
static void gdb_interface_write_retval(int ret, char *b)
{
	switch (ret) {
	case RET_OK:
		strcpy(b, "OK");
		break;
	case RET_ERR:
		strcpy(b, "E00");
		break;
	case RET_NOSUPP:
		/* Write empty string into buffer */
		*b = '\0';
		break;
	default:
		ASSERT(0);
		break;
	}
}

int handle_rcmd_command(char *in_buf, out_func of, data_func df, gdb_target *t)
{
	return RET_NOSUPP;
}

void gdb_interface_cleanup()
{
	target_cleanup();
	gdb_interface_target = NULL;
}
void gdb_interface_init()
{
	/* Set to debug level of choice */
	gdb_interface_debug_level = -1;
	target_init(&gdb_interface_target);
	gdb_interface_log = &gdb_interface_log_local;
}

int gdb_interface_quick_packet()
{
	int ret = 1;
	size_t in_len = 0;
	int s;

	/* Various buffers used by the system */
	static char in_buf[RP_PARAM_INOUTBUF_SIZE];
	/*
	 * Because no implicit ack's while reading the
	 * ack's must be explicitly done for each handled packet.
	 */
	s = gdb_interface_getpacket(in_buf, sizeof(in_buf),
				    &in_len, false /* no acks */);
	if (s == '\3') {
		if (gdb_interface_target->stop) {
			dbg_ack_packet_received(false, NULL);
			gdb_interface_target->stop(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID);
		} else {
			DBG_PRINT("TBD : Handle ctrl-c\n");
		}
	} else {

		switch (in_buf[0]) {
		case 'k':
			if (gdb_interface_target->quick_kill) {
				dbg_ack_packet_received(false, NULL);
				gdb_interface_target->quick_kill(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID);
				ret = 0;
			}
			break;

		case 'C':
			if (gdb_interface_target->quick_signal) {
				uint32_t sig;
				char *in;
				in = &in_buf[1];
				if (gdb_decode_uint32(&in, &sig, '\0')) {
					dbg_ack_packet_received(false, NULL);
					gdb_interface_target->quick_signal(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID, sig);
					ret = 0;
				}
			}
			break;

		case 'c':
			if (gdb_interface_target->quick_signal) {
				dbg_ack_packet_received(false, NULL);
				gdb_interface_target->quick_signal(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID, SIGTRAP);
				ret = 0;
			}
			break;

		case 'v':
		    if (0 == strncmp(in_buf, "vCont;c", 7)) {
			dbg_ack_packet_received(false, NULL);
			ret = 0;
		    } else {
			/* Ignore */
			DBG_PRINT("quick packet : ignoring %s ", in_buf);
		    }
		    break;

		default:
			/* Ignore */
			DBG_PRINT("quick packet : ignoring %s ", in_buf);
			break;
		}
	}

	return ret;
}

int gdb_interface_packet()
{
	int ret = 1;
	size_t in_len = 0;
	int s;
	bool binary_cmd = false;

	/* Various buffers used by the system */
	static char in_buf[RP_PARAM_INOUTBUF_SIZE];
	static char out_buf[RP_PARAM_INOUTBUF_SIZE];

	s = gdb_interface_getpacket(in_buf, sizeof(in_buf),
				    &in_len, true /* do acks */);

	if (s >= 0) {
		if (s == NAK) {
			/* Ignore */
			ret = 0;
		} else if (s == ACK) {
			/* Ignore */
			ret = 0;
		} else if (s == '\3') {
			DBG_PRINT("TBD : Handle ctrl-c\n");
		} else {

			/*
			 * If we cannot process this command,
			 * it is not supported
			 */
			gdb_interface_write_retval(RET_NOSUPP, out_buf);
			rp_target_out_valid = FALSE;

			switch (in_buf[0]) {

			case '!':
				/* Set extended operation */
				/* Not supported */
				break;

			case '?':
				/* Report the last signal status */
				handle_query_current_signal(out_buf,
							    sizeof(out_buf),
							    gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'A':
				/* Set the argv[] array of the target */
				/* Not supported */
				break;

			case 'C':
			case 'S':
			case 'W':
			case 'c':
			case 's':
			case 'w':
				handle_running_commands(in_buf,
							in_len,
							out_buf,
							sizeof(out_buf),
							gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'D':
				handle_detach_command(in_buf,
						      in_len,
						      out_buf,
						      sizeof(out_buf),
						      gdb_interface_target);
				/* Semi Supported */
				ret = 0;
				break;

			case 'g':
				handle_read_registers_command(in_buf,
							      in_len,
							      out_buf,
							      sizeof(out_buf),
							      gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'G':
				handle_write_registers_command(in_buf,
							       in_len,
							       out_buf,
							       sizeof(out_buf),
							       gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'H':
				handle_thread_commands(in_buf,
						       in_len,
						       out_buf,
						       sizeof(out_buf),
						       gdb_interface_target);
				/* Supported */
				ret = 0;
				break;
			case 'k':
				handle_kill_command(in_buf,
						    in_len,
						    out_buf,
						    sizeof(out_buf),
						    gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'm':
				handle_read_memory_command(in_buf,
							   in_len,
							   out_buf,
							   sizeof(out_buf),
							   gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'M':
				handle_write_memory_command(in_buf,
							    in_len,
							    out_buf,
							    sizeof(out_buf),
							    gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'p':
				handle_read_single_register_command(in_buf,
								    in_len,
								    out_buf,
								    sizeof(out_buf),
								    gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'P':
				handle_write_single_register_command(in_buf,
								     in_len,
								     out_buf,
								     sizeof(out_buf),
								     gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'q':
				handle_query_command(in_buf,
						     in_len,
						     out_buf,
						     sizeof(out_buf),
						     gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'Q':
				handle_general_set_command(in_buf,
							   in_len,
							   out_buf,
							   sizeof(out_buf),
							   gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'R':
				handle_restart_target_command(in_buf,
							      in_len,
							      out_buf,
							      sizeof(out_buf),
							      gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 't':
				handle_search_memory_command(in_buf,
							     in_len,
							     out_buf,
							     sizeof(out_buf),
							     gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'T':
				handle_thread_alive_command(in_buf,
							    in_len,
							    out_buf,
							    sizeof(out_buf),
							    gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'Z':
			case 'z':
				handle_breakpoint_command(in_buf,
							  in_len,
							  out_buf,
							  sizeof(out_buf),
							  gdb_interface_target);
				/* Supported */
				ret = 0;
				break;

			case 'v':
				binary_cmd = true;
				/* Handled below */
				break;

			default:
				DBG_PRINT("gdb_interface : unhandle command\n");
				break;
			}

			if (!binary_cmd) {
				gdb_interface_ack();
				gdb_interface_put_packet(out_buf, 0);
			} else {
				/* Now the binary command */
				switch (in_buf[0]) {
				case 'v':
					handle_v_command(in_buf,
							 in_len,
							 out_buf,
							 sizeof(out_buf),
							 gdb_interface_target);
					break;
				default:
					break;
				}
			}
		}
	} else {
		gdb_interface_nak();
		DBG_PRINT("gdb_interface : error getting a packet\n");
	}
	return ret;
}
