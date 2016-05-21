/*
   This file is derrived from the gdbproxy project's gdbproxy.c
   The changes to this file are
   Copyright (C) 2012-2016 Juniper Networks, Inc

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
     rp_decode_xxxxx    - various decode functions
     rp_encode_xxxxx    - various encode functions
     rp_write_xxxxx     - encode result of operation


   $Id: gdbproxy.c,v 1.12 2010/02/10 12:45:50 vapier Exp $ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#include <errno.h>
#include <fcntl.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if HAVE_LIBGEN_H
/* for freebsd basename() */
#include <libgen.h>
#endif
#include "gdb_interface.h"
#include "global.h"
#include "lldb_interface.h"
#include "macros.h"
#include "network.h"
#include "target.h"
#include "util.h"
#include "thread_db_priv.h"

static void dbg_sock_putchar(int c) {
  if (network_out_buffer_total < network_out_buffer_size) {
    network_out_buffer[network_out_buffer_total] = (uint8_t)(0xff & c);
    network_out_buffer_total++;
  } else {
    DBG_PRINT("gdb_interface : error out overflow\n");
  }
}
static uint16_t dbg_sock_readchar() {
  /* Initialize to 0xffff so error is encoded in the high byte */
  uint16_t ret = 0xffff;
  if (network_in_buffer_current < network_in_buffer_total) {
    /* Assignment of single, valid byte clear the high error byte */
    ret = (uint16_t)network_in_buffer[network_in_buffer_current];
    network_in_buffer_current++;
  } else {
      /* underflow is the most likely possiblity */
    DBG_PRINT("gdb_interface : error out underflow read %zu\n",
              network_in_buffer_current);
  }
  return ret;
}

/* Flag to catch unexpected output from target */
static int rp_target_out_valid = FALSE;

/* Decode/encode functions */

static int gdb_decode_reg_assignment(char *in, unsigned int *reg_no,
                                     unsigned char *out, size_t out_size,
                                     size_t *len);
static int gdb_decode_mem(char *in, uint64_t *addr, size_t *len);
static int rp_decode_process_query(const char *in, unsigned int *mask,
                                   gdb_thread_ref *ref);

static int rp_decode_list_query(const char *in, int *first, size_t *max,
                                gdb_thread_ref *arg);

static int rp_decode_4bytes(const char *in, uint32_t *val);
static int rp_decode_8bytes(const char *in, uint64_t *val);

static int extended_protocol;

void dbg_ack_packet_received(bool seq_valid, char *seq) {
  /* Acknowledge this good packet */
  if (_target.ack)
    dbg_sock_putchar('+');
  if (seq_valid) {
    dbg_sock_putchar(seq[0]);
    dbg_sock_putchar(seq[1]);
  }
}

#define STATE_INIT 0
#define STATE_CMD 4
#define STATE_TEXT 5
#define STATE_BINARY_RAW 6
#define STATE_PRE_BINARY_ENCODED 7
#define STATE_BINARY_ENCODED 8
#define STATE_HASHMARK 9
#define STATE_CSUM 10

/* Various buffers used by the system */
static char *in_buf = NULL;
static char *out_buf = NULL;
static char *in_buf_quick = NULL;

/* Read a packet from the remote machine, with error checking,
   and store it in buf. */
static int gdb_interface_getpacket(char *buf, size_t *len, bool ret_ack) {
  int ret = -1;
  size_t buf_len = INOUTBUF_SIZE;
  if ((buf != NULL) &&
      (buf_len > 6) &&
      (len != NULL)) {
    char seq[2] = { 0, 0 };
    bool seq_valid = false;
    unsigned char rx_csum = 0;
    unsigned char calc_csum = 0;
    size_t pkt_len = 0;
    int state = STATE_INIT;
    bool esc_found = false;
    bool binary = false;
    int nib;
    for (;;) {
      uint16_t sc = dbg_sock_readchar();
      /* Check for underflow */
      if (!(sc & 0xff00)) {
	uint8_t c = (uint8_t)sc;
	if (c == '$' && state != STATE_INIT) {
	  /*
	   * Unexpected start of packet marker
	   * in mid-packet.
	   */
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
	    ret = NAK;
	    break;
	  }
	} else if ((state == 1) || (state == 2)) {
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
	      binary = true;
	      buf[0] = 'M';
	      esc_found = false;
	      /* Have to save extra space */
	      buf_len--;
	      state = STATE_PRE_BINARY_ENCODED;
	    } else if (buf[0] == 'v') {
	      /*
	       * This case can have binary
	       * data as part of a
	       * file write. Go directly
	       * to binary data state
	       */
	      binary = true;
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
	      break;
	    }
	    buf[pkt_len++] = c;
	    rx_csum += c;
	  }
	} else if (state == STATE_BINARY_RAW) {
	  if (pkt_len >= buf_len) {
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
	    break;
	  }
	  if (esc_found) {
	    rx_csum += c;
	    esc_found = false;
	    c ^= 0x20;
	    buf[pkt_len++] = util_hex[(c >> 4) & 0xf];
	    buf[pkt_len++] = util_hex[c & 0xf];
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
	    buf[pkt_len++] = util_hex[(c >> 4) & 0xf];
	    buf[pkt_len++] = util_hex[c & 0xf];
	  }
	} else if (state == STATE_HASHMARK) {
	  /*
	   * Now get the first byte of the two
	   * byte checksum
	   */
	  nib = util_hex_nibble(c);
	  if (nib < 0) {
	    break;
	  }
	  calc_csum = (calc_csum << 4) | nib;
	  state = STATE_CSUM;
	} else if (state == STATE_CSUM) {
	  /* Now get the second byte of the checksum, and
	     check it. */
	  nib = util_hex_nibble(c);
	  if (nib < 0) {
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
	    ret = 0;
	    break;
	  }
	  break;
	} else {
	  /* Unreachable */
	  DBG_PRINT("gdb_interface : error scanner state\n");
	  break;
	}
      } else {
	/*
	 * In some cases, vFile:pwrite, no #XX is given
	 * In some cases it is, vFile:open.
	 * This shows up as an underlow.
	 * Check if we are handling a binary packet, if we are
	 * then assume the packet is ok and don't report the
	 * underflow
	 */
	if (binary) {
	  *len = pkt_len;
	  ret = 0;
	} else {
	  /* Failure */
	  DBG_PRINT("gdb_interface : error in underflow\n");
	}
	break;
      }
    }
  }
  return ret;
}

void handle_search_memory_command(char *in_buf, char *out_buf, gdb_target *t) {
  uint64_t addr;
  uint32_t pattern;
  uint32_t mask;
  char *in;
  /* Format: taddr:PP,MM
     Search backwards starting at address addr for a match with the
     supplied pattern PP and mask MM. PP and MM are 4 bytes. addr
     must be at least 3 digits. */
  in = &in_buf[1];
  if (!util_decode_uint64(&in, &addr, ':')) {
    gdb_interface_write_retval(RET_ERR, out_buf);
    return;
  }
  if (!util_decode_uint32(&in, &pattern, ',')) {
    gdb_interface_write_retval(RET_ERR, out_buf);
    return;
  }
  if (!util_decode_uint32(&in, &mask, '\0')) {
    gdb_interface_write_retval(RET_ERR, out_buf);
    return;
  }
  gdb_interface_write_retval(RET_NOSUPP, out_buf);
}

static int _decode_thread_id(char *in_buf, int64_t *process_id,
                             int64_t *thread_id) {
  int ret = 0; /* assume ok */
  char *in;
  *process_id = 0; /* Any process */
  *thread_id = 0;  /* Any thread */
  /* Check for 'p' for input in the form 'p<pid>.<tid>' */
  if (in_buf[0] == 'p') {
    in = &in_buf[1];
    if (!util_decode_int64(&in, process_id, '.')) {
      ret = 1;
    } else {
      if (!util_decode_int64(&in, thread_id, '\0'))
        ret = 1;
    }
  } else {
    in = &in_buf[0];
    /*
     * In some cases, the terminating character is not a null
     * This happens in vCont;Css:thread;c
     * So look for the second ';' and use that as a terminator
     */
    int term = '\0';
    if (strchr(in, ';'))
      term = ';';
    if (!util_decode_int64(&in, process_id, term))
      ret = 1;
  }
  return ret;
}

void handle_thread_commands(char *const in_buf, char *out_buf,
                            gdb_target *target) {
  int ret;
  if ((in_buf[1] == 'c') || (in_buf[1] == 'g')) {
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
  }
}

void handle_query_current_signal(char *out_buf, gdb_target *t) {
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

/* If a byte of avail is 0 then the corresponding data byte is
   encoded as 'xx', otherwise it is encoded in normal way */
static int gdb_encode_regs(const unsigned char *data,
                           const unsigned char *avail, size_t data_len,
                           char *out) {
  size_t i;

  ASSERT(data != NULL);
  ASSERT(avail != NULL);
  ASSERT(data_len > 0);
  ASSERT(out != NULL);

  for (i = 0; i < data_len; i++, data++, avail++, out += 2) {
    if (*avail) {
      util_encode_byte(*data, out);
    } else {
      *out = 'x';
      *(out + 1) = 'x';
    }
  }

  *out = 0;

  return TRUE;
}

void handle_read_registers_command(char *const in_buf, char *out_buf,
                                   gdb_target *t) {
  int ret;
  size_t len;
  unsigned char data_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];
  unsigned char avail_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];

  /* Get all registers. Format: 'g'. Note we do not do any
     data caching - all caching is done by the debugger */
  ret = t->read_registers(CURRENT_PROCESS_TID, data_buf, avail_buf,
                          sizeof(data_buf), &len);
  switch (ret) {
  case RET_OK:
    ASSERT(len <= GDB_INTERFACE_PARAM_DATABYTES_MAX);
    gdb_encode_regs(data_buf, avail_buf, len, out_buf);
    break;
  case RET_ERR:
  case RET_NOSUPP:
    gdb_interface_write_retval(RET_ERR, out_buf);
    /* This should not happen */
    ASSERT(0);
    break;
  }
}

/* Convert stream of chars into data */
static int gdb_decode_data(const char *in, unsigned char *out, size_t out_size,
                           size_t *len) {
  size_t count;
  uint8_t bytex;
  if ((in != NULL) &&
      (out != NULL) &&
      (out_size > 0) &&
      (len != NULL)) {
    for (count = 0; *in && count < out_size; count++, in += 2, out++) {
      if (*(in + 1) == '\0') {
	/* Odd number of nibbles. Discard the last one */
	if (count == 0)
	  return FALSE;
	*len = count;
	return TRUE;
      }
      if (!util_decode_byte(in, &bytex))
	return FALSE;
      *out = bytex & 0xff;
    }
    if (*in) {
      /* Input too long */
      return FALSE;
    }
    *len = count;
    return TRUE;
  } else {
    return FALSE;
  }
}

void handle_write_registers_command(char *const in_buf, char *out_buf,
                                    gdb_target *t) {
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

static bool _decode_reg_tid(char *const in_buf, uint32_t *reg, pid_t *tid) {
  bool ret = false;
  char *in = &in_buf[1];
  if (strchr(in, ';')) {
    int64_t thread_id;
    /* The QThreadSuffixSupported option */
    ret = util_decode_uint32(&in, reg, ';');
    if (!ret)
      goto end;
    if (strncmp(in, "thread:", 7) == 0) {
      in += 7;
      ret = util_decode_int64(&in, &thread_id, ';');
      if (!ret)
        goto end;
      *tid = thread_id;
    }
  } else {
    /* Get a single register. Format 'pNN' */
    ret = util_decode_reg(&in, reg);
    if (!ret)
      goto end;
  }
  ret = true;

end:
  return ret;
}
void handle_read_single_register_command(char *const in_buf, char *out_buf,
                                         gdb_target *t) {
  int ret;
  uint32_t reg_no;
  size_t len;
  alignas(4) unsigned char data_buf[64];
  alignas(4) unsigned char avail_buf[64];
  pid_t tid = CURRENT_PROCESS_TID;
  if (_decode_reg_tid(in_buf, &reg_no, &tid)) {
    ret = t->read_single_register(tid, reg_no, data_buf, avail_buf,
                                  sizeof(data_buf), &len);
    if (ret == RET_OK)
      gdb_encode_regs(data_buf, avail_buf, len, out_buf);
    else
      gdb_interface_write_retval(ret, out_buf);
  } else {
    gdb_interface_write_retval(RET_ERR, out_buf);
  }
}

void handle_write_single_register_command(char *const in_buf, char *out_buf,
                                          gdb_target *t) {
  int ret;
  unsigned int reg_no;
  size_t len;
  unsigned char data_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];

  /* Write a single register. Format: 'PNN=XXXXX' */
  ret = gdb_decode_reg_assignment(&in_buf[1], &reg_no, data_buf,
                                  sizeof(data_buf), &len);
  if (!ret) {
    gdb_interface_write_retval(RET_ERR, out_buf);
    return;
  }
  ASSERT(len < GDB_INTERFACE_PARAM_DATABYTES_MAX);

  ret = t->write_single_register(CURRENT_PROCESS_TID, reg_no, data_buf, len);
  gdb_interface_write_retval(ret, out_buf);
}

void handle_read_memory_command(char *const in_buf, char *out_buf,
                                gdb_target *t) {
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
  if (len > ((RP_VAL_DBG_PBUFSIZ - 32) / 2))
    len = (RP_VAL_DBG_PBUFSIZ - 32) / 2;

  ret = t->read_mem(CURRENT_PROCESS_TID, addr, data_buf, len, &read_len);
  switch (ret) {
  case RET_OK:
    ASSERT(len <= GDB_INTERFACE_PARAM_DATABYTES_MAX);
    util_encode_data(data_buf, len, out_buf, INOUTBUF_SIZE);
    break;
  case RET_ERR:
    if (cmdline_silence_memory_read_errors) {
      memset(data_buf, 0, len);
      util_encode_data(data_buf, len, out_buf, INOUTBUF_SIZE);
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

void handle_write_memory_command(char *const in_buf, char *out_buf,
                                 gdb_target *t) {
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
  if (!ret || len > GDB_INTERFACE_PARAM_DATABYTES_MAX) {
    gdb_interface_write_retval(RET_ERR, out_buf);
    return;
  }

  ret = gdb_decode_data(cp + 1, data_buf, sizeof(data_buf), &len1);
  if (!ret || len != len1) {
    gdb_interface_write_retval(RET_ERR, out_buf);
    return;
  }

  ret = t->write_mem(CURRENT_PROCESS_TID, addr, data_buf, len);
  gdb_interface_write_retval(ret, out_buf);
}

static int _target_wait(char *out_buf, gdb_target *target, int step, int sig) {
  int ret = RET_NOSUPP;
  if (target->wait) {
    /*
     * Sometimes 'wait' is used internally
     * If wait returns an ignore status, do not send
     * update to gdb, continue and go back to waiting
     */
    do {
      /* Check for Debugee console output */
      if (gPipeStdout[0] > 0) {
        char buf[1024];
        ssize_t read_size;
        while (0 < (read_size = read(gPipeStdout[0], &buf[0], 1023))) {
          /* gdb_interface_put_console depends on string to be null terminated
           */
          buf[read_size] = 0;
          /* Out to deebe console */
          fprintf(stdout, "%s", buf);
          /* Back to gdb */
          gdb_interface_put_console(buf);
          network_write();
        }
      }
      ret = target->wait(out_buf, step, false);
      if (ret == RET_IGNORE) {
        target->resume_from_current(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID,
                                    step, sig);
      }
    } while ((ret == RET_IGNORE) || (ret == RET_CONTINUE_WAIT));
  }
  return ret;
}

void handle_running_commands(char *const in_buf, char *out_buf,
                             gdb_target *target) {
  int step;
  uint32_t sig;
  int go;
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

  step = (in_buf[0] == 'S' || in_buf[0] == 's');
  go = (in_buf[0] == 'W' || in_buf[0] == 'w');

  addr_ptr = NULL;

  if (in_buf[0] == 'C' || in_buf[0] == 'S' || in_buf[0] == 'W') {
    /*
     * Resume with signal.
     * Format Csig[;AA..AA], Ssig[;AA..AA], or Wsig[;AA..AA]
     */

    in = &in_buf[1];
    if (strchr(in, ';')) {
      if (!util_decode_uint32(&in, &sig, ';')) {
        gdb_interface_write_retval(RET_ERR, out_buf);
        return;
      }
      addr_ptr = in;
    } else {
      if (!util_decode_uint32(&in, &sig, '\0')) {
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
    ret = target->go_waiting(sig);
  } else if (addr_ptr) {
    if (!util_decode_uint64(&addr_ptr, &addr, '\0')) {
      gdb_interface_write_retval(RET_ERR, out_buf);
      return;
    } /* XXX */
    ret = target->resume_from_addr(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID,
                                   step, sig, addr);
  } else { /* XXX */
    ret = target->resume_from_current(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID,
                                      step, sig);
  }
  if (ret != RET_OK) {
    gdb_interface_write_retval(ret, out_buf);
    return;
  }
  ret = _target_wait(out_buf, target, step, sig);
  if (ret != RET_OK) {
    gdb_interface_write_retval(ret, out_buf);
  }
}

int handle_kill_command(char *const in_buf, char *out_buf, gdb_target *t) {
  int ret;

  t->kill(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID);

  if (!extended_protocol) {
    return FALSE;
  }
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
    gdb_interface_write_retval(RET_ERR, out_buf);
    network_put_dbg_packet(out_buf, 0);
    return FALSE;
  }
  return TRUE;
}

void handle_thread_alive_command(char *const in_buf, char *out_buf,
                                 gdb_target *target) {
  int ret;
  int alive;
  /* Is thread alive? */
  /* This is a deprecated feature of the remote debug protocol */
  int64_t p, t;
  if (_decode_thread_id(&in_buf[1], &p, &t)) {
    gdb_interface_write_retval(RET_ERR, out_buf);
  } else {
    ret = target->is_thread_alive(p, t, &alive);
    if ((ret != RET_OK) || !alive)
      gdb_interface_write_retval(RET_ERR, out_buf);
    else
      gdb_interface_write_retval(RET_OK, out_buf);
  }
}

int handle_restart_target_command(char *const in_buf, char *out_buf,
                                  gdb_target *t) {
  int ret;
  /* Restarting the target is only supported in the extended protocol. */
  if (!extended_protocol)
    return FALSE;
  /* Let us do our best to restart the system */
  ret = t->restart();
  if (ret != RET_OK) {
    /* There is no point to continuing */
    gdb_interface_write_retval(RET_ERR, out_buf);
    network_put_dbg_packet(out_buf, 0);
    return -1;
  }
  return TRUE;
}

void handle_detach_command(char *const in_buf, char *out_buf, gdb_target *t) {
  int ret = RET_NOSUPP;
  if (t->detach)
    ret = t->detach();
  else
    t->disconnect();
  gdb_interface_write_retval(ret, out_buf);
  /* Note: The current GDB does not expect a reply */
  network_put_dbg_packet(out_buf, 0);
  /* lldb does expect a reply, so flush */
  network_write();

  /* If we created the target process (not attached to it), wait for the
     process to finish on detach */
  if (!target_is_attached() && t->detach_wait) {
    t->detach_wait();
  }

  /* Exit now or we will appear to be wedged */
  exit(0);
}

static bool gdb_handle_qxfer_command(char *const in_buf, char *out_buf,
                                     bool *binary_cmd, gdb_target *t) {
  char *n = in_buf + 1;
  bool req_handled = false;
  if (strncmp(n, "Xfer:auxv:read::", 16) == 0) {
    if (t->read_auxv) {
      bool status = false;
      uint32_t offset, usize;
      size_t size;
      char *in = &n[16];
      if (util_decode_uint32(&in, &offset, ',')) {
        if (util_decode_uint32(&in, &usize, '\0')) {
          status = true;
        }
      }
      if (status == true) {
        size = usize;
        status = t->read_auxv(out_buf, INOUTBUF_SIZE, offset, &size);
      }

      if (status == false) {
        gdb_interface_write_retval(RET_ERR, out_buf);
      } else {
        network_put_dbg_packet(out_buf, size);
        *binary_cmd = true;
      }

      req_handled = true;
    }
    goto end;
  }

end:
  return req_handled;
}

/* Encode result of list query:
   qMCCDAAAAAAAAAAAAAAAA(FFFFFFFFFFFFFFFF)*,
   where
   C   reprsents  count
   D   represents done
   A   represents arg thread reference
   F   represents found thread reference(s) */
static int rp_encode_list_query_response(size_t count, int done,
                                         const gdb_thread_ref *arg,
                                         const gdb_thread_ref *found,
                                         char *out) {
  size_t i;
  int ret = FALSE;
  if ((arg != NULL) &&
      (found != NULL || count == 0) &&
      (count <= 255)) {
    *out++ = 'q';
    *out++ = 'M';
    util_encode_byte(count, out);
    out += 2;
    *out++ = (done) ? '1' : '0';
    sprintf(out, "%016" PRIu64 "x", arg->val);
    out += 16;
    /* Encode found */
    for (i = 0; i < count; i++, found++) {
      sprintf(out, "%016" PRIu64 "x", found->val);
      out += 16;
    }
    ret = TRUE;
  }
  return ret;
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
                                            char *out) {
  int ret = 0;
  if ((ref != NULL) &&
      (info != NULL) &&
      (out != NULL)) {
    size_t len;
    unsigned int tag;
    int i;
    /* Encode header */
    *out++ = 'q';
    *out++ = 'Q';
    /* Encode mask */
    sprintf(out, "%08x", mask);
    out += 8;
    /* Encode reference thread */
    sprintf(out, "%016" PRIu64 "x", ref->val);
    out += 16;
    for (i = 0, tag = 0; i < 32; i++, tag <<= 1) {
      if ((mask & tag) == 0)
	continue;
      /* Encode tag */
      sprintf(out, "%08x", tag);
      out += 8;
      switch (tag) {
      case RP_BIT_PROCQMASK_THREADID:
	/* Encode length - it is 16 */
	util_encode_byte(16, out);
	out += 2;
	/* Encode value */
	sprintf(out, "%016" PRIu64 "x", info->thread_id.val);
	out += 16;
	break;
      case RP_BIT_PROCQMASK_EXISTS:
	/* Encode Length */
	util_encode_byte(1, out);
	out += 2;
	/* Encode value */
	*out++ = (info->exists) ? '1' : '0';
	*out = 0;
	break;
      case RP_BIT_PROCQMASK_DISPLAY:
	/* Encode length */
	len = strlen(info->display);
	ASSERT(len <= 255);
	util_encode_byte(len, out);
	out += 2;
	/* Encode value */
	strcpy(out, info->display);
	out += len;
	break;
      case RP_BIT_PROCQMASK_THREADNAME:
	/* Encode length */
	len = strlen(info->thread_name);
	ASSERT(len <= 255);
	util_encode_byte(len, out);
	out += 2;
	/* Encode value */
	strcpy(out, info->thread_name);
	out += len;
	break;
      case RP_BIT_PROCQMASK_MOREDISPLAY:
	/* Encode length */
	len = strlen(info->more_display);
	ASSERT(len <= 255);
	util_encode_byte(len, out);
	out += 2;
	/* Encode value */
	strcpy(out, info->more_display);
	out += len;
	break;
      default:
	/* Unexpected tag value */
	goto end;
      }
    }
    ret = 1;
  }
 end:
  return ret;
}

int symbol_lookup(const char *name, uintptr_t *addr)
{
  int s, ret = RET_ERR;
  uint64_t sym_addr;
  size_t in_len = 0;
  char *in;

  sprintf(out_buf, "qSymbol:");
  util_encode_string(name, out_buf + 8, strlen(name) * 2 + 1);
  network_put_dbg_packet(out_buf, 0);
  network_write();
  while (network_read() != 0) {}
  s = gdb_interface_getpacket(in_buf, &in_len, true /* do acks */);
  network_clear_read();
  if (strncmp(in_buf, "qSymbol:", 8) == 0) {
    in = in_buf + 8;
    if (util_decode_uint64(&in, &sym_addr, ':') && sym_addr) {
      *addr = (uintptr_t) sym_addr;
      ret = RET_OK;
    }
    else {
      *addr = 0;
    }
	
  }
  return ret;
}

static void handle_qsymbol_command(char *out_buf, gdb_target *t)
{
#ifdef HAVE_THREAD_DB_H
  static int threads_initialized = RET_ERR;
  if (threads_initialized == RET_OK)
    return;
  else
    threads_initialized = initialize_thread_db (CURRENT_PROCESS_PID, t);
#endif
}

static bool gdb_handle_query_command(char *const in_buf, size_t in_len, char *out_buf,
                                     gdb_target *t) {
  int status;
  uint32_t val;
  uint64_t addr;
  char str[128];
  char *n = in_buf + 1;

  bool req_handled = false;

  switch (*n) {
  case 'f':
    if (strncmp(n, "fThreadInfo", 11) == 0) {
      if (t->threadinfo_query == NULL)
        gdb_interface_write_retval(RET_NOSUPP, out_buf);
      else
        t->threadinfo_query(1, out_buf);
      req_handled = true;
      goto end;
    } else if (strncmp(n, "fProcessInfo", 12) == 0) {
      /* Get first string of process info */
      gdb_interface_write_retval(RET_NOSUPP, out_buf);
      req_handled = true;
      goto end;
    }
    break;
  case 's':
    if (strncmp(n, "sThreadInfo", 11) == 0) {
      if (t->threadinfo_query == NULL)
        gdb_interface_write_retval(RET_NOSUPP, out_buf);
      else
        t->threadinfo_query(0, out_buf);
      req_handled = true;
      goto end;
    } else if (strncmp(n, "sProcessInfo", 12) == 0) {
      /* Get subsequent string of process info */
      gdb_interface_write_retval(RET_NOSUPP, out_buf);
      req_handled = true;
      goto end;
    }
    break;
  case 'A':
    if (strncmp(n, "Attached:", 9) == 0) {
      gdb_interface_write_retval(RET_NOSUPP, out_buf);
      req_handled = true;
      goto end;
    } else if (strncmp(n, "Attached", 8) == 0) {
      bool is_attached = target_is_attached();
      if (is_attached)
        sprintf(out_buf, "1");
      else
        sprintf(out_buf, "0");
      req_handled = true;
      goto end;
    }
    break;
  case 'C':
    if (strncmp(n, "CRC:", 4) == 0) {
      char *cp = &in_buf[5];
      unsigned int len;
      /* Find the CRC32 value of the specified memory area */
      if (!util_decode_uint64(&cp, &addr, ',')) {
        gdb_interface_write_retval(RET_ERR, out_buf);
        req_handled = true;
        goto end;
      }
      if (!util_decode_uint32(&cp, &len, '\0')) {
        gdb_interface_write_retval(RET_ERR, out_buf);
        req_handled = true;
        goto end;
      }
      status = t->crc_query(addr, len, &val);
      if (status == RET_OK)
        sprintf(out_buf, "C%x", val);
      else
        gdb_interface_write_retval(status, out_buf);
      req_handled = true;
      goto end;
    } else {
      int64_t process, thread;
      /* Current thread query */
      status = t->current_thread_query(&process, &thread);
      if (status == RET_OK) {
        /*
         * LLDB only want the thread id
         *
         * GDB
         * On FreeBSD the thread id is not known until later
         * Until that happens the thread id is process id.
         * Do not report this back to gdb because then it will
         * be confused when the thread is is set later.
         */
        if (_target.lldb) {
          sprintf(out_buf, "QC%" PRIx64, thread);
        } else {
	  /* For gdb, return .-1 to indicate this is the main pid/thread */
	  sprintf(out_buf, "QCp%" PRIx64 ".-1", process);
        }
      } else {
        gdb_interface_write_retval(status, out_buf);
        req_handled = true;
        goto end;
      }
    }
    break;
  case 'G':
    if (strncmp(n, "GetTLSAddr:", 11) == 0) {
      int64_t thread_id;
      uint64_t lm;
      uintptr_t tlsaddr;
      char *cp = &in_buf[12];
      if (!util_decode_int64(&cp, &thread_id, ',')) {
        gdb_interface_write_retval(RET_ERR, out_buf);
        req_handled = true;
        goto end;
      }
      if (!util_decode_uint64(&cp, &addr, ',')) {
        gdb_interface_write_retval(RET_ERR, out_buf);
        req_handled = true;
        goto end;
      }
      if (!util_decode_uint64(&cp, &lm, '\0')) {
        gdb_interface_write_retval(RET_ERR, out_buf);
        req_handled = true;
        goto end;
      }
      if (t->get_tls_address) {
	if (t->get_tls_address(thread_id, addr, lm, &tlsaddr) == RET_OK) {
	  sprintf(out_buf, "%" PRIxPTR, tlsaddr);
	  req_handled = true;
	}
	else {
	  gdb_interface_write_retval(RET_ERR, out_buf);
	  req_handled = true;
	}
      }
    }
    break;
  case 'L': {
    int done, first;
    size_t count, max_found;
    gdb_thread_ref arg, *found;

    /* Thread list query */
    status = rp_decode_list_query(&in_buf[2], &first, &max_found, &arg);
    if (!status || max_found > 255) {
      gdb_interface_write_retval(RET_ERR, out_buf);
      req_handled = true;
      goto end;
    }
    found = malloc(max_found * sizeof(gdb_thread_ref));
    if (found == NULL) {
      gdb_interface_write_retval(RET_ERR, out_buf);
      req_handled = true;
      goto end;
    }
    status = t->list_query(first, &arg, found, max_found, &count, &done);
    if (status != RET_OK || count > max_found) {
      free(found);
      gdb_interface_write_retval(status, out_buf);
      req_handled = true;
      goto end;
    }
    status = rp_encode_list_query_response(count, done, &arg, found, out_buf);
    free(found);
    if (!status)
      gdb_interface_write_retval(RET_ERR, out_buf);

    req_handled = true;
    goto end;
  } break;

  case 'O':
    if (strncmp(n, "Offsets", 7) == 0) {
      uint64_t text, data, bss;
      /* Get the program segment offsets */
      status = t->offsets_query(&text, &data, &bss);
      if (status == RET_OK)
        sprintf(out_buf,
                "Text=%016" PRIu64 ";Data=%016" PRIu64 ";Bss=%016" PRIu64 "",
                text, data, bss);
      else
        gdb_interface_write_retval(status, out_buf);
      req_handled = true;
      goto end;
    }
    break;
  case 'P': {
    rp_thread_info info;
    gdb_thread_ref ref;
    unsigned int mask;

    /* Thread info query */
    status = rp_decode_process_query(&in_buf[2], &mask, &ref);
    if (!status) {
      gdb_interface_write_retval(RET_ERR, out_buf);
      req_handled = true;
      goto end;
    }
    info.thread_id.val = 0;
    info.display[0] = 0;
    info.thread_name[0] = 0;
    info.more_display[0] = 0;
    status = t->process_query(&mask, &ref, &info);
    if (status != RET_OK) {
      gdb_interface_write_retval(status, out_buf);
      req_handled = true;
      goto end;
    }
    status = rp_encode_process_query_response(mask, &ref, &info, out_buf);
    if (!status)
      gdb_interface_write_retval(RET_ERR, out_buf);

    req_handled = true;
    goto end;
  } break;
  case 'R':
    if (strncmp(n, "Rcmd,", 5) == 0) {
      /* Remote command */
      status = RET_NOSUPP;
      gdb_interface_write_retval(status, out_buf);
      req_handled = true;
      goto end;
    }
    break;
  case 'S':
    if (strncmp(n, "Supported", 9) == 0) {
      /*
       * Check if we were passed an xmlRegisters token as in
       * qSupported:xmlRegisters=i386,arm,mips
       * This mean we need to write registers back in xml
       */
      sprintf(str, "Supported");
      n += strlen(str);
      sprintf(str, ":xmlRegisters=");
      if (strncmp(n, str, strlen(str)) == 0) {
        n += strlen(str);
        if (t->get_xml_register_string != NULL) {
          const char *xml_register_string = t->get_xml_register_string();
          if (xml_register_string != NULL) {
            size_t xml_register_string_length = strlen(xml_register_string);
            size_t n_length = strlen(n);
            if (xml_register_string_length) {
              while (n_length >= xml_register_string_length) {
                if (strncmp(n, xml_register_string,
                            xml_register_string_length) == 0) {
                  if (t->set_xml_register_reporting != NULL)
                    t->set_xml_register_reporting();
                  break;
                } else {
                  /* Look for ',' and advance past */
                  char *comma_location = strchr(n, ',');
                  if (comma_location == NULL) {
                    /* last register string to compare, give up */
                    break;
                  } else if (comma_location <= n) {
                    /* unexpected pointer at/before start */
                    break;
                  } else if ((comma_location - n) >= n_length) {
                    /* unexpected pointer past end */
                    break;
                  } else {
                    /* Looks ok, advance past */
                    n = comma_location + 1;
                    n_length = strlen(n);
                  }
                }
              }
            }
          }
        }
      }

      /* Features supported */
      if (t->supported_features_query == NULL)
        gdb_interface_write_retval(RET_NOSUPP, out_buf);
      else
        t->supported_features_query(out_buf);
      req_handled = true;
      goto end;
    } else if (strncmp(n, "Symbol::", 8) == 0) {
      handle_qsymbol_command(out_buf, t);
      gdb_interface_write_retval(RET_OK, out_buf);
      req_handled = true;
      goto end;
    } else if (strncmp(n, "Symbol:", 7) == 0) {
      gdb_interface_write_retval(RET_NOSUPP, out_buf);
      req_handled = true;
      goto end;
    } else if (strncmp(n, "Search:memory:", 14) == 0) {
      sprintf(str, "Search:memory:");
      n += strlen(str);
      /* Look for addr */
      uint64_t addr;
      if (util_decode_uint64(&n, &addr, ';')) {
        uint32_t len;
        if (util_decode_uint32(&n, &len, ';')) {
	  size_t bmax = in_len - (n - in_buf);
          uint8_t *pattern = (uint8_t *)malloc(bmax * sizeof(uint8_t));
          if (pattern) {
            size_t pattern_len = 0;
	    /*
	     * gdb doc says pattern is hex-encoded.
	     * The pattter in really escaped binary
	     */
	    pattern_len = util_escape_binary(pattern, (uint8_t *)n, bmax);
            if (pattern_len > 0) {
              if (pattern_len <= len) {
                uint8_t *read_buf = (uint8_t *)malloc(len);
                if (read_buf) {
                  if (t->read_mem) {
                    size_t bytes_read;
                    if (RET_OK ==
                        t->read_mem(CURRENT_PROCESS_TID, addr, read_buf, len,
                                    &bytes_read)) {
                      if (bytes_read == len) {
                        void *found = NULL;
                        found = memmem(read_buf, len, pattern, pattern_len);
                        if (NULL != found) {
                          uint64_t loc = addr;
                          loc += (found - (void *)read_buf);
                          sprintf(out_buf, "1,%016" PRIx64 "", loc);
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
      req_handled = true;
      goto end;
    }
    break;

  case 'T':
    if (strncmp(n, "TStatus", 7) == 0) {
      /* sprintf(out_buf, "T0"); */
      gdb_interface_write_retval(RET_NOSUPP, out_buf);
      req_handled = true;
      goto end;
    } else if (strncmp(n, "ThreadExtraInfo,", 16) == 0) {
      char data_buf[GDB_INTERFACE_PARAM_DATABYTES_MAX];
      char *in;
      int64_t thread_id;
      if (t->threadextrainfo_query == NULL) {
        gdb_interface_write_retval(RET_NOSUPP, out_buf);
      } else {
        in = &in_buf[17];
        status = util_decode_int64(&in, &thread_id, '\0');
        if (!status) {
          gdb_interface_write_retval(RET_ERR, out_buf);
          req_handled = true;
          goto end;
        }
        status = t->threadextrainfo_query(thread_id, data_buf);
        switch (status) {
        case RET_OK:
          util_encode_data((unsigned char *)data_buf, strlen(data_buf), out_buf,
                           INOUTBUF_SIZE);
          break;
        case RET_ERR:
        case RET_NOSUPP:
          gdb_interface_write_retval(status, out_buf);
          break;
        default:
          ASSERT(0);
          break;
        }
      }
      req_handled = true;
      goto end;
    }
    break;

  default:
    break;
  }
end:
  return req_handled;
}

/* Decode a breakpoint (z or Z) packet */
static int gdb_decode_break(char *in, int *type, uint64_t *addr,
                            unsigned int *len) {
  uint8_t val;
  ASSERT(in != NULL);
  ASSERT(*in != '\0');
  ASSERT(type != NULL);
  ASSERT(addr != NULL);
  ASSERT(len != NULL);
  in++;
  if (!util_decode_nibble(in, &val))
    return FALSE;
  in++;
  if (*in++ != ',')
    return FALSE;
  *type = val;
  if (!util_decode_uint64(&in, addr, ','))
    return FALSE;
  if (!util_decode_uint32(&in, len, '\0'))
    return FALSE;
  return TRUE;
}

static void handle_breakpoint_command(char *const in_buf, char *out_buf,
                                      gdb_target *t) {
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

#define GDB_OPEN_RDONLY 0x0
#define GDB_OPEN_WRONLY 0x1
#define GDB_OPEN_RDWR 0x2
#define GDB_OPEN_APPEND 0x8
#define GDB_OPEN_CREAT 0x200
#define GDB_OPEN_TRUNC 0x400
#define GDB_OPEN_EXCL 0x800

/* Logic does not work for RDONLY */
#define GDB_OPEN_FLAG(f, g, N)                                                 \
  if ((GDB_OPEN_##N) == ((g) & (GDB_OPEN_##N)))                                \
  f |= (O_##N)
/* Special REDONLY */
#define GDB_OPEN_FLAG_RDONLY(g) (!(g & 0xf))

#define GDB_OPEN_IFREG 0100000
#define GDB_OPEN_IFDIR 040000
#define GDB_OPEN_IRUSR 0400
#define GDB_OPEN_IWUSR 0200
#define GDB_OPEN_IXUSR 0100
#define GDB_OPEN_IRGRP 040
#define GDB_OPEN_IWGRP 020
#define GDB_OPEN_IXGRP 010
#define GDB_OPEN_IROTH 04
#define GDB_OPEN_IWOTH 02
#define GDB_OPEN_IXOTH 01

#define GDB_MODE(m, g, N)                      \
  if (GDB_OPEN_##N == ((g) & (GDB_OPEN_##N)))  \
  m |= S_##N

#define GDB_MODES(m, g) \
  GDB_MODE(m, g, IXOTH); \
  GDB_MODE(m, g, IWOTH); \
  GDB_MODE(m, g, IROTH); \
  GDB_MODE(m, g, IXGRP); \
  GDB_MODE(m, g, IWGRP); \
  GDB_MODE(m, g, IRGRP); \
  GDB_MODE(m, g, IXUSR); \
  GDB_MODE(m, g, IWUSR); \
  GDB_MODE(m, g, IRUSR); \
  GDB_MODE(m, g, IFDIR); \
  GDB_MODE(m, g, IFREG);


#define POSIX_MODE(m, g, N)       \
  if (S_##N == ((m) & (S_##N)))   \
  g |= GDB_OPEN_##N

#define POSIX_MODES(m, g) \
  POSIX_MODE(m, g, IXOTH); \
  POSIX_MODE(m, g, IWOTH); \
  POSIX_MODE(m, g, IROTH); \
  POSIX_MODE(m, g, IXGRP); \
  POSIX_MODE(m, g, IWGRP); \
  POSIX_MODE(m, g, IRGRP); \
 POSIX_MODE(m, g, IXUSR); \
  POSIX_MODE(m, g, IWUSR); \
  POSIX_MODE(m, g, IRUSR); \
  POSIX_MODE(m, g, IFDIR); \
  POSIX_MODE(m, g, IFREG);

#pragma pack(1)
struct gdb_stat {
  uint32_t st_dev;
  uint32_t st_ino;
  uint32_t st_mode;
  uint32_t st_nlink;
  uint32_t st_uid;
  uint32_t st_gid;
  uint32_t st_rdev;
  uint64_t st_size;
  uint64_t st_blksize;
  uint64_t st_blocks;
  uint32_t st_a;
  uint32_t st_m;
  uint32_t st_c;
};

static int handle_v_command(char *const in_buf, size_t in_len, char *out_buf,
                            gdb_target *target) {
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
      sprintf(out_buf, "vCont;c;C;s;S");
      handled = true;
    } else if (n[0] == ';') {
      n++;
      int step = ((n[0] == 'S') || (n[0] == 's')) ? 1 : 0;
      uint8_t sig = 0;
      bool err = false;
      int64_t p, t;
      p = t = -1;
      char *in = &n[1];
      if ((n[0] == 'C') || (n[0] == 'S')) {
        util_decode_byte(in, &sig);
        in += 2;
      }
      /*
       * Handle the case where the continue applies to a specific thread
       * Look for ':<thread-id> '
       */
      if (strlen(in) > 2) {
        if (in[0] == ':') {
          if (0 == _decode_thread_id(&in[1], &p, &t)) {
            target->set_gen_thread(p, t);
            /*
             * Sending signals to individual threads is not
             * supported.
             */
            if (target_number_threads() != 1)
              sig = 0;
          }
        }
      }
      /*
       * Gdb can pass a list of continue/step commands for more than
       * one thread.  We ignore all but the first
       */
      if (!err) {
        ret = target->resume_from_current(CURRENT_PROCESS_PID,
                                          CURRENT_PROCESS_TID, step, sig);
        if (RET_OK == ret) {
          ret = _target_wait(out_buf, target, step, sig);
          handled = true;
        }
      }
    }
  }
  sprintf(str, "vFile:");
  if (strncmp(str, n, strlen(str)) == 0) {
    int fd = -1;
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
        ms = strchr(fs + 1, ',');
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
          char *filepath = (char *)malloc((fs - n) / 2);
          if (filepath) {
            uint8_t *tp;
            for (t = n, tp = (uint8_t *)filepath; t < fs - 1 && status;
                 t += 2, tp++) {
              status = util_decode_byte(t, tp);
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
		  char *rpath = NULL;
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
                  GDB_MODES(mode, gdb_mode);
		  rpath = realpath(filepath, NULL);
		  errno = 0;
		  if (rpath) {
		    fd = open(rpath, flag, mode);
		    free(rpath);
		    rpath = NULL;
		  } else {
		    fd = open(filepath, flag, mode);
		  }
                  if (fd > 0) {
                    /* Success */
                    ret = RET_OK;
                  }
		  if (fd < 0) {
		    sprintf(out_buf, "F%d,%d", -1, errno);
		  } else {
		    sprintf(out_buf, "F%x", fd);
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
        char *filepath = (char *)malloc(1 + (fe - n) / 2);
        if (filepath) {
          uint8_t *tp = NULL;
          char *t = NULL;
          int status = -1;
          for (t = n, tp = (uint8_t *)filepath; t < fe && status;
               t += 2, tp++) {
            status = util_decode_byte(t, tp);
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
      int fd = -1;
      n += strlen(str);
      handled = true;
      /*
       * Looking for
       * FD, OFFSET, DATA
       */
      end = NULL;
      fd = strtol(n, &end, 10);
      if (end != n) {
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
	   */
	  if ((n - in_buf) < in_len) {
	    if (off != lseek(fd, off, SEEK_SET)) {
	      /* Error */
	      sprintf(out_buf, "F%d", -1);
	    } else {
	      size_t bytes_to_write = 0;
	      size_t bytes_written = 0;
	      bytes_to_write = in_len - (n - in_buf);
	      /* Data is binary, no need to decode */
	      bytes_written = write(fd, n, bytes_to_write);
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
    }
    sprintf(str, "pread:");
    if (strncmp(str, n, strlen(str)) == 0) {
      int fd = -1;
      n += strlen(str);
      handled = true;
      /*
       * Looking for
       * FD, SIZE, OFFSET
       */
      end = NULL;
      fd = strtol(n, &end, 10);
      if (end != n) {
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
	    if (off != lseek(fd, off, SEEK_SET)) {
	      /* Error */
	      sprintf(out_buf, "F%d", -1);
	    } else {
	      size_t bytes_read = 0;
	      uint8_t *buf = (uint8_t *)malloc(size);
	      if (buf) {
		size_t preamble_size = 0;
		size_t escaped_size = 0;
		uint8_t *dst = NULL;
		/* The fs read */
		bytes_read = read(fd, buf, size);
		/* The preamble size */
		preamble_size = sprintf(out_buf, "F%zx;", bytes_read);
		/* this is binary data, need to escape special chars */
		dst = (uint8_t *)out_buf + preamble_size;
		escaped_size = util_escape_binary(dst, buf, bytes_read);
		/* send packet out here because being binary, can not use
		 * upstream packet put */
		ret = network_put_dbg_packet(out_buf,
					     escaped_size + preamble_size);
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
    }
    sprintf(str, "close:");
    if (strncmp(str, n, strlen(str)) == 0) {
      int fd = -1;
      n += strlen(str);
      handled = true;
      end = NULL;
      fd = strtol(n, &end, 10);
      if (end != n) {
	int status = close(fd);
	sprintf(out_buf, "F%d", status);
	if (0 == status)
	  ret = RET_OK;
      } else {
	/* Error */
	sprintf(out_buf, "F%d", -1);
      }
    }
    sprintf(str, "setfs:");
    if (strncmp(str, n, strlen(str)) == 0) {
      int pid;
      n += strlen(str);
      handled = true;
      end = NULL;
      pid = strtol(n, &end, 10);
      if (end != n) {
	if (pid == 0) {
	  /* Handle the trivial case */
	  sprintf(out_buf, "F0");
	} else {
	  /* bail */
	  sprintf(out_buf, "F%d", -1);
	}
      } else {
	/* Error */
	sprintf(out_buf, "F%d", -1);
      }
    }
    sprintf(str, "fstat:");
    if (strncmp(str, n, strlen(str)) == 0) {
      int fd = -1;
      n += strlen(str);
      handled = true;
      end = NULL;
      fd = strtol(n, &end, 10);
      if (end != n) {
	struct stat buf = { 0 };
	errno = 0;
	if (fstat(fd, &buf) == 0) {
	  struct gdb_stat g = { 0 };
	  size_t preamble_size = 0;
	  size_t escaped_size = 0;
	  uint8_t *dst = NULL;
	  g.st_dev = 0;
	  g.st_ino = buf.st_ino;
	  POSIX_MODES(buf.st_mode, g.st_mode);
	  g.st_nlink = buf.st_nlink;
	  g.st_uid = buf.st_uid;
	  g.st_gid = buf.st_gid;
	  g.st_rdev = buf.st_rdev;
	  g.st_size = buf.st_size;
	  g.st_blksize = buf.st_blksize;
	  g.st_blocks = buf.st_blocks;
	  g.st_a = buf.st_atim.tv_sec;
	  g.st_m = buf.st_mtim.tv_sec;
	  g.st_c = buf.st_ctim.tv_sec;
	  preamble_size = sprintf(out_buf, "F%zx;", sizeof(struct gdb_stat));
	  dst = (uint8_t *)out_buf + preamble_size;
	  escaped_size = util_escape_binary(dst, (uint8_t *)&g, sizeof(struct gdb_stat));
	  ret = network_put_dbg_packet(out_buf, escaped_size + preamble_size);
	  out_buf[0] = 0; /* null terminated */
	  binary_cmd = true;
	} else {
	  sprintf(out_buf, "F%d,%d", -1, errno);
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
    network_put_dbg_packet(out_buf, 0);
  }
  return ret;
}

static void gdb_handle_general_set_command(char *const in_buf, char *out_buf,
                                           gdb_target *target) {
  int ret = RET_ERR;
  char *n = in_buf + 1;
  switch (*n) {
  case 'N':
    if (strncmp(n, "NonStop:", 8) == 0) {
      n += 8;
      if (*n == '0') {
        _target.nonstop = NS_OFF;
      } else {
        _target.nonstop = NS_ON;
      }
      ret = RET_OK;
      goto end;
    }
    break;

  case 'S':
    if (strncmp(n, "StartNoAckMode", 14) == 0) {
      _target.ack = false;
      ret = RET_OK;
      goto end;
    }
    break;

  default:
    break;
  }
end:
  gdb_interface_write_retval(ret, out_buf);
}

/* Decode reg_no=XXXXXX */
static int gdb_decode_reg_assignment(char *in, unsigned int *reg_no,
                                     unsigned char *out, size_t out_size,
                                     size_t *out_len) {
  ASSERT(in != NULL);
  ASSERT(reg_no != NULL);
  ASSERT(out != NULL);
  ASSERT(out_size > 0);
  ASSERT(out_len != NULL);

  if (!util_decode_uint32(&in, reg_no, '='))
    return FALSE;

  out_size -= 8;

  return gdb_decode_data(in, out, out_size - 1, out_len);
}

/* Decode memory transfer parameter in the form of AA..A,LL..L */
static int gdb_decode_mem(char *in, uint64_t *addr, size_t *len) {
  int ret = FALSE;
  if ((in != NULL) &&
      (addr != NULL) &&
      (len != NULL)) {
    *len = 0;
    if (util_decode_uint64(&in, addr, ',')) {
      /* On 64 bit, size_t != uint32_t */
      uint32_t l = 0;
      if (util_decode_uint32(&in, &l, '\0')) {
	*len = l;
	ret = TRUE;
      }
    }
  }
  return ret;
}

/* Decode process query. Format: 'MMMMMMMMRRRRRRRRRRRRRRRR'
   where:
   M represents mask
   R represents thread reference */
static int rp_decode_process_query(const char *in, unsigned int *mask,
                                   gdb_thread_ref *ref) {
  unsigned int tmp_mask;
  uint64_t tmp_val;
  int ret = FALSE;
  if ((in != NULL) &&
      (mask != NULL) &&
      (ref != NULL)) {
    if (rp_decode_4bytes(in, &tmp_mask)) {
      in += 8;
      if (rp_decode_8bytes(in, &tmp_val)) {
	*mask = tmp_mask;
	ref->val = tmp_val;
	ret = TRUE;
      }
    }
  }
  return ret;
}

/* Decode thread list list query. Format 'FMMAAAAAAAAAAAAAAAA'
   where:
   F represents first flag
   M represents max count
   A represents argument thread reference */
static int rp_decode_list_query(const char *in, int *first, size_t *max,
                                gdb_thread_ref *arg) {
  uint8_t first_flag;
  uint8_t tmp_max;
  uint64_t tmp_val;
  int ret = FALSE;
  if ((in != NULL) &&
      (first != NULL) &&
      (max != NULL) &&
      (arg != NULL)) {
    if (util_decode_nibble(in, &first_flag)) {
      in++;
      if (util_decode_byte(in, &tmp_max)) {
	in += 2;
	if (rp_decode_8bytes(in, &tmp_val)) {
	  *first = (first_flag) ? TRUE : FALSE;
	  *max = tmp_max;
	  arg->val = tmp_val;
	  ret = true;
	}
      }
    }
  }
  return ret;
}

/* Decode exactly 4 bytes of hex from a longer string, and return the result
   as an unsigned 32-bit value */
static int rp_decode_4bytes(const char *in, uint32_t *val) {
  int ret = FALSE;
  if (in != NULL && val != NULL) {
    uint8_t nibble;
    uint32_t tmp;
    int count;
    for (tmp = 0, count = 0; count < 8; count++, in++) {
      if (!util_decode_nibble(in, &nibble))
        break;
      tmp = (tmp << 4) + nibble;
    }
    *val = tmp;
    ret = TRUE;
  }
  return ret;
}

/* Decode exactly 8 bytes of hex from a longer string, and return the result
   as an unsigned 64-bit value */
static int rp_decode_8bytes(const char *in, uint64_t *val) {
  int ret = FALSE;
  if (in != NULL && val != NULL) {
    uint8_t nibble;
    uint64_t tmp;
    int count;
    for (tmp = 0, count = 0; count < 16; count++, in++) {
      if (!util_decode_nibble(in, &nibble))
        break;
      tmp = (tmp << 4) + nibble;
    }
    *val = tmp;
    ret = TRUE;
  }
  return ret;
}

/* Encode return value */
void gdb_interface_write_retval(int ret, char *b) {
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

void gdb_interface_cleanup() {
  target_cleanup();
  gdb_interface_target = NULL;
  if (NULL != in_buf) {
    free(in_buf);
    in_buf = NULL;
  }
  if (NULL != out_buf) {
    free(out_buf);
    out_buf = NULL;
  }
  if (NULL != in_buf_quick) {
    free(in_buf_quick);
    in_buf_quick = NULL;
  }
}
void gdb_interface_init() {
  in_buf = (char *)malloc(INOUTBUF_SIZE);
  if (in_buf == NULL) {
    fprintf(stderr, "Error allocting input buffer");
    exit(1);
  }
  out_buf = (char *)malloc(INOUTBUF_SIZE);
  if (out_buf == NULL) {
    fprintf(stderr, "Error allocting output buffer");
    exit(1);
  }
  in_buf_quick = (char *)malloc(INOUTBUF_SIZE);
  if (in_buf_quick == NULL) {
    fprintf(stderr, "Error allocting input buffer");
    exit(1);
  }
  target_init(&gdb_interface_target);
}

int gdb_interface_quick_packet() {
  int ret = 1;
  size_t in_len = 0;
  int s;

  /*
   * Because no implicit ack's while reading the
   * ack's must be explicitly done for each handled packet.
   */
  s = gdb_interface_getpacket(in_buf_quick, &in_len, false /* no acks */);
  if (s == '\3') {
    if (gdb_interface_target->stop) {
      dbg_ack_packet_received(false, NULL);
      gdb_interface_target->stop(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID);
    } else {
      DBG_PRINT("TBD : Handle ctrl-c\n");
    }
  } else {

    switch (in_buf_quick[0]) {
    case 'k':
      if (gdb_interface_target->quick_kill) {
        dbg_ack_packet_received(false, NULL);
        gdb_interface_target->quick_kill(CURRENT_PROCESS_PID,
                                         CURRENT_PROCESS_TID);
        ret = 0;
      }
      break;

    case 'C':
      if (gdb_interface_target->quick_signal) {
        uint32_t sig;
        char *in;
        in = &in_buf_quick[1];
        if (util_decode_uint32(&in, &sig, '\0')) {
          dbg_ack_packet_received(false, NULL);
          gdb_interface_target->quick_signal(CURRENT_PROCESS_PID,
                                             CURRENT_PROCESS_TID, sig);
          ret = 0;
        }
      }
      break;

    case 'c':
      if (gdb_interface_target->quick_signal) {
        dbg_ack_packet_received(false, NULL);
        gdb_interface_target->quick_signal(CURRENT_PROCESS_PID,
                                           CURRENT_PROCESS_TID, SIGTRAP);
        ret = 0;
      }
      break;

    case 'v':
      if (0 == strncmp(in_buf_quick, "vCont;c", 7)) {
        dbg_ack_packet_received(false, NULL);
        ret = 0;
      } else {
        /* Ignore */
        DBG_PRINT("quick packet : ignoring %s ", in_buf_quick);
      }
      break;

    default:
      /* Ignore */
      DBG_PRINT("quick packet : ignoring %s ", in_buf_quick);
      break;
    }
  }

  return ret;
}

int gdb_interface_packet() {
  int ret = 1;
  size_t in_len = 0;
  int s;
  bool binary_cmd = false;

  s = gdb_interface_getpacket(in_buf, &in_len, true /* do acks */);

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
        gdb_stop_string(out_buf, CURRENT_PROCESS_SIG, CURRENT_PROCESS_TID, 0,
                        CURRENT_PROCESS_STOP);
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
        handle_running_commands(in_buf, out_buf, gdb_interface_target);
        /* Supported */
        ret = 0;
        break;

      case 'D':
        handle_detach_command(in_buf, out_buf, gdb_interface_target);
        /* Semi Supported */
        ret = 0;
        break;

      case 'g':
        handle_read_registers_command(in_buf, out_buf, gdb_interface_target);
        /* Supported */
        ret = 0;
        break;

      case 'G':
        handle_write_registers_command(in_buf, out_buf, gdb_interface_target);
        /* Supported */
        ret = 0;
        break;

      case 'H':
        handle_thread_commands(in_buf, out_buf, gdb_interface_target);
        /* Supported */
        ret = 0;
        break;
      case 'j':
        if (!lldb_handle_json_command(in_buf, out_buf, gdb_interface_target)) {
          /* Not supported */
        } else {
          ret = 0;
        }
        break;
      case 'k':
        handle_kill_command(in_buf, out_buf, gdb_interface_target);
        /* Supported */
        ret = 0;
        break;

      case 'm':
        handle_read_memory_command(in_buf, out_buf, gdb_interface_target);
        /* Supported */
        ret = 0;
        break;

      case 'M':
        handle_write_memory_command(in_buf, out_buf, gdb_interface_target);
        /* Supported */
        ret = 0;
        break;

      case 'p':
        handle_read_single_register_command(in_buf, out_buf,
                                            gdb_interface_target);
        /* Supported */
        ret = 0;
        break;

      case 'P':
        handle_write_single_register_command(in_buf, out_buf,
                                             gdb_interface_target);
        /* Supported */
        ret = 0;
        break;
      case 'q':
        /* qXfer */
        if (strncmp(in_buf, "qXfer", 5) == 0) {
          if (gdb_handle_qxfer_command(in_buf, out_buf, &binary_cmd,
                                       gdb_interface_target))
            ret = 0;
        } else {
          if (!lldb_handle_query_command(in_buf, out_buf,
                                         gdb_interface_target) &&
              !gdb_handle_query_command(in_buf, in_len, out_buf,
                                        gdb_interface_target)) {
            /* Not supported */
          } else {
            /* Supported */
            ret = 0;
          }
        }
        break;
      case 'Q':
        if (!lldb_handle_general_set_command(in_buf, out_buf,
                                             gdb_interface_target)) {
          gdb_handle_general_set_command(in_buf, out_buf, gdb_interface_target);
        }
        /* Supported */
        ret = 0;
        break;
      case 'R':
        handle_restart_target_command(in_buf, out_buf, gdb_interface_target);
        /* Supported */
        ret = 0;
        break;
      case 't':
        handle_search_memory_command(in_buf, out_buf, gdb_interface_target);
        /* Supported */
        ret = 0;
        break;
      case 'T':
        handle_thread_alive_command(in_buf, out_buf, gdb_interface_target);
        /* Supported */
        ret = 0;
        break;
      case 'x':
        if (!lldb_handle_binary_read_command(in_buf, out_buf, &binary_cmd,
                                             gdb_interface_target)) {
          /* Not handled */
        } else {
          ret = 0;
        }
        break;
      case 'Z':
      case 'z':
        handle_breakpoint_command(in_buf, out_buf, gdb_interface_target);
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
        network_put_dbg_packet(out_buf, 0);
      } else {
        /* Now the binary command */
        switch (in_buf[0]) {
        case 'v':
	  handle_v_command(in_buf, in_len, out_buf, gdb_interface_target);
          break;
        default:
          break;
        }
      }
    }
  } else {
    if (_target.ack)
      dbg_sock_putchar('-');
    DBG_PRINT("gdb_interface : error getting a packet\n");
  }
  return ret;
}

/* b can be no more than 1024 and must be null terminated */
void gdb_interface_put_console(char *b) {
  int esize;
  char ebuf[2049]; /* 1 for 'O', 2 * buf */
  ebuf[0] = 'O';
  esize = util_encode_string(b, &ebuf[1], 2048);
  if (esize > 0)
    network_put_dbg_packet(&ebuf[0], esize + 1);
}

/*
 * Generate the gdb 'thread:xxxxxxx' string used by the stop events
 * When there is a single thread, return an empty string.
 */
void gdb_stop_string(char *str, int sig, pid_t tid, unsigned long watch_addr,
                     int reason) {
  int index;
  char tstr[32] = "";
  char wstr[32] = "";
  size_t len = INOUTBUF_SIZE;
  /*
   * lldb always wants the thread id
   * gdb only wants it if isn't the main pid/thread's
   */
  if (_target.lldb ||
      (target_number_threads() > 1 && tid != PROCESS_TID(0)))
      snprintf(&tstr[0], 32, "thread:%x;", tid);
  if (watch_addr)
    snprintf(&wstr[0], 32, "watch:%lx;", watch_addr);
  snprintf(str, len, "T%02x%s%s", sig, tstr, wstr);
  if (_target.lldb) {
    if (cmdline_pid == 0) {
      char *d = strdup(cmdline_argv[0]);
      if (d) {
        char *name = basename(d);
        if (name && strlen(name)) {
          strncat(str, "name:", len);
          strncat(str, name, len);
          strncat(str, ";", len);
        }
        free(d);
      }
    }
  }
  if (_target.list_threads_in_stop_reply) {
    bool first = true;
    strncat(str, "threads:", len);
    for (index = 0; index < _target.number_processes; index++) {
      if (PROCESS_STATE(index) != PRS_EXIT) {
        pid_t tid = PROCESS_TID(index);
        if (first) {
          snprintf(&tstr[0], 32, "%x", tid);
          first = false;
        } else {
          snprintf(&tstr[0], 32, ",%x", tid);
        }
        strncat(str, &tstr[0], len);
      }
    }
    strncat(str, ";", len);
  }

#if 0
  /* Not needed, gdb/lldb read 2 or 3 registers, so listing them all is wasteful */
  if (gdb_interface_target->read_single_register != NULL) {
    int i;
    alignas (4) unsigned char data_buf[64];
    alignas (4) unsigned char avail_buf[64];
    size_t read_size;
    for (i = 0; i < 256; i++) {
      if (RET_OK == gdb_interface_target->read_single_register(tid, i, data_buf, avail_buf, sizeof(data_buf), &read_size)) {
	char reg_str[132];
	snprintf(&reg_str[0], 132, "%2.2x:", i);
	gdb_encode_regs(data_buf, avail_buf, read_size, &reg_str[3]);
	strncat(&reg_str[0], ";", 132);
	strncat(str, &reg_str[0], len);
      } else {
	/* No holes, we are done */
	break;
      }
    }
  }
#endif
  if (_target.lldb) {
    const char *reasons[LLDB_STOP_REASON_MAX] = {
        "reason:trace;", "reason:breakpoint;", "reason:trap;",
        "reason:watchpoint;", "reason:signal;"};
    _Static_assert(LLDB_STOP_REASON_MAX == 5,
                   "Expecting LLDB_STOP_REASON_MAX to be 5");
    if (reason > 0 && reason < LLDB_STOP_REASON_MAX) {
      strncat(str, reasons[reason], len);
    }
  }
}
