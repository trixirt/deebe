/*
 * Copyright (c) 2012-2016, Juniper Networks, Inc.
 * All rights reserved.
 *
 * You may distribute under the terms of :
 *
 * the BSD 2-Clause license
 *
 * Any patches released for this software are to be released under these
 * same license terms.
 *
 * BSD 2-Clause license:
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdbool.h>
#include "gdb_interface.h"
#include "global.h"
#include "macros.h"
#include "network.h"
#include "target.h"
#include "util.h"

static void dbg_sock_putchar(int c)
{
  if (network_out_buffer_total < network_out_buffer_size) {
    network_out_buffer[network_out_buffer_total] = (uint8_t)(0xff & c);
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
    ret = (uint16_t)network_in_buffer[network_in_buffer_current];
    network_in_buffer_current++;
  } else {
      /* underflow is the most likely possiblity */
    DBG_PRINT("gdb_interface : error out underflow read %zu:%zu\n",
              network_in_buffer_current, network_in_buffer_total);
  }
  return ret;
}

void dbg_ack_packet_received(bool seq_valid, char *seq)
{
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
char *in_buf = NULL;
char *out_buf = NULL;
char *in_buf_quick = NULL;

/* Read a packet from the remote machine, with error checking,
   and store it in buf. */
int gdb_interface_getpacket(char *buf, size_t *len, bool ret_ack)
{
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

static int _packet_read (char* in_buf, size_t* in_len, int is_quick)
{
  int s;

  /* Ignore all ACKs/NAKs */
  do {
    /* Keep reading the network until we get a message */
    if (is_quick) {
      while ((s = network_quick_read ()) != 0);
    }
    else {
      while ((s = network_read ()) != 0);
    }

    s = gdb_interface_getpacket(in_buf, in_len, true /* do acks */);
  } while (s == ACK || s == NAK);

  if (s == '\3') {
    if (gdb_interface_target->stop) {
      dbg_ack_packet_received(false, NULL);
      gdb_interface_target->stop(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID);
    } else {
      DBG_PRINT("TBD : Handle ctrl-c\n");
    }
    return 0;
  }
  else if (s < 0) {
    if (_target.ack) {
      dbg_sock_putchar('-');
    }
    DBG_PRINT("gdb_interface : error getting a packet\n");
    return 1;
  }

  return 0;
}

int packet_read (char* in_buf, size_t* in_len)
{
  return _packet_read (in_buf, in_len, 0);
}

int packet_quick_read (char* in_buf, size_t* in_len)
{
  return _packet_read (in_buf, in_len, 1);
}

static int _packet_send (int is_quick)
{
  if (is_quick)
    return network_quick_write();
  else
    return network_write();
}

int packet_send ()
{
  return _packet_send (0);
}

int packet_quick_send ()
{
  return _packet_send (1);
}

int packet_exchange (void)
{
  size_t in_len = 0;
  if (packet_read (in_buf, &in_len))
    return 1;

  gdb_packet_handle (in_buf, in_len, out_buf);
  return packet_send ();
}

int packet_quick_exchange (void)
{
  size_t in_len = 0;
  if (packet_quick_read (in_buf_quick, &in_len))
    return 1;

  gdb_quick_packet_handle (in_buf_quick);
  return packet_quick_send ();
}
