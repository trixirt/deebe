/*
 * Copyright (c) 2014-2015 Tom Rix
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

#include <sys/utsname.h>
#include <endian.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gdb_interface.h"
#include "lldb_interface.h"
#include "network.h"
#include "target.h"
#include "util.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
static char *endian_str = "little";
#else
static char *endian_str = "big";
#endif

static bool get_triple(char **ptr) {
  bool ret = false;
  struct utsname name;
  if (uname(&name) == 0) {

    /* 
     * How big will the triple string be..
     * element are null terminated, 3 strlens
     * need a null, and 2 '-' .. + 3
     * need an 'unknown' vendor + 7 -- xxx may not linux doesn't use it
     * maybe need a prefix '-gnu' or '-gnueabi' + 7
     * so 17 known/maybe + 2 strlens.. , round 17 up to 32
     */
    *ptr = (char *) malloc (32 + strlen(&name.sysname[0]) + strlen(&name.machine[0]));
    if (*ptr != NULL) {
      if (strncmp(&name.sysname[0], "Linux", 5) == 0)
	sprintf(*ptr, "%s--linux-gnu", &name.machine[0]);
      else if (strncmp(&name.sysname[0], "FreeBSD", 7) == 0)
	sprintf(*ptr, "%s-unknown-freebsd", &name.machine[0]);
      else
	sprintf(*ptr, "%s-unknown-%s", &name.machine[0], &name.sysname[0]);
      ret = true;
    }
  }
  return ret;
}

static bool get_ostype(char **ptr) {
  bool ret = false;
  struct utsname name;
  if (uname(&name) == 0) {
    *ptr = (char *) malloc (1 + strlen(&name.sysname[0]));
    if (*ptr != NULL) {
      if (strncmp(&name.sysname[0], "Linux", 5) == 0)
	sprintf(*ptr, "linux");
      else if (strncmp(&name.sysname[0], "FreeBSD", 7) == 0)
	sprintf(*ptr, "freebsd");
      else
	sprintf(*ptr, "%s", &name.machine[0]);
      ret = true;
    }
  }
  return ret;
}

bool lldb_handle_query_command(char * const in_buf, int in_len, char *out_buf, int out_buf_len, gdb_target *target)
{
  char *n = in_buf + 1;
  bool req_handled = false;
  char *triple_str = NULL;
  char *encoded_triple_str = NULL;
  char *ostype_str = NULL;
  size_t encoded_triple_str_size = 0;

  switch (*n) {
  case 'H':
    if (strncmp(n, "HostInfo", 8) == 0) {
      if (get_triple(&triple_str)) {
	encoded_triple_str_size = 1 + 2 * strlen(triple_str);
	encoded_triple_str = (char *) malloc (encoded_triple_str_size);
	if (encoded_triple_str != NULL) {
	  /* Assume the encoding doesn't fail.. */
	  util_encode_string(triple_str, encoded_triple_str, encoded_triple_str_size);
	  snprintf(out_buf, out_buf_len, "triple:%s;ptrsize:%u;endian:%s", encoded_triple_str, (unsigned) sizeof(void *), endian_str);
	  free(encoded_triple_str);
	  encoded_triple_str = NULL;
	} else {
	  gdb_interface_write_retval(RET_ERR, out_buf);
	}
	free(triple_str);
	triple_str = NULL;
      } else {
	gdb_interface_write_retval(RET_ERR, out_buf);
      }
      req_handled = true;
      goto end;
    }
    break;
  case 'M':
    if (strncmp(n, "MemoryRegionInfo:", 17) == 0) {
      uint64_t addr;
      bool err = false;
      char *in = &n[17];
      if (sizeof(void *) == 8) {
	if (!util_decode_uint64(&in, &addr, '\0')) {
	  err = true;
	}
      } else {
	uint32_t addr32;
	if (util_decode_uint32(&in, &addr32, '\0')) {
	  addr = addr32;
	} else {
	  err = true;
	}
      }
      if (!err) {
	if (target->memory_region_info) {
	  if (!target->memory_region_info(addr, out_buf, out_buf_len)) {
	    gdb_interface_write_retval(RET_ERR, out_buf);
	  }
	} else {
	  gdb_interface_write_retval(RET_NOSUPP, out_buf);
	}
      } else {
	gdb_interface_write_retval(RET_ERR, out_buf);
      }
      req_handled = true;
      goto end;
    }
    break;
  case 'P':
    /* Because of the gdb 'P' packet, all lldb 'P*' packets must be handled */
    if (strncmp(n, "Platform_shell:", 15) == 0) {
      gdb_interface_write_retval(RET_NOSUPP, out_buf);
      req_handled = true;
      goto end;
    } else if (strncmp(n, "Platform_mkdir:", 15) == 0) {
      gdb_interface_write_retval(RET_NOSUPP, out_buf);
      req_handled = true;
      goto end;
    } else if (strncmp(n, "Platform_chmod:", 15) == 0) {
      gdb_interface_write_retval(RET_NOSUPP, out_buf);
      req_handled = true;
      goto end;
    } else if (strncmp(n, "ProcessInfoPID", 14) == 0) {
      gdb_interface_write_retval(RET_NOSUPP, out_buf);
      req_handled = true;
      goto end;
    } else if (strncmp(n, "ProcessInfo", 11) == 0) {
      if (get_triple(&triple_str)) {
	encoded_triple_str_size = 1 + 2 * strlen(triple_str);
	encoded_triple_str = (char *) malloc (encoded_triple_str_size);
	if (encoded_triple_str != NULL) {
	  /* Assume the encoding doesn't fail.. */
	  util_encode_string(triple_str, encoded_triple_str, encoded_triple_str_size);

	  if (get_ostype(&ostype_str)) {
	    /* Not supporting multi process so ever process is created by deebe */
	    pid_t my_pid = getpid();
	    /* Keep it simple and use deebe's uid/euid till it breaks */
	    uid_t my_uid = getuid();
	    uid_t my_euid = geteuid();
	    gid_t my_gid = getgid();
	    gid_t my_egid = getgid();
	    snprintf(out_buf, out_buf_len, "pid:%x;parent-pid:%x;real-uid:%x;real-guid:%x;effective-uid:%x;effective-gid:%x;triple:%s;ostype:%s;endian:%s;ptrsize:%u;", CURRENT_PROCESS_PID, my_pid, my_uid, my_gid, my_euid, my_egid, encoded_triple_str, ostype_str, endian_str, (unsigned) sizeof(void *));
	    free(ostype_str);
	    ostype_str = NULL;
	  } else {
	    gdb_interface_write_retval(RET_ERR, out_buf);
	  }
	  free(encoded_triple_str);
	  encoded_triple_str = NULL;
	} else {
	  gdb_interface_write_retval(RET_ERR, out_buf);
	}
	free(triple_str);
	triple_str = NULL;
      } else {
	gdb_interface_write_retval(RET_ERR, out_buf);
      }
      req_handled = true;
      goto end;
    }
    break;
  case 'R':
    if (strncmp(n, "RegisterInfo", 12) == 0) {
      uint32_t reg;
      char *in = &n[12];
      if (util_decode_reg(&in, &reg)) {
	if (target->register_info) {
	  if (!target->register_info(reg, out_buf, out_buf_len)) {
	    gdb_interface_write_retval(RET_ERR, out_buf);
	  }
	} else {
	  gdb_interface_write_retval(RET_NOSUPP, out_buf);
	}
      } else {
	gdb_interface_write_retval(RET_ERR, out_buf);
      }
      req_handled = true;
      goto end;
    }
    break;

  default:
    break;
  }

end:
  if (req_handled)
    _target.lldb = true;

  return req_handled;
}

bool lldb_handle_json_command(char * const in_buf, int in_len, char *out_buf, int out_buf_len, gdb_target *target) {

  char *n = in_buf + 1;
  bool req_handled = false;

  switch (*n) {
  case 'T':
    if (strncmp(n, "ThreadExtendedInfo:", 19) == 0) {
      int64_t process, thread;
      int status;
      /* Current thread query */
      status = target->current_thread_query(&process, &thread);
      if (status == RET_OK) {
	/*
	 * This cores lldb :
	 * snprintf(out_buf, out_buf_len, "jThreadExtendedInfo:{\"thread\":%lu}", thread);
	 *
	 * From inspection, it looks like json is apple (?) specific.
	 * So return error instead
	 *
	 */
	gdb_interface_write_retval(RET_ERR, out_buf);
      } else {
	gdb_interface_write_retval(RET_ERR, out_buf);
      }
      req_handled = true;
      goto end;
    }
  default:
    break;
  }

end:
  if (req_handled)
    _target.lldb = true;

  return req_handled;
}

bool lldb_handle_binary_read_command(char * const in_buf, int in_len, char *out_buf, int out_buf_len, gdb_target *target)
{
  char *n = in_buf + 1;
  bool req_handled = false;

  /* Look for special $x0,0 packet */
  if (strncmp(n, "0,0", 3) == 0) {
    gdb_interface_write_retval(RET_OK, out_buf);
  } else {
    uint64_t addr;
    uint64_t size;
    bool err = true;
    char *endptr;
    
    /* lldb x packet doesn't follow gdb convention
     * 
     * $x0x7f50cc408600,0x200#80
     * 
     * From the lldb-gdb-remote.txt doc
     *   The "0x" prefixes are optional - like most of the gdb-remote packets,
     *   omitting them will work fine; these numbers are always base 16. 
     *
     * This forces us to do something special for this command
     */
    addr = strtoull(n, &endptr, 16);
    /* 1 for inc past 'x', 1 for ',' */
    if ((n != endptr) && ((endptr - n + 2 ) < in_len)) {
      /* assume ',' */
      n = endptr + 1;
      size = strtoull(n, &endptr, 16);
      if (n != endptr)
	err = false;
    }

    if (err) {
      gdb_interface_write_retval(RET_ERR, out_buf);
    } else {

      /*
       * Only only handle a singled buffer worth
       * *2 to account for worst case, every value must be escaped
       */
      if (size * 2 > out_buf_len) {
	gdb_interface_write_retval(RET_ERR, out_buf);
      } else {
	/*
	 * Use the last half of the out buf as our scratch buffer
	 * The escape conversion will read from the second half
	 * and place in the first half.
	 */
	size_t len;
	char *scratch_buf = out_buf + (out_buf_len / 2);
	/* Since we are not going to handle the error at least clear memory */
	memset(scratch_buf, 0, size);
	target->read_mem(CURRENT_PROCESS_TID, addr, (uint8_t *)scratch_buf, size, &len);
	/* ignore len, ignore ret, go ahead and escap */
	len = util_escape_binary((uint8_t *)out_buf, (uint8_t *)scratch_buf, size);
	network_put_dbg_packet(out_buf, len);
      }
    }
  }
  req_handled = true;

  if (req_handled)
    _target.lldb = true;

  return req_handled;
}

bool lldb_handle_general_set_command(char * const in_buf, int in_len, char *out_buf, int out_buf_len, gdb_target *target)
{
  char *n = in_buf + 1;
  bool req_handled = false;

  switch (*n) {
  case 'T':
    if (strncmp(n, "ThreadSuffixSupported", 21) == 0) {
      gdb_interface_write_retval(RET_OK, out_buf);
      req_handled = true;
      goto end;
    }
    break;

  case 'L':
    if (strncmp(n, "ListThreadsInStopReply", 22) == 0) {
      _target.list_threads_in_stop_reply = true;
      gdb_interface_write_retval(RET_OK, out_buf);
      req_handled = true;
      goto end;
    }
    break;
    
  default:
    break;
  }

end:
  if (req_handled)
    _target.lldb = true;

  return req_handled;
}
