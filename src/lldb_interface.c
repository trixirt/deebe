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

bool lldb_handle_query_command(char * const in_buf, int in_len, char *out_buf, int out_buf_len, gdb_target *t)
{
  char *n = in_buf + 1;
  bool req_handled = false;

  switch (*n) {
  case 'H':
    if (strncmp(n, "HostInfo", 8) == 0) {
      struct utsname name;
      if (uname(&name)) {
	gdb_interface_write_retval(RET_ERR, out_buf);
      } else {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	char *endian_str = "little";
#else
	char *endian_str = "big";
#endif

	/* 
	 * How big will the triple string be..
	 * element are null terminated, 3 strlens
	 * need a null, and 2 '-' .. + 3
	 * need an 'unknown' vendor + 7
	 * maybe need a prefix '-gnu' or '-gnueabi' + 7
	 * so 17 known/maybe + 2 strlens.. , round 17 up to 32
	 */
	char *triple_str = (char *) malloc (32 + strlen(&name.sysname[0]) + strlen(&name.machine[0]));
	if (triple_str) {
	  if (strncmp(&name.sysname[0], "Linux", 5) == 0)
	    sprintf(triple_str, "%s-unknown-linux-gnu", &name.machine[0]);
	  else if (strncmp(&name.sysname[0], "FreeBSD", 7) == 0)
	    sprintf(triple_str, "%s-unknown-freebsd", &name.machine[0]);
	  else
	    sprintf(triple_str, "%s-unknown-%s", &name.machine[0], &name.sysname[0]);
//	  snprintf(out_buf, out_buf_len, "triple:%s ptrsize:%z endian:%s", triple_str, sizeof(void *), endian_str);
	  snprintf(out_buf, out_buf_len, "triple:%s;ptrsize:%u;endian:%s", triple_str, (unsigned) sizeof(void *), endian_str);
	  free(triple_str);
	} else {
	  gdb_interface_write_retval(RET_ERR, out_buf);
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
