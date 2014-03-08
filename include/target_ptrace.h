/*
 * Copyright (c) 2012-2013, Juniper Networks, Inc.
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
#ifndef TARGET_PTRACE_H
#define TARGET_PTRACE_H

#ifndef NO_CONFIG
#include <config.h>
#endif
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "gdb_interface.h"
#include "dptrace.h"

extern int ptrace_current_thread_query(int64_t *process_id, int64_t *thread_id);
extern int ptrace_is_thread_alive(int64_t process_id, int64_t thread_id,
				  /*@unused@*/int *alive);
extern int ptrace_list_query(int first, gdb_thread_ref *arg,
			     gdb_thread_ref *result, size_t max_num,
			     size_t *num, int *done);
extern int ptrace_process_query(unsigned int *mask, gdb_thread_ref *arg,
				rp_thread_info *info);
extern int ptrace_set_ctrl_thread(int64_t process_id, int64_t thread_id);
extern int ptrace_set_gen_thread(int64_t process_id, int64_t thread_id);
extern int ptrace_threadextrainfo_query(gdb_thread_ref *thread,
					char *out_buf, size_t out_buf_size);

#endif
