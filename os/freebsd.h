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
#ifndef DEEBE_FREEBSD_H
#define DEEBE_FREEBSD_H

#include <sys/cdefs.h>
#include <sys/procfs.h>
#include "target_ptrace.h"
#include "global.h"

/* FreeBSD and Linux swap the 3rd / 4th arg */
#define PTRACE_GETSET(a, b, c, d) ptrace((a), (b), (caddr_t)(d), (c))
/* To get the cast of normal arguements correct */
#define PTRACE(a, b, c, d) ptrace((a), (b), (caddr_t)(c), (d))

/* FreeBSD ptrace returns int */
#define ptrace_return_t int

#define PT_SYSCALL_ARG3 1

void ptrace_os_set_singlestep(pid_t pid, long *request);
void ptrace_os_clear_singlestep(pid_t pid);
void ptrace_os_option_set_syscall(pid_t pid);
void ptrace_os_option_set_thread(pid_t pid);
bool ptrace_os_wait_new_thread(pid_t *out_pid, int *out_status);
bool ptrace_os_check_new_thread(pid_t pid, int status, pid_t *out_pid);
bool ptrace_os_new_thread(pid_t tid, int status);
void ptrace_os_wait(pid_t tid);
void ptrace_os_continue_others();
int os_thread_kill(int tid, int sig);
long ptrace_os_continue(pid_t pid, pid_t tid, int step, int sig);
int ptrace_os_gen_thread(pid_t pid, pid_t tid);
void ptrace_os_stopped_single(char *str, bool debug);
bool memory_os_region_info_gdb(uint64_t addr, char *out_buff,
			       size_t out_buf_size);
bool ptrace_os_read_auxv(char *out_buff, size_t out_buf_size, size_t offset,
                         size_t *size);
pid_t ptrace_os_get_wait_tid(pid_t pid);
int ptrace_os_get_tls_address(int64_t thread, uint64_t lm, uint64_t offset,
			      uintptr_t *tlsaddr);
#endif
