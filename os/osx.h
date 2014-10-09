/*
 * Copyright (c) 2012-2014, Juniper Networks, Inc.
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
#ifndef __DEEBE_OSX_H
#define __DEEBE_OSX_H

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>

/* OSX 3rd arg is caddr_t, cast to get it correct */
#define PTRACE(a, b, c, d) ptrace((a), (b), (caddr_t)(c), (d))
/* OSX and Linux swap the 3rd / 4th arg */
#define PTRACE_GETSET(a, b, c, d) PTRACE((a), (b), (d), (c))

#define PT_SYSCALL_ARG3 0

void arch_read_greg();
void arch_write_greg();

extern void osx_report_kernel_error(FILE *fp, kern_return_t kret);
extern int osx_read_registers(pid_t tid, uint8_t *data, uint8_t *avail,
			      size_t buf_size, size_t *read_size);
extern int osx_read_single_register(pid_t tid, unsigned int gdb, uint8_t *data,
				    uint8_t *avail, size_t buf_size,
				    size_t *read_size);
extern int osx_write_registers(pid_t tid, uint8_t *data, size_t size);
extern int osx_write_single_register(pid_t tid, unsigned int gdb, uint8_t *data,
				     size_t size);
bool osx_arch_read_registers(thread_act_t tid);

/* OSX ptrace returns int */
#define ptrace_return_t int

bool ptrace_os_new_thread(pid_t tid, int status);
bool ptrace_os_check_new_thread(pid_t pid, int status, pid_t *out_pid);
void ptrace_os_continue_others();
long ptrace_os_continue(pid_t pid, pid_t tid, int step, int sig);
void ptrace_os_wait(pid_t t);
int ptrace_os_gen_thread(pid_t pid, pid_t tid);
void ptrace_os_stopped_single(char *str, size_t len, bool debug);

#endif
