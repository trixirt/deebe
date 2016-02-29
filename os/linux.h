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
#ifndef __DEEBE_LINUX_H
#define __DEEBE_LINUX_H

#include <linux/elf.h>
#include <endian.h>

/*
 * To get the cast of normal arguements correct,
 * default is linux so this is a noop
*/
#define PTRACE(a, b, c, d) ptrace((a), (b), (c), (d))
/*
 * FreeBSD and Linux swap the 3rd / 4th arg,
 * default is linux so this is a noop
 */
#define PTRACE_GETSET(a, b, c, d) ptrace_linux_getset((a), (b), (c), (d))

/* Linux ptrace returns long */
#define ptrace_return_t long

#define PT_SYSCALL_ARG3 0

void ptrace_os_read_fxreg();
void ptrace_os_write_fxreg();
void ptrace_os_option_set_syscall(pid_t pid);
void ptrace_os_option_set_thread(pid_t pid);
bool ptrace_os_check_syscall(pid_t pid, int *in_out_sig);
bool ptrace_os_wait_new_thread(pid_t *out_pid, int *out_status);
bool ptrace_os_check_new_thread(pid_t pid, int status, pid_t *out_pid);
bool ptrace_os_new_thread(pid_t tid, int status);
void ptrace_os_wait(pid_t tid);
void ptrace_os_continue_others();
int os_thread_kill(int tid, int sig);
long ptrace_os_continue(pid_t pid, pid_t tid, int step, int sig);
int ptrace_os_gen_thread(pid_t pid, pid_t tid);
void ptrace_os_stopped_single(char *str, bool debug);
long ptrace_linux_getset(long request, pid_t pid, void *addr, void *data);
bool memory_os_region_info_gdb(uint64_t addr, char *out_buff,
			       size_t out_buf_size);
bool ptrace_os_read_auxv(char *out_buff, size_t out_buf_size, size_t offset,
                         size_t *size);
int elf_os_image(pid_t pid);
pid_t ptrace_os_get_wait_tid(pid_t pid);

#ifndef PT_GETREGS
#ifndef PTRACE_GETREGS
#define PTRACE_GETREGS (-12)
#endif
#define PT_GETREGS PTRACE_GETREGS
#endif

#ifndef PT_SETREGS
#ifndef PTRACE_SETREGS
#define PTRACE_SETREGS (-13)
#endif
#define PT_SETREGS PTRACE_SETREGS
#endif

#ifndef PT_GETFPREGS
#ifndef PTRACE_GETFPREGS
#define PTRACE_GETFPREGS (-14)
#endif
#define PT_GETFPREGS PTRACE_GETFPREGS
#endif

#ifndef PT_SETRFPEGS
#ifndef PTRACE_SETFPREGS
#define PTRACE_SETFPREGS (-15)
#endif
#define PT_SETFPREGS PTRACE_SETFPREGS
#endif

#endif /* __DEEBE_LINUX_H */
