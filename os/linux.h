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
#ifndef __DEEBE_LINUX_H
#define __DEEBE_LINUX_H

#define GRLL(N, E, GDB, O, S, GDB_S)				\
	{							\
		.off = (O) + offsetof(struct user, E),		\
		.size = (S) ? (S) : msizeof(struct user, E),	\
		.gdb = (GDB),					\
		.name = #N,					\
		.gdb_size = (GDB_S) ? (GDB_S) : msizeof(struct user, E), \
	}

/* Arch can define which struct to use */
#ifndef FP_STRUCT
#define FP_STRUCT user_fpregs_struct
#endif

#define FRLL(N, E, GDB, O, S, GDB_S)				\
	{							\
		.off = (O) + offsetof(struct FP_STRUCT, E),	\
		.size = (S) ? (S) : msizeof(struct FP_STRUCT, E), \
		.gdb = (GDB),					\
		.name = #N,					\
		.gdb_size = (GDB_S) ? (GDB_S) : msizeof(struct FP_STRUCT, E) \
	}
/*
 * To get the cast of normal arguements correct,
 * default is linux so this is a noop
*/
#define PTRACE(a, b, c, d) ptrace((a), (b), (c), (d))
/*
 * FreeBSD and Linux swap the 3rd / 4th arg,
 * default is linux so this is a noop
 */
#define PTRACE_GETSET(a, b, c, d) PTRACE((a), (b), (c), (d))

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
bool ptrace_os_new_thread(int status);
int os_thread_kill(int tid, int sig);

#ifndef PT_GETREGS
#define PT_GETREGS PTRACE_GETREGS
#endif
#ifndef PT_SETREGS
#define PT_SETREGS PTRACE_SETREGS
#endif
#ifndef PT_GETFPREGS
#define PT_GETFPREGS PTRACE_GETFPREGS
#endif
#ifndef PT_SETRFPEGS
#define PT_SETFPREGS PTRACE_SETFPREGS
#endif

#endif /* __DEEBE_LINUX_H */
