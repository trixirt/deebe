/*
 * Copyright (c) 2015, Juniper Networks, Inc.
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
#ifndef DEEBE_MACROS_H
#define DEEBE_MACROS_H

/* FreeBSD's assert throws warnings, rewrite here */
#define	ASSERT(e)	((e) ? (void)0 : \
fprintf(stderr, "Assertion failed at %s %s %d : %s\n",\
	__func__, __FILE__, __LINE__, #e))

#define WATCHDOG_ERROR()                                                     \
	do {                                                                 \
		fprintf(stderr, "Watchdog time expired, program exiting\n"); \
		exit(-1);						     \
	} while (0)

#ifdef DEEBE_RELEASE
#define DBG_PRINT(fmt, args...)
#else
#define DBG_PRINT(fmt, args...) util_log(fmt, ##args)
#endif

#define PRINTABLE(c) (((c) >= (__typeof__(c))0x20 && (c) < (__typeof__(c))127) ? (c) : '.')

/* Size of data buffer  */
#define GDB_INTERFACE_PARAM_DATABYTES_MAX (0x20000)
/* Size of input and out buffers */
#define INOUTBUF_SIZE (2*GDB_INTERFACE_PARAM_DATABYTES_MAX+32)

/* These must match the table of reasons the gdb_stop_string function */
#define LLDB_STOP_REASON_TRACE 0
#define LLDB_STOP_REASON_BREAKPOINT 1
#define LLDB_STOP_REASON_TRAP 2
#define LLDB_STOP_REASON_WATCHPOINT 3
#define LLDB_STOP_REASON_SIGNAL 4
#define LLDB_STOP_REASON_EXCEPTION 5 /* Not supported */
#define LLDB_STOP_REASON_MAX (LLDB_STOP_REASON_SIGNAL+1)

#define PTRACE_ERROR_TRACEME       125
#define PTRACE_ERROR_RAISE_SIGSTOP 124
#define PTRACE_ERROR_EXECV         123
#define PTRACE_ERROR_ATTACH        122
#define PTRACE_ERROR_INTERNAL      121

#endif
