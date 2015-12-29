/*
 * Copyright (c) 2013-2105, Juniper Networks, Inc.
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
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include "gdb_interface.h"
#include "dptrace.h"
#include "global.h"
#include "os.h"
#include "gdb-x86_64.h"

/* Not common with freebsd */
#define GDB_ORIG_RAX 57

#define DEEBE_REG_STRUCT user
#include "regmacros.h"
struct reg_location_list grll[] = {
  /* general */
  RLL(r15,      regs.r15,      GDB_R15,      0, 0, 0, uint, hex, 15, 15, X),
  RLL(r14,      regs.r14,      GDB_R14,      0, 0, 0, uint, hex, 14, 14, X),
  RLL(r13,      regs.r13,      GDB_R13,      0, 0, 0, uint, hex, 13, 13, X),
  RLL(r12,      regs.r12,      GDB_R12,      0, 0, 0, uint, hex, 12, 12, X),
  RLL(r11,      regs.r11,      GDB_R11,      0, 0, 0, uint, hex, 11, 11, X),
  RLL(r10,      regs.r10,      GDB_R10,      0, 0, 0, uint, hex, 10, 10, X),
  RLL(r9,       regs.r9,       GDB_R9,       0, 0, 0, uint, hex,  9,  9, arg6),
  RLL(r8,       regs.r8,       GDB_R8,       0, 0, 0, uint, hex,  8,  8, arg5),
  RLL(rsi,      regs.rsi,      GDB_RSI,      0, 0, 0, uint, hex,  4,  4, arg2),
  RLL(rdi,      regs.rdi,      GDB_RDI,      0, 0, 0, uint, hex,  5,  5, arg1),
  RLL(orig_rax, regs.orig_rax, GDB_ORIG_RAX, 0, 0, 0, uint, hex, -1, -1, X),
  RLL(rbp,      regs.rbp,      GDB_RBP,      0, 0, 0, uint, hex,  6,  6, fp),
  RLL(rbx,      regs.rbx,      GDB_RBX,      0, 0, 0, uint, hex,  3,  3, X),
  RLL(rdx,      regs.rdx,      GDB_RDX,      0, 0, 0, uint, hex,  1,  1, arg3),
  RLL(rcx,      regs.rcx,      GDB_RCX,      0, 0, 0, uint, hex,  2,  2, arg4),
  RLL(rax,      regs.rax,      GDB_RAX,      0, 0, 0, uint, hex,  0,  0, X),
  RLL(fs,       regs.fs,       GDB_FS,       0, 0, 4, uint, hex, 54, 54, X),
  RLL(gs,       regs.gs,       GDB_GS,       0, 0, 4, uint, hex, 55, 55, X),
  RLL(es,       regs.es,       GDB_ES,       0, 0, 4, uint, hex, 50, 50, X),
  RLL(ds,       regs.ds,       GDB_DS,       0, 0, 4, uint, hex, 53, 53, X),
  RLL(rip,      regs.rip,      GDB_RIP,      0, 0, 0, uint, hex, 16, 16, pc),
  RLL(cs,       regs.cs,       GDB_CS,       0, 0, 4, uint, hex, 51, 51, X),
  RLL(rflags,   regs.eflags,   GDB_RFLAGS,   0, 0, 4, uint, hex, 49, 49, flags),
  RLL(rsp,      regs.rsp,      GDB_RSP,      0, 0, 4, uint, hex,  7,  7, sp),
  RLL(ss,       regs.ss,       GDB_SS,       0, 0, 4, uint, hex, 52, 52, X),
  {0},
};

#undef DEEBE_REG_STRUCT
#define DEEBE_REG_STRUCT user_fpregs_struct
#include "regmacros.h"
struct reg_location_list frll[] = {
  RLL(st0,    st_space[0], GDB_FST0,     0,   10,   10, vector, vector-uint8, 33, 33, X),
  RLL(st1,    st_space, GDB_FST1,    10,   10,   10, vector, vector-uint8, 34, 34, X),
  RLL(st2,    st_space, GDB_FST2,    20,   10,   10, vector, vector-uint8, 35, 35, X),
  RLL(st3,    st_space, GDB_FST3,    30,   10,   10, vector, vector-uint8, 36, 36, X),
  RLL(st4,    st_space, GDB_FST4,    40,   10,   10, vector, vector-uint8, 37, 37, X),
  RLL(st5,    st_space, GDB_FST5,    50,   10,   10, vector, vector-uint8, 38, 38, X),
  RLL(st6,    st_space, GDB_FST6,    60,   10,   10, vector, vector-uint8, 39, 39, X),
  RLL(st7,    st_space, GDB_FST7,    70,   10,   10, vector, vector-uint8, 40, 40, X),
  RLL(cwd,         cwd, GDB_FCTRL,    0,    2,    4,   uint,          hex, -1, -1, X),
  RLL(swd,         swd, GDB_FSTAT,    0,    2,    4,   uint,          hex, -1, -1, X),
  RLL(ftw,         ftw, GDB_FTAG,     0,    2,    4,   uint,          hex, -1, -1, X),
  RLL(fop,         fop, GDB_FOP,      0,    2,    4,   uint,          hex, -1, -1, X),
  RLL(mm0,   xmm_space, GDB_XMM0,  0x00, 0x10, 0x10,   uint,          hex, 41, 41, X),
  RLL(mm1,   xmm_space, GDB_XMM1,  0x10, 0x10, 0x10,   uint,          hex, 42, 42, X),
  RLL(mm2,   xmm_space, GDB_XMM2,  0x20, 0x10, 0x10,   uint,          hex, 43, 43, X),
  RLL(mm3,   xmm_space, GDB_XMM3,  0x30, 0x10, 0x10,   uint,          hex, 44, 44, X),
  RLL(mm4,   xmm_space, GDB_XMM4,  0x40, 0x10, 0x10,   uint,          hex, 45, 45, X),
  RLL(mm5,   xmm_space, GDB_XMM5,  0x50, 0x10, 0x10,   uint,          hex, 46, 46, X),
  RLL(mm6,   xmm_space, GDB_XMM6,  0x60, 0x10, 0x10,   uint,          hex, 47, 47, X),
  RLL(mm7,   xmm_space, GDB_XMM7,  0x70, 0x10, 0x10,   uint,          hex, 48, 48, X),
  RLL(mm8,   xmm_space, GDB_XMM8,  0x80, 0x10, 0x10,   uint,          hex, 49, 49, X),
  RLL(mm9,   xmm_space, GDB_XMM9,  0x90, 0x10, 0x10,   uint,          hex, 50, 50, X),
  RLL(mm10,  xmm_space, GDB_XMM10, 0xa0, 0x10, 0x10,   uint,          hex, 51, 51, X),
  RLL(mm11,  xmm_space, GDB_XMM11, 0xb0, 0x10, 0x10,   uint,          hex, 52, 52, X),
  RLL(mm12,  xmm_space, GDB_XMM12, 0xc0, 0x10, 0x10,   uint,          hex, 53, 53, X),
  RLL(mm13,  xmm_space, GDB_XMM13, 0xd0, 0x10, 0x10,   uint,          hex, 54, 54, X),
  RLL(mm14,  xmm_space, GDB_XMM14, 0xe0, 0x10, 0x10,   uint,          hex, 55, 55, X),
  RLL(mm15,  xmm_space, GDB_XMM15, 0xf0, 0x10, 0x10,   uint,          hex, 56, 56, X),
  RLL(mxcsr, mxcsr,     GDB_MXCSR,    0,    0,    0,   uint,          hex, 64, 64, X),
	{0},
};

struct reg_location_list fxrll[] = {
	{0},
};

void ptrace_arch_read_fxreg(pid_t tid)
{
	/* part of fp regs */
}

void ptrace_arch_write_fxreg(pid_t tid)
{
	/* part of fp regs */
}

#ifdef PT_GETXSTATE
#define GDB_GREG_MAX 49
#else
#define GDB_GREG_MAX 40
#endif

int ptrace_arch_gdb_greg_max()
{
	return 24;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc)
{
	_read_greg(tid);
	memcpy(pc, _target.reg + offsetof(struct user, regs.rip),
	       sizeof(unsigned long));
}

void ptrace_arch_set_pc(pid_t tid, unsigned long pc)
{
	_read_greg(tid);
	memcpy(_target.reg + offsetof(struct user, regs.rip), &pc,
	       sizeof(unsigned long));
	_write_greg(tid);
}

void ptrace_arch_option_set_syscall(pid_t pid)
{
	ptrace_os_option_set_syscall(pid);
}

bool ptrace_arch_check_syscall(pid_t pid, int *in_out_sig)
{
	return false;
}

void ptrace_arch_get_syscall(pid_t tid, void *id, void *arg1, void *arg2,
			     void *arg3, void *arg4, void *ret)
{
	_read_greg(tid);
}

bool ptrace_arch_check_unrecognized_register(int reg, size_t *pad_size)
{
	bool ret = false;
	if (GDB_FISEG == reg) {
		*pad_size = 4;
		ret = true;
	} else if (GDB_FIOFF == reg) {
		*pad_size = 4;
		ret = true;
	} else if (GDB_FOSEG == reg) {
		*pad_size = 4;
		ret = true;
	} else if (GDB_FOOFF == reg) {
		*pad_size = 4;
		ret = true;
	}
	return ret;
}

void ptrace_arch_option_set_thread(pid_t pid)
{
	ptrace_os_option_set_thread(pid);
}

bool ptrace_arch_wait_new_thread(pid_t *out_pid, int *out_status)
{
	return ptrace_os_wait_new_thread(out_pid, out_status);
}

bool ptrace_arch_check_new_thread(pid_t pid, int status, pid_t *out_pid)
{
	return ptrace_os_check_new_thread(pid, status, out_pid);
}

bool ptrace_arch_memory_region_info(uint64_t addr, char *out_buff, size_t out_buf_size)
{
  return ptrace_os_memory_region_info(addr, out_buff, out_buf_size);
}

bool ptrace_arch_read_auxv(char *out_buff, size_t out_buf_size, size_t offset, size_t size)
{
  return ptrace_os_read_auxv(out_buff, out_buf_size, offset, size);
}
