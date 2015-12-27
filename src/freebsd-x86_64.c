/*
 * Copyright (c) 2013-2015, Juniper Networks, Inc.
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
#include "target_ptrace.h"
#include <machine/reg.h>
#include "os.h"
#include "global.h"
#include "gdb-x86_64.h"

#define DEEBE_REG_STRUCT reg
#include "regmacros.h"

struct reg_location_list grll[] = {
	/* general */
	RLL(r15,    r_r15,     GDB_R15,      0, 0, 0, uint, hex, 15, 15, X),
	RLL(r14,    r_r14,     GDB_R14,      0, 0, 0, uint, hex, 14, 14, X),
	RLL(r13,    r_r13,     GDB_R13,      0, 0, 0, uint, hex, 13, 13, X),
	RLL(r12,    r_r12,     GDB_R12,      0, 0, 0, uint, hex, 12, 12, X),
	RLL(r11,    r_r11,     GDB_R11,      0, 0, 0, uint, hex, 11, 11, X),
	RLL(r10,    r_r10,     GDB_R10,      0, 0, 0, uint, hex, 10, 10, X),
	RLL(r9,     r_r9,      GDB_R9,       0, 0, 0, uint, hex,  9,  9, arg6),
	RLL(r8,     r_r8,      GDB_R8,       0, 0, 0, uint, hex,  8,  8, arg5),
	RLL(rdi,    r_rdi,     GDB_RDI,      0, 0, 0, uint, hex,  4,  4, arg2),
	RLL(rsi,    r_rsi,     GDB_RSI,      0, 0, 0, uint, hex,  5,  5, arg1),
	RLL(rbp,    r_rbp,     GDB_RBP,      0, 0, 0, uint, hex,  6,  6, fp),
	RLL(rbx,    r_rbx,     GDB_RBX,      0, 0, 0, uint, hex,  3,  3, X),
	RLL(rdx,    r_rdx,     GDB_RDX,      0, 0, 0, uint, hex,  1,  1, arg3),
	RLL(rcx,    r_rcx,     GDB_RCX,      0, 0, 0, uint, hex,  2,  2, arg4),
	RLL(rax,    r_rax,     GDB_RAX,      0, 0, 0, uint, hex,  0,  0, X),
	/* trapno */
	RLL(fs,     r_fs,      GDB_FS,       0, 0, 4, uint, hex, 54, 54, X),
	RLL(gs,     r_gs,      GDB_GS,       0, 0, 4, uint, hex, 55, 55, X),
	/* err */
	RLL(es,     r_es,      GDB_ES,       0, 0, 4, uint, hex, 50, 50, X),
	RLL(ds,     r_ds,      GDB_DS,       0, 0, 4, uint, hex, 53, 53, X),
	RLL(rip,    r_rip,     GDB_RIP,      0, 0, 0, uint, hex, 16, 16, pc),
	RLL(cs,     r_cs,      GDB_CS,       0, 2, 4, uint, hex, 51, 51, X),
	RLL(rflags, r_rflags,  GDB_RFLAGS,   0, 0, 4, uint, hex, 49, 49, flags),
	RLL(rsp,    r_rsp,     GDB_RSP,      0, 0, 4, uint, hex,  7,  7, sp),
	RLL(ss,     r_ss,      GDB_SS,       0, 2, 4, uint, hex, 52, 52, X),
	{0},
};

#undef DEEBE_REG_STRUCT
#define DEEBE_REG_STRUCT fpreg
#include "regmacros.h"
struct reg_location_list frll[] = {
	RLL(ctrl, fpr_env[0], GDB_FCTRL, 0, 4, 4,   uint,          hex, -1, -1, X),
	RLL(stat, fpr_env[0], GDB_FSTAT, 4, 4, 4,   uint,          hex, -1, -1, X),
	RLL(tag,  fpr_env[1], GDB_FTAG,  0, 4, 4,   uint,          hex, -1, -1, X),
	RLL(ioff, fpr_env[1], GDB_FIOFF, 4, 4, 4,   uint,          hex, -1, -1, X),
	RLL(iseg, fpr_env[2], GDB_FISEG, 0, 4, 4,   uint,          hex, -1, -1, X),
	RLL(op,   fpr_env[2], GDB_FOP,   4, 4, 4,   uint,          hex, -1, -1, X),
	RLL(ooff, fpr_env[3], GDB_FOOFF, 0, 4, 4,   uint,          hex, -1, -1, X),
	RLL(oseg, fpr_env[4], GDB_FOSEG, 4, 4, 4,   uint,          hex, -1, -1, X),
	RLL(st0,  fpr_acc[0], GDB_FST0,  0, 0, 0, vector, vector-uint8, 33, 33, X),
	RLL(st1,  fpr_acc[1], GDB_FST1,  0, 0, 0, vector, vector-uint8, 34, 34, X),
	RLL(st2,  fpr_acc[2], GDB_FST2,  0, 0, 0, vector, vector-uint8, 35, 35, X),
	RLL(st3,  fpr_acc[3], GDB_FST3,  0, 0, 0, vector, vector-uint8, 36, 36, X),
	RLL(st4,  fpr_acc[4], GDB_FST4,  0, 0, 0, vector, vector-uint8, 37, 37, X),
	RLL(st5,  fpr_acc[5], GDB_FST5,  0, 0, 0, vector, vector-uint8, 38, 38, X),
	RLL(st6,  fpr_acc[6], GDB_FST6,  0, 0, 0, vector, vector-uint8, 39, 39, X),
	RLL(st7,  fpr_acc[7], GDB_FST7,  0, 0, 0, vector, vector-uint8, 40, 40, X),
	{0},
};

#define FXRLL(E, GDB, O, S)						\
	{								\
		.off = (O) + offsetof(struct savefpu, E),		\
			.size = (S) ? (S) : msizeof(struct savefpu, E),	\
			.gdb = (GDB),					\
	}

struct reg_location_list fxrll[] = {
	/* extended */
#ifdef PT_GETXSTATE
	FXRLL(sv_xmm[0],  GDB_XMM0,  0, 0),
	FXRLL(sv_xmm[1],  GDB_XMM1,  0, 0),
	FXRLL(sv_xmm[2],  GDB_XMM2,  0, 0),
	FXRLL(sv_xmm[3],  GDB_XMM3,  0, 0),
	FXRLL(sv_xmm[4],  GDB_XMM4,  0, 0),
	FXRLL(sv_xmm[5],  GDB_XMM5,  0, 0),
	FXRLL(sv_xmm[6],  GDB_XMM6,  0, 0),
	FXRLL(sv_xmm[7],  GDB_XMM7,  0, 0),
	FXRLL(sv_xmm[8],  GDB_XMM8,  0, 0),
	FXRLL(sv_xmm[9],  GDB_XMM9,  0, 0),
	FXRLL(sv_xmm[10], GDB_XMM10,  0, 0),
	FXRLL(sv_xmm[11], GDB_XMM11,  0, 0),
	FXRLL(sv_xmm[12], GDB_XMM12,  0, 0),
	FXRLL(sv_xmm[13], GDB_XMM13,  0, 0),
	FXRLL(sv_xmm[14], GDB_XMM14,  0, 0),
	FXRLL(sv_xmm[15], GDB_XMM15,  0, 0),
	FXRLL(sv_env.en_mxcsr, GDB_MXCSR, 0, 0),
#endif
	{0},
};

/* with PT_GETXSTATE */
#define GDB_GREG_MAX_X 49
/* without PT_GETXSTATE */
#define GDB_GREG_MAX 40

int ptrace_arch_gdb_greg_max()
{
  int size;
  /*
   * fxreg may not be supported.
   * So check the size of the register before returning
   */
  if (_target.fxreg_size)
    size = GDB_GREG_MAX_X;
  else
    size = GDB_GREG_MAX;

  return size;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc)
{
	_read_greg(tid);
	memcpy(pc, _target.reg + offsetof(struct reg, r_rip),
	       sizeof(unsigned long));
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc)
{
	_read_greg(tid);
	memcpy(_target.reg + offsetof(struct reg, r_rip), &pc,
	       sizeof(unsigned long));
	_write_greg(tid);
}


void ptrace_arch_read_fxreg(pid_t tid)
{
#ifdef PT_GETXSTATE
  /*
   * Even if this is defined, the kernel
   * can return and eror of 'no support'
   */
  _read_reg(tid, PT_GETXSTATE, PT_SETXSTATE,
	    &_target.fxreg, &_target.fxreg_rw,
	    &_target.fxreg_size);
#endif
}

void ptrace_arch_write_fxreg(pid_t tid)
{
#ifdef PT_SETXSTATE
  /* Do not bother with writing if there is nothing to write */
  if (_target.fxreg_size) {
    _write_reg(tid, PT_SETXSTATE, _target.fxreg);
  }
#endif
}

void ptrace_arch_option_set_syscall(pid_t pid)
{
	ptrace_os_option_set_syscall(pid);
}

bool ptrace_arch_check_syscall(pid_t pid, int *in_out_sig)
{
	return false;
}

extern int _ptrace_read_mem(uint64_t addr, uint8_t *data, size_t size,
			    size_t *read_size, bool breakpoint_check);
void ptrace_arch_get_syscall(pid_t tid, void *id, void *arg1, void *arg2,
			     void *arg3, void *arg4, void *ret)
{
  _read_greg(tid);
  unsigned long sp;
  int size = sizeof(unsigned long);
  memcpy(&sp, _target.reg + offsetof(struct reg, r_rsp), size);
  memcpy(id, _target.reg + offsetof(struct reg, r_rax), size);
  _ptrace_read_mem(sp + (1 * size), arg1, size, NULL, false);
  _ptrace_read_mem(sp + (2 * size), arg2, size, NULL, false);
  _ptrace_read_mem(sp + (3 * size), arg3, size, NULL, false);
  _ptrace_read_mem(sp + (4 * size), arg4, size, NULL, false);
  memcpy(ret, _target.reg + offsetof(struct reg, r_rax), size);
}

void ptrace_arch_option_set_thread(pid_t pid)
{
	ptrace_os_option_set_thread(pid);
}

bool ptrace_arch_check_new_thread(pid_t pid, int status, pid_t *out_pid)
{
    return ptrace_os_check_new_thread(pid, status, out_pid);
}

bool ptrace_arch_memory_region_info(uint64_t addr, char *out_buff, size_t out_buf_size)
{
  return ptrace_os_memory_region_info(addr, out_buff, out_buf_size);
}
