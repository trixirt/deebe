/*
 * Copyright (c) 2013-2014, Juniper Networks, Inc.
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

#define GDB_RAX       0
#define GDB_RBX       1
#define GDB_RCX       2
#define GDB_RDX       3
#define GDB_RSI       4
#define GDB_RDI       5
#define GDB_RBP       6
#define GDB_RSP       7
#define GDB_R8        8
#define GDB_R9        9
#define GDB_R10      10
#define GDB_R11      11
#define GDB_R12      12
#define GDB_R13      13
#define GDB_R14      14
#define GDB_R15      15
#define GDB_RIP      16
#define GDB_RFLAGS   17
#define GDB_CS       18
#define GDB_SS       19
#define GDB_DS       20
#define GDB_ES       21
#define GDB_FS       22
#define GDB_GS       23

struct reg_location_list grll[] = {
	/* general */
	GRLL(r15,    r_r15,     GDB_R15,      0, 0, 0),
	GRLL(r14,    r_r14,     GDB_R14,      0, 0, 0),
	GRLL(r13,    r_r13,     GDB_R13,      0, 0, 0),
	GRLL(r12,    r_r12,     GDB_R12,      0, 0, 0),
	GRLL(r11,    r_r11,     GDB_R11,      0, 0, 0),
	GRLL(r10,    r_r10,     GDB_R10,      0, 0, 0),
	GRLL(r9,     r_r9,      GDB_R9,       0, 0, 0),
	GRLL(r8,     r_r8,      GDB_R8,       0, 0, 0),
	GRLL(rdi,    r_rdi,     GDB_RDI,      0, 0, 0),
	GRLL(rsi,    r_rsi,     GDB_RSI,      0, 0, 0),
	GRLL(rbp,    r_rbp,     GDB_RBP,      0, 0, 0),
	GRLL(rbx,    r_rbx,     GDB_RBX,      0, 0, 0),
	GRLL(rdx,    r_rdx,     GDB_RDX,      0, 0, 0),
	GRLL(rcx,    r_rcx,     GDB_RCX,      0, 0, 0),
	GRLL(rax,    r_rax,     GDB_RAX,      0, 0, 0),
	/* trapno */
	GRLL(fs,     r_fs,      GDB_FS,       0, 0, 4),
	GRLL(gs,     r_gs,      GDB_GS,       0, 0, 4),
	/* err */
	GRLL(es,     r_es,      GDB_ES,       0, 0, 4),
	GRLL(ds,     r_ds,      GDB_DS,       0, 0, 4),
	GRLL(rip,    r_rip,     GDB_RIP,      0, 0, 0),
	GRLL(cs,     r_cs,      GDB_CS,       0, 2, 4),
	GRLL(rflags, r_rflags,  GDB_RFLAGS,   0, 0, 4),
	GRLL(rsp,    r_rsp,     GDB_RSP,      0, 0, 4),
	GRLL(ss,     r_ss,      GDB_SS,       0, 2, 4),
	{0},
};

#define GDB_FST0  24
#define GDB_FST1  25
#define GDB_FST2  26
#define GDB_FST3  27
#define GDB_FST4  28
#define GDB_FST5  29
#define GDB_FST6  30
#define GDB_FST7  31
#define GDB_FCTRL 32
#define GDB_FSTAT 33
#define GDB_FTAG  34
#define GDB_FISEG 35
#define GDB_FIOFF 36
#define GDB_FOSEG 37
#define GDB_FOOFF 38
#define GDB_FOP   39

struct reg_location_list frll[] = {
	FRLL(ctrl, fpr_env[0], GDB_FCTRL, 0, 4, 4),
	FRLL(stat, fpr_env[0], GDB_FSTAT, 4, 4, 4),
	FRLL(tag,  fpr_env[1], GDB_FTAG,  0, 4, 4),
	FRLL(ioff, fpr_env[1], GDB_FIOFF, 4, 4, 4),
	FRLL(iseg, fpr_env[2], GDB_FISEG, 0, 4, 4),
	FRLL(op,   fpr_env[2], GDB_FOP,   4, 4, 4),
	FRLL(ooff, fpr_env[3], GDB_FOOFF, 0, 4, 4),
	FRLL(oseg, fpr_env[4], GDB_FOSEG, 4, 4, 4),
	FRLL(st0,  fpr_acc[0], GDB_FST0,  0, 0, 0),
	FRLL(st1,  fpr_acc[1], GDB_FST1,  0, 0, 0),
	FRLL(st2,  fpr_acc[2], GDB_FST2,  0, 0, 0),
	FRLL(st3,  fpr_acc[3], GDB_FST3,  0, 0, 0),
	FRLL(st4,  fpr_acc[4], GDB_FST4,  0, 0, 0),
	FRLL(st5,  fpr_acc[5], GDB_FST5,  0, 0, 0),
	FRLL(st6,  fpr_acc[6], GDB_FST6,  0, 0, 0),
	FRLL(st7,  fpr_acc[7], GDB_FST7,  0, 0, 0),
	{0},
};

#define GDB_XMM0  40
#define GDB_XMM1  41
#define GDB_XMM2  42
#define GDB_XMM3  43
#define GDB_XMM4  44
#define GDB_XMM5  45
#define GDB_XMM6  46
#define GDB_XMM7  47
#define GDB_XMM8  48
#define GDB_XMM9  49
#define GDB_XMM10 50
#define GDB_XMM11 51
#define GDB_XMM12 52
#define GDB_XMM13 53
#define GDB_XMM14 54
#define GDB_XMM15 55
#define GDB_MXCSR 56

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

#ifdef PT_GETXSTATE
#define GDB_GREG_MAX 49
#else
#define GDB_GREG_MAX 40
#endif

int ptrace_arch_gdb_greg_max()
{
	return GDB_GREG_MAX;
}

void ptrace_arch_get_pc(unsigned long *pc)
{
	_read_greg();
	memcpy(pc, _target.reg + offsetof(struct reg, r_rip),
	       sizeof(unsigned long));
}
void ptrace_arch_set_pc(unsigned long pc)
{
	_read_greg();
	memcpy(_target.reg + offsetof(struct reg, r_rip), &pc,
	       sizeof(unsigned long));
	_write_greg();
}


void ptrace_arch_read_fxreg()
{
#ifdef PT_GETXSTATE
	/*
	 * Even if this is defined, the kernel
	 * can return and eror of 'no support'
	 */
	_read_reg(PT_GETXSTATE, PT_SETXSTATE,
		  &_target.fxreg, &_target.fxreg_rw,
		  &_target.fxreg_size);
#endif
}

void ptrace_arch_write_fxreg()
{
#ifdef PT_SETXSTATE
	_write_reg(PT_SETXSTATE, _target.fxreg);
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
void ptrace_arch_get_syscall(void *id, void *arg1, void *arg2,
			     void *arg3, void *arg4, void *ret)
{
  _read_greg();
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

bool ptrace_arch_wait_new_thread(pid_t *out_pid, int *out_status)
{
    return ptrace_os_wait_new_thread(out_pid, out_status);
}

bool ptrace_arch_check_new_thread(pid_t pid, int status, pid_t *out_pid)
{
    return ptrace_os_check_new_thread(pid, status, out_pid);
}
