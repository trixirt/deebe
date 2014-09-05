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
#include "target_ptrace.h"
#include <machine/reg.h>
#include "os.h"
#include "global.h"

#define GDB_EAX       0
#define GDB_ECX       1
#define GDB_EDX       2
#define GDB_EBX       3
#define GDB_ESP       4
#define GDB_EBP       5
#define GDB_ESI       6
#define GDB_EDI       7
#define GDB_EIP       8
#define GDB_EFLAGS    9
#define GDB_CS       10
#define GDB_SS       11
#define GDB_DS       12
#define GDB_ES       13
#define GDB_FS       14
#define GDB_GS       15
#define GDB_ORIG_EAX 41

struct reg_location_list grll[] = {
	/* general */
	GRLL(ebx,    r_ebx,     GDB_EBX,      0, 0, 0),
	GRLL(ecx,    r_ecx,     GDB_ECX,      0, 0, 0),
	GRLL(edx,    r_edx,     GDB_EDX,      0, 0, 0),
	GRLL(esi,    r_esi,     GDB_ESI,      0, 0, 0),
	GRLL(edi,    r_edi,     GDB_EDI,      0, 0, 0),
	GRLL(ebp,    r_ebp,     GDB_EBP,      0, 0, 0),
	GRLL(eax,    r_eax,     GDB_EAX,      0, 0, 0),
	GRLL(ds,     r_ds,      GDB_DS,       0, 2, 4),
	GRLL(es,     r_es,      GDB_ES,       0, 2, 4),
	GRLL(fs,     r_fs,      GDB_FS,       0, 2, 4),
	GRLL(gs,     r_gs,      GDB_GS,       0, 2, 4),
	GRLL(eip,    r_eip,     GDB_EIP,      0, 0, 0),
	GRLL(cs,     r_cs,      GDB_CS,       0, 2, 4),
	GRLL(eflags, r_eflags,  GDB_EFLAGS,   0, 0, 0),
	GRLL(esp,    r_esp,     GDB_ESP,      0, 0, 0),
	GRLL(ss,     r_ss,      GDB_SS,       0, 2, 4),
	{0},
};


#define GDB_FST0  16
#define GDB_FST1  17
#define GDB_FST2  18
#define GDB_FST3  19
#define GDB_FST4  20
#define GDB_FST5  21
#define GDB_FST6  22
#define GDB_FST7  23
#define GDB_FCTRL 24
#define GDB_FSTAT 25
#define GDB_FTAG  26
#define GDB_FISEG 27
#define GDB_FIOFF 28
#define GDB_FOSEG 29
#define GDB_FOOFF 30
#define GDB_FOP   31

struct reg_location_list frll[] = {
	/* floating */
	FRLL(ctrl, fpr_env[0], GDB_FCTRL, 0, 2, 4),
	FRLL(stat, fpr_env[1], GDB_FSTAT, 0, 2, 4),
	FRLL(tag,  fpr_env[2], GDB_FTAG,  0, 2, 4),
	FRLL(ioff, fpr_env[3], GDB_FIOFF, 0, 4, 4),
	FRLL(iseg, fpr_env[4], GDB_FISEG, 0, 2, 4),
	FRLL(op,   fpr_env[5], GDB_FOP,   2, 2, 4),
	FRLL(ooff, fpr_env[6], GDB_FOOFF, 0, 4, 4),
	FRLL(oseg, fpr_ex_sw,  GDB_FOSEG, 0, 2, 4),
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

#define GDB_XMM0  32
#define GDB_XMM1  33
#define GDB_XMM2  34
#define GDB_XMM3  35
#define GDB_XMM4  36
#define GDB_XMM5  37
#define GDB_XMM6  38
#define GDB_XMM7  39
#define GDB_MXCSR 40

#define FXRLL(E, GDB, O, S)						\
	{								\
		.off = (O) + offsetof(struct xmmreg, E),		\
			.size = (S) ? (S) : msizeof(struct xmmreg, E),	\
			.gdb = (GDB),					\
	}

struct reg_location_list fxrll[] = {
	/* extended */
#ifdef PT_GETXMMREGS
	FXRLL(xmm_reg[0], GDB_XMM0,  0, 0),
	FXRLL(xmm_reg[1], GDB_XMM1,  0, 0),
	FXRLL(xmm_reg[2], GDB_XMM2,  0, 0),
	FXRLL(xmm_reg[3], GDB_XMM3,  0, 0),
	FXRLL(xmm_reg[4], GDB_XMM4,  0, 0),
	FXRLL(xmm_reg[5], GDB_XMM5,  0, 0),
	FXRLL(xmm_reg[6], GDB_XMM6,  0, 0),
	FXRLL(xmm_reg[7], GDB_XMM7,  0, 0),
	FXRLL(xmm_env, GDB_MXCSR, 0, 0),
#endif
	{0},
};

/* 
 * GDB 7.7 complains when mmx is include
 * so only include gpr and fpr.
 */
#define GDB_GREG_MAX 32

int ptrace_arch_gdb_greg_max()
{
	return GDB_GREG_MAX;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc)
{
	_read_greg(tid);
	memcpy(pc, _target.reg + offsetof(struct reg, r_eip),
	       sizeof(unsigned long));
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc)
{
	_read_greg(tid);
	memcpy(_target.reg + offsetof(struct reg, r_eip), &pc,
	       sizeof(unsigned long));
	_write_greg(tid);
}

void ptrace_arch_read_fxreg(pid_t tid, size_t size)
{
#ifdef PT_GETXMMREGS
    _read_reg(tid, PT_GETXMMREGS, PT_SETXMMREGS,
		  &_target.fxreg, &_target.fxreg_rw,
		  &_target.fxreg_size);
#endif
}

void ptrace_arch_write_fxreg(pid_t tid)
{
#ifdef PT_GETXMMREGS
    _write_reg(tid, PT_SETXMMREGS, _target.fxreg);
#endif
}

void ptrace_arch_option_set_syscall(pid_t pid)
{
	ptrace_os_option_set_syscall(pid);
}

bool ptrace_arch_check_syscall(pid_t pid, int *in_out_sig)
{
	bool ret = false;
#if 0
	/* Older FreeBSD's do not have the syscall enter exit flags */
#ifdef PL_FLAG_SCE
	   struct ptrace_lwpinfo info;
	if (0 == PTRACE(PT_LWPINFO, pid, &info, sizeof(info))) {
		if (info.pl_flags & PL_FLAG_SCE)
			ret = true;
		else if (info.pl_flags & PL_FLAG_SCX)
			ret = true;
	}
#endif
#endif
	return ret;
}

extern int _ptrace_read_mem(uint64_t addr, uint8_t *data, size_t size,
			    size_t *read_size, bool breakpoint_check);
void ptrace_arch_get_syscall(pid_t tid, void *id, void *arg1, void *arg2,
			     void *arg3, void *arg4, void *ret)
{
  _read_greg(tid);
  unsigned long sp;
  int size = sizeof(unsigned long);
  memcpy(&sp, _target.reg + offsetof(struct reg, r_esp), size);
  memcpy(id, _target.reg + offsetof(struct reg, r_eax), size);
  _ptrace_read_mem(sp + (1 * size), arg1, size, NULL, false);
  _ptrace_read_mem(sp + (2 * size), arg2, size, NULL, false);
  _ptrace_read_mem(sp + (3 * size), arg3, size, NULL, false);
  _ptrace_read_mem(sp + (4 * size), arg4, size, NULL, false);
  memcpy(ret, _target.reg + offsetof(struct reg, r_eax), size);
}

void ptrace_arch_option_set_thread(pid_t pid)
{
    ptrace_os_option_set_thread(pid);
}

bool ptrace_arch_check_new_thread(pid_t pid, int status, pid_t *out_pid)
{
    return ptrace_os_check_new_thread(pid, status, out_pid);
}
