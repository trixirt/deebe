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
#include "global.h"
#include "os.h"

union reg_dirty {
	struct {
		unsigned int  gregs:1;
		unsigned int  fregs:1;
		unsigned int fxregs:1;
	} r;
	unsigned int u;
} dirt;

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
	GRLL(ebx,      regs.ebx,      GDB_EBX,      0, 0, 0),
	GRLL(ecx,      regs.ecx,      GDB_ECX,      0, 0, 0),
	GRLL(edx,      regs.edx,      GDB_EDX,      0, 0, 0),
	GRLL(esi,      regs.esi,      GDB_ESI,      0, 0, 0),
	GRLL(edi,      regs.edi,      GDB_EDI,      0, 0, 0),
	GRLL(ebp,      regs.ebp,      GDB_EBP,      0, 0, 0),
	GRLL(eax,      regs.eax,      GDB_EAX,      0, 0, 0),
	GRLL(ds,       regs.xds,      GDB_DS,       0, 2, 4),
	GRLL(es,       regs.xes,      GDB_ES,       0, 2, 4),
	GRLL(fs,       regs.xfs,      GDB_FS,       0, 2, 4),
	GRLL(gs,       regs.xgs,      GDB_GS,       0, 2, 4),
	GRLL(orig_eax, regs.orig_eax, GDB_ORIG_EAX, 0, 0, 0),
	GRLL(eip,      regs.eip,      GDB_EIP,      0, 0, 0),
	GRLL(cs,       regs.xcs,      GDB_CS,       0, 2, 4),
	GRLL(eflags,   regs.eflags,   GDB_EFLAGS,   0, 0, 0),
	GRLL(esp,      regs.esp,      GDB_ESP,      0, 0, 0),
	GRLL(ss,       regs.xss,      GDB_SS,       0, 2, 4),
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
	FRLL(ctrl, cwd,      GDB_FCTRL, 0,  2, 4),
	FRLL(stat, swd,      GDB_FSTAT, 0,  2, 4),
	FRLL(tag,  twd,      GDB_FTAG,  0,  2, 4),
	FRLL(ioff, fip,      GDB_FIOFF, 0,  4, 4),
	FRLL(iseg, fcs,      GDB_FISEG, 0,  2, 4),
	FRLL(op,   fcs,      GDB_FOP,   2,  2, 4),
	FRLL(ooff, foo,      GDB_FOOFF, 0,  4, 4),
	FRLL(oseg, fos,      GDB_FOSEG, 0,  2, 4),
	FRLL(st0,  st_space, GDB_FST0,  0, 10, 10),
	FRLL(st1,  st_space, GDB_FST1, 10, 10, 10),
	FRLL(st2,  st_space, GDB_FST2, 20, 10, 10),
	FRLL(st3,  st_space, GDB_FST3, 30, 10, 10),
	FRLL(st4,  st_space, GDB_FST4, 40, 10, 10),
	FRLL(st5,  st_space, GDB_FST5, 50, 10, 10),
	FRLL(st6,  st_space, GDB_FST6, 60, 10, 10),
	FRLL(st7,  st_space, GDB_FST7, 70, 10, 10),
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

#define FXRLL(N, E, GDB, O, S, GDB_S)					\
{								\
	.off = (O) + offsetof(struct user_fpxregs_struct, E),	\
	.size = (0 != S) ? (S) : msizeof(struct user_fpxregs_struct, E), \
	.gdb = (GDB),					\
	.name = #N,					\
	.gdb_size = (0 != GDB_S) ? (GDB_S) : msizeof(struct user_fpxregs_struct, E), \
}

struct reg_location_list fxrll[] = {
	FXRLL(mm0, xmm_space, GDB_XMM0, 0x00, 0x10, 0x10),
	FXRLL(mm1, xmm_space, GDB_XMM1, 0x10, 0x10, 0x10),
	FXRLL(mm2, xmm_space, GDB_XMM2, 0x20, 0x10, 0x10),
	FXRLL(mm3, xmm_space, GDB_XMM3, 0x30, 0x10, 0x10),
	FXRLL(mm4, xmm_space, GDB_XMM4, 0x40, 0x10, 0x10),
	FXRLL(mm5, xmm_space, GDB_XMM5, 0x50, 0x10, 0x10),
	FXRLL(mm6, xmm_space, GDB_XMM6, 0x60, 0x10, 0x10),
	FXRLL(mm7, xmm_space, GDB_XMM7, 0x70, 0x10, 0x10),
	FXRLL(csr, mxcsr,     GDB_MXCSR,   0,    0, 0),
	{0},
};

#define GDB_GREG_MAX 16

int ptrace_arch_gdb_greg_max()
{
	return GDB_GREG_MAX;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc)
{
	_read_greg(tid);
	memcpy(pc, _target.reg + offsetof(struct user, regs.eip),
	       sizeof(unsigned long));
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc)
{
	_read_greg(tid);
	memcpy(_target.reg + offsetof(struct user, regs.eip), &pc,
	       sizeof(unsigned long));
	_write_greg(tid);
}

bool ptrace_arch_check_unrecognized_register(/*@unused@*/int reg,
					     /*@unused@*/size_t *pad_size)
{
	bool ret = false;
	return ret;
}

void ptrace_arch_read_fxreg(pid_t tid, size_t size)
{
	ptrace_os_read_fxreg(tid);
}

void ptrace_arch_write_fxreg(pid_t tid)
{
	ptrace_os_write_fxreg(tid);
}

void ptrace_arch_option_set_syscall(pid_t pid)
{
	ptrace_os_option_set_syscall(pid);
}

bool ptrace_arch_check_syscall(pid_t pid, int *in_out_sig)
{
	return ptrace_os_check_syscall(pid, in_out_sig);
}

void ptrace_arch_get_syscall(pid_t tid, void *id, void *arg1, void *arg2,
			     void *arg3, void *arg4, void *ret)
{
	_read_greg(tid);
	memcpy(id, _target.reg + offsetof(struct user, regs.orig_eax),
	       sizeof(unsigned long));
	memcpy(arg1, _target.reg + offsetof(struct user, regs.ebx),
	       sizeof(unsigned long));
	memcpy(arg2, _target.reg + offsetof(struct user, regs.ecx),
	       sizeof(unsigned long));
	memcpy(arg3, _target.reg + offsetof(struct user, regs.edx),
	       sizeof(unsigned long));
	memcpy(arg4, _target.reg + offsetof(struct user, regs.esi),
	       sizeof(unsigned long));
	memcpy(ret,  _target.reg + offsetof(struct user, regs.eax),
	       sizeof(unsigned long));
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
