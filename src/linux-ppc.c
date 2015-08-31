/*
 * Copyright (c) 2012-2015, Juniper Networks, Inc.
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
#include "gdb-ppc.h"

#define GDB_GREG_MAX 70

int ptrace_arch_gdb_greg_max()
{
	return GDB_GREG_MAX;
}

#define GP(n)						\
	GRLL(gp##n,					\
	     regs.gpr,					\
	     GDB_GPR##n,				\
	     sizeof(unsigned int) * n,			\
	     sizeof(unsigned int),			\
	     sizeof(unsigned int)			\
	)

/* General */
struct reg_location_list grll[] = {
	GRLL(gp0,  regs.gpr[0],   GDB_GPR0,   0, 0, 0),
	GRLL(gp1,  regs.gpr[1],   GDB_GPR1,   0, 0, 0),
	GRLL(gp2,  regs.gpr[2],   GDB_GPR2,   0, 0, 0),
	GRLL(gp3,  regs.gpr[3],   GDB_GPR3,   0, 0, 0),
	GRLL(gp4,  regs.gpr[4],   GDB_GPR4,   0, 0, 0),
	GRLL(gp5,  regs.gpr[5],   GDB_GPR5,   0, 0, 0),
	GRLL(gp6,  regs.gpr[6],   GDB_GPR6,   0, 0, 0),
	GRLL(gp7,  regs.gpr[7],   GDB_GPR7,   0, 0, 0),
	GRLL(gp8,  regs.gpr[8],   GDB_GPR8,   0, 0, 0),
	GRLL(gp9,  regs.gpr[9],   GDB_GPR9,   0, 0, 0),
	GRLL(gp10, regs.gpr[10],  GDB_GPR10,  0, 0, 0),
	GRLL(gp11, regs.gpr[11],  GDB_GPR11,  0, 0, 0),
	GRLL(gp12, regs.gpr[12],  GDB_GPR12,  0, 0, 0),
	GRLL(gp13, regs.gpr[13],  GDB_GPR13,  0, 0, 0),
	GRLL(gp14, regs.gpr[14],  GDB_GPR14,  0, 0, 0),
	GRLL(gp15, regs.gpr[15],  GDB_GPR15,  0, 0, 0),
	GRLL(gp16, regs.gpr[16],  GDB_GPR16,  0, 0, 0),
	GRLL(gp17, regs.gpr[17],  GDB_GPR17,  0, 0, 0),
	GRLL(gp18, regs.gpr[18],  GDB_GPR18,  0, 0, 0),
	GRLL(gp19, regs.gpr[19],  GDB_GPR19,  0, 0, 0),
	GRLL(gp20, regs.gpr[20],  GDB_GPR20,  0, 0, 0),
	GRLL(gp21, regs.gpr[21],  GDB_GPR21,  0, 0, 0),
	GRLL(gp22, regs.gpr[22],  GDB_GPR22,  0, 0, 0),
	GRLL(gp23, regs.gpr[23],  GDB_GPR23,  0, 0, 0),
	GRLL(gp24, regs.gpr[24],  GDB_GPR24,  0, 0, 0),
	GRLL(gp25, regs.gpr[25],  GDB_GPR25,  0, 0, 0),
	GRLL(gp26, regs.gpr[26],  GDB_GPR26,  0, 0, 0),
	GRLL(gp27, regs.gpr[27],  GDB_GPR27,  0, 0, 0),
	GRLL(gp28, regs.gpr[28],  GDB_GPR28,  0, 0, 0),
	GRLL(gp29, regs.gpr[29],  GDB_GPR29,  0, 0, 0),
	GRLL(gp30, regs.gpr[30],  GDB_GPR30,  0, 0, 0),
	GRLL(gp31, regs.gpr[31],  GDB_GPR31,  0, 0, 0),
	GRLL(pc,   regs.nip,      GDB_PC,     0, 0, 0),
	GRLL(lr,   regs.link,     GDB_LR,     0, 0, 0),
	GRLL(msr,  regs.msr,      GDB_MSR,    0, 0, 0),
	GRLL(cnt,  regs.ctr,      GDB_CNT,    0, 0, 0),
	GRLL(xer,  regs.xer,      GDB_XER,    0, 0, 0),
	GRLL(cnd,  regs.ccr,      GDB_CND,    0, 0, 0),
	GRLL(mq,   regs.mq,       GDB_MQ,     0, 0, 0),
	{0},
};

#define GDB_FPSCR 71
#define FP(NAME, n)					\
	{						\
		.off    = sizeof(double) * n,		\
			.size   = sizeof(double),	\
			.gdb    = GDB_FPR##n,		\
			.name   = #NAME,		\
			.gdb_size   = sizeof(double),	\
			}

/* Floating point */
struct reg_location_list frll[] = {
	FP(fp0, 0),   FP(fp1, 1),   FP(fp2, 2),   FP(fp3, 3),
	FP(fp4, 4),   FP(fp5, 5),   FP(fp6, 6),   FP(fp7, 7),
	FP(fp8, 8),   FP(fp9, 9),   FP(fp10, 10), FP(fp11, 11),
	FP(fp12, 12), FP(fp13, 13), FP(fp14, 14), FP(fp15, 15),
	FP(fp16, 16), FP(fp17, 17), FP(fp18, 18), FP(fp19, 19),
	FP(fp20, 20), FP(fp21, 21), FP(fp22, 22), FP(fp23, 23),
	FP(fp24, 24), FP(fp25, 25), FP(fp26, 26), FP(fp27, 27),
	FP(fp28, 28), FP(fp29, 29), FP(fp30, 30), FP(fp31, 31),
	{
		.name = "scr", .off = 32 * sizeof(double) , .size = 4,
		.gdb_size = 4, .gdb = GDB_FPSCR,
	},
	{0},
};

/* XXX Check moving to gdb-ppc.h */
#define GDB_VR0  0x48
#define GDB_VR1  0x49
#define GDB_VR2  0x4A
#define GDB_VR3  0x4B
#define GDB_VR4  0x4C
#define GDB_VR5  0x4D
#define GDB_VR6  0x4E
#define GDB_VR7  0x4F
#define GDB_VR8  0x50
#define GDB_VR9  0x51
#define GDB_VR10 0x52
#define GDB_VR11 0x53
#define GDB_VR12 0x54
#define GDB_VR13 0x55
#define GDB_VR14 0x56
#define GDB_VR15 0x57
#define GDB_VR16 0x58
#define GDB_VR17 0x59
#define GDB_VR18 0x5A
#define GDB_VR19 0x5B
#define GDB_VR20 0x5C
#define GDB_VR21 0x5D
#define GDB_VR22 0x5E
#define GDB_VR23 0x5F
#define GDB_VR24 0x60
#define GDB_VR25 0x61
#define GDB_VR26 0x62
#define GDB_VR27 0x63
#define GDB_VR28 0x64
#define GDB_VR29 0x65
#define GDB_VR30 0x66
#define GDB_VR31 0x67
#define GDB_VSCR 0x68
#define GDB_VSAV 0x69

/* Extended */
struct reg_location_list fxrll[] = {
	{0},
};

size_t ptrace_arch_swbreak_size() {
  return 4;
}

int ptrace_arch_swbreak_insn(void *bdata)
{
	int ret = RET_ERR;
	/* Illegal instruction is 0's */
	memset(bdata, 0, 4);
	ret = RET_OK;
	return ret;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc)
{
	_read_greg(tid);
	memcpy(pc, _target.reg + offsetof(struct user, regs.nip),
	       sizeof(unsigned long));
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc)
{
	_read_greg(tid);
	memcpy(_target.reg + offsetof(struct user, regs.nip), &pc,
	       sizeof(unsigned long));
	_write_greg(tid);
}

void ptrace_arch_set_singlestep(/*@unused@*/pid_t pid,
				/*@unused@*/long *request)
{
	/* Let the kernel handle the heavy lifting */
	*request = PTRACE_SINGLESTEP;
}

void ptrace_arch_clear_singlestep(/*@unused@*/pid_t pid)
{
}

bool ptrace_arch_check_unrecognized_register(/*@unused@*/int reg,
					     /*@unused@*/size_t *pad_size)
{
	bool ret = false;
	if ((GDB_VR0 <= reg) &&
	    (GDB_VR31 >= reg)) {
		/* Altivec reg */
		*pad_size = 16;
		ret = true;
	} else if (GDB_VSCR == reg) {
		*pad_size = 4;
		ret = true;
	} else if (GDB_VSAV == reg) {
		*pad_size = 4;
		ret = true;
	}
	return ret;
}

int ptrace_arch_signal_to_gdb(int sig)
{
	return host_signal_to_gdb(sig);
}

int ptrace_arch_signal_from_gdb(int gdb)
{
	return host_signal_from_gdb(gdb);
}

bool ptrace_arch_support_watchpoint(pid_t tid, int type)
{
	bool ret = false;
	return ret;
}

bool ptrace_arch_add_watchpoint(pid_t pid, int type,
				unsigned long addr, size_t len)
{
	bool ret = false;
	return ret;
}

bool ptrace_arch_remove_watchpoint(pid_t pid, int type,
				   unsigned long addr, size_t len)
{
	bool ret = false;
	return ret;
}

bool ptrace_arch_hit_watchpoint(pid_t pid, unsigned long *addr)
{
	bool ret = false;
	return ret;
}

void ptrace_arch_read_fxreg(pid_t tid)
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

void ptrace_arch_read_dbreg(pid_t tid)
{
  /* noop */
}

void ptrace_arch_write_dbreg(pid_t tid)
{
  /* noop */
}

bool ptrace_arch_support_hardware_breakpoints(pid_t tid)
{
  return false;
}
bool ptrace_arch_add_hardware_breakpoint(pid_t tid, unsigned long addr,
					 size_t len)
{
  return false;
}
bool ptrace_arch_remove_hardware_breakpoint(pid_t tid, unsigned long addr,
					    size_t len)
{
  return false;
}

bool ptrace_arch_hit_hardware_breakpoint(pid_t tid, unsigned long pc)
{
  return false;
}
