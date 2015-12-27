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
#include <sys/cdefs.h>
#include <sys/procfs.h>
#include "target_ptrace.h"
#include "global.h"
#include "os.h"
#include "gdb-ppc.h"

#define GDB_GREG_MAX 71

int ptrace_arch_gdb_greg_max()
{
	return GDB_GREG_MAX;
}

#define GP(n) GRLL(gp##n,			\
		   regs.gpr,			\
		   GDB_GPR##n,			\
		   sizeof(unsigned int) * n,	\
		   sizeof(unsigned int),	\
		   sizeof(unsigned int))

/* General */
struct reg_location_list grll[] = {
	GRLL(gp0,  fixreg[0],   GDB_GPR0,   0, 0, 0),
	GRLL(gp1,  fixreg[1],   GDB_GPR1,   0, 0, 0),
	GRLL(gp2,  fixreg[2],   GDB_GPR2,   0, 0, 0),
	GRLL(gp3,  fixreg[3],   GDB_GPR3,   0, 0, 0),
	GRLL(gp4,  fixreg[4],   GDB_GPR4,   0, 0, 0),
	GRLL(gp5,  fixreg[5],   GDB_GPR5,   0, 0, 0),
	GRLL(gp6,  fixreg[6],   GDB_GPR6,   0, 0, 0),
	GRLL(gp7,  fixreg[7],   GDB_GPR7,   0, 0, 0),
	GRLL(gp8,  fixreg[8],   GDB_GPR8,   0, 0, 0),
	GRLL(gp9,  fixreg[9],   GDB_GPR9,   0, 0, 0),
	GRLL(gp10, fixreg[10],  GDB_GPR10,  0, 0, 0),
	GRLL(gp11, fixreg[11],  GDB_GPR11,  0, 0, 0),
	GRLL(gp12, fixreg[12],  GDB_GPR12,  0, 0, 0),
	GRLL(gp13, fixreg[13],  GDB_GPR13,  0, 0, 0),
	GRLL(gp14, fixreg[14],  GDB_GPR14,  0, 0, 0),
	GRLL(gp15, fixreg[15],  GDB_GPR15,  0, 0, 0),
	GRLL(gp16, fixreg[16],  GDB_GPR16,  0, 0, 0),
	GRLL(gp17, fixreg[17],  GDB_GPR17,  0, 0, 0),
	GRLL(gp18, fixreg[18],  GDB_GPR18,  0, 0, 0),
	GRLL(gp19, fixreg[19],  GDB_GPR19,  0, 0, 0),
	GRLL(gp20, fixreg[20],  GDB_GPR20,  0, 0, 0),
	GRLL(gp21, fixreg[21],  GDB_GPR21,  0, 0, 0),
	GRLL(gp22, fixreg[22],  GDB_GPR22,  0, 0, 0),
	GRLL(gp23, fixreg[23],  GDB_GPR23,  0, 0, 0),
	GRLL(gp24, fixreg[24],  GDB_GPR24,  0, 0, 0),
	GRLL(gp25, fixreg[25],  GDB_GPR25,  0, 0, 0),
	GRLL(gp26, fixreg[26],  GDB_GPR26,  0, 0, 0),
	GRLL(gp27, fixreg[27],  GDB_GPR27,  0, 0, 0),
	GRLL(gp28, fixreg[28],  GDB_GPR28,  0, 0, 0),
	GRLL(gp29, fixreg[29],  GDB_GPR29,  0, 0, 0),
	GRLL(gp30, fixreg[30],  GDB_GPR30,  0, 0, 0),
	GRLL(gp31, fixreg[31],  GDB_GPR31,  0, 0, 0),
	GRLL(pc,   pc,          GDB_PC,     0, 0, 0),
	GRLL(lr,   lr,          GDB_LR,     0, 0, 0),
	GRLL(cnt,  ctr,         GDB_CNT,    0, 0, 0),
	GRLL(xer,  xer,         GDB_XER,    0, 0, 0),
	GRLL(cnd,  cr,          GDB_CND,    0, 0, 0),
	{0},
};

#define GDB_FPSCR 70
#define GDB_LAST GDB_FPSCR

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
	{ .name = "scr", .off = 32 * sizeof(double) ,
	  .size = 4, .gdb_size = 4, .gdb = GDB_FPSCR, },
	{0},
};

/*
 * FreeBSD as of 9.0 does not support altivec
 */
#define GDB_VR0  (GDB_LAST + 1)
#define GDB_VR1  (GDB_VR0 + 1)
#define GDB_VR2  (GDB_VR0 + 2)
#define GDB_VR3  (GDB_VR0 + 3)
#define GDB_VR4  (GDB_VR0 + 4)
#define GDB_VR5  (GDB_VR0 + 5)
#define GDB_VR6  (GDB_VR0 + 6)
#define GDB_VR7  (GDB_VR0 + 7)
#define GDB_VR8  (GDB_VR0 + 8)
#define GDB_VR9  (GDB_VR0 + 9)
#define GDB_VR10 (GDB_VR0 + 10)
#define GDB_VR11 (GDB_VR0 + 11)
#define GDB_VR12 (GDB_VR0 + 12)
#define GDB_VR13 (GDB_VR0 + 13)
#define GDB_VR14 (GDB_VR0 + 14)
#define GDB_VR15 (GDB_VR0 + 15)
#define GDB_VR16 (GDB_VR0 + 16)
#define GDB_VR17 (GDB_VR0 + 17)
#define GDB_VR18 (GDB_VR0 + 18)
#define GDB_VR19 (GDB_VR0 + 19)
#define GDB_VR20 (GDB_VR0 + 20)
#define GDB_VR21 (GDB_VR0 + 21)
#define GDB_VR22 (GDB_VR0 + 22)
#define GDB_VR23 (GDB_VR0 + 23)
#define GDB_VR24 (GDB_VR0 + 24)
#define GDB_VR25 (GDB_VR0 + 25)
#define GDB_VR26 (GDB_VR0 + 26)
#define GDB_VR27 (GDB_VR0 + 27)
#define GDB_VR28 (GDB_VR0 + 28)
#define GDB_VR29 (GDB_VR0 + 29)
#define GDB_VR30 (GDB_VR0 + 30)
#define GDB_VR31 (GDB_VR0 + 31)
#define GDB_VSCR (GDB_VR0 + 32)
#define GDB_VSAV (GDB_VR0 + 33)

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
	memcpy(pc, _target.reg + offsetof(struct reg, pc),
	       sizeof(unsigned long));
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc)
{
	_read_greg(tid);
	memcpy(_target.reg + offsetof(struct reg, pc), &pc,
	       sizeof(unsigned long));
	_write_greg(tid);
}

void ptrace_arch_set_singlestep(pid_t pid, long *request)
{
	ptrace_os_set_singlestep(pid, request);
}

void ptrace_arch_clear_singlestep(pid_t pid)
{
	ptrace_os_clear_singlestep(pid);
}

bool ptrace_arch_check_unrecognized_register(int reg, size_t *pad_size)
{
	bool ret = false;
	/* msr not tracked in freebsd */
	if (GDB_MSR == reg) {
		*pad_size = 4;
		ret = true;
	} else if ((GDB_VR0 <= reg) &&
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

void ptrace_arch_read_fxreg(pid_t pid)
{
	/* stub */
}

void ptrace_arch_write_fxreg(pid_t pid)
{
	/* stub */
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

void ptrace_arch_option_set_thread(pid_t pid)
{
    ptrace_os_option_set_thread(pid);
}

bool ptrace_arch_check_new_thread(pid_t pid, int status, pid_t *out_pid)
{
    return ptrace_os_check_new_thread(pid, status, out_pid);
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

bool ptrace_arch_memory_region_info(uint64_t addr, char *out_buff, size_t out_buf_size)
{
  return ptrace_os_memory_region_info(addr, out_buff, out_buf_size);
}
