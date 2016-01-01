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

/* General */
#define DEEBE_REG_STRUCT reg
#include "regmacros.h"
struct reg_location_list grll[] = {
  RLL(gp0,  fixreg[0],   GDB_GPR0,   0, 0, 0, uint, hex,  0,  0,     X,     X),
  RLL(gp1,  fixreg[1],   GDB_GPR1,   0, 0, 0, uint, hex,  1,  1,     sp,    sp),
  RLL(gp2,  fixreg[2],   GDB_GPR2,   0, 0, 0, uint, hex,  2,  2,     X,     X),
  RLL(gp3,  fixreg[3],   GDB_GPR3,   0, 0, 0, uint, hex,  3,  3,  arg1,     arg1),
  RLL(gp4,  fixreg[4],   GDB_GPR4,   0, 0, 0, uint, hex,  4,  4,  arg2,     arg2),
  RLL(gp5,  fixreg[5],   GDB_GPR5,   0, 0, 0, uint, hex,  5,  5,  arg3,     arg3),
  RLL(gp6,  fixreg[6],   GDB_GPR6,   0, 0, 0, uint, hex,  6,  6,  arg4,     arg4),
  RLL(gp7,  fixreg[7],   GDB_GPR7,   0, 0, 0, uint, hex,  7,  7,  arg5,     arg5),
  RLL(gp8,  fixreg[8],   GDB_GPR8,   0, 0, 0, uint, hex,  8,  8,  arg6,     arg6),
  RLL(gp9,  fixreg[9],   GDB_GPR9,   0, 0, 0, uint, hex,  9,  9,  arg7,     arg7),
  RLL(gp10, fixreg[10],  GDB_GPR10,  0, 0, 0, uint, hex, 10, 10,  arg8,     arg8),
  RLL(gp11, fixreg[11],  GDB_GPR11,  0, 0, 0, uint, hex, 11, 11,     X,     X),
  RLL(gp12, fixreg[12],  GDB_GPR12,  0, 0, 0, uint, hex, 12, 12,     X,     X),
  RLL(gp13, fixreg[13],  GDB_GPR13,  0, 0, 0, uint, hex, 13, 13,     X,     X),
  RLL(gp14, fixreg[14],  GDB_GPR14,  0, 0, 0, uint, hex, 14, 14,     X,     X),
  RLL(gp15, fixreg[15],  GDB_GPR15,  0, 0, 0, uint, hex, 15, 15,     X,     X),
  RLL(gp16, fixreg[16],  GDB_GPR16,  0, 0, 0, uint, hex, 16, 16,     X,     X),
  RLL(gp17, fixreg[17],  GDB_GPR17,  0, 0, 0, uint, hex, 17, 17,     X,     X),
  RLL(gp18, fixreg[18],  GDB_GPR18,  0, 0, 0, uint, hex, 18, 18,     X,     X),
  RLL(gp19, fixreg[19],  GDB_GPR19,  0, 0, 0, uint, hex, 19, 19,     X,     X),
  RLL(gp20, fixreg[20],  GDB_GPR20,  0, 0, 0, uint, hex, 20, 20,     X,     X),
  RLL(gp21, fixreg[21],  GDB_GPR21,  0, 0, 0, uint, hex, 21, 21,     X,     X),
  RLL(gp22, fixreg[22],  GDB_GPR22,  0, 0, 0, uint, hex, 22, 22,     X,     X),
  RLL(gp23, fixreg[23],  GDB_GPR23,  0, 0, 0, uint, hex, 23, 23,     X,     X),
  RLL(gp24, fixreg[24],  GDB_GPR24,  0, 0, 0, uint, hex, 24, 24,     X,     X),
  RLL(gp25, fixreg[25],  GDB_GPR25,  0, 0, 0, uint, hex, 25, 25,     X,     X),
  RLL(gp26, fixreg[26],  GDB_GPR26,  0, 0, 0, uint, hex, 26, 26,     X,     X),
  RLL(gp27, fixreg[27],  GDB_GPR27,  0, 0, 0, uint, hex, 27, 27,     X,     X),
  RLL(gp28, fixreg[28],  GDB_GPR28,  0, 0, 0, uint, hex, 28, 28,     X,     X),
  RLL(gp29, fixreg[29],  GDB_GPR29,  0, 0, 0, uint, hex, 29, 29,     X,     X),
  RLL(gp30, fixreg[30],  GDB_GPR30,  0, 0, 0, uint, hex, 30, 30,     X,     X),
  RLL(gp31, fixreg[31],  GDB_GPR31,  0, 0, 0, uint, hex, 31, 31,     X,     X),
  RLL(pc,   pc,          GDB_PC,     0, 0, 0, uint, hex, 110, 110,   X,     X),
  RLL(lr,   lr,          GDB_LR,     0, 0, 0, uint, hex, 108, 108,   X,     X),
  RLL(cnt,  ctr,         GDB_CNT,    0, 0, 0, uint, hex, 109, 109,   X,     X),
  RLL(xer,  xer,         GDB_XER,    0, 0, 0, uint, hex, 101, 101,   X,     X),
  RLL(cnd,  cr,          GDB_CND,    0, 0, 0, uint, hex, 111, 111,   X,     X),
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

#undef DEEBE_REG_STRUCT
#define DEEBE_REG_STRUCT fpreg
#include "regmacros.h"
/* Floating point */
struct reg_location_list frll[] = {
  RLL(fp0,  fpreg[0],   GDB_FPR0,    0, 0, 0, uint, float,  32,  32,     X,     X),
  RLL(fp1,  fpreg[1],   GDB_FPR1,    0, 0, 0, uint, float,  33,  33,     X,     X),
  RLL(fp2,  fpreg[2],   GDB_FPR2,    0, 0, 0, uint, float,  34,  34,     X,     X),
  RLL(fp3,  fpreg[3],   GDB_FPR3,    0, 0, 0, uint, float,  35,  35,     X,     X),
  RLL(fp4,  fpreg[4],   GDB_FPR4,    0, 0, 0, uint, float,  36,  36,     X,     X),
  RLL(fp5,  fpreg[5],   GDB_FPR5,    0, 0, 0, uint, float,  37,  37,     X,     X),
  RLL(fp6,  fpreg[6],   GDB_FPR6,    0, 0, 0, uint, float,  38,  38,     X,     X),
  RLL(fp7,  fpreg[7],   GDB_FPR7,    0, 0, 0, uint, float,  39,  39,     X,     X),
  RLL(fp8,  fpreg[8],   GDB_FPR8,    0, 0, 0, uint, float,  40,  40,     X,     X),
  RLL(fp9,  fpreg[9],   GDB_FPR9,    0, 0, 0, uint, float,  41,  41,     X,     X),
  RLL(fp10, fpreg[10],  GDB_FPR10,   0, 0, 0, uint, float,  42,  42,     X,     X),
  RLL(fp11, fpreg[11],  GDB_FPR11,   0, 0, 0, uint, float,  43,  43,     X,     X),
  RLL(fp12, fpreg[12],  GDB_FPR12,   0, 0, 0, uint, float,  44,  44,     X,     X),
  RLL(fp13, fpreg[13],  GDB_FPR13,   0, 0, 0, uint, float,  45,  45,     X,     X),
  RLL(fp14, fpreg[14],  GDB_FPR14,   0, 0, 0, uint, float,  46,  46,     X,     X),
  RLL(fp15, fpreg[15],  GDB_FPR15,   0, 0, 0, uint, float,  47,  47,     X,     X),
  RLL(fp16, fpreg[16],  GDB_FPR16,   0, 0, 0, uint, float,  48,  48,     X,     X),
  RLL(fp17, fpreg[17],  GDB_FPR17,   0, 0, 0, uint, float,  49,  49,     X,     X),
  RLL(fp18, fpreg[18],  GDB_FPR18,   0, 0, 0, uint, float,  50,  50,     X,     X),
  RLL(fp19, fpreg[19],  GDB_FPR19,   0, 0, 0, uint, float,  51,  51,     X,     X),
  RLL(fp20, fpreg[20],  GDB_FPR20,   0, 0, 0, uint, float,  52,  52,     X,     X),
  RLL(fp21, fpreg[21],  GDB_FPR21,   0, 0, 0, uint, float,  53,  53,     X,     X),
  RLL(fp22, fpreg[22],  GDB_FPR22,   0, 0, 0, uint, float,  54,  54,     X,     X),
  RLL(fp23, fpreg[23],  GDB_FPR23,   0, 0, 0, uint, float,  55,  55,     X,     X),
  RLL(fp24, fpreg[24],  GDB_FPR24,   0, 0, 0, uint, float,  56,  56,     X,     X),
  RLL(fp25, fpreg[25],  GDB_FPR25,   0, 0, 0, uint, float,  57,  57,     X,     X),
  RLL(fp26, fpreg[26],  GDB_FPR26,   0, 0, 0, uint, float,  58,  58,     X,     X),
  RLL(fp27, fpreg[27],  GDB_FPR27,   0, 0, 0, uint, float,  59,  59,     X,     X),
  RLL(fp28, fpreg[28],  GDB_FPR28,   0, 0, 0, uint, float,  60,  60,     X,     X),
  RLL(fp29, fpreg[29],  GDB_FPR29,   0, 0, 0, uint, float,  61,  61,     X,     X),
  RLL(fp30, fpreg[30],  GDB_FPR30,   0, 0, 0, uint, float,  62,  62,     X,     X),
  RLL(fp31, fpreg[31],  GDB_FPR31,   0, 0, 0, uint, float,  63,  63,     X,     X),
  RLL(scr,  fpscr,     GDB_FPSCR,   0, 0, 0, uint, hex,  65,  64,     X,     X),
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
bool ptrace_arch_read_auxv(char *out_buff, size_t out_buf_size, size_t offset, size_t *size)
{
  return ptrace_os_read_auxv(out_buff, out_buf_size, offset, size);
}

const char *ptrace_arch_get_xml_register_string()
{
  static char *str = "powerpc";
  return str;
}

size_t ptrace_arch_swbrk_rollback()
{
  return 0;
}
