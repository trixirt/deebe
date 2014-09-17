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

#define GDB_GREG_MAX 32

int ptrace_arch_gdb_greg_max()
{
	return GDB_GREG_MAX;
}

#define GDB_ZERO 0
#define GDB_AT 1
#define GDB_V0 2
#define GDB_V1 3
#define GDB_A0 4
#define GDB_A1 5
#define GDB_A2 6
#define GDB_A3 7
#define GDB_T0 8
#define GDB_T1 9
#define GDB_T2 10
#define GDB_T3 11
#define GDB_T4 12
#define GDB_T5 13
#define GDB_T6 14
#define GDB_T7 15
#define GDB_S0 16
#define GDB_S1 17
#define GDB_S2 18
#define GDB_S3 19
#define GDB_S4 20
#define GDB_S5 21
#define GDB_S6 22
#define GDB_S7 23
#define GDB_T8 24
#define GDB_T9 25
#define GDB_K0 26
#define GDB_K1 27
#define GDB_GP 28
#define GDB_SP 29
#define GDB_S8 30
#define GDB_RA 31
#define GDB_STATUS 32 /* ? */
#define GDB_LO 33
#define GDB_HI 34
#define GDB_BADVADDR 35
#define GDB_CAUSE 36
#define GDB_PC 37

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define ENDIAN_OFFSET 0
#elif __BYTE_ORDER == __BIG_ENDIAN
# define ENDIAN_OFFSET 4
#endif

/* General */
#undef GRLL
#define GRLL(N, E, GDB, O, S, GDB_S)	\
{				\
	.off = (O) + (8 * (E)),	\
	.size = (S),		\
	.gdb = (GDB),		\
	.name = #N,		\
	.gdb_size = (GDB_S),	\
}

struct reg_location_list grll[] = {
	GRLL(zero,     0,  GDB_ZERO,     ENDIAN_OFFSET, 4, 4),
	GRLL(at,       1,  GDB_AT,       ENDIAN_OFFSET, 4, 4),
	GRLL(v0,       2,  GDB_V0,       ENDIAN_OFFSET, 4, 4),
	GRLL(v1,       3,  GDB_V1,       ENDIAN_OFFSET, 4, 4),
	GRLL(a0,       4,  GDB_A0,       ENDIAN_OFFSET, 4, 4),
	GRLL(a1,       5,  GDB_A1,       ENDIAN_OFFSET, 4, 4),
	GRLL(a2,       6,  GDB_A2,       ENDIAN_OFFSET, 4, 4),
	GRLL(a3,       7,  GDB_A3,       ENDIAN_OFFSET, 4, 4),
	GRLL(t0,       8,  GDB_T0,       ENDIAN_OFFSET, 4, 4),
	GRLL(t1,       9,  GDB_T1,       ENDIAN_OFFSET, 4, 4),
	GRLL(t2,       10, GDB_T2,       ENDIAN_OFFSET, 4, 4),
	GRLL(t3,       11, GDB_T3,       ENDIAN_OFFSET, 4, 4),
	GRLL(t4,       12, GDB_T4,       ENDIAN_OFFSET, 4, 4),
	GRLL(t5,       13, GDB_T5,       ENDIAN_OFFSET, 4, 4),
	GRLL(t6,       14, GDB_T6,       ENDIAN_OFFSET, 4, 4),
	GRLL(t7,       15, GDB_T7,       ENDIAN_OFFSET, 4, 4),
	GRLL(s0,       16, GDB_S0,       ENDIAN_OFFSET, 4, 4),
	GRLL(s1,       17, GDB_S1,       ENDIAN_OFFSET, 4, 4),
	GRLL(s2,       18, GDB_S2,       ENDIAN_OFFSET, 4, 4),
	GRLL(s3,       19, GDB_S3,       ENDIAN_OFFSET, 4, 4),
	GRLL(s4,       20, GDB_S4,       ENDIAN_OFFSET, 4, 4),
	GRLL(s5,       21, GDB_S5,       ENDIAN_OFFSET, 4, 4),
	GRLL(s6,       22, GDB_S6,       ENDIAN_OFFSET, 4, 4),
	GRLL(s7,       23, GDB_S7,       ENDIAN_OFFSET, 4, 4),
	GRLL(t8,       24, GDB_T8,       ENDIAN_OFFSET, 4, 4),
	GRLL(t9,       25, GDB_T9,       ENDIAN_OFFSET, 4, 4),
	GRLL(k0,       26, GDB_K0,       ENDIAN_OFFSET, 4, 4),
	GRLL(k1,       27, GDB_K1,       ENDIAN_OFFSET, 4, 4),
	GRLL(gp,       28, GDB_GP,       ENDIAN_OFFSET, 4, 4),
	GRLL(sp,       29, GDB_SP,       ENDIAN_OFFSET, 4, 4),
	GRLL(s8,       30, GDB_S8,       ENDIAN_OFFSET, 4, 4),
	GRLL(ra,       31, GDB_RA,       ENDIAN_OFFSET, 4, 4),
	GRLL(lo,       32, GDB_LO,       ENDIAN_OFFSET, 4, 4),
	GRLL(hi,       33, GDB_HI,       ENDIAN_OFFSET, 4, 4),
	GRLL(pc,       34, GDB_PC,       ENDIAN_OFFSET, 4, 4),
	GRLL(badvaddr, 35, GDB_BADVADDR, ENDIAN_OFFSET, 4, 4),
	GRLL(status,   36, GDB_STATUS,   ENDIAN_OFFSET, 4, 4),
	GRLL(cause,    37, GDB_CAUSE,    ENDIAN_OFFSET, 4, 4),
	{0},
};

#define GDB_FPR0  38
#define GDB_FPR1  (GDB_FPR0 + 0x01)
#define GDB_FPR2  (GDB_FPR0 + 0x02)
#define GDB_FPR3  (GDB_FPR0 + 0x03)
#define GDB_FPR4  (GDB_FPR0 + 0x04)
#define GDB_FPR5  (GDB_FPR0 + 0x05)
#define GDB_FPR6  (GDB_FPR0 + 0x06)
#define GDB_FPR7  (GDB_FPR0 + 0x07)
#define GDB_FPR8  (GDB_FPR0 + 0x08)
#define GDB_FPR9  (GDB_FPR0 + 0x09)
#define GDB_FPR10 (GDB_FPR0 + 0x0A)
#define GDB_FPR11 (GDB_FPR0 + 0x0B)
#define GDB_FPR12 (GDB_FPR0 + 0x0C)
#define GDB_FPR13 (GDB_FPR0 + 0x0D)
#define GDB_FPR14 (GDB_FPR0 + 0x0E)
#define GDB_FPR15 (GDB_FPR0 + 0x0F)
#define GDB_FPR16 (GDB_FPR0 + 0x10)
#define GDB_FPR17 (GDB_FPR0 + 0x11)
#define GDB_FPR18 (GDB_FPR0 + 0x12)
#define GDB_FPR19 (GDB_FPR0 + 0x13)
#define GDB_FPR20 (GDB_FPR0 + 0x14)
#define GDB_FPR21 (GDB_FPR0 + 0x15)
#define GDB_FPR22 (GDB_FPR0 + 0x16)
#define GDB_FPR23 (GDB_FPR0 + 0x17)
#define GDB_FPR24 (GDB_FPR0 + 0x18)
#define GDB_FPR25 (GDB_FPR0 + 0x19)
#define GDB_FPR26 (GDB_FPR0 + 0x1A)
#define GDB_FPR27 (GDB_FPR0 + 0x1B)
#define GDB_FPR28 (GDB_FPR0 + 0x1C)
#define GDB_FPR29 (GDB_FPR0 + 0x1D)
#define GDB_FPR30 (GDB_FPR0 + 0x1E)
#define GDB_FPR31 (GDB_FPR0 + 0x1F)

#define GDB_FCR31 (GDB_FPR0 + 0x20)
#define GDB_FCR0  (GDB_FPR0 + 0x21)

#define GDB_UNUSED_72 72
#define GDB_UNUSED_73 73
#define GDB_UNUSED_74 74
#define GDB_UNUSED_75 75
#define GDB_UNUSED_76 76
#define GDB_UNUSED_77 77
#define GDB_UNUSED_78 78
#define GDB_UNUSED_79 79
#define GDB_UNUSED_80 80
#define GDB_UNUSED_81 81
#define GDB_UNUSED_82 82
#define GDB_UNUSED_83 83
#define GDB_UNUSED_84 84
#define GDB_UNUSED_85 85
#define GDB_UNUSED_86 86
#define GDB_UNUSED_87 87
#define GDB_UNUSED_88 88
#define GDB_UNUSED_89 89


#define FP(NAME, n)					\
	{						\
		.off    = sizeof(uint64_t) * n,		\
			.size   = sizeof(uint64_t),	\
			.gdb    = GDB_FPR##n,		\
			.name   = #NAME,		\
			.gdb_size   = sizeof(uint64_t),	\
			}

/* Floating point */
struct reg_location_list frll[] = {
	FP(fp0,   0),   FP(fp1, 1),   FP(fp2, 2),   FP(fp3, 3),
	FP(fp4,   4),   FP(fp5, 5),   FP(fp6, 6),   FP(fp7, 7),
	FP(fp8,   8),   FP(fp9, 9), FP(fp10, 10), FP(fp11, 11),
	FP(fp12, 12), FP(fp13, 13), FP(fp14, 14), FP(fp15, 15),
	FP(fp16, 16), FP(fp17, 17), FP(fp18, 18), FP(fp19, 19),
	FP(fp20, 20), FP(fp21, 21), FP(fp22, 22), FP(fp23, 23),
	FP(fp24, 24), FP(fp25, 25), FP(fp26, 26), FP(fp27, 27),
	FP(fp28, 28), FP(fp29, 29), FP(fp30, 30), FP(fp31, 31),
	{
		.name = "fcr31", .off = 32 * sizeof(uint64_t),
		.size = 4, .gdb_size = 4, .gdb = GDB_FCR31,
	},
	{
		.name = "fcr0", .off = (32 * sizeof(uint64_t)) + 4,
		.size = 4, .gdb_size = 4, .gdb = GDB_FCR0,
	},

	{0},
};

/* Extended */
struct reg_location_list fxrll[] = {
	{0},
};

static uint8_t mips_break[4] = {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	0x0d, 0x00, 0x00, 0x00
#else
	0x00, 0x00, 0x00, 0x0d
#endif
};

int ptrace_arch_swbreak_insn(void *bdata)
{
	int ret = RET_ERR;
	/* Use bkpt */
	memcpy(bdata, &mips_break[0], 4);
	ret = RET_OK;

	return ret;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc)
{
	_read_greg();
	memcpy(pc, _target.reg + 34 * sizeof(unsigned long int),
	       sizeof(unsigned long));
}

void ptrace_arch_set_pc(pid_t tid, unsigned long pc)
{
	_read_greg(tid);
	memcpy(_target.reg + 34 * sizeof(unsigned long int), &pc,
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

bool ptrace_arch_check_unrecognized_register(int reg,
					     size_t *pad_size)
{
	bool ret = false;
	if ((GDB_UNUSED_72 == reg) ||
	    (GDB_UNUSED_73 == reg) ||
	    (GDB_UNUSED_74 == reg) ||
	    (GDB_UNUSED_75 == reg) ||
	    (GDB_UNUSED_76 == reg) ||
	    (GDB_UNUSED_77 == reg) ||
	    (GDB_UNUSED_78 == reg) ||
	    (GDB_UNUSED_79 == reg) ||
	    (GDB_UNUSED_80 == reg) ||
	    (GDB_UNUSED_81 == reg) ||
	    (GDB_UNUSED_82 == reg) ||
	    (GDB_UNUSED_83 == reg) ||
	    (GDB_UNUSED_84 == reg) ||
	    (GDB_UNUSED_85 == reg) ||
	    (GDB_UNUSED_86 == reg) ||
	    (GDB_UNUSED_87 == reg) ||
	    (GDB_UNUSED_88 == reg) ||
	    (GDB_UNUSED_89 == reg)) {
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

bool ptrace_arch_support_watchpoint(int type)
{
	bool ret = false;
	return ret;
}

bool ptrace_arch_add_watchpoint(pid_t pid, int type, unsigned long addr,
				size_t len)
{
	bool ret = false;
	return ret;
}

bool ptrace_arch_remove_watchpoint(pid_t pid, int type, unsigned long addr,
				   size_t len)
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
