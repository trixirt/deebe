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

#define FP_STRUCT user_fpregs
#include "os.h"

#define GDB_GREG_MAX 16

int ptrace_arch_gdb_greg_max()
{
	return GDB_GREG_MAX;
}

#define GDB_GPR0  0
#define GDB_GPR1  1
#define GDB_GPR2  2
#define GDB_GPR3  3
#define GDB_GPR4  4
#define GDB_GPR5  5
#define GDB_GPR6  6
#define GDB_GPR7  7
#define GDB_GPR8  8
#define GDB_GPR9  9
#define GDB_GPR10 10
#define GDB_GPR11 11
#define GDB_GPR12 12
#define GDB_SP    13
#define GDB_LR    14
#define GDB_PC    15
#define GDB_CPSR  25

/* General */
struct reg_location_list grll[] = {
	GRLL(gp0,  regs.uregs[0],  GDB_GPR0,  0, 0, 0),
	GRLL(gp1,  regs.uregs[1],  GDB_GPR1,  0, 0, 0),
	GRLL(gp2,  regs.uregs[2],  GDB_GPR2,  0, 0, 0),
	GRLL(gp3,  regs.uregs[3],  GDB_GPR3,  0, 0, 0),
	GRLL(gp4,  regs.uregs[4],  GDB_GPR4,  0, 0, 0),
	GRLL(gp5,  regs.uregs[5],  GDB_GPR5,  0, 0, 0),
	GRLL(gp6,  regs.uregs[6],  GDB_GPR6,  0, 0, 0),
	GRLL(gp7,  regs.uregs[7],  GDB_GPR7,  0, 0, 0),
	GRLL(gp8,  regs.uregs[8],  GDB_GPR8,  0, 0, 0),
	GRLL(gp9,  regs.uregs[9],  GDB_GPR9,  0, 0, 0),
	GRLL(gp10, regs.uregs[10], GDB_GPR10, 0, 0, 0),
	GRLL(gp11, regs.uregs[11], GDB_GPR11, 0, 0, 0),
	GRLL(gp12, regs.uregs[12], GDB_GPR12, 0, 0, 0),
	GRLL(sp,   regs.uregs[13], GDB_SP,    0, 0, 0),
	GRLL(lr,   regs.uregs[14], GDB_LR,    0, 0, 0),
	GRLL(pc,   regs.uregs[15], GDB_PC,    0, 0, 0),
	GRLL(cpsr, regs.uregs[16], GDB_CPSR,  0, 0, 0),
	{0},
};

#define GDB_FPR0  16
#define GDB_FPR1  17
#define GDB_FPR2  18
#define GDB_FPR3  19
#define GDB_FPR4  20
#define GDB_FPR5  21
#define GDB_FPR6  22
#define GDB_FPR7  23
#define GDB_FPS   24

/* Floating point */
struct reg_location_list frll[] = {
	FRLL(fp0, fpregs[0], GDB_FPR0, 0, 0, 0),
	FRLL(fp1, fpregs[1], GDB_FPR1, 0, 0, 0),
	FRLL(fp2, fpregs[2], GDB_FPR2, 0, 0, 0),
	FRLL(fp3, fpregs[3], GDB_FPR3, 0, 0, 0),
	FRLL(fp4, fpregs[4], GDB_FPR4, 0, 0, 0),
	FRLL(fp5, fpregs[5], GDB_FPR5, 0, 0, 0),
	FRLL(fp6, fpregs[6], GDB_FPR6, 0, 0, 0),
	FRLL(fp7, fpregs[7], GDB_FPR7, 0, 0, 0),
	{ .name = "fps", .off = 3 * sizeof(unsigned int) * 8,
	  .size = 4, .gdb_size = 4, .gdb = GDB_FPS, },
	{0},
};

/* Extended */
struct reg_location_list fxrll[] = {
	{0},
};

#ifdef ARM_SWBRK
static uint32_t bkpt[1] = {
	/*
	 * bkpt
	 * Does not always work, depends on arm verion 5 or better
	 * 0x700020e1
	 *
	 * Instead use something from the
	 * undefined instruction space
	 * See A3-28 of ARM RM
	 */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	0xf000f0e7
#else
	0xe7f000f0
#endif
};
#endif

#if 0

static long _arm_version = -1;
void arm_version()
{
	char b[1024];
	char *var, *val;
	memset(b, 0, 1024);

	FILE *fp = fopen("/proc/cpuinfo", "rt");
	if (NULL != fp) {
		while (!feof(fp)) {
			char *s = fgets(&b[0], 1024, fp);
			if (s != NULL) {
				int i;
				var = s;
				val = NULL;
				for (i = 0; i < strlen(s) - 1; i++) {
					if (s[i] == ':') {
						s[i] = '\0';
						val = &s[i+1];
						break;
					}
				}
				if (val) {
					char *str = "CPU architecture";
					if (!strncmp(str, var, strlen(str))) {
						unsigned long ver;
						char *endptr;
						ver = strtoul(val, &endptr, 10);
						if (ver > 0)
							_arm_version = ver;
						break;
					}
				}
				memset(b, 0, 1024);
			} else {
				break;
			}
		}
		fclose(fp);
	}
	/* If there was a problem, go with an ok default */
	if (_arm_version == 0)
		_arm_version = 6;
}
#endif

size_t ptrace_arch_swbreak_size()
{
#ifdef ARM_SWBRK
	return 4;
#else
	return 0;
#endif
}

int ptrace_arch_swbreak_insn(void *bdata)
{
	int ret = RET_NOSUPP;
#ifdef ARM_SWBRK
	/* Use bkpt */
	memcpy(bdata, &bkpt[0], 4);
	ret = RET_OK;
#endif
	return ret;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc)
{
	_read_greg(tid);
	memcpy(pc, _target.reg + 15 * sizeof(unsigned long int),
	       sizeof(unsigned long));
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc)
{
	_read_greg(tid);
	memcpy(_target.reg + 15 * sizeof(unsigned long int), &pc,
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

bool ptrace_arch_support_hardware_breakpoints()
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
