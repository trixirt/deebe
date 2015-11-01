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
#include "os.h"
#include "gdb-arm.h"

int ptrace_arch_gdb_greg_max()
{
	return GDB_GREG_MAX;
}

/* General */
struct reg_location_list grll[] = {
	GRLL(gp0,  r[0],   GDB_GPR0,  0, 0, 0),
	GRLL(gp1,  r[1],   GDB_GPR1,  0, 0, 0),
	GRLL(gp2,  r[2],   GDB_GPR2,  0, 0, 0),
	GRLL(gp3,  r[3],   GDB_GPR3,  0, 0, 0),
	GRLL(gp4,  r[4],   GDB_GPR4,  0, 0, 0),
	GRLL(gp5,  r[5],   GDB_GPR5,  0, 0, 0),
	GRLL(gp6,  r[6],   GDB_GPR6,  0, 0, 0),
	GRLL(gp7,  r[7],   GDB_GPR7,  0, 0, 0),
	GRLL(gp8,  r[8],   GDB_GPR8,  0, 0, 0),
	GRLL(gp9,  r[9],   GDB_GPR9,  0, 0, 0),
	GRLL(gp10, r[10],  GDB_GPR10, 0, 0, 0),
	GRLL(gp11, r[11],  GDB_GPR11, 0, 0, 0),
	GRLL(gp12, r[12],  GDB_GPR12, 0, 0, 0),
	GRLL(sp,   r_sp,   GDB_SP,    0, 0, 0),
	GRLL(lr,   r_lr,   GDB_LR,    0, 0, 0),
	GRLL(pc,   r_pc,   GDB_PC,    0, 0, 0),
	GRLL(cpsr, r_cpsr, GDB_CPSR,  0, 0, 0),
	{0},
};

/* Defined in freebsd-arm.c or netbsd-arm.c */
extern struct reg_location_list frll[];

/* Extended */
struct reg_location_list fxrll[] = {
	{0},
};

static uint32_t bkpt[1] = {
    0xe6000011
};


size_t ptrace_arch_swbreak_size()
{
	return 4;
}

int ptrace_arch_swbreak_insn(void *bdata)
{
	int ret = RET_NOSUPP;
	/* Use bkpt */
	memcpy(bdata, &bkpt[0], 4);
	ret = RET_OK;
	return ret;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc)
{
	_read_greg(tid);
	memcpy(pc, _target.reg + 15 * sizeof(unsigned int),
	       sizeof(unsigned int));
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc)
{
	_read_greg(tid);
	memcpy(_target.reg + 15 * sizeof(unsigned int), &pc,
	       sizeof(unsigned int));
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

bool ptrace_arch_add_watchpoint(pid_t pid, int type, unsigned long addr,
				size_t len)
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

void ptrace_arch_read_dbreg(pid_t tid)
{
  /* noop */
}

void ptrace_arch_write_dbreg(pid_t tid)
{
  /* noop */
}
