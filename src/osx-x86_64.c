/*
 * Copyright (c) 2012-2013, Juniper Networks, Inc.
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
#include "global.h"
#include "dptrace.h"
#include <mach/x86_64/thread_act.h>

struct reg_location_list grll[] = {
	{0},
};

struct reg_location_list frll[] = {
	{0},
};

struct reg_location_list fxrll[] = {
	{0},
};

#define GDB_GREG_MAX 0

int ptrace_arch_gdb_greg_max()
{
	return GDB_GREG_MAX;
}

int ptrace_arch_swbreak_insn(void *bdata)
{
	int ret = RET_ERR;
	return ret;
}

int ptrace_arch_add_break(int type, unsigned long addr,
			  size_t len, void **bdata)
{
	/* TBD */
	int ret = RET_ERR;
	return ret;
}

void ptrace_arch_get_pc(unsigned long *pc)
{
	/* TBD */
}
void ptrace_arch_set_pc(unsigned long pc)
{
	/* TBD */
}

void ptrace_arch_set_singlestep(pid_t pid, long *request)
{
	/* TBD */
}

void ptrace_arch_clear_singlestep(pid_t pid)
{
	/* TBD */
}

void ptrace_arch_read_greg()
{
	/* TBD */
}

void ptrace_arch_write_greg()
{
	/* TBD */
}

bool ptrace_arch_check_unrecognized_register(int reg, size_t *pad_size)
{
	bool ret = false;
	return ret;
}

int ptrace_arch_signal_to_gdb(int sig)
{
	return 0;
}

int ptrace_arch_signal_from_gdb(int gdb)
{
	return 0;
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

void ptrace_arch_read_fxreg()
{
	/* stub */
}

void ptrace_arch_write_fxreg()
{
	/* stub */
}

void ptrace_arch_option_set_syscall(pid_t pid)
{
	/* stub */
}

bool ptrace_arch_check_syscall(pid_t pid, int *in_out_sig)
{
	return false;
}

void ptrace_arch_get_syscall(void *id, void *arg1,
			     void *arg2, void *arg3, void *arg4, void *ret)
{
}

bool osx_arch_read_registers(thread_act_t tid)
{
	bool ret = false;
	if (0 == _target.reg_size) {
		_target.reg = malloc(sizeof(x86_thread_state64_t));
		if (_target.reg)
			_target.reg_size = sizeof(x86_thread_state64_t);
	}

	if (0 == _target.reg_size) {
		fprintf(stderr, "Error allocating register buffer\n");
	} else {
		kern_return_t kret;
		mach_msg_type_number_t cnt = x86_THREAD_STATE64_COUNT;
		kret = thread_get_state(tid, x86_THREAD_STATE64,
					_target.reg, &cnt);
		if (KERN_SUCCESS == kret) {
			if (cnt != x86_THREAD_STATE64_COUNT) {
				/* Failure ? */
				fprintf(stderr, "Warning : expecting reg size %zu but got %d\n", _target.reg_size, cnt);
			} else {
				/* Success */
				ret = true;
			}
		} else {
			fprintf(stderr, "problem getting registers reason : ");
			osx_report_kernel_error(stderr, kret);
			fprintf(stderr, "\n");
		}
	}
	return ret;
}
