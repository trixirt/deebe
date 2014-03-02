/*
 * Copyright (c) 2013 Juniper Networks, Inc.
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
#include "os.h"
#include "global.h"

void ptrace_arch_set_singlestep(/*@unused@*/pid_t pid, long *request)
{
	/* Let the kernel handle the heavy lifting */
	*request = PTRACE_SINGLESTEP;
}

void ptrace_arch_clear_singlestep(pid_t pid)
{
	/* a noop */
}

int ptrace_arch_signal_to_gdb(int sig)
{
	return host_signal_to_gdb(sig);
}

int ptrace_arch_signal_from_gdb(int gdb)
{
	return host_signal_from_gdb(gdb);
}

bool x86_read_debug_reg(pid_t pid, size_t reg, void *val)
{
	bool ret = false;
	if (reg < 8) {
		_read_dbreg();
		size_t addr = reg * sizeof(unsigned int);
		if (addr + sizeof(unsigned int) <= _target.dbreg_size) {
			memcpy(val, _target.regs.dbreg + addr, sizeof(unsigned int));
			ret = true;
		}
	}
	return ret;
}

bool x86_write_debug_reg(pid_t pid, size_t reg, void *val)
{
	bool ret = false;
	if (reg < 8) {
		_read_dbreg();
		unsigned long addr = reg * sizeof(unsigned int);
		if (addr + sizeof(unsigned int) <= _target.dbreg_size) {
			memcpy(_target.regs.dbreg + addr, val, sizeof(unsigned int));
			_write_dbreg();
			ret = true;
		}
	}
	return ret;
}

void ptrace_arch_read_dbreg()
{
	if (0 == _target.dbreg_size) {
		_target.regs.dbreg = malloc(8 * sizeof(long));
		if (NULL != _target.regs.dbreg)
			_target.dbreg_size = 8 * sizeof(long);
	}

	if (0 != _target.dbreg_size) {
		size_t r;
		long *val = (long *)_target.regs.dbreg;
		for (r = 0; r < 8; r++) {
			long v;
			unsigned long addr = offsetof(struct user, u_debugreg[r]);
			errno = 0;
			v = ptrace(PTRACE_PEEKUSER, tstate.cpid, addr, 0);
			if (0 == errno) {
				memcpy(&val[r], &v, sizeof(long));
			} else {
				break;
			}
		}
	}
}

void ptrace_arch_write_dbreg()
{
	if (0 != _target.dbreg_size) {
		size_t r;
		long *val = (long *)_target.regs.dbreg;
		for (r = 0; r < 8; r++) {
			unsigned long addr = offsetof(struct user, u_debugreg[r]);
			if (0 != ptrace(PTRACE_POKEUSER, tstate.cpid, addr, val[r])) {
				break;
			}
		}
	}
}
