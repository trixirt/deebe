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
#include "../os/osx.h"
#include "global.h"
#include "dptrace.h"
#include <mach/mach.h>
#include <mach/task_info.h>

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

size_t breakpoint_arch_swbreak_size() {
  return 1;
}
int breakpoint_arch_swbreak_insn(void *bdata)
{
	int ret = RET_ERR;
	/* Illegal instruction is 0xcc or 'int3' */
	memset(bdata, 0xcc, 1);
	ret = RET_OK;
	return ret;
}

int ptrace_arch_add_break(int type, unsigned long addr,
			  size_t len, void **bdata)
{
	/* TBD */
	int ret = RET_ERR;
	return ret;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc)
{
	/* TBD */
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc)
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

void ptrace_arch_read_greg(pid_t tid)
{
	/* TBD */
}

void ptrace_arch_write_greg(pid_t tid)
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

bool breakpoint_arch_support_watchpoint(int type)
{
	bool ret = false;
	return ret;
}

bool breakpoint_arch_add_watchpoint(pid_t pid, int type,
				unsigned long addr, size_t len)
{
	bool ret = false;
	return ret;
}

bool breakpoint_arch_remove_watchpoint(pid_t pid, int type,
				   unsigned long addr, size_t len)
{
	bool ret = false;
	return ret;
}

bool breakpoint_arch_hit_watchpoint(pid_t pid, unsigned long *addr)
{
	bool ret = false;
	return ret;
}

void ptrace_arch_read_fxreg(pid_t tid)
{
	/* stub */
}

void ptrace_arch_write_fxreg(pid_t tid)
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

void ptrace_arch_get_syscall(pid_t tid, void *id, void *arg1,
			     void *arg2, void *arg3, void *arg4, void *ret)
{
}

void ptrace_arch_option_set_thread(pid_t pid)
{
  kern_return_t status;
  if (PROCESS_TID(0) == PROCESS_PID(0)) {
    task_t task;
    status = task_for_pid(mach_task_self (), pid, &task);
    if (KERN_SUCCESS == status) {
      thread_array_t threads;
      mach_msg_type_number_t num_threads;
      status = task_threads(task, &threads, &num_threads);
      if (KERN_SUCCESS == status) {
	if (num_threads > 0) {
	  PROCESS_TID(0) = threads[0];
	} else {
	  DBG_PRINT("ERROR : %s : unexpected number of threads %d\n", __func__, num_threads);
	}
      } else {
	DBG_PRINT("ERROR : %s : failed to get thread info for pid %x : %d\n", __func__, pid, status);
      }
    } else {
      DBG_PRINT("ERROR : %s : failed to get osx task from pid %x : %d\n", __func__, pid, status);
    }
  } else {
    DBG_PRINT("ERROR : %s : called when pid != tid\n", __func__);
  }
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
			fprintf(stderr, "problem getting registers\n");
		}
	}
	return ret;
}

bool breakpoint_arch_support_hardware_breakpoints()
{
  return false;
}
bool breakpoint_arch_add_hardware_breakpoint(pid_t tid, unsigned long addr,
					 size_t len)
{
  return false;
}
bool breakpoint_arch_remove_hardware_breakpoint(pid_t tid, unsigned long addr,
					    size_t len)
{
  return false;
}

bool breakpoint_arch_hit_hardware_breakpoint(pid_t tid, unsigned long pc)
{
  return false;
}
