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
#include "os.h"
#include "global.h"
#include "dptrace.h"
#include "gdb-x86_64.h"
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/i386/_structs.h>

#define DEEBE_REG_STRUCT __darwin_x86_thread_state64
#include "regmacros.h"
struct reg_location_list grll[] = {
    /* general */
    RLL(r15, __r15, GDB_R15, 0, 0, 0, uint, hex, 15, 15, X, X),
    RLL(r14, __r14, GDB_R14, 0, 0, 0, uint, hex, 14, 14, X, X),
    RLL(r13, __r13, GDB_R13, 0, 0, 0, uint, hex, 13, 13, X, X),
    RLL(r12, __r12, GDB_R12, 0, 0, 0, uint, hex, 12, 12, X, X),
    RLL(r11, __r11, GDB_R11, 0, 0, 0, uint, hex, 11, 11, X, X),
    RLL(r10, __r10, GDB_R10, 0, 0, 0, uint, hex, 10, 10, X, X),
    RLL(r9, __r9, GDB_R9, 0, 0, 0, uint, hex, 9, 9, arg6, arg6),
    RLL(r8, __r8, GDB_R8, 0, 0, 0, uint, hex, 8, 8, arg5, arg5),
    RLL(rsi, __rsi, GDB_RSI, 0, 0, 0, uint, hex, 4, 4, arg2, arg2),
    RLL(rdi, __rdi, GDB_RDI, 0, 0, 0, uint, hex, 5, 5, arg1, arg1),
    RLL(rbp, __rbp, GDB_RBP, 0, 0, 0, uint, hex, 6, 6, fp, fp),
    RLL(rbx, __rbx, GDB_RBX, 0, 0, 0, uint, hex, 3, 3, X, X),
    RLL(rdx, __rdx, GDB_RDX, 0, 0, 0, uint, hex, 1, 1, arg3, arg3),
    RLL(rcx, __rcx, GDB_RCX, 0, 0, 0, uint, hex, 2, 2, arg4, arg4),
    RLL(rax, __rax, GDB_RAX, 0, 0, 0, uint, hex, 0, 0, X, X),
    RLL(fs, __fs, GDB_FS, 0, 0, 4, uint, hex, 54, 54, X, X),
    RLL(gs, __gs, GDB_GS, 0, 0, 4, uint, hex, 55, 55, X, X),
    RLL(rip, __rip, GDB_RIP, 0, 0, 0, uint, hex, 16, 16, pc, pc),
    RLL(cs, __cs, GDB_CS, 0, 0, 4, uint, hex, 51, 51, X, X),
    RLL(rflags, __rflags, GDB_RFLAGS, 0, 0, 4, uint, hex, 49, 49, flags,
        flags),
    RLL(rsp, __rsp, GDB_RSP, 0, 0, 4, uint, hex, 7, 7, sp, sp),
    {0},
};

struct reg_location_list frll[] = {
    {0},
};

struct reg_location_list fxrll[] = {
    {0},
};

#define GDB_GREG_MAX 0

int ptrace_arch_gdb_greg_max() { return GDB_GREG_MAX; }

int ptrace_arch_swbreak_insn(void *bdata) {
  int ret = RET_ERR;
  return ret;
}

int ptrace_arch_add_break(int type, unsigned long addr, size_t len,
                          void **bdata) {
  /* TBD */
  int ret = RET_ERR;
  return ret;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc) { /* TBD */ }
void ptrace_arch_set_pc(pid_t tid, unsigned long pc) { /* TBD */ }

void ptrace_arch_set_singlestep(pid_t pid, long *request) { /* TBD */ }

void ptrace_arch_clear_singlestep(pid_t pid) { /* TBD */ }

void ptrace_arch_read_greg(pid_t tid) { /* TBD */ }

void ptrace_arch_write_greg(pid_t tid) { /* TBD */ }

bool ptrace_arch_check_unrecognized_register(int reg, size_t *pad_size) {
  bool ret = false;
  return ret;
}

int ptrace_arch_signal_to_gdb(int sig) { return 0; }

int ptrace_arch_signal_from_gdb(int gdb) { return 0; }

bool ptrace_arch_support_watchpoint(pid_t tid, int type) {
  bool ret = false;
  return ret;
}

bool ptrace_arch_add_watchpoint(pid_t pid, int type, unsigned long addr,
                                size_t len) {
  bool ret = false;
  return ret;
}

bool ptrace_arch_remove_watchpoint(pid_t pid, int type, unsigned long addr,
                                   size_t len) {
  bool ret = false;
  return ret;
}

bool ptrace_arch_hit_watchpoint(pid_t pid, unsigned long *addr) {
  bool ret = false;
  return ret;
}

void ptrace_arch_read_fxreg(pid_t tid) { /* stub */ }

void ptrace_arch_write_fxreg(pid_t tid) { /* stub */ }

void ptrace_arch_option_set_syscall(pid_t pid) { /* stub */ }

bool ptrace_arch_check_syscall(pid_t pid, int *in_out_sig) { return false; }

void ptrace_arch_get_syscall(pid_t tid, void *id, void *arg1, void *arg2,
                             void *arg3, void *arg4, void *ret) {}

bool ptrace_arch_support_hardware_breakpoints(pid_t tid) { return false; }
bool ptrace_arch_add_hardware_breakpoint(pid_t tid, unsigned long addr,
                                         size_t len) {
  return false;
}
bool ptrace_arch_remove_hardware_breakpoint(pid_t tid, unsigned long addr,
                                            size_t len) {
  return false;
}

bool ptrace_arch_hit_hardware_breakpoint(pid_t tid, unsigned long pc) {
  return false;
}

const char *ptrace_arch_get_xml_register_string() {
  static char *str = "i386";
  return str;
}

void ptrace_arch_option_set_thread(pid_t pid) {
  ptrace_os_option_set_thread(pid);
}
size_t ptrace_arch_swbreak_size() { return 1; }

bool ptrace_arch_read_auxv(char *out_buff, size_t out_buf_size, size_t offset,
                           size_t *size) {
	return false;
}

size_t ptrace_arch_swbrk_rollback() { return ptrace_arch_swbreak_size(); }

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
