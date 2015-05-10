/*
 * Copyright (c) 2013-2014, Juniper Networks, Inc.
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
#ifndef DEEBE_PTRACE_H
#define DEEBE_PTRACE_H

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include "target.h"

typedef void (*out_f)(const char *string);

/* Internal functions */
bool _read_greg(pid_t tid);
void _write_greg(pid_t tid);
void _print_rll(struct reg_location_list *rl);
bool _read_dbreg(pid_t tid);
void _write_dbreg(pid_t tid);

/*
 * Defined in the ARCH
 */

/* functions */
int ptrace_arch_gdb_greg_max();
int ptrace_arch_swbreak_insn(void *bdata);
size_t ptrace_arch_swbreak_size();
void ptrace_arch_get_pc(pid_t tid, unsigned long *pc);
void ptrace_arch_set_pc(pid_t tid, unsigned long pc);
void ptrace_arch_set_singlestep(pid_t tid, long *request);
bool ptrace_arch_check_syscall(pid_t tid, int *in_out_sig);
void ptrace_arch_clear_singlestep(pid_t tid);
void ptrace_arch_read_greg(pid_t tid);
void ptrace_arch_write_greg(pid_t tid);
/* TBD : Move gdb signal handling out of ptrace */
int ptrace_arch_signal_to_gdb(int sig);
int ptrace_arch_signal_from_gdb(int gdb);
void _print_buffer(size_t current, size_t total, unsigned char *buffer);
bool ptrace_arch_check_unrecognized_register(int reg, size_t *pad_size);
bool ptrace_arch_support_hardware_breakpoints(pid_t tid);
bool ptrace_arch_add_hardware_breakpoint(pid_t tid, unsigned long addr,	size_t len);
bool ptrace_arch_remove_hardware_breakpoint(pid_t tid, unsigned long addr, size_t len);
bool ptrace_arch_hit_hardware_breakpoint(pid_t tid, unsigned long pc);
bool ptrace_arch_support_watchpoint(pid_t tid, int type);
bool ptrace_arch_add_watchpoint(pid_t tid, int type, unsigned long addr,
				size_t len);
bool ptrace_arch_remove_watchpoint(pid_t tid, int type, unsigned long addr,
				   size_t len);
bool ptrace_arch_hit_watchpoint(pid_t tid, unsigned long *watch_addr);
void ptrace_arch_read_fxreg(pid_t tid);
void ptrace_arch_write_fxreg(pid_t tid);
void ptrace_arch_read_dbreg(pid_t tid);
void ptrace_arch_write_dbreg(pid_t tid);
void ptrace_arch_option_set_syscall(pid_t pid);
void ptrace_arch_option_set_thread(pid_t pid);
void ptrace_arch_get_syscall(pid_t tid, void *id, void *arg1, void *arg2, void *arg3,
			     void *arg4, void *ret);
bool ptrace_arch_wait_new_thread(pid_t *out_pid, int *out_status);
bool ptrace_arch_check_new_thread(pid_t pid, int status, pid_t *out_pid);

/* Internal functions used by arch's */
bool _read_reg(pid_t tid, int GET, int SET, void **reg, uint8_t **reg_rw,
	       size_t *reg_size);
void _write_reg(pid_t tid, long SET, void *reg);

/* Public functions */

extern int ptrace_add_break(pid_t tid, int type, uint64_t addr, size_t len);
extern int ptrace_attach(pid_t tid);
extern void ptrace_close(void);
extern int ptrace_connect(char *status_string, size_t status_string_len,
			  int *can_restart);
extern int ptrace_detach();
extern int ptrace_crc_query(uint64_t addr, size_t len, uint32_t *val);
extern int ptrace_disconnect(void);
extern int ptrace_general_set(char *inbuf, char *outbuf, size_t size);
extern enum process_state ptrace_get_process_state(void);
extern int ptrace_go_waiting(int gdb_sig);
extern void ptrace_help(/*@unused@*/char *prog_name);
extern void ptrace_kill(pid_t pid, pid_t tid);
extern void ptrace_quick_kill(pid_t pid, pid_t tid);
extern int ptrace_no_ack();
extern int ptrace_offsets_query(uint64_t *text, uint64_t *data, uint64_t *bss);
extern int ptrace_open(/*@unused@*/int argc, /*@unused@*/char *argv[],
		       /*@unused@*/char *prog_name);
extern void ptrace_option_set_syscall();
extern int ptrace_get_signal(void);
extern int ptrace_raw_query(char *in_buf, char *out_buf, size_t out_buf_size);
extern int ptrace_read_mem(pid_t tid, uint64_t addr, uint8_t *data, size_t size,
			   size_t *read_size);
extern int ptrace_read_registers(pid_t tid, uint8_t *data, uint8_t *avail,
				 size_t buf_size, size_t *read_size);
extern int ptrace_read_single_register(pid_t tid, unsigned int gdb, uint8_t *data,
				       uint8_t *avail, size_t buf_size,
				       size_t *read_size);
extern int ptrace_restart(void);
extern int ptrace_resume_from_addr(pid_t pid, pid_t tid, int step, int gdb_sig, uint64_t addr);
extern int ptrace_resume_from_current(pid_t pid, pid_t tid, int step, int gdb_sig);
extern int ptrace_resume_with_syscall(pid_t tid);
extern int ptrace_remove_break(pid_t tid, int type, uint64_t addr, size_t len);
extern void ptrace_stop(pid_t pid, pid_t tid);
extern int ptrace_supported_features_query(char *out_buf, size_t out_buf_size);
extern int ptrace_threadinfo_query(int first, char *out_buf,
				   size_t out_buf_size);
extern int ptrace_wait(char *status_string, size_t status_string_len, int step, bool skip_continue_others);
extern void ptrace_quick_signal(pid_t pid, pid_t tid, int sig);
extern int ptrace_wait_partial(int first, char *status_string,
			       size_t status_string_len, int *implemented,
			       int *more);
extern int ptrace_write_mem(pid_t tid, uint64_t addr, uint8_t *data, size_t size);
extern int ptrace_write_registers(pid_t tid, uint8_t *data, size_t size);
extern int ptrace_write_single_register(pid_t tid, unsigned int gdb, uint8_t *data,
					size_t size);
extern void ptrace_get_syscall(pid_t tid, void *id, void *arg1, void *arg2, void *arg3,
			       void *arg4, void *ret);



#endif
