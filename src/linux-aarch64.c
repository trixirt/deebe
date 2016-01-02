/*
 * Copyright (c) 2015, Juniper Networks, Inc.
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
#include "gdb-aarch64.h"

int ptrace_arch_gdb_greg_max() { return GDB_GREG_MAX; }

#ifdef GRLL
#undef GRLL
#endif
#define GRLL(N, E, GDB, O, S, GDB_S)                                           \
  {                                                                            \
    .off = (O)+offsetof(struct user_regs_struct, E),                           \
    .size = (S) ? (S) : msizeof(struct user_regs_struct, E), .gdb = (GDB),     \
    .name = #N,                                                                \
    .gdb_size = (GDB_S) ? (GDB_S) : msizeof(struct user_regs_struct, E),       \
  }
/* General */
struct reg_location_list grll[] = {
    GRLL(gp0, regs[0], GDB_GPR0, 0, 0, 0),
    GRLL(gp1, regs[1], GDB_GPR1, 0, 0, 0),
    GRLL(gp2, regs[2], GDB_GPR2, 0, 0, 0),
    GRLL(gp3, regs[3], GDB_GPR3, 0, 0, 0),
    GRLL(gp4, regs[4], GDB_GPR4, 0, 0, 0),
    GRLL(gp5, regs[5], GDB_GPR5, 0, 0, 0),
    GRLL(gp6, regs[6], GDB_GPR6, 0, 0, 0),
    GRLL(gp7, regs[7], GDB_GPR7, 0, 0, 0),
    GRLL(gp8, regs[8], GDB_GPR8, 0, 0, 0),
    GRLL(gp9, regs[9], GDB_GPR9, 0, 0, 0),
    GRLL(gp10, regs[10], GDB_GPR10, 0, 0, 0),
    GRLL(gp11, regs[11], GDB_GPR11, 0, 0, 0),
    GRLL(gp12, regs[12], GDB_GPR12, 0, 0, 0),
    GRLL(gp13, regs[13], GDB_GPR13, 0, 0, 0),
    GRLL(gp14, regs[14], GDB_GPR14, 0, 0, 0),
    GRLL(gp15, regs[15], GDB_GPR15, 0, 0, 0),
    GRLL(gp16, regs[16], GDB_GPR16, 0, 0, 0),
    GRLL(gp17, regs[17], GDB_GPR17, 0, 0, 0),
    GRLL(gp18, regs[18], GDB_GPR18, 0, 0, 0),
    GRLL(gp19, regs[19], GDB_GPR19, 0, 0, 0),
    GRLL(gp20, regs[20], GDB_GPR20, 0, 0, 0),
    GRLL(gp21, regs[21], GDB_GPR21, 0, 0, 0),
    GRLL(gp22, regs[22], GDB_GPR22, 0, 0, 0),
    GRLL(gp23, regs[23], GDB_GPR23, 0, 0, 0),
    GRLL(gp24, regs[24], GDB_GPR24, 0, 0, 0),
    GRLL(gp25, regs[25], GDB_GPR25, 0, 0, 0),
    GRLL(gp26, regs[26], GDB_GPR26, 0, 0, 0),
    GRLL(gp27, regs[27], GDB_GPR27, 0, 0, 0),
    GRLL(gp28, regs[28], GDB_GPR28, 0, 0, 0),
    GRLL(gp29, regs[29], GDB_GPR29, 0, 0, 0),
    GRLL(gp30, regs[30], GDB_GPR30, 0, 0, 0),
    GRLL(sp, sp, GDB_SP, 0, 0, 0),
    GRLL(pc, pc, GDB_PC, 0, 0, 0),
    GRLL(pstate, pstate, GDB_PSTATE, 0, 0, 0),
    {0},
};

/* Floating point */
struct reg_location_list frll[] = {
    {0},
};

/* Extended */
struct reg_location_list fxrll[] = {
    {0},
};

static uint32_t bkpt[1] = {0x00800011};

size_t ptrace_arch_swbreak_size() { return 4; }

int ptrace_arch_swbreak_insn(void *bdata) {
  int ret = RET_NOSUPP;
  /* Use bkpt */
  memcpy(bdata, &bkpt[0], 4);
  ret = RET_OK;
  return ret;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc) {
  _read_greg(tid);
  memcpy(pc, _target.reg + 15 * sizeof(unsigned long int),
         sizeof(unsigned long));
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc) {
  _read_greg(tid);
  memcpy(_target.reg + 15 * sizeof(unsigned long int), &pc,
         sizeof(unsigned long));
  _write_greg(tid);
}

void ptrace_arch_set_singlestep(/*@unused@*/ pid_t pid,
                                /*@unused@*/ long *request) {
  /* Let the kernel handle the heavy lifting */
  *request = PTRACE_SINGLESTEP;
}

void ptrace_arch_clear_singlestep(/*@unused@*/ pid_t pid) {}

bool ptrace_arch_check_unrecognized_register(/*@unused@*/ int reg,
                                             /*@unused@*/ size_t *pad_size) {
  bool ret = false;
  return ret;
}

int ptrace_arch_signal_to_gdb(int sig) { return host_signal_to_gdb(sig); }

int ptrace_arch_signal_from_gdb(int gdb) { return host_signal_from_gdb(gdb); }

bool ptrace_arch_support_watchpoint(pid_t tid, int type) {
  bool ret = false;
  return ret;
}

bool ptrace_arch_add_watchpoint(pid_t tid, int type, unsigned long addr,
                                size_t len) {
  bool ret = false;
  return ret;
}

bool ptrace_arch_remove_watchpoint(pid_t tid, int type, unsigned long addr,
                                   size_t len) {
  bool ret = false;
  return ret;
}

bool ptrace_arch_hit_watchpoint(pid_t tid, unsigned long *addr) {
  bool ret = false;
  return ret;
}

void ptrace_arch_read_fxreg(pid_t tid) { ptrace_os_read_fxreg(tid); }

void ptrace_arch_write_fxreg(pid_t tid) { ptrace_os_write_fxreg(tid); }

void ptrace_arch_option_set_syscall(pid_t pid) {
  ptrace_os_option_set_syscall(pid);
}

bool ptrace_arch_check_syscall(pid_t pid, int *in_out_sig) {
  return ptrace_os_check_syscall(pid, in_out_sig);
}

void ptrace_arch_get_syscall(pid_t tid, void *id, void *arg1, void *arg2,
                             void *arg3, void *arg4, void *ret) {
  _read_greg(tid);
}

void ptrace_arch_option_set_thread(pid_t pid) {
  ptrace_os_option_set_thread(pid);
}

bool ptrace_arch_wait_new_thread(pid_t *out_pid, int *out_status) {
  return ptrace_os_wait_new_thread(out_pid, out_status);
}

bool ptrace_arch_check_new_thread(pid_t pid, int status, pid_t *out_pid) {
  return ptrace_os_check_new_thread(pid, status, out_pid);
}

void ptrace_arch_read_dbreg(pid_t tid) { /* noop */ }

void ptrace_arch_write_dbreg(pid_t tid) { /* noop */ }

bool ptrace_arch_support_hardware_breakpoints(pid_t tid) {
  bool ret = false;
  return ret;
}
bool ptrace_arch_add_hardware_breakpoint(pid_t tid, unsigned long addr,
                                         size_t len) {
  bool ret = false;
  return ret;
}
bool ptrace_arch_remove_hardware_breakpoint(pid_t tid, unsigned long addr,
                                            size_t len) {
  bool ret = false;
  return ret;
}

bool ptrace_arch_hit_hardware_breakpoint(pid_t tid, unsigned long pc) {
  bool ret = false;
  return ret;
}
