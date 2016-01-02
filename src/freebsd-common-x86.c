/*
 * Copyright (c) 2013-2014 Juniper Networks, Inc.
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
#include <machine/reg.h>
#include "os.h"
#include "global.h"

void ptrace_arch_set_singlestep(pid_t pid, long *request) {
  ptrace_os_set_singlestep(pid, request);
}

void ptrace_arch_clear_singlestep(pid_t pid) {
  ptrace_os_clear_singlestep(pid);
}

bool ptrace_arch_check_unrecognized_register(/*@unused@*/ int reg,
                                             /*@unused@*/ size_t *pad_size) {
  bool ret = false;
  return ret;
}

int ptrace_arch_signal_to_gdb(int sig) { return host_signal_to_gdb(sig); }

int ptrace_arch_signal_from_gdb(int gdb) { return host_signal_from_gdb(gdb); }

bool x86_read_debug_reg(pid_t tid, size_t reg, void *val) {
  bool ret = false;

#ifdef PT_GETDBREGS
  if (reg < 8) {
    _read_dbreg(tid);
    size_t addr = reg * sizeof(unsigned long);
    if (addr + sizeof(unsigned int) <= _target.dbreg_size) {
      memcpy(val, _target.dbreg + addr, sizeof(unsigned long));
      ret = true;
    }
  }
#endif
  return ret;
}

bool x86_write_debug_reg(pid_t tid, size_t reg, void *val) {
  bool ret = false;
#ifdef PT_GETDBREGS
  if (reg < 8) {
    _read_dbreg(tid);
    unsigned long addr = reg * sizeof(unsigned long);
    if (addr + sizeof(unsigned int) <= _target.dbreg_size) {
      memcpy(_target.dbreg + addr, val, sizeof(unsigned long));
      _write_dbreg(tid);
      ret = true;
    }
  }
#endif
  return ret;
}
