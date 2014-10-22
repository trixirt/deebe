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
#include <unistd.h>
#include <mach/mach_traps.h>
#include <mach/mach_init.h>
#include <mach/task.h>
#include "../os/osx.h"
#include "gdb_interface.h"
#include "target.h"

void osx_report_kernel_error(FILE *fp, kern_return_t kret)
{
	switch (kret) {
	case KERN_SUCCESS: /* 0 */
		fprintf(fp, "success!, what are you doing here?");
		break;
	case KERN_INVALID_ARGUMENT: /* 4 */
		fprintf(fp, "invalid argument");
		break;
	case KERN_FAILURE: /* 5 */
		fprintf(fp, "generic kernel failure");
		break;
	default:
		fprintf(fp, "code %d\n", kret);
		break;
	}
}

int osx_read_registers(pid_t tid, uint8_t *data, uint8_t *avail,
		       size_t buf_size, size_t *read_size)
{
  int ret = RET_ERR;
  if (osx_arch_read_registers(tid)) {
    size_t transfer_size = _target.reg_size;
    if (transfer_size > buf_size) {
      transfer_size = buf_size;
      DBG_PRINT("Warning expecting transfer buffer to be at least %zu but got %zu\n",
	      _target.reg_size, buf_size);
    }
    memcpy(data, _target.reg, transfer_size);
    memset(avail, 0xff, transfer_size);
    *read_size = transfer_size;
    ret = RET_OK;
  } else {
    /* Failure */
    DBG_PRINT("Error in arch functions\n");
  }
  return ret;
}

int osx_read_single_register(pid_t tid, unsigned int gdb, uint8_t *data,
			     uint8_t *avail, size_t buf_size, size_t *read_size)
{
	return RET_NOSUPP;
}
int osx_write_registers(pid_t tid, uint8_t *data, size_t size)
{
	return RET_NOSUPP;
}
int osx_write_single_register(pid_t tid, unsigned int gdb, uint8_t *data, size_t size)
{
	return RET_NOSUPP;
}

/* Define stubs for now */
void ptrace_arch_read_dbreg()
{
}

void ptrace_arch_write_dbreg()
{
}

bool ptrace_os_new_thread(pid_t tid, int status) {
    bool ret = false;
    return ret;
}

bool ptrace_os_check_new_thread(pid_t pid, int status, pid_t *out_pid)
{
	bool ret = false;
	return ret;
}

void ptrace_os_continue_others() {
}

long ptrace_os_continue(pid_t pid, pid_t tid, int step, int sig) {
	long ret = 0;
	return ret;
}

void ptrace_os_wait(pid_t t) {
}

int os_gen_thread(pid_t pid, pid_t tid) {
    int ret = RET_OK;
    return ret;
}

void ptrace_os_stopped_single(char *str, size_t len, bool debug) {
}
