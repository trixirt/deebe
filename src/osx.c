/*
 * Copyright (c) 2013-2016 Juniper Networks, Inc.
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
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include "os.h"
#include "gdb_interface.h"
#include "target.h"
#include "util.h"
#include "macros.h"

void osx_report_kernel_error(FILE *fp, kern_return_t kret) {
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
                       size_t buf_size, size_t *read_size) {
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
                             uint8_t *avail, size_t buf_size,
                             size_t *read_size) {
	int ret = RET_ERR;
	int c = 0;
	if (target_is_gdb_reg(gdb, &c, &grll[0])) {
		if (osx_arch_read_registers(tid)) {
			if (grll[c].off < _target.reg_size) {
				size_t s = 0;
				/* Success */
				memcpy(data + s, _target.reg + grll[c].off, grll[c].size);
				memset(avail + s, 0xff, grll[c].size);
				*read_size = s + grll[c].size;
				ret = RET_OK;
			}
		}
	}
	return ret;
}
int osx_write_registers(pid_t tid, uint8_t *data, size_t size) {
  return RET_NOSUPP;
}
int osx_write_single_register(pid_t tid, unsigned int gdb, uint8_t *data,
                              size_t size) {
  return RET_NOSUPP;
}

/* Define stubs for now */
void ptrace_arch_read_dbreg() {}

void ptrace_arch_write_dbreg() {}

int ptrace_os_gen_thread(pid_t pid, pid_t tid) {
  int ret = RET_ERR;
  return ret;
}

void ptrace_os_continue_others() {}

void ptrace_os_stopped_single(char *str, bool debug) {}

bool ptrace_os_new_thread(pid_t tid, int status) {
  bool ret = false;
  return ret;
}

void ptrace_os_wait(pid_t tid) {}

bool ptrace_os_check_syscall(pid_t pid, int *in_out_sig) {
  bool ret = false;
  return ret;
}

void ptrace_os_option_set_thread(pid_t pid) {
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

/*
 *
 * For lldb, output is
 * start:<mem start>;size:<siz>;permissions:rx;
 *
 */
bool memory_os_region_info_gdb(uint64_t addr, char *out_buff,
			       size_t out_buff_size) {
  bool ret = false;

  task_t task;
  kern_return_t status;
  status = task_for_pid(mach_task_self (), CURRENT_PROCESS_PID, &task);
  if (KERN_SUCCESS == status) {
	  mach_vm_address_t address = (mach_vm_address_t)addr;
	  mach_vm_size_t size;
	  vm_region_flavor_t flavor = VM_REGION_BASIC_INFO_64;
	  vm_region_basic_info_data_64_t info = {0};
	  mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
	  mach_port_t object_name;
	  status = mach_vm_region(task, &address, &size, flavor, (vm_region_info_t)&info, &info_count, &object_name);
	  if (KERN_SUCCESS == status) {
		  uint8_t p = 0;
		  char perm_strs[8][4] = {"", "r", "w", "rw", "x", "rx", "wx", "rwx"};
		  if (info.protection & VM_PROT_READ)
			  p |= 1;
		  if (info.protection & VM_PROT_WRITE)
			  p |= 2;
		  if (info.protection & VM_PROT_EXECUTE)
			  p |= 4;
		  if (p > 0 && p < 8) {
			  sprintf(out_buff,
				   "start:%" PRIx64 ";size:%" PRIx64 ";permissions:%s;", address,
				   size, &perm_strs[p][0]);
			  ret = true;
		  }
	  }
  }
  return ret;
}

long ptrace_os_continue(pid_t pid, pid_t tid, int step, int sig) {
  long ret = -1;
  return ret;
}

bool memory_os_read(pid_t tid, void *addr, void *dst) {
	bool ret = false;

  task_t task;
  kern_return_t status;

  status = task_for_pid(mach_task_self (), CURRENT_PROCESS_PID, &task);
  if (KERN_SUCCESS == status) {
    mach_vm_address_t address = (mach_vm_address_t)addr;
    mach_vm_size_t num_read = 0;
    status = mach_vm_read_overwrite(task, address, 1, (mach_vm_address_t)dst, &num_read);
    if ((KERN_SUCCESS == status) && (1 == num_read)) {
	    ret = true;
      } else {
	    DBG_PRINT("ERROR : %s read failed status %d num_read %d\n", __func__, status, num_read);
      }
  } else {
    DBG_PRINT("ERROR : %s getting task failed status %d\n", __func__, status);
  }
  return ret;
}
int osx_write_mem(pid_t tid, uint64_t addr, uint8_t *data,
		  size_t size) {
	int ret = RET_ERR;
	return ret;
}

void memory_os_request_size(size_t *size)
{
    *size = 1;
}

bool memory_os_write(pid_t tid, void *addr, void *val) {
    bool ret = false;
    return ret;
}
