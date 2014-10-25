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
#include "global.h"
#include "dptrace.h"
#include "memory.h"
#include "../os/osx.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>

/* Table of commands */
static const RCMD_TABLE ptrace_remote_commands[] = {
	{0, 0, 0}     /* sentinel, end of table marker */
};

gdb_state _gdb_state = {
	.gen_thread = {
		.val = 0,
	},
	.ctrl_thread = {
		 .val = 0,
	 },
};

int osx_threadextrainfo_query(int64_t thread_id, char *out_buf, size_t out_buf_size)
{
	return RET_NOSUPP;
}

int osx_set_ctrl_thread(int64_t process_id, int64_t thread_id)
{
	return RET_NOSUPP;
}

int osx_is_thread_alive(int64_t process_id, int64_t thread_id,
			/*@unused@*/int *alive)
{
	return RET_NOSUPP;
}

int osx_process_query(unsigned int *mask, gdb_thread_ref *arg,
		      rp_thread_info *info)
{
	return RET_ERR;
}

int osx_list_query(int first, gdb_thread_ref *arg,
		   gdb_thread_ref *result, size_t max_num,
		   size_t *num, int *done)
{
	return RET_ERR;
}

int osx_current_thread_query(int64_t *pid, int64_t *tid)
{
  *pid = CURRENT_PROCESS_PID;
  *tid = CURRENT_PROCESS_TID;
  return RET_OK;
}

static int osx_query_current_signal(int *s)
{
	int ret = RET_ERR;
	if (s) {
		int sig;
		/* The raw signal */
		sig = ptrace_get_signal();
		/* The gdb translation */
		*s = ptrace_arch_signal_to_gdb(sig);
		ret = RET_OK;
	}
	return ret;
}

static size_t osx_memory_access_size()
{
  return 1;
}

static bool osx_memory_copy_read(pid_t pid, void *dst, void *src)
{
  bool ret = false;
  task_t task;
  kern_return_t status;
  status = task_for_pid(mach_task_self (), pid, &task);
  if (KERN_SUCCESS == status) {
    mach_vm_address_t address = (mach_vm_address_t)src;
    mach_vm_size_t size;
    vm_region_flavor_t flavor = VM_REGION_BASIC_INFO_64;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name;
    status = mach_vm_region(task, &address, &size, flavor, (vm_region_info_t)&info, &info_count, &object_name);
    if (KERN_SUCCESS == status) {
      mach_vm_size_t num_read = 0;
      status = mach_vm_read_overwrite(task, address, 1, (mach_vm_address_t)dst, &num_read);
      if ((KERN_SUCCESS == status) && (1 == num_read)) {
	ret = true;
      } else {
	DBG_PRINT("ERROR : %s read failed status %d num_read %d\n", __func__, status, num_read);
      }
    } else {
      DBG_PRINT("ERROR : %s getting vm region info %d\n", __func__, status);
    }
  } else {
    DBG_PRINT("ERROR : %s getting task failed status %d\n", __func__, status);
  }
  return ret;
}

bool osx_memory_copy_write(pid_t pid, void *dst, void *src)
{
  bool ret = false;
//  if (0 == ptrace(PT_WRITE_D, tid, dst, src))
//    ret = true;
  return ret;
}

gdb_target osx_target = {
	.next                     = NULL,
	.name                     = "ptrace",
	.desc                     = "native ptrace target",
	.remote_commands          = ptrace_remote_commands,
	.help                     = ptrace_help,
	.open                     = ptrace_open,
	.attach                   = ptrace_attach,
	.detach                   = ptrace_detach,
	.close                    = ptrace_close,
	.connect                  = ptrace_connect,
	.disconnect               = ptrace_disconnect,
	.kill                     = ptrace_kill,
	.restart                  = ptrace_restart,
	.stop                     = ptrace_stop,
	.set_gen_thread           = target_set_gen_thread,
	.set_ctrl_thread          = osx_set_ctrl_thread,
	.is_thread_alive          = osx_is_thread_alive,
	.read_registers           = osx_read_registers,
	.write_registers          = osx_write_registers,
	.read_single_register     = osx_read_single_register,
	.write_single_register    = osx_write_single_register,
	.memory_access_size       = osx_memory_access_size,
	.memory_copy_write        = osx_memory_copy_write,
	.memory_copy_read         = osx_memory_copy_read,
	.resume_from_current      = ptrace_resume_from_current,
	.resume_from_addr         = ptrace_resume_from_addr,
	.go_waiting               = ptrace_go_waiting,
	.wait_partial             = ptrace_wait_partial,
	.wait                     = ptrace_wait,
	.process_query            = osx_process_query,
	.list_query               = osx_list_query,
	.current_thread_query     = osx_current_thread_query,
	.offsets_query            = ptrace_offsets_query,
	.crc_query                = ptrace_crc_query,
	.raw_query                = ptrace_raw_query,
	.threadinfo_query         = ptrace_threadinfo_query,
	.threadextrainfo_query    = osx_threadextrainfo_query,
	.supported_features_query = ptrace_supported_features_query,
	.query_current_signal     = osx_query_current_signal,
	.general_set              = ptrace_general_set,
	.no_ack                   = ptrace_no_ack,
};

void target_init(struct gdb_target_s **target)
{
	*target = &osx_target;
}
void target_cleanup()
{
	/* Add cleanup code here */
}
