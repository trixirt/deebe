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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "global.h"
#include "target.h"

target_state _target = {
	.no_ack = 0, /* ack until it is ok not to */
	/*
	 * Older gdb's do not know the difference between
	 * AllStop and NonStop mode for threading.
	 * Since AllStop is the oldest mode, default to that.
	 */
	.nonstop = NS_ON,
	.multiprocess = 0, /* default to supporting multiple processes */
	.syscall_enter = false,
	.flag_attached_existing_process = 1,
	.reg_size = 0,
	.freg_size = 0,
	.fxreg_size = 0,
	.dbreg_size = 0,
	.reg_rw = NULL, /* TODO : FREE THIS */
	.freg_rw = NULL, /* TODO : FREE THIS */
	.fxreg_rw = NULL, /* TODO : FREE THIS */
	.dbreg_rw = NULL, /* TODO : FREE THIS */
	.number_processes = 0,
	.current_process = 0,
	.process = NULL, /* TODO : FREE THIS */
};

bool target_new_thread(pid_t pid, pid_t tid, int wait_status, bool waiting)
{
    bool ret = false;
    int index = _target.number_processes;

    /*
     * Try to reused an exited process's space
     */
     for (index = 0; index < _target.number_processes; index++) {
       if (PROCESS_STATE(index) == PS_EXIT)
         break;
     }

    /* No space, tack one onto the end */
    if (index >= _target.number_processes) {
	    void *try_process = NULL;

	    /* Allocate registers for the process */
	    try_process = realloc(_target.process,
				  (_target.number_processes + 1) *
				  sizeof(struct target_process_rec));
	    if (!try_process) {
		    goto end;
	    } else {
		    _target.process = try_process;
		    index = _target.number_processes;
		    _target.number_processes++;
	    }
    } 

    PROCESS_PID(index) = pid;
    PROCESS_TID(index) = tid;
    PROCESS_STATE(index) = PS_START;
    PROCESS_WAIT_STATUS(index) = wait_status;
    PROCESS_WAIT(index) = waiting;
    PROCESS_SIG(index) = 0;
    ret = true;

end:

    DBG_PRINT("%s pid %x tid %x index %d return %d\n", __func__, pid, tid, index, ret);
    return ret;
}

int target_number_threads()
{
    int ret = 0;
    int index;
    
    for (index = 0; index < _target.number_processes; index++) {
	if (PROCESS_STATE(index) != PS_EXIT)
	    ret++;
    }
    return ret;
}

pid_t target_get_pid() 
{
    pid_t ret = -1;
    ret = PROCESS_PID(0);

    return ret;
}

bool target_dead_thread(pid_t tid) 
{
    bool ret = false;
    int index;
   
    for (index = 0; index < _target.number_processes; index++) {
	if (tid == PROCESS_TID(index)) {
	    PROCESS_STATE(index) = PS_EXIT;
	    ret = true;
	    break;
	}
    }
    return ret;
}

void target_all_dead_thread(pid_t tid) 
{
    int index;
    for (index = 0; index < _target.number_processes; index++) {
	PROCESS_STATE(index) = PS_EXIT;
    }
}

bool target_alive_thread(pid_t tid) 
{
    bool ret = false;
    int index;
   
    for (index = 0; index < _target.number_processes; index++) {
	if (tid == PROCESS_TID(index)) {
	    PROCESS_STATE(index) = PS_START;
	    ret = true;
	    break;
	}
    }
    return ret;
}

bool target_is_tid(pid_t tid)
{
    bool ret = false;
    int index;
   
    for (index = 0; index < _target.number_processes; index++) {
	if (tid == PROCESS_TID(index)) {
	    if (PROCESS_STATE(index) != PS_EXIT)
		ret = true;
	    break;
	}
    }
    return ret;
}

int target_index(pid_t tid)
{
    int ret = -1;
    int index;
   
    for (index = 0; index < _target.number_processes; index++) {
	if (tid == PROCESS_TID(index)) {
	    ret = index;
	    break;
	}
    }

    return ret;
}

bool target_thread_make_current(pid_t tid)
{
    bool ret = false;
    int index = target_index(tid);
    if (index >= 0) {
	_target.current_process = index;
	ret = true;

	DBG_PRINT("%s %x %d\n", __func__, tid, index);
	
    }
    return ret;
}

void _target_debug_print() {
    int index;
   
    for (index = 0; index < _target.number_processes; index++) {
	fprintf(stderr, "%d %x %x %d\n", index, PROCESS_PID(index), PROCESS_TID(index),
		PROCESS_STATE(index));
    }
}

int target_current_index()
{
	return _target.current_process;
}
