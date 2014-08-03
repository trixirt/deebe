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
#include <unistd.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include "global.h"
#include "dptrace.h"

void ptrace_os_read_fxreg()
{
#ifdef PT_GETFPXREGS
	if (NULL != _target.fxreg) {
		_read_reg(PT_GETFPXREGS, PT_SETFPXREGS,
			  &_target.fxreg, &_target.fxreg_rw,
			  &_target.fxreg_size);
	}
#endif
}

void ptrace_os_write_fxreg()
{
#ifdef PT_GETFPXREGS
	if (NULL != _target.fxreg) {
		_write_reg(PT_SETFPXREGS, _target.fxreg);
	}
#endif
}

void ptrace_os_option_set_syscall(pid_t pid)
{
#ifdef PTRACE_O_TRACESYSGOOD
	errno = 0;
	if (0 == ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD)) {
		/* Success */
		;
	} else {
		/* Failure */
		char str[128];
		memset(&str[0], 0, 128);
		DBG_PRINT("Error in %s\n", __func__);
		if (0 == strerror_r(errno, &str[0], 128))
			DBG_PRINT("Error %d %s\n", errno, str);
		else
			DBG_PRINT("Error %d\n", errno);
	}
#endif
}

bool ptrace_os_check_syscall(pid_t pid, int *in_out_sig)
{
	bool ret = false;
	if (*in_out_sig == (SIGTRAP | 0x80)) {
		*in_out_sig = SIGTRAP;
		ret = true;
	}
	return ret;
}

void ptrace_os_option_set_thread(pid_t pid)
{
#ifdef PTRACE_O_TRACECLONE
    if (0 != ptrace(PTRACE_SETOPTIONS, CURRENT_PROCESS_TID, 
		    NULL, PTRACE_O_TRACECLONE)) {
	DBG_PRINT("error setting PTRACE_O_TRACECLONE\n");
    }
#endif
}

bool ptrace_os_wait_new_thread(pid_t *out_pid, int *out_status)
{
    bool ret = false;
    bool is_old = false;
    int index;
    pid_t pid;
	  
    pid = waitpid(-1, &current_status, __WALL);
    /* Ingnore non children, because the clone returns before the parent */
    for (index = 0; index < _target.number_processes; index++) {
	if (PROCESS_TID(index) == pid) {
	    is_old = true;
	    break;
	}
    }
    /* Handle case of a child pid showing up before the parent */
    if (!is_old) {
	pid_t new_tid = pid;
	int errs_max = 5;
	int errs = 0;
	for (errs = 0; errs < errs_max; errs++) {
	    /* Sleep for a 1 msec */
	    usleep(1000);
	    pid = waitpid(CURRENT_PROCESS_TID, &current_status, WNOHANG);
	    if (pid == CURRENT_PROCESS_TID) {
		break;
	    }
	}
	if (errs == errs_max) {
	    void *try_process = NULL;
	    /* child pid without a parent */
	    
	    /* Since the parent is not known, use a valid, if incorrect value */
	    pid_t current_process_pid = CURRENT_PROCESS_PID;
	    
	    /* re-Allocate per process state */
	    try_process = realloc(_target.process,
				  (_target.number_processes + 1) *
				  sizeof(struct target_process_rec));
	    if (try_process) {
		
		_target.process = try_process;
		_target.current_process = _target.number_processes; /* this one */
		_target.number_processes++;
		
		CURRENT_PROCESS_PID   = current_process_pid;
		CURRENT_PROCESS_TID   = new_tid;
		CURRENT_PROCESS_BPL   = NULL;
		CURRENT_PROCESS_ALIVE = true;

		if (out_pid)
		    *out_pid = new_tid;
		if (out_status)
		    *out_status = current_status;

		ret = true;
		} else {
		DBG_PRINT("Allocation of proccess failed\n");
	    }
	}
    }

    if (!ret) {
		if (out_pid)
		    *out_pid = new_tid;
		if (out_status)
		    *out_status = current_status;
    }

return ret;
}

bool ptrace_os_check_new_thread(pid_t pid, int status, pid_t *out_pid)
{
  bool ret = false;

  int s = WSTOPSIG(status);
  if (s == SIGTRAP) {
    int e = (status >> 16) & 0xff;
    if (e == PTRACE_EVENT_CLONE) {

	unsigned long new_tid = 0;
	if (0 != ptrace(PTRACE_GETEVENTMSG, CURRENT_PROCESS_TID, 0, &new_tid)) {
	    DBG_PRINT("ptrace error with new thread id\n");
	} else {
	    void *try_process = NULL;
	    int thread_status;
	    pid_t wait_pid;
	    
	    /* Wait for all children, to catch the thread */
	    wait_pid = waitpid(-1, &thread_status, __WALL);
	    if ((new_tid == wait_pid) && 
		(WIFSTOPPED(thread_status) &&
		 (WSTOPSIG(thread_status) == SIGSTOP))) {

		pid_t current_process_pid = CURRENT_PROCESS_PID;
			      
		/* re-Allocate per process state */
		try_process = realloc(_target.process,
				      (_target.number_processes + 1) *
				      sizeof(struct target_process_rec));
		if (try_process) {
		    
		    _target.process = try_process;
		    _target.current_process = _target.number_processes; /* this one */
		    _target.number_processes++;
		    
		    CURRENT_PROCESS_PID   = current_process_pid;
		    CURRENT_PROCESS_TID   = new_tid;
		    CURRENT_PROCESS_BPL   = NULL;
		    CURRENT_PROCESS_ALIVE = true;

		    if (out_pid)
			*out_pid = new_pid;
		    ret = true;
		} else {
		    DBG_PRINT("Allocation of proccess failed\n");
		}
	    }
	}
    }
  }
  return ret;
}
