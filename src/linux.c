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

void ptrace_os_read_fxreg(pid_t tid)
{
#ifdef PT_GETFPXREGS
	if (NULL != _target.fxreg) {
		_read_reg(tid, PT_GETFPXREGS, PT_SETFPXREGS,
			  &_target.fxreg, &_target.fxreg_rw,
			  &_target.fxreg_size);
	}
#endif
}

void ptrace_os_write_fxreg(pid_t tid)
{
#ifdef PT_GETFPXREGS
	if (NULL != _target.fxreg) {
		_write_reg(tid, PT_SETFPXREGS, _target.fxreg);
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
    pid_t tid;
    int status = 0;
    
    tid = waitpid(-1, &status, __WALL | WNOHANG);
    if (tid > 0) {

	    fprintf(stderr, "%x\n", tid);

	    if (!target_is_tid(tid)) {
		    pid_t tid2;
		    fprintf(stderr, "Got %x %x\n", tid, status);

		    int thread_status;
		    int errs_max = 5;
		    int errs = 0;
		    for (errs = 0; errs < errs_max; errs++) {
			    /* Sleep for a 1 msec */
			    usleep(1000);
			    tid2 = waitpid(tid, &thread_status, WNOHANG | __WCLONE);
			    if (tid2 == tid) {
				    break;
			    } else {
				    int other_index;
				    other_index = target_index(tid2);
				    if (other_index >= 0) {
					    PROCESS_WAIT_STATUS(other_index) = status;
					    PROCESS_WAIT(other_index) = true;
					    
					    DBG_PRINT("%s strange.. %d %x\n", __func__, other_index, status);
					    
				    } else {
					    DBG_PRINT("%s try %d %x vs %x status %d\n", __func__, errs, tid2, tid, thread_status);
				    }
			    }
		    }
		    
		    if (errs < errs_max) {
			    if (WIFSTOPPED(thread_status) &&
				(WSTOPSIG(thread_status) == SIGSTOP)) {
				    if (target_new_thread(CURRENT_PROCESS_PID, tid, 0, /* thread_status,*/ true)) {
					    if (out_pid)
						    *out_pid = tid;
					    ret = true;
					    
					    DBG_PRINT("%s good.. %x\n", __func__, tid);
					    
				    } else {
					    DBG_PRINT("%s error allocating new thread\n", __func__);
				    }
			    } else {
				    DBG_PRINT("%s error with expected thread wait status %x\n", __func__, thread_status);
			    }
		    } else {
			    DBG_PRINT("%s error waiting for child thread : Error is %s\n", __func__, strerror(errno));
		    }
		    
	    } else {
		    int index = target_index(tid);
		    PROCESS_WAIT_STATUS(index) = status;
		    PROCESS_WAIT(index) = true;
	    }
    }

    return ret;
}

bool ptrace_os_new_thread(int status) {
    bool ret = false;
    int e = (status >> 16) & 0xff;
    if (e == PTRACE_EVENT_CLONE) {
	ret = true;
    }
    return ret;
}

bool ptrace_os_check_new_thread(pid_t pid, int status, pid_t *out_pid)
{
	bool ret = false;

#if 0
	int s = WSTOPSIG(status);
	if (s == SIGTRAP) {
		int e = (status >> 16) & 0xff;
		if (e == PTRACE_EVENT_CLONE) {

			DBG_PRINT("%s looking good\n", __func__);

			unsigned long new_tid = 0;
			if (0 != ptrace(PTRACE_GETEVENTMSG, CURRENT_PROCESS_TID, 0, &new_tid)) {
				DBG_PRINT("ptrace error with new thread id\n");
			} else {
				int thread_status;
				int errs_max = 5;
				int errs = 0;
				for (errs = 0; errs < errs_max; errs++) {
					/* Sleep for a 1 msec */
					usleep(1000);
					pid = waitpid(new_tid, &thread_status, WNOHANG | __WCLONE);
					if (pid == new_tid) {
						break;
					} else {
						int other_index;
						other_index = target_index(pid);
						if (other_index >= 0) {
							PROCESS_WAIT_STATUS(other_index) = status;
							PROCESS_WAIT(other_index) = true;

							DBG_PRINT("%s strange.. %d %x\n", __func__, other_index, status);

						} else {
							DBG_PRINT("%s try %d %x vs %x status %d\n", __func__, errs, pid, new_tid, thread_status);
						}
					}
				}

				if (errs < errs_max) {
					if (WIFSTOPPED(thread_status) &&
					    (WSTOPSIG(thread_status) == SIGSTOP)) {
						if (target_new_thread(CURRENT_PROCESS_PID, new_tid, 0, /* thread_status,*/ true)) {
							if (out_pid)
								*out_pid = new_tid;
							ret = true;
							
							DBG_PRINT("%s good.. %x\n", __func__, new_tid);

						} else {
							DBG_PRINT("%s error allocating new thread\n", __func__);
						}
					} else {
						DBG_PRINT("%s error with expected thread wait status %x\n", __func__, thread_status);
					}
				} else {
					DBG_PRINT("%s error waiting for child thread : Error is %s\n", __func__, strerror(errno));
				}
			}
		}
	}
#endif

	return ret;
}

int os_thread_kill(int tid, int sig) {
    return 1;
}
