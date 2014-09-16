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
	    if (!target_is_tid(tid)) {
		    pid_t tid2;
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

bool ptrace_os_new_thread(pid_t tid, int status) {
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

void ptrace_os_wait(pid_t t) {
    pid_t tid;
    int status = -1;

    /*
     * Only look for parent event after the children
     * are taken care of.  Do not do both.
     */
    status = -1;
    tid = waitpid(t, &status, WNOHANG);
    if (tid > 0 && status != -1) {
	int index;
	index = target_index(tid);
	if (index >= 0) {
	    PROCESS_WAIT(index) = true;
	    PROCESS_WAIT_STATUS(index) = status;
	}  else {
	    if (!target_new_thread(PROCESS_PID(0), tid, status, true)) {
		DBG_PRINT("error allocation of new thread\n");
	    }
	}
    } else {
	/*
	 * Look for children events first
	 */
	tid = waitpid(-1, &status, __WALL | WNOHANG);
	if (tid > 0 && status != -1) {
	    int index;
	    index = target_index(tid);
	    if (index >= 0) {
		PROCESS_WAIT(index) = true;
		PROCESS_WAIT_STATUS(index) = status;
	    }  else {
		if (!target_new_thread(PROCESS_PID(0), tid, status, true)) {
		    DBG_PRINT("error allocation of new thread\n");
		}
	    }
	} 
    }
    
    /*
     * DEBUGGING CODE
     * Check on why the wait happend
     *
     if (tid > 0 && status != -1) {
       siginfo_t si = { 0 };
       if (0 == ptrace(PTRACE_GETSIGINFO, tid, NULL, &si)) {
         fprintf(stderr, "Got siginfo %x %x\n", tid, status);
         fprintf(stderr, "signo %x\n", si.si_signo);
         fprintf(stderr, "errno %x\n", si.si_errno);
         fprintf(stderr, "code  %x\n", si.si_code);
       } else {
         fprintf(stderr, "NO siginfo\n");
       }
     }
    */
}

void ptrace_os_continue_others()
{
    /* In AllStop mode, this is a noop */
    if (NS_ON == _target.nonstop) {
	int index;
	for (index = 0; index < _target.number_processes; index++) {
	    pid_t pid = PROCESS_PID(index);
	    pid_t tid = PROCESS_TID(index);
	    bool wait = PROCESS_WAIT(index);

	    if (!wait || (tid == CURRENT_PROCESS_TID)) {
		continue;
	    } else {
		if (PS_CONT == PROCESS_STATE(index)) {
		    int sig = PROCESS_SIG(index);
		    int g = ptrace_arch_signal_to_gdb(sig);
		    ptrace_resume_from_current(pid, tid, 0, g);
		}
	    }
	}
    }
}

long ptrace_os_continue(pid_t pid, pid_t tid, int step, int sig) {
    long ret;
    long request = PT_CONTINUE;
    if (step == 1) {
	ptrace_arch_set_singlestep(tid, &request);
    } else {
	ptrace_arch_clear_singlestep(tid);
    }
    ret = ptrace(request, tid, 1, sig);
    return ret;
}

int ptrace_os_gen_thread(pid_t pid, pid_t tid)
{
    int ret = RET_ERR;
    int index;
    if ((pid < 0) || (tid < 0))
	goto end;

    index = target_index(tid);

    DBG_PRINT("%s index %d\n", __func__, index);
    
    if (index < 0) {
	/* Not a valid thread */
    } else if (!target_alive_thread(tid)) {
	/* dead thread */
	DBG_PRINT("%s dead %d\n", __func__, index);
    } else if (_target.current_process == index) {
	/* The trival case */
	DBG_PRINT("%s trivial %d\n", __func__, index);
	ret = RET_OK;
    } else if (PROCESS_WAIT(index)) {
	/* We got lucky, the process is already in a wait state */
	target_thread_make_current(index);
	
	DBG_PRINT("%s already waiting %d\n", __func__, index);
	
	/*
	 * Continuing the old current will happen automatically
	 * when the normal continue/wait logic runs
	 */
	ret = RET_OK;
    } else {
	
	DBG_PRINT("%s hard case %x %d\n", __func__, tid, index);
	
	/*
	 * The current thread is not the one that is being switched to.
	 * So stop the needed thread, and continue the now old current thread
	 */
	ptrace_stop(pid, tid);
	/*
	 * ptrace_stop send a SIG_INT to the tid
	 * To seperate this signal from a normal signal, flag it as 'internal'
	 */
	PROCESS_STATE(index) = PS_INTERNAL_SIG_PENDING;
	
	/*
	 * Now wait..
	 * Ripped off logic from normal wait.
	 * TBD : Clean up.
	 */
	{
	    int wait_ret;
	    char str[128];
	    size_t len = 128;
	    int tries = 0;
	    int max_tries = 20;
	    do {
		
		/*
		 * Keep track of the number of tries
		 * Don't get stuck in an infinite loop here.
		 */
		tries++;
		if (tries > max_tries) {
		    DBG_PRINT("Exceeded maximume retries to switch threads\n");
		    /* Some thread is waiting.. so goto end and return an error */
		    goto end;
		}
		
		/* Sleep for a a msec */
		usleep(1000);
		
		wait_ret = ptrace_wait(str, len, 0, true);
		if (wait_ret == RET_OK) {
		    DBG_PRINT("%s hard case %s\n", __func__, str);
		    
		    
		    /*
		     * When an RET_OK was hit, we have something to report
		     * However the thread handling the event may not be
		     * the thread we want.
		     *
		     * However since everyone is waiting then
		     * it is ok to switch the current thread
		     */
		    target_thread_make_current(index);
		} else if (wait_ret == RET_IGNORE) {
		    int g = ptrace_arch_signal_to_gdb(SIGINT);
		    ptrace_resume_from_current(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID, 0, g);
		}
		
	    } while ((wait_ret == RET_IGNORE) || (wait_ret == RET_CONTINUE_WAIT));
	    
	    /* 
	     * ptrace_wait could have thrown an error
	     * use ptrace_wait's return as this functions return 
	     */
	    ret = wait_ret;
	}
    }
end:
    return ret;
}

void ptrace_os_stopped_single(char *str, size_t len, bool debug)
{
    int index;
    for (index = 0; index < _target.number_processes; index++) {
	bool process_wait = PROCESS_WAIT(index);
	if (process_wait) {
	    DBG_PRINT("%s stopped %x looking for %x\n", __func__, index, _target.current_process);	    
	}
    }

    if (CURRENT_PROCESS_WAIT) {

		pid_t tid = CURRENT_PROCESS_TID;
		int wait_status = CURRENT_PROCESS_WAIT_STATUS;

		if (WIFSTOPPED(wait_status)) {

			int s = WSTOPSIG(wait_status);
			int g = ptrace_arch_signal_to_gdb(s);

			if (s == SIGTRAP) {
				unsigned long watchpoint_addr = 0;
				unsigned long pc = 0;

				ptrace_arch_get_pc(tid, &pc);
			
				/* Fill out the status string */
				if (ptrace_arch_hit_watchpoint(tid, &watchpoint_addr)) {
					/* A watchpoint was hit */
				    gdb_stop_string(str, len, g, tid, watchpoint_addr);
				} else {
					/* Either a normal breakpoint or a step, it doesn't matter */
				    gdb_stop_string(str, len, g, tid, 0);
				}

				if (debug) {
					DBG_PRINT("stopped at pc 0x%lx\n", pc);
					if (pc) {
						uint8_t b[32] = { 0 };
						size_t read_size = 0;
						ptrace_read_mem(tid, pc, &b[0], 32,
								&read_size);
						util_print_buffer(fp_log, 0, 32, &b[0]);
					}
				}
			} else {
			    /* A non trap signal */
			    gdb_stop_string(str, len, g, tid, 0);
			}
		}
	}
}
