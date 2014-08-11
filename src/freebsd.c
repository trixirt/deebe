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
#include <sys/syscall.h>
#include "target_ptrace.h"
#include <machine/reg.h>
#include "global.h"
#include "os.h"
#include "target.h"

static bool _lwpinfo_verbose = false;

void ptrace_os_set_singlestep(pid_t pid, long *request)
{
	/*
	 * Needs to do a PT_SETSTEP and a PT_CONTINUE
	 * Do the PT_SETSTEP here and do the PT_CONTINUE in the callee
	 */
	ptrace(PT_SETSTEP, pid, 0, 0);
}

void ptrace_os_clear_singlestep(pid_t pid)
{
	ptrace(PT_CLEARSTEP, pid, 0, 0);
}

void ptrace_os_option_set_syscall(pid_t pid)
{
}

void ptrace_os_option_set_thread(pid_t pid)
{
}

bool ptrace_os_wait_new_thread(pid_t *out_pid, int *out_status)
{
    bool ret = false;
    pid_t pid;
    int status = 0;

    pid = waitpid(-1, &status, 0);

    if (out_pid)
	*out_pid = pid;
    if (out_status)
	*out_status = status;
    
    return ret;
}

bool ptrace_os_check_new_thread(pid_t pid, int status, pid_t *out_pid)
{
    /* deault to 'not handled' */
    bool ret = false;

    /*
     * Set to an invalid pid
     * This sets up the default 'handled' behaviour to
     * ignore the event and try again
     */
    if (out_pid)
	*out_pid = -1;

#ifdef PT_LWPINFO
    struct ptrace_lwpinfo lwpinfo = { 0 };

    if (0 == PTRACE(PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo))) {

	if (_lwpinfo_verbose) {
	    DBG_PRINT("lwpinfo.pl_lwpid %x \n", lwpinfo.pl_lwpid);
	    DBG_PRINT("lwpinfo.pl_event %x \n", lwpinfo.pl_event);
	    DBG_PRINT("lwpinfo.pl_flags %x \n", lwpinfo.pl_flags);
	    DBG_PRINT("lwpinfo.pl_tdname %s \n", lwpinfo.pl_tdname);
	    DBG_PRINT("lwpinfo.pl_child_pid %x \n", lwpinfo.pl_child_pid);
	    if (lwpinfo.pl_flags & PL_FLAG_SI) {
		DBG_PRINT("lwpinfo.pl_siginfo\n");
		DBG_PRINT("\t si_signo %d\n", lwpinfo.pl_siginfo.si_signo);
		DBG_PRINT("\t si_errno %d\n", lwpinfo.pl_siginfo.si_errno);
		DBG_PRINT("\t si_code  %d\n", lwpinfo.pl_siginfo.si_code);
		DBG_PRINT("\t si_pid   %x\n", lwpinfo.pl_siginfo.si_pid);
		DBG_PRINT("\t si_addr  %p\n", lwpinfo.pl_siginfo.si_addr);
	    }
	}

	if (lwpinfo.pl_flags & PL_FLAG_SCE) {
	    /* 
	     * Entering a system call
	     * Find which system call it was.
	     */
	    unsigned long id, arg1, arg2, arg3, arg4, r;
	    id = -1; /* only initiaze id, because it is the only used variable */
	    ptrace_arch_get_syscall(&id, &arg1, &arg2, &arg3, &arg4, &r);
	    
	    /* handled */
	    ret = true;
	    
	    if (id == SYS_thr_exit) {
	    /*
	     * On the edge of exiting the thread
	     * Reset the global current thread to the parent process
	     * Then manually continue with the dieing thread
	     */
		target_dead_thread(pid);
		_target.current_process = 0; /* parent process index */
		if (out_pid)
		    *out_pid = CURRENT_PROCESS_TID;
		
		PTRACE(PT_CONTINUE, pid, 1, 0);
		pid = waitpid(-1, &status, 0);
		
	    }

	} else if (lwpinfo.pl_flags & PL_FLAG_SCX) {
	    
	    int num_lwps = 0;
	    int num_threads = 0;
	    lwpid_t *lwpid_list = NULL;
	    
	    /* Handled but invalid */
	    ret = true;
	    
	    num_lwps = PTRACE(PT_GETNUMLWPS, pid, NULL, 0);
	    num_threads = target_number_threads();
	    
	    /*
	     * Look for different in number of threads the system
	     * has versus what we have.
	     *
	     * WARNING : System does not seem to report dead threads
	     * by removing the number of threads reported by PT_GETNUMLWPS
	     * This means neither can we.
	     */
	    if (num_lwps != num_threads) {
		if (num_lwps) {
		    lwpid_list = (lwpid_t *) calloc(num_lwps, sizeof(lwpid_t));
		    if (lwpid_list) {
			if (num_lwps == PTRACE(PT_GETLWPLIST, pid, lwpid_list, num_lwps)) {
			    /* More than expected, A new thread is born! */
			    if (num_lwps > num_threads) {
				pid_t parent = target_get_pid();
				int i;
				for (i = 0; i < num_lwps; i++) {
				    /* Find the one that isn't already being tracked */
				    if (! target_is_tid(lwpid_list[i])) {
					if (target_new_thread(parent, lwpid_list[i])) {
					    if (out_pid)
						*out_pid = CURRENT_PROCESS_TID;
					}
					break;
				    }
				}
			    } else {
				/*
				 * A thread has died
				 *
				 * In development, this case was never reached.
				 * Leave it here in case somthing improved
				 */
				DBG_PRINT("Unexpected code hit %s %d \n", __func__, __LINE__);
			    }
			} else {
			    DBG_PRINT("Error with PT_GETLWPLIST\n");
			}
		    } else {
			DBG_PRINT("Error allocating lwpid_list\n");
		    }
		} else {
		    /* Everyone is dead */
		    target_all_dead_thread();
		}
	    }
	    
	    if (lwpid_list)
		free(lwpid_list);
	    
	} else {
	    
	    if (_lwpinfo_verbose) {
		DBG_PRINT("UNHANDLED lwpinfo.pl_flags %x \n", lwpinfo.pl_flags);
	    }
	    
	    /* Stopping for something that isn't a system call, like a breakpoint */
	    if (lwpinfo.pl_flags & PL_FLAG_SI) {
		ret = false;
	    } else {
		/* Maybe ? */
		ret = true;
	    }
	    
	} /* sycall exit check */
	
    } /* pt_lwpinfo */
#endif

    return ret;
}


