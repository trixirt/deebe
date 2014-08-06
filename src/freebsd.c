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
#ifdef PT_LWPINFO
    struct ptrace_lwpinfo lwpinfo = { 0 };
    if (0 == PTRACE(PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo))) {
	CURRENT_PROCESS_TID = lwpinfo.pl_lwpid;
    }
#endif
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
    bool ret = false;
    pid_t ppid = target_get_pid();
    static bool enter_ret;

    fprintf(stderr, "%x %x\n", pid, ppid);


    if (out_pid)
	*out_pid = -1;

#ifdef PT_LWPINFO
    struct ptrace_lwpinfo lwpinfo = { 0 };

    if (0 == PTRACE(PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo))) {
//    if (0 == PTRACE(PT_LWPINFO, ppid, &lwpinfo, sizeof(lwpinfo))) {
	    
	fprintf(stderr, "lwpinfo.pl_lwpid %x \n", lwpinfo.pl_lwpid);
	fprintf(stderr, "lwpinfo.pl_event %x \n", lwpinfo.pl_event);
	fprintf(stderr, "lwpinfo.pl_flags %x \n", lwpinfo.pl_flags);
	fprintf(stderr, "lwpinfo.pl_tdname %s \n", lwpinfo.pl_tdname);
	fprintf(stderr, "lwpinfo.pl_child_pid %x \n", lwpinfo.pl_child_pid);
	if (lwpinfo.pl_flags & PL_FLAG_SI) {
	    fprintf(stderr, "lwpinfo.pl_siginfo\n");
	    fprintf(stderr, "\t si_signo %d\n", lwpinfo.pl_siginfo.si_signo);
	    fprintf(stderr, "\t si_errno %d\n", lwpinfo.pl_siginfo.si_errno);
	    fprintf(stderr, "\t si_code  %d\n", lwpinfo.pl_siginfo.si_code);
	    fprintf(stderr, "\t si_pid   %x\n", lwpinfo.pl_siginfo.si_pid);
	    fprintf(stderr, "\t si_addr  %p\n", lwpinfo.pl_siginfo.si_addr);
	}


#if 1
    if (! WIFSTOPPED(status) ||
	(WSTOPSIG(status) != SIGTRAP)) {
	fprintf(stderr, "Confused with %d or %d vs %d\n",
		WIFSTOPPED(status), WSTOPSIG(status), SIGTRAP);

	exit (-1);
	ret = true;
	return ret;
    }
#endif

	if (lwpinfo.pl_flags & PL_FLAG_SCE) {
#if 1

	    unsigned long id, arg1, arg2, arg3, arg4, r;
	    ptrace_arch_get_syscall(&id, &arg1, &arg2, &arg3, &arg4, &r);
	    fprintf(stderr, "syscall %lx %lx %lx %lx \n", id, arg1, arg2, r);
#else
	    unsigned long id;
	    id = 4;
#endif
	    


	    if (id == SYS_thr_new) {
		
		fprintf(stderr, "thr_new %x %x ------------------- \n", pid, status);
		ret = true;

	    } else if (id == SYS_thr_exit) {
		target_dead_thread(pid);
		_target.current_process = 0; /* TODO rework */
		if (out_pid)
		    *out_pid = CURRENT_PROCESS_TID;

		PTRACE(PT_CONTINUE, pid, 1, 0);
		pid = waitpid(-1, &status, 0);
		
		fprintf(stderr, "thr_exit %x %x ------------------------\n", pid, status);
		ret = true;
	    } else if (id == SYS_exit) {
//		ret = false;
		ret = true;
	    } else {
		ret = true;
	    }
	    enter_ret = ret;
	} else if (lwpinfo.pl_flags & PL_FLAG_SCX) {

	    ret = enter_ret;
#if 1
	    int num_lwps = 0;
	    int num_threads = 0;
	    lwpid_t *lwpid_list = NULL;
	    
	    /* Handled but invalid */
	    ret = true;
	    if (out_pid)
		*out_pid = -1;

	    num_lwps = PTRACE(PT_GETNUMLWPS, pid, NULL, 0);
	    num_threads = target_number_threads();
    
	    if (num_lwps != num_threads) {

		fprintf(stderr, "%d vs %d\n", num_lwps, num_threads);

		if (num_lwps) {
		    fprintf(stderr, "%d \n", __LINE__);

		    lwpid_list = (lwpid_t *) calloc(num_lwps, sizeof(lwpid_t));
		    if (lwpid_list) {
			fprintf(stderr, "%d \n", __LINE__);

			if (num_lwps == PTRACE(PT_GETLWPLIST, pid, lwpid_list, num_lwps)) {
			    int i;
			    fprintf(stderr, "%d %d %d\n", __LINE__, num_lwps, num_threads);
			    if (num_lwps > num_threads) {

				fprintf(stderr, "%d \n", __LINE__);

				pid_t parent = target_get_pid();
				/* A thread is born */
				for (i = 0; i < num_lwps; i++) {
				    if (! target_is_tid(lwpid_list[i])) {
					if (target_new_thread(parent, lwpid_list[i])) {
					    if (out_pid)
						*out_pid = CURRENT_PROCESS_TID;
					    ret = true;
					}
					break;
				    }
				}
			    } else {
				fprintf(stderr, "%d \n", __LINE__);

				fprintf(stderr, "A thread has died\n");
				/* A thread has died */
			    }
			} else {
			    fprintf(stderr, "%d \n", __LINE__);

			    DBG_PRINT("Error with PT_GETLWPLIST\n");
			}
		    } else {
			fprintf(stderr, "%d \n", __LINE__);

			DBG_PRINT("Error allocating lwpid_list\n");
		    }
		} else {

		    fprintf(stderr, "%d \n", __LINE__);

		    /* Everyone is dead */
		    target_all_dead_thread();
		}
	    }

	    if (lwpid_list)
		free(lwpid_list);
#endif
	} else {

	    fprintf(stderr, "UNHANDLED lwpinfo.pl_flags %x \n", lwpinfo.pl_flags);

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

    fprintf(stderr, "ret %d\n", ret);

    return ret;
}


