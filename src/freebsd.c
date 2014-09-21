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
#include <sys/thr.h>
#include "target_ptrace.h"
#include <machine/reg.h>
#include "global.h"
#include "os.h"
#include "target.h"

static bool _lwpinfo_verbose = true;

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
			if (lwpinfo.pl_flags & PL_FLAG_SCE) {
				unsigned long id, arg1, arg2, arg3, arg4, r;
				id = -1; /* only initiaze id, because it is the only used variable */
				ptrace_arch_get_syscall(pid, &id, &arg1, &arg2, &arg3, &arg4, &r);
				DBG_PRINT("syscall enter %d\n", id);
			}
		}
		if (lwpinfo.pl_flags & PL_FLAG_SCE) {
			/*
			 * Entering a system call
			 * Find which system call it was.
			 */
			unsigned long id, arg1, arg2, arg3, arg4, r;
			id = -1; /* only initiaze id, because it is the only used variable */
			ptrace_arch_get_syscall(pid, &id, &arg1, &arg2, &arg3, &arg4, &r);
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
				DBG_PRINT("Dead %x switch to %x\n", pid, CURRENT_PROCESS_TID);


/*
  PTRACE(PT_CONTINUE, pid, 1, 0);
  pid = waitpid(-1, &status, 0); */
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
										if (target_new_thread(parent, lwpid_list[i], 0, false)) {
											if (out_pid)
												*out_pid = lwpid_list[i];
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

int os_thread_kill(int tid, int sig) {
	int ret = thr_kill((long)tid, sig);
	return ret;
}

bool ptrace_os_new_thread(pid_t tid, int status) {
	bool ret = false;
	int index = target_index(tid);
	if (index >= 0) {
		if ((PS_SYSCALL_ENTER == PROCESS_STATE(index)) ||
		    (PS_SYSCALL_EXIT == PROCESS_STATE(index))) {
			ret = true;
		}
	}
	return ret;
}

static void check_lwplist_for_new_threads(pid_t pid)
{
	int num_lwps = 0;
	lwpid_t *lwpid_list = NULL;

#if PT_GETNUMLWPS
	num_lwps = PTRACE(PT_GETNUMLWPS, pid, NULL, 0);
#endif

#ifdef PT_GETLWPLIST
	/*
	 * Look for different in number of threads the system
	 * has versus what we have.
	 *
	 * WARNING : System does not seem to report dead threads
	 * by removing the number of threads reported by PT_GETNUMLWPS
	 *
	 */
	if (num_lwps) {
		lwpid_list = (lwpid_t *) calloc(num_lwps, sizeof(lwpid_t));
		if (num_lwps == PTRACE(PT_GETLWPLIST, pid, lwpid_list, num_lwps)) {
			int i;
			for (i = 0; i < num_lwps; i++) {
				/* Find the one that isn't already being tracked */
				if (! target_is_tid(lwpid_list[i])) {
					pid_t new_tid = lwpid_list[i];
					pid_t parent = target_get_pid();
					/*
					 * The first time this is hit, it is the main thread of
					 * the parent process.  Set the parent process tid to
					 * this value so the first and second threads will be
					 * handled the same.
					 */
					if (PROCESS_TID(0) == PROCESS_PID(0)) {
						PROCESS_TID(0) = new_tid;
					} else {
						/*
						 * The tread has not quite been born
						 * Waiting for it now does not work.
						 * So defer waiting for it by adding the new thread
						 * but setting it's state to PRE_START
						 *
						 * Since the new thread is not in a wait state, set the
						 * wait flag to false.
						 */
						if (!target_new_thread(parent, new_tid, PROCESS_WAIT_STATUS_DEFAULT, false)) {
							DBG_PRINT("%s error allocating new thread\n", __func__);
						} else {
							int index = target_index(new_tid);
							PROCESS_STATE(index) = PS_PRE_START;
						}
						break;
					}
				}
			} /* lwps loop */
		}
	}

#endif
	if (lwpid_list)
		free(lwpid_list);
}


static int check_lwpinfo(pid_t pid)
{
	int ret = 0; /* Index */
#ifdef PT_LWPINFO
	int index;
	pid_t tid;
	int ptrace_status;
	/*
	 * Use PT_LWPINFO to get a fine grained reason for the wait
	 */
	struct ptrace_lwpinfo lwpinfo = { 0 };
	ptrace_status = PTRACE(PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo));
	if (0 == ptrace_status) {

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
			if (lwpinfo.pl_flags & PL_FLAG_SCE) {
				unsigned long id, arg1, arg2, arg3, arg4, r;
				id = -1; /* only initiaze id, because it is the only used variable */
				ptrace_arch_get_syscall(pid, &id, &arg1, &arg2, &arg3, &arg4, &r);
				DBG_PRINT("syscall enter %d\n", id);
			}
		}
		/*
		 * wait works on the pid
		 * This does not tell us which lwp caused the event
		 * To find this, look in the lwpinfo.pl_lwpid
		 */
		tid = lwpinfo.pl_lwpid;
		if (! target_is_tid(tid)) {
			/*
			 * The first time this is hit, it is the main thread of
			 * the parent process.  Set the parent process tid to
			 * this value so the first and second threads will be
			 * handled the same.
			 */
			if (PROCESS_TID(0) == PROCESS_PID(0)) {
				PROCESS_TID(0) = tid;
			} else {
				if (!target_new_thread(PROCESS_PID(0), tid, PROCESS_WAIT_STATUS_DEFAULT, false)) {
					DBG_PRINT("%s error allocating new thread\n", __func__);
				}
			}
		}
		index = target_index(tid);
		if (index >= 0) {
			if (lwpinfo.pl_flags & PL_FLAG_SCE) {
				unsigned long id, arg1, arg2, arg3, arg4, r;
				id = -1; /* only initiaze id, because it is the only used variable */
				ptrace_arch_get_syscall(tid, &id, &arg1, &arg2, &arg3, &arg4, &r);
				PROCESS_SYSCALL(index) = id;
				PROCESS_STATE(index) = PS_SYSCALL_ENTER;
			} else if (lwpinfo.pl_flags & PL_FLAG_SCX) {
				PROCESS_STATE(index) = PS_SYSCALL_EXIT;
			}
			ret = index;
		}
	} else {
		char str[128];
		DBG_PRINT("Error get lwpinfo, status is %d\n", ptrace_status);
		if (0 == strerror_r(errno, &str[0], 128)) {
			DBG_PRINT("Error %d %s\n", errno, str);
		}
	}
#endif
	return ret;
}

void ptrace_os_wait(pid_t t)
{
	/*
	 * FreeBSD wait only works on the process id
	 * So no matter what is passed in, use the process id
	 * of the parent.
	 */
	pid_t pid = PROCESS_PID(0);
	int wait_status = -1;
	pid_t wait_tid = 0;
	wait_tid = waitpid(pid, &wait_status, WNOHANG);
	if ((wait_tid == pid) && (-1 != wait_status)) {
		int wait_index;
		int index;
		/*
		 * check_lwpinfo returns the index to the tid that
		 * caused the event.
		 */
		wait_index = check_lwpinfo(wait_tid);
		/* check_lwpinfo can fail */
		if (wait_index >= 0) {
			PROCESS_WAIT(wait_index) = true;
			PROCESS_WAIT_STATUS(wait_index) = wait_status;
			/* Since we waited on the pid, everyone is stopped */
			for (index = 0; index < _target.number_processes; index++) {
				if (PROCESS_STATE(index) != PS_EXIT) {
					PROCESS_STATE(index) = PS_STOP;
				}
			}
			/*
			 * Need to keep track of new threads being created
			 * Without this check only those that hit a breakpoint
			 * would be reported.
			 *
			 * This call can change the number of threads in the thread
			 * list but it will not change the order.
			 */
			check_lwplist_for_new_threads(pid);
		} else {
			DBG_PRINT("ERROR %s lwpinfo failed %x %x %x\n", __func__, pid, wait_tid, wait_status);
		}
	}
}

void ptrace_os_continue_others()
{
	/* Noop */
}

/*
 * FreeBSD continues all threads as a group
 * There is no control over individual threads.
 * So always use the pid.
 */
long ptrace_os_continue(pid_t pid, pid_t tid, int step, int sig) {
	long ret;
	long request = PT_CONTINUE;
	int index;
	/*
	 * FreeBSD does not notify when a thread exits
	 * So if we continue a thread continues until it ends, we are stuck.
	 * So only continue the thread when single stepping.
	 * Unhandled is single stepping to the end of the thread.
	 */
	if (step == 1) {
		ptrace_arch_set_singlestep(tid, &request);
	} else {
		ptrace_arch_clear_singlestep(tid);
	}
	/*
	 * Staring up everyone
	 * XXX out of order, does not handle the error
	 */
	for (index = 0; index < _target.number_processes; index++) {
		if (PROCESS_STATE(index) != PS_EXIT) {
			PROCESS_STATE(index) = PS_RUN;
		}
	}
	ret = PTRACE(request, pid, 1, sig);
	return ret;
}

int ptrace_os_gen_thread(pid_t pid, pid_t tid)
{
	int ret = RET_ERR;
	int index;
	if ((pid < 0) || (tid < 0))
		goto end;
	index = target_index(tid);
	if (index < 0) {
		/* Not a valid thread */
	} else if (!target_alive_thread(tid)) {
		/* dead thread */
		DBG_PRINT("%s dead %d\n", __func__, index);
	} else if (_target.current_process == index) {
		/* The trival case */
		DBG_PRINT("%s trivial %d\n", __func__, index);
		ret = RET_OK;
	} else if (PROCESS_STATE(index) == PS_RUN) {
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
	} else {
		/* Assume stopped */
		/* We got lucky, the process is already in a stopped state */
		target_thread_make_current(index);
		/*
		 * Continuing the old current will happen automatically
		 * when the normal continue/wait logic runs
		 */
		ret = RET_OK;
	}

end:
	return ret;
}

/*
 * In FreeBSD all threads single step together.
 * So the stopped thread may not be the current thread.
 * This makes it difficult because gdb assume the single stepped
 * thread is the only thread running and relies on single
 * stepping to get past a normal break point.  So if we see
 * a SIGTRAP on any thread, remap to the current thread assuming
 * that the non current thread is also reporting the single step
 * and isn't reporting a normal break point or watch point.
 * However any other signal's need to be handled normally, the
 * current thread is set to signalling thread.
 */
void ptrace_os_stopped_single(char *str, size_t len, bool debug)
{
	int index;
	for (index = 0; index < _target.number_processes; index++) {
		if (PROCESS_WAIT(index))
			break;
	}
	if (index < _target.number_processes) {
		pid_t current_tid = CURRENT_PROCESS_TID;
		pid_t tid = PROCESS_TID(index);
		int wait_status = PROCESS_WAIT_STATUS(index);
		if (WIFSTOPPED(wait_status)) {
			int s = WSTOPSIG(wait_status);
			int g = ptrace_arch_signal_to_gdb(s);
			if (s == SIGTRAP) {
				unsigned long watchpoint_addr = 0;
				unsigned long pc = 0;
				ptrace_arch_get_pc(tid, &pc);
				/* Only check if the current thread is at a watchpoint */
				if (ptrace_arch_hit_watchpoint(tid, &watchpoint_addr)) {
					/* A watchpoint was hit */
					target_thread_make_current(tid);
					gdb_stop_string(str, len, g, tid, 0);
					/*
					 * process stat points to the true thread to continue
					 * Not that it matter on FreeBSD as they all go at once
					 */
					PROCESS_STATE(index) = PS_CONT;
				} else {
					/*
					 * Map all tid's to the current tid
					 *
					 * Either a normal breakpoint or a step, it doesn't matter
					 */
					target_thread_make_current(tid);
					gdb_stop_string(str, len, g, tid, 0);
					/*
					 * process stat points to the true thread to continue
					 * Not that it matter on FreeBSD as they all go at once
					 */
					PROCESS_STATE(index) = PS_CONT;

				}
			} else {
				/* A non trap signal, report the true thread */
				target_thread_make_current(tid);
				gdb_stop_string(str, len, g, tid, 0);
				PROCESS_STATE(index) = PS_CONT;
			}
		}
	}
}
