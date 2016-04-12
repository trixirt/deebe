/*
 * Copyright (c) 2012-2016, Juniper Networks, Inc.
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
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/thr.h>
#include <sys/user.h>
#include <fcntl.h>
#include <stdint.h>
#include <libutil.h>
#include <libprocstat.h>
#include "target_ptrace.h"
#include <machine/reg.h>
#include "global.h"
#include "os.h"
#include "target.h"

static bool _lwpinfo_verbose = false;
static bool _threadstate_verbose = false;

bool fbsd_thread_state() {
  bool ret = true;
  struct procstat *prstat;
  /* See FreeBSD usr.bin/procstat/procstat_threads.c */
  prstat = procstat_open_sysctl();
  if (prstat != NULL) {
    pid_t pid = CURRENT_PROCESS_PID;
    struct kinfo_proc *kp;
    unsigned int count = 0;
    kp = procstat_getprocs(prstat,
			   KERN_PROC_PID | KERN_PROC_INC_THREAD,
			   pid, &count);
    if (kp != NULL) {
      int i;
      if (_threadstate_verbose) {
	DBG_PRINT("Thread state\n");
      }
      for (i = 0; i < count; i++) {
	struct kinfo_proc *kpp = &kp[i];
	const char *str;
	if (_threadstate_verbose) {
	  DBG_PRINT("\tpid %x tid %x ", kpp->ki_pid, kpp->ki_tid);
	}
	switch (kpp->ki_stat) {
	case SRUN:
	  ret = false;
	  str = "run";
	  break;
	case SSTOP:
	  str = "stop";
	  break;
	case SSLEEP:
	  ret = false;
	  str = "sleep";
	  break;
	case SLOCK:
	  ret = false;
	  str = "lock";
	  break;
	case SWAIT:
	  ret = false;
	  str = "wait";
	  break;
	case SZOMB:
	  ret = false;
	  str = "zomb";
	  break;
	case SIDL:
	  ret = false;
	  str = "idle";
	  break;
	default:
	  ret = false;
	  str = "??";
	  break;
	}
	if (_threadstate_verbose) {
	  DBG_PRINT("%s\n", str);
	}
      }
      procstat_freeprocs(prstat, kp);
      kp = NULL;
    }
    procstat_close(prstat);
    prstat = NULL;
  }
  return ret;
}

static void fbsd_update_thread_state() {
    struct procstat *prstat;
    /* See FreeBSD usr.bin/procstat/procstat_threads.c */
    prstat = procstat_open_sysctl();
    if (prstat != NULL) {
	pid_t pid = CURRENT_PROCESS_PID;
	struct kinfo_proc *kp;
	unsigned int k_count = 0;
	kp = procstat_getprocs(prstat,
			       KERN_PROC_PID | KERN_PROC_INC_THREAD,
			       pid, &k_count);
	if (kp != NULL) {
	    int k_index, d_index;
	    struct kinfo_proc *kpp;

	    for (d_index = 0; d_index < _target.number_processes; d_index++) {
		bool found = false;
		for (k_index = 0; k_index < k_count; k_index++) {
		    kpp = &kp[k_index];

		    if ((PROCESS_PID(d_index) == kpp->ki_pid) &&
			(PROCESS_TID(d_index) == kpp->ki_tid)) {
			found = true;

			/*
			 * Mapping from kernel to deebe state isn't great.
			 * At this point everyone should be stopped, but
			 * check to be sure.
			 */
			if (SSTOP != kpp->ki_stat) {
			    DBG_PRINT("Unexpected run state for %x %x %d\n",
				      kpp->ki_pid, kpp->ki_tid, kpp->ki_stat);
			}
			PROCESS_STATE(d_index) = PS_STOP;
			break;
		    }
		}
		/* Thread died */
		if (found == false) {
		    PROCESS_STATE(d_index) = PS_EXIT;
		}
	    }

	    /* Double check that all our threads are accounted for */
	    for (k_index = 0; k_index < k_count; k_index++) {
		bool found = false;
		for (d_index = 0; d_index < _target.number_processes;
		     d_index++) {
		    kpp = &kp[k_index];

		    if ((PROCESS_PID(d_index) == kpp->ki_pid) &&
			(PROCESS_TID(d_index) == kpp->ki_tid)) {
			found = true;
			break;
		    }
		}
		/* Unaccounded for k_thread */
		if (found == false) {
		    DBG_PRINT("Unexpected kernel thread %x %x %d\n",
			      kpp->ki_pid, kpp->ki_tid, kpp->ki_stat);
		    PROCESS_STATE(d_index) = PS_EXIT;
		}
	    }
	    procstat_freeprocs(prstat, kp);
	    kp = NULL;
	}
	procstat_close(prstat);
	prstat = NULL;
    }
}

void ptrace_os_set_singlestep(pid_t pid, long *request) {
  /*
   * Needs to do a PT_SETSTEP and a PT_CONTINUE
   * Do the PT_SETSTEP here and do the PT_CONTINUE in the callee
   */
  ptrace(PT_SETSTEP, pid, 0, 0);
}

void ptrace_os_clear_singlestep(pid_t pid) { ptrace(PT_CLEARSTEP, pid, 0, 0); }

void ptrace_os_option_set_syscall(pid_t pid) {}

bool ptrace_os_check_new_thread(pid_t pid, int status, pid_t *out_tid) {
  /* deault to 'not handled' */
  bool ret = false;
  /*
   * Set to an invalid pid
   * This sets up the default 'handled' behaviour to
   * ignore the event and try again
   */
  if (out_tid)
    *out_tid = -1;

#ifdef PT_LWPINFO
  struct ptrace_lwpinfo lwpinfo = {0};
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
        if (out_tid)
          *out_tid = CURRENT_PROCESS_TID;
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
          lwpid_list = (lwpid_t *)calloc(num_lwps, sizeof(lwpid_t));
          if (lwpid_list) {
            if (num_lwps == PTRACE(PT_GETLWPLIST, pid, lwpid_list, num_lwps)) {
              /* More than expected, A new thread is born! */
              if (num_lwps > num_threads) {
                pid_t parent = target_get_pid();
                int i;
                for (i = 0; i < num_lwps; i++) {
                  /* Find the one that isn't already being tracked */
                  if (!target_is_tid(lwpid_list[i])) {
                    if (target_new_thread(parent, lwpid_list[i], 0, false,
                                          SIGSTOP)) {
                      if (out_tid)
                        *out_tid = lwpid_list[i];
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
  }   /* pt_lwpinfo */
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

static void check_lwplist_for_new_threads(pid_t pid) {
  int num_lwps = 0;
  lwpid_t *lwpid_list = NULL;

#if PT_GETNUMLWPS
  num_lwps = PTRACE(PT_GETNUMLWPS, pid, NULL, 0);
  if (_lwpinfo_verbose) {
    DBG_PRINT("%s threads %d\n", __func__, num_lwps);
  }
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
    lwpid_list = (lwpid_t *)calloc(num_lwps, sizeof(lwpid_t));
    if (num_lwps == PTRACE(PT_GETLWPLIST, pid, lwpid_list, num_lwps)) {
      int i;
      for (i = 0; i < num_lwps; i++) {
        /* Find the one that isn't already being tracked */
        if (!target_is_tid(lwpid_list[i])) {
          pid_t new_tid = lwpid_list[i];
          pid_t parent = target_get_pid();
          /*
           * The tread has not quite been born
           * Waiting for it now does not work.
           * So defer waiting for it by adding the new thread
           * but setting it's state to PRE_START
           *
           * Since the new thread is not in a wait state, set the
           * wait flag to false.
           */
          if (!target_new_thread(parent, new_tid, PROCESS_WAIT_STATUS_DEFAULT,
                                 false, SIGSTOP)) {
            DBG_PRINT("%s error allocating new thread\n", __func__);
          } else {
            int index = target_index(new_tid);
            PROCESS_STATE(index) = PS_PRE_START;
          }
          /*
           * If we were adding threads one at a time, it would be safe to break
           * here.
           * However, when this function is called via an attach there could be
           * multiple new threads.  This will have the side effect of setting
           * the
           * last thread in the list to the current thread.
           */
        }
      } /* lwps loop */
    }
  }

#endif
  if (lwpid_list)
    free(lwpid_list);
}

void ptrace_os_option_set_thread(pid_t pid) {
  /*
   * Need to query PT_LWPINFO to get the tid of the main process
   */
  if (PROCESS_TID(0) == PROCESS_PID(0)) {
#ifdef PT_LWPINFO
    struct ptrace_lwpinfo lwpinfo = {0};
    if (0 == PTRACE(PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo))) {
      PROCESS_TID(0) = lwpinfo.pl_lwpid;
    }
#endif
  }
  /*
   * This function is called when an attach is made,
   * There may be other threads already started that need to
   * be accounted for so check for them now.
   */
  check_lwplist_for_new_threads(pid);
 }

void ptrace_os_wait(pid_t t) {
  /*
   * FreeBSD wait only works on the process id
   * So no matter what is passed in, use the process id
   * of the parent.
   */
  pid_t pid = PROCESS_PID(0);
  int wait_status = -1;
  pid_t wait_tid = 0;
  bool stopped = false;
  int index;

  /* Reset the thread wait state */
  for (index = 0; index < _target.number_processes; index++) {
    PROCESS_WAIT(index) = false;
    PROCESS_WAIT_STATUS(index) = -1;
  }
  wait_tid = waitpid(pid, &wait_status, WNOHANG);
  /*
   * Waiting on the pid doesn't mean everyone is stopped
   * Look closer to make sure
   */
  stopped = fbsd_thread_state();
  if ((wait_tid == pid) && (-1 != wait_status) && stopped) {
    /* Not single stepping so the current thread isn't always going to be valid */
    if (t == -1) {
      t = ptrace_os_get_wait_tid(pid);
    }
    for (index = 0; index < _target.number_processes; index++) {
      if (PROCESS_STATE(index) != PS_EXIT) {
	PROCESS_STATE(index) = PS_STOP;
	/* Expecting everyone to stop or current tid*/
	if (t == PROCESS_TID(index)) {
	  PROCESS_WAIT(index) = true;
	  PROCESS_WAIT_STATUS(index) = wait_status;
	}
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
  }
}

void ptrace_os_continue_others() { /* Noop */ }

/*
 * FreeBSD continues all threads as a group
 * There is no control over individual threads.
 * So always use the pid.
 */
long ptrace_os_continue(pid_t pid, pid_t tid, int step, int sig) {
  long ret;
  long request = PT_CONTINUE;
  int index;
  DBG_PRINT("%s %x %x %d %d\n", __func__, pid, tid, step, sig);
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
  DBG_PRINT("%s %x %x %d : %d\n", __func__, request, pid, sig, ret);
  return ret;
}

int ptrace_os_gen_thread(pid_t pid, pid_t tid) {
  int ret = RET_ERR;
  int index;
  /*
   * Double check on the thread state to avoid running an
   * exited thread
   */
  fbsd_update_thread_state();
  if ((pid < 0) || (tid < 0))
    goto end;
  index = target_index(tid);
  if (index < 0) {
    /* Not a valid thread */
  } else if (!target_is_alive_thread(tid)) {
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
        util_usleep(1000);
        wait_ret = ptrace_wait(str, 0, true);
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
          target_thread_make_current(tid);
        } else if (wait_ret == RET_IGNORE) {
          int g = ptrace_arch_signal_to_gdb(SIGINT);
          ptrace_resume_from_current(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID,
                                     0, g);
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
    target_thread_make_current(tid);
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
void ptrace_os_stopped_single(char *str, bool debug) {
  int index = _target.current_process;
  pid_t tid = CURRENT_PROCESS_TID;
  int wait_status = PROCESS_WAIT_STATUS(index);
  if (WIFSTOPPED(wait_status)) {
    int s = WSTOPSIG(wait_status);
    int g = ptrace_arch_signal_to_gdb(s);
    if (s == SIGTRAP) {
      unsigned long pc = 0;
      unsigned long watch_addr = 0;
      ptrace_arch_get_pc(tid, &pc);
      if (ptrace_arch_hit_hardware_breakpoint(tid, pc)) {
	gdb_stop_string(str, g, tid, 0, LLDB_STOP_REASON_BREAKPOINT);
	CURRENT_PROCESS_STOP = LLDB_STOP_REASON_BREAKPOINT;
	/*
	 * process stat points to the true thread to continue
	 * Not that it matter on FreeBSD as they all go at once
	 */
	PROCESS_STATE(index) = PS_CONT;
      } else if (ptrace_arch_hit_watchpoint(tid, &watch_addr)) {
	/* A watchpoint was hit */
	gdb_stop_string(str, g, tid, watch_addr, LLDB_STOP_REASON_WATCHPOINT);
	CURRENT_PROCESS_STOP = LLDB_STOP_REASON_WATCHPOINT;
	/*
	 * process stat points to the true thread to continue
	 * Not that it matters on FreeBSD as they all go at once
	 */
	PROCESS_STATE(index) = PS_CONT;
      } else {
	int reason;
	/*
	 * Map all tid's to the current tid
	 *
	 * Either a normal breakpoint or a step, it doesn't matter
	 */
	if (_target.step) {
	  /* stepping can run over a normal breakpoint so precidence is for
	   * stepping */
	  reason = LLDB_STOP_REASON_TRACE;
	} else {
	  /*
	   * XXX A real trap and a breakpoint could be at the same location
	   *
	   * lldb checks if the pc matches what was used to set the
	   *breakpoint.
	   * At this point the pc can advanced (at least on x86).
	   * If the pc and the breakpoint don't match, lldb puts itself in a
	   *bad
	   * state.  So check if we are on lldb and roll back the pc one sw
	   *break's
	   * worth.
	   *
	   * On freebsd arm, the pc isn't advanced so use the arch dependent
	   *function
	   * ptrace_arch_swbreak_rollback
	   */
	  if (_target.lldb)
	    ptrace_arch_set_pc(tid, pc - ptrace_arch_swbrk_rollback());
	  reason = LLDB_STOP_REASON_BREAKPOINT;
	}
	gdb_stop_string(str, g, tid, 0, reason);
	CURRENT_PROCESS_STOP = reason;
	/*
	 * process stat points to the true thread to continue
	 * Not that it matter on FreeBSD as they all go at once
	 */
	PROCESS_STATE(index) = PS_CONT;
      }
    } else {
      /* A non trap signal, report the true thread */
      gdb_stop_string(str, g, tid, 0, LLDB_STOP_REASON_SIGNAL);
      CURRENT_PROCESS_STOP = LLDB_STOP_REASON_SIGNAL;
    }
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
  pid_t pid = CURRENT_PROCESS_PID;
  struct kinfo_vmentry *ptr;
  int cntp = 0;
  ptr = kinfo_getvmmap(pid, &cntp);
  if (ptr) {
    int i;
    for (i = 0; i < cntp; i++) {
      if ((addr >= ptr[i].kve_start) && (addr < ptr[i].kve_end)) {
        if (ptr[i].kve_protection &
            (KVME_PROT_READ | KVME_PROT_WRITE | KVME_PROT_EXEC)) {
          uint8_t p = 0;
          char perm_strs[8][4] = {"", "r", "w", "rw", "x", "rx", "wx", "rwx"};
          if (ptr[i].kve_protection & KVME_PROT_READ)
            p |= 1;
          if (ptr[i].kve_protection & KVME_PROT_WRITE)
            p |= 2;
          if (ptr[i].kve_protection & KVME_PROT_EXEC)
            p |= 4;
          snprintf(out_buff, out_buff_size,
                   "start:%" PRIx64 ";size:%" PRIx64 ";permissions:%s;",
                   ptr[i].kve_start, ptr[i].kve_end - ptr[i].kve_start,
                   &perm_strs[p][0]);
          ret = true;
        }
        break;
      }
    }
    free(ptr);
  }
  return ret;
}

bool ptrace_os_read_auxv(char *out_buf, size_t out_buf_size, size_t offset,
                         size_t *size) {
  bool ret = false;
  /*
   * An offset != 0 doesn't fit how auxv is retrieved in FreeBSD
   * So bail..
   * XXX also assume it will all fit in the return buffer
   */
  if (offset == 0) {
    struct procstat *prstat;
    /* See FreeBSD usr.bin/procstat/ */
    prstat = procstat_open_sysctl();
    if (prstat != NULL) {
      pid_t pid = CURRENT_PROCESS_PID;
      struct kinfo_proc *kp;
      unsigned int cntp = 0;
      kp = procstat_getprocs(prstat, KERN_PROC_PID, pid, &cntp);
      if (kp != NULL) {
        /* Assume 1 */
        Elf_Auxinfo *auxv;
        cntp = 0; /* reset */
        auxv = procstat_getauxv(prstat, kp, &cntp);
        if (auxv != NULL && cntp > 0) {
          size_t space_left = *size;
          size_t el_size = sizeof(Elf_Auxinfo);
          /* Need to know at least 1 will fit */
          if (space_left > el_size) {
            unsigned int i;
            /*
             * The > takes care of the prefix 'l'
             * Because we can not tolerate an offset, there will be no 'm'
             */
            out_buf[0] = 'l';
            space_left--;
            for (i = 0; i < cntp; i++) {
              if (space_left >= el_size) {
                memcpy(&out_buf[i * el_size + 1], &auxv[i], el_size);
                space_left -= el_size;
              } else {
                break;
              }
            }
            /* Return what we filled */
            *size = *size - space_left;
            ret = true;
          }
          procstat_freeauxv(prstat, auxv);
          auxv = NULL;
        }
        procstat_freeprocs(prstat, kp);
        kp = NULL;
      }
      procstat_close(prstat);
      prstat = NULL;
    }
  }
  return ret;
}

void memory_os_request_size(size_t *size)
{
    *size = sizeof(ptrace_return_t);
}

bool memory_os_read(pid_t tid, void *addr, void *val) {
    bool ret = false;
    ptrace_return_t *pt_val = (ptrace_return_t *) val;
    errno = 0;
    *pt_val = ptrace(PT_READ_D, tid, addr, 0);
    if (errno == 0)
	ret = true;
    return ret;
}

bool memory_os_write(pid_t tid, void *addr, void *val) {
    bool ret = false;
    ptrace_return_t *pt_val = (ptrace_return_t *) val;
    if (0 == ptrace(PT_WRITE_D, tid, addr, *pt_val))
	ret = true;
    return ret;
}

int elf_os_image(pid_t pid) {
  int ret = -1;
  char filepath[MAXPATHLEN];
  size_t filepathlen = MAXPATHLEN;
  int name[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, pid };

  if (sysctl(name, 4, filepath, &filepathlen, NULL, 0) == 0) {
    ret = open(filepath, O_RDONLY);
  }
  return ret;
}

pid_t ptrace_os_get_wait_tid(pid_t pid) {
  pid_t ret = -1;
#ifdef PT_LWPINFO
    int status;
    struct ptrace_lwpinfo lwpinfo = {0};
    status = PTRACE(PT_LWPINFO, pid, &lwpinfo, sizeof(lwpinfo));
    if (0 == status) {
	ret = lwpinfo.pl_lwpid;
    }
#endif
    return ret;
}
