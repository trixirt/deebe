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
#include <unistd.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "global.h"
#include "dptrace.h"
#include "breakpoint.h"
#include "memory.h"
#include "../os/linux.h"

void ptrace_os_read_fxreg(pid_t tid) {
#ifdef PT_GETFPXREGS
  if (NULL != _target.fxreg) {
    _read_reg(tid, PT_GETFPXREGS, PT_SETFPXREGS, &_target.fxreg,
              &_target.fxreg_rw, &_target.fxreg_size);
  }
#endif
}

void ptrace_os_write_fxreg(pid_t tid) {
#ifdef PT_GETFPXREGS
  if (NULL != _target.fxreg) {
    _write_reg(tid, PT_SETFPXREGS, _target.fxreg);
  }
#endif
}

void ptrace_os_option_set_syscall(pid_t pid) {
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

bool ptrace_os_check_syscall(pid_t pid, int *in_out_sig) {
  bool ret = false;
  if (*in_out_sig == (SIGTRAP | 0x80)) {
    *in_out_sig = SIGTRAP;
    ret = true;
  }
  return ret;
}

void ptrace_os_option_set_thread(pid_t pid) {
#ifdef PTRACE_O_TRACECLONE
  if (0 != ptrace(PTRACE_SETOPTIONS, CURRENT_PROCESS_TID, NULL,
                  PTRACE_O_TRACECLONE)) {
    DBG_PRINT("error setting PTRACE_O_TRACECLONE\n");
  }
#endif
}

bool ptrace_os_wait_new_thread(pid_t *out_pid, int *out_status) {
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
        util_usleep(1000);
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
            DBG_PRINT("%s try %d %x vs %x status %d\n", __func__, errs, tid2,
                      tid, thread_status);
          }
        }
      }

      if (errs < errs_max) {
        if (WIFSTOPPED(thread_status) && (WSTOPSIG(thread_status) == SIGSTOP)) {
          if (target_new_thread(CURRENT_PROCESS_PID, tid, 0,
                                /* thread_status,*/ true, SIGSTOP)) {
            if (out_pid)
              *out_pid = tid;
            ret = true;

            DBG_PRINT("%s good.. %x\n", __func__, tid);

          } else {
            DBG_PRINT("%s error allocating new thread\n", __func__);
          }
        } else {
          DBG_PRINT("%s error with expected thread wait status %x\n", __func__,
                    thread_status);
        }
      } else {
        DBG_PRINT("%s error waiting for child thread : Error is %s\n", __func__,
                  strerror(errno));
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

bool ptrace_os_check_new_thread(pid_t pid, int status, pid_t *out_pid) {
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
					util_usleep(1000);
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
					  if (target_new_thread(CURRENT_PROCESS_PID, new_tid, 0, /* thread_status,*/ true, SIGSTOP)) {
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

int os_thread_kill(int tid, int sig) { return 1; }

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
    } else {
      if (!target_new_thread(PROCESS_PID(0), tid, status, true, SIGSTOP)) {
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
      } else {
        if (!target_new_thread(PROCESS_PID(0), tid, status, true, SIGSTOP)) {
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

void ptrace_os_continue_others() {
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
        if (PRS_CONT == PROCESS_STATE(index)) {
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

int ptrace_os_gen_thread(pid_t pid, pid_t tid) {
  int ret = RET_ERR;
  int index;
  if ((pid < 0) || (tid < 0))
    goto end;

  index = target_index(tid);

  DBG_PRINT("%s index %d\n", __func__, index);

  if (index < 0) {
    /* Not a valid thread */
  } else if (!target_is_alive_thread(tid)) {
    /* dead thread */
    DBG_PRINT("%s dead %d\n", __func__, index);
  } else if (_target.current_process == index) {
    /* The trival case */
    DBG_PRINT("%s trivial %d\n", __func__, index);
    ret = RET_OK;
  } else if (PROCESS_WAIT(index)) {
    /* We got lucky, the process is already in a wait state */
    target_thread_make_current(tid);

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
    PROCESS_STATE(index) = PRS_INTERNAL_SIG_PENDING;

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
  }
end:
  return ret;
}

void ptrace_os_stopped_single(char *str, bool debug) {
  int index;
  for (index = 0; index < _target.number_processes; index++) {
    bool process_wait = PROCESS_WAIT(index);
    if (process_wait) {
      DBG_PRINT("%s stopped %x looking for %x\n", __func__, index,
                _target.current_process);
    }
  }

  if (CURRENT_PROCESS_WAIT) {

    pid_t tid = CURRENT_PROCESS_TID;
    int wait_status = CURRENT_PROCESS_WAIT_STATUS;

    if (WIFSTOPPED(wait_status)) {
      unsigned long pc = 0;
      int s = WSTOPSIG(wait_status);
      int g = ptrace_arch_signal_to_gdb(s);
      ptrace_arch_get_pc(tid, &pc);

      if (debug) {
        DBG_PRINT("stopped at pc 0x%lx\n", pc);
        if (pc) {
          uint8_t b[32] = {0};
          size_t read_size = 0;
          memory_read_gdb(tid, pc, &b[0], 32, &read_size);
          util_print_buffer(fp_log, 0, 32, &b[0]);
        }
      }
      if (s == SIGTRAP) {
        unsigned long watch_addr = 0;
        /* Fill out the status string */
        if (ptrace_arch_hit_hardware_breakpoint(tid, pc)) {
          gdb_stop_string(str, g, tid, 0, LLDB_STOP_REASON_BREAKPOINT);
          CURRENT_PROCESS_STOP = LLDB_STOP_REASON_BREAKPOINT;
        } else if (ptrace_arch_hit_watchpoint(tid, &watch_addr)) {
          /* A watchpoint was hit */
          gdb_stop_string(str, g, tid, watch_addr, LLDB_STOP_REASON_WATCHPOINT);
          CURRENT_PROCESS_STOP = LLDB_STOP_REASON_WATCHPOINT;
        } else {
          int reason;
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
        }

      } else {
        /* A non trap signal */
        gdb_stop_string(str, g, tid, 0, LLDB_STOP_REASON_SIGNAL);
        CURRENT_PROCESS_STOP = LLDB_STOP_REASON_SIGNAL;
      }
    }
  }
}

long ptrace_linux_getset(long request, pid_t pid, void *addr, void *data) {
  long ret = -1;
  /* The old way.. */
  if (request > 0) {
    ret = PTRACE(request, pid, addr, data);
  } else {
    struct iovec vec;
    vec.iov_base = data;
    vec.iov_len = REG_MAX_SIZE;
    if (request == PTRACE_GETREGS) {
      ret = PTRACE(PTRACE_GETREGSET, pid, NT_PRSTATUS, &vec);
    } else if (request == PTRACE_GETFPREGS) {
      ret = PTRACE(PTRACE_GETREGSET, pid, NT_PRFPREG, &vec);
    } else if (request == PTRACE_SETREGS) {
      ret = PTRACE(PTRACE_SETREGSET, pid, NT_PRSTATUS, &vec);
    } else if (request == PTRACE_SETFPREGS) {
      ret = PTRACE(PTRACE_SETREGSET, pid, NT_PRFPREG, &vec);
    }
  }
  return ret;
}

/*
 * Tested on linux versions
 * 3.11.0
 *
 * For lldb, output is
 * start:<mem start>;size:<siz>;permissions:rx;
 *
 * Only trick bit is the permissions field, its a permutation of rwx
 * Assuming if there is no permissions, then shouldn't report the region.
 */
bool memory_os_region_info_gdb(uint64_t addr, char *out_buff,
			       size_t out_buff_size) {
  bool ret = false;
  FILE *fp = NULL;
  pid_t pid = CURRENT_PROCESS_PID;
  char n[256];
  snprintf(n, 256, "/proc/%u/maps", pid);
  fp = fopen(n, "rt");
  if (fp) {
    char l[1024], perms[64];
    while (fgets(l, 1024, fp) != NULL) {
      memset(&perms[0], 0, 64);
      uint64_t rs, re;
      int status;
      if (sizeof(void *) == 8) {
        status =
            sscanf(l, "%016" PRIx64 "-%016" PRIx64 " %s ", &rs, &re, &perms[0]);
      } else {
        uint32_t s, e;
        status =
            sscanf(l, "%08" PRIx32 "-%08" PRIx32 " %s ", &s, &e, &perms[0]);
        rs = s;
        re = e;
      }
      /* 3 items found.. */
      if (status == 3) {
        if ((addr >= rs) && (addr < re)) {
          uint8_t p = 0;
          char perm_strs[8][4] = {"", "r", "w", "rw", "x", "rx", "wx", "rwx"};
          if (strchr(&perms[0], 'r'))
            p |= 1;
          if (strchr(&perms[0], 'w'))
            p |= 2;
          if (strchr(&perms[0], 'x'))
            p |= 4;
          if (p > 0 && p < 8) {
            snprintf(out_buff, out_buff_size,
                     "start:%" PRIx64 ";size:%" PRIx64 ";permissions:%s;", rs,
                     re - rs, &perm_strs[p][0]);
            ret = true;
          }
          break;
        }
      }
    }
    fclose(fp);
  }
  return ret;
}

bool ptrace_os_read_auxv(char *out_buf, size_t out_buf_size, size_t offset,
                         size_t *size) {
  bool ret = false;
  FILE *fp = NULL;
  pid_t pid = CURRENT_PROCESS_PID;
  char n[256];
  snprintf(n, 256, "/proc/%u/auxv", pid);
  fp = fopen(n, "rt");
  if (fp) {
    if (*size < out_buf_size) {
      if (0 == fseek(fp, offset, SEEK_SET)) {
        size_t total_read;
        total_read = fread(&out_buf[1], 1, *size - 1, fp);
        if (total_read != *size) {
          if (1 == feof(fp)) {
            out_buf[0] = 'l';
            *size = total_read + 1;
            ret = true;
          }
        } else {
          out_buf[0] = 'm';
          ret = true;
        }
      }
    }
    fclose(fp);
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
  int ret;
  char n[256];
  snprintf(n, 256, "/proc/%u/exe", pid);
  ret = open(n, O_RDONLY);
  return ret;
}

pid_t ptrace_os_get_wait_tid(pid_t pid) {
    pid_t ret = -1;
#ifdef PTRACE_GETEVENTMSG
    int status;
    unsigned long new_tid = 0;
    status = ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_tid);
    if (0 == status) {
	ret = new_tid;
    }
#endif
    return ret;
}

int ptrace_os_get_tls_address(int64_t thread,  uint64_t lm, uint64_t offset,
			      uintptr_t *tlsaddr)
{
  return RET_NOSUPP;
}
