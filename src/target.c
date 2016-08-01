/*
 * Copyright (c) 2013-2016 Juniper Networks, Inc.
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
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>

#include "target.h"
#include "global.h"

target_state _target = {
    .lldb = false, /* we run assuming gdb until we know otherwise */
    .list_threads_in_stop_reply =
        false,   /* this is a lldb feature, only do this if asked for */
    .ack = true, /* ack until it is ok not to */
                 /*
                  * Older gdb's do not know the difference between
                  * AllStop and NonStop mode for threading.
                  * Since AllStop is the oldest mode, default to that.
                  */
    .nonstop = NS_ON,
    .multiprocess = 0, /* default to supporting multiple processes */
    .xml_register_reporting = false, /* default to old style reporting */
    .step = false,                   /* no single stepping here.. */
    .syscall_enter = false,
    .flag_attached_existing_process = 0,
    .reg_size = 0,
    .freg_size = 0,
    .fxreg_size = 0,
    .dbreg_size = 0,
    .reg_rw = NULL,   /* TODO : FREE THIS */
    .freg_rw = NULL,  /* TODO : FREE THIS */
    .fxreg_rw = NULL, /* TODO : FREE THIS */
    .dbreg_rw = NULL, /* TODO : FREE THIS */
    .number_processes = 0,
    .current_process = 0,
    .process = NULL, /* TODO : FREE THIS */
#ifdef HAVE_THREAD_DB_H
    .ph.pid = 0,
    .ph.target = NULL,
    .thread_agent = NULL,
#endif
};

bool target_new_thread(pid_t pid, pid_t tid, int wait_status, bool waiting,
                       int sig) {
  bool ret = false;
  int index = 0;

  /*
   * Try to reused an exited process's space
   */
  for (index = 0; index < _target.number_processes; index++) {
    if (PROCESS_STATE(index) == PRS_EXIT)
      break;
  }

  /* No space, tack one onto the end */
  if (index >= _target.number_processes) {
    void *try_process = NULL;

    /* Allocate registers for the process */
    try_process =
        realloc(_target.process, (_target.number_processes + 1) *
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
  PROCESS_STATE(index) = PRS_START;
  PROCESS_WAIT_STATUS(index) = wait_status;
  PROCESS_WAIT(index) = waiting;
  PROCESS_SIG(index) = sig;
  PROCESS_STOP(index) = LLDB_STOP_REASON_SIGNAL;
  ret = true;

end:

  DBG_PRINT("%s pid %x tid %x index %d return %d\n", __func__, pid, tid, index,
            ret);
  return ret;
}

int target_number_threads() {
  int ret = 0;
  int index;

  for (index = 0; index < _target.number_processes; index++) {
    if (PROCESS_STATE(index) != PRS_EXIT)
      ret++;
  }
  return ret;
}

pid_t target_get_pid() {
  pid_t ret = -1;
  ret = PROCESS_PID(0);

  return ret;
}

bool target_dead_thread(pid_t tid) {
  bool ret = false;
  int index;

  for (index = 0; index < _target.number_processes; index++) {
    if (tid == PROCESS_TID(index)) {
      PROCESS_STATE(index) = PRS_EXIT;
      ret = true;
      break;
    }
  }
  return ret;
}

void target_all_dead_thread(pid_t tid) {
  int index;
  for (index = 0; index < _target.number_processes; index++) {
    PROCESS_STATE(index) = PRS_EXIT;
  }
}

bool target_is_alive_thread(pid_t tid) {
  bool ret = false;
  int index;

  for (index = 0; index < _target.number_processes; index++) {
    if (tid == PROCESS_TID(index)) {
      if (PROCESS_STATE(index) != PRS_EXIT)
        ret = true;
      break;
    }
  }
  return ret;
}

bool target_is_alive_process(pid_t pid) {
  bool ret = false;
  int index;

  for (index = 0; index < _target.number_processes; index++) {
    if (pid == PROCESS_PID(index)) {
      if (PROCESS_STATE(index) != PRS_EXIT)
        ret = true;
      break;
    }
  }
  return ret;
}

bool target_is_tid(pid_t tid) {
  bool ret = false;
  int index;

  for (index = 0; index < _target.number_processes; index++) {
    if (tid == PROCESS_TID(index)) {
      ret = true;
      break;
    }
  }
  return ret;
}

bool target_is_pid(pid_t pid) {
  bool ret = false;
  int index;

  for (index = 0; index < _target.number_processes; index++) {
    if (pid == PROCESS_PID(index)) {
      ret = true;
      break;
    }
  }
  return ret;
}

int target_index(pid_t tid) {
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

bool target_thread_make_current(pid_t tid) {
  bool ret = false;
  int index = target_index(tid);
  if (index >= 0) {
    _target.current_process = index;
    ret = true;

    DBG_PRINT("%s %x %d\n", __func__, tid, index);

  } else {
    DBG_PRINT("%s ERROR Invalid tid %x\n", __func__, tid);
  }
  return ret;
}

void _target_debug_print() {
  int index;

  for (index = 0; index < _target.number_processes; index++) {
    DBG_PRINT("%d %x %x %d\n", index, PROCESS_PID(index), PROCESS_TID(index),
              PROCESS_STATE(index));
  }
}

int target_current_index() { return _target.current_process; }

void target_attached(bool flag) {
  if (flag)
    _target.flag_attached_existing_process = 1;
  else
    _target.flag_attached_existing_process = 0;
}
bool target_is_attached() {
  bool ret = false;
  if (_target.flag_attached_existing_process == 1)
    ret = true;
  return ret;
}

bool target_is_gdb_reg(int gdb, int *g_index, struct reg_location_list *rl) {
  bool ret = false;
  int c = 0;
  while (1) {
    if (GUARD_RLL(rl[c])) {
      break;
    } else if (rl[c].gdb == gdb) {
      *g_index = c;
      ret = true;
      break;
    } else {
      c++;
    }
  }
  return ret;
}

