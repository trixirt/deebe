/*
 * Copyright (c) 2012-2015, Juniper Networks, Inc.
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
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include "util.h"
#include "macros.h"

static bool signal_verbose = false;

void (*signal_handle_sigio)(int sig) = NULL;
void (*signal_handle_sigrtmin)(int sig) = NULL;
void (*signal_handle_sigchld)(int sig) = NULL;

static void signal_sigio(int sig) {
  if (signal_handle_sigio)
    signal_handle_sigio(sig);
}

void signal_sigrtmin(int sig) {
  if (signal_handle_sigrtmin)
    signal_handle_sigrtmin(sig);
}

void signal_sigchld(int sig) {
  if (signal_handle_sigchld)
    signal_handle_sigchld(sig);
}

bool signal_sigio_setup(int fd) {
  bool ret = false;
  int flags;
  if (fcntl(fd, F_SETOWN, getpid()) < 0) {
    /* Failure */
    if (signal_verbose) {
      fprintf(stderr, "ERROR setting socket pid\n");
      perror("");
    }
  } else {
    /* Sucess */
    flags = fcntl(fd, F_GETFL);
    flags |= FASYNC;
    if (fcntl(fd, F_SETFL, flags) < 0) {
      /* Failure */
      fprintf(stderr, "ERROR setting socket to async\n");
      perror("");
    } else {
      /* Success */
      ret = true;
    }
  }
  return ret;
}

bool signal_sigio_on() {
  bool ret = false;
  if (SIG_ERR != signal(SIGIO, signal_sigio)) {
    /* Success */
    ret = true;
  } else {
    if (signal_verbose) {
      fprintf(stderr, "ERROR turning SIGIO on");
      perror("");
    }
  }
  return ret;
}

bool signal_sigio_off() {
  bool ret = false;
  if (SIG_ERR != signal(SIGIO, SIG_IGN)) {
    /* Success */
    ret = true;
  } else {
    if (signal_verbose) {
      fprintf(stderr, "ERROR turning SIGIO off");
      perror("");
    }
  }
  return ret;
}

bool signal_sigrtmin_on() {
  bool ret = false;
#ifdef SIGRTMIN
  if (SIG_ERR != signal(SIGRTMIN, signal_sigrtmin)) {
    /* Success */
    ret = true;
  } else {
    if (signal_verbose) {
      fprintf(stderr, "ERROR turning SIGRTMIN on");
      perror("");
    }
  }
#endif
  return ret;
}

bool signal_sigrtmin_off() {
  bool ret = false;
#ifdef SIGRTMIN
  if (SIG_ERR != signal(SIGRTMIN, SIG_IGN)) {
    /* Success */
    ret = true;
  } else {
    if (signal_verbose) {
      fprintf(stderr, "ERROR turning SIGRTMIN off");
      perror("");
    }
  }
#endif
  return ret;
}

void signal_query_mask() {
  sigset_t o_block, o_unblock, o_setmask;
  int max_s = 128;
  int i;
  if (0 == sigemptyset(&o_setmask)) {
    if (0 == sigprocmask(SIG_SETMASK, NULL, &o_setmask)) {
      bool found = false;
      for (i = 0; i < max_s; i++) {
        if (1 == sigismember(&o_setmask, i)) {
          found = true;
          if (signal_verbose)
            DBG_PRINT("SIG_SETMASK %d\n", i);
        }
      }
      if (false == found) {
        if (signal_verbose)
          DBG_PRINT("SIG_SETMASK - none\n");
      }
    } else {
      /* failure */
      if (signal_verbose)
        DBG_PRINT("Error with sigprocmask SIG_SETMASK\n");
    }
  } else {
    /* failure */
    if (signal_verbose)
      DBG_PRINT("Error with sigemptyset\n");
  }

  if (0 == sigemptyset(&o_block)) {
    if (0 == sigprocmask(SIG_BLOCK, NULL, &o_block)) {
      bool found = false;
      for (i = 0; i < max_s; i++) {
        if (1 == sigismember(&o_block, i)) {
          found = true;
          if (signal_verbose)
            DBG_PRINT("SIG_BLOCK %d\n", i);
        }
      }
      if (false == found) {
        if (signal_verbose)
          DBG_PRINT("SIG_BLOCK - none\n");
      }
    } else {
      /* failure */
      if (signal_verbose)
        DBG_PRINT("Error with sigprocmask SIG_BLOCK\n");
    }
  } else {
    /* failure */
    if (signal_verbose)
      DBG_PRINT("Error with sigemptyset\n");
  }

  if (0 == sigemptyset(&o_unblock)) {
    if (0 == sigprocmask(SIG_UNBLOCK, NULL, &o_unblock)) {
      bool found = false;
      for (i = 0; i < max_s; i++) {
        if (1 == sigismember(&o_unblock, i)) {
          found = true;
          if (signal_verbose)
            DBG_PRINT("SIG_UNBLOCK %d\n", i);
        }
      }
      if (false == found) {
        if (signal_verbose)
          DBG_PRINT("SIG_UNBLOCK - none\n");
      }
    } else {
      /* failure */
      if (signal_verbose)
        DBG_PRINT("Error with sigprocmask SIG_UNBLOCK\n");
    }
  } else {
    /* failure */
    if (signal_verbose)
      DBG_PRINT("Error with sigemptyset\n");
  }
}

bool signal_sigchld_on() {
  bool ret = false;
  if (SIG_ERR != signal(SIGCHLD, signal_sigchld)) {
    /* Success */
    ret = true;
  } else {
    if (signal_verbose) {
      fprintf(stderr, "ERROR turning SIGCHLD on");
      perror("");
    }
  }
  return ret;
}

bool signal_sigchld_off() {
  bool ret = false;
  if (SIG_ERR != signal(SIGCHLD, SIG_IGN)) {
    /* Success */
    ret = true;
  } else {
    if (signal_verbose) {
      fprintf(stderr, "ERROR turning SIGCHLD off");
      perror("");
    }
  }
  return ret;
}
