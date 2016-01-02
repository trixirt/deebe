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

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "global.h"
#include "version.h"

static void print_usage() {
  fprintf(stdout, "Usage : for deebe\n");
  fprintf(stdout,
          "deebe [OPTIONS] <netork IP>:<PORT> debug_program arg1 arg2 etc..\n");
  fprintf(stdout, "deebe [OPTIONS] <netork IP>:<PORT> --attach <PID>\n");
  fprintf(
      stdout,
      "deebe [OPTIONS] <netork IP>:<PORT> --forward <netork IP>:<PORT>\n\n");
  fprintf(stdout, "Options:\n");
  fprintf(stdout, "  --version             : Print application version\n");
  fprintf(stdout, "  --copyright           : Print application copyright\n");
  fprintf(stdout, "  --license             : Print application license\n");
  fprintf(stdout, "  --once                : Accept only one connection, exit "
                  "when done\n\n");
  fprintf(stdout, "  --watchdog <minutes>  : Exit program with no activity "
                  "within <minutes> time limit\n\n");
  fprintf(stdout, "Notes:\n");
  fprintf(stdout, "<network IP> is optional, if not supplied \'localhost\' "
                  "will be used\n\n");
  fprintf(stdout, "Examples\n\n");
  fprintf(stdout, "Starting and debugging a program\n");
  fprintf(stdout, "  program               : /usr/bin/true\n");
  fprintf(stdout, "  network               : localhost\n");
  fprintf(stdout, "  port                  : 2345\n\n");
  fprintf(stdout, "deebe :2345 /usr/bin/true\n\n");
  fprintf(stdout, "Attaching to a running process and debugging\n");
  fprintf(stdout, "  process id            : 54321\n");
  fprintf(stdout, "  network               : 10.12.34.5\n");
  fprintf(stdout, "  port                  : 2345\n\n");
  fprintf(stdout, "deebe 10.12.34.5:2345 --attach 54321\n\n");
  fprintf(stdout, "Forwarding to another deebe\n");
  fprintf(stdout, "  local network         : 10.12.34.5\n");
  fprintf(stdout, "  local port            : 2345\n\n");
  fprintf(stdout, "  forward to network    : 10.12.34.21\n");
  fprintf(stdout, "  forward to port       : 3456\n\n");
  fprintf(stdout, "deebe 10.12.34.5:2345 --forward 10.12.34.21:3456\n\n");
}

extern void cmdline_cleanup() {
  if (cmdline_net != NULL)
    free(cmdline_net);

  cmdline_net = NULL;
  cmdline_port = -1;
  if (cmdline_net_fwd != NULL)
    free(cmdline_net_fwd);

  cmdline_net_fwd = NULL;
  cmdline_port_fwd = -1;
  cmdline_pid = 0;
  if (cmdline_program_name != NULL)
    free(cmdline_program_name);

  cmdline_program_name = NULL;

  if ((cmdline_argc > 0) && (cmdline_argv != NULL)) {
    int a;
    for (a = 0; a < cmdline_argc; a++) {
      if (cmdline_argv[a] != NULL) {
        free(cmdline_argv[a]);
        cmdline_argv[a] = NULL;
      }
    }
    free(cmdline_argv);
  }
  cmdline_argv = NULL;
  cmdline_argc = 0;
}

static bool _set_network_port(char *arg, char **network, long *port) {
  bool ret = false;

  *network = NULL;
  *port = 0;

  char *p;
  /* Try to split net:port */
  p = strchr(arg, ':');
  if (p) {
    /* check for only ':' */
    if (p != arg) {
      *p = '\0';
      /* Try to continue even if this fails */
      *network = strdup(arg);
    }
    /* advance past ':' */
    p++;
  } else {
    p = arg;
  }

  if (NULL != p) {
    if (strlen(p) > 0) {
      char *e = NULL;
      *port = strtol(p, &e, 10);
      /* Check for a trailing problem */
      if (*port && e < p + strlen(p))
        *port = 0;

      if (*port != 0)
        ret = true;
    }
  }
  return ret;
}

static bool _has_parameter(char *arg, char *op) {
  bool ret = false;

  char str[128];
  /* Look for --attach pid */
  if (0 < snprintf(str, sizeof(str) - 1, "%s", op)) {
    if (0 == strncmp(arg, str, strlen(str)))
      ret = true;
  } else {
    /* Error with snprintf function */
    fprintf(stderr, "INTERNAL ERROR\n");
  }
  return ret;
}

extern bool cmdline_init(int argc, char *argv[]) {
  bool ret = true;
  int option_args = 0;
  int argo = 1;

  /* In case init is called multiple times.. */
  cmdline_cleanup();

  if (argc > 0)
    cmdline_program_name = strdup(argv[0]);

  for (argo = 1; argo < argc; argo++) {
    bool option_found = false;

    if (_has_parameter(argv[argo], "--version")) {
      fprintf(stdout, "%s\n", version());
      cmdline_msg = true;
      goto end;
    }

    if (_has_parameter(argv[argo], "--copyright")) {
      fprintf(stdout, "%s\n", version_copyright());
      cmdline_msg = true;
      goto end;
    }

    if (_has_parameter(argv[argo], "--license")) {
      fprintf(stdout, "%s\n", version_license());
      cmdline_msg = true;
      goto end;
    }

    if (_has_parameter(argv[argo], "--once")) {
      cmdline_once = true;
      option_found = true;
    }

    if (_has_parameter(argv[argo], "--silence-mre")) {
      cmdline_silence_memory_read_errors = true;
      option_found = true;
    }

    if (_has_parameter(argv[argo], "--watchdog")) {
      argo++;
      if (argo < argc) {
        char *m = argv[argo];
        char *e = NULL;
        long try_minutes = 0;
        try_minutes = strtol(m, &e, 10);
        /* Check for a trailing problem */
        if (try_minutes > 0) {
          /* trailing problem */
          if (e != m + strlen(m)) {
            fprintf(stderr, "Warning : Expecting a positive number for the "
                            "watchdog parameter instead of %s\n",
                    m);
            fprintf(stderr, "          Please review usage\n");
            try_minutes = 0;
          }
        } else {
          fprintf(stderr, "Warning : Expecting positive number for watchdog "
                          "parameter instead of %s\n",
                  m);
          fprintf(stderr, "          Please review usage\n");
          try_minutes = 0;
        }
        if (try_minutes > 0)
          cmdline_watchdog_minutes = try_minutes;
      }
      option_found = true;
    }

    if (!option_found)
      break;
  }
  option_args = argo - 1;

  if (argc >= option_args + 3) {

    if (_set_network_port(argv[option_args + 1], &cmdline_net, &cmdline_port)) {

      if (_has_parameter(argv[option_args + 2], "--forward")) {

        if (argc == option_args + 4) {
          /* Success */
          if (!_set_network_port(argv[option_args + 3], &cmdline_net_fwd,
                                 &cmdline_port_fwd)) {
            /* Error */
            fprintf(stderr, "Error : Unexpected --forward parameter\n");
            fprintf(stderr, "        Please review usage\n");
            print_usage();
          }
        } else {
          /* Failure */
          fprintf(stderr, "Error : Unexpected --forward parameter\n");
          fprintf(stderr, "        Please review usage\n");
          print_usage();
        }

      } else if (_has_parameter(argv[option_args + 2], "--attach")) {
        if (argc == option_args + 4) {
          /* Success */
          cmdline_pid = strtol(argv[option_args + 3], NULL, 10);
          if (0 >= cmdline_pid) {
            /* Error */
            fprintf(stderr, "Error : Unexpected --attach parameter\n");
            fprintf(stderr, "        Please review usage\n");
            print_usage();
          }
        } else {
          /* Failure */
          fprintf(stderr, "Error : Unexpected --attach parameter\n");
          fprintf(stderr, "        Please review usage\n");
          print_usage();
        }
      } else {

        cmdline_argc = argc - 2 - option_args;
        /*
         * Add 1 so array can be null terminated and
         * passed directly to execv
         */
        cmdline_argv = (char **)malloc((cmdline_argc + 1) * sizeof(char *));
        if (cmdline_argv) {
          int a;
          for (a = 0; a < cmdline_argc; a++) {
            cmdline_argv[a] = strdup(argv[a + 2 + option_args]);
            if (cmdline_argv[a] == NULL) {
              ret = false;
              fprintf(stderr, "Error : copying command line parameters\n");
            }
          }
          /* NULL terminate the last entry */
          cmdline_argv[cmdline_argc] = NULL;
        } else {
          ret = false;
          fprintf(stderr, "Error : allocating command line parameters\n");
        }
      }

    } else {
      ret = false;
      fprintf(stderr, "Error : Setting network parameters\n");
      fprintf(stderr, "        Please review usage\n");
      print_usage();
    }
  } else {
    ret = false;
    fprintf(stderr, "Error : Unexpected command line arguements\n");
    fprintf(stderr, "        Please review usage\n");
    print_usage();
  }
end:
  return ret;
}
