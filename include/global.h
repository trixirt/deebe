/*
 * Copyright (c) 2012-2013, Juniper Networks, Inc.
 * All rights reserved.
 *
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

#ifndef _GLOBAL_H
#define _GLOBAL_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "gdb_interface.h"
#include "version.h"
#include "util.h"

/* FreeBSD's assert throws warnings, rewrite here */
#define	ASSERT(e)	((e) ? (void)0 : \
fprintf(stderr, "Assertion failed at %s %s %d : %s\n",\
	__func__, __FILE__, __LINE__, #e))

#define WATCHDOG_ERROR()                                                     \
	do {                                                                 \
		fprintf(stderr, "Watchdog time expired, program exiting\n"); \
		exit(-1);						     \
	} while (0)

/* In developement.. */
#define DEEBE_RELEASE__
#ifdef DEEBE_RELEASE
#define DBG_PRINT(fmt, args...)
#else
#define DBG_PRINT(fmt, args...) util_log(fmt, ##args)
#endif

extern int host_signal_to_gdb(int sig);
extern int host_signal_from_gdb(int gdb);

#ifndef DECL_GLOBAL

/* cmdline */
extern char *cmdline_net;
extern char *cmdline_net_fwd;
extern long cmdline_port;
extern long cmdline_port_fwd;
extern int cmdline_argc;
extern char **cmdline_argv;
extern pid_t cmdline_pid;
extern char *cmdline_program_name;
extern bool cmdline_once;
extern long cmdline_watchdog_minutes;
extern bool cmdline_silence_memory_read_errors;

/* network */
extern int network_listen_sd;
extern int network_client_sd;
extern int network_fwd_sd;
extern struct sockaddr_in network_address;
extern struct sockaddr_in network_address_fwd;
extern struct sockaddr_in network_client_address;
extern socklen_t network_client_address_size;
extern unsigned char network_out_buffer[];
extern unsigned char network_in_buffer[];
extern size_t network_out_buffer_size;
extern size_t network_out_buffer_current;
extern size_t network_out_buffer_total;
extern size_t network_in_buffer_size;
extern size_t network_in_buffer_current;
extern size_t network_in_buffer_total;
/* gdb interface */
extern gdb_target *gdb_interface_target;
extern int gdb_interface_debug_level;
extern log_func gdb_interface_log;
extern FILE *fp_log;
extern bool gDebugeeRunning;
extern int gPipeStdout[2];

#else

/* cmdline */
/*@null@*/char *cmdline_net = NULL;
/*@null@*/char *cmdline_net_fwd = NULL;
long cmdline_port = -1;
long cmdline_port_fwd = -1;
int cmdline_argc = 0;
/*@null@*/char **cmdline_argv = NULL;
pid_t cmdline_pid = 0;
/*@null@*/char *cmdline_program_name = NULL;
bool cmdline_once = false;
long cmdline_watchdog_minutes = -1;
bool cmdline_silence_memory_read_errors = false;

/* network */
int network_listen_sd = -1;
int network_client_sd = -1;
int network_fwd_sd = -1;
struct sockaddr_in network_address = { 0 };
struct sockaddr_in network_client_address = { 0 };
struct sockaddr_in network_address_fwd = { 0 };
socklen_t network_client_address_size = sizeof(struct sockaddr_in);
uint8_t network_out_buffer[RP_PARAM_INOUTBUF_SIZE];
uint8_t network_in_buffer[RP_PARAM_INOUTBUF_SIZE];
size_t network_out_buffer_size = RP_PARAM_INOUTBUF_SIZE;
size_t network_out_buffer_current = 0;
size_t network_out_buffer_total = 0;
size_t network_in_buffer_size = RP_PARAM_INOUTBUF_SIZE;
size_t network_in_buffer_current = 0;
size_t network_in_buffer_total = 0;
/* gdb interface */
/*@null@*/gdb_target *gdb_interface_target = NULL;
int gdb_interface_debug_level = -1;
/*@null@*/log_func gdb_interface_log = NULL;

FILE *fp_log = NULL;

bool gDebugeeRunning = true;

int gPipeStdout[2] = { -1, -1, };

#endif /* DECL_GLOBAL */
#endif /* _GLOBAL_H */
