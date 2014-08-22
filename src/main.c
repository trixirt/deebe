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


#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define DECL_GLOBAL
#include "global.h"
#undef DECL_GLOBAL

#include "cmdline.h"
#include "network.h"
#include "watchdog.h"

#define LOG_FILENAME "/tmp/deebe.log"

/* Defined in signal.c */
extern void (*signal_handle_sigio)(int sig);
extern void (*signal_handle_sigrtmin)(int sig);
extern void (*signal_handle_sigchld)(int sig);

static int _network_io(int (*r)(), int (*w)(), int (*pkt)())
{
	int ret = 0;
	int s;

	s = r();
	if (s > 0) {
		/* Error or disconnect */
		ret = 1;
	} else if (s == 0) {
		/*
		 * Normal case
		 * A packet has been received
		 */
	} else {
		/*
		 * Timeout
		 * Do nothing
		 */
	}
	if (!ret) {
		while (network_in_buffer_current < network_in_buffer_total) {
			/*
			 * Draining the network buffer,
			 * packets are being dropped
			 */
			if (pkt)
				pkt();

			s = w();
			if (s)
				fprintf(stderr, "error writing\n");
		}
	}
	return ret;
}

void main_sigchld(/*@unused@*/int sig)
{
}

void main_sigio(/*@unused@*/int sig)
{
	/*
	 * When switching from normal to quick
	 * drop the oustanding output packages
	 */
	network_clear_write();

	_network_io(network_quick_read, network_quick_write,
		    gdb_interface_quick_packet);
}

void main_sigrtmin(int sig)
{
	bool watch = watchdog_get();
	if (watch) {
		WATCHDOG_ERROR();
	} else {
		watchdog_set();
	}
}
static void _forward_packet(uint8_t *dst, uint8_t *src,
			    size_t *dst_size, size_t *src_size) {
	if (*src_size) {
		memcpy(dst, src, *src_size);
		*dst_size = *src_size;
		*src_size = 0;
	}
}

int main_forward()
{
	int ret = 1;

	/* reuse the normal network setup */
	if (network_init()) {
		/* Now accept from gdb */
		if (network_accept()) {
			/* Now connect to remote deebe */
			if (network_connect()) {
				while (true) {
					network_read();
					if (network_in_buffer_total > 0) {
						_forward_packet(&network_out_buffer[0],
								&network_in_buffer[0],
								&network_out_buffer_total,
								&network_in_buffer_total);

						network_write_fwd();
					}
					network_read_fwd();
					if (network_in_buffer_total > 0) {
						_forward_packet(&network_out_buffer[0],
								&network_in_buffer[0],
								&network_out_buffer_total,
								&network_in_buffer_total);

						network_write();
					}
				}
			}
		}
		network_cleanup();
	}

	return ret;
}

int main_debug()
{
	int ret = 1;
	bool debugee_ok = false;

	/* Sets up the gdb_interface_target */
	gdb_interface_init();

	if (gdb_interface_target == NULL) {
		fprintf(stderr, "INTERNAL ERROR : gdb interface uninitalized\n");
	} else {
		/* Check network setup */
		if (network_init()) {
			/* Basic network ok, now setup the cmdline debuggee */
			if (0 != cmdline_pid) {
				if (gdb_interface_target->attach) {
					if (RET_OK != gdb_interface_target->attach(cmdline_pid))
						fprintf(stderr, "Error attaching to pid %d\n", cmdline_pid);
					else
						debugee_ok = true;

				} else {
					fprintf(stderr, "Error : Attaching to a running process is not supported\n");
				}

			} else if (0 != cmdline_argc) {
				if (gdb_interface_target->open) {
					if (RET_OK != gdb_interface_target->open(cmdline_argc, cmdline_argv, cmdline_argv[0]))
						fprintf(stderr, "Error opening program %s to debug\n", cmdline_argv[0]);
					else
						debugee_ok = true;

				} else {
					fprintf(stderr, "Error : Starting a new process is not supported\n");
				}

			} else {
				fprintf(stderr, "Error : no valid program to debug\n");
			}
			if (debugee_ok) {
				/* Debuggee is ok, now accept connection */
				/* Success */
				fprintf(stdout, "Listening on port %ld\n", cmdline_port);
				fflush(stdout);

				if (network_accept()) {
				    do {
					if (_network_io(network_read, network_write,
							gdb_interface_packet)) {
					    break;
					}
				    } while (gDebugeeRunning);
				}
			}
			network_cleanup();
		}
	}

	gdb_interface_cleanup();

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = -1;

#ifndef DEEBE_RELEASE
	FILE *try_log = fopen(LOG_FILENAME, "wt");
	if (NULL != try_log)
		fp_log = try_log;
	else
		fp_log = stdout;

	try_log = NULL;
#else
	fp_log = stdout;
#endif

	/* Signal handlers */
	signal_handle_sigio = main_sigio;
	signal_handle_sigrtmin = main_sigrtmin;
	signal_handle_sigchld = main_sigchld;

	if (0 != cmdline_init(argc, argv)) {
		/* start the watchdog timer */
		if (cmdline_watchdog_minutes > 0) {
			/* watchdog is in seconds, for *= 60 */
			long seconds = 60 * cmdline_watchdog_minutes;
			if (!watchdog_init(seconds)) {
				/*
				 * Only report this error if timer_create
				 * is supported.  If it isn't then the watchdog
				 * functionality is simulated in the network
				 * code where read or connect delays are
				 * expected.
				 */
#ifdef HAVE_TIMER_CREATE
				fprintf(stderr, "Problem initializing watchdog timer for %ld seconds\n",
					seconds);
				/*
				 * watchdog_init does not turn on the
				 * the signal unless it is successful
				 * so we do not have to disable it
				 */
#endif
			}
		}

		if (cmdline_port_fwd > 0)
			ret = main_forward();
		else
			ret = main_debug();
	}
	cmdline_cleanup();

	if (fp_log) {
		if (fp_log != stdout) {
			fflush(fp_log);
			fclose(fp_log);
			fp_log = stdout;
		}
	}
	return ret;
}
