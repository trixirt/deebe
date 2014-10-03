/*
 * Copyright (c) 2012-2013, Juniper Networks, Inc.
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
#include <stdbool.h>
#include "dsignal.h"

#ifdef HAVE_TIMER_CREATE
static timer_t timer;
#endif
static bool watchdog = false;

void watchdog_cleanup()
{
	signal_sigrtmin_off();
}
bool watchdog_init(long sec)
{
	bool ret = false;
#ifdef HAVE_TIMER_CREATE
	struct sigevent signal_event;
	signal_sigrtmin_off();

	signal_event.sigev_notify = SIGEV_SIGNAL;
	signal_event.sigev_signo = SIGRTMIN;
	signal_event.sigev_value.sival_ptr = &timer;
	if (0 == timer_create(CLOCK_MONOTONIC, &signal_event, &timer)) {
		struct itimerspec time;

		time.it_value.tv_sec = sec;
		time.it_value.tv_nsec = 0;
		time.it_interval.tv_sec = time.it_value.tv_sec;
		time.it_interval.tv_nsec = time.it_value.tv_nsec;

		if (0 == timer_settime(timer, 0, &time, NULL)) {
			signal_sigrtmin_on();
			ret = true;
		}
	}
#endif
	return ret;
}
bool watchdog_get()
{
	return watchdog;
}

void watchdog_set()
{
	watchdog = true;
}

void watchdog_clear()
{
	watchdog = false;
}
