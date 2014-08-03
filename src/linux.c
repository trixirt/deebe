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
#include <unistd.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include "global.h"
#include "dptrace.h"

void ptrace_os_read_fxreg()
{
#ifdef PT_GETFPXREGS
	if (NULL != _target.fxreg) {
		_read_reg(PT_GETFPXREGS, PT_SETFPXREGS,
			  &_target.fxreg, &_target.fxreg_rw,
			  &_target.fxreg_size);
	}
#endif
}

void ptrace_os_write_fxreg()
{
#ifdef PT_GETFPXREGS
	if (NULL != _target.fxreg) {
		_write_reg(PT_SETFPXREGS, _target.fxreg);
	}
#endif
}

void ptrace_os_option_set_syscall(pid_t pid)
{
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

bool ptrace_os_check_syscall(pid_t pid, int *in_out_sig)
{
	bool ret = false;
	if (*in_out_sig == (SIGTRAP | 0x80)) {
		*in_out_sig = SIGTRAP;
		ret = true;
	}
	return ret;
}

void ptrace_os_option_set_thread(pid_t pid)
{
#ifdef PTRACE_O_TRACECLONE
    if (0 != ptrace(PTRACE_SETOPTIONS, CURRENT_PROCESS_TID, 
		    NULL, PTRACE_O_TRACECLONE)) {
	DBG_PRINT("error setting PTRACE_O_TRACECLONE\n");
    }
#endif
}
