/*
 * Copyright (c) 2013 Juniper Networks, Inc.
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

struct _tstate tstate = {
	.cpid = 0,
	.bpl  = NULL,
	.pil  = NULL,
};

target_state _target = {
	.no_ack = 0, /* ack until it is ok not to */
	.syscall_enter = false,
	.current_signal = SIGTRAP,
	.flag_attached_existing_process = 1,
	.ps = PS_START,
	.reg_size = 0,
	.regs.reg = NULL, /* TODO : FREE THIS */
	.regs.reg_rw = NULL, /* TODO : FREE THIS */
	.freg_size = 0,
	.regs.freg = NULL, /* TODO : FREE THIS */
	.regs.freg_rw = NULL, /* TODO : FREE THIS */
	.fxreg_size = 0,
	.regs.fxreg = NULL, /* TODO : FREE THIS */
	.regs.fxreg_rw = NULL, /* TODO : FREE THIS */
	.dbreg_size = 0,
	.regs.dbreg = NULL, /* TODO : FREE THIS */
	.regs.dbreg_rw = NULL, /* TODO : FREE THIS */
};
