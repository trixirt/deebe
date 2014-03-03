/*
 * Copyright (c) 2013, Juniper Networks, Inc.
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
#ifndef DEEBE_TARGET_H
#define DEEBE_TARGET_H

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

enum process_state {
	PS_NULL = 0,
	PS_START,
	PS_RUN,
	PS_EXIT,
	PS_SIG,
	PS_SIG_PENDING,
	PS_ERR,
	PS_CONT,
	PS_STOP,
	PS_SYSCALL_ENTER,
	PS_SYSCALL_EXIT,
};

struct _tstate {
	struct breakpoint *bpl;
	struct process_info *pil;
};

extern struct _tstate tstate;

typedef struct target_process_rec {
	pid_t pid;
	void *reg;
	void *freg;
	void *fxreg;
	void *dbreg;
} target_process;

typedef struct target_state_rec {
	int no_ack;
	int multiprocess;
	bool syscall_enter;
	int current_signal;
	int current_gdb_signal;
	int step;
	int flag_attached_existing_process;
	enum process_state ps;
	size_t reg_size;
	size_t freg_size;
	size_t fxreg_size;
	size_t dbreg_size;
	uint8_t *reg_rw;
	uint8_t *freg_rw;
	uint8_t *fxreg_rw;
	uint8_t *dbreg_rw;
	size_t number_processes;
	size_t current_process;
	target_process *process;
} target_state;

#define TARGET_PID_GET()  _target.process[_target.current_process].pid
#define TARGET_PID_SET(s) _target.process[_target.current_process].pid = s
#define TARGET_REG        _target.process[_target.current_process].reg
#define TARGET_FREG       _target.process[_target.current_process].freg
#define TARGET_FXREG      _target.process[_target.current_process].fxreg
#define TARGET_DBREG      _target.process[_target.current_process].dbreg

extern target_state _target;
#define msizeof(TYPE, MEMBER) sizeof(((TYPE *)0)->MEMBER)

struct reg_location_list {
	size_t off;
	size_t size;
	int gdb;
	char *name;
	size_t gdb_size;
};

/* The register lookup lists */
/* General */
extern struct reg_location_list grll[];
/* Floating point */
extern struct reg_location_list frll[];
/* Extended */
extern struct reg_location_list fxrll[];

#endif
