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
#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <stdlib.h>
#include <stdbool.h>

struct breakpoint;
struct breakpoint {
	int type;
  void *addr;
	size_t len;
	int ref_count;
	void *data;
	void *bdata;
	struct breakpoint *n;
	struct breakpoint *p;
};

void _breakpoint_print(struct breakpoint *bpl);
/*@null@*/struct breakpoint *breakpoint_find(struct breakpoint *bpl,
					      int debug_level,
					      void *addr);
void breakpoint_remove(struct breakpoint **bpl, int debug_level,
		       void *addr);
/*@null@*/struct breakpoint *breakpoint_add(struct breakpoint **bpl,
					    int debug_level,
					    void *addr, int type,
					    size_t len);
void breakpoint_adjust_read_buffer(struct breakpoint *bpl,
				   int debug_level,
				   void *addr,
				   size_t len,
				   void *buffer);

void breakpoint_adjust_write_buffer(struct breakpoint *bpl,
				    int debug_level,
				    void *addr,
				    size_t len,
				    void *buffer);

int breakpoint_add_gdb(pid_t pid, pid_t tid, int type, uint64_t addr, size_t len);
int breakpoint_remove_gdb(pid_t pid, pid_t tid, int type, uint64_t addr, size_t len);
bool breakpoint_arch_support_hardware_breakpoints();
bool breakpoint_arch_add_hardware_breakpoint(pid_t tid, unsigned long addr,	size_t len);
bool breakpoint_arch_remove_hardware_breakpoint(pid_t tid, unsigned long addr, size_t len);
bool breakpoint_arch_hit_hardware_breakpoint(pid_t tid, unsigned long pc);
bool breakpoint_arch_support_watchpoint(int type);
bool breakpoint_arch_add_watchpoint(pid_t tid, int type, unsigned long addr,
				size_t len);
bool breakpoint_arch_remove_watchpoint(pid_t tid, int type, unsigned long addr,
				   size_t len);
int breakpoint_arch_swbreak_insn(void *bdata);
size_t breakpoint_arch_swbreak_size();

#endif
