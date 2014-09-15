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
#include "target_ptrace.h"
#include "global.h"
#include "os.h"

static bool x86_verbose = false;
union u_drc {
	struct {
		unsigned   l0:1;
		unsigned   g0:1;
		unsigned   l1:1;
		unsigned   g1:1;
		unsigned   l2:1;
		unsigned   g2:1;
		unsigned   l3:1;
		unsigned   g3:1;
		unsigned   le:1;
		unsigned   ge:1;
		unsigned pad0:3;
		unsigned   gd:1;
		unsigned pad1:2;
		unsigned  rw0:2;
		unsigned len0:2;
		unsigned  rw1:2;
		unsigned len1:2;
		unsigned  rw2:2;
		unsigned len2:2;
		unsigned  rw3:2;
		unsigned len3:2;
	} b;
	unsigned int v;
};

union u_drs {
	struct {
		unsigned  b0:1;
		unsigned  b1:1;
		unsigned  b2:1;
		unsigned  b3:1;
		unsigned pad:9;
		unsigned  bd:1;
		unsigned  bs:1;
		unsigned  bt:1;
	} b;
	unsigned int v;
};

#define DEBUG_ADDR_0  0
#define DEBUG_ADDR_1  1
#define DEBUG_ADDR_2  2
#define DEBUG_ADDR_3  3
#define DEBUG_STATUS  6
#define DEBUG_CONTROL 7

extern bool x86_read_debug_reg(pid_t pid, size_t reg, void *val);
extern bool x86_write_debug_reg(pid_t pid, size_t reg, void *val);

int ptrace_arch_swbreak_insn(void *bdata)
{
	int ret = RET_ERR;
	/* Illegal instruction is 0xcc or 'int3' */
	memset(bdata, 0xcc, 1);
	ret = RET_OK;

	return ret;
}

bool ptrace_arch_support_watchpoint(int type)
{
	bool ret = false;
	if ((GDB_INTERFACE_BP_WRITE_WATCH == type) ||
	    (GDB_INTERFACE_BP_ACCESS_WATCH == type)) {
		ret = true;
	}
	return ret;
}

bool _supported_access(unsigned long addr, size_t len)
{
	bool ret = false;
	if (1 == len) {
		ret = true;
	} else if (2 == len) {
		/* At least 2 byte aligned */
		if (0 == (addr & 0x1))
			ret = true;
	} else if (4 == len) {
		/* At least 4 byte aligned */
		if (0 == (addr & 0x3))
			ret = true;
	}
	return ret;
}

bool ptrace_arch_add_watchpoint(pid_t pid, int type,
				unsigned long addr, size_t len)
{
	bool ret = false;
	if (ptrace_arch_support_watchpoint(type)) {
		if (_supported_access(addr, len)) {
			union u_drc drc;
			if (x86_read_debug_reg(pid, DEBUG_CONTROL, &drc)) {
				if ((0 == drc.b.l0) &&
				    (0 == drc.b.g0)) {
					drc.b.l0 = 1;
					drc.b.rw0 = (type == GDB_INTERFACE_BP_WRITE_WATCH) ? 1 : 3;
					drc.b.len0 = len - 1;
					if (x86_write_debug_reg(
						    pid, DEBUG_ADDR_0,
						    &addr)) {
						ret = x86_write_debug_reg(
							pid, DEBUG_CONTROL,
							&drc);
					}
				} else if ((0 == drc.b.l1) &&
					   (0 == drc.b.g1)) {
					drc.b.l1 = 1;
					drc.b.rw1 = (type == GDB_INTERFACE_BP_WRITE_WATCH) ? 1 : 3;
					drc.b.len1 = len - 1;
					if (x86_write_debug_reg(
						    pid, DEBUG_ADDR_1,
						    &addr)) {
						ret = x86_write_debug_reg(
							pid, DEBUG_CONTROL,
							&drc);
					}
				} else if ((0 == drc.b.l2) &&
					   (0 == drc.b.g2)) {
					drc.b.l2 = 1;
					drc.b.rw2 = (type == GDB_INTERFACE_BP_WRITE_WATCH) ? 1 : 3;
					drc.b.len2 = len - 1;
					if (x86_write_debug_reg(
						    pid, DEBUG_ADDR_2,
						    &addr)) {
						ret = x86_write_debug_reg(
							pid, DEBUG_CONTROL,
							&drc);
					}
				} else if ((0 == drc.b.l3) &&
					   (0 == drc.b.g3)) {
					drc.b.l3 = 1;
					drc.b.rw3 = ((type == GDB_INTERFACE_BP_WRITE_WATCH) ? 1 : 3);
					drc.b.len3 = len - 1;
					if (x86_write_debug_reg(
						    pid, DEBUG_ADDR_3,
						    &addr)) {
						ret = x86_write_debug_reg(
							pid, DEBUG_CONTROL,
							&drc);
					}
				}
			}
		}
	}
	return ret;
}

bool ptrace_arch_remove_watchpoint(pid_t pid, int type,
				   unsigned long addr, size_t len)
{
	bool ret = false;
	if (ptrace_arch_support_watchpoint(type)) {
		if (_supported_access(addr, len)) {
			union u_drc drc;
			if (x86_read_debug_reg(pid, DEBUG_CONTROL, &drc)) {
				unsigned long r_addr = 0;
				if ((x86_read_debug_reg(
					     pid, DEBUG_ADDR_0, &r_addr)) &&
				    (r_addr == addr) &&
				    ((len - 1) == drc.b.len0)) {
					/* Does not handle a double tap */
					drc.b.l0 = 0;
					ret = x86_write_debug_reg(
						pid, DEBUG_CONTROL, &drc);
				} else if ((x86_read_debug_reg(
						    pid, DEBUG_ADDR_1,
						    &r_addr)) &&
					   (r_addr == addr) &&
					   ((len - 1) == drc.b.len1)) {
					/* Does not handle a double tap */
					drc.b.l1 = 0;
					ret = x86_write_debug_reg(
						pid, DEBUG_CONTROL, &drc);
				} else if ((x86_read_debug_reg(
						    pid, DEBUG_ADDR_2,
						    &r_addr)) &&
					   (r_addr == addr) &&
					   ((len - 1) == drc.b.len2)) {
					/* Does not handle a double tap */
					drc.b.l2 = 0;
					ret = x86_write_debug_reg(
						pid, DEBUG_CONTROL, &drc);
				} else if ((x86_read_debug_reg(
						    pid, DEBUG_ADDR_3,
						    &r_addr)) &&
					   (r_addr == addr) &&
					   ((len - 1) == drc.b.len3)) {
					/* Does not handle a double tap */
					drc.b.l3 = 0;
					ret = x86_write_debug_reg(
						pid, DEBUG_CONTROL, &drc);
				}
			}
		}
	}
	return ret;
}

bool ptrace_arch_hit_watchpoint(pid_t pid, unsigned long *addr)
{
	bool ret = false;
	union u_drc drc;
	if (x86_read_debug_reg(pid, DEBUG_CONTROL, &drc)) {

		if (x86_verbose)
			DBG_PRINT("%s : drc %x\n", __func__, drc.v);
		union u_drs drs;
		if (x86_read_debug_reg(pid, DEBUG_STATUS, &drs)) {
			if (x86_verbose)
				DBG_PRINT("%s : drs %x\n", __func__, drs.v);

			if (drs.b.b0 && ((1 == drc.b.l0) ||
					 (1 == drc.b.g0))) {
				ret = x86_read_debug_reg(pid,
							 DEBUG_ADDR_0, addr);
				if (x86_verbose)
					DBG_PRINT("%s : addr %lx\n",
						  __func__, *addr);

			} else if (drs.b.b1 && ((1 == drc.b.l1) ||
						(1 == drc.b.g1))) {
				ret = x86_read_debug_reg(pid, DEBUG_ADDR_1,
							 addr);
				if (x86_verbose)
					DBG_PRINT("%s : addr %lx\n",
						  __func__, *addr);
			} else if (drs.b.b2 && ((1 == drc.b.l2) ||
						(1 == drc.b.g2))) {
				ret = x86_read_debug_reg(pid, DEBUG_ADDR_2,
							 addr);
				if (x86_verbose)
					DBG_PRINT("%s : addr %lx\n",
						  __func__, *addr);
			} else if (drs.b.b3 && ((1 == drc.b.l3) ||
						(1 == drc.b.g3))) {
				ret = x86_read_debug_reg(pid, DEBUG_ADDR_3,
							 addr);
				if (x86_verbose)
					DBG_PRINT("%s : addr %lx\n",
						  __func__, *addr);
			}
		}
	}
	return ret;
}
