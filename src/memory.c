/*
 * Copyright (c) 2014, Juniper Networks, Inc.
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
#include <string.h>
#include <errno.h>
#include "global.h"
#include "memory.h"
#include "target.h"
#include "gdb_interface.h"
#include "breakpoint.h"

static bool _read_mem_verbose = true;
static bool _write_mem_verbose = true;

/*
 * read mem is used by breakpoint creation
 * So break out the reading parts from the
 * public interface
 */
int memory_read(pid_t pid, uint64_t addr, uint8_t *data, size_t size,
		size_t *read_size, bool breakpoint_check)
{
	size_t kbuf_size = 0;
	size_t tran_size = gdb_interface_target->memory_access_size();
	size_t mask = tran_size - 1;
	size_t leading = 0;
	size_t trailing = 0;
	void *a = NULL;
	int ret = RET_ERR;
	void *kb_addr = (void *) addr;
	void *ke_addr = kb_addr + size;
	/* align */
	leading = (unsigned long)kb_addr & mask;
	kb_addr -= leading;
	trailing = (unsigned long)ke_addr & mask;
	if (trailing) {
		ke_addr += tran_size - trailing;
	}
	kbuf_size = (ke_addr - kb_addr) / tran_size;
	a = malloc(kbuf_size * tran_size);
	if (a) {
	  size_t i, offset;
		for (i = 0; i < kbuf_size; i++) {
		  offset = i * tran_size;
		  if (!gdb_interface_target->memory_copy_read(pid, a + offset, kb_addr + offset)) {
		    if (_read_mem_verbose) {
		      DBG_PRINT("Error with failed to read %p\n", kb_addr + offset);
		      DBG_PRINT("leading %zu trailing %zu\n",
				leading, trailing);
		    }
		    break;
		  }
		}
		if (i == kbuf_size) {
			/* Success */
			uint8_t *b = (uint8_t *) a;
			b += leading;
			memcpy(data, b, size);
			if (NULL != read_size)
				*read_size = size;
			/*
			 * If a read memory region overlaps an existing breakpoint,
			 * The contents of the data buffer contain the breakpoint
			 * and not the original memory.  To recover this memory
			 * run the data buffer through the breakpoint memory
			 * adjuster.
			 */
			if (breakpoint_check) {
				breakpoint_adjust_read_buffer(_target.bpl,
							      _read_mem_verbose,
							      kb_addr + leading,
							      size, data);
			}
			ret = RET_OK;
		} else {
			/* Failure */
			if (_read_mem_verbose) {
				DBG_PRINT("ERROR only read %zu of %zu\n",
					  i, kbuf_size);
			}
		}
		free(a);
		a = NULL;
	} else {
		/* Failure */
		if (_read_mem_verbose) {
			DBG_PRINT("ERROR Allocating buffer for memory read of size %zu\n",
				  kbuf_size * tran_size);
		}
	}
	return ret;
}

int memory_read_gdb(pid_t pid, uint64_t addr, uint8_t *data, size_t size,
		    size_t *read_size)
{
	int ret;
	ret = memory_read(pid, addr, data, size, read_size,
			  true /*breakpoint check*/);
	return ret;
}

int memory_write(pid_t pid, uint64_t addr, uint8_t *data,
		 size_t size, bool breakpoint_check)
{
	size_t kbuf_size = 0;
	size_t tran_size = gdb_interface_target->memory_access_size();
	size_t mask = tran_size - 1;
	size_t leading = 0;
	size_t trailing = 0;
	void *a = NULL;
	int ret = RET_ERR;
	void *kb_addr = (void *) addr;
	void *ke_addr = kb_addr + size;
	/* align */
	leading = (unsigned long)kb_addr & mask;
	kb_addr -= leading;
	trailing = (unsigned long)ke_addr & mask;
	if (trailing)
		ke_addr += tran_size - trailing;
	kbuf_size = (ke_addr - kb_addr) / tran_size;
	a = malloc(kbuf_size * tran_size);
	if (a) {
		int err = 0;
		size_t i = 0;
		void *l = NULL;
		size_t offset;
		/*
		 * If there is leading or trailing data, the
		 * buffer is a mix of what is already there
		 * and what is being written now.
		 * Fetch just the leading and trailing data
		 */
		if (leading) {
			i = 0;
			offset = i * tran_size;
			l = (void *)(kb_addr + i * tran_size);
			if (!gdb_interface_target->memory_copy_read(pid, a + offset, kb_addr + offset)) {
				if (_write_mem_verbose) {
					DBG_PRINT("Error with reading data at %p\n", l);
				}
				err = 1;
			}
		}
		if (trailing && !err) {
			i = kbuf_size - 1;
			/* No double tap */
			if (i || !leading) {
			  offset = i * tran_size;
			  if (!gdb_interface_target->memory_copy_read(pid, a + offset, kb_addr + offset)) {
			    if (_write_mem_verbose) {
			      DBG_PRINT("Error with reading data at %p\n", l);
			    }
			    err = 1;
			  }
			}
		}
		/* Copy the user data */
		if (!err) {
		  uint8_t *b = a + leading;
			memcpy(b, data, size);
			/*
			 * If a write memory region overlaps an existing breakpoint,
			 * The breakpoint needs to update is memory location
			 * and the code for the breakpoint insn should not change.
			 */
			if (breakpoint_check) {
				breakpoint_adjust_write_buffer(_target.bpl, _read_mem_verbose,
							       kb_addr + leading,
							       size, data);
			}
			for (i = 0; i < kbuf_size; i++) {
			  offset = i * tran_size;
			  if (!gdb_interface_target->memory_copy_write(pid, kb_addr + offset, a + offset)) {
			    if (_write_mem_verbose) {
			      DBG_PRINT("Error with reading data at %p\n", l);
			    }
			    err = 1;
			  }
			}
			if (i == kbuf_size) {
				/* Success */
				ret = RET_OK;
			} else {
				/* Failure */
				;
			}
		}
		free(a);
		a = NULL;
	} else {
		/* Failure */
		;
	}
	return ret;
}

int memory_write_gdb(pid_t pid, uint64_t addr, uint8_t *data, size_t size)
{
	int ret;
	ret = memory_write(pid, addr, data, size, true /* breakpoint check */);
	return ret;
}


