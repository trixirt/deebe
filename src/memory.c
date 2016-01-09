/*
 * Copyright (c) 2016, Juniper Networks, Inc.
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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#include <sys/types.h>
#include <stdint.h>
#include "breakpoint.h"
#include "dptrace.h"
#include "memory.h"
#include "macros.h"
#include "os.h"

static bool _read_mem_verbose = false;
static bool _write_mem_verbose = false;

/*
 * read mem is used by breakpoint creation
 * So break out the reading parts from the
 * public interface
 */
int memory_read(pid_t tid, uint64_t addr, uint8_t *data, size_t size,
		size_t *read_size, bool breakpoint_check) {
  size_t kbuf_size = 0;
  size_t tran_size, mask;
  size_t leading = 0;
  size_t trailing = 0;
  uint8_t *a = NULL;
  int ret = RET_ERR;
  /* Linux kernel uses unsigned long's internally */
  /* This cast may need to be cleaned up */
  unsigned long kb_addr = (unsigned long)addr;
  unsigned long ke_addr = kb_addr + size;
  /* Find transaction size, assume power of 2 */
  memory_os_request_size(&tran_size);
  mask = tran_size - 1;
  /* align */
  leading = kb_addr & mask;
  kb_addr -= leading;
  trailing = ke_addr & mask;
  if (trailing) {
    ke_addr += tran_size - trailing;
  }
  kbuf_size = (ke_addr - kb_addr) / tran_size;
  a = malloc(kbuf_size * tran_size);
  memset(a, 0xaa, kbuf_size * tran_size);
  if (a) {
    size_t i;
    for (i = 0; i < kbuf_size; i++) {
      void *l = (void *)(kb_addr + i * tran_size);
      if (! memory_os_read(tid, l, &a[i * tran_size])) {
	  if (_read_mem_verbose) {
	      DBG_PRINT("Error with failed to read %p\n", l);
	      DBG_PRINT("leading %zu trailing %zu\n", leading, trailing);
	  }
	  break;
      }
    }
    if (i == kbuf_size) {
      /* Success */
      uint8_t *b = (uint8_t *)a;
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
        breakpoint_adjust_read_buffer(_target.bpl, _read_mem_verbose,
                                      kb_addr + leading, size, data);
      }
      ret = RET_OK;
    } else {
      /* Failure */
      if (_read_mem_verbose) {
        DBG_PRINT("ERROR only read %zu of %zu\n", i, kbuf_size);
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

int memory_read_gdb(pid_t tid, uint64_t addr, uint8_t *data, size_t size,
                    size_t *read_size) {
  int ret;
  ret = memory_read(tid, addr, data, size, read_size,
		    true /*breakpoint check*/);
  return ret;
}

int memory_write(pid_t tid, uint64_t addr, uint8_t *data,
			size_t size, bool breakpoint_check) {
  size_t kbuf_size = 0;
  size_t tran_size, mask;
  size_t leading = 0;
  size_t trailing = 0;
  uint8_t *a = NULL;
  int ret = RET_ERR;
  /* Linux kernel uses unsigned long's internally */
  /* This cast may need to be cleaned up */
  unsigned long kb_addr = (unsigned long)addr;
  unsigned long ke_addr = kb_addr + size;
  /* Find transaction size, assume power of 2 */
  memory_os_request_size(&tran_size);
  mask = tran_size - 1;
  /* align */
  leading = kb_addr & mask;
  kb_addr -= leading;
  trailing = ke_addr & mask;
  if (trailing)
    ke_addr += tran_size - trailing;
  kbuf_size = (ke_addr - kb_addr) / tran_size;
  a = malloc(kbuf_size * tran_size);
  if (a) {
    int err = 0;
    size_t i = 0;
    void *l = NULL;
    /*
     * If there is leading or trailing data, the
     * buffer is a mix of what is already there
     * and what is being written now.
     * Fetch just the leading and trailing data
     */
    if (leading) {
      i = 0;
      l = (void *)(kb_addr + i * tran_size);
      if (! memory_os_read(tid, l, &a[i * tran_size])) {
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
        l = (void *)(kb_addr + i * tran_size);
	if (! memory_os_read(tid, l, &a[i * tran_size])) {
          if (_write_mem_verbose) {
            DBG_PRINT("Error with reading data at %p\n", l);
          }
          err = 1;
        }
      }
    }
    /* Copy the user data */
    if (!err) {
      uint8_t *b = (uint8_t *)&a[0];
      b += leading;
      memcpy(b, data, size);
      /*
       * If a write memory region overlaps an existing breakpoint,
       * The breakpoint needs to update is memory location
       * and the code for the breakpoint insn should not change.
       */
      if (breakpoint_check) {
        breakpoint_adjust_write_buffer(_target.bpl, _read_mem_verbose,
                                       kb_addr + leading, size, data);
      }
      for (i = 0; i < kbuf_size; i++) {
        void *l = (void *)(kb_addr + i * tran_size);
        if (!memory_os_write(tid, l, &a[i * tran_size])) {
          if (_write_mem_verbose) {
            DBG_PRINT("Error with write data at %p\n", l);
          }
          break;
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

int memory_write_gdb(pid_t tid, uint64_t addr, uint8_t *data, size_t size) {
  int ret;
  ret = memory_write(tid, addr, data, size, true /* breakpoint check */);
  return ret;
}

bool memory_region_info_gdb(uint64_t addr, char *out_buff,
			    size_t out_buf_size) {
	return memory_os_region_info_gdb(addr, out_buff, out_buf_size);
}
