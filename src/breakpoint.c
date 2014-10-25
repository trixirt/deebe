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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "breakpoint.h"
#include "global.h"
#include "util.h"
#include "target.h"
#include "memory.h"

static bool _add_break_verbose = true;
static bool _remove_break_verbose = true;

/* For debugging */
void _breakpoint_print(struct breakpoint *bpl)
{
	struct breakpoint *p = bpl;
	while (p != NULL) {
		DBG_PRINT("%p\n", p);
		DBG_PRINT("\ta 0x%lx\n", p->addr);
		DBG_PRINT("\tn %p\n", p->n);
		DBG_PRINT("\tp %p\n", p->p);
		DBG_PRINT("\tdata\n\t");
		util_print_buffer(fp_log, 0, p->len, p->data);
		DBG_PRINT("\tbdata\n\t");
		util_print_buffer(fp_log, 0, p->len, p->bdata);
		p = p->n;
	}
}

struct breakpoint *breakpoint_find(struct breakpoint *bpl,
				   /*@unused@*/int debug_level,
				   void *addr) {

	struct breakpoint *ret = NULL;
	struct breakpoint *p = bpl;
	while (p != NULL) {
	    if ((p->addr <= addr) &&
		((p->addr + p->len) > addr)) {
			ret = p;
			break;
		} else {
			p = p->n;
		}
	}
	return ret;
}

void breakpoint_remove(struct breakpoint **bpl,
		       int debug_level, void *addr) {
	struct breakpoint *bp = NULL;
	bp = breakpoint_find(*bpl, debug_level, addr);
	if (bp) {
		bp->ref_count--;
		if (bp->ref_count <= 0) {
			if (bp == *bpl) {
				*bpl = bp->n;
				if (*bpl)
					(*bpl)->p = NULL;
			} else {
				bp->p->n = bp->n;
				if (bp->n)
					bp->n->p = bp->p;
			}
			if (bp->data)
				free(bp->data);
			if (bp->bdata)
				free(bp->bdata);
			free(bp);
		}
	}
}

struct breakpoint *breakpoint_add(struct breakpoint **bpl, int debug_level,
				  void *addr,
				  int type, size_t len) {
	/*@null@*/struct breakpoint *ret = NULL;
	struct breakpoint *bp = NULL;

	/*
	 * It is ok to have multiple breakpoints at the same address
	 * If we find one, increment its reference count
	 */
	bp = breakpoint_find(*bpl, debug_level, addr);
	if (bp) {
		bp->ref_count++;
		ret = bp;
	} else {
		bp = (struct breakpoint *) malloc(sizeof(struct breakpoint));
		if (bp) {
			bp->p = NULL;
			bp->n = NULL;
			bp->data = NULL;
			bp->bdata = NULL;
			bp->data = malloc(len);
			if (!bp->data) {
				if (debug_level) {
					fprintf(fp_log,
						"INTERNAL ERROR Allocating breakpoint at %p\n",
						addr);
				}
				free(bp);
			}  else {
				memset(bp->data, 0, len);
				bp->bdata = malloc(len);
				if (!bp->bdata) {
					if (debug_level) {
						fprintf(fp_log,
							"INTERNAL ERROR Allocating breakpoint at %p\n",
							addr);
					}
					free(bp->data);
					free(bp);
				} else {
					memset(bp->bdata, 0, len);
					/*
					 * This the break insn
					 * is filled in later
					 */
					bp->addr = addr;
					bp->type = type;
					bp->len = len;
					bp->ref_count = 1;
					if (*bpl) {
						bp->n = *bpl;
						(*bpl)->p = bp;
					}
					*bpl = bp;
					ret = bp;
				}
			}
		} else {
			if (debug_level) {
				fprintf(fp_log,
					"INTERNAL ERROR Allocating breakpoint at %p\n",
					addr);
			}
		}
	}
	return ret;
}

static void _leading(struct breakpoint *bp, void *addr,
		     /*@unused@*/size_t len,
		     size_t *leading) {
	*leading = 0;
	if (bp->addr < addr)
		*leading = addr - bp->addr;
}

static void _trailing(struct breakpoint *bp, void *addr,
		      /*@unused@*/size_t len,
		      size_t *trailing) {
	*trailing = 0;
	if (bp->addr + bp->len > addr + len)
		*trailing = bp->addr + bp->len - addr - len;
}

void breakpoint_adjust_read_buffer(struct breakpoint *bpl,
				   int debug_level,
				   void *addr,
				   size_t len,
				   void *buffer)
{
	struct breakpoint *p = bpl;
	while (p != NULL) {
		size_t leading = 0;
		_leading(p, addr, len, &leading);
		if (leading < p->len) {
			size_t trailing = 0;
			_trailing(p, addr, len, &trailing);
			if (trailing < p->len) {
				void *src;
				void *dst;
				size_t size = p->len - leading - trailing;
				src = p->data + leading;
				dst = buffer + (p->addr + leading - addr);
				if (debug_level) {
					fprintf(fp_log,
						"%s %p %p %zd : %zd %zd\n",
						__func__, src, dst, size,
						leading, trailing);
				}
				memcpy(dst, src, size);
			}
		}
		p = p->n;
	}
}

void breakpoint_adjust_write_buffer(struct breakpoint *bpl,
				    int debug_level,
				    void *addr,
				    size_t len,
				    void *buffer)
{
	struct breakpoint *p = bpl;
	while (p != NULL) {
		size_t leading = 0;
		_leading(p, addr, len, &leading);
		if (leading < p->len) {
			size_t trailing = 0;
			_trailing(p, addr, len, &trailing);
			if (trailing < p->len) {
				void *src;
				void *dst;
				size_t size = p->len - leading - trailing;
				/* The breakpoint's data */
				dst = p->data + leading;
				src = buffer + (p->addr + leading - addr);
				if (debug_level) {
					fprintf(fp_log,
						"%s 1 %p %p %zd : %zd %zd\n",
						__func__, src, dst, size,
						leading, trailing);
				}
				memcpy(dst, src, size);
				/* The breakpoint insn */
				src = p->bdata + leading;
				dst = buffer + (p->addr + leading - addr);
				if (debug_level) {
					fprintf(fp_log,
						"%s 1 %p %p %zd : %zd %zd\n",
						__func__, src, dst, size,
						leading, trailing);
				}
				memcpy(dst, src, size);
			}
		}
		p = p->n;
	}
}

int breakpoint_add_gdb(pid_t pid, pid_t tid, int type, uint64_t addr, size_t len)
{
	int ret = RET_ERR;
	void *kaddr = (void *) addr;

	ret = RET_ERR;
	if (_add_break_verbose) {
		DBG_PRINT("%s %d %lx %zu\n",
			  __func__, type, kaddr, len);
	}

	if (type == GDB_INTERFACE_BP_HARDWARE) {
	  if (breakpoint_arch_support_hardware_breakpoints()) {
	    if (breakpoint_arch_add_hardware_breakpoint(tid, addr, len)) {
	      ret = RET_OK;
	      if (_add_break_verbose) {
		DBG_PRINT("OK setting hardware breakpoint at 0x%lx\n", kaddr);
	      }
	    } else {
	      if (_add_break_verbose) {
		DBG_PRINT("ERROR setting hardware breakpoint at 0x%lx\n", kaddr);
	      }
	    }
	  } else {
	    ret = RET_NOSUPP;
	    if (_add_break_verbose) {
	      DBG_PRINT("Hardware breakpoint is not supported\n");
	    }
	  }
	} else if ((type == GDB_INTERFACE_BP_READ_WATCH) ||
	    (type == GDB_INTERFACE_BP_WRITE_WATCH) ||
	    (type == GDB_INTERFACE_BP_ACCESS_WATCH)) {
		if (breakpoint_arch_support_watchpoint(type)) {
			if (breakpoint_arch_add_watchpoint(tid,
						       type, addr, len)) {
				ret = RET_OK;
				if (_add_break_verbose) {
					DBG_PRINT("OK setting watchpoint at 0x%lx\n", kaddr);
				}
			} else {
				if (_add_break_verbose) {
					DBG_PRINT("ERROR setting watchpoint at 0x%lx\n", kaddr);
				}
			}
		} else {
			ret = RET_NOSUPP;
			if (_add_break_verbose) {
				DBG_PRINT("Watchpoints type %d is not supported\n", type);
			}
		}
	} else if (type == GDB_INTERFACE_BP_SOFTWARE) {
		/* Add to general list first */
		struct breakpoint *bp = NULL;
		size_t arch_brkpt_len = breakpoint_arch_swbreak_size();
		bp = breakpoint_add(&_target.bpl, _add_break_verbose,
				    kaddr, type, arch_brkpt_len);
		if (bp) {
			/* Get the arch specific break insn */
			ret = breakpoint_arch_swbreak_insn(bp->bdata);
			if (ret == RET_OK) {
				size_t read_size;
				/* Read and save off the memory location that the break is goint to */
				ret = memory_read(pid, addr, bp->data,
						  bp->len, &read_size,
						  false);
				if (ret == RET_OK) {
					/* Now write the sw break insn in it's place */
					ret = memory_write(pid, addr, bp->bdata,
							   bp->len, false);
					if (ret == RET_OK) {
						if (_add_break_verbose) {
							DBG_PRINT("OK setting breakpoint at 0x%lx\n", kaddr);
						}
					} else {
						/* Failure */
						if (_add_break_verbose) {
							DBG_PRINT("ERROR writing breakpoint at 0x%lx\n", kaddr);
						}
						breakpoint_remove(&_target.bpl, _add_break_verbose, kaddr);
					}
				} else {
					/* Failure */
					if (_add_break_verbose) {
						DBG_PRINT("ERROR reading data for breakpoint at 0x%lx\n", kaddr);
					}
					breakpoint_remove(&_target.bpl,
							  _add_break_verbose,
							  kaddr);
				}
			} else {
				/* Failure */
				if (_add_break_verbose) {
					DBG_PRINT("INTERNAL ERROR with ARCH breakpoint at 0x%lx\n", kaddr);
				}
				breakpoint_remove(&_target.bpl,
						  _add_break_verbose, kaddr);
			}
		} else {
			if (_add_break_verbose) {
				DBG_PRINT("INTERNAL ERROR creating breakpoint at 0x%lx\n", kaddr);
			}
		}
	} else {
		if (_add_break_verbose) {
			DBG_PRINT("Warning unsupported breakpoint type %d at 0x%lx\n", type, kaddr);
		}
		ret = RET_NOSUPP;
	}
	return ret;
}

int breakpoint_remove_gdb(pid_t pid, pid_t tid, int type, uint64_t addr, size_t len)
{
	int ret = RET_ERR;
	void *kaddr = (void *) addr;
	if (_remove_break_verbose) {
		DBG_PRINT("%s %d %p %zu\n",
			  __func__, type, kaddr, len);
	}

	if (type == GDB_INTERFACE_BP_HARDWARE) {
	  if (breakpoint_arch_support_hardware_breakpoints()) {
	    if (breakpoint_arch_remove_hardware_breakpoint(tid, addr, len)) {
	      ret = RET_OK;
	      if (_remove_break_verbose) {
		DBG_PRINT("OK removing hardware breakpoint at %p\n", kaddr);
	      }
	    } else {
	      if (_remove_break_verbose) {
		DBG_PRINT("ERROR removing hardware breakpoint at %p\n", kaddr);
	      }
	    }
	  } else {
	    ret = RET_NOSUPP;
	    if (_add_break_verbose) {
	      DBG_PRINT("Hardware breakpoint is not supported\n");
	    }
	  }
	} else if ((type == GDB_INTERFACE_BP_READ_WATCH) ||
		   (type == GDB_INTERFACE_BP_WRITE_WATCH) ||
		   (type == GDB_INTERFACE_BP_ACCESS_WATCH)) {
		if (breakpoint_arch_support_watchpoint(type)) {
			if (breakpoint_arch_remove_watchpoint(tid, type, addr, len)) {
				ret = RET_OK;
				if (_remove_break_verbose) {
					DBG_PRINT("OK removing watchpoint at %p\n", kaddr);
				}
			} else {
				if (_remove_break_verbose) {
					DBG_PRINT("ERROR removing watchpoint at %p\n", kaddr);
				}
			}
		} else {
			ret = RET_NOSUPP;
			if (_remove_break_verbose) {
				DBG_PRINT("Watchpoint type %d is not supported\n", type);
			}
		}
	} else if (type == GDB_INTERFACE_BP_SOFTWARE) {
		struct breakpoint *bp = NULL;
		bp = breakpoint_find(_target.bpl, _remove_break_verbose, kaddr);
		if (bp) {
			/*
			 * Only really remove the breakpoint if it's reference count
			 * is one.
			 */
			if (1 == bp->ref_count) {
				ret = memory_write(pid, addr,
						   bp->data, bp->len,
						   false);
				if (ret == RET_OK) {
					breakpoint_remove(&_target.bpl,
							  _remove_break_verbose,
							  kaddr);
					if (_add_break_verbose) {
						DBG_PRINT("OK removing breakpoint at %p\n", kaddr);
					}
				} else {
					/* Failure */
					if (_add_break_verbose) {
						DBG_PRINT("ERROR restoring data for breakpoint at %p\n", kaddr);
					}
				}
			} else {
				/* This just decrements the ref_count */
				breakpoint_remove(&_target.bpl,
						  _remove_break_verbose, kaddr);
				ret = RET_OK;
			}
		} else {
			if (_add_break_verbose) {
				DBG_PRINT("Warning problem removing breakpoint at %p\n", kaddr);
			}
		}
	} else {
		if (_remove_break_verbose) {
			DBG_PRINT("Warning unsupported breakpoint type %d at %p\n", type, kaddr);
		}
		ret = RET_NOSUPP;
	}

	return ret;
}

