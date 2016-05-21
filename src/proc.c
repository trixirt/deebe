/*
 * Copyright (c) 2012-2015, Juniper Networks, Inc.
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

#include <proc_service.h>
#include "global.h"
#include "thread_db_priv.h"

ps_err_e ps_lcontinue(struct ps_prochandle *ph, lwpid_t lwpid)
{
  return PS_ERR;
}

ps_err_e ps_lgetfpregs(struct ps_prochandle *ph, lwpid_t lwpid,
		       prfpregset_t *fpregs)
{
  return PS_ERR;
}

ps_err_e ps_lgetregs(struct ps_prochandle *ph, lwpid_t lwpid,
		     prgregset_t gregs)
{
  return PS_ERR;
}

ps_err_e ps_lsetfpregs(struct ps_prochandle *ph, lwpid_t lwpid,
		       const prfpregset_t *fpregs)
{
  return PS_ERR;
}

ps_err_e ps_lsetregs(struct ps_prochandle *ph, lwpid_t lwpid,
		     const prgregset_t gregs)
{
  return PS_ERR;
}

#ifdef __i386__
ps_err_e ps_lgetxmmregs (struct ps_prochandle *ph, lwpid_t lwpid,
			 char *xmmregs)
{
  return PS_ERR;
}

ps_err_e ps_lsetxmmregs (struct ps_prochandle *ph, lwpid_t lwpid,
			 const char *xmmregs)
{
  return PS_ERR;
}
#endif

ps_err_e ps_lstop(struct ps_prochandle *ph, lwpid_t lwpid)
{
  return PS_ERR;
}

ps_err_e ps_linfo(struct ps_prochandle *ph, lwpid_t lwpid, void *buf)
{
  return PS_ERR;
}

ps_err_e ps_pcontinue(struct ps_prochandle *ph)
{
  return PS_ERR;
}

ps_err_e ps_pdmodel(struct ps_prochandle *ph, int *mod)
{
  return PS_ERR;
}

ps_err_e ps_pglobal_lookup(struct ps_prochandle *ph, const char *obj,
			   const char *sym, psaddr_t *addr)
{
  uintptr_t sym_addr;

  if (symbol_lookup(sym, &sym_addr) == RET_ERR)
    return PS_NOSYM;

  *addr = (psaddr_t) sym_addr;
  return PS_OK;
}

void     ps_plog(const char *fmt, ...)
{
}

ps_err_e ps_pread(struct ps_prochandle *ph, psaddr_t addr, void *buf,
		  size_t size)
{
  size_t read_size;
  
  if (ph->target->read_mem(ph->pid, (uint64_t) addr, (uint8_t*) buf, size,
			   &read_size) == RET_ERR) {
    return PS_ERR;
  }

  if (size != read_size)
    return PS_ERR;
  
  return PS_OK;
}

ps_err_e ps_pstop(struct ps_prochandle *ph)
{
  return PS_ERR;
}

ps_err_e ps_pwrite(struct ps_prochandle *ph, psaddr_t addr, const void *buf,
		   size_t size)
{
  if (ph->target->write_mem(ph->pid, (uint64_t) addr, (uint8_t*) buf,
			    size) == RET_ERR) {
    return PS_ERR;
  }

  return PS_OK;
}
