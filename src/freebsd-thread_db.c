/*
 * Copyright (c) 2012-2016, Juniper Networks, Inc.
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

#ifdef HAVE_THREAD_DB_H

#include "global.h"
#include "target.h"
#include "thread_db_priv.h"

int initialize_thread_db(pid_t pid, struct gdb_target_s *t)
{
  int ret;
  ret = td_init ();
  if (ret != TD_OK)
    return RET_ERR;

  _target.ph.pid = pid;
  _target.ph.target = t;
  ret = td_ta_new (&_target.ph, &_target.thread_agent);
  switch (ret)
    {
    case TD_NOLIBTHREAD:
      /* Thread library not detected */
      _target.ph.pid = 0;
      _target.ph.target = NULL;
      return RET_ERR;
      
    case TD_OK:
      /* Thread library detected */
      return RET_OK;

    default:
      fprintf(stderr, "Error initializing thread_db library\n");
      _target.ph.pid = 0;
      _target.ph.target = NULL;
      return RET_ERR;
    }
  return RET_OK;
}

int thread_db_get_tls_address(int64_t thread, uint64_t lm, uint64_t offset,
			      uintptr_t *tlsaddr)
{
  td_err_e err;
  td_thrhandle_t th;
  psaddr_t addr = 0;

  if (_target.thread_agent == NULL)
    return RET_ERR;
  
  err = td_ta_map_id2thr(_target.thread_agent, thread, &th);
  if (err)
    return RET_ERR;

  err = td_thr_tls_get_addr(&th, lm, offset, &addr);
  if (err)
    return RET_ERR;
  *tlsaddr = (uintptr_t) addr;

  return RET_OK;
}

#endif /* HAVE_THREAD_DB_H */
