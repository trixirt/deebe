/*
 * Copyright (c) 2012, Juniper Networks, Inc.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "process_info.h"

/* For debugging */
void _process_info_print(struct process_info *pil)
{
	struct process_info *p = pil;
	while (p != NULL) {
		fprintf(stdout, "%p\n", p);
		fprintf(stdout, "\tpid %d\n", p->pid);
		fprintf(stdout, "\tn   %p\n", p->n);
		fprintf(stdout, "\tp   %p\n", p->p);
		p = p->n;
	}
}

struct process_info *process_info_find(struct process_info *pil,
				       /*@unused@*/int debug_level, pid_t pid)
{
	struct process_info *ret = NULL;
	struct process_info *p = pil;
	while (p != NULL) {
		if (p->pid == pid) {
			ret = p;
			break;
		} else {
			p = p->n;
		}
	}
	return ret;
}

void process_info_remove(struct process_info **pil,
			 int debug_level, pid_t pid) {
	struct process_info *pi = NULL;
	pi = process_info_find(*pil, debug_level, pid);
	if (pi) {
		if (pi == *pil) {
			*pil = pi->n;
			if (*pil)
				(*pil)->p = NULL;
		} else {
			pi->p->n = pi->n;
			if (pi->n)
				pi->n->p = pi->p;
		}
		free(pi);
	}
}

struct process_info *process_info_add(struct process_info **pil,
				      int debug_level, pid_t pid)
{
	/*@null@*/struct process_info *ret = NULL;
	struct process_info *pi = NULL;
	pi = process_info_find(*pil, debug_level, pid);
	if (pi) {
		if (debug_level)
			fprintf(stdout,	"Warning adding the same process_info %d ignored.\n", pid);
	} else {
		pi = (struct process_info *)
			malloc(sizeof(struct process_info));
		if (pi) {
			pi->p = NULL;
			pi->n = NULL;
			pi->pid = pid;
			if (*pil) {
				pi->n = *pil;
				(*pil)->p = pi;
			}
			*pil = pi;
			ret = pi;
		} else {
			if (debug_level)
				fprintf(stdout, "INTERNAL ERROR Allocating process_info for %d\n", pid);
		}
	}
	return ret;
}
