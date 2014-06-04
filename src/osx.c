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
#include <unistd.h>
#include <mach/mach_traps.h>
#include <mach/mach_init.h>
#include <mach/task.h>
#include "os.h"
#include "gdb_interface.h"
#include "target.h"

void osx_report_kernel_error(FILE *fp, kern_return_t kret)
{
	switch (kret) {
	case KERN_SUCCESS: /* 0 */
		fprintf(fp, "success!, what are you doing here?");
		break;
	case KERN_INVALID_ARGUMENT: /* 4 */
		fprintf(fp, "invalid argument");
		break;
	case KERN_FAILURE: /* 5 */
		fprintf(fp, "generic kernel failure");
		break;
	default:
		fprintf(fp, "code %d\n", kret);
		break;
	}
}

int osx_read_registers(uint8_t *data, uint8_t *avail,
		       size_t buf_size, size_t *read_size)
{
	/*
	 * XXX
	 * Assumes single threaded
	 */
	int ret = RET_ERR;
#if 0
	task_t task = 0;
	kern_return_t kret;

	kret = task_for_pid(mach_task_self(), tstate.cpid, &task);
	if (KERN_SUCCESS == kret) {
		thread_act_array_t threads;
		mach_msg_type_number_t cnt;
		kret = task_threads(task, &threads, &cnt);
		if (KERN_SUCCESS == kret) {
			if (0 == cnt) {
				fprintf(stderr, "Error number of threads is 0 for pid %d\n", tstate.cpid);
			} else {
				if (1 < cnt) {
					fprintf(stderr, "Warning number of threads is %d for pid %d\n", cnt, tstate.cpid);
					fprintf(stderr, "ONLY USING THE FIRST THREAD\n");
				}
				if (osx_arch_read_registers(threads[0])) {
					size_t transfer_size = _target.reg_size;
					if (transfer_size > buf_size) {
						transfer_size = buf_size;
						fprintf(stderr, "Warning expecting transfer buffer to be at least %zu but got %zu\n",
							_target.reg_size, buf_size);
					}
					memcpy(data, _target.reg,
					       transfer_size);
					memset(avail, 0xff, transfer_size);
					*read_size = transfer_size;
					ret = RET_OK;
				} else {
					/* Failure */
					fprintf(stderr,
						"Error in arch functions\n");
				}
			}
		} else {
			fprintf(stderr,
				"Error getting the osx threads pid %d reason :",
				tstate.cpid);
			osx_report_kernel_error(stderr, kret);
			fprintf(stderr, "\n");
		}
	} else {
		fprintf(stderr,
			"Error getting the osx task for pid %d reason :",
			tstate.cpid);
		osx_report_kernel_error(stderr, kret);
		fprintf(stderr, "\n");
	}
#endif
	return ret;
}

int osx_read_single_register(unsigned int gdb, uint8_t *data,
			     uint8_t *avail, size_t buf_size, size_t *read_size)
{
	return RET_NOSUPP;
}
int osx_write_registers(uint8_t *data, size_t size)
{
	return RET_NOSUPP;
}
int osx_write_single_register(unsigned int gdb, uint8_t *data, size_t size)
{
	return RET_NOSUPP;
}
