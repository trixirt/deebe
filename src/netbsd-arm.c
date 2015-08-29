/*
 * Copyright (c) 2015, Juniper Networks, Inc.
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
#include "os.h"
#include "gdb-arm.h"

struct reg_location_list frll[] = {
	FRLL(fp0, vfp_regs[0], GDB_FPR0, 0, 0, 0),
	FRLL(fp1, vfp_regs[1], GDB_FPR1, 0, 0, 0),
	FRLL(fp2, vfp_regs[2], GDB_FPR2, 0, 0, 0),
	FRLL(fp3, vfp_regs[3], GDB_FPR3, 0, 0, 0),
	FRLL(fp4, vfp_regs[4], GDB_FPR4, 0, 0, 0),
	FRLL(fp5, vfp_regs[5], GDB_FPR5, 0, 0, 0),
	FRLL(fp6, vfp_regs[6], GDB_FPR6, 0, 0, 0),
	FRLL(fp7, vfp_regs[7], GDB_FPR7, 0, 0, 0),
	FRLL(fpsr, vfp_fpscr, GDB_FPS, 0, 0, 0),
	{0},
};
