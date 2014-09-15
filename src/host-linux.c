/*
 * Copyright (c) 2013, Juniper Networks, Inc.
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
 *
 * Signal mapping for
 * Version 7.5
 * Host    i686-pc-linux-gnu
 * Target  i686-pc-linux-gnu
 */
#define SIGNAL_MAX 128
static int signal_from_gdb[SIGNAL_MAX] = {
	0,    1,    2,    3,    4,    5,    6,   -1,
	8,    9,    7,   11,   31,   13,   14,   15,
	23,   19,   20,   18,   17,   21,   22,   29,
	24,   25,   26,   27,   28,   -1,   10,   12,
	30,   29,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   33,   34,   35,
	36,   37,   38,   39,   40,   41,   42,   43,
	44,   45,   46,   47,   48,   49,   50,   51,
	52,   53,   54,   55,   56,   57,   58,   59,
	60,   61,   62,   63,   -1,   32,   64,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
};

static int signal_to_gdb[SIGNAL_MAX] = {
	0,    1,    2,    3,    4,    5,    6,   10,
	8,    9,   30,   11,   31,   13,   14,   15,
	-1,   20,   19,   17,   18,   21,   22,   16,
	24,   25,   26,   27,   28,   23,   32,   12,
	77,   45,   46,   47,   48,   49,   50,   51,
	52,   53,   54,   55,   56,   57,   58,   59,
	60,   61,   62,   63,   64,   65,   66,   67,
	68,   69,   70,   71,   72,   73,   74,   75,
	78,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
};

int host_signal_to_gdb(int sig)
{
	int ret = -1;
	if (sig < SIGNAL_MAX)
		ret = signal_to_gdb[sig];
	return ret;
}

int host_signal_from_gdb(int gdb)
{
	int ret = -1;
	if (gdb < SIGNAL_MAX)
		ret = signal_from_gdb[gdb];
	return ret;
}
