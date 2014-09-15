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
 #
 * Signal mapping for
 * Version 6.1.1 [FreeBSD]
 * Host    i386-marcel-freebsd
 * Target  i386-marcel-freebsd
 */
#define SIGNAL_MAX 256
static int signal_from_gdb[SIGNAL_MAX] = {
	0,    1,    2,    3,    4,    5,    6,    7,
	8,    9,   10,   11,   12,   13,   14,   15,
	16,   17,   18,   19,   20,   21,   22,   23,
	24,   25,   26,   27,   28,   -1,   30,   31,
	-1,   -1,   -1,   -1,   -1,   32,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   65,
	66,   67,   68,   69,   70,   71,   72,   73,
	74,   75,   76,   77,   78,   79,   80,   81,
	82,   83,   84,   85,   86,   87,   88,   89,
	90,   91,   92,   93,   94,   95,   96,   97,
	98,   99,  100,  101,  102,  103,  104,  105,
	106,  107,  108,  109,  110,  111,  112,  113,
	114,  115,  116,  117,  118,  119,  120,  121,
	122,  123,  124,  125,   -1,   -1,   29,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
};

static int signal_to_gdb[SIGNAL_MAX] = {
	0,    1,    2,    3,    4,    5,    6,    7,
	8,    9,   10,   11,   12,   13,   14,   15,
	16,   17,   18,   19,   20,   21,   22,   23,
	24,   25,   26,   27,   28,  142,   30,   31,
	37,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   79,   80,   81,   82,   83,   84,   85,
	86,   87,   88,   89,   90,   91,   92,   93,
	94,   95,   96,   97,   98,   99,  100,  101,
	102,  103,  104,  105,  106,  107,  108,  109,
	110,  111,  112,  113,  114,  115,  116,  117,
	118,  119,  120,  121,  122,  123,  124,  125,
	126,  127,  128,  129,  130,  131,  132,  133,
	134,  135,  136,  137,  138,  139,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
	-1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
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
