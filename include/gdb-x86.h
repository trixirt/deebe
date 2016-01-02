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
#ifndef __DEEBE_GDB_X86_H
#define __DEEBE_GDB_X86_H

#define GDB_EAX 0
#define GDB_ECX 1
#define GDB_EDX 2
#define GDB_EBX 3
#define GDB_ESP 4
#define GDB_EBP 5
#define GDB_ESI 6
#define GDB_EDI 7
#define GDB_EIP 8
#define GDB_EFLAGS 9
#define GDB_CS 10
#define GDB_SS 11
#define GDB_DS 12
#define GDB_ES 13
#define GDB_FS 14
#define GDB_GS 15
#define GDB_ORIG_EAX 41

#define GDB_FST0 16
#define GDB_FST1 17
#define GDB_FST2 18
#define GDB_FST3 19
#define GDB_FST4 20
#define GDB_FST5 21
#define GDB_FST6 22
#define GDB_FST7 23
#define GDB_FCTRL 24
#define GDB_FSTAT 25
#define GDB_FTAG 26
#define GDB_FISEG 27
#define GDB_FIOFF 28
#define GDB_FOSEG 29
#define GDB_FOOFF 30
#define GDB_FOP 31

#define GDB_XMM0 32
#define GDB_XMM1 33
#define GDB_XMM2 34
#define GDB_XMM3 35
#define GDB_XMM4 36
#define GDB_XMM5 37
#define GDB_XMM6 38
#define GDB_XMM7 39
#define GDB_MXCSR 40

#endif
