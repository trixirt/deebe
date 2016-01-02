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
#ifndef __DEEBE_GDB_ARM_H
#define __DEEBE_GDB_ARM_H

#define GDB_GREG_MAX 26

#define GDB_GPR0 0
#define GDB_GPR1 1
#define GDB_GPR2 2
#define GDB_GPR3 3
#define GDB_GPR4 4
#define GDB_GPR5 5
#define GDB_GPR6 6
#define GDB_GPR7 7
#define GDB_GPR8 8
#define GDB_GPR9 9
#define GDB_GPR10 10
#define GDB_GPR11 11
#define GDB_GPR12 12
#define GDB_SP 13
#define GDB_LR 14
#define GDB_PC 15
#define GDB_CPSR 25

#define GDB_FPR0 16
#define GDB_FPR1 17
#define GDB_FPR2 18
#define GDB_FPR3 19
#define GDB_FPR4 20
#define GDB_FPR5 21
#define GDB_FPR6 22
#define GDB_FPR7 23
#define GDB_FPS 24

#endif
