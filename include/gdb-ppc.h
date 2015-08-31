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
#ifndef __DEEBE_GDB_PPC_H
#define __DEEBE_GDB_PPC_H


#define GDB_GPR0  0x00
#define GDB_GPR1  0x01
#define GDB_GPR2  0x02
#define GDB_GPR3  0x03
#define GDB_GPR4  0x04
#define GDB_GPR5  0x05
#define GDB_GPR6  0x06
#define GDB_GPR7  0x07
#define GDB_GPR8  0x08
#define GDB_GPR9  0x09
#define GDB_GPR10 0x0A
#define GDB_GPR11 0x0B
#define GDB_GPR12 0x0C
#define GDB_GPR13 0x0D
#define GDB_GPR14 0x0E
#define GDB_GPR15 0x0F
#define GDB_GPR16 0x10
#define GDB_GPR17 0x11
#define GDB_GPR18 0x12
#define GDB_GPR19 0x13
#define GDB_GPR20 0x14
#define GDB_GPR21 0x15
#define GDB_GPR22 0x16
#define GDB_GPR23 0x17
#define GDB_GPR24 0x18
#define GDB_GPR25 0x19
#define GDB_GPR26 0x1A
#define GDB_GPR27 0x1B
#define GDB_GPR28 0x1C
#define GDB_GPR29 0x1D
#define GDB_GPR30 0x1E
#define GDB_GPR31 0x1F

#define GDB_FPR0  0x20
#define GDB_FPR1  0x21
#define GDB_FPR2  0x22
#define GDB_FPR3  0x23
#define GDB_FPR4  0x24
#define GDB_FPR5  0x25
#define GDB_FPR6  0x26
#define GDB_FPR7  0x27
#define GDB_FPR8  0x28
#define GDB_FPR9  0x29
#define GDB_FPR10 0x2A
#define GDB_FPR11 0x2B
#define GDB_FPR12 0x2C
#define GDB_FPR13 0x2D
#define GDB_FPR14 0x2E
#define GDB_FPR15 0x2F
#define GDB_FPR16 0x30
#define GDB_FPR17 0x31
#define GDB_FPR18 0x32
#define GDB_FPR19 0x33
#define GDB_FPR20 0x34
#define GDB_FPR21 0x35
#define GDB_FPR22 0x36
#define GDB_FPR23 0x37
#define GDB_FPR24 0x38
#define GDB_FPR25 0x39
#define GDB_FPR26 0x3A
#define GDB_FPR27 0x3B
#define GDB_FPR28 0x3C
#define GDB_FPR29 0x3D
#define GDB_FPR30 0x3E
#define GDB_FPR31 0x3F


#define GDB_PC    64
#define GDB_MSR   65
#define GDB_CND   66
#define GDB_LR    67
#define GDB_CNT   68
#define GDB_XER   69
#define GDB_MQ    70

#endif
