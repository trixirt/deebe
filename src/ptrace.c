/*
 * Copyright (c) 2012-2014, Juniper Networks, Inc.
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

#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>

#include "breakpoint.h"
#include "global.h"
#include "network.h"
#include "os.h"
#include "util.h"
#include "dsignal.h"
#include "dptrace.h"
#include "target.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

static bool _general_set_verbose = true;
static bool _read_mem_verbose = true;
static bool _read_reg_verbose = true;
static bool _resume_current_verbose = true;
static bool _resume_from_addr_verbose = true;
#ifdef PT_SYSCALL
static bool _resume_syscall_verbose = false;
#endif
static bool _write_mem_verbose = true;
static bool _write_reg_verbose = true;
static bool _wait_partial_verbose = true;
static bool _wait_verbose = true;
static bool _add_break_verbose = true;
static bool _remove_break_verbose = false;
static bool _read_single_reg_verbose = false;
static bool _write_single_reg_verbose = false;
static bool _stop_verbose = true;
static bool _restart_verbose = true;
static bool _detach_verbose = true;

#define REG_MAX_SIZE 0x1000

#define GUARD_RLL(r) (((r).off == 0) && ((r).size == 0) && ((r).gdb == 0))

bool is_reg(int gdb, int *g_index, struct reg_location_list *rl)
{
	bool ret = false;
	int c = 0;
	while (1) {
		if (GUARD_RLL(rl[c])) {
			break;
		} else if (rl[c].gdb == gdb) {
			*g_index = c;
			ret = true;
			break;
		} else {
			c++;
		}
	}
	return ret;
}

void _print_rll(struct reg_location_list *rl)
{
	if (_read_reg_verbose || _write_reg_verbose) {
		int c = 0;
		while (1) {
			if (GUARD_RLL(rl[c])) {
				break;
			} else {
				DBG_PRINT("RLL %d : %s offset %zu size %zu gdb_size %zu gdb %d\n",
					  c, rl[c].name, rl[c].off, rl[c].size, rl[c].gdb_size, rl[c].gdb);
				c++;
			}
		}
	}
}

void _print_greg()
{
	struct reg_location_list *rl = &grll[0];

	int c = 0;
	size_t max_name = 0;

	c = 0;
	while (1) {
		if (GUARD_RLL(rl[c])) {
			break;
		} else {
			if (strlen(rl[c].name) > max_name) {
				max_name = strlen(rl[c].name);
			}
		}
		c++;
	}
	max_name++;

	c = 0;
	while (1) {
		if (GUARD_RLL(rl[c])) {
			break;
		} else {
			size_t s;
			union {
				uint16_t r16;
				uint32_t r32;
				uint64_t r64;
			} r;
			r.r64 = 0;
			memcpy(&r, _target.reg + grll[c].off, grll[c].size);
			DBG_PRINT("%s", rl[c].name);
			s = max_name - strlen(rl[c].name);
			while (s--) {
				DBG_PRINT(" ");
			}
			DBG_PRINT(": off 0x%zx %zd : size %zd : ",
				  grll[c].off, grll[c].off, grll[c].size);
			if (grll[c].size == 2) {
				DBG_PRINT("0x%x\n", r.r16);
			} else if (grll[c].size == 4) {
				DBG_PRINT("0x%x\n", r.r32);
			} else {
				DBG_PRINT("0x%016"PRIx64"\n", r.r64);
			}
			c++;
		}
	}
}

static size_t _copy_greg_to_gdb(void *gdb, void *avail)
{
	size_t ret = 0;
	int r, rmax;
	size_t diff;
	rmax = ptrace_arch_gdb_greg_max();

	for (r = 0; r < rmax; r++) {
		int i;
		if (is_reg(r, &i, grll)) {
			memcpy(gdb, _target.reg + grll[i].off, grll[i].size);
			memset(avail, 0xff, grll[i].size);
			gdb += grll[i].size;
			avail += grll[i].size;
			ret += grll[i].size;
			if (grll[i].gdb_size > grll[i].size) {
				diff = grll[i].gdb_size - grll[i].size;
				memset(gdb, 0, diff);
				memset(avail, 0, diff);
				gdb   += diff;
				avail += diff;
				ret   += diff;
			}
		} else if (is_reg(r, &i, frll)) {
			memcpy(gdb, _target.freg + frll[i].off, frll[i].size);
			memset(avail, 0xff, frll[i].size);
			gdb += frll[i].size;
			avail += frll[i].size;
			ret += frll[i].size;
			if (frll[i].gdb_size > frll[i].size) {
				diff = frll[i].gdb_size - frll[i].size;
				memset(gdb, 0, diff);
				memset(avail, 0, diff);
				gdb   += diff;
				avail += diff;
				ret   += diff;
			}

		} else if (is_reg(r, &i, fxrll)) {
			if ((fxrll[i].off + fxrll[i].size) <=
			    _target.fxreg_size) {
				memcpy(gdb, _target.fxreg + fxrll[i].off,
				       fxrll[i].size);
				memset(avail, 0xff, frll[i].size);
				gdb   += fxrll[i].size;
				avail += fxrll[i].size;
				ret   += fxrll[i].size;
				if (fxrll[i].gdb_size > fxrll[i].size) {
					diff = fxrll[i].gdb_size -
						fxrll[i].size;
					memset(gdb, 0, diff);
					memset(avail, 0, diff);
					gdb   += diff;
					avail += diff;
					ret   += diff;
				}
			} else {
				DBG_PRINT("INTERNAL ERROR : rll entry %d exceeds reg buffer (%zu + %zu) vs %zu\n",
					  i, fxrll[i].off, fxrll[i].size, _target.fxreg_size);
				/* try to cope */
				memset(gdb,   0, fxrll[i].gdb_size);
				memset(avail, 0, fxrll[i].gdb_size);
				gdb   += fxrll[i].gdb_size;
				avail += fxrll[i].gdb_size;
				ret   += fxrll[i].gdb_size;
			}

		} else {
			size_t pad_size = 0;
			if (ptrace_arch_check_unrecognized_register(r, &pad_size)) {
				/* If the register is known not to be supported, handle */
				if (pad_size > 0) {
					memset(gdb, 0, pad_size);
					memset(avail, 0, pad_size);
					gdb   += pad_size;
					avail += pad_size;
					ret   += pad_size;
				} else {
					DBG_PRINT("INTERNAL ERROR : expecting pad size to be non zero\n");
				}
			} else {
				DBG_PRINT("INTERNAL ERROR : unrecognized reg %d\n", r);
			}
		}
	}
	return ret;
}

#ifdef PT_GETREGS
bool _read_reg(int GET, int SET,
	       void **reg, uint8_t **reg_rw, size_t *reg_size)
{
	bool ret = false;
	size_t buf_size = REG_MAX_SIZE;
	uint8_t *a = NULL;
	a = (uint8_t *) malloc(buf_size);
	if (a) {
		uint8_t *b = NULL;
		b = (uint8_t *) malloc(buf_size);
		if (b) {
			int ptrace_status;

			/*
			 * ptrace get's do not return how much was written
			 * so the have a general read function, we need to figure
			 * that out for ourselves.
			 *
			 * Fill the 'a' buffer with 0xff
			 * fill the 'b' buffer with 0xee
			 * Do 2 reads
			 * Reading from the end of the buffer,
			 * figure out the size of the returned buffer.
			 */
			memset(a, 0xff, buf_size);
			memset(b, 0xee, buf_size);

			errno = 0;
			ptrace_status = PTRACE_GETSET(GET, CURRENT_PROCESS_TID, 0, a);
			if (0 != ptrace_status) {
				/* Failure */
				if (_read_reg_verbose) {
					char str[128];
					memset(&str[0], 0, 128);
					DBG_PRINT("Error reading registers, status is %d\n", ptrace_status);
					if (0 == strerror_r(errno, &str[0], 128)) {
						DBG_PRINT("Error %d %s\n", errno, str);
					}
				}
			} else {

				ptrace_status = PTRACE_GETSET(GET, CURRENT_PROCESS_TID, 0, b);
				if (0 == ptrace_status) {
					size_t i = 0;
					for (i = buf_size; i > 0; i--) {
						if ((a[i - 1] != 0xff) ||
						    (b[i - 1] != 0xee))
							break;
					}
					if (i) {
						/* check if end of buffer was used */
						if (i > buf_size / 2) {
							if (_read_reg_verbose) {
								DBG_PRINT("Warning register read buffer may not be big enough used %zu of %zu\n",
									  i, buf_size);
							}
						}
						if (*reg_size) {
							if (*reg_size != i) {
								if (_read_reg_verbose) {
									DBG_PRINT("%s Warning register read size does not agree with last read %zu vs %zu\n",
										  __func__, *reg_size, i);
								}
								*reg_size = i;
								if (*reg) {
									if (*reg)
										free(*reg);
									*reg = malloc(*reg_size);
									if (*reg == NULL) {
										DBG_PRINT("%s Internal Error register buffer allocation failed\n",
											  __func__);
										*reg_size = 0;
									}
									if (*reg_rw) {
										free(*reg_rw);
										*reg_rw = NULL;
									}
								}
							}

						} else {
							/* First */
							*reg_size = i;
							*reg = malloc(*reg_size);
							if (*reg == NULL) {
								DBG_PRINT("%s Internal Error register buffer allocation failed\n",
									  __func__);
								*reg_size = 0;
							}
						}

						if (0 != (*reg_size) && (NULL != *reg)) {
							memcpy(*reg, b, *reg_size);
							/* Success or no point in handling the error */
							ret = true;

							/*
							 * Find out which registers are read/write vs just read only
							 * Do this by toggling each byte in just read registers and
							 * noting where failures happen.  This depends on a well
							 * behaved kernel reporting the error and that the registers
							 * are accessed on byte boundaryies.
							 *
							 * Assume the read/write nature does not change and only
							 * recalculate the read/write information when the size of
							 * the register read changes (should also not happen) or
							 * to initialize.
							 */
							if (*reg_rw == NULL) {
								*reg_rw = (uint8_t *)malloc(*reg_size * sizeof(uint8_t));
								if (*reg_rw) {
									size_t j;
									/* Assume read write */
									memset(*reg_rw, 0xff, *reg_size);
									for (j = 0; j < *reg_size; j++) {
										if (0 == PTRACE_GETSET(SET, CURRENT_PROCESS_TID, 0, a)) {
											/* Toggle current byte */
											a[j] ^= 0xff;
											if (0 != PTRACE_GETSET(SET, CURRENT_PROCESS_TID, 0, a)) {
												/* Set byte to read only */
												(*reg_rw)[j] = 0;
												if (_read_reg_verbose) {
													DBG_PRINT("Register location %zu is read only\n", j);
												}
											}
											/* Restore current byte */
											a[j] ^= 0xff;
										}
									}
									/*
									 * Trailing restore
									 * No point handling the error case
									 */
									if (0 != PTRACE_GETSET(SET, CURRENT_PROCESS_TID, 0, a)) {
										if (_read_reg_verbose) {
											DBG_PRINT("Error restoring registers\n");
										}
									}
								}
							}
						} else {
							/* Failure */
							;
						}
					} else {
						if (_read_reg_verbose) {
							DBG_PRINT("Error no data returned in %s\n", __func__);
						}
					}
				} else {
					/* Failure */
					if (_read_reg_verbose) {
						DBG_PRINT("Error reading registers in %s\n", __func__);
					}
				}
			}
			free(b);
			b = NULL;
		} else {
			/* Failure */
			;
		}
		free(a);
		a = NULL;
	} else {
		/* Failure */
		;
	}
	return ret;
}
#endif

#ifdef PT_SETREGS
void _write_reg(long SET, void *reg)
{
	if (0 != PTRACE_GETSET(SET, CURRENT_PROCESS_TID, 0, reg)) {
		if (_write_reg_verbose) {
			DBG_PRINT("Error : Write register\n");
		}
	}
}
#endif

bool _read_greg()
{
	bool ret = false;
#ifdef PT_GETREGS
	ret = _read_reg(PT_GETREGS, PT_SETREGS, &_target.reg,
			&_target.reg_rw, &_target.reg_size);
#else
	_target.reg = NULL;
	_target.reg_rw = NULL;
	_target.reg_size = 0;
#endif
	return ret;
}

bool _read_freg()
{
	bool ret = false;
#ifdef PT_GETFPREGS
	ret = _read_reg(PT_GETFPREGS, PT_SETFPREGS, &_target.freg,
			&_target.freg_rw, &_target.freg_size);
#else
	_target.freg = NULL;
	_target.freg_rw = NULL;
	_target.freg_size = 0;
#endif
	return ret;
}

bool _read_dbreg()
{
	bool ret = false;
#ifdef PT_GETDBREGS
	ret = _read_reg(PT_GETDBREGS, PT_SETDBREGS,
			&_target.dbreg, &_target.dbreg_rw,
			&_target.dbreg_size);
#else
	ptrace_arch_read_dbreg();
	if (_target.dbreg_size > 0) {
		ret = true;
	}
#endif
	return ret;
}

void _write_greg()
{
#ifdef PT_SETREGS
	_write_reg(PT_SETREGS, _target.reg);
#endif
}

void _write_freg()
{
#ifdef PT_SETFPREGS
	_write_reg(PT_SETFPREGS, _target.freg);
#endif
}

void _write_dbreg()
{
#ifdef PT_GETDBREGS
	_write_reg(PT_SETDBREGS, _target.dbreg);
#else
	ptrace_arch_write_dbreg();
#endif
}

void ptrace_help(/*@unused@*/char *prog_name)
{
}

#define PTRACE_ERROR_TRACEME       125
#define PTRACE_ERROR_RAISE_SIGSTOP 124
#define PTRACE_ERROR_EXECV         123
#define PTRACE_ERROR_ATTACH        122
#define PTRACE_ERROR_INTERNAL      121


static int _yamma_check()
{
	int ret = 0;
	int fd = -1;
	fd = open("/proc/sys/kernel/yama/ptrace_scope", O_RDONLY);
	if (fd >= 0) {
		ssize_t got = -1;
		char buf[0x10];
		memset(&buf[0], 0, sizeof(buf));
		got = read(fd, buf, sizeof(buf) - 1);
		if (got > 0) {
			ret = atoi(&buf[0]);
		}
		if (0 != close(fd)) {
			DBG_PRINT("Error closing file descriptor for yamma check\n");
		}
		fd = -1;
	}
	return ret;
}

int ptrace_attach(pid_t process_id)
{
	int ret = RET_ERR;
	int status;
	pid_t wait_child;

	if (0 != ptrace(PT_ATTACH, process_id, 0, 0)) {
		/* Failure */
		DBG_PRINT("Error attaching to pid %d\n", process_id);

		/* Check for security */
		if (_yamma_check()) {
			DBG_PRINT("Failure caused by YAMA security setting of %d\n", ret);
			DBG_PRINT("Recommend as root : \n");
			DBG_PRINT("# echo \"0\" > /proc/sys/kernel/yama/ptrace_scope\n");
		}
	} else {
		/* Success */
		wait_child = waitpid(process_id, &status, 0);
		if (wait_child == process_id) {
			/* Check for error / early exit */
			if (WIFEXITED(status)) {
				int __attribute__((unused)) exit_status;
				exit_status = WEXITSTATUS(status);

				DBG_PRINT("Debuggee %d exited with %d\n",
					  process_id, exit_status);
			} else {
				/* Check that process stopped because of implied SIGSTOP */
				if (WIFSTOPPED(status) &&
				    (WSTOPSIG(status) == SIGSTOP)) {

					if (target_new_thread(process_id, process_id)) {
					    ptrace_arch_option_set_thread(process_id);
					    ret = RET_OK;
					}

				} else {
					/* Unexpected */
					DBG_PRINT("ptrace unexpected wait status\n");
				}
			}
		} else {
			/* Unexpected */
			DBG_PRINT("ptrace unexpected wait return\n");
		}
	}
	return ret;
}

static int _ptrace_detach(int gdb_sig)
{
	int ret = RET_ERR;

	int sig;
	sig = ptrace_arch_signal_from_gdb(gdb_sig);
	if (sig < 0) {
		sig = 0;
	}
	if (cmdline_pid > 0) {
		if (0 != ptrace(PT_DETACH, CURRENT_PROCESS_TID, 0, sig)) {
			/* Failure */
			if (_detach_verbose) {
				DBG_PRINT("Error detaching from pid %d\n", CURRENT_PROCESS_TID);
			}
		} else {
			if (_detach_verbose) {
				DBG_PRINT("OK detaching from pid %d\n", CURRENT_PROCESS_TID);
			}
			ret = RET_OK;
		}
	}
	return ret;
}

int ptrace_detach()
{
	int ret = _ptrace_detach(0);
	return ret;
}

void ptrace_close(void)
{
}

int ptrace_connect(char *status_string,
		   size_t status_string_len, int *can_restart)
{
	return RET_NOSUPP;
}

int ptrace_disconnect(void)
{
	return RET_NOSUPP;
}


int ptrace_restart(void)
{
	int ret = RET_ERR;

	if (cmdline_argc) {
		/* fork -n- exec */
		pid_t try_child;
		try_child = fork();
		if (try_child == 0) {
			/* The child */
			if (0 != ptrace(PT_TRACE_ME, 0,
					/*@null@*/0, /*@null@*/0)) {
				_exit(PTRACE_ERROR_TRACEME);
			} else {
				/* Implied SIGTRAP when ptraced execv is successful */
				if (execv(cmdline_argv[0], cmdline_argv)) {
					_exit(PTRACE_ERROR_EXECV);
				}
				/* Not expecting to reach here.. */
				_exit(PTRACE_ERROR_INTERNAL);
			}
		} else {
			if (try_child > 0) {
				/* The parent with a child */
				int status;
				pid_t wait_child;

				wait_child = waitpid(try_child, &status, 0);
				if (wait_child == try_child) {
					/* Check for error / early exit */
					if (WIFEXITED(status)) {
						int __attribute__((unused)) exit_status;
						exit_status =
							WEXITSTATUS(status);
						DBG_PRINT("Debuggee %s exited with %d\n",
							  cmdline_argv[0], exit_status);
					} else {
						/*
						 * Check that process stopped because of implied
						 * SIGTRAP from execv
						 */
						if (WIFSTOPPED(status) &&
						    (WSTOPSIG(status) == SIGTRAP)) {

							if (target_new_thread(try_child, try_child)) {
							    ptrace_arch_option_set_thread(try_child);
							    
							    fprintf(stdout, "Process %s created; pid = %d\n", cmdline_argv[0], CURRENT_PROCESS_PID);
							    fflush(stdout);
							    ret = RET_OK;
							}

						} else {
							/* Unexpected */
							if (_restart_verbose) {
								DBG_PRINT(
									"ptrace unexpected wait status\n");
							}
						}
					}
				} else {
					/* Unexpected */
					if (_restart_verbose) {
						DBG_PRINT("ptrace unexpected wait return\n");
					}
				}
			} else {
				/* The parent without a child */
				/* Unexpected */
				if (_restart_verbose) {
					DBG_PRINT("ptrace fork failed\n");
				}
			}
		}
	}

	return ret;
}

int ptrace_open(/*@unused@*/int argc, /*@unused@*/char *argv[],
		/*@unused@*/char *prog_name)
{
	int ret = RET_ERR;

	ret = ptrace_restart();

	return ret;
}

void ptrace_stop(void)
{
	if (kill(CURRENT_PROCESS_TID, SIGINT)) {
		/* Failure */
		if (_stop_verbose) {
			DBG_PRINT("ERROR sending SIGINT to %d\n", CURRENT_PROCESS_TID);
		}
	} else {
		/* Success */
		if (_stop_verbose) {
			DBG_PRINT("OK sending SIGINT to %d\n", CURRENT_PROCESS_TID);
		}
	}
}


int ptrace_read_registers(uint8_t *data, uint8_t *avail,
			  size_t buf_size, size_t *read_size)
{
	int ret = RET_ERR;
	uint8_t *g = data;
	uint8_t *ga = avail;
	size_t s = 0;

	if (_read_greg()) {
		if (_read_freg()) {
			ptrace_arch_read_fxreg(buf_size);
		} else {
			if (_read_reg_verbose) {
				DBG_PRINT("Error reading floating point registers\n");
			}
		}

		/* Pass is just the general registers are read */
		s = _copy_greg_to_gdb(g, ga);
		if (s > 0) {
			ret = RET_OK;
		}

	} else {
		if (_read_reg_verbose) {
			DBG_PRINT("Error reading general registers\n");
		}
	}
	*read_size = s;

	return ret;
}

int ptrace_read_single_register(unsigned int gdb, uint8_t *data,
				uint8_t *avail, size_t buf_size,
				size_t *read_size)
{
	int ret = RET_ERR;


	if (_read_single_reg_verbose) {
		DBG_PRINT("%s %d\n", __func__, gdb);
	}

	int c = 0;
	if (is_reg(gdb, &c, &grll[0])) {

		_read_greg();

		if (grll[c].off < _target.reg_size) {
			size_t s = 0;
#ifdef DEEBE_BIG_ENDIAN
			if (grll[c].gdb_size > grll[c].size) {
				size_t diff = grll[c].gdb_size - grll[c].size;
				memset(data, 0, diff);
				memset(avail, 0xff, diff);
				s = diff;
			}
#endif
			/* Success */
			memcpy(data + s, _target.reg + grll[c].off,
			       grll[c].size);
			memset(avail + s, 0xff, grll[c].size);

			*read_size = s + grll[c].size;
			ret = RET_OK;
		} else {
			/* Failure */
			if (_read_single_reg_verbose) {
				DBG_PRINT("INTERNAL ERROR Problem in g read of reg %d\n", gdb);
			}
		}

	} else if (is_reg(gdb, &c, &frll[0])) {
		_read_freg();

		if (frll[c].off < _target.freg_size) {
			if (frll[c].size > 0) {
				size_t pad = 0;
				/* Success */
				memcpy(data, _target.freg + frll[c].off,
				       frll[c].size);
				memset(avail, 0xff, frll[c].size);
				/* for parts of x86_64 */
				if (frll[c].size < frll[c].gdb_size) {
					pad = frll[c].gdb_size - frll[c].size;
					memset(data + frll[c].size, 0, pad);
					memset(avail + frll[c].size, 0xff, pad);
				}
				*read_size = frll[c].size + pad;

				ret = RET_OK;
			} else {
				/* Internal error, something is wrong with fp rll */
				DBG_PRINT("INTERNAL ERROR floating point register size is 0 for reg %d %d\n", gdb, c);
			}
		} else {
			/* Failure */
			DBG_PRINT("Problem in fp read of reg %d offset %zu size %zu freg size %zu\n",
				  gdb, frll[c].off, frll[c].size, _target.freg_size);
		}

	} else if (is_reg(gdb, &c, &fxrll[0])) {

		ptrace_arch_read_fxreg(0x1000 /* XXX FIX */);

		if (fxrll[c].off < _target.fxreg_size) {
			/* Success */
			memcpy(data, _target.fxreg + fxrll[c].off,
			       fxrll[c].size);
			memset(avail, 0xff, fxrll[c].size);
			*read_size = fxrll[c].size;
			ret = RET_OK;
		} else {
			/* Failure */
			DBG_PRINT("Problem in fx read of reg %d\n", gdb);
			memset(data, 0, fxrll[c].size);
			memset(avail, 0, fxrll[c].size);
			*read_size = fxrll[c].size;
			ret = RET_OK;
		}

	} else {
		size_t pad_size = 0;
		if (ptrace_arch_check_unrecognized_register(gdb, &pad_size)) {
			/* If the register is known not to be supported, handle */
			if (pad_size > 0) {
				memset(data, 0, pad_size);
				memset(avail, 0, pad_size);
				ret = RET_OK;
			} else {
				/* no support or returning 0 pad and an ok does not work, so return default error */
				DBG_PRINT("Unhandled read of reg %d\n", gdb);
			}

			*read_size = pad_size;
		} else {
			/* Freak out */
			DBG_PRINT("Unhandled read of reg %d\n", gdb);
		}
	}

	return ret;
}

static bool _gdb_register_size(unsigned int gdb, size_t *gdb_size, size_t *size)
{
	bool ret = false;
	*gdb_size = *size = 0;
	int c = 0;
	if (is_reg(gdb, &c, &grll[0])) {
		*size = grll[c].size;
		*gdb_size = grll[c].gdb_size;
		ret = true;
	} else if (is_reg(gdb, &c, &frll[0])) {
		*size = frll[c].size;
		*gdb_size = frll[c].gdb_size;
		ret = true;
	} else if (is_reg(gdb, &c, &fxrll[0])) {
		*size = fxrll[c].size;
		*gdb_size = fxrll[c].gdb_size;
		ret = true;
	}
	return ret;
}

int ptrace_write_single_register(unsigned int gdb, uint8_t *data, size_t size)
{
	int ret = RET_ERR;

	if (_write_single_reg_verbose) {
		DBG_PRINT("%s %d %p %zu\n", __func__, gdb, data, size);
		util_print_buffer(fp_log, 0, size, data);
	}

	int c = 0;
	if (is_reg(gdb, &c, &grll[0])) {

		_read_greg();

		if (grll[c].off < _target.reg_size) {
			/* Success */
			size_t s = 0;
#ifdef DEEBE_BIG_ENDIAN
			/* For mips32 in 64 bit compatiblity mode */
			if (size > grll[c].size) {
				size_t diff = size - grll[c].size;
				s = diff;
			}
#endif
			memcpy(_target.reg + grll[c].off, data + s,
			       grll[c].size);

			_write_greg();

			ret = RET_OK;
		} else {
			/* Failure */
			DBG_PRINT("Problem in g read of reg %d\n", gdb);
		}

	} else if (is_reg(gdb, &c, &frll[0])) {
		_read_freg();
		if (frll[c].off < _target.freg_size) {
			/* Success */
			memcpy(_target.freg + frll[c].off, data, frll[c].size);
			_write_freg();

			ret = RET_OK;
		} else {
			/* Failure */
			DBG_PRINT("Problem in fp read of reg %d\n", gdb);
		}

	} else if (is_reg(gdb, &c, &fxrll[0])) {

		ptrace_arch_read_fxreg();
		/*
		 * It is possible for the fx reg read to fail
		 * because the registers are not supported or
		 * available on the machine.  When this happens
		 * nothing is read and the fxreg_size is 0
		 *
		 * Treat this as an unrecognized register
		 */
		if (0 == _target.fxreg_size) {
			/* Failure */
			DBG_PRINT("Warning : coping with fx read failure\n");
			ret = RET_NOSUPP;
		} else {
			/* Read at least partially succeeded */
			if (fxrll[c].off < _target.fxreg_size) {
				/* Success */
				memcpy(_target.fxreg + fxrll[c].off,
				       data, fxrll[c].size);
				ptrace_arch_write_fxreg();

				ret = RET_OK;
			} else {
				/* Failure */
				DBG_PRINT("INTERNAL ERROR : Problem in fx read of reg %d\n", gdb);
			}
		}

	} else {
		size_t pad_size = 0;
		if (ptrace_arch_check_unrecognized_register(gdb, &pad_size)) {
			/* Unsupported */
			ret = RET_NOSUPP;
		} else {
			/* Freak out */
			DBG_PRINT("INTERNAL ERROR : Unhandled read of reg %d\n", gdb);
		}
	}
	return ret;
}

int ptrace_write_registers(uint8_t *data, size_t size)
{
	int ret = RET_ERR;

	unsigned int gdb = 0;
	size_t done = 0;

	while (done < size) {
		size_t gdb_size, r_size;
		if (_gdb_register_size(gdb, &gdb_size, /*@unused@*/&r_size)) {
			if (done + gdb_size > size) {
				break;
			} else if (!gdb_size) {
				break;
			}
			if (RET_OK !=
			    ptrace_write_single_register(gdb,
							 &data[done],
							 gdb_size)) {
				break;
			}
		} else {
			DBG_PRINT("INTERNAL ERROR : Unhandled write of reg %d\n", gdb);
			break;
		}

		done += gdb_size;
		gdb++;
	}

	if (done == size) {
		ret = RET_OK;
	}

	return ret;
}

/*
 * read mem is used by breakpoint creation
 * So break out the reading parts from the
 * public interface
 */
int _ptrace_read_mem(uint64_t addr, uint8_t *data, size_t size,
		     size_t *read_size, bool breakpoint_check)
{
	size_t kbuf_size = 0;
	size_t tran_size = sizeof(ptrace_return_t);
	size_t mask = tran_size - 1;
	size_t leading = 0;
	size_t trailing = 0;
	ptrace_return_t *a = NULL;
	int ret = RET_ERR;
	/* Linux kernel uses unsigned long's internally */
	/* This cast may need to be cleaned up */
	unsigned long kb_addr = (unsigned long) addr;
	unsigned long ke_addr = kb_addr + size;

	/* align */
	leading = kb_addr & mask;
	kb_addr -= leading;
	trailing = ke_addr & mask;
	if (trailing) {
		ke_addr += tran_size - trailing;
	}
	kbuf_size = (ke_addr - kb_addr) / tran_size;

	a = (ptrace_return_t *) malloc(kbuf_size * tran_size);
	if (a) {
		size_t i;
		for (i = 0; i < kbuf_size; i++) {
			void *l = (void *)(kb_addr + i * tran_size);
			errno = 0;
			a[i] = ptrace(PT_READ_D, CURRENT_PROCESS_TID, l, 0);
			if (errno) {
				if (_read_mem_verbose) {
					DBG_PRINT("Error with failed to read %p\n", l);
					DBG_PRINT("leading %zu trailing %zu\n",
						  leading, trailing);
				}
				break;
			}
		}
		if (i == kbuf_size) {
			/* Success */
			uint8_t *b = (uint8_t *) a;
			b += leading;
			memcpy(data, b, size);
			if (NULL != read_size)
				*read_size = size;

			/*
			 * If a read memory region overlaps an existing breakpoint,
			 * The contents of the data buffer contain the breakpoint
			 * and not the original memory.  To recover this memory
			 * run the data buffer through the breakpoint memory
			 * adjuster.
			 */
			if (breakpoint_check) {
				breakpoint_adjust_read_buffer(_target.bpl,
							      _read_mem_verbose,
							      kb_addr + leading,
							      size, data);
			}

			ret = RET_OK;
		} else {
			/* Failure */
			if (_read_mem_verbose) {
				DBG_PRINT("ERROR only read %zu of %zu\n",
					  i, kbuf_size);
			}
		}
		free(a);
		a = NULL;
	} else {
		/* Failure */
		if (_read_mem_verbose) {
			DBG_PRINT("ERROR Allocating buffer for memory read of size %zu\n",
				  kbuf_size * tran_size);
		}
	}
	return ret;
}


int ptrace_read_mem(uint64_t addr, uint8_t *data, size_t size,
		    size_t *read_size)
{
	int ret;
	ret = _ptrace_read_mem(addr, data, size, read_size,
			       true /*breakpoint check*/);

	return ret;
}

static int _ptrace_write_mem(uint64_t addr, uint8_t *data,
			     size_t size, bool breakpoint_check)
{
	size_t kbuf_size = 0;
	size_t tran_size = sizeof(ptrace_return_t);
	size_t mask = tran_size - 1;
	size_t leading = 0;
	size_t trailing = 0;
	ptrace_return_t *a = NULL;
	int ret = RET_ERR;
	/* Linux kernel uses unsigned long's internally */
	/* This cast may need to be cleaned up */
	unsigned long kb_addr = (unsigned long) addr;
	unsigned long ke_addr = kb_addr + size;

	/* align */
	leading = kb_addr & mask;
	kb_addr -= leading;
	trailing = ke_addr & mask;
	if (trailing) {
		ke_addr += tran_size - trailing;
	}
	kbuf_size = (ke_addr - kb_addr) / tran_size;
	a = (ptrace_return_t *) malloc(kbuf_size * tran_size);

	if (a) {
		int err = 0;
		size_t i = 0;
		void *l = NULL;

		/*
		 * If there is leading or trailing data, the
		 * buffer is a mix of what is already there
		 * and what is being written now.
		 * Fetch just the leading and trailing data
		 */
		if (leading) {
			i = 0;
			l = (void *)(kb_addr + i * tran_size);
			errno = 0;
			a[i] = ptrace(PT_READ_D, CURRENT_PROCESS_TID, l, 0);
			if (errno) {
				if (_write_mem_verbose) {
					DBG_PRINT("Error with reading data at %p\n", l);
				}
				err = 1;
			}
		}
		if (trailing && !err) {
			i = kbuf_size - 1;
			/* No double tap */
			if (i || !leading) {
				l = (void *)(kb_addr + i * tran_size);
				errno = 0;
				a[i] = ptrace(PT_READ_D, CURRENT_PROCESS_TID, l, 0);
				if (errno) {
					if (_write_mem_verbose) {
						DBG_PRINT("Error with reading data at %p\n", l);
					}
					err = 1;
				}
			}
		}
		/* Copy the user data */
		if (!err) {
			uint8_t *b = (uint8_t *) &a[0];
			b += leading;
			memcpy(b, data, size);

			/*
			 * If a write memory region overlaps an existing breakpoint,
			 * The breakpoint needs to update is memory location
			 * and the code for the breakpoint insn should not change.
			 */
			if (breakpoint_check) {
				breakpoint_adjust_write_buffer(_target.bpl, _read_mem_verbose,
							       kb_addr + leading,
							       size, data);
			}

			for (i = 0; i < kbuf_size; i++) {
				void *l = (void *)(kb_addr + i * tran_size);
	
				if (0 != ptrace(PT_WRITE_D, CURRENT_PROCESS_TID,
						l, a[i])) {
					if (_write_mem_verbose) {
						DBG_PRINT("Error with write data at %p\n", l);
					}
					break;
				}
			}

			if (i == kbuf_size) {
				/* Success */


				ret = RET_OK;
			} else {
				/* Failure */
				;
			}
		}
		free(a);
		a = NULL;
	} else {
		/* Failure */
		;
	}
	return ret;
}

int ptrace_write_mem(uint64_t addr, uint8_t *data, size_t size)
{
	int ret;
	ret = _ptrace_write_mem(addr, data, size, true /* breakpoint check */);
	return ret;
}

int ptrace_resume_from_current(int step, int gdb_sig)
{
	int ret = RET_ERR;
#ifdef PT_SYSCALL
	/* 
	 * For FreeBSD
	 * Use PT_SYSCALL to continue but stop at syscall exits
	 * This is done to be notified when a thread has been created
	 * and when a thread is about to be destroyed.
	 * If this is a single step, then the single step request will
	 * take precedence.
	 */
	long request = PT_SYSCALL;
#else
	long request = PT_CONTINUE;
#endif
	int sig;

	_target.step = step;
	_target.current_gdb_signal = gdb_sig;

	sig = ptrace_arch_signal_from_gdb(gdb_sig);
	if (sig < 0) {
		sig = 0;
	}

	if (step == 1) {
		ptrace_arch_set_singlestep(CURRENT_PROCESS_TID, &request);
	} else {
		ptrace_arch_clear_singlestep(CURRENT_PROCESS_TID);
	}

	/* TODO : Map sig to arg4 */
	if (0 == PTRACE(request, CURRENT_PROCESS_TID, 1, sig)) {
		/* Success */
		_target.current_signal = sig;
		if (sig)
			_target.ps = PS_SIG_PENDING;
		else
			_target.ps = PS_RUN;
		ret = RET_OK;
	} else {
		/* Failure */
		if (_resume_current_verbose) {
			DBG_PRINT("%s Error%d %d\n", __func__, step, sig);
		}
	}

	if (_resume_current_verbose) {
		DBG_PRINT("%s %d gdb %d sig %d -> ret %d\n",
			  __func__, step, gdb_sig, sig, ret);
	}

	return ret;
}

int ptrace_resume_with_syscall(void)
{
	int ret = RET_ERR;
#ifdef PT_SYSCALL
	errno = 0;
	if (0 == PTRACE(PT_SYSCALL, CURRENT_PROCESS_TID, PT_SYSCALL_ARG3, 0)) {
		/* Success */
		_target.ps = PS_RUN;
		ret = RET_OK;
	} else {
		/* Failure */
		if (_resume_syscall_verbose) {
			char str[128];
			memset(&str[0], 0, 128);
			DBG_PRINT("Error in %s\n", __func__);
			if (0 == strerror_r(errno, &str[0], 128)) {
				DBG_PRINT("Error %d %s\n", errno, str);
			} else {
				DBG_PRINT("Error %d\n", errno);
			}
		}
	}
#endif
	return ret;
}

int ptrace_resume_from_addr(int step, int gdb_sig, uint64_t addr)
{
	int ret = RET_ERR;
#ifndef DEEBE_RELEASE
	unsigned long kb_addr = (unsigned long) addr;
#endif

	int sig;
	sig = ptrace_arch_signal_from_gdb(gdb_sig);
	if (sig < 0) {
		sig = 0;
	}

	if (_resume_from_addr_verbose) {
		DBG_PRINT("ERROR NEED TO SUPPORT %s %d %d 0x%lx\n",
			  __func__, step, sig, kb_addr);
	}

	return ret;
}

void ptrace_quick_kill(void)
{
	kill(CURRENT_PROCESS_TID, SIGKILL);
}

void ptrace_quick_signal(int gdb_sig)
{
#if 0
	/* This is how the routine should work */
	int sig;
	sig = ptrace_arch_signal_from_gdb(gdb_sig);
	if (sig > 0)
		kill(CURRENT_PROCESS_TID, sig);
#endif
	/* But be blunt */
	kill(CURRENT_PROCESS_TID, SIGTRAP);
}

void ptrace_kill(void)
{
	if (cmdline_pid > 0) {
		_ptrace_detach(SIGKILL);
	} else {
		ptrace_resume_from_current(0, SIGKILL);
	}
}

int ptrace_go_waiting(int gdb_sig)
{
	int sig;
	sig = ptrace_arch_signal_from_gdb(gdb_sig);
	if (sig < 0) {
		sig = 0;
	}

	DBG_PRINT("ERROR NEED TO SUPPORT %s %d \n", __func__, sig);


	return RET_ERR;
}

int ptrace_wait_partial(int first, char *status_string,
			size_t status_string_len,
			int *implemented, int *more)
{
	int ret = RET_ERR;

	if (_wait_partial_verbose) {
		DBG_PRINT("%s %d %s %zu %p %p\n",
			  __func__, first, status_string, status_string_len,
			  implemented, more);
	}

	/*
	 * Defer to wait routine
	 * This depends strongly on the logic in the calling function
	 */
	ret = RET_OK;
	*implemented = 0;
	*more = 0;

	return ret;
}

int ptrace_offsets_query(uint64_t *text, uint64_t *data, uint64_t *bss)
{
	*text = 0;
	*data = 0;
	*bss = 0;
	return RET_OK;
}

int ptrace_crc_query(uint64_t addr, size_t len, uint32_t *val)
{
	return RET_ERR;
}

int ptrace_raw_query(char *in_buf, char *out_buf, size_t out_buf_size)
{
	return RET_ERR;
}

int ptrace_add_break(int type, uint64_t addr, size_t len)
{
	int ret = RET_ERR;

	unsigned long kaddr = (unsigned long) addr;

	ret = RET_ERR;
	if (_add_break_verbose) {
		DBG_PRINT("%s %d %lx %zu\n",
			  __func__, type, kaddr, len);
	}

	if ((type == GDB_INTERFACE_BP_READ_WATCH) ||
	    (type == GDB_INTERFACE_BP_WRITE_WATCH) ||
	    (type == GDB_INTERFACE_BP_ACCESS_WATCH)) {
		if (ptrace_arch_support_watchpoint(type)) {
			if (ptrace_arch_add_watchpoint(CURRENT_PROCESS_TID,
						       type, addr, len)) {
				ret = RET_OK;
				if (_add_break_verbose) {
					DBG_PRINT("OK setting watchpoint at 0x%lx\n", kaddr);
				}
			} else {
				if (_add_break_verbose) {
					DBG_PRINT("ERROR setting watchpoint at 0x%lx\n", kaddr);
				}
			}
		} else {
			ret = RET_NOSUPP;
			if (_add_break_verbose) {
				DBG_PRINT("Watchpoints type %d is not supported\n", type);
			}
		}
	} else if (type == GDB_INTERFACE_BP_SOFTWARE) {
		/* Add to general list first */
		struct breakpoint *bp = NULL;
		bp = breakpoint_add(&_target.bpl, _add_break_verbose,
				    kaddr, type, len);
		if (bp) {
			/* Get the arch specific break insn */
			ret = ptrace_arch_swbreak_insn(bp->bdata);
			if (ret == RET_OK) {
				size_t read_size;
				/* Read and save off the memory location that the break is goint to */
				ret = _ptrace_read_mem(addr, bp->data,
						       bp->len, &read_size,
						       false);

				if (ret == RET_OK) {
					/* Now write the sw break insn in it's place */
					ret = _ptrace_write_mem(addr, bp->bdata,
								bp->len, false);
					if (ret == RET_OK) {
						if (_add_break_verbose) {
							DBG_PRINT("OK setting breakpoint at 0x%lx\n", kaddr);
						}
					} else {
						/* Failure */
						if (_add_break_verbose) {
							DBG_PRINT("ERROR writing breakpoint at 0x%lx\n", kaddr);
						}
						breakpoint_remove(&_target.bpl, _add_break_verbose, kaddr);
					}
				} else {
					/* Failure */
					if (_add_break_verbose) {
						DBG_PRINT("ERROR reading data for breakpoint at 0x%lx\n", kaddr);
					}
					breakpoint_remove(&_target.bpl,
							  _add_break_verbose,
							  kaddr);
				}
			} else {
				/* Failure */
				if (_add_break_verbose) {
					DBG_PRINT("INTERNAL ERROR with ARCH breakpoint at 0x%lx\n", kaddr);
				}
				breakpoint_remove(&_target.bpl,
						  _add_break_verbose, kaddr);
			}
		} else {
			if (_add_break_verbose) {
				DBG_PRINT("INTERNAL ERROR creating breakpoint at 0x%lx\n", kaddr);
			}
		}
	} else {
		if (_add_break_verbose) {
			DBG_PRINT("Warning unsupported breakpoint type %d at 0x%lx\n", type, kaddr);
		}
		ret = RET_NOSUPP;
	}

	return ret;
}

int ptrace_remove_break(int type, uint64_t addr, size_t len)
{
	int ret = RET_ERR;
	unsigned long kaddr = (unsigned long) addr;

	if (_remove_break_verbose) {
		DBG_PRINT("%s %d %lx %zu\n",
			  __func__, type, kaddr, len);
	}

	if ((type == GDB_INTERFACE_BP_READ_WATCH) ||
	    (type == GDB_INTERFACE_BP_WRITE_WATCH) ||
	    (type == GDB_INTERFACE_BP_ACCESS_WATCH)) {
		if (ptrace_arch_support_watchpoint(type)) {
			if (ptrace_arch_remove_watchpoint(CURRENT_PROCESS_TID, type, addr, len)) {
				ret = RET_OK;
				if (_remove_break_verbose) {
					DBG_PRINT("OK removing watchpoint at 0x%lx\n", kaddr);
				}
			} else {
				if (_remove_break_verbose) {
					DBG_PRINT("ERROR removing watchpoint at 0x%lx\n", kaddr);
				}
			}
		} else {
			ret = RET_NOSUPP;
			if (_remove_break_verbose) {
				DBG_PRINT("Watchpoint type %d is not supported\n", type);
			}
		}
	} else if (type == GDB_INTERFACE_BP_SOFTWARE) {
		struct breakpoint *bp = NULL;
		bp = breakpoint_find(_target.bpl, _remove_break_verbose, kaddr);
		if (bp) {
			/*
			 * Only really remove the breakpoint if it's reference count
			 * is one.
			 */
			if (1 == bp->ref_count) {
				ret = _ptrace_write_mem(addr,
							bp->data, bp->len,
							false);
				if (ret == RET_OK) {
					breakpoint_remove(&_target.bpl,
							  _remove_break_verbose,
							  kaddr);
					if (_add_break_verbose) {
						DBG_PRINT("OK removing breakpoint at 0x%lx\n", kaddr);
					}
				} else {
					/* Failure */
					if (_add_break_verbose) {
						DBG_PRINT("ERROR restoring data for breakpoint at 0x%lx\n", kaddr);
					}
				}
			} else {
				/* This just decrements the ref_count */
				breakpoint_remove(&_target.bpl,
						  _remove_break_verbose, kaddr);
				ret = RET_OK;
			}

		} else {
			if (_add_break_verbose) {
				DBG_PRINT("Warning problem removing breakpoint at 0x%lx\n", kaddr);
			}
		}
	} else {
		if (_remove_break_verbose) {
			DBG_PRINT("Warning unsupported breakpoint type %d at 0x%lx\n", type, kaddr);
		}
		ret = RET_NOSUPP;
	}

	return ret;
}

int ptrace_wait(char *status_string, size_t status_string_len)
{
	int ret = RET_ERR;
	int current_status = 0;
	pid_t pid = -1;

	if (_wait_verbose) {
		DBG_PRINT("%s %p %zu\n", __func__,
			  status_string, status_string_len);
	}

	/* Could be waiting awhile, turn on sigio */
	signal_sigio_on();

	if (PS_SIG_PENDING == _target.ps) {
		int errs_max = 5;
		int errs = 0;
		for (errs = 0; errs < errs_max; errs++) {
			/* Sleep for a msec */
			usleep(100);
			pid = waitpid(CURRENT_PROCESS_TID, &current_status, WNOHANG);
			if (pid == CURRENT_PROCESS_TID) {
				break;
			} else {
				/* failure */
				if (errs + 2 < errs_max)
					kill(CURRENT_PROCESS_TID,
					     _target.current_signal);
				else
					kill(CURRENT_PROCESS_TID, SIGTRAP);
				usleep(100);
			}
		}
		if (errs >= errs_max) {
			DBG_PRINT("Signal lost\n");
			/* Lie */
			ret = RET_OK;
		}

	} else {
	    
	    if (ptrace_arch_wait_new_thread(&pid, &current_status)) {
		/* Success */
		
		snprintf(status_string, status_string_len,
			 "Tthread:%x;", pid);

		ret = RET_OK;

	    } else {

		if ((pid == CURRENT_PROCESS_TID) ||
		    (pid == CURRENT_PROCESS_PID)) {

		    uint8_t g = 0;
		
		    if (WIFSTOPPED(current_status)) {
			int s = WSTOPSIG(current_status);
			unsigned long watchpoint_addr = 0;
			/* Normal signal */
			_target.current_signal = s;
			
			unsigned long pc = 0;
			ptrace_arch_get_pc(&pc);
			
			if (_wait_verbose) {
			    DBG_PRINT("stopped at pc 0x%lx\n", pc);
			    if (pc) {
				uint8_t b[32] = { 0 };
				size_t read_size = 0;
				ptrace_read_mem(pc, &b[0], 32,
						&read_size);
				util_print_buffer(fp_log, 0, 32, &b[0]);
			    }
			}
			
			if (ptrace_arch_check_new_thread(CURRENT_PROCESS_TID, current_status, &pid)) {

			    /* Check if handled check returns a valid response */
			    if (pid > 0) {

				snprintf(status_string, status_string_len,
					 "T%02xthread:%x;", 5, pid); 

				ret = RET_OK;

			    } else {

				/* 
				 * If there was any event but a new pid was not created
				 * then send an 'ignore' return to the calling function.
				 * It is the responsibly of that function to continue
				 * execution and wait for the next event.
				 */
				ret = RET_IGNORE;
			    }
			    
			} else if (ptrace_arch_check_syscall(CURRENT_PROCESS_TID, &s)) {

			    /* Check for syscall */
			    
			    /* sycall entry or exit */
			    if (_target.syscall_enter) {
				/* This assumes no breakpoints etc.. */
				_target.ps = PS_SYSCALL_EXIT;
				_target.syscall_enter = false;
			    } else {
				_target.ps = PS_SYSCALL_ENTER;
				_target.syscall_enter = true;
			    }
			    /* signal is optionally
			       modified by *_check_syscall */
			    snprintf(status_string, status_string_len,
				     "T%02x",
				     ptrace_arch_signal_to_gdb(s));
			} else {
			    /* break point or watch point */
			    
			    /* Second guess the kernel */
			    if (s != SIGTRAP) {
				if (pc) {
				    if (NULL != breakpoint_find(_target.bpl, _wait_verbose, pc)) {
					s = SIGTRAP;
				    }
				}
			    }
			    
			    g = ptrace_arch_signal_to_gdb(s);
			    if (_wait_verbose) {
				DBG_PRINT("Wait STOPPED %d %d\n", s, g);
			    }
			    
			    /* Fill out the status string */
			    if (ptrace_arch_hit_watchpoint(CURRENT_PROCESS_TID, &watchpoint_addr)) {
				/* A watchpoint was hit */
				snprintf(status_string, status_string_len, "T%02xwatch:%lx;", g, watchpoint_addr);
				ret = RET_OK;
			    } else {
				/* A normal breakpoint was hit */
				snprintf(status_string, status_string_len, "T%02x", g);
				ret = RET_OK;

			    }
			    
			    _target.ps = PS_STOP;

			}

		    } else if (WIFEXITED(current_status)) {

			/*
			 * returns true if the child terminated normally, that is,
			 * by calling exit(3) or _exit(2), or by returning from main().
			 */
			
			int s = WEXITSTATUS(current_status);
			pid_t pid, tid;
			pid = CURRENT_PROCESS_PID;
			tid = CURRENT_PROCESS_TID;

			/*
			 * returns the exit status of the  child.   This  consists  of  the
			 * least  significant  16-8  bits  of  the status argument that the
			 * child specified in a call to exit() or _exit() or as  the  argu-
			 * ment  for  a return statement in main().  This macro should only
			 * be employed if WIFEXITED returned true.
			 */

			if (_wait_verbose) {
			    DBG_PRINT("Wait EXITED %lx:%lx with %d\n", pid, tid, s);
			}
			

			if (pid == target_get_pid()) {
			    /* Check if this is the parent process */
			    
			    _target.ps = PS_EXIT;
			    
			    /* Fill out the status string */
			    snprintf(status_string, status_string_len, "W%02x", s);
			} else {
			    int index;
			    
			    /* 
			     * A thread has exited, set it's alive state to false
			     * and switch to the parent process
			     */
			    CURRENT_PROCESS_ALIVE = false;
			    
			    /* Ingnore non children, because the clone returns before the parent */
			    for (index = 0; index < _target.number_processes; index++) {
				if (PROCESS_TID(index) == pid) {
				    _target.current_process = index;
				    break;
				}
			    }

			    snprintf(status_string, status_string_len,
				     "T%02xthread:%x;", 
				     0 /* No signal */, 
				     CURRENT_PROCESS_TID);
			}

			ret = RET_OK;

		    } else if (WIFSIGNALED(current_status)) {
			
			/* returns true if the child process
			   was terminated by a signal. */
			
			int s = WTERMSIG(current_status);
#ifndef DEEBE_RELEASE
			int c = WCOREDUMP(current_status);
#endif
			g = ptrace_arch_signal_to_gdb(s);
			if (_wait_verbose) {
			    DBG_PRINT("Wait SIGNALED %d cored %d - %d\n", s, c, g);
			}
			snprintf(status_string, status_string_len, "X%02x", g);
			
			_target.ps = PS_SIG;
			
			ret = RET_OK;

		    } else if (WIFCONTINUED(current_status)) {

			if (_wait_verbose) {
			    DBG_PRINT("Wait CONTINUED\n");
			}
			_target.ps = PS_CONT;
			ret = RET_OK;
		    } else {

			if (_wait_verbose) {
			    DBG_PRINT("Internal error : Unhandled wait status %d\n", current_status);
			}
			_target.ps = PS_ERR;
		    }

		} else {
		    /* Failure */
		    if (_wait_verbose) {
			DBG_PRINT("%s wait returned unexpect pid %x vs %x or %x\n",
				  __func__, pid, CURRENT_PROCESS_TID, CURRENT_PROCESS_PID);
		    }
		    _target.ps = PS_ERR;
		}
	    }
	}
	if (_wait_verbose) {
	    DBG_PRINT("%s returns %d\n", __func__, ret);
	}
	    
	/* Finished waiting, turn off sigio */
	signal_sigio_off();
	
	return ret;
}

int ptrace_threadinfo_query(int first, char *out_buf, size_t out_buf_size)
{
  int ret = RET_ERR;
  static int n;
  if (first) {
    n = 0;
  } else {
    n++;
  }
  if (n < _target.number_processes) {
    pid_t t = PROCESS_TID(n);
    if (n+1 == _target.number_processes)
      sprintf(out_buf, "m %x,l", t);
    else
      sprintf(out_buf, "m %x", t);
    ret = RET_OK;
  } else {
    sprintf(out_buf, "m l");
  }
  return ret;
}


int ptrace_supported_features_query(char *out_buf, size_t out_buf_size)
{
	int ret = RET_ERR;
	char str[128];

	size_t c = 1;
	sprintf(str, "PacketSize=%x;", GDB_INTERFACE_PARAM_DATABYTES_MAX);
	if (((strlen(str)) + c) < out_buf_size) {
		strcat(out_buf, str);
		c += strlen(str);
	}

	if (_target.multiprocess) {
		/* Support multi process extensions */
		sprintf(str, "multiprocess+;");
		if (((strlen(str)) + c) < out_buf_size) {
			strcat(out_buf, str);
			c += strlen(str);
		}
	}

#if 0
	sprintf(str, "QPassSignals+;");
	if (((strlen(str)) + c) < out_buf_size) {
		strcat(out_buf, str);
		c += strlen(str);
	}
	sprintf(str, "QProgramSignals+;");
	if (((strlen(str)) + c) < out_buf_size) {
		strcat(out_buf, str);
		c += strlen(str);
	}
#endif


#if 0
	/* Disabling because it cause gdb to
	   ignore errors on unsupported features */
	sprintf(str, "QStartNoAckMode+;");
	if (((strlen(str)) + c) < out_buf_size) {
		strcat(out_buf, str);
		c += strlen(str);
	}
#endif


	if (c > 1) {
		ret = RET_OK;
	}

	return ret;
}

int ptrace_get_signal(void)
{
	return _target.current_signal;
}

static int _parseHexList(char *inbuf)
{
	return -1;
}

int ptrace_general_set(char *inbuf, char *outbuf, size_t size)
{
	int ret = RET_ERR;
	char str[128];
	if (_general_set_verbose) {
		DBG_PRINT("%s %p %p %zu\n", __func__, inbuf, outbuf, size);
	}

	sprintf(str, "QPassSignals;");
	if (strncmp(inbuf, str, strlen(str)) == 0) {
		int sig;
		inbuf += strlen(str);

		if (_general_set_verbose) {
			DBG_PRINT("%s %p %p %zu\n",
				  __func__, inbuf, outbuf, size);
		}

#if 0
		size_t i;

		/* Initialize */
		for (i = 0; i < CURRENT_PROCESS_PTRACE_SIGNAL_MAX; i++) {
			pass_sig[i] = i;
		}
#endif
		while ((sig = _parseHexList(inbuf)) > 1) {

		}
		/* Parse and update */
		/* XXX : TBD */
		ret = RET_OK;
	}
#if 0

	sprintf(str, "QProgramSignals;");
	if (strncmp(inbuf, str, strlen(str)) == 0) {
		inbuf += strlen(str);

		size_t i;

		/* Initialize */
		for (i = 0; i < CURRENT_PROCESS_PTRACE_SIGNAL_MAX; i++) {
			program_sig[i] = i;
		}
		/* Parse and update */
		/* XXX : TBD */


		ret = RET_OK;
	}

#endif

	sprintf(str, "QStartNoAckMode");
	if (strncmp(inbuf, str, strlen(str)) == 0) {
		_target.no_ack = 1;
		ret = RET_OK;
	}

	return ret;
}


int ptrace_no_ack()
{
	return _target.no_ack;
}

enum process_state ptrace_get_process_state(void)
{
	return _target.ps;
}

void ptrace_option_set_syscall()
{
	ptrace_arch_option_set_syscall(CURRENT_PROCESS_TID);
}

void ptrace_get_syscall(void *id, void *arg1, void *arg2,
			void *arg3, void *arg4, void *ret)
{
	ptrace_arch_get_syscall(id, arg1, arg2, arg3, arg4, ret);
}
