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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include "dsignal.h"
#include "global.h"
#include "macros.h"
#include "util.h"

#define NO_TIMEOUT_PROGRESS

/*
 * Input record and playback
 *
 * If NETWORK_INPUT_RECORD is defined, the input from the debugger is recorded
 * to a text file.  Each receive is delimited by a newline. 
 * The text file is 'deebe.playback' and is created in the current
 * working directory.
 *
 * If NETWORK_INPUT_PLAYBACK is defined, the text file 'deebe.playback' is
 * read from the current working directory.
 * The normal network processing is subverted.
 * Instead of reading from an input socket from the debugger, the
 * the input is read back a line at a time from the playback file.
 * Since there is no debugger listening for output, the output is
 * dropped.
 */
/* #define NETWORK_INPUT_RECORD */
/* #define NETWORK_INPUT_PLAYBACK */

#if defined(NETWORK_INPUT_PLAYBACK) && defined(NETWORK_INPUT_RECORD)
#error "NETWORK_INPUT_PLAYBACK and NETWORK_INPUT_RECORD can not both be defined at the same time"
#endif

#if defined(NETWORK_INPUT_PLAYBACK) || defined(NETWORK_INPUT_RECORD)
static FILE *fp_playback;
#endif

static bool network_verbose = false;
#ifndef NETWORK_INPUT_PLAYBACK
/* No timeout in playback, this variable is unused */
static bool network_verbose_timeout = false;
#endif
static bool network_verbose_print_read_buffer = false;
static bool network_verbose_print_write_buffer = false;


void network_print()
{
	DBG_PRINT("network : listen sd          : %d\n", network_listen_sd);
	DBG_PRINT("network : client sd          : %d\n", network_client_sd);
	DBG_PRINT("network : in buffer total    : %zu\n",
		  network_in_buffer_total);
	DBG_PRINT("network : in buffer current  : %zu\n",
		  network_in_buffer_current);
	DBG_PRINT("network : read buffer\n");
	util_print_buffer(fp_log, network_in_buffer_current,
			  network_in_buffer_total,
			  &network_in_buffer[0]);
	DBG_PRINT("network : out buffer total   : %zu\n",
		  network_out_buffer_total);
	DBG_PRINT("network : out buffer current : %zu\n",
		  network_out_buffer_current);
	DBG_PRINT("network : write buffer\n");
	util_print_buffer(fp_log, network_out_buffer_current,
			  network_out_buffer_total,
			  &network_out_buffer[0]);
}

void network_cleanup()
{
	memset(&network_address, 0, sizeof(struct sockaddr_in));
	if (network_listen_sd > 0) {
		if (0 != close(network_listen_sd)) {
			if (network_verbose) {
				DBG_PRINT("network : Error closing the listen socket\n");
			}
		}
	}
	network_listen_sd = -1;
	memset(&network_client_address, 0, sizeof(struct sockaddr_in));
	if (network_client_sd > 0) {
		if (0 != close(network_client_sd)) {
			if (network_verbose) {
				DBG_PRINT("network : Error closing the client socket\n");
			}
		}
	}
	network_client_sd = -1;
	network_client_address_size = (socklen_t) sizeof(struct sockaddr_in);
	network_out_buffer_current = 0;
	network_out_buffer_total = 0;
	network_in_buffer_current = 0;
	network_in_buffer_total = 0;

#if defined(NETWORK_INPUT_PLAYBACK) || defined(NETWORK_INPUT_RECORD)
	if (fp_playback) {
		fflush(fp_playback);
		fclose(fp_playback);
		fp_playback = NULL;
	}
#endif
}


bool _set_net(struct sockaddr_in *sockadd, char *net)
{
	bool ret = true;
	if (net != NULL) {
		struct in_addr inp;
		ret = false;
		if (0 != inet_aton(net, &inp)) {
			memcpy(&sockadd->sin_addr.s_addr,
			       &inp, sizeof(struct in_addr));
			ret = true;
		} else if (INADDR_NONE != inet_addr(net)) {
			in_addr_t iat;
			iat = inet_addr(net);
			memcpy(&sockadd->sin_addr.s_addr,
			       &iat, sizeof(struct in_addr));
			ret = true;
		} else if (gethostbyname(net)) {
			/* gethostbyname returns static data */
			struct hostent *h = gethostbyname(net);
			if (h) {
				if (AF_INET == h->h_addrtype) {
					/* h_length is int */
					if (h->h_length > 0) {
						size_t len = (size_t) h->h_length;
						memcpy(&sockadd->sin_addr.s_addr, h->h_addr, len);
						ret = true;
					} else {
						DBG_PRINT("INTERNAL ERROR\n");
					}
				}
			} else {
				DBG_PRINT("INTERNAL ERROR\n");
			}
		}
	}
	return ret;
}

bool network_init()
{
	bool ret = false;
	/* Cleanup possible old use */
	network_cleanup();

#ifdef NETWORK_INPUT_PLAYBACK
	/*
	 * If we are playing back, no need to create any sockets
	 * Open the playback file
	 */
	fp_playback = fopen("deebe.playback", "rt");
	if (fp_playback == NULL) {
		DBG_PRINT("network : error opening playback file deebe.playback\n");
	} else {
		ret = true;
	}
#else
	/* New socket */
	network_listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	if (network_listen_sd > 0) {
		int socket_reuse = 1;
		/*
		 * Set reuse option
		 * Assume passes, not fatal if it doesn't
		 */
		if (0 != setsockopt(network_listen_sd, SOL_SOCKET, SO_REUSEADDR,
				    (void *)&socket_reuse, sizeof(int))) {
			if (network_verbose) {
				DBG_PRINT("network : warning : failed to set listen socket reuse option\n");
			}
		}
		/*
		 * Set the network address
		 * Use the cmdline port
		 */
		network_address.sin_family = AF_INET;
		network_address.sin_port = htons(cmdline_port);
		network_address.sin_addr.s_addr = htonl(INADDR_ANY);
		/* Optional address, use if provided */
		if (!_set_net(&network_address, cmdline_net)) {
			DBG_PRINT("network : warning failed to find host %s, falling back to default\n",
				  cmdline_net);
		}
		/*
		 * Bind..
		 * Cast to sockaddr * to make compiler happy..
		 */
		if (0 != bind(network_listen_sd,
			      (const struct sockaddr *)&network_address,
			      sizeof(struct sockaddr_in))) {
			/* Failure */
			if (network_verbose) {
				DBG_PRINT("network : error binding listen socket to address %s : %ld\n",
					  cmdline_net ? cmdline_net : "localhost",
					  cmdline_port);
			}
			if (strerror(errno)) {
				fprintf(stderr, "Can't bind address: %s.\n", strerror(errno));
			} else {
				perror("Can't bind address");
			}

		} else {
			/* Listen to only 1 connection at a time. */
			if (0 != listen(network_listen_sd, 1)) {
				/* Failure */
				if (network_verbose) {
					DBG_PRINT("network : error listening on listen socket %s : %ld\n",
						  cmdline_net ? cmdline_net : "localhost",
						  cmdline_port);
				}
			} else {
				/* Defer printing until the debuggee starts */
				ret = true;
#ifdef NETWORK_INPUT_RECORD
				fp_playback = fopen("deebe.playback", "wt");
#endif
			}
		}
	} else {
		/* Failure */
		if (network_verbose) {
			DBG_PRINT("network : error creating listen socket\n");
		}
	}
#endif /* NETWORK_INPUT_PLAYBACK */
	if (!ret) {
		network_cleanup();
	}

	return ret;
}

bool network_accept()
{
	bool ret = false;
#ifdef  NETWORK_INPUT_PLAYBACK
	/* No network sockets to do anything with so return true */
	ret = true;
#else
	struct timeval timeout;
	int a = 0;
	int accept_max;

	timeout.tv_sec  = 60;
	timeout.tv_usec = 0;
#ifndef HAVE_TIMER_CREATE
	/*
	 * Older OS's (ex freebsd 6) do not have timer_create
	 * In order to support a watchdog timeout,
	 * use the network timeout here to simulate.
	 */
	static struct timeval old_time;
	if (cmdline_watchdog_minutes > 0) {
		/* get a time to compare to */
		gettimeofday(&old_time, NULL);
		accept_max = (60 * cmdline_watchdog_minutes) / timeout.tv_sec;
	} else {
		accept_max = 3600 / timeout.tv_sec; /* hour */
	}
#else
	accept_max = 3600 / timeout.tv_sec; /* hour */
#endif
	for (a = 0; a < accept_max; a++) {
		fd_set read_fd;
		int s = 0;
		FD_ZERO(&read_fd);
		FD_SET(network_listen_sd, &read_fd);
		s = select(network_listen_sd+1, &read_fd,
			   /*@null@*/NULL, /*@null@*/NULL, &timeout);
		if (s == 0) {
#ifndef NO_TIMEOUT_PROGRESS
			/* Timeout */
			fprintf(stdout, ".");
			if (0 != fflush(stdout)) {
				if (network_verbose) {
					DBG_PRINT("network : flushing stdout\n");
				}
			}
#endif
#ifndef HAVE_TIMER_CREATE
			if (cmdline_watchdog_minutes > 0) {
				struct timeval new_time;
				/* Assumes old time failed too */
				if (0 == gettimeofday(&new_time, NULL)) {
					long w = cmdline_watchdog_minutes * 60;
					long e = new_time.tv_sec -
						old_time.tv_sec;
					if (e > w) {
						WATCHDOG_ERROR();
					}
				}
			}
#endif

		} else if (s > 0) {
#ifndef NO_TIMEOUT_PROGRESS
			/* Success */
			if (a) {
				fprintf(stdout, "\n");
			}
#endif
			network_client_sd = accept(network_listen_sd,
						   (struct sockaddr *)&network_client_address,
						   &network_client_address_size);
			if (network_client_sd > 0) {
				/* Try to set socket options here */
				int one = 1;
				socklen_t len = (socklen_t) sizeof(one);
				if (0 != setsockopt(network_client_sd,
						    IPPROTO_TCP, TCP_NODELAY,
						    &one, len)) {
					/* Failure */
					if (network_verbose) {
						DBG_PRINT("network : warning : unable to set socket no-delay option\n");
					}
				}
				if (signal_sigio_off()) {
					if (signal_sigio_setup(network_client_sd)) {
						/* Success */
						ret = true;
					} else {
						if (network_verbose) {
							DBG_PRINT("network : error with sigio setup\n");
						}
					}
				} else {
					if (network_verbose) {
						DBG_PRINT("network : error with sigio\n");
					}
				}
				break;
			} else {
				/* Error */
				if (network_verbose) {
					DBG_PRINT("network : warning : problem with client accept\n");
				}
			}
		} else {
			/* Error */
			if (network_verbose) {
				DBG_PRINT("network : error with select on listen socket\n");
			}
			break;
		}
	}
	if (a == accept_max) {
		DBG_PRINT("\n");
		if (network_verbose) {
			DBG_PRINT("network : warning : no connection with client in alotted time\n");
		}
#ifndef HAVE_TIMER_CREATE
		if (cmdline_watchdog_minutes > 0) {
			WATCHDOG_ERROR();
		}
#endif
	}
#endif /* NETWORK_INPUT_PLAYBACK */
	return ret;
}

bool network_connect()
{
	bool ret = false;
#ifdef  NETWORK_INPUT_PLAYBACK
	/* No network sockets to do anything with so return true */
	ret = true;
#else
	/* New socket */
	network_fwd_sd = socket(AF_INET, SOCK_STREAM, 0);
	if (network_fwd_sd > 0) {
		int socket_reuse = 1;
		/*
		 * Set reuse option
		 * Assume passes, not fatal if it doesn't
		 */
		if (0 != setsockopt(network_fwd_sd, SOL_SOCKET, SO_REUSEADDR,
				    (void *)&socket_reuse, sizeof(int))) {
			if (network_verbose) {
				DBG_PRINT("network : warning : failed to set listen socket reuse option\n");
			}
		}
		network_address_fwd.sin_family = AF_INET;
		network_address_fwd.sin_port = htons(cmdline_port_fwd);
		network_address_fwd.sin_addr.s_addr = htonl(INADDR_ANY);
		/* Optional address, use if provided */
		/* Optional address, use if provided */
		if (!_set_net(&network_address_fwd, cmdline_net_fwd)) {
			DBG_PRINT("network : warning failed to find host %s, falling back to default\n",
				  cmdline_net);
		}

		if (0 != connect(network_fwd_sd,
				 (struct sockaddr *)&network_address_fwd,
				 sizeof(network_address_fwd))) {
			/* Failure */
			if (network_verbose) {
				DBG_PRINT("network : error connect to forwarding socket to address %s : %ld\n",
					  cmdline_net_fwd ? cmdline_net_fwd : "localhost",
					  cmdline_port_fwd);
			}
		} else {
			/* Success */
			ret = true;
		}
	}
#endif /* NETWORK_INPUT_PLAYBACK */
	return ret;
}

int _network_read(int sd, int sec, int usec)
{
	int ret = 1;
#ifdef NETWORK_INPUT_PLAYBACK
	if (network_in_buffer_current > network_in_buffer_total) {
		/* Ok, still some packet to read. */
		ret = 0;
	} else {
		/* Need another packet.. */
		network_in_buffer_current = network_in_buffer_total = 0;
		if (fp_playback) {
			int c;
			int index = 0;
			char three_chars[3] = {0,0,0};
			bool err = false;
			while (EOF != (c = fgetc(fp_playback))) {
				/*
				 * Keep scanning for new line even if there is an error
				 * Try to consume the bad line
				 */
				if (c == '\n') {
					break;
				}
				if (err == false) {
					three_chars[index++] = c & 0xff;

					if (index == 2) {
						uint8_t b;
						if (util_decode_byte(&three_chars[0], &b)) {
							network_in_buffer[network_in_buffer_total++] = b;
						} else {
							err = true;
							/* Reset the buffer total, as if nothing happended */
							network_in_buffer_total = b;
						}
						index = 0;
					}
				}
			}
			if (c == EOF) {
				/* Nothing more to read */
				ret = 1;
			} else {
				/* A fake packet */
				if (network_verbose_print_read_buffer) {
					DBG_PRINT("playback packet ----->\n");
					util_print_buffer(fp_log, 0 /* network_in_buffer_current */, network_in_buffer_total, &network_in_buffer[0]);
					if (fp_log)
						fflush(fp_log);
				}
				/* success or dumpped error packet */
				ret = 0;
			}
			
		} else {
			/* A problem with the playback file */
			ret = 1;
		}
	}
#else
	if (sd > 0) {
		if (network_in_buffer_current > network_in_buffer_total) {
			/* Ok, still some packet to read. */
			ret = 0;
		} else {
			/* Need another packet.. */
			network_in_buffer_current = network_in_buffer_total = 0;
			struct timeval timeout;
			fd_set read_fd;
			int s;

			timeout.tv_sec  = sec;
			timeout.tv_usec = usec;

			FD_ZERO(&read_fd);
			FD_SET(sd, &read_fd);
			s = select(sd+1, &read_fd, NULL, NULL, &timeout);

			if (s == 0) {
				/* Timeout */
				ret = -1;
				if (network_verbose_timeout) {
					DBG_PRINT("network : read timeout\n");
				}
			} else if (s > 0) {
				/* Success */
				ssize_t r;
				r = recv(sd, &network_in_buffer[0],
					 network_in_buffer_size, 0);
				if (r == 0) {
					/*
					 * This should not have made it past the select.
					 * Handle like a timeout
					 */
					ret = -1;
						
				} else if (r < 0) {
					DBG_PRINT("network : read error returns %zd errno %d\n", r, errno);
					
					if (network_verbose) {
						switch (errno) {
						case EAGAIN:
							DBG_PRINT("EAGAIN\n");
							/* This maybe is a timeout, that should have been flagged by the select */
							ret = -1;
							break;
						case EBADF:
							DBG_PRINT("EBADF\n");
							break;
						case ECONNREFUSED:
							DBG_PRINT("ECONREFUSED\n");
							break;
						case EFAULT:
							DBG_PRINT("EFAULT\n");
							break;
						case EINTR:
							DBG_PRINT("EINTR\n");
							break;
						case EINVAL:
							DBG_PRINT("EINVAL\n");
							break;
						case ENOMEM:
							DBG_PRINT("ENOMEM\n");
							break;
						case ENOTCONN:
							DBG_PRINT("ENOTCONN\n");
							break;
						case ENOTSOCK:
							DBG_PRINT("ENOTSOCK\n");
							break;
						default:
							/* Unexpected network error */
							DBG_PRINT("network : error %d\n", errno);
							perror("network : error");
							break;
						}
					}
				} else if (r > network_in_buffer_size) {
					/* Error : Overflow */
					DBG_PRINT("network : error input overflow got %zd vs max %zd\n", r, network_in_buffer_size);
				} else {
					/* Success */
					network_in_buffer_total = r;
					ret = 0;
					if (network_verbose) {
						DBG_PRINT("network : received %zu\n", r);
					}
					if (network_verbose_print_read_buffer) {
						DBG_PRINT("----->\n");
						util_print_buffer(fp_log, 0 /* network_in_buffer_current */, network_in_buffer_total, &network_in_buffer[0]);
						if (fp_log)
							fflush(fp_log);
					}
#ifdef NETWORK_INPUT_RECORD
					if (fp_playback) {
						size_t i;
						for (i = 0; i < network_in_buffer_total; i++) {
							char three_chars[3] = {0,0,0};
							util_encode_byte(network_in_buffer[i], &three_chars[0]);
							fprintf(fp_playback,"%s", &three_chars[0]);
						}
						/* Terminate with a newline */
						fprintf(fp_playback,"\n");
					}
#endif
				}
			}
		}
	}
#endif /* NETWORK_INPUT_PLAYBACK */
	return ret;
}

int network_read()
{
	int ret;
	int sec = 0;
	int usec = 10;
	static long accum_timeout = 0;
#ifndef HAVE_TIMER_CREATE
	static struct timeval old_time;
	if (cmdline_watchdog_minutes > 0) {
		/* get a time to compare to */
		if (accum_timeout == 0) {
			gettimeofday(&old_time, NULL);
		}

		/*
		 * When the timout is in usec's,
		 * the actual wait time is much longer
		 * than adding up the waits.
		 * So adjust the timout so it is more reasonable
		 */
		sec += 1;
	}
#endif
	ret = _network_read(network_client_sd, sec, usec);
	if (-1 == ret) {
		accum_timeout += usec;
		accum_timeout += 1000000 * sec;
	} else {
		accum_timeout = 0;
	}
#ifndef HAVE_TIMER_CREATE
	/*
	 * Older OS's (ex freebsd 6) do not have timer_create
	 * In order to support a watchdog timeout,
	 * use the network timeout here to simulate.
	 */
	if (cmdline_watchdog_minutes > 0) {
		long watchdog_timeout =
			cmdline_watchdog_minutes * 60; /* to sec */
		long accum_timeout_secs;
		struct timeval new_time;
		/* Assumes old time failed too */
		if (0 == gettimeofday(&new_time, NULL)) {
			accum_timeout_secs = new_time.tv_sec - old_time.tv_sec;
		} else {
			accum_timeout_secs =
				accum_timeout / 1000000;     /* to sec */
		}

		if (accum_timeout_secs > watchdog_timeout) {
			WATCHDOG_ERROR();
		}
	}
#endif
	return ret;
}

int network_quick_read()
{
	return _network_read(network_client_sd, 0, 0);
}

int network_read_fwd()
{
	return _network_read(network_fwd_sd, 0, 0);
}

int _network_write(int sd, int timeout, int sec, int usec)
{
	int ret = 1;
#ifdef NETWORK_INPUT_PLAYBACK
	if (network_out_buffer_total > 0) {
		if (network_verbose_print_write_buffer) {
			DBG_PRINT("playback dropping packet <-----\n");
			util_print_buffer(fp_log, network_out_buffer_current, network_out_buffer_total, &network_out_buffer[0]);
			if (fp_log)
				fflush(fp_log);
		}
		network_out_buffer_total = network_out_buffer_current = 0;
	}
	ret = 0;
#else
	if (sd > 0) {
		int timeout_count = 0;
		int timeout_max = timeout;

		while (network_out_buffer_total > 0) {
			struct timeval timeout;
			fd_set write_fd;
			int s;

			timeout.tv_sec  = sec;
			timeout.tv_usec = usec;

			FD_ZERO(&write_fd);
			FD_SET(sd, &write_fd);
			s = select(sd+1, NULL, &write_fd, NULL, &timeout);

			if (s == 0) {
				timeout_count++;
				if (timeout_count > timeout_max) {
					if (network_verbose_timeout) {
						DBG_PRINT("network : write timeout\n");
					}
					break;
				}
			} else if (s > 0) {
				/* Success */
				ssize_t r = 0;

				if (network_verbose_print_write_buffer) {
					DBG_PRINT("<-----\n");
					util_print_buffer(fp_log, network_out_buffer_current, network_out_buffer_total, &network_out_buffer[0]);
					if (fp_log)
						fflush(fp_log);
				}

				r = send(sd, &network_out_buffer[0], network_out_buffer_total, 0);
				if (r == 0) {
					/*
					 * Error : nothing sent..
					 * Try again..
					 */
				} else if (r > 0) {
					if (r < network_out_buffer_total) {
						/* Partial */
						size_t leftover;
						leftover = network_out_buffer_total - r;
						memmove(&network_out_buffer[0], &network_out_buffer[r], leftover);
					} else {
						/*
						 * Success
						 * State of ret checked below, so it is not needed here
						 */
						network_out_buffer_total = network_out_buffer_current = 0;
					}
				} else {
					/*
					 * Error
					 * Treat as a timeout and hope fore the best
					 */
					timeout_count++;
					if (network_verbose) {
						switch (r) {
						case EACCES:
							DBG_PRINT("EACCES\n");
							break;
						case EAGAIN:
							DBG_PRINT("EAGAIN\n");
							break;
						case EBADF:
							DBG_PRINT("EBADF\n");
							break;
						case ECONNRESET:
							DBG_PRINT("ECONNRESET\n");
							break;
						case EDESTADDRREQ:
							DBG_PRINT("EDESTADDRREQ\n");
							break;
						case EFAULT:
							DBG_PRINT("EFAULT\n");
							break;
						case EINTR:
							DBG_PRINT("EINTR\n");
							break;
						case EINVAL:
							DBG_PRINT("EINVAL\n");
							break;
						case EISCONN:
							DBG_PRINT("EISCONN\n");
							break;
						case EMSGSIZE:
							DBG_PRINT("EMSGSIZE\n");
							break;
						case ENOBUFS:
							DBG_PRINT("ENOBUFS\n");
							break;
						case ENOMEM:
							DBG_PRINT("ENOMEM\n");
							break;
						case ENOTCONN:
							DBG_PRINT("ENOTCONN\n");
							break;
						case ENOTSOCK:
							DBG_PRINT("ENOTSOCK\n");
							break;
						case EOPNOTSUPP:
							DBG_PRINT("EOPNOTSUPP\n");
							break;
						case EPIPE:
							DBG_PRINT("EPIPE\n");
							break;
						default:
							/* Unexpected network error */
							DBG_PRINT("network : error %d\n", errno);
							perror("network : error");
							break;
						}
					}
				}
			}
		}
		if (network_out_buffer_total == 0) {
			/* Success */
			ret = 0;
		}
	}
#endif /* NETWORK_INPUT_PLAYBACK */
	return ret;
}

int network_write()
{
	return _network_write(network_client_sd, 100, 0, 100);
}

int network_quick_write(int timeout, int sec, int usec)
{
	return _network_write(network_client_sd, 0, 0, 0);
}

int network_write_fwd()
{
	return _network_write(network_fwd_sd, 100, 0, 100);
}

void network_clear_write()
{
	if (network_out_buffer_total > 0) {
		if (network_verbose) {
			DBG_PRINT("Clearing write buffer <-----\n");
			util_print_buffer(fp_log, network_out_buffer_current,
					  network_out_buffer_total,
					  &network_out_buffer[0]);
		}
		network_out_buffer_total = network_out_buffer_current = 0;
	}
}

static size_t _sock_write(unsigned char *b, size_t l)
{
  size_t ret = 0;
  if (l < network_out_buffer_size - network_out_buffer_total) {
    memcpy(&network_out_buffer[network_out_buffer_total], b, l);
    network_out_buffer_total += l;
    ret = l;
  }
  return ret;
}

/*
 * Send packet to debugger
 * For normal text packets, buf is null teminated and size = 0
 * For binary packets, size must be use
 */
int network_put_dbg_packet(const char *buf, size_t size)
{
  int i;
  int ret = 1;
  size_t len;
  uint8_t csum;
  uint8_t *d;
  const char *s;
  uint8_t buf2[INOUTBUF_SIZE + 4];

  ASSERT(buf != NULL);

  /* Copy the packet into buf2, encapsulate it, and give
     it a checksum. */
  d = buf2;
  *d++ = '$';
  csum = 0;
  /* Normal text packet */
  if (size == 0) {
    for (s = buf, i = 0; *s; i++) {
      csum += *s;
      *d++ = *s++;
    }
    ASSERT(*s == '\0');
  } else {
    /* Binary packet */
    for (s = buf, i = 0; i < size; i++) {
      csum += *s;
      *d++ = *s++;
    }
  }
  /* Add the sumcheck to the end of the message */
  *d++ = '#';
  *d++ = util_hex[(csum >> 4) & 0xf];
  *d++ = util_hex[(csum & 0xf)];
  /* Do not null terminate binary transfers */
  if (0 == size)
    *d = '\0';
  /* Send it over and over until we get a positive ack. */
  len = d - buf2;
  ret = _sock_write(buf2, len);
  return ret;
}
