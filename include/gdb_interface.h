/*
  This file is derrived from the gdbproxy project's gdbproxy.h
  The changes to this file are
  Copyright (C) 2012-2015 Juniper Networks, Inc

  The original copyright is

  Copyright (C) 1999-2001 Quality Quorum, Inc.
  Copyright (C) 2002 Chris Liechti and Steve Underwood

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.
  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
  EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


  QQI can be contacted as qqi@world.std.com


  Remote proxy definitions.
*/

#ifndef DEEBE_PROXY_H_
#define DEEBE_PROXY_H_

#include <sys/types.h>

typedef void (*log_func)(int level, const char *string, ...);

/*=================  Global Parameters ================================ */

/* Size of data buffer  */
#define GDB_INTERFACE_PARAM_DATABYTES_MAX (16384)


/* Size of input and out buffers */
#define RP_PARAM_INOUTBUF_SIZE (2*GDB_INTERFACE_PARAM_DATABYTES_MAX+32)

/* First socket port to try */
#define RP_PARAM_SOCKPORT_MIN (2000)


/*================= Debugger Parameters ================================*/

/* These values have to be in synch with corresponding values used
   by debugger, fortunately, they are not going to change any
   time soon */

/* Target signals, the only definition we need at this level is one which
   specifies 'no signal' signal. This definition is good one as long
   as gdb's TARGET_SIGNAL_0 is 0 */
#define RP_VAL_TARGETSIG_0 (0)

/* Acceptable packet size for target and for gdb !!!!!
   a lot of gdb_versions will ask for 200 bytes of memory
   and will choke on response. It seems like it only
   affects read memory requests */
#define RP_VAL_DBG_PBUFSIZ  (400)

/* Thread related definitions */
typedef struct __gdb_thread_ref {
	int64_t val;
} gdb_thread_ref;

/*
 * Thread value meaning all threads
 */
#define RP_VAL_THREADID_ALL (0ULL)

typedef struct __rp_thread_nfo {
	gdb_thread_ref thread_id;
	int           exists;
	char          display[256];
	char          thread_name[32];
	char          more_display[256];
} rp_thread_info;

typedef struct gdb_state_rec {
	gdb_thread_ref gen_thread;
	gdb_thread_ref ctrl_thread;
} gdb_state;

/* Function to do console output from wait methods */
typedef void (*out_func)(const char *string);

/* Function to transefer data received as qRcmd response */
typedef void (*data_func)(const char *string);

/* Log level definitions */
#define GDB_INTERFACE_LOGLEVEL_EMERG   (0x1234)
#define GDB_INTERFACE_LOGLEVEL_ALERT   (0x4321)
#define GDB_INTERFACE_LOGLEVEL_CRIT    (0xabcd)
#define GDB_INTERFACE_LOGLEVEL_ERR     (0xdcba)
#define GDB_INTERFACE_LOGLEVEL_WARNING (0x5678)
#define GDB_INTERFACE_LOGLEVEL_NOTICE  (0x8765)
#define GDB_INTERFACE_LOGLEVEL_INFO    (0x1111)
#define GDB_INTERFACE_LOGLEVEL_DEBUG   (0x2222)
#define GDB_INTERFACE_LOGLEVEL_DEBUG2  (0x3333)
#define GDB_INTERFACE_LOGLEVEL_DEBUG3  (0x4444)


/* Target, all functions return boolen values */
typedef struct gdb_target_s gdb_target;

/* Table entry definition */
typedef struct {
	/* command name */
	const char *name;
	/* command function */
	int (*function)(int, char **, out_func, data_func);
	/* one line of help text */
	const char *help;
} RCMD_TABLE;

struct gdb_target_s {
	gdb_target *next;

	const char *name; /* Unique ASCII name of the target */

	const char *desc; /* Short description */

	/* Table of remote commands */
	const RCMD_TABLE *remote_commands;

	/*======================   Help/Debug  =======================*/

	/* Help, argument is a pointer to itself */
	void (*help)(char *prog_name);

	/*=========   Open/Close/Connect/Disconnect  ==============*/

	/* Start target stub and provide run time parameters
	   in time tested manner, does not assume actually
	   connecting to target.  */
	int (*open)(int argc,
		    char *argv[],
		    char *prog_name);

	/* Attach to a running process */
	int (*attach)(pid_t pid);
	/* Detach from a process that had been running */
	int (*detach)();


	/* Close target stub: if target is still connected disconnect and
	   leave it running */
	void (*close)(void);

	/* Actually connect to a target and return status string; */
	int (*connect)(char *status_string,
		       size_t status_string_size,
		       int *can_restart);

	/* Disconnect from a target a leave it running */
	int (*disconnect)(void);


	/*=================== Start/Stop =========================*/

	/* Kill target: disconnect from a target and leave it waiting
	   for a command. Target output is ignored.

	   Restart: start target all over again.

	   Stop: break into running target

	   Note these commands are used in following sequences only

	   1. kill, close, terminate proxy
	   2. kill, restart, connect
	   3. restart, connect
	   4. stop, wait */


	/* Kill target: disconnect from a target and leave it waiting
	   for a command. It is expected that either close or wait or
	   connect will follow after kill to get last status_string */
    void (*kill)(pid_t pid, pid_t tid);
	/* Similar to kill but called from signal handler */
    void (*quick_kill)(pid_t pid, pid_t tid);

	/* Restart target and return status string */
	int (*restart)(void);

	/* Stop target. E.g. send ^C or BREAK to target - note
	   it has to be followed either by wait or connect in order to
	   to get last status_string */
    void (*stop)(pid_t pid, pid_t tid);

	/*============== Thread Control ===============================*/

	/* Set generic thread */
	int (*set_gen_thread)(int64_t process_id, int64_t thread_id);

	/* Set control thread */
	int (*set_ctrl_thread)(int64_t process_id, int64_t thread_id);

	/* Get thread status */
	int (*is_thread_alive)(int64_t process_id, int64_t thread_id, int *alive);

	/*============= Register Access ================================*/

	/* Read all registers. buf is 4-byte aligned and it is in
	   target byte order. If  register is not available
	   corresponding bytes in avail_buf are 0, otherwise
	   avail buf is 1 */
	int (*read_registers)(pid_t tid,
			      unsigned char *data_buf,
			      unsigned char *avail_buf,
			      size_t buf_size,
			      size_t *read_size);

	/* Write all registers. buf is 4-byte aligned and it is in target
	   byte order */
	int (*write_registers)(pid_t tid, unsigned char *buf, size_t write_size);

	/* Read one register. buf is 4-byte aligned and it is in
	   target byte order. If  register is not available
	   corresponding bytes in avail_buf are 0, otherwise
	   avail buf is 1 */
	int (*read_single_register)(pid_t tid,
				    unsigned int reg_no,
				    unsigned char *buf,
				    unsigned char *avail_buf,
				    size_t buf_size,
				    size_t *read_size);

	/* Write one register. buf is 4-byte aligned and it is in target byte
	   order */
	int (*write_single_register)(pid_t tid,
				     unsigned int reg_no,
				     unsigned char *buf,
				     size_t write_size);

	/*=================== Memory Access =====================*/

	/* Read memory, buf is 4-bytes aligned and it is in target
	   byte order */
	int (*read_mem)(pid_t tid,
			uint64_t addr,
			unsigned char *buf,
			size_t req_size,
			size_t *actual_size);

	/* Write memory, buf is 4-bytes aligned and it is in target
	   byte order */
	int (*write_mem)(pid_t tid,
			 uint64_t addr,
			 unsigned char *buf,
			 size_t req_size);

	/*================ Resume/Wait  ============================*/

	/* Resume from current address, if not supported it
	   has to be figured out by wait */
    int (*resume_from_current)(pid_t pid, pid_t tid, int step, int sig);

	/* Resume from specified address, if not supported it
	   has to be figured out by wait */
    int (*resume_from_addr)(pid_t pid, pid_t tid, int step, int sig, uint64_t addr);

	/* Allow threads which are not stopped already to continue */
	int (*go_waiting)(int sig);

	/* Wait function, wait_partial is called by the proxy with one
	   tick intervals, so it allows to break into running
	   target */

	/* Check for event and return. It allows proxy server to
	   check messages from gdb allowing gdb to stop/kill target.
	   Break and kill commands are generated by a human being so,
	   the process can wait inside wait_partial with some substantial
	   timeouts. It seems like 1s time will be highest acceptable value.

	   In this case return value RP_TARGETRET_NOSUPP means, that
	   response to previous resume was - 'not supported'. If this operation
	   is not implemented by target, then it will return OK and
	   implemeted will be 0.

	   status_string is unchanged unless return value is OK and
	   implemented is non 0 */
	int (*wait_partial)(int first,
			    char *status_string,
			    size_t status_string_len,
			    int *implemented,
			    int *more);

	/* Wait for event, fill (null-terminated) status_string upon successful
	   return, if there is not enough space for 'TAA... string' use
	   'SAA' instead, status_sting_len is always > 3

	   In this case return value RP_TARGETRET_NOSUPP means, that
	   response to previous resume was - 'not supported'. If this operation
	   is not implemented by target, then it will return OK and
	   implemeted will be 0

	   status_string is unchanged unless return value is OK and
	   implemented is non 0 */
	int (*wait)(char *status_string,
		    size_t status_string_len,
		    int step,
		    bool skip_continue_others
	    );

	/* From signal handler, pass a general signal to a waiting process */
    void (*quick_signal)(pid_t pid, pid_t tid, int sig);
	/*============= Queries ===============================*/

	/* Bits of mask determine set of information about thread
	   to be retrieved, results are put into info.  */
	int (*process_query)(unsigned int *mask,
			     gdb_thread_ref *arg,
			     rp_thread_info *info);

	/* List threads. If first is non-zero then start from the first thread,
	   otherwise start from arg, result points to array of threads to be
	   filled out, result size is number of elements in the result,
	   num points to the actual number of threads found, done is
	   set if all threads are processed.  */
	int (*list_query)(int first,
			  gdb_thread_ref *arg,
			  gdb_thread_ref *result,
			  size_t max_num,
			  size_t *num,
			  int *done);

	/* Query current thread id */
	int (*current_thread_query)(int64_t *process, int64_t *thread);

	/* Query offset of major sections in memory */
	int (*offsets_query)(uint64_t *text, uint64_t *data, uint64_t *bss);

	/* Query crc32 of memory area */
	int (*crc_query)(uint64_t addr, size_t len, uint32_t *val);

	/*============ Breakpoints ===========================*/

	int (*add_break)(pid_t tid, int type, uint64_t addr, size_t length);
	int (*remove_break)(pid_t tid, int type, uint64_t addr, size_t length);

	/* Query thread info */
  void (*threadinfo_query)(int first, char *out_buf, size_t out_buf_size);

	/* Query thread extra info */
  int (*threadextrainfo_query)(int64_t thread, char *out_buf, size_t out_buf_size);

	/* Query Supported features */
  void (*supported_features_query)(char *out_buf, size_t out_buf_size);

	/* Query current signal */
	int (*query_current_signal)(int *sig);

	/* If it is ok not to ack / nak */
	int (*no_ack)();

	/* If the multiprocess extensions are supported 0 = no, 1 = yes */
	int (*support_multiprocess)();
  
  /* The string to look for when Supported:xmlResisters=<string1>,<string2> is seen */
  const char *(*get_xml_register_string)();
  /* Tell target to report registers as xml */
  void (*set_xml_register_reporting)();
};


/* Return values of target functions */
#define RET_OK     (0) /* Success */
#define RET_ERR    (1) /* Error */
#define RET_NOSUPP (2) /* Operation is not supported */
#define RET_IGNORE (3) /* Repeat the last operation */
#define RET_CONTINUE_WAIT (4) /* No body waiting.. skip resume and go back to waiting */

/* Bits of process_query mask */
#define RP_BIT_PROCQMASK_THREADID    (1)
#define RP_BIT_PROCQMASK_EXISTS      (2)
#define RP_BIT_PROCQMASK_DISPLAY     (4)
#define RP_BIT_PROCQMASK_THREADNAME  (8)
#define RP_BIT_PROCQMASK_MOREDISPLAY (16)

/* Breakpoint types */

#define GDB_INTERFACE_BP_SOFTWARE             0
#define GDB_INTERFACE_BP_HARDWARE             1
#define GDB_INTERFACE_BP_WRITE_WATCH          2
#define GDB_INTERFACE_BP_READ_WATCH           3
#define GDB_INTERFACE_BP_ACCESS_WATCH         4

#if !defined(FALSE)
#define FALSE 0
#endif
#if !defined(TRUE)
#define TRUE (!FALSE)
#endif

#define ACK                             '+'
#define NAK                             '-'

#define PACKET_BUFF_SIZE                8192

extern int rp_debug_level;

/* Initialization function in init.c */
gdb_target *rp_init(void);

/* Functions to display warranty and copying information */
void rp_show_copying(void);
void rp_show_warranty(void);
int rp_hex_nibble(char in);
int rp_encode_string(const char *s, char *out, size_t out_size);
int handle_rcmd_command(char *in_buf, out_func of, data_func df,
			gdb_target *t);

void gdb_interface_cleanup();
void gdb_interface_init();
int gdb_interface_packet();
int gdb_interface_quick_packet();
void gdb_interface_put_console(char *b);
void gdb_stop_string(char *str, size_t len, int sig, pid_t tid, unsigned long watch_addr);
void gdb_interface_write_retval(int ret, char *buf);

/* Defined by the target to initalize and cleanup its support */
void target_init(struct gdb_target_s **target);
void target_cleanup();

#endif /* DEEBE_PROXY_H_ */
