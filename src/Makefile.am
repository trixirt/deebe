INCLUDES = -I$(srcdir)/../include

bin_PROGRAMS = deebe

deebe_SOURCES = \
	breakpoint.c \
	cmdline.c \
	gdb_interface.c \
	elf.c \
	lldb_interface.c \
	memory.c \
	main.c \
	network.c \
	packet.c \
	ptrace.c \
	proc.c \
	signal.c \
	target.c \
	thread_db.c \
	util.c \
	version.c \
	watchdog.c

EXTRA_deebe_SOURCES = linux.c linux-ppc.c linux-x86.c linux-aarch64.c linux-arm.c freebsd-x86.c osx-x86_64.c freebsd-ppc.c freebsd-x86.c freebsd.c target_ptrace.c target_osx.c 
deebe_LDADD = $(TD_SRC) $(HD_SRC) $(TD_LIBS)
deebe_DEPENDENCIES = $(TD_SRC) $(HD_SRC)

