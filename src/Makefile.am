INCLUDES = -I$(srcdir)/../include

bin_PROGRAMS = deebe

deebe_SOURCES = \
	breakpoint.c \
	cmdline.c \
	gdb_interface.c \
	main.c \
	network.c \
	ptrace.c \
	signal.c \
	target.c \
	util.c \
	version.c \
	watchdog.c

EXTRA_deebe_SOURCES = linux.c linux-ppc.c linux-x86.c linux-arm.c freebsd-x86.c osx-x86_64.c freebsd-ppc.c freebsd-x86.c freebsd.c target_ptrace.c target_osx.c 
deebe_LDADD = $(TD_SRC) $(HD_SRC)
deebe_DEPENDENCIES = $(TD_SRC) $(HD_SRC)

