dnl Process this file with autoconf to produce a configure script.
dnl This software is provided 'as-is', without any express or implied
dnl warranty.  In no event will the authors be held liable for any damages
dnl arising from the use of this software.
dnl
dnl Copyright (c) 2012-2013, Juniper Networks, Inc.
dnl 

AC_PREREQ(2.59)
AC_INIT(deebe, 1.0)


AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
# All warnings
# Warnings as errors
# c11 c
# _GNU_SOURCE to compile is non-c99 parts
AC_PROG_CC
CFLAGS="$CFLAGS -Wall -Werror -std=c11 -D_GNU_SOURCE"


AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB(rt)

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h inttypes.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h unistd.h sys/param.h libgen.h thread_db.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIGNAL
AC_HEADER_TIME
AC_HEADER_STDBOOL
AC_CHECK_SIZEOF(unsigned long)

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gethostbyname memmove memset select socket strchr strdup strtol timer_create timer_settime])

ti_src="cmdline.c main.c ptrace.c network.c gdb_interface.c target_skeleton.c watchdog.c lldb_interface.c"

case ${target} in

powerpc-*-freebsd*)
	# powerpc freebsd
	os=freebsd
	TD_SRC='target_ptrace.$(OBJEXT) freebsd-ppc.$(OBJEXT) freebsd-proc.$(OBJEXT) freebsd.$(OBJEXT) '
	;;

powerpc-*-linux*)
	# ppc 32 bit linux
	os=linux
	TD_SRC='target_ptrace.$(OBJEXT) linux-ppc.$(OBJEXT) linux.$(OBJEXT)'
	;;

i686-*-linux-*)
	# x86 32 bit linux
	os=linux
	TD_SRC='target_ptrace.$(OBJEXT) linux-x86.$(OBJEXT) linux-common-x86.$(OBJEXT) linux.$(OBJEXT) x86.$(OBJEXT)'
	;;

x86_64-*-linux-*)
	# x86 64 bit linux
	os=linux
	TD_SRC='target_ptrace.$(OBJEXT) linux-x86_64.$(OBJEXT) linux-common-x86.$(OBJEXT) linux.$(OBJEXT) x86.$(OBJEXT)'
	;;

i386-*-freebsd*)
	# x86 freebsd
	os=freebsd
	TD_SRC='target_ptrace.$(OBJEXT) freebsd-x86.$(OBJEXT) freebsd-common-x86.$(OBJEXT) freebsd-proc.$(OBJEXT) freebsd.$(OBJEXT) x86.$(OBJEXT)'
	;;

amd64-*-freebsd*|x86_64-*-freebsd*)
	# x64 freebsd
	os=freebsd
	TD_SRC='target_ptrace.$(OBJEXT) freebsd-x86_64.$(OBJEXT) freebsd-common-x86.$(OBJEXT) freebsd-proc.$(OBJEXT) freebsd.$(OBJEXT) x86.$(OBJEXT)'
	;;

aarch64-*-linux-*)
	os=linux
	TD_SRC='target_ptrace.$(OBJEXT) linux-aarch64.$(OBJEXT) linux.$(OBJEXT)'
	;;
	

armel*-*-linux-*)
	# arm 32 little endian bit linux
	os=linux
	TD_SRC='target_ptrace.$(OBJEXT) linux-arm.$(OBJEXT) linux.$(OBJEXT)'
	;;

arm*-*-linux-*)
	# arm 32 big endian bit linux
	os=linux
	TD_SRC='target_ptrace.$(OBJEXT) linux-arm.$(OBJEXT) linux.$(OBJEXT)'
	;;

arm*-*-freebsd*)
	os=freebsd
	TD_SRC='target_ptrace.$(OBJEXT) bsd-arm.$(OBJEXT) freebsd-arm.$(OBJEXT) freebsd-proc.$(OBJEXT) freebsd.$(OBJEXT)'
	;;

arm*-*-netbsd*)
	os=netbsd
	TD_SRC='target_ptrace.$(OBJEXT) bsd-arm.$(OBJEXT) netbsd-arm.$(OBJEXT) netbsd.$(OBJEXT)'
	;;

x86_64-apple-darwin*)
	# x64 osx
	os=osx
	TD_SRC='target_osx.$(OBJEXT) osx.$(OBJEXT) osx-x86_64.$(OBJEXT)'
	;;

mipsel-*-linux-*)
	# mips 32 bit little endian linux
	os=linux
	TD_SRC='target_ptrace.$(OBJEXT) linux-mips.$(OBJEXT) linux.$(OBJEXT)'
	;;

mips-*-linux-*)
	# mips 32 bit big endian linux
	os=linux
	TD_SRC='target_ptrace.$(OBJEXT) linux-mips.$(OBJEXT) linux.$(OBJEXT)'
	;;

*)
	echo "*** Unsupported target $target." >&2
	exit 1
	;;	
esac
AC_SUBST([TD_SRC])

case ${target} in

*freebsd*)
	TD_LIBS='-lutil -lprocstat -lthread_db'
	;;

powerpc-*-linux*)
	TD_LIBS=''
	;;
esac
AC_SUBST([TD_LIBS])

# Confusing..
# Would like use 'host' to mean what gdb is running on
case ${host} in

*-freebsd*|*-netbsd*)
	# freebsd
	HD_SRC='host-freebsd.$(OBJEXT)'
	deebe_version=Yes
	;;

*-linux*)
	# linux
	HD_SRC='host-linux.$(OBJEXT)'
	deebe_version=Yes
	;;

x86_64-apple-darwin*)
	# x64 osx
	os=osx
	HD_SRC='host-osx.$(OBJEXT)'
	deebe_version=Yes
	;;

*)
	echo "*** Unsupported host $host." >&2
	deebe_version=No
	exit 1
	;;	
esac
AC_SUBST([HD_SRC])

AM_CONDITIONAL(OS_FOR_DEEBE_VERSION, [test x"$deebe_version" = xYes])

AC_CONFIG_LINKS(os.h:os/$os.h)

AC_CONFIG_FILES([Makefile
                 src/Makefile])


AC_OUTPUT

