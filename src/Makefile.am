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
	signal.c \
	target.c \
	thread_db.c \
	util.c \
	version.c \
	watchdog.c

EXTRA_deebe_SOURCES = linux.c linux-ppc.c linux-x86.c linux-aarch64.c linux-arm.c freebsd-x86.c osx-x86_64.c freebsd-ppc.c freebsd-x86.c freebsd.c target_ptrace.c target_osx.c freebsd-proc.c
deebe_LDADD = $(TD_SRC) $(HD_SRC) $(TD_LIBS)
deebe_DEPENDENCIES = $(TD_SRC) $(HD_SRC)

version.o: version.inc

## NOTE: The build machine should have awk to make it working.
## 1. Its ok for errors to appear on the console. echo will takeover in such scenario.
## 2. If head is detached, the branch name will not appear
## 3. We do not want to pollute the source dir, generate the inc file in build path
## 4. Linux git client will not support --short for symbolic-ref so drop it
version.inc:
if OS_FOR_DEEBE_VERSION
	cd $(srcdir);\
	(git describe --tags --always --abbrev=100 || echo ) | awk ' BEGIN {} {print "#define REVISION "$$0""} END {}' > $(abs_builddir)/version.inc;\
	(git symbolic-ref HEAD || echo ) | awk ' BEGIN {} {print "#define BRANCH "$$0""} END {}' >> $(abs_builddir)/version.inc;\
	(date +'%Y-%m-%d' || echo 1970-01-01) | awk ' BEGIN {} {print "#define BUILD_DATE "$$0""} END {}' >> $(abs_builddir)/version.inc;\
	(git config --get remote.origin.url || echo ) | awk ' BEGIN {} {print "#define REPO_URL \""$$0"\""} END {}' >> $(abs_builddir)/version.inc;\
	echo $(host_triplet) | awk ' BEGIN {} {print "#define DEEBE_TARGET "$$0""} END {}' >> $(abs_builddir)/version.inc
else
	echo "#define REVISION"      > $(abs_builddir)/version.inc
	echo "#define BRANCH"  	     >> $(abs_builddir)/version.inc
	echo "#define BUILD_DATE"    >> $(abs_builddir)/version.inc
	echo "#define REPO_URL"      >> $(abs_builddir)/version.inc
	echo "#define DEEBE_TARGET"  >> $(abs_builddir)/version.inc
endif
