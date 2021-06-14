TOPDIR = ../syscall_hook
PROG = sqroot
CXXSRCS = main.cpp

CFLAGS = -O2
LDFLAGS =

include ${TOPDIR}/make/comm.mk
include ${TOPDIR}/make/cxx.mk
include ${TOPDIR}/user.mk
