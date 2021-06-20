TOPDIR = ../syscall_hook
PROG = libsqroot.so
CXXSRCS = hook.cpp utils.cpp path_resolver.cpp execve.cpp dlfcn.cpp

CFLAGS = -fPIC -O2 -I${TOPDIR}/include -fvisibility=hidden -g
LDFLAGS = -shared --whole-archive ${TOPDIR}/runtime/runtime.a --no-whole-archive

include ${TOPDIR}/make/comm.mk
include ${TOPDIR}/make/cxx.mk
include ${TOPDIR}/user.mk

${PROG}: ${TOPDIR}/runtime/runtime.a
