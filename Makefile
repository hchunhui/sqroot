TOPDIR = syscall_hook
SUBDIRS = syscall_hook src

include ${TOPDIR}/make/comm.mk
include ${TOPDIR}/user.mk

src.all: syscall_hook.all
