#include <dlfcn.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <errno.h>
#include "array.h"
#include "utils.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

static int resolve_path(const char *path, char *realpath)
{
	int fd = open(path, O_PATH);
	if (fd < 0) {
		return -errno;
	}

	char procpath[80];
	snprintf(procpath, 80, "/proc/self/fd/%d", fd);
	int ret = syscall(0xaaaaaaaa, procpath, realpath, PATH_MAX);
	close(fd);

	if (ret < 0) {
		return -errno;
	}

	realpath[ret] = 0;
	return 0;
}

extern "C" {

__attribute__((visibility("default")))
void *dlopen(const char *filename, int flags)
{
	Array<char, PATH_MAX> realpath;
	typedef void *(*T)(const char *, int);
	static T orig;
	if (!orig) {
		orig = (T) dlsym(RTLD_NEXT, "dlopen");
	}

	int ret = resolve_path(filename, realpath.data());
	if (ret == 0) {
		return orig(realpath.data(), flags);
	} else {
		return orig("", 0);
	}
}

__attribute__((visibility("default")))
void *dlmopen(Lmid_t lmid, const char *filename, int flags)
{
	Array<char, PATH_MAX> realpath;
	typedef void *(*T)(Lmid_t, const char *, int);
	static T orig;
	if (!orig) {
		orig = (T) dlsym(RTLD_NEXT, "dlmopen");
	}

	int ret = resolve_path(filename, realpath.data());
	if (ret == 0) {
		return orig(lmid, realpath.data(), flags);
	} else {
		return orig(lmid, "", 0);
	}
}

}
