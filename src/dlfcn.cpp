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

static int try_path(const char *filename, char *realpath)
{
	Array<char, PATH_MAX> filepath;
	if (!filename)
		return -1;

	if (filename[0] != '/') {
		const char *p[] = {
			"/usr/lib/",
			"/usr/lib/x86_64-linux-gnu/",
			NULL,
		};
		for (const char **q = p; *q; q++) {
			strcpy(filepath.data(), *q);
			strcat(filepath.data(), filename);
			if (resolve_path(filepath.data(), realpath) == 0)
				return 0;
		}
		return -1;
	}
	return resolve_path(filename, realpath);
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

	int ret = try_path(filename, realpath.data());
	if (ret == 0) {
		return orig(realpath.data(), flags);
	} else {
		return orig(filename, flags);
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

	int ret = try_path(filename, realpath.data());
	if (ret == 0) {
		return orig(lmid, realpath.data(), flags);
	} else {
		return orig(lmid, filename, flags);
	}
}

}
