#include "utils.h"
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <string>

#define HIGHFD 384

int xopenpath(const char *path)
{
	int ret = open(path, O_PATH | O_CLOEXEC);
	assert(ret >= 0);
	if (ret < HIGHFD) {
		int old = ret;
		ret = fcntl(old, F_DUPFD_CLOEXEC, HIGHFD);
		assert(ret >= 0);
		close(old);
	}
	return ret;
}

int xdup(int fd)
{
	if (fd == AT_FDCWD) {
		int ret = openat(AT_FDCWD, ".", O_PATH | O_CLOEXEC);
		assert (ret >= 0);
		if (ret < HIGHFD) {
			int old = ret;
			ret = fcntl(old, F_DUPFD_CLOEXEC, HIGHFD);
			assert(ret >= 0);
			close(old);
		}
		return ret;
	}

	int fd2 = fcntl(fd, F_DUPFD_CLOEXEC, HIGHFD);
	return fd2;
}

int xclose(int fd)
{
	if (fd != AT_FDCWD)
		return close(fd);
	return 0;
}

int xfdpath(int fd, char *path)
{
	std::string link = "/proc/" + std::to_string(getpid()) + "/fd/" + std::to_string(fd);
	int len = readlink(link.c_str(), path, PATH_MAX);

	if (len < 0) {
		return -errno;
	}

	if (len == PATH_MAX) {
		return -ENAMETOOLONG;
	}

	path[len] = 0;
	return 0;
}
