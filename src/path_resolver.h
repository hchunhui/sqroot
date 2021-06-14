#ifndef PATH_RESOLVER_H
#define PATH_RESOLVER_H

#include <sys/types.h>
#include <string>
#include <vector>
#include <map>
#include "array.h"

struct FD {
	int fd;
	dev_t st_dev;
	ino_t st_ino;
	bool issym;
	bool isdir;

	FD(int _fd);

	FD() : fd(-1), issym(false), isdir(false) {}

	bool operator==(const FD &o) const {
		return fd >= 0 && o.fd >= 0 &&
			st_dev == o.st_dev &&
			st_ino == o.st_ino;
	}

	bool operator<(const FD &o) const {
		return st_dev < o.st_dev ||
			(st_dev == o.st_dev && st_ino < o.st_ino);
	}
};

struct BindInfo {
	std::string oldpath;
	std::string newpath;
	FD oldfd;
	FD newfd;
};

class PathResolver {
	FD root_fd;
	std::map<FD, int> binds;
	std::map<FD, int> rbinds;
	std::string new_root;
	std::vector<BindInfo> all_binds;
public:
	PathResolver();
	bool isin(int fd);
	unsigned xgetcwd(char *buf, unsigned long bsize);
	bool set_root(const char *root);
	bool bind(const char *olddir, const char *newdir);
	int openpath(FD dirfd, const char *name);
	int resolve1(FD fd, const char *path, char *last, bool follow, int count);
	int resolve(const char *path, char *last, bool follow);
	~PathResolver();
};

#endif /* PATH_RESOLVER_H */
