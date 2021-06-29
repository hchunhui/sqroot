#include "path_resolver.h"
#include <assert.h>
#include <string.h>
#include <string>
#include <vector>
#include <map>

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#include "array.h"
#include "utils.h"

FD::FD(int _fd) : fd(_fd)
{
	if (fd >= 0) {
		struct stat stbuf;
		int ret = fstat(fd, &stbuf);
		assert(ret == 0);
		st_dev = stbuf.st_dev;
		st_ino = stbuf.st_ino;
		issym = (stbuf.st_mode & S_IFMT) == S_IFLNK;
		isdir = (stbuf.st_mode & S_IFMT) == S_IFDIR;
	} else if (fd == AT_FDCWD) {
		issym = false;
		isdir = true;
	} else {
		issym = false;
		isdir = false;
	}
}

PathResolver::PathResolver()
{
}

bool PathResolver::isin(int fd)
{
	if (fd == root_fd.fd) {
		return true;
	}

	for (auto &p : all_binds) {
		if (p.oldfd.fd == fd || p.newfd.fd == fd) {
			return true;
		}
	}

	return false;
}

long PathResolver::reverse_resolve(char *buf, unsigned long bsize)
{
	unsigned long size = strlen(buf);
	BindInfo *lmatch = NULL;
	unsigned long lsize = 0;

	for (auto &b : all_binds) {
		unsigned long rsize = b.oldpath.size();
		if (strncmp(buf, b.oldpath.c_str(), rsize) == 0) {
			if (lsize < rsize) {
				lsize = rsize;
				lmatch = &b;
			}
		}
	}

	if (lmatch) {
		unsigned long nsize = lmatch->newpath.size();
		if (size - lsize + 1 >= bsize)
			return -ENAMETOOLONG;

		memmove(buf + nsize, buf + lsize, size - lsize);
		memmove(buf, lmatch->newpath.c_str(), nsize);
		buf[size - lsize + nsize] = 0;
		size = strlen(buf);
	}

	unsigned long rsize = new_root.size();
	if (strncmp(buf, new_root.c_str(), rsize) == 0) {
		if (size != rsize) {
			memmove(buf, buf + rsize, size - rsize);
			buf[size - rsize] = 0;
			return size - rsize + 1;
		} else {
			strcpy(buf, "/");
			return 2;
		}
	} else {
		return -ENOENT;
	}
}

bool PathResolver::set_root(const char *root)
{
	if (root_fd.fd >= 0)
		return false;

	int fd = xopenpath(root);
	if (fd < 0)
		return false;

	root_fd = FD(fd);
	new_root = root;
	return true;
}

bool PathResolver::bind(const char *olddir, const char *newdir)
{
	FD oldfd = xopenpath(olddir);
	FD newfd = xopenpath(newdir);
	if (oldfd.fd < 0 || newfd.fd < 0 ||
	    binds.find(newfd) != binds.end())
		return false;

	int i = all_binds.size();
	all_binds.push_back({olddir, newdir, oldfd, newfd});
	binds[newfd] = i;
	rbinds[oldfd] = i;
	return true;
}

int PathResolver::openpath(FD dirfd, const char *name)
{
	if (strcmp(name, "..") == 0) {
		if (dirfd == root_fd) {
			return xdup(root_fd.fd);
		} else {
			auto it = rbinds.find(dirfd);
			if (it != rbinds.end()) {
				return openpath(all_binds[it->second].newfd, "..");
			}
		}
	}

	int fd = openat(dirfd.fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if (fd >= 0) {
		auto it = binds.find(fd);
		if (it != binds.end()) {
			xclose(fd);
			fd = xdup(all_binds[it->second].oldfd.fd);
		}
	}
	return fd;
}

int PathResolver::resolve1(FD fd, const char *path, char *last, bool follow, int count)
{
	//fprintf(stderr, "resolve1(%s): %d %s\n", last ? "true" : "false", fd.fd, path);
	if (count >= 40)
		return -ELOOP;

	if (path == NULL)
		return -EFAULT;
	const char *epath = path;
	while (*epath && *epath != '/')
		epath++;

	bool islast;
	bool trailing = false;
	char buf[epath - path + 2];
	memcpy(buf, path, epath - path);
	buf[epath - path] = 0;
	while (*epath == '/') {
		epath++;
		trailing = true;
	}
	islast = *epath == 0;
	trailing = islast && trailing;
	if (*buf == 0) {
		strcpy(buf, ".");
		islast = true;
	}

//		fprintf(stderr, "buf: %s\n", buf);

	int xfd = openpath(fd, buf);

	if (xfd < 0) {
		if (islast && last) {
			strcpy(last, buf);
			return xdup(fd.fd);
		} else {
			return -errno;
		}
	}

	// xfd >= 0
	FD newfd = FD(xfd);
	if (newfd.issym && (!islast || follow || (islast && trailing))) {
		Array<char, PATH_MAX> symbuf;
		//char symbuf[PATH_MAX];
		int ret = readlinkat(fd.fd, buf, symbuf.data(), PATH_MAX);
		if (ret < 0) {
			xclose(newfd.fd);
			return -errno;
		}

		if (ret == PATH_MAX) {
			xclose(newfd.fd);
			return -ENAMETOOLONG;
		}

		symbuf[ret] = 0;
		const char *symp = symbuf.data();
		FD dirfd;
		if (*symp == '/') {
			while (*symp && *symp == '/') {
				symp++;
			}
			dirfd = FD(root_fd.fd);
		} else {
			dirfd = FD(fd.fd);
		}

		int symret;
		if (!islast) {
			symret = resolve1(dirfd, symp, NULL, follow, count + 1);
		} else {
			symret = resolve1(dirfd, symp, last, follow, count + 1);
		}

		if (symret < 0) {
			xclose(newfd.fd);
			return symret;
		}

		if (islast) {
			xclose(newfd.fd);
			return symret;
		}
		xclose(newfd.fd);
		newfd = FD(symret);
	}

	if (!islast) {
		int res = resolve1(newfd, epath, last, follow, count);
		xclose(newfd.fd);
		return res;
	} else {
		if (last) {
			if (trailing) {
				if (!newfd.isdir) {
					xclose(newfd.fd);
					return -ENOTDIR;
				}
			}

			auto it = rbinds.find(newfd);
			if (it != rbinds.end()) {
				if (newfd.isdir)
					strcpy(last, ".");
				else
					strcpy(last, "");
				return newfd.fd;
			}

			xclose(newfd.fd);
			strcpy(last, buf);
			return xdup(fd.fd);
		} else {
			return newfd.fd;
		}
	}
}

int PathResolver::resolve(const char *path, char *last, bool follow)
{
	if (!path) {
		return -EFAULT;
	}

	if (*path == '/') {
		while (*path == '/')
			path++;
		if (*path) {
			return resolve1(root_fd, path, last, follow, 0);
		} else {
			if (last)
				strcpy(last, ".");
			return xdup(root_fd.fd);
		}
	} else {
		int xfd = resolve1(AT_FDCWD, path, last, follow, 0);
		return xfd;
	}
}

PathResolver::~PathResolver()
{
	if (root_fd.fd >= 0)
		xclose(root_fd.fd);
	for (auto &it : all_binds) {
		if (it.newfd.fd >= 0)
			xclose(it.newfd.fd);
		if (it.oldfd.fd >= 0)
			xclose(it.oldfd.fd);
	}
}
