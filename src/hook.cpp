#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <syscall.h>
#include <string.h>
extern "C" {
#include "syscall_hook.h"
}

#include "path_resolver.h"
#include "array.h"
#include "utils.h"
#include <string>
#include <vector>
#include <map>
#include <sys/prctl.h>

#include <sys/socket.h>
#include <sys/un.h>

#ifndef SYS_clone3
#define SYS_clone3 435
#endif

#ifndef SYS_close_range
#define SYS_close_range 436
#endif

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif

static int get_comp(const char *p, int i)
{
	while (p[i] != 0 && p[i] != ':')
		i++;
	return i;
}

struct _G {
	char *loader;
	PathResolver resolver;
	int fake_uid;
	_G() {
		const char *orig_exe = getenv("SQROOT_ORIG_EXE");
		if (orig_exe) {
			const char *slash = strrchr(orig_exe, '/');
			slash = slash ? slash + 1 : orig_exe;
			prctl(PR_SET_NAME, slash, 0, 0, 0);
		}
		loader = getenv("SQROOT_LOADER");
		char *root = getenv("SQROOT_ROOT");
		if (!root)
			abort();

		if (!resolver.set_root(root))
			abort();

		char *uid_str = getenv("SQROOT_UID");
		if (uid_str) {
			fake_uid = atoi(uid_str);
		} else {
			fake_uid = -1;
		}

		char *binds = getenv("SQROOT_BINDS");
		if (binds) {
			if (strchr(binds, '\\')) {
				fprintf(stderr, "NIY: SQROOT_BINDS is quoted\n");
				abort();
			}

			int i = 0;
			int j;
			int state = 0;
			int k1, k2;
			bool ok = true;
			while (true) {
				j = get_comp(binds, i);
				if (state == 0) {
					k1 = i;
					k2 = j;
					state = 1;
				} else if (state == 1) {
					ok = ok &&
						resolver.bind(std::string(binds + k1 , binds + k2).c_str(),
							      (root + std::string(binds + i , binds + j)).c_str());
					state = 0;
				}

				if (binds[j]) {
					i = j + 1;
				} else {
					break;
				}
			}

			if (state || !ok) {
				fprintf(stderr, "bad SQROOT_BINDS\n");
				abort();
			}
		}
	}
};

static _G globals;

int handle_execve(struct frame *f, PathResolver *resolver, char *loader);

bool pathat_follow(struct frame *f)
{
	unsigned long nr = f->nr_ret;
	if (nr == SYS_name_to_handle_at)
		return !!(f->args[4] & AT_SYMLINK_FOLLOW);

	if (nr == SYS_linkat)
		return !!(f->args[4] & AT_SYMLINK_FOLLOW);

	bool follow = true;
	if (nr == SYS_openat && (f->args[2] & (O_NOFOLLOW|O_CREAT)) ||
	    nr == SYS_fchownat && (f->args[4] & AT_SYMLINK_NOFOLLOW) ||
	    nr == SYS_newfstatat && (f->args[3] & AT_SYMLINK_NOFOLLOW) ||
	    nr == SYS_statx && (f->args[2] & AT_SYMLINK_NOFOLLOW) ||
	    nr == SYS_faccessat2 && (f->args[3] & AT_SYMLINK_NOFOLLOW) ||
	    nr == SYS_mkdirat ||
	    nr == SYS_mknodat ||
	    nr == SYS_unlinkat) {
		follow = false;
	}
	return follow;
}

bool pathat_empty_path(struct frame *f)
{
	bool res = false;
	unsigned long nr = f->nr_ret;
	if (nr == SYS_fchownat && (f->args[4] & AT_EMPTY_PATH) ||
	    nr == SYS_newfstatat && (f->args[3] & AT_EMPTY_PATH) ||
	    nr == SYS_name_to_handle_at && (f->args[4] & AT_EMPTY_PATH) ||
	    nr == SYS_statx && (f->args[2] & AT_EMPTY_PATH) ||
	    nr == SYS_linkat && (f->args[4] & AT_EMPTY_PATH)) {
		res = true;
	}
	return res;
}

int handle_pathat1_generic(struct frame *f, PathResolver *resolver, bool follow, bool empty_path)
{
	const char *path = (char *) f->args[1];
	Array<char, PATH_MAX> last;

	int ret;
	if (empty_path && (path && path[0] == 0)) {
		ret = xdup(f->args[0]);
	} else {
		if ((int) f->args[0] == AT_FDCWD || (path && path[0] == '/')) {
			ret = resolver->resolve(path, last.data(), follow);
		} else {
			FD dirfd = FD(f->args[0]);
			ret = resolver->resolve1(dirfd, path, last.data(), follow, 0);
		}
	}

	if (ret < 0) {
		f->nr_ret = ret;
		return 1;
	}

	if (f->nr_ret != SYS_unlinkat && path && path[0] && last[0] == 0) {
		int err = xfdpath(ret, last.data());
		if (err < 0) {
			f->nr_ret = err;
			xclose(ret);
			return 1;
		}
		f->args[0] = AT_FDCWD;
		f->args[1] = (unsigned long) last.data();
	} else {
		f->args[0] = ret;
		if (!empty_path)
			f->args[1] = (unsigned long) last.data();
	}
	f->nr_ret = syscall(f->nr_ret, f->args[0], f->args[1], f->args[2], f->args[3], f->args[4], f->args[5]);
	if ((long) f->nr_ret < 0)
		f->nr_ret = -errno;
	xclose(ret);
	return 1;
}

int handle_pathat2_generic(struct frame *f, PathResolver *resolver, bool follow)
{
	const char *path = (char *) f->args[2];
	Array<char, PATH_MAX> last;

	int ret;
	if ((int) f->args[1] == AT_FDCWD || (path && path[0] == '/')) {
		ret = resolver->resolve(path, last.data(), follow);
	} else {
		FD dirfd = FD(f->args[1]);
		ret = resolver->resolve1(dirfd, path, last.data(), follow, 0);
	}

	if (ret < 0) {
		f->nr_ret = ret;
		return 1;
	}

	f->args[1] = ret;
	f->args[2] = (unsigned long) last.data();
	f->nr_ret = syscall(f->nr_ret, f->args[0], f->args[1], f->args[2], f->args[3], f->args[4], f->args[5]);
	if ((long) f->nr_ret < 0)
		f->nr_ret = -errno;
	xclose(ret);
	return 1;
}

int handle_pathat1_null(struct frame *f, PathResolver *resolver, bool follow, bool empty_path)
{
	if (f->args[1])
		return handle_pathat1_generic(f, resolver, follow, empty_path);
	else
		return 0;
}

bool path_follow(struct frame *f)
{
	bool follow = true;
	unsigned long nr = f->nr_ret;
	if (nr == SYS_lstat || nr == SYS_lchown || nr == SYS_readlink ||
	    nr == SYS_unlink ||
	    nr == SYS_lsetxattr || nr == SYS_lgetxattr ||
	    nr == SYS_llistxattr || nr == SYS_lremovexattr) {
		follow = false;
	}
	return follow;
}

int handle_path_generic(struct frame *f, PathResolver *resolver, bool follow)
{
	const char *path = (char *) f->args[0];
	Array<char, PATH_MAX> newpath;

	int ret = resolver->resolve(path, NULL, follow);

	if (ret < 0) {
		f->nr_ret = ret;
		return 1;
	}

	int err = xfdpath(ret, newpath.data());
	if (err < 0) {
		f->nr_ret = err;
		xclose(ret);
		return 1;
	}

	f->args[0] = (unsigned long) newpath.data();
	f->nr_ret = syscall(f->nr_ret, f->args[0], f->args[1], f->args[2], f->args[3], f->args[4], f->args[5]);
	if ((long) f->nr_ret < 0)
		f->nr_ret = -errno;
	xclose(ret);
	return 1;
}

int handle_readlink(struct frame *f, PathResolver *resolver)
{
	const char *path = (char *) f->args[0];
	int pathlen = path ? strlen(path) : 0;

	if (path &&
	    strncmp(path, "/proc/", 6) == 0 &&
	    strncmp(path + pathlen - 4, "/exe", 4) == 0) {
		const char *orig_exe = getenv("SQROOT_ORIG_EXE");
		if (orig_exe) {
			Array<char, PATH_MAX> exepath;
			strcpy(exepath.data(), orig_exe);
			resolver->reverse_resolve(exepath.data(), PATH_MAX);
			unsigned long size = strlen(exepath.data());

			if (f->args[1] && f->args[2] >= size) {
				memcpy((char *) f->args[1], exepath.data(), size);
				f->nr_ret = size;
				return 1;
			} else {
				f->nr_ret = -ENAMETOOLONG;
				return 1;
			}
		}
	}
	return handle_path_generic(f, resolver, path_follow(f));
}

int handle_pathat13_generic(struct frame *f, PathResolver *resolver, bool follow1, bool empty_path1)
{
	const char *path1 = (char *) f->args[1];
	const char *path2 = (char *) f->args[3];
	Array<char, PATH_MAX> last1, last2;

	int ret1;
	if (empty_path1 && (path1 && path1[0] == 0)) {
		ret1 = xdup(f->args[0]);
	} else {
		if ((int) f->args[0] == AT_FDCWD || (path1 && path1[0] == '/')) {
			ret1 = resolver->resolve(path1, last1.data(), follow1);
		} else {
			FD dirfd = FD(f->args[0]);
			ret1 = resolver->resolve1(dirfd, path1, last1.data(), follow1, 0);
		}
	}
	if (ret1 < 0) {
		f->nr_ret = ret1;
		return 1;
	}

	int ret2;
	if ((int) f->args[2] == AT_FDCWD || (path2 && path2[0] == '/')) {
		ret2 = resolver->resolve(path2, last2.data(), false);
	} else {
		FD dirfd = FD(f->args[2]);
		ret2 = resolver->resolve1(dirfd, path2, last2.data(), false, 0);
	}
	if (ret2 < 0) {
		f->nr_ret = ret2;
		return 1;
	}

	f->args[0] = ret1;
	if (!empty_path1)
		f->args[1] = (unsigned long) last1.data();
	f->args[2] = ret2;
	f->args[3] = (unsigned long) last2.data();
	f->nr_ret = syscall(f->nr_ret, f->args[0], f->args[1], f->args[2], f->args[3], f->args[4], f->args[5]);
	if ((long) f->nr_ret < 0)
		f->nr_ret = -errno;
	xclose(ret1);
	xclose(ret2);
	return 1;
}

int handle_chdir(struct frame *f, PathResolver *resolver)
{
	const char *path = (char *) f->args[0];
	int ret = resolver->resolve(path, NULL, true);
	if (ret < 0) {
		f->nr_ret = ret;
		return 1;
	}

	f->nr_ret = syscall(SYS_fchdir, ret);
	if (f->nr_ret != 0) {
		f->nr_ret = -errno;
	}
	xclose(ret);
	return 1;
}

int handle_close(struct frame *f, PathResolver *resolver)
{
	int fd = (int) f->args[0];
	if (resolver->isin(fd)) {
		f->nr_ret = 0;
		return 1;
	}
	return 0;
}

int handle_dup23(struct frame *f, PathResolver *resolver)
{
	int fd = (int) f->args[1];
	if (resolver->isin(fd)) {
		fprintf(stderr, "dup\n");
		f->nr_ret = -EMFILE;
		return 1;
	}
	return 0;
}

int handle_getcwd(struct frame *f, PathResolver *resolver)
{
	char *buf = (char *) f->args[0];
	unsigned long bsize = f->args[1];
	char *p = getcwd(buf, bsize);
	if (!p) {
		return -ENAMETOOLONG;
	}

	f->nr_ret = resolver->reverse_resolve(buf, bsize);
	return 1;
}

int handle_bind_or_connect(struct frame *f, PathResolver *resolver)
{
	const char *root = getenv("SQROOT_ROOT");
	if (!root)
		return 0;

	struct sockaddr_un *addr_un = (struct sockaddr_un *) f->args[1];
	if (addr_un->sun_family == AF_UNIX && addr_un->sun_path && *(addr_un->sun_path)) {
		socklen_t newaddrlen;
		struct sockaddr_un newaddr_un;

		const int af_unix_path_max = sizeof(addr_un->sun_path);
		const char *path = addr_un->sun_path;

		Array<char, PATH_MAX> last, realpath;
		int pathfd = resolver->resolve(path, last.data(), false);
		if (pathfd < 0) {
			f->nr_ret = -ENOENT;
			return 1;
		}

		int ret1 = xfdpath(pathfd, realpath.data());
		xclose(pathfd);

		if (ret1 < 0) {
			f->nr_ret = -ENOENT;
			return 1;
		}

		if (strlen(realpath.data()) + 1 + strlen(last.data()) >= af_unix_path_max) {
			f->nr_ret = -ENAMETOOLONG;
			return 1;
		}

		strcat(realpath.data(), "/");
		strcat(realpath.data(), last.data());
		path = realpath.data();

		memset(&newaddr_un, 0, sizeof(struct sockaddr_un));
		newaddr_un.sun_family = addr_un->sun_family;
		strcpy(newaddr_un.sun_path, path);
		newaddrlen = SUN_LEN(&newaddr_un);

		int ret = syscall(f->nr_ret, f->args[0], (struct sockaddr *)&newaddr_un, newaddrlen);
		if (ret < 0) {
			f->nr_ret = -errno;
		} else {
			f->nr_ret = ret;
		}
		return 1;
	}
	return 0;
}

int no_privilege(struct frame *f)
{
	f->nr_ret = -EPERM;
	return 1;
}

int no_syscall(struct frame *f)
{
	f->nr_ret = -ENOSYS;
	return 1;
}

int ignore_eperm(struct frame *f)
{
	f->nr_ret = syscall(f->nr_ret, f->args[0], f->args[1], f->args[2], f->args[3], f->args[4], f->args[5]);
	if ((long) f->nr_ret < 0) {
		if (errno == EPERM) {
			f->nr_ret = 0;
		} else {
			f->nr_ret = -errno;
		}
	}
	return 1;
}

void prepend_at(struct frame *f, unsigned long nr)
{
	f->args[5] = f->args[4];
	f->args[4] = f->args[3];
	f->args[3] = f->args[2];
	f->args[2] = f->args[1];
	f->args[1] = f->args[0];
	f->args[0] = AT_FDCWD;
	f->nr_ret = nr;
}

static void preprocess(struct frame *f)
{
	switch (f->nr_ret) {
	case SYS_open:
		prepend_at(f, SYS_openat);
		break;
	case SYS_creat:
		prepend_at(f, SYS_openat);
		f->args[3] = f->args[2];
		f->args[2] = O_CREAT | O_WRONLY | O_TRUNC;
		break;
	case SYS_mkdir:
		prepend_at(f, SYS_mkdirat);
		break;
	case SYS_mknod:
		prepend_at(f, SYS_mknodat);
		break;
	case SYS_rename:
		f->args[3] = f->args[1];
		f->args[2] = AT_FDCWD;
		f->args[1] = f->args[0];
		f->args[0] = AT_FDCWD;
		f->nr_ret = SYS_renameat;
		break;
	case SYS_link:
		f->args[4] = 0;
		f->args[3] = f->args[1];
		f->args[2] = AT_FDCWD;
		f->args[1] = f->args[0];
		f->args[0] = AT_FDCWD;
		f->nr_ret = SYS_linkat;
		break;
	case SYS_symlink:
		f->args[2] = f->args[1];
		f->args[1] = AT_FDCWD;
		f->nr_ret = SYS_symlinkat;
		break;
	case SYS_unlink:
		f->args[2] = 0;
		f->args[1] = f->args[0];
		f->args[0] = AT_FDCWD;
		f->nr_ret = SYS_unlinkat;
		break;
	case SYS_rmdir:
		f->args[2] = AT_REMOVEDIR;
		f->args[1] = f->args[0];
		f->args[0] = AT_FDCWD;
		f->nr_ret = SYS_unlinkat;
		break;
	case SYS_chown:
		prepend_at(f, SYS_fchownat);
		f->args[4] = 0;
		break;
	case SYS_lchown:
		prepend_at(f, SYS_fchownat);
		f->args[4] = AT_SYMLINK_NOFOLLOW;
		break;
	case SYS_access:
		prepend_at(f, SYS_faccessat);
		break;
	default:
		break;
	}
}

int handle_getuid(struct frame *f)
{
	if (globals.fake_uid != -1) {
		f->nr_ret = globals.fake_uid;
		return 1;
	}
	return 0;
}

int syscall_hook(struct frame *f)
{
	preprocess(f);

	auto resolver = &globals.resolver;
	auto loader = globals.loader;

	switch (f->nr_ret) {
	case SYS_geteuid:
	case SYS_getuid:
		return handle_getuid(f);
	case SYS_fchown:
		if (globals.fake_uid == 0) {
			return ignore_eperm(f);
		}
		return 0;
	case SYS_fchownat:
		if (handle_pathat1_generic(f, resolver, pathat_follow(f), pathat_empty_path(f))) {
			if (globals.fake_uid == 0 && f->nr_ret == -EPERM)
				f->nr_ret = 0;
			return 1;
		} else {
			if (globals.fake_uid == 0)
				return ignore_eperm(f);
			return 0;
		}
	case SYS_execve:
		return handle_execve(f, resolver, loader);
	case SYS_execveat:
		return no_syscall(f);
	case SYS_readlink:
		return handle_readlink(f, resolver);
	case SYS_getcwd:
		return handle_getcwd(f, resolver);
	case SYS_chdir:
		return handle_chdir(f, resolver);
	case SYS_close:
		return handle_close(f, resolver);
	case SYS_dup2:
	case SYS_dup3:
		return handle_dup23(f, resolver);
	case SYS_statx:
	case SYS_utimensat:
		return handle_pathat1_null(f, resolver, pathat_follow(f), pathat_empty_path(f));
	case SYS_openat:
	case SYS_mkdirat:
	case SYS_mknodat:
	case SYS_futimesat:
	case SYS_newfstatat:
	case SYS_unlinkat:
	case SYS_readlinkat:
	case SYS_fchmodat:
	case SYS_faccessat:
	case SYS_name_to_handle_at:
	case SYS_faccessat2:
		return handle_pathat1_generic(f, resolver, pathat_follow(f), pathat_empty_path(f));
	case SYS_symlinkat:
		return handle_pathat2_generic(f, resolver, false);
	case SYS_renameat:
	case SYS_renameat2:
		return handle_pathat13_generic(f, resolver, false, false);
	case SYS_linkat:
		return handle_pathat13_generic(f, resolver, pathat_follow(f), pathat_empty_path(f));
	case SYS_chroot:
		if (globals.fake_uid == 0 &&
		    strcmp((char *) f->args[0], "/") == 0) {
			f->nr_ret = 0;
			return 1;
		}
		/* fall through */
	case SYS_stat:
	case SYS_lstat:
	case SYS_truncate:
	case SYS_chmod:
	case SYS_uselib:
	case SYS_statfs:
	case SYS_acct:
	case SYS_swapon:
	case SYS_swapoff:
	case SYS_setxattr:
	case SYS_lsetxattr:
	case SYS_getxattr:
	case SYS_lgetxattr:
	case SYS_listxattr:
	case SYS_llistxattr:
	case SYS_removexattr:
	case SYS_lremovexattr:
		return handle_path_generic(f, resolver, path_follow(f));
	case SYS_pivot_root:
	case SYS_mount:
		return no_privilege(f);
	case SYS_access:
	case SYS_open:
	case SYS_creat:
	case SYS_rename:
	case SYS_link:
	case SYS_symlink:
	case SYS_mkdir:
	case SYS_mknod:
	case SYS_unlink:
	case SYS_rmdir:
	case SYS_chown:
	case SYS_lchown:
	case SYS_clone3:
	case SYS_close_range:
	case SYS_openat2:
		return no_syscall(f);
	case SYS_bind:
	case SYS_connect:
		return handle_bind_or_connect(f, resolver);
	case 0xaaaaaaaa: {
		ssize_t ret = syscall(SYS_readlink, f->args[0], f->args[1], f->args[2]);
		if (ret < 0) {
			f->nr_ret = -errno;
		} else {
			f->nr_ret = ret;
		}
		return 1;
	}
	default:
		return 0;
	}
}
