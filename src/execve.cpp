#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <syscall.h>
#include <string.h>
extern "C" {
#include "syscall_hook.h"
}
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "path_resolver.h"
#include "utils.h"

int handle_execve(struct frame *f, PathResolver *resolver, char *loader)
{
	if (loader == NULL) {
		const char *path = (char *) f->args[0];
		int ret = resolver->resolve(path, NULL, true);
		if (ret < 0) {
			f->nr_ret = -EACCES;
			return 1;
		}
		Array<char, PATH_MAX> exepath;
		int err = xfdpath(ret, exepath.data());
		if (err < 0) {
			f->nr_ret = err;
			xclose(ret);
			return 1;
		}
		f->args[0] = (unsigned long) exepath.data();
		f->nr_ret = syscall(SYS_execve, f->args[0], f->args[1], f->args[2]);
		if ((long) f->nr_ret == -1)
			f->nr_ret = -errno;
		return 1;
	}

	if (strcmp((char *) f->args[0], "/proc/self/exe") == 0) {
		char **argv = (char **) f->args[1];
		char **argv_last = argv;
		while (*argv_last) argv_last++;
		char **new_argv = (char **) malloc((argv_last - argv + 2) * sizeof(*argv));
		memcpy(new_argv + 1, argv, (argv_last - argv + 1) * sizeof(*argv));
		new_argv[1] = getenv("SQROOT_ORIG_EXE");
		new_argv[0] = loader;

		f->args[0]= (long) new_argv[0];
		f->args[1] = (long) new_argv;
		f->nr_ret = syscall(SYS_execve, f->args[0], f->args[1], f->args[2]);
		if ((long) f->nr_ret == -1)
			f->nr_ret = -errno;

		free(new_argv);
		return 1;
	}

	const char *path = (char *) f->args[0];
	if (strstr(path, "ld-linux-") != NULL)
		return 0;

	Array<char, PATH_MAX> last;
	int ret = resolver->resolve(path, last.data(), true);
	if (ret < 0) {
		f->nr_ret = -EACCES;
		return 1;
	}

	int exefd;
	if (last[0]) {
		if (faccessat(ret, last.data(), X_OK, 0)) {
			f->nr_ret = -EACCES;
			xclose(ret);
			return 1;
		}
		exefd = openat(ret, last.data(), O_RDONLY);
	} else {
		Array<char, PATH_MAX> exepath;
		if (xfdpath(ret, exepath.data()) < 0) {
			exefd = -1;
		} else {
			if (access(exepath.data(), X_OK)) {
				f->nr_ret = -EACCES;
				xclose(ret);
				return 1;
			}
			exefd = open(exepath.data(), O_RDONLY);
		}
	}
	if (exefd < 0) {
		f->nr_ret = -EACCES;
		xclose(ret);
		return 1;
	}

	char buf[2];
	if (read(exefd, buf, 2) != 2) {
		f->nr_ret = -EACCES;
		xclose(exefd);
		xclose(ret);
		return 1;
	}

	if (buf[0] == '#' && buf[1] == '!') {
		xclose(ret);
		char line[256];
		int ret = read(exefd, line, 255);
		if (ret < 0) {
			f->nr_ret = -errno;
			return 1;
		}
		line[ret] = 0;

		xclose(exefd);
		int h = 0;
		while (line[h] && line[h] == ' ')
			h++;
		int i = h;
		int j = 0;
		while (line[i] &&
		       line[i] != ' ' &&
		       line[i] != '\n')
			i++;
		char sep = line[i];
		line[i] = 0;
		if (sep == ' ') {
			j = i + 1;
			while (line[j] && line[j] != '\n')
				j++;
			line[j] = 0;
			j = i + 1;
		}

		int pathfd = resolver->resolve(line + h, NULL, true);
		Array<char, PATH_MAX> exepath;
		Array<char, PATH_MAX> env_exepath; // + 20
		int err = xfdpath(pathfd, exepath.data());
		xclose(pathfd);
		if (err < 0) {
			f->nr_ret = err;
			return 1;
		}
		strcpy(env_exepath.data(), "SQROOT_ORIG_EXE=");
		strcat(env_exepath.data(), exepath.data());

		char **argv = (char **) f->args[1];
		char **argv_last = argv;
		while (*argv_last) argv_last++;
		char **new_argv = (char **) malloc((argv_last - argv + 4) * sizeof(*argv));
		if (j > 0) {
			memcpy(new_argv + 3, argv, (argv_last - argv + 1) * sizeof(*argv));
			new_argv[3] = (char *) f->args[0];
			new_argv[2] = line + j;
			new_argv[1] = exepath.data();
			new_argv[0] = loader;
		} else {
			memcpy(new_argv + 2, argv, (argv_last - argv + 1) * sizeof(*argv));
			new_argv[2] = (char *) f->args[0];
			new_argv[1] = exepath.data();
			new_argv[0] = loader;
		}

		char **envp = (char **) f->args[2];
		char **envp_last = envp;
		char **old_env_exepath = NULL;
		while (*envp_last) {
			if (strncmp(*envp_last, "SQROOT_ORIG_EXE=", 16) == 0)
				old_env_exepath = envp_last;
			envp_last++;
		}

		char **new_envp;
		if (old_env_exepath) {
			new_envp = envp;
		} else {
			new_envp = (char **) malloc((envp_last - envp + 2) * sizeof(*envp));
			memcpy(new_envp + 1, envp, (envp_last - envp + 1) * sizeof(*envp));
			old_env_exepath = new_envp;
		}
		*old_env_exepath = env_exepath.data();

		f->args[0] = (long) new_argv[0];
		f->args[1] = (long) new_argv;
		f->args[2] = (long) new_envp;
		f->nr_ret = syscall(SYS_execve, f->args[0], f->args[1], f->args[2]);
		if ((long) f->nr_ret == -1)
			f->nr_ret = -errno;

		free(new_argv);
		if (new_envp != envp)
			free(new_envp);
		return 1;
	}
	xclose(exefd);

	Array<char, PATH_MAX> exepath;
	Array<char, PATH_MAX> env_exepath; // + 20
	int err = xfdpath(ret, exepath.data());
	xclose(ret);
	if (err < 0) {
		f->nr_ret = err;
		return 1;
	}
	if (last[0]) {
		strcat(exepath.data(), "/");
		strcat(exepath.data(), last.data());
	}

	strcpy(env_exepath.data(), "SQROOT_ORIG_EXE=");
	strcat(env_exepath.data(), exepath.data());

	char **argv = (char **) f->args[1];
	char **argv_last = argv;
	while (*argv_last) argv_last++;
	char **new_argv = (char **) malloc((argv_last - argv + 2) * sizeof(*argv));
	memcpy(new_argv + 1, argv, (argv_last - argv + 1) * sizeof(*argv));
	new_argv[1] = exepath.data();
	new_argv[0] = loader;

	char **envp = (char **) f->args[2];
	char **envp_last = envp;
	char **old_env_exepath = NULL;
	while (*envp_last) {
		if (strncmp(*envp_last, "SQROOT_ORIG_EXE=", 16) == 0)
			old_env_exepath = envp_last;
		envp_last++;
	}

	char **new_envp;
	if (old_env_exepath) {
		new_envp = envp;
	} else {
		new_envp = (char **) malloc((envp_last - envp + 2) * sizeof(*envp));
		memcpy(new_envp + 1, envp, (envp_last - envp + 1) * sizeof(*envp));
		old_env_exepath = new_envp;
	}
	*old_env_exepath = env_exepath.data();

	f->args[0] = (long) new_argv[0];
	f->args[1] = (long) new_argv;
	f->args[2] = (long) new_envp;
	f->nr_ret = syscall(SYS_execve, f->args[0], f->args[1], f->args[2]);
	if ((long) f->nr_ret == -1)
		f->nr_ret = -errno;

	free(new_argv);
	if (new_envp != envp)
		free(new_envp);
	return 1;
}
