#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>

void usage(const char *basename)
{
	fprintf(stderr,
		"Usage: %s [-r rootdir] [-b old:new] [-L library_path] [-l loader] -- commands...\n", basename);
}

int main(int argc, char *argv[])
{
	const char *root = "/";
	const char *wd = "/";
	const char *library_path = NULL;
	std::string binds;
	std::string loader = "ld-linux-x86-64.so.2";
	std::string shared_object;
	bool flag = true;
	int opt;

	while (flag && (opt = getopt(argc, argv, "r:b:L:l:-")) != -1) {
		switch (opt) {
		case 'r':
			root = optarg;
			if (root[0] != '/') {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'b':
			if (binds.size())
				binds += ":";
			binds += optarg;
			break;
		case 'L':
			library_path = optarg;
			if (library_path[0] != '/') {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'l':
			loader = optarg;
			break;
		case '-':
			flag = false;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (!library_path || optind >= argc) {
		usage(argv[0]);
		return 1;
	}

	loader = std::string(library_path) + "/" + loader;
	shared_object = std::string(library_path) + "/libsqroot.so";

	if (binds.size())
		setenv("SQROOT_BINDS", binds.c_str(), 1);
	setenv("SQROOT_ROOT", root, 1);
	setenv("SQROOT_LOADER", loader.c_str(), 1);
	setenv("LD_LIBRARY_PATH", library_path, 1);
	setenv("LD_PRELOAD", shared_object.c_str(), 1);

	argv[optind - 1] = (char *) loader.c_str();
	chdir(root);
	return execv(loader.c_str(), argv + optind - 1);
}
