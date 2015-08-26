/*
 * Copyright 2015 Andrew Ayer
 *
 * This file is part of disorderfs.
 *
 * disorderfs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * disorderfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with disorderfs.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdlib>
#include <ctime>
#include <cstring>
#include <string>
#include <fstream>
#include <fuse.h>
#include <dirent.h>
#include <iostream>
#include <memory>
#include <signal.h>
#include <sstream>
#include <unistd.h>
#include <errno.h>
#include <vector>
#include <random>
#include <algorithm>
#include <attr/xattr.h>
#include <sys/types.h>

#define DISORDERFS_VERSION "0.1.0"

namespace {
	std::vector<std::string>	bare_arguments;
	std::string			root;
	// TODO: cmdline opts for these:
	bool				shuffle_dirents{true};
	bool				reverse_dirents{false};
	bool				randomize_block_count{false};

	int wrap (int retval) { return retval == -1 ? -errno : 0; }
	using Dirents = std::vector<std::string>;

	struct fuse_operations		disorderfs_fuse_operations;
	enum {
		KEY_HELP,
		KEY_VERSION
	};
	const struct fuse_opt disorderfs_fuse_opts[] = {
		FUSE_OPT_KEY("-h", KEY_HELP),
		FUSE_OPT_KEY("--help", KEY_HELP),
		FUSE_OPT_KEY("-V", KEY_VERSION),
		FUSE_OPT_KEY("--version", KEY_VERSION),
		FUSE_OPT_END
	};
	int fuse_opt_proc (void* data, const char* arg, int key, struct fuse_args* outargs)
	{
		if (key == FUSE_OPT_KEY_NONOPT) {
			bare_arguments.emplace_back(arg);
			return 0;
		} else if (key == KEY_HELP) {
			std::clog << "Usage: disorderfs [OPTIONS] ROOTDIR MOUNTPOINT" << std::endl;
			std::clog << "General options:" << std::endl;
			std::clog << "    -o opt,[opt...]        mount options (see below)" << std::endl;
			std::clog << "    -h, --help             display help" << std::endl;
			std::clog << "    -V, --version          display version info" << std::endl;
			std::clog << std::endl;
			fuse_opt_add_arg(outargs, "-ho");
			fuse_main(outargs->argc, outargs->argv, &disorderfs_fuse_operations, NULL);
			std::exit(0);
		} else if (key == KEY_VERSION) {
			std::cout << "disorderfs version: " DISORDERFS_VERSION << std::endl;
			fuse_opt_add_arg(outargs, "--version");
			fuse_main(outargs->argc, outargs->argv, &disorderfs_fuse_operations, NULL);
			std::exit(0);
		}
		return 1;
	}
}

int	main (int argc, char** argv)
{
	signal(SIGPIPE, SIG_IGN);

	/*
	 * Initialize disorderfs_fuse_operations
	 */
	std::memset(&disorderfs_fuse_operations, '\0', sizeof(disorderfs_fuse_operations));

	disorderfs_fuse_operations.getattr = [] (const char* path, struct stat* st) -> int {
		if (lstat((root + path).c_str(), st) == -1) {
			return -errno;
		}
		if (randomize_block_count) {
			// TODO: also randomize blocks st->st_blocks = 129381;
		}
		return 0;
	};
	disorderfs_fuse_operations.readlink = [] (const char* path, char* buf, size_t sz) -> int {
		const ssize_t len{readlink((root + path).c_str(), buf, sz - 1)}; // sz > 0, since it includes space for null terminator
		if (len == -1) {
			return -errno;
		}
		buf[len] = '\0';
		return 0;
	};
	disorderfs_fuse_operations.mknod = [] (const char* path, mode_t mode, dev_t dev) -> int {
		return wrap(mknod((root + path).c_str(), mode, dev));
	};
	disorderfs_fuse_operations.mkdir = [] (const char* path, mode_t mode) -> int {
		return wrap(mkdir((root + path).c_str(), mode));
	};
	disorderfs_fuse_operations.unlink = [] (const char* path) -> int {
		return wrap(unlink((root + path).c_str()));
	};
	disorderfs_fuse_operations.rmdir = [] (const char* path) -> int {
		return wrap(rmdir((root + path).c_str()));
	};
	disorderfs_fuse_operations.symlink = [] (const char* target, const char* linkpath) -> int {
		return wrap(symlink(target, (root + linkpath).c_str()));
	};
	disorderfs_fuse_operations.rename = [] (const char* oldpath, const char* newpath) -> int {
		return wrap(rename((root + oldpath).c_str(), (root + newpath).c_str()));
	};
	disorderfs_fuse_operations.link = [] (const char* oldpath, const char* newpath) -> int {
		return wrap(link((root + oldpath).c_str(), (root + newpath).c_str()));
	};
	disorderfs_fuse_operations.chmod = [] (const char* path, mode_t mode) -> int {
		return wrap(chmod((root + path).c_str(), mode));
	};
	disorderfs_fuse_operations.chown = [] (const char* path, uid_t uid, gid_t gid) -> int {
		return wrap(lchown((root + path).c_str(), uid, gid));
	};
	disorderfs_fuse_operations.truncate = [] (const char* path, off_t length) -> int {
		return wrap(truncate((root + path).c_str(), length));
	};
	disorderfs_fuse_operations.open = [] (const char* path, struct fuse_file_info* info) -> int {
		const int fd{open((root + path).c_str(), info->flags)};
		if (fd == -1) {
			return -errno;
		}
		info->fh = fd;
		return 0;
	};
	disorderfs_fuse_operations.read = [] (const char* path, char* buf, size_t sz, off_t off, struct fuse_file_info* info) -> int {
		return pread(info->fh, buf, sz, off);
	};
	disorderfs_fuse_operations.write = [] (const char* path, const char* buf, size_t sz, off_t off, struct fuse_file_info* info) -> int {
		return pwrite(info->fh, buf, sz, off);
	};
	disorderfs_fuse_operations.statfs = [] (const char* path, struct statvfs* f) -> int {
		return wrap(statvfs((root + path).c_str(), f));
	};
	/* TODO: flush
	disorderfs_fuse_operations.flush = [] (const char* path, struct fuse_file_info* info) -> int {
	};
	*/
	disorderfs_fuse_operations.release = [] (const char* path, struct fuse_file_info* info) -> int {
		close(info->fh);
		return 0; // return value is ignored
	};
	/* TODO: fsync
	disorderfs_fuse_operations.fsync = [] (const char* path, int datasync, struct fuse_file_info* info) -> int {
	};
	*/
	disorderfs_fuse_operations.setxattr = [] (const char* path, const char* name, const char* value, size_t size, int flags) -> int {
		return wrap(setxattr((root + path).c_str(), name, value, size, flags));
	};
	disorderfs_fuse_operations.getxattr = [] (const char* path, const char* name, char* value, size_t size) -> int {
		ssize_t res = getxattr((root + path).c_str(), name, value, size);
		return res >= 0 ? res : -errno;
	};
	disorderfs_fuse_operations.listxattr = [] (const char* path, char* list, size_t size) -> int {
		ssize_t res = listxattr((root + path).c_str(), list, size);
		return res >= 0 ? res : -errno;
	};
	disorderfs_fuse_operations.removexattr = [] (const char* path, const char* name) -> int {
		return wrap(removexattr((root + path).c_str(), name));
	};
	disorderfs_fuse_operations.opendir = [] (const char* path, struct fuse_file_info* info) -> int {
		std::unique_ptr<Dirents> dirents{new Dirents};

		DIR* d = opendir((root + path).c_str());
		if (!d) {
			return -errno;
		}
		struct dirent	dirent_storage;
		struct dirent*	dirent_p;
		int		res;
		while ((res = readdir_r(d, &dirent_storage, &dirent_p)) == 0 && dirent_p) {
			dirents->emplace_back(dirent_p->d_name);
		}
		if (reverse_dirents) {
			std::reverse(dirents->begin(), dirents->end());
		}
		closedir(d);
		if (res != 0) {
			return -res;
		}

		info->fh = reinterpret_cast<uint64_t>(dirents.release());
		return 0;
	};
	disorderfs_fuse_operations.readdir = [] (const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* info) {
		Dirents&		dirents = *reinterpret_cast<Dirents*>(info->fh);
		if (shuffle_dirents) {
			std::random_device	rd;
			std::mt19937		g(rd());
			std::shuffle(dirents.begin(), dirents.end(), g);
		}

		for (const std::string& dirent : dirents) {
			if (filler(buf, dirent.c_str(), nullptr, 0) != 0) {
				return -ENOMEM;
			}
		}
		return 0;
	};
	disorderfs_fuse_operations.releasedir = [] (const char* path, struct fuse_file_info* info) -> int {
		delete reinterpret_cast<Dirents*>(info->fh);
		return 0;
	};
	/* TODO: fsyncdir
	disorderfs_fuse_operations.fsyncdir = [] (const char* path, int datasync, struct fuse_file_info* info) -> int {
	};
	*/
	disorderfs_fuse_operations.access = [] (const char* path, int mode) -> int {
		return wrap(access((root + path).c_str(), mode));
	};
	disorderfs_fuse_operations.create = [] (const char* path, mode_t mode, struct fuse_file_info* info) -> int {
		// XXX: use info->flags?
		const int fd{open((root + path).c_str(), info->flags | O_CREAT, mode)};
		if (fd == -1) {
			return -errno;
		}
		info->fh = fd;
		return 0;
	};
	disorderfs_fuse_operations.ftruncate = [] (const char* path, off_t off, struct fuse_file_info* info) -> int {
		return wrap(ftruncate(info->fh, off));
	};
	disorderfs_fuse_operations.fgetattr = [] (const char* path, struct stat* st, struct fuse_file_info* info) -> int {
		if (fstat(info->fh, st) == -1) {
			return -errno;
		}
		if (randomize_block_count) {
			// TODO: also randomize blocks st->st_blocks = 129381;
		}
		return 0;
	};
	/* TODO: locking
	disorderfs_fuse_operations.loc = [] (const char *, struct fuse_file_info *, int cmd, struct flock *) -> int {
	};
	disorderfs_fuse_operations.flock = [] (const char *, struct fuse_file_info *, int op) -> int {
	};
	*/
	disorderfs_fuse_operations.utimens = [] (const char* path, const struct timespec tv[2]) -> int {
		return wrap(utimensat(AT_FDCWD, (root + path).c_str(), tv, AT_SYMLINK_NOFOLLOW));
	};
	/* Not applicable?
	disorderfs_fuse_operations.bmap = [] (const char *, size_t blocksize, uint64_t *idx) -> int {
	};
	*/
	/* Not needed?
	disorderfs_fuse_operations.ioctl = [] (const char *, int cmd, void *arg, struct fuse_file_info *, unsigned int flags, void *data) -> int {
	};
	*/
	/* ???
	disorderfs_fuse_operations.poll = [] (const char *, struct fuse_file_info *, struct fuse_pollhandle *ph, unsigned *reventsp) -> int {
	};
	*/
	/* TODO: implement these, for efficiency
	disorderfs_fuse_operations.write_buf = [] (const char *, struct fuse_bufvec *buf, off_t off, struct fuse_file_info *) -> int {
	};
	disorderfs_fuse_operations.read_buf = [] (const char *, struct fuse_bufvec **bufp, size_t size, off_t off, struct fuse_file_info *) -> int {
	};
	*/
	disorderfs_fuse_operations.fallocate = [] (const char* path, int mode, off_t off, off_t len, struct fuse_file_info* info) -> int {
		return wrap(fallocate(info->fh, mode, off, len));
	};

	/*
	 * Parse command line options
	 */
	struct fuse_args	fargs = FUSE_ARGS_INIT(argc, argv);
	fuse_opt_parse(&fargs, nullptr, disorderfs_fuse_opts, fuse_opt_proc);

	if (bare_arguments.size() != 2) {
		std::clog << "disorderfs: error: wrong number of arguments" << std::endl;
		std::clog << "Usage: disorderfs [OPTIONS] ROOTDIR MOUNTPOINT" << std::endl;
		return 2;
	}

	root = bare_arguments[0];

	// Add some of our own hard-coded FUSE options:
	fuse_opt_add_arg(&fargs, "-o");
	fuse_opt_add_arg(&fargs, "direct_io,atomic_o_trunc"); // XXX: other mount options?
	fuse_opt_add_arg(&fargs, bare_arguments[1].c_str());

	return fuse_main(fargs.argc, fargs.argv, &disorderfs_fuse_operations, nullptr);
}
