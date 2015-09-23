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
extern "C" {
#include <ulockmgr.h>
}
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
#include <sys/syscall.h>
#include <sys/file.h>
#include <stddef.h>

#define DISORDERFS_VERSION "0.3.0"

namespace {
	std::vector<std::string>	bare_arguments;
	std::string			root;
	struct Disorderfs_config {
		bool			multi_user{false};
		bool			shuffle_dirents{false};
		bool			reverse_dirents{true};
		unsigned int		pad_blocks{1};
	};
	Disorderfs_config		config;

	void perror_and_die (const char* s)
	{
		std::perror(s);
		std::abort();
	}

	int wrap (int retval) { return retval == -1 ? -errno : 0; }
	using Dirents = std::vector<std::string>;

	// The libc versions of seteuid, etc. set the credentials for all threads.
	// We need to set credentials for a single thread only, so call the syscalls directly.
	int thread_seteuid (uid_t euid)
	{
#ifdef SYS_setresuid32
		return syscall(SYS_setresuid32, static_cast<uid_t>(-1), euid, static_cast<uid_t>(-1));
#else
		return syscall(SYS_setresuid, static_cast<uid_t>(-1), euid, static_cast<uid_t>(-1));
#endif
	}
	int thread_setegid (gid_t egid)
	{
#ifdef SYS_setresgid32
		return syscall(SYS_setresgid32, static_cast<gid_t>(-1), egid, static_cast<gid_t>(-1));
#else
		return syscall(SYS_setresgid, static_cast<gid_t>(-1), egid, static_cast<gid_t>(-1));
#endif
	}
	int thread_setgroups (size_t size, const gid_t* list)
	{
#ifdef SYS_setgroups32
		return syscall(SYS_setgroups32, size, list);
#else
		return syscall(SYS_setgroups, size, list);
#endif
	}

	std::vector<gid_t> get_fuse_groups ()
	{
		long				ngroups_max = sysconf(_SC_NGROUPS_MAX);
		if (ngroups_max < 0) {
			ngroups_max = 65536;
		}
		std::vector<gid_t>		groups(ngroups_max + 1);
		int				ngroups = fuse_getgroups(groups.size(), groups.data());
		if (ngroups < 0) {
			std::perror("fuse_getgroups");
			groups.clear();
		} else if (static_cast<unsigned int>(ngroups) < groups.size()) {
			groups.resize(ngroups);
		}
		return groups;
	}

	void drop_privileges ()
	{
		// These functions should not fail as long as disorderfs is running as root.
		// If they do fail, things could be in a pretty inconsistent state, so just
		// kill the program instead of trying to gracefully recover.
		const std::vector<gid_t>	groups(get_fuse_groups());
		if (thread_setgroups(groups.size(), groups.data()) == -1) {
			perror_and_die("setgroups");
		}
		if (thread_setegid(fuse_get_context()->gid) == -1) {
			perror_and_die("setegid");
		}
		if (thread_seteuid(fuse_get_context()->uid) == -1) {
			perror_and_die("seteuid");
		}
	}

	void restore_privileges ()
	{
		// These functions should not fail as long as disorderfs is running as root.
		// If they do fail, things could be in a pretty inconsistent state, so just
		// kill the program instead of trying to gracefully recover.
		const std::vector<gid_t>	groups;
		if (thread_seteuid(0) == -1) {
			perror_and_die("seteuid()");
		}
		if (thread_setegid(0) == -1) {
			perror_and_die("setegid(0)");
		}
		if (thread_setgroups(groups.size(), groups.data()) == -1) {
			perror_and_die("setgroups(0)");
		}
	}

	struct Guard {
		Guard ()
		{
			if (config.multi_user) {
				drop_privileges();
			}
		}
		~Guard ()
		{
			if (config.multi_user) {
				restore_privileges();
			}
		}
	};

	struct fuse_operations		disorderfs_fuse_operations;
	enum {
		KEY_HELP,
		KEY_VERSION
	};
#define DISORDERFS_OPT(t, p, v) { t, offsetof(Disorderfs_config, p), v }
	const struct fuse_opt disorderfs_fuse_opts[] = {
		DISORDERFS_OPT("--multi-user=no", multi_user, false),
		DISORDERFS_OPT("--multi-user=yes", multi_user, true),
		DISORDERFS_OPT("--shuffle-dirents=no", shuffle_dirents, false),
		DISORDERFS_OPT("--shuffle-dirents=yes", shuffle_dirents, true),
		DISORDERFS_OPT("--reverse-dirents=no", reverse_dirents, false),
		DISORDERFS_OPT("--reverse-dirents=yes", reverse_dirents, true),
		DISORDERFS_OPT("--pad-blocks=%i", pad_blocks, 0),
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
			std::clog << "disorderfs options:" << std::endl;
			std::clog << "    --multi-user=yes|no    allow multiple users to access overlay (requires root; default: no)" << std::endl;
			std::clog << "    --shuffle-dirents=yes|no  randomly shuffle dirents? (default: no)" << std::endl;
			std::clog << "    --reverse-dirents=yes|no  reverse dirent order? (default: yes)" << std::endl;
			std::clog << "    --pad-blocks=N         add N to st_blocks (default: 1)" << std::endl;
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
		Guard g;
		if (lstat((root + path).c_str(), st) == -1) {
			return -errno;
		}
		st->st_blocks += config.pad_blocks;
		return 0;
	};
	disorderfs_fuse_operations.readlink = [] (const char* path, char* buf, size_t sz) -> int {
		Guard g;
		const ssize_t len{readlink((root + path).c_str(), buf, sz - 1)}; // sz > 0, since it includes space for null terminator
		if (len == -1) {
			return -errno;
		}
		buf[len] = '\0';
		return 0;
	};
	disorderfs_fuse_operations.mknod = [] (const char* path, mode_t mode, dev_t dev) -> int {
		Guard g;
		return wrap(mknod((root + path).c_str(), mode, dev));
	};
	disorderfs_fuse_operations.mkdir = [] (const char* path, mode_t mode) -> int {
		Guard g;
		return wrap(mkdir((root + path).c_str(), mode));
	};
	disorderfs_fuse_operations.unlink = [] (const char* path) -> int {
		Guard g;
		return wrap(unlink((root + path).c_str()));
	};
	disorderfs_fuse_operations.rmdir = [] (const char* path) -> int {
		Guard g;
		return wrap(rmdir((root + path).c_str()));
	};
	disorderfs_fuse_operations.symlink = [] (const char* target, const char* linkpath) -> int {
		Guard g;
		return wrap(symlink(target, (root + linkpath).c_str()));
	};
	disorderfs_fuse_operations.rename = [] (const char* oldpath, const char* newpath) -> int {
		Guard g;
		return wrap(rename((root + oldpath).c_str(), (root + newpath).c_str()));
	};
	disorderfs_fuse_operations.link = [] (const char* oldpath, const char* newpath) -> int {
		Guard g;
		return wrap(link((root + oldpath).c_str(), (root + newpath).c_str()));
	};
	disorderfs_fuse_operations.chmod = [] (const char* path, mode_t mode) -> int {
		Guard g;
		return wrap(chmod((root + path).c_str(), mode));
	};
	disorderfs_fuse_operations.chown = [] (const char* path, uid_t uid, gid_t gid) -> int {
		Guard g;
		return wrap(lchown((root + path).c_str(), uid, gid));
	};
	disorderfs_fuse_operations.truncate = [] (const char* path, off_t length) -> int {
		Guard g;
		return wrap(truncate((root + path).c_str(), length));
	};
	disorderfs_fuse_operations.open = [] (const char* path, struct fuse_file_info* info) -> int {
		Guard g;
		const int fd{open((root + path).c_str(), info->flags)};
		if (fd == -1) {
			return -errno;
		}
		info->fh = fd;
		return 0;
	};
	disorderfs_fuse_operations.read = [] (const char* path, char* buf, size_t sz, off_t off, struct fuse_file_info* info) -> int {
		size_t bytes_read = 0;
		while (bytes_read < sz) {
			const ssize_t res = pread(info->fh, buf + bytes_read, sz - bytes_read, off + bytes_read);
			if (res < 0) {
				return -errno;
			} else if (res == 0) {
				break;
			} else {
				bytes_read += res;
			}
		}
		return bytes_read;
	};
	disorderfs_fuse_operations.write = [] (const char* path, const char* buf, size_t sz, off_t off, struct fuse_file_info* info) -> int {
		size_t bytes_written = 0;
		while (bytes_written < sz) {
			const ssize_t res = pwrite(info->fh, buf + bytes_written, sz - bytes_written, off + bytes_written);
			if (res < 0) {
				return -errno;
			} else {
				bytes_written += res;
			}
		}
		return bytes_written;
	};
	disorderfs_fuse_operations.statfs = [] (const char* path, struct statvfs* f) -> int {
		Guard g;
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
		Guard g;
		return wrap(lsetxattr((root + path).c_str(), name, value, size, flags));
	};
	disorderfs_fuse_operations.getxattr = [] (const char* path, const char* name, char* value, size_t size) -> int {
		Guard g;
		ssize_t res = lgetxattr((root + path).c_str(), name, value, size);
		return res >= 0 ? res : -errno;
	};
	disorderfs_fuse_operations.listxattr = [] (const char* path, char* list, size_t size) -> int {
		Guard g;
		ssize_t res = llistxattr((root + path).c_str(), list, size);
		return res >= 0 ? res : -errno;
	};
	disorderfs_fuse_operations.removexattr = [] (const char* path, const char* name) -> int {
		Guard g;
		return wrap(lremovexattr((root + path).c_str(), name));
	};
	disorderfs_fuse_operations.opendir = [] (const char* path, struct fuse_file_info* info) -> int {
		Guard g;
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
		if (config.reverse_dirents) {
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
		if (config.shuffle_dirents) {
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
	disorderfs_fuse_operations.create = [] (const char* path, mode_t mode, struct fuse_file_info* info) -> int {
		Guard g;
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
		st->st_blocks += config.pad_blocks;
		return 0;
	};
	disorderfs_fuse_operations.lock = [] (const char* path, struct fuse_file_info* info, int cmd, struct flock* lock) -> int {
		return ulockmgr_op(info->fh, cmd, lock, &info->lock_owner, sizeof(info->lock_owner));
	};
	disorderfs_fuse_operations.flock = [] (const char* path, struct fuse_file_info* info, int op) -> int {
		return wrap(flock(info->fh, op));
	};
	disorderfs_fuse_operations.utimens = [] (const char* path, const struct timespec tv[2]) -> int {
		Guard g;
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
	fuse_opt_parse(&fargs, &config, disorderfs_fuse_opts, fuse_opt_proc);

	if (bare_arguments.size() != 2) {
		std::clog << "disorderfs: error: wrong number of arguments" << std::endl;
		std::clog << "Usage: disorderfs [OPTIONS] ROOTDIR MOUNTPOINT" << std::endl;
		return 2;
	}

	root = bare_arguments[0];

	if (root[0] != '/') {
		// TODO: support absolute paths by using *at syscalls everywhere, instead of string concatenation.
		std::clog << "disorderfs: error: ROOTDIR is not an absolute path" << std::endl;
		return 1;
	}

	// Add some of our own hard-coded FUSE options:
	fuse_opt_add_arg(&fargs, "-o");
	fuse_opt_add_arg(&fargs, "atomic_o_trunc,default_permissions"); // XXX: other mount options?
	if (config.multi_user) {
		fuse_opt_add_arg(&fargs, "-o");
		fuse_opt_add_arg(&fargs, "allow_other");
	}
	fuse_opt_add_arg(&fargs, bare_arguments[1].c_str());

	return fuse_main(fargs.argc, fargs.argv, &disorderfs_fuse_operations, nullptr);
}
