/* SPDX-License-Identifier: MIT-0 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_fsmount
	#if defined __alpha__
		#define __NR_fsmount 542
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_fsmount 4432
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_fsmount 6432
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_fsmount 5432
		#endif
	#elif defined __ia64__
		#define __NR_fsmount (432 + 1024)
	#else
		#define __NR_fsmount 432
	#endif
#endif

#ifndef __NR_fsconfig
	#if defined __alpha__
		#define __NR_fsconfig 541
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_fsconfig 4431
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_fsconfig 6431
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_fsconfig 5431
		#endif
	#elif defined __ia64__
		#define __NR_fsconfig (431 + 1024)
	#else
		#define __NR_fsconfig 431
	#endif
#endif

#ifndef __NR_fsopen
	#if defined __alpha__
		#define __NR_fsopen 540
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_fsopen 4430
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_fsopen 6430
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_fsopen 5430
		#endif
	#elif defined __ia64__
		#define __NR_fsopen (430 + 1024)
	#else
		#define __NR_fsopen 430
	#endif
#endif

#ifndef __NR_open_tree
	#if defined __alpha__
		#define __NR_open_tree			538
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_open_tree		(428 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_open_tree		(428 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_open_tree		(428 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_open_tree			(428 + 1024)
	#else
		#define __NR_open_tree			428
	#endif
#endif

#ifndef __NR_move_mount
	#if defined __alpha__
		#define __NR_move_mount			539
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_move_mount		(429 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_move_mount		(429 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_move_mount		(429 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_move_mount			(428 + 1024)
	#else
		#define __NR_move_mount			429
	#endif
#endif

#ifndef __NR_mount_setattr
	#if defined __alpha__
		#define __NR_mount_setattr 552
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32	/* o32 */
			#define __NR_mount_setattr (442 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32	/* n32 */
			#define __NR_mount_setattr (442 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64	/* n64 */
			#define __NR_mount_setattr (442 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_mount_setattr (442 + 1024)
	#else
		#define __NR_mount_setattr 442
	#endif
#endif

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1 /* Clone the target tree and attach the clone */
#endif

#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC /* Close the file on execve() */
#endif

static inline int do_open_tree(int dfd, const char *filename, unsigned int flags)
{
	return syscall(__NR_open_tree, dfd, filename, flags);
}

#ifndef MOVE_MOUNT_F_SYMLINKS
#define MOVE_MOUNT_F_SYMLINKS 0x00000001 /* Follow symlinks on from path */
#endif

#ifndef MOVE_MOUNT_F_AUTOMOUNTS
#define MOVE_MOUNT_F_AUTOMOUNTS 0x00000002 /* Follow automounts on from path */
#endif

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004 /* Empty from path permitted */
#endif

#ifndef MOVE_MOUNT_T_SYMLINKS
#define MOVE_MOUNT_T_SYMLINKS 0x00000010 /* Follow symlinks on to path */
#endif

#ifndef MOVE_MOUNT_T_AUTOMOUNTS
#define MOVE_MOUNT_T_AUTOMOUNTS 0x00000020 /* Follow automounts on to path */
#endif

#ifndef MOVE_MOUNT_T_EMPTY_PATH
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040 /* Empty to path permitted */
#endif

#ifndef MOVE_MOUNT_BENEATH
#define MOVE_MOUNT_BENEATH 0x00000200
#endif

#ifndef MOVE_MOUNT_SET_GROUP
#define MOVE_MOUNT_SET_GROUP 0x00000100
#endif

#ifndef MOVE_MOUNT__MASK
#define MOVE_MOUNT__MASK 0x00000077
#endif

static inline int do_move_mount(int from_dfd, const char *from_pathname,
				int to_dfd, const char *to_pathname,
				unsigned int flags)
{
	return syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd, to_pathname, flags);
}

#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#endif

#ifndef MOUNT_ATTR_NOSUID
#define MOUNT_ATTR_NOSUID 0x00000002
#endif

#ifndef MOUNT_ATTR_NODEV
#define MOUNT_ATTR_NODEV 0x00000004
#endif

#ifndef MOUNT_ATTR_NOEXEC
#define MOUNT_ATTR_NOEXEC 0x00000008
#endif

#ifndef MOUNT_ATTR__ATIME
#define MOUNT_ATTR__ATIME 0x00000070
#endif

#ifndef MOUNT_ATTR_RELATIME
#define MOUNT_ATTR_RELATIME 0x00000000
#endif

#ifndef MOUNT_ATTR_NOATIME
#define MOUNT_ATTR_NOATIME 0x00000010
#endif

#ifndef MOUNT_ATTR_STRICTATIME
#define MOUNT_ATTR_STRICTATIME 0x00000020
#endif

#ifndef MOUNT_ATTR_NODIRATIME
#define MOUNT_ATTR_NODIRATIME 0x00000080
#endif

#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP 0x00100000
#endif

struct mount_attr_local {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};

static inline int do_mount_setattr(int dfd, const char *path, unsigned int flags,
				   struct mount_attr_local *attr, size_t size)
{
	return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}

#ifndef FSOPEN_CLOEXEC
#define FSOPEN_CLOEXEC 0x00000001
#endif

static inline int do_fsopen(const char *fs_name, unsigned int flags)
{
	return syscall(__NR_fsopen, fs_name, flags);
}

#ifndef FSCONFIG_SET_FLAG
#define FSCONFIG_SET_FLAG 0 /* Set parameter, supplying no value */
#endif

#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING 1 /* Set parameter, supplying a string value */
#endif

#ifndef FSCONFIG_SET_BINARY
#define FSCONFIG_SET_BINARY 2 /* Set parameter, supplying a binary blob value */
#endif

#ifndef FSCONFIG_SET_PATH
#define FSCONFIG_SET_PATH 3 /* Set parameter, supplying an object by path */
#endif

#ifndef FSCONFIG_SET_PATH_EMPTY
#define FSCONFIG_SET_PATH_EMPTY 4 /* Set parameter, supplying an object by (empty) path */
#endif

#ifndef FSCONFIG_SET_FD
#define FSCONFIG_SET_FD 5 /* Set parameter, supplying an object by fd */
#endif

#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE 6 /* Invoke superblock creation */
#endif

#ifndef FSCONFIG_CMD_RECONFIGURE
#define FSCONFIG_CMD_RECONFIGURE 7 /* Invoke superblock reconfiguration */
#endif

#ifndef FSCONFIG_CMD_CREATE_EXCL
#define FSCONFIG_CMD_CREATE_EXCL 8 /* Invoke exclusive superblock creation */
#endif

static inline int do_fsconfig(int fd, unsigned int cmd, const char *key,
			      const void *value, int aux)
{
	char buf[4096];
	int ret;
	ret = syscall(__NR_fsconfig, fd, cmd, key, value, aux);
	if (ret < 0) {
		ret = read(fd, buf, sizeof(buf));
		if (ret <= 0)
			strcpy(buf, "EMPTY");
		fprintf(stderr, "%m | %s: %d: %s: %s\n",
			__FILE__, __LINE__, __func__, buf);
	}
}

#ifndef FSMOUNT_CLOEXEC
#define FSMOUNT_CLOEXEC 0x00000001
#endif

static inline int do_fsmount(int fs_fd, unsigned int flags,
			     unsigned int attr_flags)
{
	return syscall(__NR_fsmount, fs_fd, flags, attr_flags);
}

#define die_errno(format, ...)                                             \
	do {                                                               \
		fprintf(stderr, "%m | %s: %d: %s: " format "\n", __FILE__, \
			__LINE__, __func__, ##__VA_ARGS__);                \
		exit(EXIT_FAILURE);                                        \
	} while (0)

static struct option long_options[] = {
	{ "filesystem",  required_argument,	0,  'f' },
	{ "options",     required_argument,	0,  'o' },
	{ "beneath",     no_argument,		0,  'b' },
	{ "delegate",    optional_argument,	0,  'q' },
	{ "detached",    no_argument,		0,  'd' },
	{ "exclusive",   no_argument,		0,  'e' },
	{ "move",        no_argument, 		0,  'm' },
	{ "peer-group",  no_argument, 		0,  'p' },
	{ "read-only",   no_argument, 		0,  'r' },
	{ "tree",        no_argument, 		0,  't' },
	{ NULL,          0,           		0,   0  }
};

static size_t split_options(char *str)

{
	size_t ctr = 1;
	char *s, *d;

	if (!str)
		return 0;

	for (s = d = str;; s++, d++) {
		if (*s == '\\') {
			s++;
		} else if (*s == ',') {
			*d = '\0';
			ctr++;
			continue;
		}
		*d = *s;
		if (!*s)
			break;
	}
	return ctr;
}

int main(int argc, char *argv[])
{
	int mnt_fd, target_fd, ret;
	bool exclusive = false, moving = false;
	unsigned int flags_open_tree = OPEN_TREE_CLOEXEC;
	unsigned int flags_move_mount = 0, flags_attr = 0;
	int new_argc;
	char **new_argv;
	char *options = NULL;
	const char *fstype = NULL;
	struct mount_attr_local attr = {
		.propagation = 0,

	};
	size_t len;

	for (;;) {
		int index = 0;
		int opt;

		opt = getopt_long(argc, argv, "bdemptf:o:", long_options, &index);
		if (opt == -1)
			break;

		switch(opt) {
		case 'b':
			flags_move_mount |= MOVE_MOUNT_BENEATH;
			fprintf(stderr, "Mounting beneath top mount\n");
			break;
		case 'f':
			fstype = optarg;
			fprintf(stderr, "Requesting filesystem type %s\n", fstype);
			break;
		case 'd':
			flags_open_tree |= OPEN_TREE_CLONE;
			fprintf(stderr, "Creating anonymous mount\n");
			break;
		case 'e':
			exclusive = true;
			fprintf(stderr, "Request exclusive superblock creation\n");
			break;
		case 'm':
			moving = true;
			fprintf(stderr, "Moving mount\n");
			break;
		case 'o':
			options = strdup(optarg);
			if (!options)
				die_errno("Failed to duplicate mount option string %s", optarg);
			fprintf(stderr, "Mount options requested: %s\n", options);
			break;
		case 'p':
			flags_move_mount |= MOVE_MOUNT_SET_GROUP;
			fprintf(stderr, "Setting peer group\n");
			break;
		case 'r':
			flags_attr |= MOUNT_ATTR_RDONLY;
			fprintf(stderr, "Creating read-only mount\n");
			break;
		case 't':
			flags_open_tree |= AT_RECURSIVE;
			fprintf(stderr, "Using entire mount tree\n");
			break;
		default: /* '?' */
			errno = EINVAL;
			printf("--beneath/-b	mounting beneath top mount\n"
			       "--delegate/-q	delegate superblock to user namespace\n"
			       "--detached/-d	creating anonymous mount\n"
			       "--exclusive/-e	fail if matching superblock already exists\n"
			       "--filesystem/-f	filesytem type\n"
			       "--move/-m	moving attached mount\n"
			       "--options/-o	mount options\n"
			       "--peer-group/-p	setting peer group\n"
			       "--tree/-t	using entire mount tree\n");
			exit(EXIT_FAILURE);
		}
	}

	new_argv = &argv[optind];
	new_argc = argc - optind;

	if (!fstype && new_argc != 2)
		die_errno("Invalid number of arguments %d", new_argc);
	if (fstype && new_argc != 1)
		die_errno("Invalid number of arguments %d", new_argc);

	if (options && !fstype)
		die_errno("Using --options and without --fstype forbidden");

	if (exclusive && !fstype)
		die_errno("Using --exclusive and without --fstype forbidden");

	if (fstype && (flags_open_tree & (OPEN_TREE_CLONE | AT_RECURSIVE)))
		die_errno("Using --fstype and --detached/--tree forbidden");

	if ((flags_move_mount & MOVE_MOUNT_SET_GROUP) &&
	    ((flags_move_mount & MOVE_MOUNT_BENEATH) ||
	     (flags_open_tree & OPEN_TREE_CLONE)))
		die_errno("Setting sharing group can only be done exclusively");

	if (!fstype && !(flags_move_mount & MOVE_MOUNT_SET_GROUP) && !moving &&
	    !(flags_open_tree & OPEN_TREE_CLONE))
		die_errno("Please explicitly request either moving or detached mounts");

	if (!fstype) {
		printf("Attaching mount %s -> %s\n", new_argv[0], new_argv[1]);
		target_fd = open(new_argv[1], O_PATH | O_NOFOLLOW);
	} else {
		printf("Attaching mount at %s\n", new_argv[0]);
		target_fd = open(new_argv[0], O_PATH | O_NOFOLLOW);
	}
	if (target_fd < 0)
		die_errno("openat");

	if (flags_open_tree & OPEN_TREE_CLONE)
		printf("Creating %s detached mount\n", (flags_open_tree & AT_RECURSIVE) ? "recursive" : "single");
	else
		printf("Moving %s attached mount\n", (flags_open_tree & AT_RECURSIVE) ? "recursive" : "single");

	if (fstype) {
		int fs_fd;
		char *token;

		fs_fd = do_fsopen(fstype, FSOPEN_CLOEXEC);
		if (fs_fd < 0)
			die_errno("fsopen");

		len = split_options(options);
		token = options;
		for (size_t i = 0; i < len; i++) {
			char *key, *val = NULL, *cut;

			key = token;
			key += strspn(key, " \t");
			cut = strchr(key, '=');
			if (cut) {
				*cut = '\0';
				val = cut;
				val++;
				if (!*val)
					die_errno("Invalid mount option format key without a value specified");
			}

			if (strcmp(key, "delegate") == 0 && val) {
				int fd_userns;

				fd_userns = open(val, O_RDONLY | O_CLOEXEC | O_NOCTTY);
				if (fd_userns < 0)
					die_errno("Failed to open user namespace %s", val);

				printf("EXPERIMENTAL: Delegating filesystems %s to user namespace %d\n", fstype, fd_userns);
				ret = do_fsconfig(fs_fd, FSCONFIG_SET_FD, "delegate", NULL, fd_userns);
			} else {
				printf("Setting key(%s) with val(%s)\n", key, val ?: "(empty)");
				if (val)
					ret = do_fsconfig(fs_fd, FSCONFIG_SET_STRING, key, val, 0);
				else
					ret = do_fsconfig(fs_fd, FSCONFIG_SET_FLAG, key, NULL, 0);
			}
			if (ret)
				die_errno("fsconfig");
			if (cut)
				*cut = '=';
			token = strchr(token, '\0') + 1;
		}

		if (exclusive)
			ret = do_fsconfig(fs_fd, FSCONFIG_CMD_CREATE_EXCL, NULL, NULL, 0);
		else
			ret = do_fsconfig(fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
		if (ret)
			die_errno("%sfsconfig", exclusive ? "EXPERIMENTAL exclusive: " : "");

		mnt_fd = do_fsmount(fs_fd, FSMOUNT_CLOEXEC, flags_attr);
		if (mnt_fd < 0)
			die_errno("fsmount");
	} else {
		mnt_fd = do_open_tree(-EBADF, new_argv[0], flags_open_tree);
		if (mnt_fd < 0)
			die_errno("open_tree");
	}

	if (!fstype)
		attr.attr_set |= flags_attr;
	if (do_mount_setattr(mnt_fd, "", AT_EMPTY_PATH | 0, &attr, sizeof(attr)))
		die_errno("mount_setattr");

	ret = do_move_mount(mnt_fd, "", target_fd, "",
			    flags_move_mount |
			    MOVE_MOUNT_F_EMPTY_PATH |
			    MOVE_MOUNT_T_EMPTY_PATH);
	if (ret < 0)
		die_errno("move_mount");

	exit(EXIT_SUCCESS);
}
