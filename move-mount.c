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

static inline int open_tree(int dfd, const char *filename, unsigned int flags)
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

static inline int move_mount(int from_dfd, const char *from_pathname, int to_dfd,
			     const char *to_pathname, unsigned int flags)
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

struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};

static inline int mount_setattr(int dfd, const char *path, unsigned int flags,
				struct mount_attr *attr, size_t size)
{
	return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}

#define die_errno(format, ...)                                             \
	do {                                                               \
		fprintf(stderr, "%m | %s: %d: %s: " format "\n", __FILE__, \
			__LINE__, __func__, ##__VA_ARGS__);                \
		exit(EXIT_FAILURE);                                        \
	} while (0)

static struct option long_options[] = {
	{ "beneath",     no_argument, 0,  'b' },
	{ "detached",    no_argument, 0,  'd' },
	{ "move",        no_argument, 0,  'm' },
	{ "peer-group",  no_argument, 0,  'p' },
	{ "tree",        no_argument, 0,  't' },
	{ NULL,          0,           0,   0  }
};

int main(int argc, char *argv[])
{
	int mnt_fd, ret;
	bool moving = false;
	unsigned int flags_open_tree = OPEN_TREE_CLOEXEC;
	unsigned int flags_move_mount = 0;
	int new_argc;
	char **new_argv;
	struct mount_attr attr = {
		.propagation = 0,

	};

	for (;;) {
		int index = 0;
		int opt;

		opt = getopt_long(argc, argv, "bdmpt", long_options, &index);
		if (opt == -1)
			break;

		switch(opt) {
		case 'b':
			flags_move_mount |= MOVE_MOUNT_BENEATH;
			fprintf(stderr, "Mounting beneath top mount\n");
			break;
		case 'd':
			flags_open_tree |= OPEN_TREE_CLONE;
			fprintf(stderr, "Creating anonymous mount\n");
			break;
		case 'm':
			moving = true;
			fprintf(stderr, "Moving mount\n");
			break;
		case 'p':
			flags_move_mount |= MOVE_MOUNT_SET_GROUP;
			fprintf(stderr, "Setting peer group\n");
			break;
		case 't':
			flags_open_tree |= AT_RECURSIVE;
			fprintf(stderr, "Using entire mount tree\n");
			break;
		default: /* '?' */
			errno = EINVAL;
			die_errno("Unknown option");
		}
	}

	new_argv = &argv[optind];
	new_argc = argc - optind;

	if (new_argc != 2)
		die_errno("Invalid number of arguments %d", new_argc);

	if ((flags_move_mount & MOVE_MOUNT_SET_GROUP) &&
	    ((flags_move_mount & MOVE_MOUNT_BENEATH) ||
	     (flags_open_tree & OPEN_TREE_CLONE)))
		die_errno("Setting sharing group can only be done exclusively");

	if (!(flags_move_mount & MOVE_MOUNT_SET_GROUP) && !moving &&
	    !(flags_open_tree & OPEN_TREE_CLONE))
		die_errno("Please explicitly request either moving or detached mounts");

	printf("Attaching mount %s -> %s\n", new_argv[0], new_argv[1]);
	if (flags_open_tree & OPEN_TREE_CLONE)
		printf("Creating %s detached mount\n", (flags_open_tree & AT_RECURSIVE) ? "recursive" : "single");
	else
		printf("Moving %s attached mount\n", (flags_open_tree & AT_RECURSIVE) ? "recursive" : "single");

	mnt_fd = open_tree(-EBADF, new_argv[0], flags_open_tree);
	if (mnt_fd < 0)
		die_errno("open_tree");

	if (mount_setattr(mnt_fd, "", AT_EMPTY_PATH | 0, &attr, sizeof(attr)))
		die_errno("mount_setattr");

	ret = move_mount(mnt_fd, "", -EBADF, new_argv[1],
			 flags_move_mount | MOVE_MOUNT_F_EMPTY_PATH);
	if (ret < 0)
		die_errno("move_mount");

	exit(EXIT_SUCCESS);
}