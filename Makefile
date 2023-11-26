# SPDX-License-Identifier: MIT-0

all: move-mount

move_mount: move-mount.o

clean:
	rm -f move-mount move-mount.o

.PHONY: all clean
