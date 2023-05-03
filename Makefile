all: move-mount

move_mount: move-mount.o

clean:
	rm -f move-mount move-mount.o

.PHONY: all clean
