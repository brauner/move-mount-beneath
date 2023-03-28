all: move-mount-beneath

move_mount_beneath: move-mount-beneath.o

clean:
	rm -f move-mount-beneath move-mount-beneath.o

.PHONY: all clean
