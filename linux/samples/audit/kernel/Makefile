#
# Unless set "CONFIG_MODULE_SIG=n" in the Linux kernel configuration,
# the following messages will appear in kernel message when the fkdev module
# is loaded:
#   fkdev: loading out-of-tree module taints kernel.
#   fkdev: module verification failed: signature and/or required key missing
#          - tainting kernel

#CFLAGS_MODULE = -DZT_IOT

obj-m := fkdev.o
all: fkdev.ko ioctl-test show-field
fkdev.ko: fkdev.c
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
ioctl-test: ioctl-test.c
	cc -o ioctl-test ioctl-test.c
show-field: show-field.c
	cc -o show-field show-field.c
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm -f ioctl-test
#
#
mknod:
	sudo  mknod /dev/fkdev c 60 1
	sudo chmod 666 /dev/fkdev
	ls -l /dev/fkdev
insmod:
	sudo insmod fkdev.ko
	cat /proc/devices | grep fkdev
rmmod:
	sudo rmmod fkdev.ko
dmesg:
	sudo dmesg
test:
	./ioctl-test /dev/fkdev
show:
	./show-field

