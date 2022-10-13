CONFIG_MODULE_SIG=n

obj-m := fkdev.o
all: fkdev.ko ioctl-test
fkdev.ko: fkdev.c
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
ioctl-test: ioctl-test.c
	cc -o ioctl-test ioctl-test.c
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
	cat /proc/devices
rmmod:
	sudo rmmod fkdev.ko
dmesg:
	sudo dmesg
test:
	./ioctl-test /dev/fkdev
