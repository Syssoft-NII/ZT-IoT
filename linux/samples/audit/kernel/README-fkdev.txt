$ make
$ make insmode
	# sudo insmode fkdev.ko
$ cat /proc/devices
  You will find the following entry
  Character devices:
     1 mem
     ...
    60 fkdev
     ...
$ make mknod
	# sudo mknod /dev/fkdev c 60 1
	# sudo chmod 666 /dev/fkdev
$ ls -l /dev/fkdev
  crw-rw-rw- 1 root root 60, 1 10月 13 11:18 /dev/fkdev
$ make test
	# ./ioctl-test /dev/fkdev
do_ioctl: &arg= 0x7ffed5d25410
do_ioctl: read_write= 0x0
do_ioctl: commmand= 0x5
do_ioctl: size= 0x3
do_ioctl: data= 0x7ffed5d25450
do_ioctl: data.word = 0xa
err=0
len(16): 00050000030000005054d2d5fe7f0000

$ make dmesg
	# sudo dmesg
[55604.414134] fkdev_open: called
[55604.414408] fkdev_unlocked_ioctl: cmd=0x720 arg=0x7ffed5d25410
[55604.414420] ioctl: I2C_SMBUS(0x720) &arg(sz=16) = 0x7ffed5d25410 arg.data(sz=34) = 0x7ffed5d25450
[55604.414724] ioctl: data1=00050000030000005054d2d5fe7f0000
[55604.414785] ioctl: data2=0a000000000000000000000000000000000000000000000000000000000000000000
[55604.415492] fkdev_flush: called
[55604.415538] fkdev_close: called
