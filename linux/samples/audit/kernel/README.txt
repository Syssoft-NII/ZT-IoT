Linux audit modification:
      Making the third argument of the ioctl system call visible
							       2022/10/12
						yutaka_ishikawa@nii.ac.jp
(1) Kernel modification for audit ioctl
The following three files have been modified based on Linux kernel
version 5.4.230:
    audit.h is the modified version of
	kernel/audit.h
    auditsc.c is the modified version of
	kernel/auditsc.c
    i2c-dev.c is the modified version of
	drivers/i2c/i2c-dev.c
If you use another Kernel version, don't copy them, but make sure the
source differences and update them using the diff tool.

(2) The ioctl-test.c code is a test program.
    $ ./ioctl-test /dev/i2c-7 ##???
    NOTE that the actual device test has NOT yet been done.

(3) The LOG.txt file explains a log of the "ioctl-test" running on QEMU as follows:
    $ echo >/tmp/123
    $ ./ioctl-test /tmp/123
    That is, the i2c device is not opened. So the ioctl system call fails, but
    the structure of ioctl's third argument is visible,
    	i.e., the "data1" field.
    The "data2" field is invisible in this log because the i2c device is not
    opened. If the i2c device is successfully opened, The "data2" field
    represents the value of i2c_smbu_data.
    cf.
        struct i2c_smbus_ioctl_data args;  // data1
        union i2c_smbus_data data;	   // data2
	data.word = 10;
        args.read_write = 0x1;
    	args.command = 0x05
	args.size = 0x3;
	args.data = &data;
	ioctl(fd, I2C_SMBUS, &args);

(4) Memo
    PTZ-Camera-Controller/Focuser.py
	using smbus python
	      self.bus = smbus.SMBus(bus)
	      SMBus initializer opens "/dev/i2c-<bus>" device
	      e.g. /dev/i2c-7 in case of smbus.SMBus(7)
    The smbus python is defined in i2c-tools/py-smbus/{setup.py,smbusmodule.c}
    The smbus python implements the following methods:
       open(), close(), write_quick(), read_byte(), write_byte(),
       read_byte_data(), write_byte_data(),
       read_word_data(), write_word_data(),
       process_call(), read_block_data(), write_block_data(),
       block_process_call(), read_i2c_block_data(), write_i2c_block_data()
     uses C codes in i2c-tools/lib/smbus.c

--
