#include <linux/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

#define I2C_SLAVE	0x0703	/* Use this slave address */
#define I2C_SLAVE_FORCE	0x0706	/* Use this slave address, even if it
				   is already in use by a driver! */
#define I2C_TENBIT	0x0704	/* 0 for 7 bit addrs, != 0 for 10 bit */
#define I2C_FUNCS	0x0705	/* Get the adapter functionality mask */
#define I2C_RDWR	0x0707	/* Combined R/W transfer (one STOP only) */
#define I2C_PEC		0x0708	/* != 0 to use PEC with SMBus */
#define I2C_SMBUS	0x0720	/* SMBus transfer */


/* i2c_smbus_xfer read or write markers */
#define I2C_SMBUS_READ	1
#define I2C_SMBUS_WRITE	0
/* SMBus transaction types (size parameter in the above functions)
   Note: these no longer correspond to the (arbitrary) PIIX4 internal codes! */
#define I2C_SMBUS_QUICK		    0
#define I2C_SMBUS_BYTE		    1
#define I2C_SMBUS_BYTE_DATA	    2
#define I2C_SMBUS_WORD_DATA	    3
#define I2C_SMBUS_PROC_CALL	    4
#define I2C_SMBUS_BLOCK_DATA	    5
#define I2C_SMBUS_I2C_BLOCK_BROKEN  6
#define I2C_SMBUS_BLOCK_PROC_CALL   7		/* SMBus 2.0 */
#define I2C_SMBUS_I2C_BLOCK_DATA    8

/*
 * Data for SMBus Messages
 */
#define I2C_SMBUS_BLOCK_MAX	32	/* As specified in SMBus standard */
union i2c_smbus_data {
	__u8 byte;
	__u16 word;
	__u8 block[I2C_SMBUS_BLOCK_MAX + 2]; /* block[0] is used for length */
			       /* and one more for user-space compatibility */
};

/* This is the structure as used in the I2C_SMBUS ioctl call */
struct i2c_smbus_ioctl_data {
    __u8 read_write;
    __u8 command;
    __u32 size;
    union i2c_smbus_data *data;
};

void
printhex(unsigned char *cp, int len)
{
    int	i;
    printf("len(%d): ", len);
    for (i = 0; i < len; i++) {
	printf("%02x", cp[i]);
    }
    printf("\n");
}

int
do_ioctl(int file, char read_write, __u8 command, int size, union i2c_smbus_data *data)
{
    struct i2c_smbus_ioctl_data args;
    __s32 err;

    args.read_write = read_write;
    args.command = command;
    args.size = size;
    args.data = data;

    printf("%s: &arg= %p\n", __func__, &args);
    printf("%s: read_write= 0x%x\n", __func__, args.read_write);
    printf("%s: commmand= 0x%x\n", __func__, args.command);
    printf("%s: size= 0x%x\n", __func__, args.size);
    printf("%s: data= %p\n", __func__, args.data);
    if (data != NULL) {
	printf("%s: data.word = 0x%x\n", __func__, data->word);
    }
    err = ioctl(file, I2C_SMBUS, &args);
    printf("err=%d\n", err);
    printhex((char*) &args, sizeof(args));
}

int
i2c_smbus_write_word_data(int file, unsigned char command, unsigned int value)
{
	union i2c_smbus_data data;
	data.word = value;
	return do_ioctl(file, I2C_SMBUS_WRITE, command,
			I2C_SMBUS_WORD_DATA, &data);
}

int
main(int argc, char **argv)
{
    int	file;
    union i2c_smbus_data data;

    memset(&data, 0, sizeof(data));
    file = open(argv[1], O_RDWR);
    if (file < 0) {
	printf("Cannot open the file: %s\n", argv[1]);
	exit(-1);
    }
#if 0
    do_ioctl(file, I2C_SMBUS_READ, 0, I2C_SMBUS_BYTE, &data);
    do_ioctl(file, I2C_SMBUS_WRITE, 0, I2C_SMBUS_QUICK, NULL);
    do_ioctl(file, I2C_SMBUS_WRITE, 123, I2C_SMBUS_BYTE, NULL);
    do_ioctl(file, I2C_SMBUS_WORD_DATA, 123, I2C_SMBUS_BYTE_DATA, &data); 
#endif
#define ZOOM	0x01
#define FOCUS	0x00
#define MOTOR_X	0x05
#define MOTOR_Y	0x06
    i2c_smbus_write_word_data(file, MOTOR_X, 10);
    return 0;
}
