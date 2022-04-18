#include <stdio.h>
#include <unistd.h>
#include <string.h>

char	*msg = "hello\n";
#define BSIZE 128
char	buf[BSIZE];
int
main()
{
    write(1, msg, strlen(msg));
    read(0, buf, BSIZE);
    return 0;
}
