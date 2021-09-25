#include <stdio.h>
#include <string.h>

char	*sysname[1024];

int
main()
{
    int	i = 0;
    memset(sysname, 0, sizeof(sysname));
#include "sysname.incl"
    printf("char *sysname[] = {\n");
    while(sysname[i] != 0) {
	printf("\t\"%s\",\n", sysname[i]);
	i++;
    }
    printf("};\n");
    printf("#define SYSCALL_MAX\t%d\n", i);
}
