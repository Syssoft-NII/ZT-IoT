#include <stdio.h>
#include <string.h>

char	*sysname[1024];

int
main()
{
    int	i, entmax;
    memset(sysname, 0, sizeof(sysname));
#include "sysname.incl"
    for (i = 0; i < 1024; i++) {
	if (sysname[i] != 0) entmax = i;
    }
    printf("char *sysname[%d] = {\n", entmax + 1);
    for (i = 0; i <= entmax; i++) {
	if (sysname[i]) {
	    printf("\t\"%s\", \t/* %d */\n", sysname[i], i);
	} else {
	    printf("\t0, \t\t/* %d */\n", i);
	}
    }
    printf("};\n");
    printf("#define SYSCALL_MAX\t%d\n", i);
}
