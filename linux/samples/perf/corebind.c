#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>

#define BUF_SZ	1024
char	cores[BUF_SZ];

pid_t	pid;
int	sflag = 0;

void
opt_parse(int argc, char **argv)
{
    int		opt;

    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        switch (opt) {
	case 'p': /* pid */
	    pid = atoi(optarg);
	    break;
	case 's': /* core */
	    strncpy(cores, optarg, BUF_SZ - 1);
	    sflag = 1;
	    break;
        default:
            printf("Unknown option = -%c\n", opt);
        }
    }
}

void
core_show()
{
    int		i;
    cpu_set_t   mask;
    
    CPU_ZERO(&mask);
    sched_getaffinity(pid, sizeof(cpu_set_t), &mask);
    printf("Core Affinity of Process %d:\n", pid);
    for (i = 0; i < CPU_SETSIZE; i++) {
	if (CPU_ISSET(i, &mask)) {
	    printf("\tCORE#%d ", i);
	}
    }
    printf("\n");
}

int
main(int argc, char **argv)
{
    cpu_set_t   mask;
    
    opt_parse(argc, argv);
    core_show();
    if (sflag) {
	char	*cp = cores;
	char	*mk;
	int	core, cont, rc;
	cont = 1;
	CPU_ZERO(&mask);
	while (*cp && cont && isdigit(*cp)) {
	    if ((mk = index(cp, ','))) {
		core = atoi(cp);
		*mk = 0;
		cp = mk + 1;
	    } else {
		core = atoi(cp);
		cont = 0;
	    }
	    printf("core = %d\n", core);
	    CPU_SET(core, &mask);
	}
	rc = sched_setaffinity(pid, sizeof(mask), &mask);
	if (rc < 0) {
	    printf("Cannot set CPU affinity\n");
	}
	core_show();
    }
    printf("\n");
    return 0;
}
