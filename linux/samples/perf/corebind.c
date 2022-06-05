#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>

pid_t	pid;

void
opt_parse(int argc, char **argv)
{
    int		opt;

    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
	case 'p': /* pid */
	    pid = atoi(optarg);
	    break;
        default:
            printf("Unknown option = -%c\n", opt);
        }
    }
}

int
main(int argc, char **argv)
{
    cpu_set_t   mask;
    int		i;
    
    opt_parse(argc, argv);
    CPU_ZERO(&mask);
    sched_getaffinity(getpid(), sizeof(cpu_set_t), &mask);
    printf("Core Affinity of Process %d:\n", pid);
    for (i = 0; i < CPU_SETSIZE; i++) {
	if (CPU_ISSET(i, &mask)) {
	    printf("\tCORE#%d ", i);
	}
    }
    printf("\n");
    return 0;
}
