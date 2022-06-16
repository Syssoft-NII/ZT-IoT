#include <stdio.h>
#include <unistd.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>

int
core_bind(int cpu)
{
    int		rc;
    unsigned int	ncpu, nnode;
    int		pid;
    cpu_set_t   nmask;

    if (cpu < 0) {
	/* just return the current core */
	goto skip;
    }
    CPU_ZERO(&nmask);
    CPU_SET(cpu, &nmask);
    pid = getpid();
    rc = sched_setaffinity(pid, sizeof(nmask), &nmask);
    if (rc < 0) {
	printf("Cattno bind core %d\n", cpu);
    }
skip:
    getcpu(&ncpu, &nnode);
    return ncpu;
}
