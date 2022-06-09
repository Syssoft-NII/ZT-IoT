/*
 *	Measurement library for Aarch64
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <linux/limits.h>
#include "tsc.h"

int
core_info(char *path, const char *fmt, void *val)
{
    int		rc = -1;
    FILE	*fp = fopen(path, "r");
    char	buf[PATH_MAX];
    if (fp) {
	if (!strcmp(fmt, "%s")) {
	    rc = fread(val, 1, PATH_MAX, fp);
	    /* removing the last character \n */
	    ((char*) val)[rc - 1] = 0;
	} else {
	    rc = fread(buf, 1, PATH_MAX, fp);
	    rc = sscanf(buf, fmt, val);
	}
	fclose(fp);
    }
    return rc;
}


void
cpu_info(FILE *fout)
{
    int		i;
    char	buf[PATH_MAX], buf2[PATH_MAX];
    uint64_t	ohz;
    uint64_t	chz = tick_helz(0);
    cpu_set_t   mask;
    unsigned    cpu, node;
    
    CPU_ZERO(&mask);
    sched_getaffinity(getpid(), sizeof(cpu_set_t), &mask);
    fprintf(fout, "Core Affinity:\n");
    for (i = 0; i < CPU_SETSIZE; i++) {
	if (CPU_ISSET(i, &mask)) {
	    fprintf(fout, "\tCORE#%d ", i);
	}
    }
    fprintf(fout, "\n");
    getcpu(&cpu, &node);
    snprintf(buf, PATH_MAX,
	     "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq",
	     cpu);
    core_info(buf, "%ld\n", &ohz);
    fprintf(fout, "Running Core#%d on Node#%d, "
	   "operation: %ld kHz, counter: %ld Hz\n",  cpu, node, ohz, chz);

    /* Current governor */
    snprintf(buf, PATH_MAX,
	     "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor",
	     cpu);
    core_info(buf, "%s", &buf2);
    fprintf(fout, "Current Governor: %s\n", buf2);

    /* available frequenceis */
    snprintf(buf, PATH_MAX,
	     "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_available_frequencies",
	     cpu);
    core_info(buf, "%s", &buf2);
    fprintf(fout, "\nAvailable Freequencies: %s\n", buf2);
    /* available governor */
    snprintf(buf, PATH_MAX,
	     "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_available_governors",
	     cpu);
    core_info(buf, "%s", &buf2);
    fprintf(fout, "Available Governors: %s\n", buf2);
}

