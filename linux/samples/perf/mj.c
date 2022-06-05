/*
 *	Measurement of jitter: A Fixed Work Quantum Benchmark
 *		yutaka_ishikawa@nii.ac.jp, 2022/06/04
 *  Example:
 *         $ ./sample -v -I 100000 -f mytest_100k
 *        fwq_17_cnt.csv and mytest_17_tim.csv will be generated.
 *         $ octave
 *           > load mytest_17_tim.csv
 *           > plot (mytest_17_tim, "+")
 *        or
 *         $  gnuplot
 *           > set xlabel "trials"
 *           > set ylabel "msec"
 *           > unset key
 *           > set terminal jpeg
 *           > set output "mytest_17_tim.jpeg"
 *           > plot "mytest_17_tim.csv"
 */
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <linux/limits.h>
#include <string.h>
#include <time.h>
#include "tsc.h"

#define DEFAULT_ITER	1000000
#define DEFAULT_NTRIES	1000
#define MAX_NTRIES	100000
#define SCALE		1000
#define DEFAULT_FNAME	"fwq"
#define PATH_MAXPREFIX	128

static uint64_t counters[MAX_NTRIES];
static int	verbose = 0;
static int	dflag = 0;
static uint32_t	iter = DEFAULT_ITER;
static uint32_t	ntries = DEFAULT_NTRIES;
static cpu_set_t mymask;
static char     fbuf[PATH_MAX];
static char     prefix[PATH_MAXPREFIX] = DEFAULT_FNAME;

void
memo_show(FILE *fp)
{
    fprintf(fp,
	    "1) show core freqency\n"
	    "\t/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq\n"
	    "2) show a list of available frequencies\n"
	    "\t/sys/devices/system/cpu/cpu*/cpufreq/scaling_available_frequencies\n"
	    "3) show/select a frequency\n"
	    "\t/sys/devices/system/cpu/cpu*/cpufreq/scaling_setspeed\n"
	    "4) show a list of available governors\n"
	    "\t/sys/devices/system/cpu/cpu*/cpufreq/scaling_available_governors\n"
	    "5) show/select a governor\n"
	    "\t/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor\n"
	    "6) set core online/offline\n"
	    "\t/sys/devices/system/cpu/cpu?/oonline\n"
	    "7) show core online/offline list\n"
	    "\t/sys/devices/system/cpu/oonline\n"
	    "\t/sys/devices/system/cpu/offline\n"
	);
}

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
	if (CPU_ISSET(i, &mymask)) {
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

FILE *
out_open(char *fbuf, const char *type, const char *ext)
{
    FILE	*fp;
    struct tm	tm;
    time_t	tt;

    time(&tt);
    localtime_r(&tt, &tm);
    snprintf(fbuf, PATH_MAX,"%s_%04d:%02d:%02d:%02d:%02d_i%d_n%d_%s.%s",
	     prefix,
	     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	     tm.tm_hour, tm.tm_min,
	     iter, ntries, type, ext);
    fp = fopen(fbuf, "w+");
    if (fp == NULL) {
	fprintf(stderr, "Cannot open file: %s\n", fbuf);
	exit(-1);
    }
    return fp;
}

int
main(int argc, char *argv[])
{
    int		opt;
    uint64_t	hz;
    int		cnum = -1;
    FILE        *fp_cnt, *fp_tim, *fp_inf;
    uint32_t	i, j;
    uint64_t	count = 0;
    uint64_t	mx, mn;
    double	scale = SCALE;

    while ((opt = getopt(argc, argv, "c:f:i:I:n:vfd")) != -1) {
        switch (opt) {
	case 'c': /* core binding */
	    cnum = atoi(optarg);
	    break;
        case 'f':
	    strncpy(prefix, optarg, PATH_MAXPREFIX);
            break;
        case 'i':
            iter = atoi(optarg);
            break;
        case 'I':
            i = atoi(optarg);
            if (i > 32) {
                i = 31;
            }
            iter = (1 << i);
            break;
        case 'n':
            ntries = atoi(optarg);
            if (ntries > MAX_NTRIES) {
                ntries = MAX_NTRIES;
            }
            break;
        case 'v':
            verbose = 1;
            break;
	case 'd':
	    dflag = 1; verbose = 1;
	    break;
        default:
            printf("Unknown option = -%c\n", opt);
        }
    }
    hz = tick_helz(0);
    if (hz == 0) {
	printf("Cannot obtain counter frequency\n");
	exit(-1);
    }

    CPU_ZERO(&mymask);
    sched_getaffinity(getpid(), sizeof(cpu_set_t), &mymask);
    if (cnum > 0) {
	int		rc;
	cpu_set_t	nmask;
	CPU_SET(cnum, &nmask);
	/* set CPU affinity */
	rc = sched_setaffinity(0, sizeof(nmask), &nmask);
	if (rc < 0) {
	    printf("Cannot set CPU affinity %d\n", cnum);
	    exit(-1);
	}
    }
    
    if (verbose) {
        printf("work load iteration: %u, #trials: %u\n", iter, ntries);
	cpu_info(stdout);
	if (dflag) {
	    exit(0);
	}
    }
    /* counter file */
    fp_cnt = out_open(fbuf, "cnt", "csv");
    /* time file */
    fp_tim = out_open(fbuf, "tim", "csv");
    /* info file */
    fp_inf = out_open(fbuf, "inf", "dat");
    
    memset(counters, 0, sizeof(counters));
    /* Fixed Work Quantum */
    for (i = 0; i < ntries; i++) {
	for (j = 0; j < iter; j++) {
	    count++;
	}
	counters[i] = tick_time();
    }
    /* Results */
    mx = mn = counters[1] - counters[0];
    for (i = 2; i < ntries; i++) {
	uint32_t    diff = (uint32_t) counters[i] - (uint32_t) counters[i - 1];
	mx = diff > mx ? diff : mx;
	mn = diff < mn ? diff : mn;
	fprintf(fp_cnt, "%u\n", diff);
	fprintf(fp_tim, "%12.9f\n", (double)diff/((double)hz/scale));
    }
    /* Info */
    fprintf(fp_inf, "clock: max=%016lu, min=%016lu\n", mx, mn);
    fprintf(fp_inf, "time(msec): max=%12.9f, min=%12.9f\n\n",
	    (double)mx/((double)hz/scale), (double)mn/((double)hz/scale));
    cpu_info(fp_inf);
    memo_show(fp_inf);
    /**/
    fclose(fp_cnt);
    fclose(fp_tim);
    fclose(fp_inf);
    return 0;
}
