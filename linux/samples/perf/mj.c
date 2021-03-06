/*
 *	Measurement of jitter: A Fixed Work Quantum Benchmark
 *		yutaka_ishikawa@nii.ac.jp, 2022/06/04
 *  Example:
 *         $ ./sample -v -I 100000 -f mytest_100k
 *        fwq_17_cnt.csv and mytest_17_tim.csv will be generated.
 *         $ octave
 *           > load fwq_2022:06:04:15:24_i1000000_n1000_tim.csv
 *           > plot (fwq_2022:06:05:15:24_i1000000_n1000_tim, "+")
 *        or
 *         $  gnuplot
 *           > set xlabel "trials"
 *           > set ylabel "msec"
 *           > unset key
 *           > set terminal jpeg
 *           > set output "fwq_2022:06:05:15:24_i1000000_n1000_tim.jpeg"
 *           > plot "fwq_2022:06:05:15:24_i1000000_n1000_tim.csv"
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <linux/limits.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "measurelib.h"

#define DEFAULT_ITER	1000000
#define DEFAULT_NTRIES	1000
#define MAX_NTRIES	100000
#define SCALE		1000
#define DEFAULT_FNAME	"fwq"
#define PATH_MAXPREFIX	128

static uint64_t counters[MAX_NTRIES+1];
static int	verbose = 0;
static int	dflag = 0;
static uint32_t	iter = DEFAULT_ITER;
static uint32_t	ntries = DEFAULT_NTRIES;
static cpu_set_t mymask;
static int	cnum = -1;
static char     fbuf[PATH_MAX];
static char	ftim_name[PATH_MAX];
static char     prefix[PATH_MAXPREFIX] = DEFAULT_FNAME;

void
opt_show()
{
    printf("options:\n"
	   "    -h                 printing this message\n"
	   "    -c <core number>   binding this process on the specified core\n"
	   "    -f <prefix string> specifying prefix of output file. \"fwq\" in default\n"
	   "    -i <iter count>    specifying computation loop count by decimal. %d is in default\n"
	   "    -I <iter count>    specifying computation loop count by power of 2 (max is 31)\n"
	   "    -n <traial count>  specifying trial count by decimal\n"
	   "    -v                 verbose mode\n"
	   "    -d                 printing CPU information only\n",
	   DEFAULT_ITER);
}

void
opt_parse(int argc, char **argv)
{
    int		opt, i;

    while ((opt = getopt(argc, argv, "c:f:i:I:n:vfdh")) != -1) {
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
	case 'h':
	    opt_show();
	    exit(0);
	    break;
        default:
            printf("Unknown option = -%c\n", opt);
        }
    }
}

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


FILE *
out_open(char *fbuf, const char *type, const char *ext, char *fname)
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
    if (fname) {
	char	*cp;
	strcpy(fname, fbuf);
	if ((cp = index(fname, '.'))) {
	    *cp = 0;
	}
    }
    return fp;
}

int
main(int argc, char *argv[])
{
    uint64_t	hz;
    FILE        *fp_cnt, *fp_tim, *fp_inf;
    uint32_t	i, j;
    uint64_t	count = 0;
    uint64_t	mx, mn, avg;
    double	scale = SCALE;
    double	ttim, tavg, dev, stdev;

    opt_parse(argc, argv);
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
	    memo_show(stdout);
	    exit(0);
	}
    }
    /* counter file */
    fp_cnt = out_open(fbuf, "cnt", "csv", NULL);
    /* time file */
    fp_tim = out_open(fbuf, "tim", "csv", ftim_name);
    /* info file */
    fp_inf = out_open(fbuf, "inf", "txt", NULL);
    
    memset(counters, 0, sizeof(counters));
    /* Fixed Work Quantum */
    /* dry run */
    for (i = 0; i < 100; i++) {
	for (j = 0; j < iter; j++) {
	    count++;
	}
    }
    /* measuring */
    counters[0] = tick_time();
    for (i = 1; i <= ntries; i++) {
	for (j = 0; j < iter; j++) {
	    count++;
	}
	counters[i] = tick_time();
    }
    /* Results */
    ttim = 0;
    mx = mn = counters[1] - counters[0];
    for (i = 2; i <= ntries; i++) {
	uint32_t    diff = (uint32_t) counters[i] - (uint32_t) counters[i - 1];
	mx = diff > mx ? diff : mx;
	mn = diff < mn ? diff : mn;
	fprintf(fp_cnt, "%u\n", diff);
	fprintf(fp_tim, "%12.9f\n", (double)diff/((double)hz/scale));
    }
    ttim = (double)((uint32_t)counters[ntries - 1]
		    - (uint32_t) counters[0])/((double)hz/scale);
    avg = (counters[ntries - 1] - counters[0])/ntries;
    tavg = (double)avg/((double)hz/scale);
    /* Info */
    fprintf(fp_inf, "clock: max=%016lu, min=%016lu\n", mx, mn);
    fprintf(fp_inf, "total time(sec): %12.9f\n", ttim/1000);
    fprintf(fp_inf, "time(msec): max=%12.9f, min=%12.9f, av=%12.9f\n",
	    (double)mx/((double)hz/scale), (double)mn/((double)hz/scale),
	    tavg);
    dev = 0; 
    for (i = 1; i <= ntries; i++) {
	uint32_t diff = (uint32_t) counters[i] - (uint32_t) counters[i - 1];
	double	tim = (double) diff/((double)hz/scale);
	dev += (tim - tavg) * (tim - tavg);
    }
    dev /= (double) ntries;
    stdev = sqrt(dev);
    fprintf(fp_inf, "standard deviation= %12.9f\n", stdev);
    fprintf(fp_inf, "1 clock= %6.3f nsec\n",
	    (double)1.0/((double)hz/1000000000));
    cpu_info(fp_inf);
    memo_show(fp_inf);
    /**/
    fclose(fp_cnt);
    fclose(fp_tim);
    fclose(fp_inf);
    printf("%s\n", ftim_name);
    return 0;
}
