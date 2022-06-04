/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil ; -*- */
/* vim: set ts=8 sts=4 sw=4 noexpandtab : */
/*
 * tsc.h - get elapsetime using hardware time stamp counter
 *         for sparc, arm64, and x86
 * HISTORY:
 *      -  x86 code was added by Yutaka Ishikawa, yutaka.ishikawa@riken.jp
 *      -  written by Masayuki Hatanaka, mhatanaka@riken.jp
 *       
 *   A sample code is included in this header file.
 */

#ifndef	_TICK_H
#define _TICK_H

#include <stdint.h>	/* for uint64_t */


/*
 * rdtsc (read time stamp counter)
 */
static inline uint64_t tick_time(void)
{
#if    defined(__GNUC__) && (defined(__i386__) || defined (__x86_64__))
        unsigned int lo, hi;
    __asm__ __volatile__ (      // serialize
	"xorl %%eax,%%eax \n        cpuid"
	::: "%rax", "%rbx", "%rcx", "%rdx");
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return (unsigned long long)hi << 32 | lo;

#elif	defined(__GNUC__) && (defined(__sparcv9__) || defined(__sparc_v9__))
    uint64_t rval;
    asm volatile("rd %%tick,%0" : "=r"(rval));
    return (rval);
#elif	defined(__GNUC__) && defined(__aarch64__)
    uint64_t tsc;
    asm volatile("mrs %0, cntvct_el0" : "=r" (tsc));
    return tsc;
#else
    return 0UL;
#error	"unsupported platform for tick_time()"
#endif
}

#if    defined(__GNUC__) && (defined(__i386__) || defined (__x86_64__))
#include <stdio.h>	/* for FILE, fopen() */
static inline uint64_t tick_helz_auto(void)
{
    FILE *fp;
    uint64_t helz = 0;

    fp = fopen("/proc/cpuinfo", "r");
    if (fp == 0) {
	helz = 0;
    }
    else {
	float ls = 0;
	const char *fmt1 = "cpu MHz\t\t: %f\n";
	char buf[1024];

	while (fgets(buf, sizeof (buf), fp) != 0) {
	    int rc = sscanf(buf, fmt1, &ls);
	    if (rc == 1) { break; }
	}
	helz = (uint64_t)(ls * 1.0e6);
	fclose(fp); fp = 0;
    }

    return helz;
}
#elif	defined(__GNUC__) && (defined(__sparcv9__) || defined(__sparc_v9__))
#include <stdio.h>	/* for FILE, fopen() */
static inline uint64_t tick_helz_auto(void)
{
    FILE *fp;
    uint64_t helz = 0;

    fp = fopen("/proc/cpuinfo", "r");
    if (fp == 0) {
	helz = 0;
    }
    else {
	long ls = 0;
	const char *fmt1 = "Cpu0ClkTck\t: %lx\n";
	char buf[1024];

	while (fgets(buf, sizeof (buf), fp) != 0) {
	    int rc = sscanf(buf, fmt1, &ls);
	    if (rc == 1) { break; }
	}
	helz = (ls <= 0)? 0: ls;
	fclose(fp); fp = 0;
    }

    return helz;
}
#elif	defined(__GNUC__) && defined(__aarch64__)

static inline uint64_t tick_helz_auto(void)
{
    uint32_t helz = 0;
    asm volatile("mrs %0, cntfrq_el0" : "=r" (helz));
    return helz;
}

#if 0
static inline uint64_t tick_status(void)
{
    uint32_t cnd = 0;
    asm volatile("mrs %0, cntv_ctl_el0" : "=r" (cnd));
    return cnd;
}
static inline uint64_t tick_status2(void)
{
    uint32_t off = 0;
    asm volatile("mrs %0, cntvoff_el2" : "=r" (off));
    return off;
}
#endif

#else

static inline uint64_t tick_helz_auto(void)
{
    uint64_t helz = 0;
    return helz;
}
#endif

static inline uint64_t tick_helz(double *p_helz)
{
    static uint64_t helz = 0;

    if (helz == 0) {
	helz = tick_helz_auto(); /* auto detection */
    }
    if (helz == 0) {
	helz = 2000 * 1000 * 1000; /* K */
    }
    if (p_helz != 0) {
	p_helz[0] = (double) helz;
    }
    return helz;
}
#ifdef	STANDALONE_TICK

/* SAMPLE CODE */
/*
 *      e.g.,
 *         $ ./sample -v -i 17 -f mytest_17
 *        mytest_17_cnt.csv and mytest_17_tim.csv will be generated.
 *         $ octave
 *           > load mytest_17_tim.csv
 *           > plot (mytest_17_tim, "+")
 *        or
 *         $  gnuplot
 *           > set xlabel "trials"
 *           > set ylabel "msec"
 *           > unset key
 *           > set terminal png ####  jpeg
 *           > set output "mytest_17_tim.png" ### "mytest_17_tim.jpeg"
 *           > plot "mytest_17_tim.csv"
 */
#include <time.h>	/* for nanosleep() */
#include <stdio.h>	/* for printf() */
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <linux/limits.h>

#define DEFAULT_ITER    (1<<4)
#define DEFAULT_NTRIES  1000
#define MAX_NTRIES      100000
static uint64_t counters[MAX_NTRIES];
static int verbose = 0;
static char     fbuf[PATH_MAX];

int main(int argc, char *argv[])
{
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000, };
    int		opt, i;
    uint64_t	st, et, hz;
    cpu_set_t   mask;
    unsigned    cpu, node;
    uint32_t    iter = DEFAULT_ITER;
    uint32_t    ntries = DEFAULT_NTRIES;
    FILE        *fp_cnt = NULL;
    FILE        *fp_tim = NULL;

    while ((opt = getopt(argc, argv, "f:i:n:vf")) != -1) {
        switch (opt) {
        case 'f':
            snprintf(fbuf, PATH_MAX, "%s_cnt.csv", optarg);
            fp_cnt = fopen(fbuf, "w+");
            if (fp_cnt == NULL) {
                fprintf(stderr, "Cannot open file: %s\n", fbuf);
            }
            snprintf(fbuf, PATH_MAX, "%s_tim.csv", optarg);
            fp_tim = fopen(fbuf, "w+");
            if (fp_tim == NULL) {
                fprintf(stderr, "Cannot open file: %s\n", fbuf);
            }
            break;
        case 'i':
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
        default:
            printf("Unknown option = -%c\n", opt);
        }
    }
    if (verbose) {
        printf("work load iteration: %u, #trials: %u\n", iter, ntries);
        CPU_ZERO(&mask);
        sched_getaffinity(getpid(), sizeof(cpu_set_t), &mask);
        printf("Core Affinity:\n");
        for (i = 0; i < CPU_SETSIZE; i++) {
            if (CPU_ISSET(i, &mask)) {
                printf("\tCORE#%d ", i);
            }
        }
        printf("\n");
#if 0
        printf("Condition: %ld\n", tick_status());
        printf("Condition2: %ld\n", tick_status2());
#endif
    }
    getcpu(&cpu, &node);
    printf("Running Core: Core#%d on Node#%d\n", cpu, node);

    hz = tick_helz( 0 );
    printf("hz(%ld)\n", hz);
    if (hz == 0) {
	printf("Cannot obtain CPU frequency\n");
	exit(-1);
    }
    for (i = 50*1000000; i < 500*1000000; i += 50*1000000) {
	ts.tv_nsec = i;
	st = tick_time();
	(void) nanosleep(&ts, 0);
	et = tick_time();
	printf("0.%02d sec sleep: elapsed time %12.9f sec\n",
	       i/10000000, (double)(et - st) / (double)hz);
        printf("\t\t start: %12.9f end: %12.9f\n",
               (double)(st)/(double)(hz), (double)(et)/(double)(hz));

    }
    printf("st=%016ld\n", st);
    printf("et=%016ld\n", et);
    {
        uint32_t        i, j;
        uint64_t        count = 0;
        uint64_t        mx, mn;
        double          scale = 1000;

        memset(counters, 0, sizeof(counters));
        for (i = 0; i < ntries; i++) {
            for (j = 0; j < iter; j++) {
                count++;
            }
            counters[i] = tick_time();
        }
        mx = mn = counters[1] - counters[0];
        for (i = 2; i < ntries; i++) {
            uint32_t    diff = (uint32_t) counters[i] - (uint32_t) counters[i - 1];
            mx = diff > mx ? diff : mx;
            mn = diff < mn ? diff : mn;
            if (fp_cnt) {
                fprintf(fp_cnt, "%u\n", diff);
            }
            if (fp_tim) {
                fprintf(fp_tim, "%12.9f\n", (double)diff/((double)hz/scale));
            }
        }
        printf("max=%016lu, min=%016lu\n", mx, mn);
        printf("max=%12.9f, min=%12.9f\n",
               (double)mx/((double)hz/scale), (double)mn/((double)hz/scale));
        if (fp_cnt) fclose(fp_cnt);
        if (fp_tim) fclose(fp_tim);
    }
    return 0;
}

#endif	/* STANDALONE_TICK */

#endif	/* _TICK_H */
