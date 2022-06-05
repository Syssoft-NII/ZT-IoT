/* -*- Mode: C; c-basic-offset:4 ; indent-tabs-mode:nil ; -*- */
/* vim: set ts=8 sts=4 sw=4 noexpandtab : */
/*
 * tsc.h - get elapsetime using hardware time stamp counter
 *         for sparc, arm64, and x86
 * HISTORY:
 *      -  core settings are displayed in the sample code
 *              by yutaka_ishikawa@nii.ac.jp
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

#if 0 /* This is for EL2 */
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
 *  $ ./sample
 */
#include <time.h>	/* for nanosleep() */
#include <stdio.h>	/* for printf() */
#include <stdlib.h>
#include <unistd.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <linux/limits.h>
#include <string.h>

int main()
{
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000, };
    int		i;
    uint64_t	st, et, hz;
    cpu_set_t   mask;
    unsigned    cpu, node;

    CPU_ZERO(&mask);
    sched_getaffinity(getpid(), sizeof(cpu_set_t), &mask);
    printf("Core Affinity:\n");
    for (i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, &mask)) {
            printf("\tCORE#%d ", i);
        }
    }
    printf("\n");
    getcpu(&cpu, &node);
    hz = tick_helz( 0 );
#if	defined(__GNUC__) && defined(__aarch64__)
    {
        char buf[PATH_MAX];
        FILE            *fp;
        uint64_t        ohz;
        snprintf(buf, PATH_MAX,
                 "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq",
                 cpu);
        fp = fopen(buf, "r");
        if (fp) {
            ohz = 0;
            fread(buf, PATH_MAX, 1, fp);
            sscanf(buf, "%ld\n", &ohz);
            fclose(fp);
        } else {
            ohz = 0;
        }
        printf("Running Core#%d on Node#%d, "
               "operation: %ld Hz, counter: %ld Hz\n",  cpu, node, hz, ohz);
    }
#else
    printf("Running Core#%d on Node#%d, %ld Hz\n", cpu, node, hz);
#endif

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
    return 0;
}

#endif	/* STANDALONE_TICK */

#endif	/* _TICK_H */
