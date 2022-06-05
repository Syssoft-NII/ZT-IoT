#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include "sysname.h"
#include "tsc.h"
#include "autestlib.h"

/* gettid() is the Linux specific system call */
extern int	gettid();

struct syscalls systab[SYS_MAX] = {
    { 1, {"getpid", NULL, NULL} },
    { 1, {"getuid", NULL, NULL} },
    { 2, {"openat", "close", NULL} }
};

pthread_mutex_t	mx1, mx2, mx3;
uint64_t			ptm_st[3][10000], ptm_et[3][10000], hz;

#define MEASURE_SYSCALL(syscl, sysfunc)	{	\
	for (i = 0; i < iter; i++) {	\
            ptm_st[0][i] = tick_time();	\
	    sysfunc;	\
	    ptm_et[0][i] = tick_time();	\
	}	\
	MEASURE_FINISH_SYSCALL;		\
    }

#define MEASURE_OPEN_CLOSE(syscl) {		\
	char	fname[1024];	\
	snprintf(fname, 1024, "/tmp/atest-%d", getpid());	\
	for (i = 0; i < iter; i++) {	\
	    int	fd;	\
	    ptm_st[0][i] = tick_time();	\
	    fd = open(fname, O_RDWR|O_CREAT, 0666);	\
	    ptm_et[0][i] = tick_time();			\
	    if (fd < 0) {	\
		printf("Cannot open file %s\n", fname);	\
		break;	\
	    }	\
	    ptm_st[1][i] = tick_time();		\
	    close(fd);	\
	    ptm_et[1][i] = tick_time();	\
	}	\
	MEASURE_FINISH_SYSCALL;	\
	unlink(fname);	\
    }

uint64_t	ptm_st[3][10000], ptm_et[3][10000], hz;

/*
 *
 *	argv[0] = iteration, argv[1] = system call number
 */
int
appl(void *f)
{
    int i, iter, syscl;

    iter = *((int**)f)[0];
    syscl = *((int**)f)[1];
    VERBOSE {
	printf("Cloned-thread is running. stack = %p pid=%d iter = %d\n", &i, getpid(), iter); fflush(stdout);
    }
    /* waiting for unlock by main */
    pthread_mutex_lock(&mx1);
    switch (syscl) {
    case SYS_GETID:
	//MEASURE_SYSCALL(SYS_GETID, gettid());
	MEASURE_SYSCALL(SYS_GETID, getpid());
	break;
    case SYS_GETUID:
	MEASURE_SYSCALL(SYS_GETUID, getuid());
	break;
    case SYS_OPEN_CLOSE:
	MEASURE_OPEN_CLOSE(SYS_OPEN_CLOSE);
	break;
#if 0
    case SYS_OPEN_WRITE_CLOSE:
    {
	char	ch = 0;
	MEASURE_OPEN_CLOSE(write(fd, &ch, 1), SYS_OPEN_CLOSE);
	break;
    }
#endif
    default:
	fprintf(stderr, "%s: internal error\n", __func__);
	break;
    }
    /* */
    VERBOSE {
	printf("%s: Exiting\n", __func__); fflush(stdout);
    }
    pthread_mutex_unlock(&mx2);
    /* waiting for unlock by main */
    pthread_mutex_lock(&mx3);
    exit(0);
    return 0;
}

static void
workarea_init()
{
    memset(ptm_st, 0, sizeof(ptm_st));
    memset(ptm_et, 0, sizeof(ptm_et));
    pthread_mutex_init(&mx1, 0);
    pthread_mutex_init(&mx2, 0);
    pthread_mutex_init(&mx3, 0);
    pthread_mutex_lock(&mx1);
    pthread_mutex_lock(&mx2);
    pthread_mutex_lock(&mx3);
}


int
search_syscall(char *snam)
{
    int	snum;
    for (snum = 0; snum < SYSCALL_MAX; snum++) {
	if (!strcmp(snam, sysname[snum])) {
	    goto find;
	}
    }
    /* not found */
    snum = -1;
find:
    return snum;
}

void
url_parse(char *cp, char **host, char **proto, int *port)
{
    char	*p, *q;
    /* find ':'  */
    p = index(cp, ':');
    if (p) {
	*p = 0;
	*proto = p;
	p += 1;
    } else {
	*proto = cp;
	/* just protocol */
	return;
    }
    if (!strncmp(p, "//", 2)) {
	p += 2;
	*host = p;
	q = index(p, ':');
	if (q) {
	    *q = 0;
	    q += 1;
	    if (isdigit(*q)) {
		*port = atoi(q);
	    }
	} else { /* just host name */
	    ;
	}
    } else {
	return;
    }
}

#define ARG_SERVER	"server="
#define ARG_LOGFILE	"logfile="

void
arg_parse(const char *cp, char **logfile,
	  char	**url, char **protocol, char **host, int *port) 
{
    char	*nxt;
    size_t	slen = strlen(ARG_SERVER);
    size_t	flen = strlen(ARG_LOGFILE);
    while (*cp) {
	if (!strncmp(ARG_SERVER, cp, slen)) {
	    cp += slen;
	    nxt = index(cp, ',');
	    if (nxt) {
		*url = strndup(cp, nxt - cp);
	    } else {
		*url = strdup(cp);
	    }
	    url_parse(*url, host, protocol, port);
	    if (nxt) {
		cp = nxt + 1;
	    } else {/* no more string */
		break;
	    }
	} else if (!strncmp(ARG_LOGFILE, cp, flen)) {
	    cp += flen;
	    nxt = index(cp, ',');
	    if (nxt) {
		*logfile = strndup(cp, nxt - cp);
		cp = nxt + 1;
	    } else {
		*logfile = strdup(cp);
		break;
	    }
	} else {
	    break;
	}
    }
}

void
clone_init()
{
    void	*stack;
    int		flags = CLONE_VM
		// CLONE_NEWPID | CLONE_FS | CLONE_IO| CLONE_NEWUTS
		;

    stack = malloc(STACK_SIZE);
    if (stack == NULL) {
	fprintf(stderr, "Cannot allocate stack memory\n");
	exit(-1);
    }
    memset(stack, 0, STACK_SIZE);
    printf("Clone application\n");
    clone(appl, STACK_TOP(stack), flags, NULL);
}

#define UNIT	"usec"
#define SCALE	1000000
void
measure_show(int syscl, int iter, int npkt,
	     int nflag, int hflag, int vflag)
{
    int	i, l;
    uint64_t	tclk;
    double		ttim;

    if (hflag) {
	printf("# iteration = %d, syscalls/1iter = %d,  %s/syscall, total: npkt=%d\n", iter, systab[syscl].ncall, UNIT, npkt);
    }
    /* application */
    if (vflag) {
	for (l = 0; l < systab[syscl].ncall; l++)  {
	    for (i = 0; i < iter; i++) {
		tclk = ptm_et[l][i] - ptm_st[l][i];
		ttim = (double)tclk/(((double)hz)/(double)SCALE);
		printf("%s, %12.9f, %12.9f, %ld\n",
		       tm_msg[syscl][l], (double)ttim/systab[syscl].ncall, ttim, tclk);
	    }
	}
    } else {
	uint64_t	ptm_max, ptm_min;
	double	avg, dev, stdev;
	unsigned	cpu, node;
	for (l = 0; l < systab[syscl].ncall; l++) {
	    /* skipping the first call */
	    ttim = 0;
	    tclk = ptm_et[l][0] - ptm_st[l][0];
	    ptm_max = 0; ptm_min = (uint64_t) -1LL;
	    for (i = 1; i < iter; i++) {
		tclk = ptm_et[l][i] - ptm_st[l][i];
		ttim += (double)tclk/(((double)hz)/(double)SCALE);
		ptm_max = tclk > ptm_max ? tclk : ptm_max;
		ptm_min = tclk < ptm_min ? tclk : ptm_min;
	    }
	    avg = (ttim/(double)(iter-1))/(double)systab[syscl].ncall;
	    dev = 0;
	    for (i = 1; i < iter; i++) {
		double	dclk = (ptm_et[l][i] - ptm_st[l][i]) - avg;
		dev += dclk * dclk;
	    }
	    dev /= (double)(iter-1);
	    stdev = sqrt(dev);
	    getcpu(&cpu, &node);
	    printf("#syscall, avg without 1st, total without 1st, 1st, "
		   "max, min, stdev, core#, node#\n");
	    printf("%s, %12.9f, %12.9f, %ld, %ld, %ld, %e, %d, %d\n",
		   tm_msg[syscl][l], avg, ttim, ptm_et[l][0] - ptm_st[l][0],
		   ptm_max, ptm_min, stdev, cpu, node);
	}
    }
}
