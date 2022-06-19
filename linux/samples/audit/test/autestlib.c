#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <libaudit.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include "sysname.h"
#include "tsc.h"
#include "autestlib.h"
#include "measurelib.h"

/* gettid() is the Linux specific system call */
extern int	gettid();

struct syscalls systab[SYS_MAX] = {
    { 1, {"getpid", NULL, NULL} },
    { 1, {"getuid", NULL, NULL} },
    { 2, {"openat", "close", NULL} }
};

char	*tm_msg[SYS_MAX][3] = {
    { "getpid", NULL, NULL},
    {"getuid", NULL, NULL},
    {"open", "close", NULL},
};


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

#define AUDIT_RULE_BY_NAME(rc, rl, name, errsym)	\
{	\
    rc = audit_rule_syscallbyname_data(rl, name);	\
    if (rc != 0) {	\
	fprintf(stderr,	\
		"audit_rule_syscallbyname_data(\"%s\") fails: %s (%d)\n",\
		name, audit_errno_to_name(-rc), rc);			\
	goto errsym; \
    }	\
}


pthread_mutex_t	mx1, mx2, mx3;
static struct audit_rule_data *rule;
static uint64_t	ptm_st[3][10000], ptm_et[3][10000], hz;
static int	app_core;

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

/*
 *
 *	argv[0] = iteration, argv[1] = system call number
 */
int
appl(void *f)
{
    int		i, iter, syscl, vflag;
    int		cpu;
    int		*argv = f;

    iter = argv[0];
    syscl = argv[1];
    vflag = argv[2];
    cpu = argv[3];

    app_core = core_bind(cpu);
    VERBOSE {
	printf("Cloned-thread is running on core#%d (requring core#%d. stack = %p pid=%d iter = %d syscl = %d vflag = %d\n", app_core, cpu, &i, getpid(), iter, syscl, vflag); fflush(stdout);
    }
    /* waiting for unlock by main */
    pthread_mutex_lock(&mx1);
    VERBOSE {
	printf("Start\n"); fflush(stdout);
    }
    switch (syscl) {
    case SYS_GETID:
	//MEASURE_SYSCALL(SYS_GETID, gettid());
	// pid 
	MEASURE_SYSCALL(SYS_GETID, syscall(172));
	break;
    case SYS_GETUID:
	//MEASURE_SYSCALL(SYS_GETUID, getuid());
	MEASURE_SYSCALL(SYS_GETUID, syscall(174));
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
#if 0
    /* Another system call for finishing */
    MEASURE_FINISH_SYSCALL_2;
#endif
    /* */
    VERBOSE {
	printf("%s: Going to exit\n", __func__); fflush(stdout);
    }
    pthread_mutex_unlock(&mx2);
    /* waiting for unlock by main */
    pthread_mutex_lock(&mx3);
    VERBOSE {
	printf("%s: Exiting\n", __func__); fflush(stdout);
    }
    exit(0);
    return 0;
}

static void
workarea_init()
{
    hz = tick_helz(0);
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
#define ARG_PREFIX	"prefix="
#define ARG_ITER	"iter="
#define ARG_CPU		"cpu="
#define ARG_SYSCALL	"sys="

/*
 * TODO: CLEAN UP!!
 */
void
arg_parse(const char *cp, char **prefix,
	  char	**url, char **protocol, char **host, int *port,
	  int *iter, int *cpu, int *syscall) 
{
    char	*nxt;
    size_t	slen = strlen(ARG_SERVER);
    size_t	flen = strlen(ARG_PREFIX);
    size_t	ilen = strlen(ARG_ITER);
    size_t	clen = strlen(ARG_CPU);
    size_t	syslen = strlen(ARG_SYSCALL);
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
	} else if (!strncmp(ARG_PREFIX, cp, flen)) {
	    cp += flen;
	    nxt = index(cp, ',');
	    if (nxt) {
		*prefix = strndup(cp, nxt - cp);
		cp = nxt + 1;
	    } else {
		*prefix = strdup(cp);
		break;
	    }
	} else if (!strncmp(ARG_ITER, cp, ilen)) {
	    char	*tmp;
	    cp += ilen;
	    nxt = index(cp, ',');
	    if (nxt) {
		tmp = strndup(cp, nxt - cp);
		*iter = atoi(tmp);
		free(tmp);
		cp = nxt + 1;
	    } else {
		tmp = strdup(cp);
		*iter = atoi(tmp);
		free(tmp);
		break;
	    }
	} else if (!strncmp(ARG_CPU, cp, clen)) {
	    char	*tmp;
	    cp += clen;
	    nxt = index(cp, ',');
	    if (nxt) {
		tmp = strndup(cp, nxt - cp);
		*cpu = atoi(tmp);
		free(tmp);
		cp = nxt + 1;
	    } else {
		tmp = strdup(cp);
		*cpu = atoi(tmp);
		free(tmp);
		break;
	    }
	} else if (!strncmp(ARG_SYSCALL, cp, syslen)) {
	    char	*tmp;
	    cp += clen;
	    nxt = index(cp, ',');
	    if (nxt) {
		tmp = strndup(cp, nxt - cp);
		if (syscall) *syscall = atoi(tmp);
		free(tmp);
		cp = nxt + 1;
	    } else {
		tmp = strdup(cp);
		if (syscall) *syscall = atoi(tmp);
		free(tmp);
		break;
	    }
	} else {
	    break;
	}
    }
}

static  int  app_argv[4];

int
clone_init(int iter, int syscl, int vflag, int app_cpu,
	   int *fd_audit, int is_enb)
{
    int		i, mrkr, rc = 0;
    int		fd;
    void	*stack;
    int		flags = CLONE_VM
		// CLONE_NEWPID | CLONE_FS | CLONE_IO| CLONE_NEWUTS
		;
    mrkr = search_syscall(MEASURE_FINISH_SYSNAME);
    if (mrkr < 0) {
	printf("The %s system call is not avalabe on your system.\n",
	       MEASURE_FINISH_SYSNAME);
	exit(-1);
    }
    if (fd_audit) {
	/* audit open */
	fd = audit_open();
	if (fd < 0) {
	    perror("audit_open: ");
	    exit(-1);
	}
	*fd_audit = fd;
	rule = audit_rule_create_data();
	if (rule == NULL) {
	    fprintf(stderr, "Cannot allocate an audit rule structure\n");
	    close(fd);
	    exit(-1);
	}
    }

    stack = malloc(STACK_SIZE);
    if (stack == NULL) {
	fprintf(stderr, "Cannot allocate stack memory\n");
	exit(-1);
    }
    memset(stack, 0, STACK_SIZE);
    workarea_init();

    if (fd_audit) {
	/* add marker and other syscalls for capturing */
	AUDIT_RULE_BY_NAME(rc, rule, MEASURE_FINISH_SYSNAME, err);
#if 0
	AUDIT_RULE_BY_NAME(rc, rule, MEASURE_FINISH_SYSNAME_2, err);
#endif
	for (i = 0; i < systab[syscl].ncall; i++) {
	    VERBOSE {
		printf("systab[i]: %s\n",  systab[syscl].sysname[i]);
	    }
	    AUDIT_RULE_BY_NAME(rc, rule, systab[syscl].sysname[i], err);
	}
	rc = audit_add_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
	if (rc <= 0) {
	    fprintf(stderr, "audit_add_rule_data() fails: %s, %d\n",
		    audit_errno_to_name(-rc), rc);
	    if (rc == -17) {
		fprintf(stderr, "The rule already exists. Please see the rules and delete them using the auditctl command.\n");
	    }
	    close(fd);
	    goto err;
	}
	if (is_enb) {
	    /* Enabling the audit system to capture system calls */
	    rc = audit_set_enabled(fd, 1);
	    if (rc <= 0) {
		fprintf(stderr, "audit_set_enabled() fails: %d\n", rc);
		close(fd);
		goto err;
	    }
	    /* This process becomes audit daemon process */
	    rc = audit_set_pid(fd, getpid(), WAIT_YES);
	    if (rc <= 0) {
		fprintf(stderr, "audit_set_enabled() fails: %d\n", rc);
		close(fd);
		exit(-1);
	    }
	}
    }

    /* create thread */
    VERBOSE {
	printf("Clone application\n");
    }
    app_argv[0] = iter;
    app_argv[1] = syscl;
    app_argv[2] = vflag;
    app_argv[3] = app_cpu;
    rc = clone(appl, STACK_TOP(stack), flags, app_argv);
    if (rc < 0) {
	perror("");
	close(fd);
	exit(-1);
    }
    /* thread is now waiting */
ret:
    free(rule);
    return mrkr;
err:
    mrkr = -1;
    goto ret;
}

#define UNIT	"usec"
#define SCALE	1000000
void
measure_show(int syscl, int iter, int npkt, uint64_t st, uint64_t et,
	     int hflag, int vflag, int isaud)
{
    int	i, l;
    uint64_t	tclk;
    double	ttim;
    uint64_t	ptm_max, ptm_min;
    double	avg, dev, stdev;
    unsigned	cpu, node;

    if (hflag) {
	printf("# iteration = %d, syscalls/1iter = %d,  %s/syscall, total: npkt=%d\n", iter, systab[syscl].ncall, UNIT, npkt);
    }
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
	       "max, min, stdev, iter, core#, node#\n");
	printf("%s, %12.9f, %12.9f, %ld, %ld, %ld, %e, %d, %d, %d\n",
	       tm_msg[syscl][l], avg, ttim, ptm_et[l][0] - ptm_st[l][0],
	       ptm_max, ptm_min, stdev, iter, cpu, node);
    }
    if (isaud) {
	printf("audit processing time (usec): "
	       "start clock(%ld) end clock(%ld)\n"
	       "                            : %12.9f in %d packets\n",
	       st, et, (double)(et - st)/(((double)hz)/(double)SCALE), npkt);
    }
    printf("\n-----------------------------\n");
    cpu_info(stdout);
}

void
measure_dout(FILE *fp, int syscl, int iter)
{
    int	i, l;
    uint64_t	tclk;
    double	ttim;
    for (l = 0; l < systab[syscl].ncall; l++)  {
	fprintf(fp, "# %s ruuning on Core#%d iter=%d\n", tm_msg[syscl][l], app_core, iter);
	for (i = 0; i < iter; i++) {
	    tclk = ptm_et[l][i] - ptm_st[l][i];
	    ttim = (double)tclk/(((double)hz)/(double)SCALE);
	    fprintf(fp, "%12.9f # %12.9f %ld\n",
		    (double)ttim/systab[syscl].ncall, ttim, tclk);
	}
    }
}

FILE *
out_open(char *fbuf, const char *prefix, int iter, int ntries,
	 const char *type, const char *ext, char *fname)
{
    FILE	*fp;
    static int	notfirst = 0;
    static struct tm	tm;
    static time_t	tt;

    if (notfirst == 0) {
	time(&tt);
	localtime_r(&tt, &tm);
	notfirst = 1;
    }
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
