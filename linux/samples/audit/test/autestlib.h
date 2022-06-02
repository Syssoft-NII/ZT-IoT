#define MEASURE_FINISH_SYSNAME	"gettid"
#define MEASURE_FINISH_SYSCALL	{ gettid(); }
#define VERBOSE	if (verbose)

#define SYS_GETID	0
#define SYS_GETUID	1
#define SYS_OPEN_CLOSE	2
#define SYS_MAX		3

#define STACK_SIZE	(32*1024)
#define STACK_TOP(addr)	((addr) + STACK_SIZE)

struct syscalls {
    int		ncall;
    const char	*sysname[3];
};

extern int	verbose;
extern char	*sysname[];
extern pthread_mutex_t	mx1, mx2, mx3;
extern uint64_t			ptm_st[3][10000], ptm_et[3][10000], hz;

extern void	arg_parse(const char *cp, char **logfile,
			  char	**url, char **protocol, char **host,
			  int *port);
extern int	appl(void *f);
extern int	search_syscall(char *snam);


