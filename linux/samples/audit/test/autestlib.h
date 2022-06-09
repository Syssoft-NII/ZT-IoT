#define MEASURE_FINISH_SYSNAME	"gettid"
#define MEASURE_FINISH_SYSCALL	{ gettid(); }
#define MEASURE_FINISH_SYSNAME_2	"getgid"
#define MEASURE_FINISH_SYSCALL_2	{ getgid(); }
#define VERBOSE	if (vflag)

#define SYS_GETID	0
#define SYS_GETUID	1
#define SYS_OPEN_CLOSE	2
#define SYS_MAX		3

#define STACK_SIZE	(128*1024)
#define STACK_TOP(addr)	((addr) + STACK_SIZE)

struct syscalls {
    int		ncall;
    const char	*sysname[3];
};

extern char	*sysname[];

extern void	arg_parse(const char *cp, char **logfile,
			  char	**url, char **protocol, char **host,
			  int *port, int *iter, int *cpu);
extern FILE	*out_open(char *fbuf, const char *prefix, int iter, int ntries,
			  const char *type, const char *ext, char *fname);
extern int	clone_init(int iter, int syscl, int vflag, int cpu,
			   int *fd, int is_enable);
extern int	core_bind(int cpu);
extern int	appl(void *f);
extern pthread_mutex_t	mx1, mx2, mx3;

extern int	search_syscall(char *snam);
extern void	measure_show(int syscl, int iter, int npkt,
			     uint64_t st, uint64_t et,
			     int hflag, int vflag, int isaud);
extern void	measure_dout(FILE *fp, int syscl, int iter);
