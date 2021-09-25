typedef struct monlst {
    struct monlst	*next, *prev;
    int		seq;
    int		syscall;
    int		pid;
    char	proctitle[1024];
} monlst;

#define MAX_MONLIST	1024

extern void	monlst_init();
extern monlst	*monlst_alloc();
extern void	monlst_free(monlst *mlst);
extern monlst *monlst_find(int seq);


