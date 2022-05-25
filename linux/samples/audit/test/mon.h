typedef struct monlst {
    struct monlst	*next, *prev;
    int		seq;
    int		syscall;
    int		pid;
    char	proctitle[1024];
} monlst;

extern monlst	*montop;
extern monlst	*monfree;
#define MAX_MONLIST	1024

