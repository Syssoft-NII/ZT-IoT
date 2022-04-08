extern void	regex_init();
extern int	msg_seqnum(char *msg, long *seq, long *tm1, long *tm2);
extern int	msg_syscall(char *msg, long *rslt);
extern int	msg_pid(char *msg, long *rslt);
extern int	msg_proctitle(char *msg, char *rslt);
extern int	msg_filepath(char *msg, long *item, char *path);
extern int	msg_cwd(char *msg, char *path);
extern int	hex2ascii(char *hex, char *asc);
