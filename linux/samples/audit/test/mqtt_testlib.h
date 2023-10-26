extern int	mqtt_optargs(int argc, char **argv,
			     char **hostp, int *portp, char **topicp,
			     int *qosp, int *iterp, int *lenp, int *verbp);
extern void	*mqtt_init(char *host, int port, int keepalive, int iter, int verb);
//extern void	mqtt_loop_forever(void *vp);
extern void	mqtt_setdebugf();
extern void	mqtt_fin(void *vp);
extern void	mqtt_subscribe(void *vp, int *mid, char *topic, int qos);
extern void	mqtt_loop(void *vp);
extern void	mqtt_loop_forever(void *vp);
extern int	mqtt_publish(void *vp, int *mid, char *topic,
			     int len, char *msg, int qos, int retain);
extern int	mqtt_clone(char *host, int port, int keepalive, char *topic,
			   int len, int iter, int cpu, int vflag);
#if 0
extern void	mqtt_publisher(void **argv);
#endif
extern void	mqtt_publisher(char **argv);
extern void	mqtt_publish_callback_set(void *vp, void (*func)(void*, void*, int));
extern void	mqtt_publish_v5_callback_set(void *vp, void (*func)(void*, void*, int, int, void*));
extern void	mqtt_message_callback_set(void *vp, void (*func)(void *, void *, void*));
extern void	mqtt_getmessage(void *msg, const char **topic, const void **payload);
extern int	mqtt_loop_start(void *vp);
extern void	*mqtt_mxalloc();
extern void	mqtt_mxsignal(void*);
extern void	mqtt_mxwait(void*);
extern void	mqtt_setsighandler(int signo, void (*hndl)(int));

extern volatile int	mqtt_connected;
extern int	mqtt_iter;
extern char	mqtt_lastmsg[];
//extern uint64_t	clock_time();
