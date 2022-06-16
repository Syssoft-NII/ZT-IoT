extern int	mqtt_optargs(int argc, char **argv,
			     char **hostp, int *portp, char **topicp,
			     int *qosp, int *iterp, int *lenp, int *verbp);
extern void	*mqtt_init(char *host, int port, int keepalive, int iter, int verb);
//extern void	mqtt_loop_forever(void *vp);
extern void	mqtt_setdebugf();
extern void	mqtt_fin(void *vp);
extern void	mqtt_subscribe(void *vp, int *mid, char *topic, int qos);
extern void	mqtt_loop(void *vp);
extern int	mqtt_publish(void *vp, int *mid, char *topic,
			     int len, char *msg, int qos, int retain);
extern int	mqtt_clone(char *host, int port, int keepalive, char *topic,
			   int len, int iter, int cpu, int vflag);
#if 0
extern void	mqtt_publisher(void **argv);
#endif
extern void	mqtt_publisher(char **argv);
