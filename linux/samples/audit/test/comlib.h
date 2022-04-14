extern int	mqtt_init(char *host, int port, int keepalive);
extern int	mqtt_pub(char *topic, char *msg);
extern void	mqtt_poll();
extern int	mqtt_shutdown();
