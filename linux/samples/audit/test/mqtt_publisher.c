/*
 * ./mqtt_publisher <host> <port> <keep> <topic> <len> <iter> <cpu> <fd> <vflg>
 * ./mqtt_publisher localhost 1883 60 "test" 1024 1 0 0 1
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "mqtt_testlib.h"

int
main(int argc, char **argv)
{
    void	*mosq;
    char	*msg;
    int	i;
    char	*host;
    char	*topic;
    int		port, keepalive, len, iter, cpu, sub_bfd, vflag;
    
    mqtt_setdebugf();
    host = (char*) argv[1];
    port = atoi(argv[2]);
    keepalive = atoi(argv[3]);
    topic = argv[4];
    len =  atoi(argv[5]);
    iter = atoi(argv[6]);
    cpu = atoi(argv[7]);
    sub_bfd = atoi(argv[8]);
    vflag = atoi(argv[9]);
    mosq = mqtt_init(host, port, keepalive, iter, vflag);

    printf("mqtt_publisher: run\n");

    msg = malloc(len);
    for (i = 0; i < len; i++) {
	msg[i] = 'a' + (i % 24);
    }
    msg[len-1] = 0;
    printf("%s: Publishing\n", __func__);
    fflush(stdout);
    for (i = 0; i < iter; i++) {
	int	rc;
	snprintf(msg, len, "SEQ:%6d ", i);
	rc = mqtt_publish(mosq, NULL, topic, len, msg, 1, 0);
	printf("%s: rc = %d %d\n", __func__, rc, i);
    }
    /* loop forever */
    mqtt_loop(mosq);

#if 0
    mqtt_publisher(argv);
#endif
    return 0;
}
