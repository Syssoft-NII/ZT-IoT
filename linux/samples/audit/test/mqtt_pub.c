#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mqtt_testlib.h"

static int	counter = 0;
static int	iteration;

#define MSG_SIZE	128
static char	msgbuf[MSG_SIZE];
int
main(int argc, char **argv)
{
    void	*mosq;
    char	*host = "localhost";
    char	*topic = "test";
    char	*msg;
    int	keepalive = 60;
    int	port = 1883;
    int	qos = 0;
    int	verbose;
    int	iter = 100;
    int optidx, i;
    
    optidx = mqtt_optargs(argc, argv, &host, &port, &topic, &qos,
			  &iter, NULL, &verbose);
    if (optidx != argc - 1) {
	printf("Requiring one argument for a topic message\n");
	return -1;
    }
    msg = argv[optidx];
    if (verbose) {
	printf("host= %s port= %d topic= %s qos= %d "
	       "iter= %d message = \"%s\"\n",
	       host, port, topic, qos, iter, msg);
    }
    mosq = mqtt_init(host, port, keepalive, iter, verbose);
    iteration = iter;
    for (i = 0; i < iter; i++) {
	snprintf(msgbuf, MSG_SIZE, "SEQ=%d: %s", i, msg);
	mqtt_publish(mosq, NULL, topic, strlen(msgbuf), msgbuf, qos, 0);
    }
    printf("counter = %d\n", counter);
    /* loop forever */
    mqtt_loop(mosq);
    /* if error happen */
    mqtt_fin(mosq);
    return 0;
}
