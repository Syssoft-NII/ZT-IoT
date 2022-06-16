#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mqtt_testlib.h"

int
main(int argc, char **argv)
{
    void	*mosq;
    char	*host = "localhost";
    char	*topic = "test";
    int	keepalive = 60;
    int	port = 1883;
    int	qos = 0;
    int	verbose;
    int	iter = 100;

    mqtt_optargs(argc, argv, &host, &port, &topic, &qos,
		 &iter, NULL, &verbose);
    if (verbose) {
	printf("host= %s port= %d topic= %s qos= %d iter= %d\n",
	       host, port, topic, qos, iter);
    }
    mosq = mqtt_init(host, port, keepalive, iter, verbose);
    mqtt_subscribe(mosq, NULL, topic, qos);
    mqtt_loop(mosq);
    mqtt_fin(mosq);
    return 0;
}
