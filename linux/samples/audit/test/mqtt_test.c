#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "mqtt_testlib.h"

int
main(int argc, char **argv)
{
    char	*host = "localhost";
    char	*topic = "test";
    int		len;
    int	keepalive = 60;
    int	port = 1883;
    int	qos = 0;
    int	vflag;
    int	iter = 100;

    mqtt_optargs(argc, argv, &host, &port, &topic, &qos, &iter, &len, &vflag);
    if (vflag) {
	printf("host = %s port = %d topic = %s qos= %d iter = %d len = %d\n",
	       host, port, topic, qos, iter, len);
    }
    mqtt_clone(host, port, keepalive, topic, len, iter, -1, vflag);
    return 0;
}
