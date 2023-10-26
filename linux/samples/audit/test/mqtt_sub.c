#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "mqtt_testlib.h"

static int	uslp = 0;
/*
 * SIGHUP handler
 */
static void hup_handler(int sig)
{
    printf("SIGHUP is catched. mqtt_iter=%d\n", mqtt_iter);
    printf("last message is %s\n", mqtt_lastmsg);
}

static void
received(void *vp, void *obj, void *msg)
{
    const char	*topic, *payload;
    mqtt_getmessage(msg, &topic, (const void**) &payload);
    printf("%s %s\n", topic, payload);
    if (uslp > 0) {
	usleep(uslp);
    }
}

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
    int optidx;
    int	iter = 100;

    optidx = mqtt_optargs(argc, argv, &host, &port, &topic, &qos,
			  &iter, NULL, &verbose);
    if (argc > optidx) {
	printf("optidx=%d argc=%d\n", optidx, argc);
	uslp = atoi(argv[optidx]) * 1000;
    }
    if (verbose) {
	printf("host= %s port= %d topic= %s qos= %d iter= %d usleep= %d\n",
	       host, port, topic, qos, iter, uslp);
    }
    mqtt_setsighandler(SIGHUP, hup_handler);
    mosq = mqtt_init(host, port, keepalive, iter, verbose);
    mqtt_message_callback_set(mosq, received);
    mqtt_subscribe(mosq, NULL, topic, qos);
    mqtt_loop(mosq);
    mqtt_fin(mosq);
    return 0;
}
