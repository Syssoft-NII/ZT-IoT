#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mqtt_testlib.h"

static int	iteration;

#define MSG_SIZE	128
static char	msgbuf[MSG_SIZE];
static volatile int	myiter = 0;
static int	iter = 100;
static void	*mx;

void
published(void *mosq, void *obj, int mid)
{
    myiter++;
    if (myiter == iter) {
	mqtt_mxsignal(mx);
    }
}

void
published_v5(void *mosq, void *obj, int mid, int rc, void *prop)
{
    if (rc) {
	fprintf(stderr, "publish error: 0x%x\n", rc);
    }
    myiter++;
    if (myiter == iter) {
	mqtt_mxsignal(mx);
    }
}

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
    //mqtt_publish_callback_set(mosq, published);
    mqtt_publish_callback_set(mosq, 0);
    mqtt_publish_v5_callback_set(mosq, published_v5);
    mx = mqtt_mxalloc();
    /**/
    mqtt_loop_start(mosq);
    iteration = iter;
    for (i = 0; i < iter; i++) {
	int	rc;
	snprintf(msgbuf, MSG_SIZE, "SEQ=%d: %s", i, msg);
	rc = mqtt_publish(mosq, NULL, topic, strlen(msgbuf), msgbuf, qos, 0);
	if (rc != 0) {
	    printf("%s: mqtt_publish returns error (%d)\n", argv[0], rc);
	    break;
	}
    }
    printf("Myiter = %d\n", myiter);
    mqtt_mxwait(mx);
    printf("Myiter = %d\n", myiter);
    mqtt_fin(mosq);
    return 0;
}
