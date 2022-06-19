#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "tsc.h"
#include "mqtt_testlib.h"

#define SCALE	1000000
#define MSG_SIZE	128
static char	msgbuf[MSG_SIZE];
static int	myiter = 0;
static int	nsend;
static int	iter = 100;
static void	*mx;
static void	*mosq;
static char	*topic = "test";
static char	*msg;
static int	qos = 0;
static uint64_t	st, et, hz;
static uint64_t	clk_st, clk_et;

extern uint64_t	clock_time();

void
mypublish()
{
    int	rc;
    snprintf(msgbuf, MSG_SIZE, "SEQ=%d: %s", myiter, msg);
    rc = mqtt_publish(mosq, NULL, topic, strlen(msgbuf), msgbuf, qos, 0);
    if (rc != 0) {
	printf("%s: mqtt_publish returns error (%d) myiter(%d)\n",
	       __func__, rc, myiter);
    }
}

void
published(void *mosq, void *obj, int mid)
{
    myiter++;
    if (myiter == iter) {
	et = tick_time();
	clk_et = clock_time();
	mqtt_mxsignal(mx);
    } else {
	mypublish();
    }
}

int
main(int argc, char **argv)
{
    char	*host = "localhost";
    int	keepalive = 60;
    int	port = 1883;
    int	verbose;
    int optidx;
    
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
    mqtt_publish_callback_set(mosq, published);
    mx = mqtt_mxalloc();
    /**/
    mqtt_loop_start(mosq);
    nsend = 0;
    /**/
    clk_st = clock_time();
    hz = tick_helz(0);
    st = tick_time();
    mypublish();
    mqtt_mxwait(mx);
    {
	uint64_t	clk = et - st;
	double	tm = (double)(clk)/((double)hz/(double)SCALE);
	printf("%s: time: %f/publish (usec) %f (usec) (%ld), start: %ld, end: %ld\n",
	       argv[0], tm/(iter), tm, clk, st, et);
	printf("\ttime(usec): %f/publish, %ld, start: %ld, end: %ld\n",
	       (double)(clk_et - clk_st)/(double)iter, clk_et - clk_st, clk_st, clk_et);
	fflush(stdout);
    }
    return 0;
}
