#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mosquitto.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <pthread.h>
#include <signal.h>
#include "mqtt_testlib.h"
#include "tsc.h"

#define VERBOSE	if (vflag)
#define DEBUG if (debugflag)
#define STACK_SIZE	(128*1024)
#define STACK_TOP(addr)	((addr) + STACK_SIZE)
#define PUB_LOCKF_BEGIN	"/tmp/lock_pub_begin"
#define PUB_LOCKF_END	"/tmp/lock_pub_end"
#define SUB_LOCKF_BEGIN	"/tmp/lock_sub_begin"
#define SUB_LOCKF_END	"/tmp/lock_sub_end"
#define SYNC_FILE	"/tmp/sync_mqtt"
#define SYNC_TOPIC	"mqtt_sync"
#define SYNC_MESSAGE	"Let's start"

extern int	core_bind(int cpu);

#define SCALE	1000000

volatile int	mqtt_connected = 0;
int	mqtt_iter = 100;
char	mqtt_lastmsg[1024];
static int	verbose = 0;
static int	debugflag = 0;
static uint64_t	tm_st, tm_et, tm_hz;
static int	subscriber_bfd = -1;
static int	subscriber_efd = -1;
static int	publisher_bfd = -1;

/* usec */
uint64_t
clock_time()
{
    struct timeval tv;
    uint64_t	val ;
    gettimeofday (&tv, NULL);
    val = tv.tv_sec*1000000 + tv.tv_usec;
    return val;
}

void
mqtt_setsighandler(int signo, void (*hndl)(int))
{
    struct sigaction sa;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    /* Set handler for the ones we care about */
    sa.sa_handler = hndl;
    sigaction(signo, &sa, NULL);
}

void*
mqtt_mxalloc()
{
    pthread_mutex_t	*mxp;
    mxp = malloc(sizeof(pthread_mutex_t));
    if (mxp == NULL) {
	fprintf(stderr, "Cannot allocate mutex\n");
	exit(-1);
    }
    pthread_mutex_init(mxp, 0);
    pthread_mutex_lock(mxp);
    return mxp;
}

void
mqtt_mxsignal(void *p)
{
    pthread_mutex_t	*mxp = p;
    pthread_mutex_unlock(mxp);
}

void
mqtt_mxwait(void *p)
{
    pthread_mutex_t	*mxp =p;
    pthread_mutex_lock(mxp);
}

char *
mqtt_int2string(int val)
{
    char	*mem = malloc(128);
    snprintf(mem, 128, "%d", val);
    return mem;
}

int
mqtt_lockopen(char *path)
{
    int	fd;
    fd = open(path, O_CREAT|O_RDWR, 0666);
    if (fd < 0) {
	fprintf(stderr, "Cannot create lock file: %s\n", path);
	exit(-1);
    }
    lockf(fd, F_LOCK, 0);
    return fd;
}

#define SYNC_OP_WRITE	0
#define SYNC_OP_INC	1
#define SYNC_OP_READ	2

int
mqtt_lock_op(char *path, int op, char data)
{
    int		fd;
    char	tmp;
    ssize_t	sz;
    fd = mqtt_lockopen(SYNC_FILE);
    switch(op) {
    case SYNC_OP_WRITE:
	sz = write(fd, &data, 1);
	if (sz != 1) goto err_ext;
	tmp = data;
	break;
    case SYNC_OP_READ:
	sz = read(fd, &tmp, 1);
	if (sz != 1) goto err_ext;
	break;
    case SYNC_OP_INC:
	sz = read(fd, &tmp, 1);
	if (sz != 1) goto err_ext;
	tmp++;
	lseek(fd, 0, SEEK_SET);
	sz = write(fd, &tmp, 1);
	if (sz != 1) goto err_ext;
	break;
    }
err_ext:
    fprintf(stderr, "%s:Fail\n", __func__);
    lockf(fd, F_ULOCK, 0);
    close(fd);
    return tmp;
}

int
mqtt_lockclose(int fd)
{
    return close(fd);
}

void
mqtt_getmessage(void *msg, const char **topic, const void **payload)
{
    struct mosquitto_message *mos_msg = (struct mosquitto_message*) msg;
    *topic = mos_msg->topic;
    *payload = mos_msg->payload;
}

void
mqtt_publish_v5_callback_set(void *vp, void (*func)(void*, void*, int, int, void*))
{
    struct mosquitto *mosq = vp;
    void (*mosq_func)(struct mosquitto*, void *, int, int, const mosquitto_property *);
    mosq_func = (void (*)(struct mosquitto*, void*, int, int, const mosquitto_property *)) func;
    mosquitto_publish_v5_callback_set(mosq, mosq_func);
}

void
mqtt_message_callback_set(void *vp, void (*func)(void *, void *, void*))
{
    struct mosquitto *mosq = vp;
    void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *);
    on_message = (void(*)(struct mosquitto *, void *, const struct mosquitto_message *)) func;
    mosquitto_message_callback_set(mosq, on_message);
}

static void
mqtt_on_connect(struct mosquitto *mosq, void *obj, int rc)
{
    printf("%s: CONNECTED rc=%d\n", __func__, rc);
    mqtt_connected = 1;
}

static void
mqtt_on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    --mqtt_iter;
    /**/
    strncpy(mqtt_lastmsg, message->payload, 128);
    DEBUG {
	char	buf[128];
	strncpy(buf, message->payload, 10);
	buf[10] = 0;
	printf("%s:<%d> topc=\"%s\" msg(%s)\n", __func__, mqtt_iter, message->topic, buf);
	fflush(stdout);
    }
    if (mqtt_iter == 0) {
	DEBUG {
	    printf("%s: subscriber_bfd= %d\n", __func__, subscriber_bfd); fflush(stdout);
	}
	if (subscriber_bfd > 0) {
	    lockf(subscriber_bfd, F_ULOCK, 0);
	    lockf(subscriber_efd, F_ULOCK, 0);
	    mqtt_lockclose(subscriber_bfd);
	    mqtt_lockclose(subscriber_efd);
	}
	mqtt_fin(mosq);
	tm_et = tick_time();
	if (verbose) {
	    uint64_t	clk = tm_et - tm_st;
	    double	tm = (double)(clk)/((double)tm_hz/(double)SCALE);
	    printf("%s: time: %f (usec) (%ld), start: %ld, end: %ld, \n",
		   __func__, tm, clk, tm_st, tm_et); fflush(stdout);
	}
	exit(0);
    }
}

static void
mqtt_on_publish(struct mosquitto *mosq, void *obj, int mid)
{
    --mqtt_iter;
    DEBUG {
	printf("%s: mqtt_iter(%d)\n", __func__, mqtt_iter); fflush(stdout);
    }
    if (mqtt_iter == 0) {
	mqtt_fin(mosq);
	tm_et = tick_time();
	if (verbose) {
	    uint64_t	clk = tm_et - tm_st;
	    double	tm = (double)(clk)/((double)tm_hz/(double)SCALE);
	    printf("%s: time: %f (usec) (%ld), start: %ld, end: %ld, \n",
		   __func__, tm, clk, tm_st, tm_et);
	    fflush(stdout);
	}
	/* !!!! */
	exit(0);
    }
}

void
mqtt_setdebugf()
{
    debugflag = 1;
}

int
mqtt_optargs(int argc, char **argv, char **hostp, int *portp, char **topicp,
	     int *qosp, int *iterp, int *lenp, int *verbp)
{
    int	opt;

    *verbp = 0;
    while ((opt = getopt(argc, argv, "H:P:T:Q:i:l:vhd")) != -1) {
	switch (opt) {
	case 'H':
	    *hostp = strdup(optarg);
	    break;
	case 'P':
	    *portp = atoi(optarg);
	    break;
	case 'T':
	    *topicp = strdup(optarg);
	    break;
	case 'Q':
	    *qosp = atoi(optarg);
	    break;
	case 'i':
	    *iterp = atoi(optarg);
	    break;
	case 'l':
	    if (lenp) *lenp = atoi(optarg);
	    break;
	case 'v':
	    *verbp = 1;
	    break;
	case 'd':
	    debugflag = 1;
	    break;
	case 'h':
	    fprintf(stderr, "%s -H <host> -P <port> -T <topic> -h\n", argv[0]);
	    exit(0);
	}
    }
    return optind;
}

void *
mqtt_init(char *host, int port, int keepalive, int iter, int verb)
{
    struct mosquitto *mosq;

    verbose = verb;
    mqtt_iter = iter;
    tm_hz = tick_helz(0);
    if (verbose) {
	printf("%s: hz(%ld) debugflag=%d\n", __func__, tm_hz, debugflag);
    }
    if (tm_hz == 0) {
	printf("Cannot obtain CPU frequency\n");
	exit(-1);
    }
    mosquitto_lib_init();
    mosq = mosquitto_new(NULL, true, NULL);
    if(!mosq) {
        fprintf(stderr, "Error mosquitto_new()\n");
        mosquitto_lib_cleanup();
	exit(-1);
    }
    mosquitto_connect_callback_set(mosq, mqtt_on_connect);
    mosquitto_message_callback_set(mosq, mqtt_on_message);
    mosquitto_publish_callback_set(mosq, mqtt_on_publish);
    if(mosquitto_connect(mosq, host, port, keepalive)) {
        fprintf(stderr, "failed to connect broker: host=%s port=%d keepalive=%d.\n", host, port, keepalive);
        mosquitto_lib_cleanup();
        return NULL;
    }
    return (void*) mosq;
}

int
mqtt_loop_start(void *vp)
{
    struct mosquitto *mosq = vp;
    return mosquitto_loop_start(mosq);
}

void
mqtt_publish_callback_set(void *vp, void (*func)(void*, void*, int))
{
    struct mosquitto *mosq = vp;
    void	 (*mosq_func)(struct mosquitto*, void*, int);
    mosq_func = (void(*)(struct mosquitto*, void*, int))func;
    mosquitto_publish_callback_set(mosq, mosq_func);
}

void
mqtt_fin(void *vp)
{
    struct mosquitto *mosq = (struct mosquitto *) vp;
    mosquitto_disconnect(mosq);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
}

void
mqtt_loop_forever(void *vp)
{
    int	rc;
    struct mosquitto *mosq = (struct mosquitto *) vp;
    rc = mosquitto_loop_forever(mosq, -1, 1);
    if(rc != MOSQ_ERR_SUCCESS){
	fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
    }
}

void
mqtt_subscribe(void *vp, int *mid, char *topic, int qos)
{
    struct mosquitto *mosq = (struct mosquitto *) vp;
    mosquitto_subscribe(mosq, mid, topic, qos);
}

int
mqtt_publish(void *vp, int *mid, char *topic, int len, char *msg,
	     int qos, int retain)
{
    struct mosquitto *mosq = (struct mosquitto *) vp;
    int	rc;
    rc = mosquitto_publish(mosq, mid, topic, len, msg, qos, retain);
    return rc;
}

void
mqtt_loop(void *vp)
{
    struct mosquitto *mosq = (struct mosquitto *) vp;
    int ret;

    tm_st = tick_time();
    /* 2nd arg: timeout
     * 3rd arg: max_packets, unused and must be set to 1 */
    ret = mosquitto_loop_forever(mosq, -1, 1);
    if (ret != MOSQ_ERR_SUCCESS) {
	fprintf(stderr, "mosquitto_loop_forever error %d\n", ret);
    }
}

/*
 *	mqtt_publisher:
 *		argv[0] = "publisher"
 *		argv[1] = (char*) host
 *		argv[2] = (int) port
 *		argv[3] = (int) keepalive
 *		argv[4] = (char*) topic
 *		argv[5] = (int) message length
 *		argv[6] = (int) iteration
 *		argv[7] = (int) cpu
 *		argv[8] = (int) sub_bfd
 *		argv[9] = (int) vflag
 *		argv[10] = 0
 */
void
mqtt_publisher(char **argv)
{
    char	*host, *topic;
    int		port, keepalive, len, iter, cpu, vflag;
    int		app_core;
    int		i, sub_bfd;
    char	*msg;
    void	*mosq;

    host = argv[1];
    port = atoi(argv[2]);
    keepalive = atoi(argv[3]);
    topic = argv[4];
    len   = atoi(argv[5]);
    iter  = atoi(argv[6]);
    cpu   = atoi(argv[7]);
    sub_bfd = atoi(argv[8]);
    vflag  = atoi(argv[9]);

    app_core = core_bind(cpu);

    if (len < 1024) {
	len = 1024;
    }
    VERBOSE {
	printf("%s: host= %s port= %d keepalive=%d topic= %s "
	       "len=%d iter= %d core= %d sub_bfd= %d\n",
	       __func__, host, port, keepalive, topic, len, iter, app_core, sub_bfd);
    }
    /**/
    msg = malloc(len);
    for (i = 0; i < len; i++) {
	msg[i] = 'a' + (i % 24);
    }
    msg[len-1] = 0;
    mosq = mqtt_init(host, port, keepalive, iter, vflag);
    /* Synchronization with subscriber */
    {
	char	data;
	data = mqtt_lock_op(SYNC_FILE, SYNC_OP_INC, 1);
	while (data != 2) {
	    data = mqtt_lock_op(SYNC_FILE, SYNC_OP_READ, 1);
	}
    }
    DEBUG {
	printf("%s: Publishing len(%d)\n", __func__, len); fflush(stdout);
    }
    tm_st = tick_time();
    for (i = 0; i < iter; i++) {
	int	rc;
	snprintf(msg, len, "SEQ:%6d ", i);
	rc = mqtt_publish(mosq, NULL, topic, len, msg, 1, 0);
	if (rc != MOSQ_ERR_SUCCESS) {
	    fprintf(stderr, "%s: Error %s\n",
		    __func__, mosquitto_strerror(rc));
	}
	printf("%s: %d\n", __func__, i);
    }
    //mqtt_fin(mosq);
    /* loop forever */
    mqtt_loop(mosq);
}

static void	*sub_argv[8];
#if 0
static void	*pub_argv[10];
#endif
static char	*pub_argv[11];

/*
 *	mqtt_subscriber:
 *		argv[0] = (char*) host
 *		argv[1] = (int) port,
 *		argv[2] = (int) keepalive, 
 *		argv[3] = (char*) topic,
 *		argv[4] = (int) iter,
 *		argv[5] = (int) cpu
 *		argv[6] = (int) lockfd
 *		argv[7] = (int) verbose
 */
void
mqtt_subscriber(void **argv)
{
    char	*host, *topic;
    int		port, keepalive, iter, cpu, vflag;
    int		app_core;
    void	*mosq;
    int		sub_bfd, sub_efd;
    int		pub_bfd;

    host = (char*) argv[0];
    port = (int64_t) ((char*) argv[1]);
    keepalive = (int64_t) ((char*) argv[2]);
    topic = (char*) argv[3];
    iter = (int64_t) ((char*) argv[4]);
    cpu = (int64_t) ((char*) argv[5]);
    pub_bfd = (int64_t) ((char*) argv[6]);
    vflag = (int64_t) ((char*) argv[7]);

    app_core = core_bind(cpu);
    subscriber_efd = sub_efd = mqtt_lockopen(SUB_LOCKF_END);
    VERBOSE {
	printf("%s: host= %s port= %d topic= %s core= %d pub_bfd= %d\n",
	       __func__, host, port, topic, app_core, pub_bfd); fflush(stdout);
	printf("%s(%d): lock file = %s\n", __func__, getpid(), SUB_LOCKF_END);
    }
    mosq = mqtt_init(host, port, keepalive, iter, vflag);
    mqtt_subscribe(mosq, NULL, topic, 1);
#if 0
    mqtt_subscribe(mosq, NULL, topic, 0);
#endif
    /* Synchronization with publisher */
    {
	char	data;
	data = mqtt_lock_op(SYNC_FILE, SYNC_OP_INC, 1);
	while (data != 2) {
	    data = mqtt_lock_op(SYNC_FILE, SYNC_OP_READ, 1);
	}
    }
#if 0
    /* Synchronization with publisher */
    lockf(pub_bfd, F_ULOCK, 0);
    subscriber_bfd = sub_bfd = mqtt_lockopen(SUB_LOCKF_BEGIN);
#endif
    printf("%s: Subscribing\n", __func__); fflush(stdout);
    DEBUG {
	printf("%s: Subscribing\n", __func__); fflush(stdout);
    }
    mqtt_loop(mosq);
    /* Never comes here */
    VERBOSE {
	printf("%s: Error return\n", __func__); fflush(stdout);
    }
#if 0
    lockf(sub_bfd, F_ULOCK, 0);
    lockf(sub_efd, F_ULOCK, 0);
    mqtt_lockclose(sub_bfd);
    mqtt_lockclose(sub_efd);
#endif
    mqtt_fin(mosq);
}

int
mqtt_clone(char *host, int port, int keepalive, char *topic,
	   int len, int iter, int cpu, int vflag)
{
    int	pid;
    int	sub_bfd = -1;
    int	sub_efd = -1;
    int pub_bfd = -1;

    printf("%s: keepalive = %d\n", __func__, keepalive);
    {
	unlink(SYNC_FILE);
	mqtt_lock_op(SYNC_FILE, SYNC_OP_WRITE, 0);
	printf("%s: SYNC_FILE = %s\n", __func__, SYNC_FILE); fflush(stdout);
    }
#if 0
    unlink(SUB_LOCKF_BEGIN);
    unlink(SUB_LOCKF_END);
    sub_bfd = mqtt_lockopen(SUB_LOCKF_BEGIN);
    pub_bfd = mqtt_lockopen(PUB_LOCKF_BEGIN);
    printf("%s: %s (sub_bfd= %d) %s (pub_bfd= %d)\n", __func__,
	   SUB_LOCKF_BEGIN, sub_bfd, PUB_LOCKF_BEGIN, pub_bfd); fflush(stdout);
#endif
    /* subscriber */
    sub_argv[0] = (void*) host;
    sub_argv[1] = (void*) (uint64_t) port;
    sub_argv[2] = (void*) (uint64_t)keepalive;
    sub_argv[3] = (void*) topic;
    sub_argv[4] = (void*) (uint64_t) iter;
    sub_argv[5] = (void*) (uint64_t) cpu;
    sub_argv[6] = (void*) (uint64_t) pub_bfd;
    sub_argv[7] = (void*) (uint64_t) vflag;
    pid = fork();
    if (pid == 0) {
	//mqtt_lockclose(sub_bfd);
	mqtt_subscriber(sub_argv);
	exit(0);
    }
    /* parent: creating publisher */
#if 0
    pub_argv[0] = (void*) host;
    pub_argv[1] = (void*) (uint64_t) port;
    pub_argv[2] = (void*) (uint64_t)keepalive;
    pub_argv[3] = (void*) topic;
    pub_argv[4] = (void*) (uint64_t) len;
    pub_argv[5] = (void*) (uint64_t) iter;
    pub_argv[6] = (void*) (uint64_t) cpu;
    pub_argv[7] = (void*) (uint64_t) sub_bfd;
    pub_argv[8] = (void*) (uint64_t) vflag;
    pub_argv[9] = 0;
#endif
    pub_argv[0] = "mqtt_publisher";
    pub_argv[1] = host;
    pub_argv[2] = mqtt_int2string(port);
    pub_argv[3] = mqtt_int2string(keepalive);
    pub_argv[4] = topic;
    pub_argv[5] = mqtt_int2string(len);
    pub_argv[6] = mqtt_int2string(iter);
    pub_argv[7] = mqtt_int2string(cpu);
    pub_argv[8] = mqtt_int2string(sub_bfd);
    pub_argv[9] = mqtt_int2string(vflag);
    pub_argv[10] = 0;

#if 0
    printf("%s: Now sleeping\n", __func__); fflush(stdout);
    sleep(1);
    printf("%s: Wakeup\n", __func__); fflush(stdout);
#endif
    pid = fork();
    if (pid == 0) {
	mqtt_publisher(pub_argv);
#if 0
	printf("%s: exec\n", __func__);fflush(stdout);
	execvp("./mqtt_publisher", pub_argv);
	printf("%s: EXEC ERROR\n", __func__); fflush(stdout);
#endif
	exit(0);
    }
    //printf("Parent(%d): ", getpid()); fflush(stdout);
    //fgets(buf, 128, stdin);
    printf("%s: Now trying to lock %s\n", __func__, SUB_LOCKF_END); fflush(stdout);
    /* wait */
    sub_efd = mqtt_lockopen(SUB_LOCKF_END);
    printf("Parent Resume\n"); fflush(stdout);
    close(sub_efd);
    return 0;
}
