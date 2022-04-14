#include <mosquitto.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "comlib.h"

#define DEBUG	 if (comdflag)

int	comdflag;

static struct mosquitto *mosq_hndl;
static int	mosq_init = 0;

void
on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
    fprintf(stderr, "%s obj=%p rc =%d\n", __func__, obj, rc);
    fflush(stderr);
}

int
mqtt_init(char *host, int port, int keepalive)
{
    int	sock;
    mosquitto_lib_init();
    mosq_hndl = mosquitto_new(NULL, true, NULL);
    if(!mosq_hndl) {
        fprintf(stderr, "Cannot create mosquitto object\n");
        mosquitto_lib_cleanup();
        return -1;
    }
    mosquitto_disconnect_callback_set(mosq_hndl, on_disconnect);
    if(mosquitto_connect(mosq_hndl, host, port, keepalive)) {
        fprintf(stderr, "failed to connect broker.\n");
        mosquitto_lib_cleanup();
        return -1;
    }
    sock = mosquitto_socket(mosq_hndl);
    mosq_init = 1;
    DEBUG {
	printf("%s: host=%s port=%d sock=%d\n", __func__, host, port, sock);
    }
    return sock;
}

/*
 *	qos :  0, 1, or 2
 */
int
mqtt_pub(char *topic, char *msg)
{
    int	rc;
    int	qos = 1;
//    int	qos = 2; /* does not work ?? */

    if (mosq_init == 0) {
	fprintf(stderr, "mosquitto has not yet initialized\n");
	return -1;
    }
    rc = mosquitto_publish(mosq_hndl, NULL, topic, strlen(msg), msg, qos, false);
    DEBUG {
	fprintf(stderr, "%s: mosq_init=%d size(%ld) topic=%s\n", __func__, mosq_init, strlen(msg), topic);
	switch (rc) {
	case MOSQ_ERR_SUCCESS:
	    fprintf(stderr, "\tsuccess (%d).\n", rc);
	    break;
	case MOSQ_ERR_INVAL:
	    fprintf(stderr, "\tthe input parameters were invalid (%d).\n", rc);
	    break;
	case MOSQ_ERR_NOMEM:
	    fprintf(stderr,  "\tan out of memory condition occurred (%d).\n", rc);
	    break;
	case MOSQ_ERR_NO_CONN:
	    fprintf(stderr, "\tthe client isn¡Çt connected to a broker (%d).\n", rc);
	    break;
	case MOSQ_ERR_PROTOCOL:
	    fprintf(stderr, "\tthere is a protocol error communicating with the broker (%d).\n", rc);
	    break;
	case MOSQ_ERR_PAYLOAD_SIZE:
	    fprintf(stderr, "\tpayloadlen is too large (%d).\n", rc);
	    break;
	case MOSQ_ERR_MALFORMED_UTF8:
	    fprintf(stderr, "\tthe topic is not valid UTF-8 (%d).\n", rc);
	    break;
	case MOSQ_ERR_QOS_NOT_SUPPORTED:
	    fprintf(stderr, "\tthe QoS is greater than that supported by the broker (%d).\n", rc);
	    break;
	case MOSQ_ERR_OVERSIZE_PACKET:
	    fprintf(stderr, "\tthe resulting packet would be larger than supported by the broker (%d).\n", rc);
	    break;
	case MOSQ_ERR_ERRNO:
	    fprintf(stderr, "\t%s rc(%d) errno(%d)\n", strerror(errno), rc, errno);
	    break;
	default:
	    fprintf(stderr, "\tunknown return code %d.\n", rc);
	}
    }
    return rc;
}

void
mqtt_poll()
{
    int	timeout = 10;  /* timeout in millisecond */
    int rc;
    rc = mosquitto_loop(mosq_hndl, timeout, 1);
    if (rc != MOSQ_ERR_SUCCESS) {
	fprintf(stderr, "%s error %d\n", __func__, rc);
    }
}

int
mqtt_shutdown()
{
    if (mosq_init) {
	mosquitto_destroy(mosq_hndl);
	mosquitto_lib_cleanup();
	mosq_init = 0;
    }
    return 0;
}
