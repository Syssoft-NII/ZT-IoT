#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mosquitto.h>

void
on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    printf("%s ", message->topic);
    if (message->payloadlen > 0) {
        fwrite(message->payload, 1, message->payloadlen, stdout);
        printf("\n");
    } else {
        printf("%s (null)\n", message->topic);
    }
    fflush(stdout);
}

int
main(int argc, char **argv)
{
    struct mosquitto *mosq;
    char	*host = "localhost";
    char	*topic;
    int	keepalive = 60;
    int	port = 1883;
    int ret;

    if (argc != 2) {
	fprintf(stderr, "%s <topic>\n", argv[0]);
	return -1;
    }
    topic = argv[1];
    mosquitto_lib_init();
    mosq = mosquitto_new(NULL, true, NULL);
    if(!mosq) {
        fprintf(stderr, "Cannot create mosquitto object\n");
        mosquitto_lib_cleanup();
        return -1;
    }
    mosquitto_message_callback_set(mosq, on_message);
    if(mosquitto_connect(mosq, host, port, keepalive)) {
        fprintf(stderr, "failed to connect broker.\n");
        mosquitto_lib_cleanup();
        return -1;
    }
    mosquitto_subscribe(mosq, NULL, topic, 0);
    ret = mosquitto_loop_forever(mosq, -1, 1);
    if (ret != MOSQ_ERR_SUCCESS) {
	fprintf(stderr, "mosquitto_loo_forever error %d\n", ret);
    }
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    return 0;
}
