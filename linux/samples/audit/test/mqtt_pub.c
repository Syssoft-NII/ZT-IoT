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
    char	*topic, *msg;
    int	keepalive = 60;
    int	port = 1883;
    int ret;

    if (argc != 3) {
	fprintf(stderr, "%s <topic> <message>\n", argv[0]);
	return -1;
    }
    topic = argv[1];
    msg = argv[2];
    mosquitto_lib_init();
    mosq = mosquitto_new(NULL, true, NULL);
    if(!mosq) {
        fprintf(stderr, "Cannot create mosquitto object\n");
        mosquitto_lib_cleanup();
        return -1;
    }
    if(mosquitto_connect(mosq, host, port, keepalive)) {
        fprintf(stderr, "failed to connect broker.\n");
        mosquitto_lib_cleanup();
        return -1;
    }
    mosquitto_publish(mosq, NULL, topic, strlen(msg), msg, 0, false);
    
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    return 0;
}
