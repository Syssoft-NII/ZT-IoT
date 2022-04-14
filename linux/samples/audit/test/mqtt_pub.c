#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mosquitto.h>

int
main(int argc, char **argv)
{
    struct mosquitto *mosq;
    char	*host = "localhost";
    char	*topic, *msg;
    int	keepalive = 60;
    int	port = 1883;
    int ret;

    if (argc == 4) {
	host = argv[1];
	topic = argv[2]; msg = argv[3];
    } else if (argc == 3) {
	topic = argv[1]; msg = argv[2];
    } else {
	fprintf(stderr, "%s <topic> <message>\n", argv[0]);
	fprintf(stderr, "   | <host> <topic> <message>\n");
	return -1;
    }
    mosquitto_lib_init();
    mosq = mosquitto_new(NULL, true, NULL);
    if(!mosq) {
        fprintf(stderr, "Error mosquitto_new()\n");
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
