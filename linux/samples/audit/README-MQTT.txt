1) ./test/
	auditd daemon plugin code that sends logs to the MQTT broker.
2) ./test/docker/
	Dockerfile for auditd and plugin code.
3) ./test/hijack/
	watch_mqtt.so is a protocol watcher.
4) ./test/mosquitto
   	test environment for mosquitto bug.
	TCP port 1983 is used.
	$ make for run mosquitto
5) ./test/mosquitto/client
	client program to send packets manually.
	


