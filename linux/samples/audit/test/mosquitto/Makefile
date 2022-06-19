run:
#	export LD_LIBRARY_PATH=.:; export LD_PRELOAD=testlib.so;
	export LD_LIBRARY_PATH=.:; export LD_PRELOAD=watch_mqtt.so; \
	./mosquitto-v2.0.0 -c mosquitto.conf
run-measure:
	../../mosquitto/src/mosquitto -c mosquitto-1883.conf
