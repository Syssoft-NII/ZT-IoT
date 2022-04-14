#
#
#  docker run -itd --name mytest -v /mnt2:/remote mydocker

docker:
	docker build -t audit_mqtt .
dist:
	docker save audit_mqtt -o audit_mqtt.tar
	chmod a+r audit_mqtt.tar
