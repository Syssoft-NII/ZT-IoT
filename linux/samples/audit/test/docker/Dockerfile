FROM ubuntu:latest
RUN mkdir /remote; \
    apt update && apt-get install -yq auditd audispd-plugins locales; \
    apt install tzdata -y; \
    ln -s /usr/share/zoneinfo/Asia/Tokyousr/share/zoneinfo/Asia/Tokyo /etc/localtime; \
    sed -i 's/^# *\(en_US.UTF-8\)/\1/' /etc/locale.gen; \
    sed -i 's/^# *\(ja_JP.UTF-8\)/\1/' /etc/locale.gen; \
    locale-gen; \
    apt install -q vim iputils-ping net-tools; \
    mkdir -p /usr/local/etc/audit
#
#
ADD audit.tar.gz /
COPY audit/ /usr/local/etc/audit
ENV TZ='Asia/Tokyo'
ENV LD_LIBRARY_PATH=:/usr/local/lib
RUN ldconfig
CMD ["/usr/bin/bash"]

############################################################################
#
#docker run -itd --privileged --cap-add=ALL --pid=host --name mytest -v /mnt2:/remote mydocker
# docker exec -it mytest bash
# auditd -f -n -s enable -c /usr/local/etc/audit
# auditctl -a always,exit -F arch=b64 -S execve,clone
#
#----------------------------------------------------
# docker rmi <IMAGEID>
#
# auditd -f -n -s enable
# auditctl -a always,exit -F arch=b64 -S execve,clone,openat
# auditctl -a always,exit -F arch=b64 -S execve,clone
# /etc/audit/auditd.conf
#	local_events = yes  
# /etc/audisp/plugins.d/syslog.conf
