						By yutaka_ishikawa@nii.ac.jp
						2020/06/09

The current codes are very nasty as a result of trial-and-error. Needs to clean up all codes.

######################################
HOW TO SET UP nohltz
######################################
..... skip ....

######################################
HOW TO SET UP CPU FREQ
######################################
1) Set up CPU governer
   Assuming CPU 4 and 5 are used for evaluation
  # echo userspace > /sys/devices/system/cpu/cpu4/cpufreq/scaling_governor
  # echo userspace > /sys/devices/system/cpu/cpu5/cpufreq/scaling_governor
  Note that available governors are shown reading the following file:
     /sys/devices/system/cpu/cpu5/cpufreq/scaling_available_governors
2) Check them
  # cat /sys/devices/system/cpu/cpu4/cpufreq/scaling_governor
  # cat /sys/devices/system/cpu/cpu5/cpufreq/scaling_governor
3) Check availability of operation frequencies and set it up
  # cat /sys/devices/system/cpu/cpu4/cpufreq/scaling_available_frequencies
  # cat /sys/devices/system/cpu/cpu5/cpufreq/scaling_available_frequencies
4) Select the higest frequency and set it
  # echo 1800000 >/sys/devices/system/cpu/cpu4/cpufreq/scaling_setspeed
  # echo 1800000 >/sys/devices/system/cpu/cpu5/cpufreq/scaling_setspeed
5) Check them
  # cat /sys/devices/system/cpu/cpu4/cpufreq/scaling_cur_freq
  # cat /sys/devices/system/cpu/cpu5/cpufreq/scaling_cur_freq

######################################
HOW TO BUILD 
######################################
1) Please read the ../README.txt and
  (1.1) installing libaudit
  (1.2) installing mosquitto
2) Make sure if the installed audit library will be dynamically linked.
  $ sudo bash
  # which auditctl
  It is OK, if the /usr/loca/sabin/auditctl is found.
  Otherwise set up the following shell variables:
  # export LD_LIBRARY_PATH=:/usr/local/lib
  # export PATH=:/usr/local/bin:$PATH


######################################
HOW TO MEASURE ADUIT COSTS
######################################
1) Measure basic system calls using audit library, not via audit daemon.
   $ make run-audit-test3
     result files are located under the /tmp/ in default.
     You may change the prefix of generated files. See the program.
2) Measure basic system calls using audid plugin process.
 3.1) copy auditd.conf to /usr/local/etc/audit/
   # cp auditd.conf /usr/local/etc/audit/
 3.2) copy test.conf to /usr/local/etc/audit/plugins.d/
   # cp auditd.conf /usr/local/etc/audit/plugins.d/
3) 
   
######################################
./plot.sh results/auditlib-no/audit-test3_2022:06:09:10:56_i10000_n0_tim
./plot.sh results/auditlib-same/audit-test3_2022:06:09:10:56_i10000_n0_tim
./plot.sh results/plugin-same/auplugin_2022:06:10:03:47_i10000_n0_tim

