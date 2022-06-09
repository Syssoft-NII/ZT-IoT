						By yutaka_ishikawa@nii.ac.jp
						2020/06/09

The current codes are very nasty as a result of trial-and-error. Needs to clean up all codes.

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
HOW TO MEASURE ADUIT COSTS
######################################
1) make
2) Measure basic system calls using audit library, not via audit daemon.
   $ make run-audit-test3
     result files are located under the /tmp/ in default.
     You may change the prefix of generated files. See the program.
   
