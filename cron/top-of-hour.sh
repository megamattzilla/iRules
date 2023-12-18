### Add all lines below to crontab for SR 487902 

## Two minutes before the top of the hour, enable sod debug

58 * * * *  tmsh modify sys db failover.debugsteadystate value enable

## Two minutes after the top of the hour, disable sod debug

2 * * * *  tmsh modify sys db failover.debugsteadystate value disable


## Per Proccess CPU ## 5 minutes before top of every hour start tight loop that logs ~1/sec for ~10min.

55 * * * * /bin/bash -c "for i in {1..500}; do tmctl -w999 -c proc_pid_stat  |  awk '{ print strftime()\", \" \$0}' >> /shared/tmp/cpu_logger-proc_pid_stat.out ; sleep 1; done"

## Memory and Disk Stats ## 5 minutes before top of every hour start tight loop that logs ~1/sec for ~10min.

55 * * * * /bin/bash -c "for i in {1..500}; do tmctl -w999 -c host_info_stat |  awk '{ print strftime()\", \" \$0}' >> /shared/tmp/cpu_logger-host_info_stat.out; sleep 1; done"

## I/O Stats ## 5 minutes before top of every hour start tight loop that logs ~1/sec for ~10min.

55 * * * * /bin/bash -c "for i in {1..500}; do iostat |  awk '{ print strftime()\", \" \$0}' >> /shared/tmp/cpu_logger-iostat.out; sleep 1; done"


## Log Cleanup ## At 23:30 every other day (odd days only - 48 hours between runs) delete the previous log and copy current log

30 23 1-31/2 * * cp /shared/tmp/cpu_logger-proc_pid_stat.out /shared/tmp/cpu_logger-proc_pid_stat.out.1
30 23 1-31/2 * * cp /shared/tmp/cpu_logger-host_info_stat.out /shared/tmp/cpu_logger-host_info_stat.out.1
30 23 1-31/2 * * cp /shared/tmp/cpu_logger-iostat.out /shared/tmp/cpu_logger-iostat.out.1

### End of lines for SR 487902 Crontab 
