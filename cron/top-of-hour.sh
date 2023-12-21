### Add all lines below to crontab for SR 487902 
## Version 12/21/2023  ## Latest Version Here https://github.com/megamattzilla/iRules/blob/master/cron

#Two minutes before the top of the hour, enable sod debug
58 * * * *  /usr/bin/tmsh modify sys db failover.debugsteadystate value enable
#Two minutes after the top of the hour, disable sod debug
2 * * * *  /usr/bin/tmsh modify sys db failover.debugsteadystate value disable
#5 minutes before top of every hour start tight loop that logs ~1/sec for ~10min.
55 * * * * /bin/bash -c "for i in {1..500}; do top bn1  |  awk '{ print strftime()\", \" \$0}' >> /shared/tmp/cpu_logger-top.out ; sleep 1; done"
55 * * * * /bin/bash -c "for i in {1..500}; do tmctl -w999 -c host_info_stat |  awk '{ print strftime()\", \" \$0}' >> /shared/tmp/cpu_logger-host_info_stat.out; sleep 1; done"
55 * * * * /bin/bash -c "for i in {1..500}; do iostat |  awk '{ print strftime()\", \" \$0}' >> /shared/tmp/cpu_logger-iostat.out; sleep 1; done"
#log cleanup
#at 23:30 every other day (odd days only - 48 hours between runs) delete the previous log and copy current log
30 23 1-31/2 * * mv -f /shared/tmp/cpu_logger-top.out /shared/tmp/cpu_logger-top.out.1
30 23 1-31/2 * * mv -f /shared/tmp/cpu_logger-host_info_stat.out /shared/tmp/cpu_logger-host_info_stat.out.1
30 23 1-31/2 * * mv -f /shared/tmp/cpu_logger-iostat.out /shared/tmp/cpu_logger-iostat.out.1


### End of lines for SR 487902 Crontab 
