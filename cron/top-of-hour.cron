#Add all lines below to crontab. 
#Below added for SR 487902 

#Run top 5 minutes before and after the top of every hour. Each top spawn runs for 60 seconds (run 10 times with 6 second delay).
#Configure top in interactive mode to log all cores: https://unix.stackexchange.com/a/256385
#start top
#enable the options you want (press 1)
#hit W (that is, shift+w)  
55-59,0-5 * * * *  date >> /var/log/top-hourly.txt; /bin/top -b -n 10 -d 6 | grep "load average" -A 50 >> /var/log/top-hourly.txt 

#Two minutes before the top of the hour, enable sod debug
58 * * * *  tmsh modify sys db failover.debugsteadystate value enable

#Two minutes after the top of the hour, disable sod debug
2 * * * *  tmsh modify sys db failover.debugsteadystate value disable

#Run tmctl 5 minutes before and after the top of every hour.Each tmctl spawn runs for 60 seconds (run 10 times with 6 second delay).
55-59,0-5 * * * * for i in {1..10}; do date >> /var/log/tmctl.txt; /bin/tmctl -d blade -i tmm/clock_advance  >> /var/log/tmctl.txt ;sleep 6 ;done

#Run ifconfig 5 minutes before and after the top of every hour.Each ifconfig spawn runs for 60 seconds (run 10 times with 6 second delay).
55-59,0-5 * * * * for i in {1..10}; do date >> /var/log/ifconfig.txt; /sbin/ifconfig -a  >> /var/log/ifconfig.txt ;sleep 6 ;done

#Run iostat 5 minutes before and after the top of every hour.Each iostat spawn runs for 60 seconds (run 10 times with 6 second delay).
55-59,0-5 * * * * for i in {1..10}; do date >> /var/log/iostat.txt; /bin/iostat -x  >> /var/log/iostat.txt ;sleep 6 ;done

#log cleanup
#at 23:30 every other day (odd days only - 48 hours between runs) delete the previous log and copy current log
30 23 1-31/2 * * cp /var/log/top-hourly.txt /var/log/top-hourly.txt.1 
30 23 1-31/2 * * cp /var/log/tmctl.txt /var/log/tmctl.txt.1 
30 23 1-31/2 * * cp /var/log/ifconfig.txt /var/log/ifconfig.txt.1 
30 23 1-31/2 * * cp /var/log/sodlog /var/log/sodlog.1 
30 23 1-31/2 * * cp /var/log/iostat.txt /var/log/iostat.txt.1
#End of lines for SR 487902  
