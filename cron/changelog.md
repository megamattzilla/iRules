# Updates 


## 12/21/2023 
* Added absolute path to commands 
* Removed `tmctl -w999 -c proc_pid_stat` command and replaced with `top bn1`
* Removed `cp` command for log rotation and replaced with `mv -f`


## 12/18/2023 
* Added `tmctl -w999 -c host_info_stat` 
* Modified `for` loop to be one 10 minute loop versus ten 1 minute loops
* Modified log file to be in /shared/tmp. There is more disk space there just incase. 
* Removed `top` command and replaced with `tmctl -w999 -c proc_pid_stat`
* Removed `tmctl -d blade -i tmm/clock_advance`
* Removed `/sbin/ifconfig -a`
  
