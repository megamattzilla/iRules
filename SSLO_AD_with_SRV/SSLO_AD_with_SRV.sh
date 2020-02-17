#!/bin/bash
#Use Linux DNS lookup to update the AD Servers list using DNS SRV Records.
#Recommended crontab(midnight): 0 0 * * * /root/SSLO_AD_with_SRV.sh >> /var/log/SSLO_AD_with_SRV.log 2>&1

###Global Variables###
configsync=no #yes/no to perform a configuration sync after updating FQDN list
devicegroup=default #Name of the device group for configsync
currentquery=/var/log/SSLO_AD_with_SRV_current_query.log
lastquery=/var/log/SSLO_AD_with_SRV_last_query.log

###Per domain Variables###
#syntax is <domain name>,<ntlm auth profile>,<SRV query health check string (domain name etc..)>
domain1=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local #domain 1
#domain2=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local #domain 2
#domain3=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local #domain 3
#domain4=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local #domain 4
#domain5=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local #domain 5
### end variables ###
echo start
#Check if device is active or standby
if [[ $(/bin/tmsh show cm failover-status) =~ "ACTIVE" ]]; then
    echo device is active at $(/bin/date)
    #Update line below {1..x} for your number of domains. Example for 5 domains {1..5}
    for i in {1..1} #Start for loop to update SRV record per domain
    do
    var="domain$i"
    perdomain=$(echo ${!var} | awk -F',' '{print $1}')
    ntlmprofilename=$(echo ${!var} | awk -F',' '{print $2}')
    querycheck=$(echo ${!var} | awk -F',' '{print $3}')
    #Perorm DNS lookup for DCs by using the SRV record
    queryresult=$(/bin/host -t SRV _ldap._tcp.dc._msdcs.$perdomain | /bin/awk '{ print $8 }' | /bin/sort -r -n | /bin/sed 's/\.$//g' | /bin/tr '\n' ' ')
    #Check if query lookup was successful. result much contain the querycheck value and a period. 
    if [[ $queryresult =~ "$querycheck" ]] && [[ $queryresult == *"."* ]]; then
        echo query for domain $perdomain was successful. Got: $queryresult
        #Saving query result as current query
        echo $queryresult > $currentquery
        #Check if lastquery history file exists. If not, create one. This is important for first execution. 
        if /bin/test -f "$lastquery"; then
            echo "$lastquery history file exist"
            else
            echo "No query history found. Recreating history file." 
            echo $queryresult > $lastquery
        fi
        #compare current SRV DNS query versus the last successful query. If its the same, do nothing. If its different, update NTLM with new SRV
        if /bin/cmp -s "$currentquery" "$lastquery"; then
            /bin/printf 'The file "%s" is the same as "%s"\n' "$currentquery" "$lastquery"
            updatedSRV=no
            else   
            /bin/printf 'The file "%s" is different from "%s"\n' "$currentquery" "$lastquery"
            #Updating NTLM authentication with FQDN list
            echo "running command for domain $perdomain /bin/tmsh modify apm ntlm ntlm-auth $ntlmprofilename dc-fqdn-list replace-all-with { $queryresult}"
            updatedSRV=yes
            /bin/tmsh modify apm ntlm ntlm-auth $ntlmprofilename dc-fqdn-list replace-all-with { $queryresult}
            #Save successful query as lastquery history file  
            echo $queryresult > /var/log/SSLO_AD_with_SRV_last_query.log
        fi
    else
        #SRV DNS health check failed- do nothing. 
        echo SRV query was unsuccessful for domain $perdomain
        updatedSRV=no
    fi
    done
    #If NTLM was updated with new SRV, save the tmsh configuration. 
    if [ $updatedSRV == "yes" ]; then
        echo saving configuration
        /bin/tmsh save sys config
        #If we saved config and if configsync is set to yes, sync the configuration with the standby node. 
        if [ $configsync == "yes" ]; then
            echo syncing configuration
            /bin/tmsh run cm config-sync to-group $devicegroup
        fi
    fi
else
    #If device is not active, do nothing. 
    echo device is not active
fi

#Check log file and cleanup after 5MB
filename=/var/log/SSLO_AD_with_SRV.log
maxsize=5242880
filesize=$(stat -c%s "$filename")
#echo "Size of $filename = $filesize bytes."
if (( filesize > maxsize )); then
    echo "Clearing log file at $(/bin/date)" > $filename
fi
echo end