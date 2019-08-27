#!/bin/bash
#Use Linux DNS lookup to update the AD Servers list using DNS SRV Records.
#Recommended crontab: * * * * * /root/SSLO_AD_with_SRV2.sh >> /var/log/SSLO_AD_with_SRV.log 2>&1

###Global Variables###
numberofdomains=5 #Number of different AD domains to check. If more than 5 add more domain<x> variables. 
configsync=no #yes/no to perform a configuration sync after updating FQDN list
devicegroup=default #Name of the device group for configsync

###Per domain Variables###
#syntax is <domain name>,<ntlm auth profile>,<SRV query health check string (domain name etc..)>
domain1=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local #domain 1
domain2=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local #domain 2
domain3=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local #domain 3
domain4=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local #domain 4
domain5=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local #domain 5
### end variables ### 

#Check if device is active or standby
if [[ $(/bin/tmsh show cm failover-status) =~ "ACTIVE" ]]; then
    echo device is active at $(/bin/date)
    for i in {1..5} #Start for loop to update SRV record per domain
    do
    var="domain$i"
    perdomain=$(echo ${!var} | awk -F',' '{print $1}')
    ntlmprofilename=$(echo ${!var} | awk -F',' '{print $2}')
    querycheck=$(echo ${!var} | awk -F',' '{print $3}')
    #Perorm DNS lookup for DCs by using the SRV record 
    queryresult=$(/bin/host -t SRV _ldap._tcp.dc._msdcs.$perdomain | /bin/awk '{ print $8 }' | /bin/sed 's/\.$//g' | /bin/tr '\n' ' ')
    #Check if query lookup was successful
    if [[ $queryresult =~ "$querycheck" ]]; then
        echo query for domain $perdomain was successful. Got: $queryresult
        #Updating NTLM authentication with FQDN list
        echo "running command for domain $perdomain /bin/tmsh modify apm ntlm ntlm-auth $ntlmprofilename dc-fqdn-list replace-all-with { $queryresult}"
        updatedSRV=yes
        /bin/tmsh modify apm ntlm ntlm-auth $ntlmprofilename dc-fqdn-list replace-all-with { $queryresult}
    else
        echo SRV query was unsuccessful for domain $perdomain
    fi
    done
    if [ $updatedSRV == "yes" ]; then
        echo saving configuration
        /bin/tmsh save sys config
        if [ $configsync == "yes" ]; then
            echo syncing configuration
            /bin/tmsh run cm config-sync to-group $devicegroup
        fi
    fi
else
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