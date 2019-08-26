#!/bin/bash
#Use Linux DNS lookup to update the AD Servers list using DNS SRV Records. 

###Variables###
domain=example.com #Specify your AD domain here
ntlmprofilename=default #Specify NTLM auth profile here
querycheck=example.com #String that should always appear in successful SRV query (Example domain name etc)
configsync=no #yes/no to perform a configuration sync after updating FQDN list
devicegroup=default #Name of the device group for configsync
###Variables###

#Check if device is active or standby
if [[ $(/bin/tmsh show cm failover-status) =~ "ACTIVE" ]]; then
    #echo device is active
    #Perorm DNS lookup for DCs by using the SRV record 
    queryresult=$(/bin/host -t SRV _ldap._tcp.dc._msdcs.$domain | /bin/awk '{ print $8 }' | /bin/sed 's/\.$//g' | /bin/tr '\n' ' ')
    #Check if query lookup was successful
    if [[ $queryresult =~ "$querycheck" ]]; then
        #echo query was successful!
        #Updating NTLM authentication with FQDN list
        #echo "running command /bin/tmsh modify apm ntlm ntlm-auth $ntlmprofilename dc-fqdn-list replace-all-with { $queryresult}"
        /bin/tmsh modify apm ntlm ntlm-auth $ntlmprofilename dc-fqdn-list replace-all-with { $queryresult}
        /bin/tmsh save sys config
        if [ $configsync == "yes" ]; then
            echo syncing configuration
            /bin/tmsh run cm config-sync to-group $devicegroup
        fi
    else
        #echo SRV query was unsuccessful
    fi
else
    #echo device is not active 
fi