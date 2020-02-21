#!/bin/bash
#Use Linux DNS lookup to update the AD Servers list using DNS SRV Records.
#Recommended icall or crontab(midnight): 0 0 * * * /root/SSLO_AD_with_SRV.sh >> /var/log/SSLO_AD_with_SRV.log 2>&1

###Global Variables###
configsync=no #yes/no to perform a configuration sync after updating FQDN list
devicegroup=default #Name of the device group for configsync
updatentlm=yes #should NTLM auth profile be updated? (yes/no)
updateldap=yes #should LDAP AAA profile be updated? (yes/no)
ntlmsrvprefix=_ldap._tcp.dc._msdcs #SRV record query for NTLM
ldapsrvprefix=_ldap._tcp.gc._msdcs #SRV record query for LDAP
currentntlmquery=/var/log/SSLO_AD_with_SRV_current_ntlmquery.log #history file for NTLM
lastntlmquery=/var/log/SSLO_AD_with_SRV_last_ntlmquery.log #history file for NTLM
currentldapquery=/var/log/SSLO_AD_with_SRV_current_ldapquery.log #history file for LDAP
lastldapquery=/var/log/SSLO_AD_with_SRV_last_ldapquery.log #history file for LDAP
filename=/var/log/SSLO_AD_with_SRV.log #log file for this script. 

###Per domain Variables###
#syntax is <domain name>,<ntlm auth profile>,<NTLM SRV query health check string (domain name etc..)>, <LDAP LTM Pool name>, <LDAP LTM pool port>,  <LDAP domain FQDN>, <LDAP SRV query health check string (domain name etc..)>
domain1=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local,change-to-fqdn,389,f5kc.lab.local,f5kc.lab.local #domain 1
domain2=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local,change-to-fqdn,389,f5kc.lab.local,f5kc.lab.local #domain 2
domain3=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local,change-to-fqdn,389,f5kc.lab.local,f5kc.lab.local #domain 3
domain4=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local,change-to-fqdn,389,f5kc.lab.local,f5kc.lab.local #domain 4
domain5=f5kc.lab.local,f5kclab_ntlm,f5kc.lab.local,change-to-fqdn,389,f5kc.lab.local,f5kc.lab.local #domain 5
### end variables ###
echo start
updatedSRV=no #setting variable we check later if something was modified to default (no). 
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
    if [ $updatentlm == "yes" ]; then
        #Perorm DNS lookup for DCs by using the SRV record for NTLM
        ntlmqueryresult=$(/bin/host -t SRV $ntlmsrvprefix.$perdomain | /bin/awk '{ print $8 }' | /bin/sort -r -n | /bin/sed 's/\.$//g' | /bin/tr '\n' ' ')
        #Check if NTLM query lookup was successful. result much contain the querycheck value and a period. 
        if [[ $ntlmqueryresult =~ "$querycheck" ]] && [[ $ntlmqueryresult == *"."* ]]; then
            echo NTLM query for domain $perdomain was successful. Got: $ntlmqueryresult
            #Saving query result as current query
            echo $ntlmqueryresult > $currentntlmquery
            #Check if lastntlmquery history file exists. If not, create one. This is important for first execution. 
            if /bin/test -f "$lastntlmquery"; then
                echo "$lastntlmquery history file exist"
                else
                echo "No query history found. Recreating NTLM history file." 
                echo first-time-init > $lastntlmquery
            fi
            #compare current SRV DNS query versus the last successful query. If its the same, do nothing. If its different, update NTLM with new SRV
            if /bin/cmp -s "$currentntlmquery" "$lastntlmquery"; then
                echo "No NTLM changes detected"
                else   
                echo "NTLM changes detected- updating NTLM APM AAA object"
                #Updating NTLM authentication with FQDN list
                echo "running command for domain $perdomain /bin/tmsh modify apm ntlm ntlm-auth $ntlmprofilename dc-fqdn-list replace-all-with { $ntlmqueryresult}"
                updatedSRV=yes
                /bin/tmsh modify apm ntlm ntlm-auth $ntlmprofilename dc-fqdn-list replace-all-with { $ntlmqueryresult}
                #Save successful query as lastntlmquery history file  
                echo $ntlmqueryresult > $lastntlmquery
            fi
        else
            #SRV DNS health check failed- do nothing. 
            echo NTLM SRV query was unsuccessful for domain $perdomain
        fi
    fi
    if [ $updateldap == "yes" ]; then
        ltmpool=$(echo ${!var} | awk -F',' '{print $4}')
        ltmport=$(echo ${!var} | awk -F',' '{print $5}')
        perdomain=$(echo ${!var} | awk -F',' '{print $6}')
        querycheck=$(echo ${!var} | awk -F',' '{print $7}')
        #Perorm DNS lookup for DCs by using the SRV record for LDAP
        ldapqueryresult=$(/bin/host -t SRV $ldapsrvprefix.$perdomain | /bin/awk '{ print $8 }' | /bin/sort -r -n | /bin/sed 's/\.$//g' | /bin/tr '\n' ' ') #SRV record query  
        if [[ $ldapqueryresult =~ "$querycheck" ]] && [[ $ldapqueryresult == *"."* ]]; then
            dnsnames=($ldapqueryresult) #create an array of DNS names from the DC query 
            IParray=($(for a in "${dnsnames[@]}"; do /bin/dig +short "$a"; done)) #take the array of DNS names and resolve them to a respective array of IP addresses 
            poolarray=($(/bin/printf "%s:$ltmport\n" "${IParray[@]}")) #Take the array of IP addresses and append port needed for the ltmpool
            echo "LDAP query for domain $perdomain was successful. Got DCs: $ldapqueryresult which resolved to respective IPs: ${IParray[*]}"
            #Saving query result as current query
            echo ${IParray[*]} > $currentldapquery
            #Check if lastldapquery history file exists. If not, create one. This is important for first execution. 
            if /bin/test -f "$lastldapquery"; then
                echo "$lastldapquery history file exist"
                else
                echo "No query history found. Recreating LDAP history file." 
                echo first-time-init > $lastldapquery
            fi
            #compare current LDAP DNS query versus the last successful query. If its the same, do nothing. If its different, update LDAP with new SRV
            if /bin/cmp -s "$currentldapquery" "$lastldapquery"; then
                echo "No LDAP changes detected"
                else   
                echo "LDAP changes detected- updating LDAP APM AAA object"
                updatedSRV=yes
                echo "running command for domain $perdomain /bin/tmsh modify ltm pool $ltmpool members replace-all-with { ${poolarray[*]} }"
                /bin/tmsh modify ltm pool change-to-fqdn members replace-all-with { ${poolarray[*]} }
                #Save successful query as lastldapquery history file  
                echo ${IParray[*]} > $lastldapquery
            fi
        else
            #SRV DNS health check failed- do nothing. 
            echo LDAP SRV query was unsuccessful for domain $perdomain
        fi
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
maxsize=5242880
filesize=$(stat -c%s "$filename")
#echo "Size of $filename = $filesize bytes."
if (( filesize > maxsize )); then
    echo "Clearing log file at $(/bin/date)" > $filename
fi
echo end