when RULE_INIT priority 200 {
###v1.4###
###See https://github.com/megamattzilla/iRules/tree/master/SSLO_Multiple_Auth
###User-Edit Variables start###

#Specify name for Captive Portal SSLO topology
set static::prod_portal_sslo "sslo_prod_portal.app/sslo_prod_portal-xp-4"
#Specify name for Kerberos SSLO topology
set static::prod_kerberos_sslo "sslo_prod_kerb.app/sslo_prod_kerb-xp-4"
#Specify name for no-auth SSLO topology
set static::prod_noauth_sslo "sslo_prod_noauth.app/sslo_prod_noauth-xp-4"
#Specify authentication preference idle timeout 
set static::prod_idle_sec_timeout "300" 
#Specify number of requests to allow while trying 407 kerberos auth. This will catch clients that do not support proxy auth and do not respond to the 407s.  
set static::prod_num_407_attempts "10" 
#Specify number of requests to allow before client redirects to captive portal. This will catch clients that do not respond to the 302 redirects. Once a client redirects to the captive portal we stop counting and assume they can handle it. 
set static::prod_num_302_attempts "50" 
#Specify datagroup to use for client IP authentication bypass
set static::noauth_datagroup_ip "bypass_auth_ips"
#Specify datagroup to use for HTTP host exact match authentication bypass
set static::noauth_datagroup_host_exact "auth_bypass_hostname_exact" ; #exact match data group
#Specify datagroup to use for HTTP wildacard match authentication bypass
set static::noauth_datagroup_host_wildcard "auth_bypass_hostname_wildcard" ; #ends_with data group

#Specify if debug logging should be enabled. 1 = enabled, 0 = disabled.    
set static::debuglog "1"

###User-Edit Variables end###
}

when HTTP_REQUEST priority 200 {

#Debug Logging for troubleshooting.Should be typically disabled. 
if { $static::debuglog } { log local0. "DEBUG: CPU [TMM::cmp_unit] VS [virtual] 5tuple [client_addr]:[client_port] -> [IP::local_addr]:[TCP::local_port] proto [IP::protocol] for [HTTP::host][HTTP::uri] SID [ACCESS::session sid] Access profile [ACCESS::session data get "session.access.profile"] user [ACCESS::session data get "session.logon.last.username"] accesssid [table lookup -subtable [IP::client_addr] accesssid] kerbaccesssid [table lookup -subtable [IP::client_addr] kerbaccesssid] attempt# [table lookup -subtable [IP::client_addr] attempt] captiveattempt [ table lookup -subtable [IP::client_addr] captiveattempt]" 
 }


#set variable called authlookup with the current authstatus of this session 
set authlookup [table lookup -subtable [IP::client_addr] authstatus]
if { $static::debuglog } { log local0. "client IP [IP::client_addr] auth status is $authlookup for URI [HTTP::uri]" } 
#Definition of all authstatus
#1 = trying Kerberos auth
#2 = known kerberos client
#3 = trying captive portal auth 
#4 = known captive portal client
#5 = whitelist to no auth

##Optional Debug mode to clear table entries##
switch [HTTP::uri]  {
  "http://neverssl.com/debug" {
  table delete -subtable "[IP::client_addr]" authstatus
  HTTP::respond 302 Location "http://neverssl.com" cache-control "no-store"
  if { $static::debuglog } { log local0. "Purged table entries for [IP::client_addr] and redirected to new page" }
  return
  }
}

#Whitelist. Comment out if not needed. 
#Check source IP against the IP auth bypass list. If we find a match, send to noauth VS and exit.  
if { [class match [IP::client_addr] equals "$static::noauth_datagroup_ip" ] } {
    table set -subtable "[IP::client_addr]" authstatus 5 $static::prod_idle_sec_timeout
    virtual $static::prod_noauth_sslo
    if { $static::debuglog } { log local0. "##Whitelist Match## ConnFlow ([IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port]) HTTP [HTTP::host] [HTTP::uri] matched IP auth bypass and sent to VS noauth." } 
    return
}
#Check HTTP host against the exact match auth bypass list. If we find a match, send to noauth VS and add to known user table as noauth.  
if { [class match  [lindex [split [HTTP::host] ":" ] 0 ] equals $static::noauth_datagroup_host_exact ] } {
    log local0. "##Whitelist Match## ConnFlow ([IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port]) HTTP [HTTP::host] [HTTP::uri] matched exact match data group"
    virtual $static::prod_noauth_sslo
    return
}
#Check HTTP host against the wildcard match auth bypass list. If we find a match, send to noauth VS and exit. 
if { [class match  [lindex [split [HTTP::host] ":" ] 0 ] ends_with $static::noauth_datagroup_host_wildcard ] } {
    log local0. "##Whitelist Match## ConnFlow ([IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port]) HTTP [HTTP::host] [HTTP::uri] matched wildcard data group"
    virtual $static::prod_noauth_sslo
    return
}

#known user lookup. After successful Kerberos or captive portal sessions most HTTP requests will be handled here. 
switch $authlookup  {
    "2" {
    #Found known kerberos client. direct request to SSLO Kerberos/Basic virtual server name and exit iRule. 
    virtual $static::prod_kerberos_sslo
    if { $static::debuglog } { log local0. "##known client match## IP [IP::client_addr] sent to VS kerberos" }
	return
  }
  "4" {
    #Found known captive portal client. direct request to SSLO Captive Portal virtual server and exit iRule. 
    virtual $static::prod_portal_sslo
    if { $static::debuglog } { log local0. "##known client match## IP [IP::client_addr] sent to VS captive portal" }
	return
  }
  "5" {
    #Found known no-auth client. direct request to SSLO no-auth virtual server and exit iRule. 
	virtual $static::prod_noauth_sslo
    if { $static::debuglog } { log local0. "##known client match## IP [IP::client_addr] sent to VS fallback noauth" }
	return
  } 
}

#Initalize table entries for new sessions. This must be done to set the proper idle timeout when the counters are incremented later. 
if { !([string length [table lookup -subtable [IP::client_addr] authstatus]] > 0) } {
table set -subtable [IP::client_addr] accesssid 0 $static::prod_idle_sec_timeout
table set -subtable [IP::client_addr] kerbaccesssid 0 $static::prod_idle_sec_timeout
table set -subtable [IP::client_addr] attempt 0 $static::prod_idle_sec_timeout
table set -subtable [IP::client_addr] captiveattempt 0 $static::prod_idle_sec_timeout
if { $static::debuglog } { log local0. "Initalizing counters for [IP::client_addr]" }
}


#Check if we are trying captive portal auth for a client. 
if { $authlookup == 3 } {
    #Confirmed we are captive portal auth. Check if captive portal access has been completed and we know the captive portal access session SID
    if { [string length [table lookup -subtable [IP::client_addr] accesssid]] > 1 } {
        #Captive portal access session completed.This is a success criteria, as of this version it doesnt matter if captive portal failed to find user and failed open.  
        if { $static::debuglog } { log local0. "##Captive portal Passed## client IP [IP::client_addr] session [table lookup -subtable [IP::client_addr] accesssid]" }
        table set -subtable "[IP::client_addr]" authstatus 4 $static::prod_idle_sec_timeout
        virtual $static::prod_portal_sslo
        return
    #Trying Captive portal auth but captive portal access session has not been completed. Check if number of 302 attempts has been exceeded.      
    } elseif { [table lookup -subtable [IP::client_addr] attempt] > $static::prod_num_302_attempts } {
        #Client is not responding to 302 proxy auth. Send to no-auth VS.  
        if { $static::debuglog } { log local0. "##Captive portal failed## client IP [IP::client_addr]. Sending to no-auth VS" }
        table set -subtable "[IP::client_addr]" authstatus 5 $static::prod_idle_sec_timeout
        virtual $static::prod_noauth_sslo
        table set -subtable [IP::client_addr] attempt 0 $static::prod_idle_sec_timeout
        return
    #Trying captive portal auth but its not complete and number of attempts is still within the limit
    } else {
        #Incrment the attempt counter if captive portal is not receiving requests.
        if { [table lookup -subtable [IP::client_addr] captiveattempt] < 1 } { 
            table incr -subtable "[IP::client_addr]" attempt 
        #Clear attempt counter if client is trying captive portal 
        } elseif { [table lookup -subtable [IP::client_addr] captiveattempt] > 1 } { 
            table set -subtable [IP::client_addr] attempt 0 $static::prod_idle_sec_timeout
            if { $static::debuglog } { log local0. "Still trying captive portal for client IP [IP::client_addr]" }
        }
        #Send request to captive portal VS. Leave in status trying captive portal auth. 
        if { $static::debuglog } { log local0. "##Trying captive portal## client IP [IP::client_addr]" }
        virtual $static::prod_portal_sslo
        return
    }
}

#Check if we are trying kerberos auth for a client. 
if { [table lookup -subtable [IP::client_addr] authstatus] == 1 } {
    #Confirmed we are trying kerberos. Check if Kerberos access agent has been triggered and we know the kerberos access session SID
    if { [string length [table lookup -subtable [IP::client_addr] kerbaccesssid]] > 1 } {
        #Kerberos SID found. Check if we found a username for that sid
        if { [string length [ACCESS::session data get -sid [table lookup -subtable [IP::client_addr] kerbaccesssid] "session.logon.last.username"]] < 1 } {
            #No User identified. Delete kerberos access session and try captive portal auth. 
            ACCESS::session remove -sid [table lookup -subtable [IP::client_addr] kerbaccesssid]
            virtual $static::prod_portal_sslo
            table set -subtable "[IP::client_addr]" authstatus 3 $static::prod_idle_sec_timeout
            if { $static::debuglog } { log local0. "##Kerberos Failed##Try captive portal auth for client IP [IP::client_addr]. Removed kerberos access sid was [table lookup -subtable [IP::client_addr] kerbaccesssid]" }
            #Reset kerbaccesssid that we deleted the corresponding APM session. 
            table set -subtable [IP::client_addr] kerbaccesssid 0 $static::prod_idle_sec_timeout
            #Clear attempt counter for this client 
            table set -subtable [IP::client_addr] attempt 0 $static::prod_idle_sec_timeout
            return
        } elseif { [string length [ACCESS::session data get -sid [table lookup -subtable [IP::client_addr] kerbaccesssid] "session.logon.last.username"]] > 0 } {
            #User identified from kerberos. Mark client IP as known kerberos user. 
            if { $static::debuglog } { log local0. "##Kerberos Passed## client IP [IP::client_addr] user [ACCESS::session data get -sid [table lookup -subtable [IP::client_addr] kerbaccesssid] "session.logon.last.username"]" }
            virtual $static::prod_kerberos_sslo
            table set -subtable "[IP::client_addr]" authstatus 2 $static::prod_idle_sec_timeout
            return 
        }
    #Trying kerberos auth but kerbaccesssid has not yet been created. Checking if this client is not responding to 407 proxy auth.     
    } elseif { [table lookup -subtable [IP::client_addr] attempt] > $static::prod_num_407_attempts } {
        #Client is not responding to 407 proxy auth. Try captive portal instead.  
        virtual $static::prod_portal_sslo
        table set -subtable "[IP::client_addr]" authstatus 3 $static::prod_idle_sec_timeout
        if { $static::debuglog } { log local0. "##Client not responding to 407## Try captive portal auth for client IP [IP::client_addr]." }
        #Clear attempt counter for this client 
        table set -subtable [IP::client_addr] attempt 0 $static::prod_idle_sec_timeout
        return
    }
}

#Fallback to Kerberos auth. Probably first proxy HTTP requests from client.   
#Set authstatus to 1 (trying kerberos auth)
table set -subtable "[IP::client_addr]" authstatus 1 $static::prod_idle_sec_timeout
#Increment the attempt table for this client if the HTTP request does NOT contain the Proxy-Authorization HTTP header. This is used to detect if client is failing to respond to proxy auth.
if { !([HTTP::header exists "Proxy-Authorization"]) } { table incr -subtable "[IP::client_addr]" attempt }
if { $static::debuglog } { log local0. "##Fallback## Client IP [IP::client_addr] trying kerberos auth" }
virtual $static::prod_kerberos_sslo
return
}