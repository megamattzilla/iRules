when RULE_INIT priority 200 {
###User-Edit Variables start###
#Specify name for Captive Portal SSLO topology
set static::prod_portal_sslo "sslo_prod_portal.app/sslo_prod_portal-xp-4"
#Specify name for Kerberos SSLO topology
set static::prod_kerberos_sslo "sslo_prod_kerb.app/sslo_prod_kerb-xp-4"
#Specify name for no-auth SSLO topology
set static::prod_noauth_sslo "sslo_prod_noauth.app/sslo_prod_noauth-xp-4"
#Specify authentication preference idle timeout 
set static::prod_idle_sec_timeout "30" 
#Specify datagroup to use for client IP authentication bypass
set static::noauth_datagroup_ip "bypass_auth_ips"
#Specify number of HTTP responses to collect to use for pass/fail decisions
set static::noauth_HTTPtocount "4"
#Specify (in seconds) rolling window of HTTP responses to collect to use for pass/fail decisions
set static::noauth_rollingwindow "10"
#Specify ratio of HTTP Status code 407s:200s to use for pass/fail decisions. 
set static::noauth_ratio "3"
#Specify if debug logging should be enabled. 1 = enabled, 0 = disabled.    
set static::debuglog "1"
#Example if APM Kerberos access profile is set to 3 auth attempts, it will generally send ~3 HTTP 407s until it fails open. After successful/fail open Kerberos HTTP status code will change to 200 Connected.  
#So assuming 3:1 will be a failure- 3 divided by 1 equals 3. This variable sets the number that will be checked when we divide 407s by 200s.  
#In practice a failed kerberos session will have high ratio of 407s to 200s (>3) and a successful kerberos session will have a log ratio of 407s to 200s (<3) 
###User-Edit Variables end###
}

when HTTP_REQUEST priority 200 {

if { $static::debuglog } { log local0. "DEBUG: CPU [TMM::cmp_unit] VS [virtual] 5tuple [client_addr]:[client_port] -> [IP::local_addr]:[TCP::local_port] proto [IP::protocol] for [HTTP::host][HTTP::uri] SID [ACCESS::session sid] Access profile [ACCESS::session data get "session.access.profile"] user [ACCESS::session data get "session.logon.last.username"] accesssid [table lookup -subtable [IP::client_addr] accesssid]" 
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
  HTTP::respond 301 Location "http://neverssl.com"
  if { $static::debuglog } { log local0. "Purged table entries for [IP::client_addr] and redirected to new page" }
  return
  }
}

#Whitelist
#Check source IP against the IP auth bypass list. If we find a match, send to noauth VS and add to known user table as noauth.  
if { [class match [IP::client_addr] equals "$static::noauth_datagroup_ip" ] } {
    table set -subtable "[IP::client_addr]" authstatus 5 $static::prod_idle_sec_timeout
    virtual $static::prod_noauth_sslo
    if { $static::debuglog } { log local0. "discovered IP [IP::client_addr] matched IP auth bypass and sent to VS noauth." } 
    return
}


#known user lookup
switch $authlookup  {
    "2" {
    #set the SSLO Kerberos/Basic virtual server name
    virtual $static::prod_kerberos_sslo
    if { $static::debuglog } { log local0. "known IP [IP::client_addr] sent to VS kerberos" }
	return
  }
  "4" {
    #set the SSLO Captive Portal virtual server name
    virtual $static::prod_portal_sslo
    if { $static::debuglog } { log local0. "known IP [IP::client_addr] sent to VS captive portal" }
	return
  }
  "5" {
    #set the no auth virtual server name
	virtual $static::prod_noauth_sslo
    if { $static::debuglog } { log local0. "known IP [IP::client_addr] sent to VS fallback noauth" }
	return
  } 
}

#Send captive portal traffic to the captive portal VS- bypassing the HTTP Proxy. 
if { [HTTP::host] == "ssloprxy.f5kc.lab.local:4001" } {
    if { $static::debuglog } { log local0. "Sending to captive portal VS" }
    virtual auth2.0_captive_portal
    return
}

#If we are trying captive portal for a client, do that now. 
if { $authlookup == 3 } {
        if { $static::debuglog } { log local0. "Trying captive portal auth for client IP [IP::client_addr]" }
        #As of this version we dont check the captive portal clients- we expect it to fail open so set their auth status to captive portal. Add Captive portal check here in future if needed. 
        table set -subtable "[IP::client_addr]" authstatus 4 $static::prod_idle_sec_timeout
        virtual $static::prod_portal_sslo
        return
}

#After 4 HTTP responses have been observed check the Response Ratio of 407s to 200s
set 407s [table keys -count -subtable "407reqrate:[IP::client_addr]"]
set 200s [table keys -count -subtable "200reqrate:[IP::client_addr]"]
if { $407s + $200s > $static::noauth_HTTPtocount } {
    #If no 200s or no 407s have been sent, reset the value to .1. 
    if { $407s == 0 } { set 407s .1 } 
    if { $200s == 0 } { set 200s .1 } 
    #Required number of HTTP responses have been sent to client. Looking at ratio of 407s to 200s. 
    if { $407s / $200s >= $static::noauth_ratio } {
        #Kerberos Pass Condition 
        if { $static::debuglog } { log local0. "Kerberos Failed. Try captive portal auth for client IP [IP::client_addr]" }
        virtual $static::prod_portal_sslo
        table set -subtable "[IP::client_addr]" authstatus 3 $static::prod_idle_sec_timeout
        return
        } elseif { $407s / $200s <= 3 } { 
        #Kerberos Fail Confidition
        if { $static::debuglog } { log local0. "Kerberos Passed for client IP [IP::client_addr]" }
        virtual $static::prod_kerberos_sslo
        table set -subtable "[IP::client_addr]" authstatus 2 $static::prod_idle_sec_timeout
        return
    }
}



#Fallback to Kerberos auth. Probably first HTTP requests from client.   
virtual $static::prod_kerberos_sslo
table set -subtable "[IP::client_addr]" authstatus 1 $static::prod_idle_sec_timeout
if { $static::debuglog } { log local0. "Client IP [IP::client_addr] trying kerberos auth" }
return
}


when HTTP_RESPONSE priority 200 { 

#Disable checking status code if its a Kerberos or Captive portal user. 
if { [table lookup -subtable [IP::client_addr] authstatus] == 2 || [table lookup -subtable [IP::client_addr] authstatus] == 4 } {
return
}

switch [HTTP::status]  {
    "407" {
    #Create a rolling 10 second window and increment for each HTTP 407 response
    set 407reqno [table incr "407reqs:[IP::client_addr]"]
    table set -subtable 407reqrate:[IP::client_addr] $407reqno ignore 30 $static::noauth_rollingwindow 
    if { $static::debuglog } { log local0. "found HTTP 407 for Client IP [IP::client_addr]" }
	return
  }
  "200" {
    #Create a rolling 10 second window and increment for each HTTP 200 response
    set 200reqno [table incr "200reqs:[IP::client_addr]"]
    table set -subtable 200reqrate:[IP::client_addr] $200reqno ignore 30 $static::noauth_rollingwindow 
    if { $static::debuglog } { log local0. "found HTTP 200 for Client IP [IP::client_addr]" }
  }
}

}