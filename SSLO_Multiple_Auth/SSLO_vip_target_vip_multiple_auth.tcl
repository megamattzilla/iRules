when RULE_INIT priority 200 {
###User-Edit Variables start###

#Specify name for Captive Portal SSLO topology
set static::prod_portal_sslo "sslo_prod_portal.app/sslo_prod_portal-xp-4"
#Specify name for Kerberos SSLO topology
set static::prod_kerberos_sslo "sslo_prod_kerb.app/sslo_prod_kerb-xp-4"
#Specify name for no-auth SSLO topology
set static::prod_noauth_sslo "sslo_prod_noauth.app/sslo_prod_noauth-xp-4"
#Specify authentication preference idle timeout 
set static::prod_idle_sec_timeout "900" 
#Specify datagroup to use for client IP authentication bypass
set static::noauth_datagroup_ip "bypass_auth_ips"
#Specify if debug logging should be enabled. 1 = enabled, 0 = disabled.    
set static::debuglog "1"

###User-Edit Variables end###
}

when HTTP_REQUEST priority 200 {

#Debug Logging for troubleshooting.Should be typically disabled. 
if { $static::debuglog } { log local0. "DEBUG: CPU [TMM::cmp_unit] VS [virtual] 5tuple [client_addr]:[client_port] -> [IP::local_addr]:[TCP::local_port] proto [IP::protocol] for [HTTP::host][HTTP::uri] SID [ACCESS::session sid] Access profile [ACCESS::session data get "session.access.profile"] user [ACCESS::session data get "session.logon.last.username"] accesssid [table lookup -subtable [IP::client_addr] accesssid] kerbaccesssid [table lookup -subtable [IP::client_addr] kerbaccesssid]" 
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

#Whitelist
#Check source IP against the IP auth bypass list. If we find a match, send to noauth VS and add to known user table as noauth.  
if { [class match [IP::client_addr] equals "$static::noauth_datagroup_ip" ] } {
    table set -subtable "[IP::client_addr]" authstatus 5 $static::prod_idle_sec_timeout
    virtual $static::prod_noauth_sslo
    if { $static::debuglog } { log local0. "discovered IP [IP::client_addr] matched IP auth bypass and sent to VS noauth." } 
    return
}


#known user lookup. After successful Kerberos or captive portal sessions most HTTP requests will be handled here. 
switch $authlookup  {
    "2" {
    #Found known kerberos client. direct request to SSLO Kerberos/Basic virtual server name and exit iRule. 
    virtual $static::prod_kerberos_sslo
    if { $static::debuglog } { log local0. "known IP [IP::client_addr] sent to VS kerberos" }
	return
  }
  "4" {
    #Found known captive portal client. direct request to SSLO Captive Portal virtual server and exit iRule. 
    virtual $static::prod_portal_sslo
    if { $static::debuglog } { log local0. "known IP [IP::client_addr] sent to VS captive portal" }
	return
  }
  "5" {
    #Found known no-auth client. direct request to SSLO no-auth virtual server and exit iRule. 
	virtual $static::prod_noauth_sslo
    if { $static::debuglog } { log local0. "known IP [IP::client_addr] sent to VS fallback noauth" }
	return
  } 
}

#If we are trying captive portal for a client, do that now. 
if { $authlookup == 3 } {
        #Found trying captive portal session
        if { $static::debuglog } { log local0. "Trying captive portal auth for client IP [IP::client_addr]" }
        #As of this version we dont check the captive portal clients for success/fail criteria. We expect clients to handle the redirect and the access policy to fail open so set their auth status to known captive portal. Add Captive portal check here in future if needed. 
        table set -subtable "[IP::client_addr]" authstatus 4 $static::prod_idle_sec_timeout
        virtual $static::prod_portal_sslo
        return
}

#Check if we are trying kerberos auth for a client. 
if { [table lookup -subtable [IP::client_addr] authstatus] == 1 } {
    #Confirmed we are trying kerberos. Check if Kerberos access agent has been triggered and we know the kerberos access session SID
    if { [string length [table lookup -subtable [IP::client_addr] kerbaccesssid]] > 0 } {
        #Kerberos SID found. Check if we found a username for that sid
        if { [string length [ACCESS::session data get -sid [table lookup -subtable [IP::client_addr] kerbaccesssid] "session.logon.last.username"]] < 1 } {
            #No User identified. Delete kerberos access session and try captive portal auth. 
            ACCESS::session remove -sid [table lookup -subtable [IP::client_addr] kerbaccesssid]
            virtual $static::prod_portal_sslo
            table set -subtable "[IP::client_addr]" authstatus 3 $static::prod_idle_sec_timeout
            if { $static::debuglog } { log local0. "Kerberos Failed. Try captive portal auth for client IP [IP::client_addr]. Removed kerberos access sid was [table lookup -subtable [IP::client_addr] kerbaccesssid]" }
            #Cleanup kerbaccesssid that we deleted the corresponding APM session. 
            table delete -subtable [IP::client_addr] kerbaccesssid
            return
        } elseif { [string length [ACCESS::session data get -sid [table lookup -subtable [IP::client_addr] kerbaccesssid] "session.logon.last.username"]] > 0 } {
            #User identified from kerberos. Mark client IP as known kerberos user. 
            if { $static::debuglog } { log local0. "Kerberos Passed for client IP [IP::client_addr] user [ACCESS::session data get -sid [table lookup -subtable [IP::client_addr] kerbaccesssid] "session.logon.last.username"]" }
            virtual $static::prod_kerberos_sslo
            table set -subtable "[IP::client_addr]" authstatus 2 $static::prod_idle_sec_timeout
            return 
        }
    } 
}

#Fallback to Kerberos auth. Probably first HTTP requests from client.   
virtual $static::prod_kerberos_sslo
table set -subtable "[IP::client_addr]" authstatus 1 $static::prod_idle_sec_timeout
if { $static::debuglog } { log local0. "Fallback: Client IP [IP::client_addr] trying kerberos auth" }
return
}