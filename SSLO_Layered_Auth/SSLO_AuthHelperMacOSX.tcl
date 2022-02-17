when HTTP_REQUEST {
#
#Users will be authenticated once at session start. If no traffic has been observed in $static::prod_idle_sec_timeout seconds we will re-request their authentication preference with a 407 Proxy Authentication Required. 
#Note- this will iRule will pass traffic to the SSLO VS for that auth type. An existing access session may not be re-authenticated every time, that is determined by the access profile.    


###User-Edit Variables start###
#Specify name for NTLM SSLO topology
set static::prod_ntlm_sslo "sslo_ntlm.app/sslo_ntlm-xp-4"

#Specify name for Kerberos SSLO topology
set static::prod_kerberos_sslo "sslo_prod_kerberos.app/sslo_prod_kerberos-xp-4"

#Specify name for no-auth SSLO topology
set static::prod_noauth_sslo "sslo_prod_noauth.app/sslo_prod_noauth-xp-4"

#Specify authentication preference idle timeout 
set static::prod_idle_sec_timeout "900" 

#Specify datagroup to use for client IP authentication bypass
set static::noauth_datagroup_ip "bypass_auth_ips"

#Specify custom URL object to use for URL authentication bypass- **this will bypass auth for all traffic from this client IP**
set static::noauth_custom_url "auth_bypass" 
###User-Edit Variables end###


##Optional Debug mode to clear table entries##
switch [HTTP::uri]  {
  "http://neverssl.com/debug" {
  table delete -subtable "[IP::client_addr]" authstatus
  table delete -subtable "[IP::client_addr]" attempt
  HTTP::respond 301 Location "http://neverssl.com"
  log local0. "Purged table entries for [IP::client_addr] and redirected to new page"
  return
  }
}

#set variable called authlookup with the current authstatus of this session 
set authlookup [table lookup -subtable [IP::client_addr] authstatus]
log local0. "client IP [IP::client_addr] auth status is $authlookup for URI [HTTP::uri]"
#Definition of all authstatus
#1 = known ntlm client
#2 = known kerberos/basic auth client
#3 = known unauthenticated
#4 = pending - HTTP 407 sent to request authenticaiton method 

#known user lookup
switch $authlookup  {
  "1" {
  #set the SSLO NTLM virtual server name
  virtual $static::prod_ntlm_sslo
  log local0. "known IP [IP::client_addr] sent to VS ntlm"
	return
  }
  "2" {
  #set the SSLO Kerberos/Basic virtual server name
  virtual $static::prod_kerberos_sslo
  log local0. "known IP [IP::client_addr] sent to VS kerberos"
	return
  }
  "3" {
  #set the no auth virtual server name
	virtual $static::prod_noauth_sslo
  log local0. "known IP [IP::client_addr] sent to VS noauth"
	return
  } 
}

#Check source IP against the IP auth bypass list. If we find a match, send to noauth VS and add to known user table as noauth.  
if { [class match [IP::client_addr] equals "$static::noauth_datagroup_ip" ] } {
  table set -subtable "[IP::client_addr]" authstatus 3 $static::prod_idle_sec_timeout
  virtual $static::prod_noauth_sslo
  log local0. "discovered IP [IP::client_addr] matched IP auth bypass and sent to VS noauth."
  return
}

#Check URL against the URL auth bypass list. If we find a match, send to noauth VS and add to known user table as noauth.  
set custom_uri http://[HTTP::host]
if { [catch [CATEGORY::lookup $custom_uri request_default_and_custom] contains $static::noauth_custom_url ]  } {
  table set -subtable "[IP::client_addr]" authstatus 3 $static::prod_idle_sec_timeout
  virtual $static::prod_noauth_sslo
  log local0. "discovered IP [IP::client_addr] with request [HTTP::uri] matched URL auth bypass and sent to VS noauth."
  return
}

#set variable called attempt with the current auth attempt number for this client  
set attempt [table lookup -subtable [IP::client_addr] attempt]
log local0. "client IP [IP::client_addr] starting auth attempt $attempt"

#unknown user lookup
switch -glob "$authlookup|[HTTP::header "Proxy-Authorization"]|$attempt"  {
  "4|NTLM*|*" {
    table set -subtable "[IP::client_addr]" authstatus 1 $static::prod_idle_sec_timeout
    virtual $static::prod_ntlm_sslo
    log local0. "discovered IP [IP::client_addr] with header [HTTP::header "Proxy-Authorization"] sent to VS ntlm"
  }
  "4|Negotiate*|*" {
    #NTLM can sometimes use Negotiate header. Decode the authdata and see if NTLM data is present. 
    set decodedauth [b64decode [string trimleft [HTTP::header "Proxy-Authorization"] "Negotiate " ]]
    #The following log can cause non-ascii characters to be logged which can make some log viewing clients show garbage. 
    #log local0. "decoded proxy-auth header value is $decodedauth"
        switch -glob $decodedauth {
          "NTLM*" {
            table set -subtable "[IP::client_addr]" authstatus 1 $static::prod_idle_sec_timeout
            virtual $static::prod_ntlm_sslo
            log local0. "discovered IP [IP::client_addr] sent to VS ntlm because header [HTTP::header "Proxy-Authorization"]"
            }
        default {
            table set -subtable "[IP::client_addr]" authstatus 2 $static::prod_idle_sec_timeout
            virtual $static::prod_kerberos_sslo
            log local0. "discovered IP [IP::client_addr] sent to VS kerberos because header [HTTP::header "Proxy-Authorization"]"
            }
  }
  }
  "4|Basic*|*" {
    #Kerberos access profile can also handle Basic as an option. If basic is returned by client send to Kerberos VS.  
    table set -subtable "[IP::client_addr]" authstatus 2 $static::prod_idle_sec_timeout
    virtual $static::prod_kerberos_sslo
    log local0. "discovered IP [IP::client_addr] with header [HTTP::header "Proxy-Authorization"] sent to VS kerberos for basic auth"
  }
  "4|*|5" {
	  table set -subtable "[IP::client_addr]" authstatus 3 indefinite 30
    table set -subtable "[IP::client_addr]" attempt 5 indefinite 30
	  virtual $static::prod_noauth_sslo
    log local0. "discovered IP [IP::client_addr] with header [HTTP::header "Proxy-Authorization"] sent to VS noauth. will re-challange auth in 30 seconds"
  }  
  default {
    log local0. "new IP [IP::client_addr] sending HTTP 407"
	  table incr -subtable "[IP::client_addr]" attempt
	  table set -subtable "[IP::client_addr]" authstatus 4 $static::prod_idle_sec_timeout
    #Check if User-Agent header exists. 
    if { [HTTP::header exists User-Agent] } {
      #Convert the User-Agent value to all lowercase and then check if it contains the string "mac". 
      if { [string tolower [HTTP::header "User-Agent"]] contains "mac" } {
        #User-agent contains "mac", send Mac 407. 
        HTTP::respond 407 -version auto content "<html><title>MacOS Authentication Required</title><body>Error: Authentication Failure</body></html>" Proxy-Authenticate "Negotiate" 
        } else {
        #User-Agent exists, but does not contain "mac". Send default 407. 
        HTTP::respond 407 -version auto content "<html><title>Authentication Required</title><body>Error: Authentication Failure</body></html>" Proxy-Authenticate "Negotiate" Proxy-Authenticate "NTLM" 
        }
    } else {
        #No User-Agent header exists, send default 407. 
        HTTP::respond 407 -version auto content "<html><title>Authentication Required</title><body>Error: Authentication Failure</body></html>" Proxy-Authenticate "Negotiate" Proxy-Authenticate "NTLM" 
        }
  }
}
}