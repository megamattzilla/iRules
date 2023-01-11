# Made with ❤ by Matt Stovall 12/2022. 
# New mac sessions default to saml. New windows sessions default to Kerberos/NTLM.
# This iRule should execute first on a front door VS with the normal Kerberos/NTLM flow executing afterwards. 
# This iRule is not intended to be ran alone, the non-matching default actions need to be performed by another iRule such as layered Kerberos/NTLM auth https://github.com/megamattzilla/iRules/blob/master/SSLO_Layered_Auth/SSLO_AuthHelper.tcl  
#More info here https://github.com/megamattzilla/iRules/tree/master/SSLO_Layered_SAML_Auth
when RULE_INIT priority 400 {
###User-Edit Variables start###

##DEBUG logging flag (1=on, 0=off)
set static::SSLODEBUG_MAC 1

#Specify name for captive portal/SAML SSLO topology
set static::prod_captive_sslo "sslo_saml.app/sslo_saml-xp-4"

#Specify name for SAML JS Challenge virtual server 
set static::functionJSChallenge "functionJS-xp"

#Specify keyword for OS detection  
set static::detectOSKeyword "mac"

###User-Edit Variables end###
}

when HTTP_REQUEST priority 250 {

#Optional debug log of the entire request and its HTTP headers. Useful for troubleshooting. 
if { $static::SSLODEBUG_MAC  } {
   set LogString "Client [IP::client_addr]:[TCP::client_port] -> [HTTP::host][HTTP::uri]"
   log local0. "============================================="
   log local0. "$LogString (request)"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="
}
#First check for existing session
#set variable called authlookup with the current authstatus of this session 
set authlookup [table lookup -subtable [IP::client_addr] authstatus]
if { $static::SSLODEBUG_MAC  } { log local0. "client IP [IP::client_addr] auth status is $authlookup for URI [HTTP::uri]" } 
#Definition of all authstatus
#1 = known ntlm client
#2 = known kerberos/basic auth client
#3 = known unauthenticated
#4 = known Captive Portal/SAML client
#no value/null = unknown auth client 
#5 = SAML/Captive portal auth

#Direct known users to respective topologies.  
switch $authlookup  {
  "5" {
    #set the captive portal virtual server name
	virtual $static::prod_captive_sslo
   if { $static::SSLODEBUG_MAC  } {  log local0. "known IP [IP::client_addr] sent to VS captive portal"}
	return
	
  } 
}


#Check for HTTP request chain that has passed the JS challange and should be sent to captive portal to complete SAML auth. 
if { [HTTP::host] equals "example.com" and [HTTP::path] equals "/pass" } {
    #Clear any existing base64 URLs
    table delete -subtable "[IP::client_addr]" originalURLbase64
    #Extract base64 of original web request and save it to a table to recall later for final redirect.
    table set -subtable "[IP::client_addr]" originalURLbase64 [string trimleft [HTTP::query] url=]
    #Direct this request to SAML enabled SSLO topology to start SAML auth proccess. 
    virtual $static::prod_captive_sslo
    if { $static::SSLODEBUG_MAC  } {  log local0. "PASSED JS - IP [IP::client_addr] sent to VS captive portal" }
    return

    #End if statement when URL is example.com/pass?url={{base64}} 
}

#Check if SAML should be disabled for this client IP
set samlFallback [table lookup -notouch -subtable [IP::client_addr] samlFallback]
 if { $static::SSLODEBUG_MAC  } {  log local0. "samlFallback is $samlFallback"}

#Send mac users to complete the JS challenge so that we can attempt SAML auth on a request chain that is capable of running JS. 
if { [string tolower [HTTP::header "User-Agent"]] contains $static::detectOSKeyword and !($samlFallback == 1) } {
     if { $static::SSLODEBUG_MAC  } {  log local0. "MAC user detected. Sending GET to functionJS virtual server" }
    virtual $static::functionJSChallenge
    return
    
}

#If no HTTP request header User-Agent is present- do something here. 
#In this example, treat No-user agent as a possible Safari CONNECT which does not use User-Agent on CONNECT tunnel. 
if { !([HTTP::header exists "User-Agent"]) and !($samlFallback == 1) } {
     if { $static::SSLODEBUG_MAC  } {  log local0. "No User-Agent detected. Sending GET to functionJS virtual server" }
    virtual $static::functionJSChallenge
    return
}

#Default action here for no user-agent match
virtual sslo_noAuth.app/sslo_noAuth-xp-4
log local0. "DEFAULT TO NO AUTH" 

}