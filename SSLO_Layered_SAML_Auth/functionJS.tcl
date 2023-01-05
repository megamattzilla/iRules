# Made with ❤ by Matt Stovall 12/2022. 
# challenge the requestor to see if they can run javascript. 
# If success, they will be redirected to a special dummy URL with the original URL base64 encoded in the URI. 
#More info here https://github.com/megamattzilla/iRules/tree/master/SSLO_Layered_SAML_Auth

when RULE_INIT {
    ## User-defined: DEBUG logging flag (1=on, 0=off)
    set static::SsloDebugFunctionJS 1
    set static::JSCHALLENGEHOST "example.com"
}

when HTTP_REQUEST { 

#Check if original URL is HTTP or HTTPS
if { [ TCP::local_port ] == 80 } {
set scheme "http"
} else {
set scheme "https"
}
#Set variable of the original scheme and URL (host + URI) to use for the JS challenge. 
set base64oforiginalURL [b64encode $scheme://[HTTP::host][HTTP::uri]]

#DEBUG 
if { $static::SsloDebugFunctionJS ==1 } {
   set LogString "Client [IP::client_addr]:[TCP::client_port] -> [HTTP::host][HTTP::uri]"
   log local0. "============================================="
   log local0. "$LogString (request)"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="
 log local0. "ConnFlow ([IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port])"
}

#Now that CONNECT tunnel has a chance to establish on in-t-4 virtual, check the request headers for user agent match.
#If we dont have a user agent match to perform SAML, redirect the request back to the original page. 
#we specify connection close so that the browser will issue a new connection to the front door.
#also specify a table entry to prevent this client IP from coming back to the functionJS logic. 
if { !([string tolower [HTTP::header "User-Agent"]] contains $static::detectOSKeyword) } {
    if { $static::SsloDebugFunctionJS ==1 } { log local0. "User-Agent did not match SAML filter"}
    #Create a table to keep track of no user agent attempts. This can be used to fail the client back to non-SAML auth.  
    table incr -subtable "[IP::client_addr]" noUaAttempt
    #set variable called noUaAttempt with the current auth attempt number for this client 
    set noUaAttempt [table lookup -subtable [IP::client_addr] noUaAttempt]
    if { $static::SsloDebugFunctionJS ==1 } { log local0. "client IP [IP::client_addr] starting auth attempt $noUaAttempt"}
    #If the number of no user agent attempts reaches the threshold, disable SAML auth for this client IP. 
    if { $noUaAttempt > 9 } { 
        table set -subtable "[IP::client_addr]" samlFallback 1 900
        if { $static::SsloDebugFunctionJS ==1 } { log local0. "disabling SAML auth for client IP [IP::client_addr]"}
    }
    #Set a new variable with the original URL (not base64).
    set originalURL $scheme://[HTTP::host][HTTP::uri]
    #Respond to this no-user-agent match request with a redirect to the same page. After $noUaAttempt attempts SAML will fall back to non-SAML methods. 
    HTTP::respond 301 "Location" $originalURL "Connection" Close "Cache-Control" no-store
    return
}

#Start building the content for the JS challenge. 
catch { set customData [subst {
<html>
  <head>
    <meta http-equiv="refresh" content="0;url=http://$static::JSCHALLENGEHOST/$base64oforiginalURL/pass" />
    <title></title>
  </head>
 <body></body>
</html>
}]
}
#Send JS Challenge!
HTTP::respond 200 content $customData "Connection" Close "Cache-Control" no-store

}