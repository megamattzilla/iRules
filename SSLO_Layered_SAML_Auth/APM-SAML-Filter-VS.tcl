# Made with ❤ by Matt Stovall 12/2022. 
#More info here https://github.com/megamattzilla/iRules/tree/master/SSLO_Layered_SAML_Auth
when RULE_INIT {
    ## User-defined: DEBUG logging flag (1=on, 0=off)
    set static::SSLOAPMFILTERVS 1
    #Set this to the real LTM+APM VS with SAML access policy applied.
    set static::SSLOAPMVS "captive-portal"
}
when HTTP_REQUEST {
if { $static::SSLOAPMFILTERVS  } {
   set LogString "Client [IP::client_addr]:[TCP::client_port] -> [HTTP::host][HTTP::uri]"
   log local0. "============================================="
   log local0. "$LogString (request)"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="
}
#check if APM session ID has been assigned to this user/IP.    
catch { set accesssid [table lookup -subtable [IP::client_addr] accesssid] } 
#if $accesssid exists see if the session is in protected mode
if { [string length $accesssid] > 1 } {
    #Check if this access sid is in protected mode
    if { [table lookup -subtable $accesssid protectedMode] == 1 } {
        #When this accesssid is in protected mode, disallow requests that are NOT a POST to the ACS URL
        if { [HTTP::method] == "POST"  &&  [HTTP::uri] == "/saml/sp/profile/post/acs" } {
        if { $static::SSLOAPMFILTERVS  } { log local0. "detected ACS Post" } 
        virtual $static::SSLOAPMVS
        return
    } else {
        #Respond with auth in progress page
        HTTP::respond 200 content {
        <html>
        <head>
        <title>Apology Page</title>
        </head>
        <body>
        Please complete your authentication promt before continuing. The authentication promt may be in another browser tab or application window. 
        </body>
        </html>
        }
       if { $static::SSLOAPMFILTERVS  } { log local0. "rejecting request to APM while in protected mode for this access id" } 
    }
}
}
virtual virtual $static::SSLOAPMVS
}

when HTTP_RESPONSE {
if { $static::SSLOAPMFILTERVS  } { 
   log local0. "============================================="
   log local0. "$LogString (response) - status: [HTTP::status]"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="  

}
#add protective mode logic here.
#Once APM redirects to ping identity, block any requests that are NOT a HTTP POST to the ACS URL.
if { [HTTP::header value "Location"] contains "auth.pingone.com" } { 
if { $static::SSLOAPMFILTERVS  } { log local0. "detected ping redirect" } 
#Enter protected mode per source IP address
set accesssid [table lookup -subtable [IP::client_addr] accesssid]
table set -subtable "$accesssid" protectedMode 1
if { $static::SSLOAPMFILTERVS  } { log local0. "ProtectedMode: [table lookup -subtable "$accesssid" protectedMode]" }
}
}