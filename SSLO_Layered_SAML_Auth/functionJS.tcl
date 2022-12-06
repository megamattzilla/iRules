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