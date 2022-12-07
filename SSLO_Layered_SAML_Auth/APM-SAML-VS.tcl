when RULE_INIT {
    ## User-defined: DEBUG logging flag (1=on, 0=off)
    set static::SSLOAPMSAMLVS 1
    set static::JSCHALLENGEHOST "example.com"
}

when ACCESS_SESSION_STARTED {
#when access session is started, write a table entry so that we can lookup the session ID on other iRules. 
table delete -subtable "[IP::client_addr]" accesssid
table set -subtable "[IP::client_addr]" accesssid [ACCESS::session sid] 900
}
when ACCESS_ACL_DENIED {
#if APM session fails for any reason remove accesssid from table. 
table delete -subtable "[IP::client_addr]" accesssid
}
when ACCESS_SESSION_CLOSED {
#if APM session fails for any reason remove accesssid from table. 
table delete -subtable "[IP::client_addr]" accesssid
}

when ACCESS_POLICY_COMPLETED priority 200 {
    table set -subtable "[IP::client_addr]" authstatus 5 $static::prod_idle_sec_timeout
    log local0. "client IP [IP::client_addr] access sid is [ACCESS::session sid]"
}

when HTTP_REQUEST {
 if { $static::SSLODEBUG_MAC  } {
   #Log HTTP request when debug logging is enabled. 
   set LogString "Client [IP::client_addr]:[TCP::client_port] -> [HTTP::host][HTTP::uri]"
   log local0. "============================================="
   log local0. "$LogString (request)"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="
}
}

when HTTP_RESPONSE_RELEASE {

if { $static::SSLODEBUG_MAC  } { 
    #Log HTTP response before its transmitted client-side. After most F5 modules. 
   log local0. "============================================="
   log local0. "$LogString (response) - status: [HTTP::status]"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="  
}
#Fix final redirect using base64 we saved at the front door VS previosly. 
    if { [HTTP::header "Location"] equals "/vdesk/policy_done.php3?"  }{
   
        #Check if we have an original URL in the table. If APM session was reset but not the table value from noauth topology this will be missing. 
        if { [string length [b64decode [table lookup -subtable [IP::client_addr] originalURLbase64]]] < 2 } { 
            set originalURL https://www.google.com 
            if { $static::SSLODEBUG_MAC  } { log local0. "replacing location header with $originalURL"}
            HTTP::header replace "Location" $originalURL
        } else { 
            #set originalURL [lindex [split [ACCESS::session data get "session.server.landinguri"] "=" ] 1] ; dont use APM vars anymore with new front door logic. 
            set originalURL [b64decode [table lookup -subtable [IP::client_addr] originalURLbase64]]
            if { $static::SSLODEBUG_MAC  } { log local0. "replacing location header with $originalURL"} 
            HTTP::header replace "Location" $originalURL
   }
}
}