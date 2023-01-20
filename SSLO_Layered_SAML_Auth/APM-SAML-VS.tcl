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
set apmip [ACCESS::session data get "session.user.clientip"]
table delete -subtable $apmip accesssid
table delete -subtable $apmip authstatus
table lookup -subtable $apmip protectedMode
log local0. "client IP $apmip purged table data"
}

when ACCESS_POLICY_AGENT_EVENT { 
if { [ACCESS::policy agent_id] eq "42" } {
#Request is coming into APM Captive portal SSLO topology without completing JS challenge. 
#Delete iRule table data to force next connection to go through the iRule JS challenge. 
log local0. "BEFORE authstatus: [table lookup -subtable "[IP::client_addr]" authstatus ]"
catch { table delete -subtable "[IP::client_addr]" authstatus } 
log local0. "AFTER authstatus: [table lookup -subtable "[IP::client_addr]" authstatus ]"
catch { table delete -subtable "[IP::client_addr]" samlFallback } 
catch { table delete -subtable "[IP::client_addr]" noUaAttempt } 
catch { set accesssid [table lookup -subtable "[IP::client_addr]" accesssid] } 
catch { table delete -subtable "$accesssid" protectedMode }
log local0. "Client IP: [IP::client_addr] Detected stale iRule session data. Clearing iRule session data"
}
}

when ACCESS_POLICY_COMPLETED priority 200 {
#Check if APM was able to identify a username
set username 0 
catch { set username [ACCESS::session data get "session.logon.last.username"] } 
if { [string length $username ] > 1 } {
    table delete -subtable "[IP::client_addr]" authstatus
    table set -subtable "[IP::client_addr]" authstatus 5 900
    log local0. "client IP [IP::client_addr] access sid is [ACCESS::session sid]"
}
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