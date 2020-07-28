when HTTP_REQUEST priority 200 {
    #log local0. "DEBUG: CPU [TMM::cmp_unit] VS [virtual] 5tuple [client_addr]:[client_port] -> [IP::local_addr]:[TCP::local_port] proto [IP::protocol] for [HTTP::host][HTTP::uri] SID [ACCESS::session sid] Access profile [ACCESS::session data get "session.access.profile"] user [ACCESS::session data get "session.logon.last.username"] accesssid [table lookup -subtable [IP::client_addr] accesssid]" 
    if { [HTTP::header exists X-Authenticated-User] } {
        HTTP::header remove X-Authenticated-User
    }
    if { [HTTP::header exists X-Authenticated-Groups] } {
        HTTP::header remove X-Authenticated-Groups
    }
    sharedvar ctx
    #First Check APM built-in sesssion table for username
    if { [string length [ACCESS::session data get "session.logon.last.username"]] > 0  } {
        HTTP::header insert "X-Authenticated-User" [ACCESS::session data get "session.logon.last.username"]
        #log local0. "X-Authenticated-User: [ACCESS::session data get "session.logon.last.username"]"
        #Then check iRule table for access session ID for username 
   } elseif { ( [info exists ctx(headers2)] ) and [expr { [llength $ctx(headers2)] % 2 }] == 0 } {
    foreach {h_name h_value} $ctx(headers2) {
        #If the accesssid exists, try looking it up and see if a username is present
        if  { [ catch { [string length [ACCESS::session data get -sid ${h_value} "session.logon.last.username"]] > 0 } ] } {
            #Insert found username into HTTP Header
            HTTP::header insert X-Authenticated-User [ACCESS::session data get -sid ${h_value} "session.logon.last.username"]
            #log local0. "sc  client IP [IP::client_addr] user is [ACCESS::session data get -sid ${h_value} "session.logon.last.username"]"
            }
        }
    }   
    #First Check APM built-in sesssion table for group
    if { [string length [ACCESS::session data get "session.ldap.last.attr.memberOf"]] > 0 } {
        HTTP::header insert "X-Authenticated-Groups" [ACCESS::session data get "session.ldap.last.attr.memberOf"]
        #log local0. "X-Authenticated-Groups: [ACCESS::session data get "session.ldap.last.attr.memberOf"]"
        #Then check iRule table for access session ID for group
    } elseif { ( [info exists ctx(headers2)] ) and [expr { [llength $ctx(headers2)] % 2 }] == 0 } {
    foreach {h_name h_value} $ctx(headers2) {
        #If the accesssid exists, try looking it up and see if a group is present
        if  { [ catch { [string length [ACCESS::session data get -sid ${h_value} "session.ldap.last.attr.memberOf"]] > 0 } ] } {
            #Insert found group into HTTP Header
            HTTP::header insert X-Authenticated-Groups [ACCESS::session data get -sid ${h_value} "session.ldap.last.attr.memberOf"]
            #log local0. "sc  client IP [IP::client_addr] groups are [ACCESS::session data get -sid ${h_value} "session.ldap.last.attr.memberOf"]"
            }
        }
    }
}