when ACCESS_POLICY_AGENT_EVENT priority 200 { 
    #Look for the custom trigger iRule in VPE
    if { [ACCESS::policy agent_id] eq "42" } {
        #Kerberos auth failed
        table set -subtable "[IP::client_addr]" kerbaccesssid [ACCESS::session sid] 
        log local0. "client IP [IP::client_addr] kerberos access sid is [table lookup -subtable [IP::client_addr] kerbaccesssid] for user [ACCESS::session data get "session.logon.last.username"]"
    }
}

when ACCESS_POLICY_COMPLETED priority 200 { 
        #Kerberos auth passed
        table set -subtable "[IP::client_addr]" kerbaccesssid [ACCESS::session sid] 
        log local0. "client IP [IP::client_addr] kerberos access sid is [table lookup -subtable [IP::client_addr] kerbaccesssid] for user [ACCESS::session data get "session.logon.last.username"]"
}