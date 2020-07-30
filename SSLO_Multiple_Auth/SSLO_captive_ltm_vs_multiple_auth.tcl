when ACCESS_POLICY_COMPLETED priority 200 {
    table set -subtable "[IP::client_addr]" accesssid [ACCESS::session sid] $static::prod_idle_sec_timeout
    log local0. "client IP [IP::client_addr] access sid is [table lookup -subtable [IP::client_addr] accesssid]"
}

when HTTP_REQUEST { 
    log local0. "DEBUG: CPU [TMM::cmp_unit] VS [virtual] 5tuple [client_addr]:[client_port] -> [IP::local_addr]:[TCP::local_port] proto [IP::protocol] for [HTTP::host][HTTP::uri] SID [ACCESS::session sid] Access profile [ACCESS::session data get "session.access.profile"] user [ACCESS::session data get "session.logon.last.username"] accesssid [table lookup -subtable [IP::client_addr] accesssid] kerbaccesssid [table lookup -subtable [IP::client_addr] kerbaccesssid] attempt# [table lookup -subtable [IP::client_addr] attempt] captiveattempt [ table lookup -subtable [IP::client_addr] captiveattempt]"
    table incr -subtable "[IP::client_addr]" captiveattempt
}