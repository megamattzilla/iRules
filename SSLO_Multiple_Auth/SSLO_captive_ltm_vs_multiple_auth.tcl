when ACCESS_POLICY_COMPLETED priority 200 {
    table set -subtable "[IP::client_addr]" accesssid [ACCESS::session sid] 
    #log local0. "client IP [IP::client_addr] access sid is [table lookup -subtable [IP::client_addr] accesssid]"
}