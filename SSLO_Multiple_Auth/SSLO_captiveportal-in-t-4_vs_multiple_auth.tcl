when CLIENT_ACCEPTED priority 200  {
if { [string length [table lookup -subtable [IP::client_addr] accesssid]] > 0 } {
    sharedvar ctx
    lappend ctx(headers2) "[IP::client_addr]" [table lookup -subtable [IP::client_addr] accesssid]
    }
}