when CLIENT_ACCEPTED  {
    sharedvar ctx
    lappend ctx(headers) "[IP::client_addr]" [table lookup -subtable [IP::client_addr] ingressport]
    if { [expr { [llength $ctx(headers)] % 2 }] == 0 } {
        foreach {h_name h_value} $ctx(headers) {
        log local0. "INTERCEPT client IP [IP::client_addr] ingress port is ${h_value}"
}
}
}