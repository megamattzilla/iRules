when CLIENT_ACCEPTED  {
    sharedvar ctx
    lappend ctx(headers) "[IP::client_addr]" [table lookup -subtable [IP::client_addr] ingressport]
}