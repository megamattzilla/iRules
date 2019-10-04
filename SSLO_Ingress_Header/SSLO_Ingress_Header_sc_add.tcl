#ICAP virtual server in service chain has access to session variables but not table data. read from access session set in interception VS and insert a header with the value if present. 
when HTTP_REQUEST {
    sharedvar ctx
    if { [HTTP::header exists X-Ingress-Port] } {
        HTTP::header remove X-Ingress-Port
    }
    if { [expr { [llength $ctx(headers)] % 2 }] == 0 } {
    foreach {h_name h_value} $ctx(headers) {
    HTTP::header insert X-Ingress-Port ${h_value}
    log local0. "sc  client IP [IP::client_addr] ingress port is ${h_value}"
}
}
}