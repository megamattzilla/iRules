#ICAP virtual server in service chain has access to session variables but not table data. read from access session set in interception VS and insert a header with the value if present. 
when HTTP_REQUEST {
    if { [HTTP::header exists X-Ingress-Port] } {
        HTTP::header remove X-Ingress-Port
    }
    if { [string length [ACCESS::session data get "session.ingress.port"]] > 0 } {
        HTTP::header insert "X-Ingress-Port" [ACCESS::session data get "session.ingress.port"]
        log local0. "X-Ingress-Port: [ACCESS::session data get "session.ingress.port"]"
    }
}