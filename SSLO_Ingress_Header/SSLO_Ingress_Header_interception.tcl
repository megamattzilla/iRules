#Interception VS has access to table data and APM session variables. Read from the table and set an access session variable 
when HTTP_REQUEST {
    ACCESS::session data set session.ingress.port "[table lookup -subtable [IP::client_addr] ingressport]"
    log local0. "INTERCEPT client IP [IP::client_addr] ingress port is [table lookup [IP::client_addr]] access variable is [ACCESS::session data get "session.ingress.port"]"
}