when HTTP_REQUEST {
    if { [HTTP::header exists X-Ingress-Port] } {
        HTTP::header remove X-Ingress-Port
    }
}