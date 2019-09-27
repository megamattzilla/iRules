when HTTP_REQUEST {
    sharedvar ctx
    if { ( [info exists ctx(cert_control)] ) and ( $ctx(cert_control) ne "" ) } {
        HTTP::header insert "X-Origin-BlockCertificate" reason $ctx(cert_control)
        #log local0. "X-Origin-BlockCertificate: reason $ctx(cert_control)"
        }
}