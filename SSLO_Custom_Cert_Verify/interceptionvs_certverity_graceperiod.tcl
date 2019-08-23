##Place on SSLO interception -in-t-4 rule to enable custom origin certificate checks.  
when SERVERSSL_HANDSHAKE {
    if { [info exists cert_error] } {
        SSL::forward_proxy cert response_control mask
    }
}
when SERVERSSL_SERVERCERT {
    if { [X509::verify_cert_error_string [SSL::verify_result]] ne "ok" } {
        ##If any certificate errors are found, enable certificate masking and set a shared variable with the certificate status 
        set cert_error 1
        sharedvar ctx
        set ctx(cert_control) [X509::verify_cert_error_string [SSL::verify_result]]
    }
    if { [X509::verify_cert_error_string [SSL::verify_result]] contains "expired" } {
        set now [clock seconds]
        set offset 604800 ; ## 7 days
        if { [expr { ( ${now} - [clock scan [X509::not_valid_after [SSL::cert 0]]] ) < ${offset} }] } {
            ##If the only problem with this certificate is that it expired in 7 days or less, mask the cert and\
            #unset the ctc(cert_control) variable so no HTTP headers will get inserted by the second iRule. 
            set cert_error 1
            unset ctx(cert_control)
            }
        }
}