when SERVERSSL_HANDSHAKE {
    if { [info exists cert_error] } {
        SSL::forward_proxy cert response_control mask
    }
}
when SERVERSSL_SERVERCERT {
    if { [X509::verify_cert_error_string [SSL::verify_result]] contains "expired" } {
    set now [clock seconds]
    set offset 604800 ; ## must be expired mode than 7 days
    if { [expr { ( ${now} - [clock scan [X509::not_valid_after [SSL::cert 0]]] ) > ${offset} }] } {
        set cert_error 1
        sharedvar ctx
        set ctx(cert_control) [X509::verify_cert_error_string [SSL::verify_result]]
    }
}
}