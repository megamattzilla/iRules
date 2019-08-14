when SERVERSSL_HANDSHAKE {
    if { [info exists cert_error] } {
        SSL::forward_proxy cert response_control mask
    }
}
when SERVERSSL_SERVERCERT {
    if { [X509::verify_cert_error_string [SSL::verify_result]] ne "ok" } {
        set cert_error 1
        sharedvar ctx
        set ctx(cert_control) [X509::verify_cert_error_string [SSL::verify_result]]
    }
}
