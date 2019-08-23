# Copyright (c) 2018.  F5 Networks, Inc.  See End User License Agreement (EULA) for license terms.
# Notwithstanding anything to the contrary in the EULA, Licensee may copy and modify
# this software product for its internal business purposes. Further, Licensee may upload,
# publish and distribute the modified version of the software product on devcentral.f5.com.


when HTTP_DISABLED {
 set tmp "ADAPT::enable request 0; ADAPT::enable response 0"
 eval $tmp
 unset tmp
}
when HTTP_REQUEST {
    sharedvar ctx
    if { ( [info exists ctx(cert_control)] ) and ( $ctx(cert_control) ne "" ) } {
        HTTP::header insert "X-Origin-BlockCertificate" reason $ctx(cert_control)
        #log local0. "X-Origin-BlockCertificate: reason $ctx(cert_control)"
        }
}