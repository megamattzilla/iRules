## Made with heart by Matt Stovall 2/2024. 
## version 1.1.1 Updated 2/2025

## This iRule sets iRule session variables at various events with data values of existing TCP, HTTP, TLS variables. These new variables can be recalled and logged by other iRules. 
## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. 
## See https://github.com/megamattzilla/iRules/blob/master/Modular_Functions/README.md for more details

## Modular iRule dependency: none


when FLOW_INIT priority 530 {
if {[catch {

    ###User-Edit Variables start###
    set dc_globalStringLimit 100 ; #How many characters to collect from user-supplied HTTP values like HTTP host, version, referrer. 
    set dc_uriStringLimit 600 ; #How many characters to collect from HTTP value of URI
    set dc_httpHeaders "Upgrade Sec-WebSocket-Version User-Agent Referer Content-Type Content-Length" ; #Type: String #Space separated name(s) of HTTP headers to log. Name and value of header will be logged. 
    ###User-Edit Variables end###

    #Don't edit these system variables 
    set dc_FLOW_INIT [clock clicks -milliseconds]
    set dc_tcpID [TMM::cmp_unit][clock clicks]
    set dc_CLIENT_ACCEPTED 0
    set dc_CLIENTSSL_CLIENTHELLO 0
    set dc_CLIENTSSL_HANDSHAKE 0 
    set dc_http_request_count 0
    set dc_HTTP_REQUEST 0 
    set dc_ASM_REQUEST_DONE 0 
    set dc_LB_SELECTED 0 
    set dc_HTTP_REQUEST_RELEASE 0 
    set dc_SERVER_CONNECTED 0 
    set dc_SERVERSSL_CLIENTHELLO_SEND 0 
    set dc_SERVERSSL_HANDSHAKE 0 
    set dc_HTTP_RESPONSE 0 
    set dc_HTTP_RESPONSE_RELEASE 0


} err]} { log local0.error "Error in FLOW_INIT: $err" }
}

when HTTP_REQUEST priority 530 {
if {[catch {
    set dc_clientsslprofile [PROFILE::clientssl name]
    set dc_virtual_server [virtual name]
    set dc_http_host [string range [HTTP::host] 0 $dc_globalStringLimit]
    set dc_http_uri [string range [HTTP::uri] 0 $dc_uriStringLimit]
    set dc_http_method [string range [HTTP::method] 0 $dc_globalStringLimit]
    set dc_http_version [string range [HTTP::version] 0 $dc_globalStringLimit]
    set dc_vip [IP::local_addr]

    ## Collect User-Defined list of HTTP Headers and values. Add all that were found to array dc_user_defined_headers.
    foreach http_header $dc_httpHeaders {
        if { [HTTP::header exists $http_header] } {
            ##Syntax is set [array name]([name of array entry]) [value of array entry]
            set dc_user_defined_headers($http_header) [string range [HTTP::header value $http_header] 0 $dc_globalStringLimit]
        }
    }
} err] } {
        log local0.error "Error in HTTP_REQUEST: $err"
    }
}
when LB_SELECTED priority 530 {
if {[catch { set dc_pool [LB::server] } err]} { log local0.error "Error in LB_SELECTED: $err" } 
}

when HTTP_RESPONSE priority 530 {
if {[catch {
    set dc_http_status [string range [HTTP::status] 0 $dc_globalStringLimit]
    if { [HTTP::header Content-Length] > 0 } then {
        set dc_res_length [string range [HTTP::header "Content-Length"] 0 $dc_globalStringLimit]
    } else {
        set dc_res_length 0
    }
} err]} { log local0.error "Error in HTTP_RESPONSE: $err" }
}