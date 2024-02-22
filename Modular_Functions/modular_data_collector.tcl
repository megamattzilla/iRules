# Made with ❤ by Matt Stovall 2/2024. 
# This iRule sets iRule session variables at various events with data values of existing TCP, HTTP, TLS variables. These new variables can be recalled and logged by other iRules. 
#All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. 
#See https://github.com/megamattzilla/iRules/blob/master/Modular_Functions/README.md for more details
#Version 1.0
#Modular iRule dependency: none

when FLOW_INIT priority 530 {
catch {

    ###User-Edit Variables start###
    set dc_globalStringLimit 100 ; #How many characters to collect from user-supplied HTTP values like HTTP host, version, referrer. 
    set dc_uriStringLimit 600 ; #How many characters to collect from HTTP value of URI
    ###User-Edit Variables end###

}
}

when HTTP_REQUEST priority 530 {
catch {
    set dc_clientsslprofile [PROFILE::clientssl name]
    set dc_virtual_server [virtual name]
    set dc_http_host [string range [HTTP::host] 0 $dc_globalStringLimit]
    set dc_http_uri [string range [HTTP::uri] 0 $dc_uriStringLimit]
    set dc_http_method [string range [HTTP::method] 0 $dc_globalStringLimit]
    set dc_http_referrer [string range [HTTP::header "Referer"] 0 $dc_globalStringLimit]
    set dc_http_content_type [string range [HTTP::header "Content-Type"] 0 $dc_globalStringLimit]
    set dc_http_user_agent [string range [HTTP::header "User-Agent"] 0 $dc_globalStringLimit]
    set dc_http_version [string range [HTTP::version] 0 $dc_globalStringLimit]
    set dc_vip [IP::local_addr]
    if { [HTTP::header Content-Length] > 0 } then {
        set dc_req_length [string range [HTTP::header "Content-Length"] 0 $dc_globalStringLimit]
    } else {
        set dc_req_length 0
    }
}
}
when LB_SELECTED priority 530 {
    catch { set dc_pool [LB::server] } 
}

when HTTP_RESPONSE priority 530 {
catch {
    set dc_http_status [string range [HTTP::status] 0 $dc_globalStringLimit]
    if { [HTTP::header Content-Length] > 0 } then {
        set dc_res_length [string range [HTTP::header "Content-Length"] 0 $dc_globalStringLimit]
    } else {
        set dc_res_length 0
    }
}
}