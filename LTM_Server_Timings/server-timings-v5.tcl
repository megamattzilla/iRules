# Made with ❤ by Matt Stovall and Shane Levin @ F5 6/2023. Updated 2/2024.
#Version 5.0. See https://github.com/megamattzilla/iRules/tree/master/LTM_Server_Timings for more info. 
#This iRule collect timing information at multiple events to determine latency between many client and server side events.
#All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. 
#Requirements: 
#Event CLIENTSSL_HANDSHAKE requires clientssl profile on virtual
#Event SERVERSSL_HANDSHAKE requires serverssl profile on virtual
#Requires ASM profile on virtual server with iRule events enabled (this is common for most ASM deployments)

when FLOW_INIT {
catch {

    ###User-Edit Variables start###
    set st_enableLogWithoutHeader 1 ; #1 = enabled, 0 = disabled. when enabled, start logging for all HTTP requests and responses regardless of HTTP request header X-Enable-Server-Timing being present. The log local and remote variables still need to be enabled in order for the relevant logging to take place.
    set st_clientEnableTimingHeaderName X-Enable-Server-Timing ; #Client HTTP header name that triggers debug timing to take place.
    set st_clientEnableTimingHeaderValue 1 ; #Recommend an integer. Client HTTP header value that triggers debug timing to take place. 
    set st_enableInsertResponseHeader 1 ; #1 = enabled, 0 = disabled. Insert response HTTP header named $st_serverTimingHeaderName with server-timing data. 
    set st_enableRemoteLog 1 ; #1 = enabled, 0 = disabled
    set st_enableLocalLog 1 ; #1 = enabled, 0 = disabled !MONITOR CPU AFTER ENABLING!
    set st_remoteLoggingPool logging-pool ; #Name of LTM pool to use for remote logging servers 
    set st_remoteLogProtocol UDP ; #UDP or TCP
    set st_globalStringLimit 100 ; #How many characters to collect from user-supplied HTTP values like HTTP host, version, referrer. 
    set st_uriStringLimit 600 ; #How many characters to collect from HTTP value of URI
    set st_serverTimingHeaderName Server-Timing ; #specify the HTTP response header name to be inserted.
    set st_iruleBlockResponseCode 403 ; #append an HTTP status code to the iRule block log. 
    set st_asmBlockResponseCode 403 ; #append an HTTP status code to the ASM block log. 
    ###User-Edit Variables end###

    #Don't edit these system variables 
    set st_FLOW_INIT [clock clicks -milliseconds]
    set st_tcpID [TMM::cmp_unit][clock clicks]
    set st_CLIENT_ACCEPTED 0
    set st_CLIENTSSL_CLIENTHELLO 0
    set st_CLIENTSSL_HANDSHAKE 0 
    set st_http_request_count 0
    set st_HTTP_REQUEST 0 
    set st_ASM_REQUEST_DONE 0 
    set st_LB_SELECTED 0 
    set st_HTTP_REQUEST_RELEASE 0 
    set st_SERVER_CONNECTED 0 
    set st_SERVERSSL_CLIENTHELLO_SEND 0 
    set st_SERVERSSL_HANDSHAKE 0 
    set st_HTTP_RESPONSE 0 
    set st_HTTP_RESPONSE_RELEASE 0
    set st_debugTiming 0
    set st_triggerInsertHeader 0
    set st_triggerLogging 0   
}
}
when CLIENT_ACCEPTED priority 10 {
    catch { 
    set st_CLIENT_ACCEPTED [clock clicks -milliseconds] 
    set st_hsl [HSL::open -proto $st_remoteLogProtocol -pool $st_remoteLoggingPool]
    }
}
when CLIENTSSL_CLIENTHELLO {
    catch { set st_CLIENTSSL_CLIENTHELLO [clock clicks -milliseconds] }
}
when CLIENTSSL_HANDSHAKE {
    catch { set st_CLIENTSSL_HANDSHAKE [clock clicks -milliseconds] }
}

when HTTP_REQUEST priority 10 {
catch {
#Check if this HTTP request indicates further timing events should be collected. 
#Currently all HTTP requests with the enable timings header will be collected although this could be modified in the future to a sampling %. 
if { $st_enableLogWithoutHeader equals 1 or [HTTP::header value $st_clientEnableTimingHeaderName ] equals $st_clientEnableTimingHeaderValue } {
    set st_debugTiming 1
    incr st_http_request_count
    set st_HTTP_REQUEST [clock clicks -milliseconds]
    if { $st_enableRemoteLog equals 1 or $st_enableLocalLog equals 1 } {
        set st_triggerLogging 1  
        set st_virtual_server [virtual name]
        set st_http_host [string range [HTTP::host] 0 $st_globalStringLimit]
        set st_http_uri [string range [HTTP::uri] 0 $st_uriStringLimit]
        set st_http_method [string range [HTTP::method] 0 $st_globalStringLimit]
        set st_http_referrer [string range [HTTP::header "Referer"] 0 $st_globalStringLimit]
        set st_http_content_type [string range [HTTP::header "Content-Type"] 0 $st_globalStringLimit]
        set st_http_user_agent [string range [HTTP::header "User-Agent"] 0 $st_globalStringLimit]
        set st_http_version [string range [HTTP::version] 0 $st_globalStringLimit]
        set st_vip [IP::local_addr]
        if { [HTTP::header Content-Length] > 0 } then {
            set st_req_length [string range [HTTP::header "Content-Length"] 0 $st_globalStringLimit]
        } else {
            set st_req_length 0
        }
    }
} 

if { [HTTP::header value $st_clientEnableTimingHeaderName ] equals $st_clientEnableTimingHeaderValue } {
    set st_triggerInsertHeader 1
}

#If HTTP request does not match above conditionals in this event, exit gracefully. 
return 
} 
}

#Requires ASM profile to have iRule events enabled to populate data. It wont cause failures if its disabled in the ASM policy and still uncommented here but it will cause stat collection to be skipped.   
when ASM_REQUEST_DONE {
    catch { if { $st_debugTiming equals 1 } { set st_ASM_REQUEST_DONE [clock clicks -milliseconds] } }
}
when LB_SELECTED {
    catch { 
    if { $st_debugTiming equals 1 } { set st_LB_SELECTED [clock clicks -milliseconds] } 
    set st_pool [LB::server]
    } 
}
when SERVER_CONNECTED {
    catch { if { $st_debugTiming equals 1 } { set st_SERVER_CONNECTED [clock clicks -milliseconds] } }
}
when SERVERSSL_CLIENTHELLO_SEND {
    catch { if { $st_debugTiming equals 1 } { set st_SERVERSSL_CLIENTHELLO_SEND [clock clicks -milliseconds] } } 
}
when SERVERSSL_HANDSHAKE {
    catch { if { $st_debugTiming equals 1 } { set st_SERVERSSL_HANDSHAKE [clock clicks -milliseconds] } } 
}
when HTTP_REQUEST_RELEASE {
    catch { if { $st_debugTiming equals 1 } { set st_HTTP_REQUEST_RELEASE [clock clicks -milliseconds] } }
}
when HTTP_RESPONSE priority 10 {
    catch {
    if { $st_debugTiming equals 1 } {
        set st_HTTP_RESPONSE [clock clicks -milliseconds] 
        #If logging is enabled, collect helpful HTTP Response values. Uses $st_globalStringLimit to prevent large string abuse. 
        if { $st_enableRemoteLog equals 1 or $st_enableLocalLog equals 1 } {
            set st_http_status [string range [HTTP::status] 0 $st_globalStringLimit]
            if { [HTTP::header Content-Length] > 0 } then {
                set st_res_length [string range [HTTP::header "Content-Length"] 0 $st_globalStringLimit]
            } else {
                set st_res_length 0
            }
        }
    }
    } 
}

when HTTP_REQUEST priority 1000 {
    #Run at priority 1000 (very last) to see if another iRule has responded to the HTTP request. If so, send a log with the request data we have.
    #Exit gracefully if request does not contain required server timing enable header.
    catch {
    if { $st_debugTiming equals 0 } {
    return
    }

    #If another iRule has responded to this request, calculate the stats we have collected so far and send a partial log. 
    if {[HTTP::has_responded]} {
    
    # Log additional connection level stats if this is the first http request In this TCP session. 
    if { $st_http_request_count equals 1 } {

        set st_a [expr { $st_CLIENT_ACCEPTED - $st_FLOW_INIT } ] ; #measure time spent in Client TCP 3WHS. 
        set st_b [expr { $st_CLIENTSSL_HANDSHAKE - $st_CLIENTSSL_CLIENTHELLO } ] ; #measure time spent in client side ssl handshake.
        
        if { $st_enableRemoteLog equals 1 and $st_triggerLogging equals 1 } { 
            HSL::send $st_hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$st_a\",cTLS=\"$st_b\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",vs=\"$st_virtual_server\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",statusCode=\"$st_iruleBlockResponseCode\",vip=\"$st_vip\",iRuleBlock=\"True\"" 
        } 
        
        if { $st_enableLocalLog equals 1 and $st_triggerLogging equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$st_a\",cTLS=\"$st_b\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",vs=\"$st_virtual_server\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",statusCode=\"$st_iruleBlockResponseCode\",vip=\"$st_vip\",iRuleBlock=\"True\""
        } 
} else {
        #Only log request Level stats when this is not the first http Request in the TCP session 
        if { $st_enableRemoteLog equals 1 and $st_triggerLogging equals 1 } { 
            HSL::send $st_hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",vs=\"$st_virtual_server\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",statusCode=\"$st_iruleBlockResponseCode\",vip=\"$st_vip\",iRuleBlock=\"True\""
        }
        
        if { $st_enableLocalLog equals 1 and $st_triggerLogging equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",vs=\"$st_virtual_server\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",statusCode=\"$st_iruleBlockResponseCode\",vip=\"$st_vip\",iRuleBlock=\"True\""
        }
        }
    #Clean up variables for next HTTP request incase there is TCP reuse. 
    #Dont edit these system Variables 
    set st_FLOW_INIT [clock clicks -milliseconds]
    set st_CLIENT_ACCEPTED 0
    set st_CLIENTSSL_CLIENTHELLO 0
    set st_CLIENTSSL_HANDSHAKE 0 
    set st_HTTP_REQUEST 0 
    set st_ASM_REQUEST_DONE 0 
    set st_HTTP_REQUEST_RELEASE 0 
    set st_SERVER_CONNECTED 0 
    set st_SERVERSSL_CLIENTHELLO_SEND 0 
    set st_SERVERSSL_HANDSHAKE 0  
    set st_HTTP_RESPONSE 0 
    set st_HTTP_RESPONSE_RELEASE 0
    set st_debugTiming 0
    set st_triggerInsertHeader 0
    set st_triggerLogging 0  
     }

}
}

when ASM_REQUEST_BLOCKING {
    #Requires ASM policy "raise iRule event" setting to be enabled in ASM policy. This event is raised when ASM has triggered a block action for the request. If so, send a log with the request data we have.
    #Exit gracefully if request does not contain required server timing enable header.
    catch {
    if { $st_debugTiming equals 0 } {
    return
    }
    # Log additional connection level stats if this is the first http request In this TCP session. 
    if { $st_http_request_count equals 1 } {

        set st_a [expr { $st_CLIENT_ACCEPTED - $st_FLOW_INIT } ] ; #measure time spent in Client TCP 3WHS. 
        set st_b [expr { $st_CLIENTSSL_HANDSHAKE - $st_CLIENTSSL_CLIENTHELLO } ] ; #measure time spent in client side ssl handshake.
        set st_c [expr { $st_ASM_REQUEST_DONE - $st_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.
        
        if { $st_enableRemoteLog equals 1 and $st_triggerLogging equals 1 } { 
            HSL::send $st_hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$st_a\",cTLS=\"$st_b\",f5Req=\"$st_c\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",vs=\"$st_virtual_server\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",statusCode=\"$st_asmBlockResponseCode\",vip=\"$st_vip\",asmBlock=\"True\"" 
        } 
        
        if { $st_enableLocalLog equals 1 and $st_triggerLogging equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$st_a\",cTLS=\"$st_b\",f5Req=\"$st_c\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",vs=\"$st_virtual_server\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",statusCode=\"$st_asmBlockResponseCode\",vip=\"$st_vip\",asmBlock=\"True\""
        } 
} else {
        set st_c [expr { $st_ASM_REQUEST_DONE - $st_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.

        #Only log request Level stats when this is not the first http Request in the TCP session 
        if { $st_enableRemoteLog equals 1 and $st_triggerLogging equals 1 } { 
            HSL::send $st_hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$st_c\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",vs=\"$st_virtual_server\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",statusCode=\"$st_asmBlockResponseCode\",vip=\"$st_vip\",asmBlock=\"True\""
        }
        
        if { $st_enableLocalLog equals 1 and $st_triggerLogging equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$st_c\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",vs=\"$st_virtual_server\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",statusCode=\"$st_asmBlockResponseCode\",vip=\"$st_vip\",asmBlock=\"True\""
        }
        }
    #Clean up variables for next HTTP request incase there is TCP reuse. 
    #Dont edit these system Variables 
    set st_FLOW_INIT [clock clicks -milliseconds]
    set st_CLIENT_ACCEPTED 0
    set st_CLIENTSSL_CLIENTHELLO 0
    set st_CLIENTSSL_HANDSHAKE 0 
    set st_HTTP_REQUEST 0 
    set st_ASM_REQUEST_DONE 0 
    set st_HTTP_REQUEST_RELEASE 0 
    set st_SERVER_CONNECTED 0 
    set st_SERVERSSL_CLIENTHELLO_SEND 0 
    set st_SERVERSSL_HANDSHAKE 0  
    set st_HTTP_RESPONSE 0 
    set st_HTTP_RESPONSE_RELEASE 0
    set st_debugTiming 0
    set st_triggerInsertHeader 0
    set st_triggerLogging 0  
     }
}
when HTTP_RESPONSE_RELEASE {
    #Exit gracefully if request does not contain required server timing enable header.
    catch {
    if { $st_debugTiming equals 0 } {
    return
    }

    set st_HTTP_RESPONSE_RELEASE [clock clicks -milliseconds]

    # catch if important stats are missing and exit gracefully
    if { ($st_HTTP_REQUEST_RELEASE equals 0) || ($st_ASM_REQUEST_DONE equals 0 ) } {
        #Check if local logging is enabled before error messages are logged. 
        if { $st_enableLocalLog equals 1 and $st_triggerLogging equals 1 } {
        log local0. "Stats Collection Skipped. Request likely blocked or ASM bypassed,tcpID=$st_tcpID,Start_Client_IP=[IP::client_addr],Start_Client_Port=[TCP::client_port]" 
        }
        return 
    }

    # Log additional connection level stats if this is the first http request In this TCP session. 
    if { $st_http_request_count equals 1 } {

        set st_a [expr { $st_CLIENT_ACCEPTED - $st_FLOW_INIT } ] ; #measure time spent in Client TCP 3WHS. 
        set st_b [expr { $st_CLIENTSSL_HANDSHAKE - $st_CLIENTSSL_CLIENTHELLO } ] ; #measure time spent in client side ssl handshake.
        set st_c [expr { $st_ASM_REQUEST_DONE - $st_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time. 
        set st_d [expr { $st_SERVER_CONNECTED - $st_LB_SELECTED } ] ; #measure time spent in Server TCP 3WHS.
        set st_e [expr { $st_SERVERSSL_HANDSHAKE - $st_SERVERSSL_CLIENTHELLO_SEND } ] ; #measure time spent in side ssl handshake.
        set st_f [expr { $st_HTTP_RESPONSE - $st_HTTP_REQUEST_RELEASE } ] ; #measure time spent in pool HTTP response latency.
        set st_g [expr { $st_HTTP_RESPONSE_RELEASE - $st_HTTP_RESPONSE } ] ; #measure time spent in F5 HTTP response processing time. 
        set st_overhead [expr { $st_c + $st_g } ] ; #Combine HTTP Request and Response F5 processing time 

        
        if { $st_enableInsertResponseHeader equals 1 and $st_triggerInsertHeader equals 1 } { 
            #Insert Server-Timing HTTP header into the HTTP response. Formatting per https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing. These labels can be adjusted as needed.   
            HTTP::header insert $st_serverTimingHeaderName "waf, overhead;dur=$st_overhead, origin;dur=$st_f, client-ssl;dur=$st_b, server-ssl;dur=$st_e, client-tcp;dur=$st_a, server-tcp;dur=$st_d" 
        }   

        if { $st_enableRemoteLog equals 1 and $st_triggerLogging equals 1 } { 
            HSL::send $st_hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$st_a\",cTLS=\"$st_b\",f5Req=\"$st_c\",sTCP=\"$st_d\",sTLS=\"$st_e\",poolRes=\"$st_f\",f5Res=\"$st_g\",overhead=\"$st_overhead\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",statusCode=\"$st_http_status\",resLength=\"$st_res_length\",vs=\"$st_virtual_server\",pool=\"$st_pool\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",vip=\"$st_vip\"" 
        } 
        
        if { $st_enableLocalLog equals 1 and $st_triggerLogging equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$st_a\",cTLS=\"$st_b\",f5Req=\"$st_c\",sTCP=\"$st_d\",sTLS=\"$st_e\",poolRes=\"$st_f\",f5Res=\"$st_g\",overhead=\"$st_overhead\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",statusCode=\"$st_http_status\",resLength=\"$st_res_length\",vs=\"$st_virtual_server\",pool=\"$st_pool\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",vip=\"$st_vip\"" 
        } 
} else {
        #Only log request Level stats when this is not the first http Request in the TCP session.
        set st_c [expr { $st_ASM_REQUEST_DONE - $st_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.
        set st_f [expr { $st_HTTP_RESPONSE - $st_HTTP_REQUEST_RELEASE } ] ; #measure time spent in pool HTTP response latency.
        set st_g [expr { $st_HTTP_RESPONSE_RELEASE - $st_HTTP_RESPONSE } ] ; #measure time spent in F5 HTTP response processing time.
        set st_overhead [expr { $st_c + $st_g } ] ; #Combine HTTP Request and Response F5 processing time 

        if { $st_enableInsertResponseHeader equals 1 and $st_triggerInsertHeader equals 1 } { 
            #Insert Server-Timing HTTP header into the HTTP response. Formatting per https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing. These labels can be adjusted as needed.   
            HTTP::header insert $st_serverTimingHeaderName "waf, overhead;dur=$st_overhead, origin;dur=$st_f" 
        } 
        
        if { $st_enableRemoteLog equals 1 and $st_triggerLogging equals 1 } { 
            HSL::send $st_hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$st_c\",poolRes=\"$st_f\",f5Res=\"$st_g\",overhead=\"$st_overhead\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",statusCode=\"$st_http_status\",resLength=\"$st_res_length\",vs=\"$st_virtual_server\",pool=\"$st_pool\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",vip=\"$st_vip\"" 
        }
        
        if { $st_enableLocalLog equals 1 and $st_triggerLogging equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$st_tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$st_c\",poolRes=\"$st_f\",f5Res=\"$st_g\",overhead=\"$st_overhead\",uri=\"$st_http_uri\",host=\"$st_http_host\",method=\"$st_http_method\",reqLength=\"$st_req_length\",statusCode=\"$st_http_status\",resLength=\"$st_res_length\",vs=\"$st_virtual_server\",pool=\"$st_pool\",referrer=\"$st_http_referrer\",cType=\"$st_http_content_type\",userAgent=\"$st_http_user_agent\",httpv=\"$st_http_version\",vip=\"$st_vip\"" 
        }
        }
        

    #Clean up variables for next HTTP request incase there is TCP reuse. 
    #Dont edit these system Variables 
    set st_FLOW_INIT [clock clicks -milliseconds]
    set st_CLIENT_ACCEPTED 0
    set st_CLIENTSSL_CLIENTHELLO 0
    set st_CLIENTSSL_HANDSHAKE 0 
    set st_HTTP_REQUEST 0 
    set st_ASM_REQUEST_DONE 0 
    set st_HTTP_REQUEST_RELEASE 0 
    set st_SERVER_CONNECTED 0 
    set st_SERVERSSL_CLIENTHELLO_SEND 0 
    set st_SERVERSSL_HANDSHAKE 0  
    set st_HTTP_RESPONSE 0 
    set st_HTTP_RESPONSE_RELEASE 0
    set st_debugTiming 0
    set st_triggerInsertHeader 0
    set st_triggerLogging 0  
}
}