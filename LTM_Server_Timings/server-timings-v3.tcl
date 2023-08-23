# Made with ❤ by Matt Stovall and Shane Levin @ F5 6/2023.
#This iRule collect timing information at multiple events to determine latency between many client and server side events.
#All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. 
#Requirements: 
#Event CLIENTSSL_HANDSHAKE requires clientssl profile on virtual
#Event SERVERSSL_HANDSHAKE requires serverssl profile on virtual
#Requires ASM profile on virtual server with iRule events enabled (this is common for most ASM deployments)

### Proc ### Do Not Edit Start ###
proc cleanupVars cleanupVars {
    #Dont edit these system Variables 
    set FLOW_INIT [clock clicks -milliseconds]
    set CLIENT_ACCEPTED 0
    set CLIENTSSL_CLIENTHELLO 0
    set CLIENTSSL_HANDSHAKE 0 
    set HTTP_REQUEST 0 
    set ASM_REQUEST_DONE 0 
    set HTTP_REQUEST_RELEASE 0 
    set SERVER_CONNECTED 0 
    set SERVERSSL_CLIENTHELLO_SEND 0 
    set SERVERSSL_HANDSHAKE 0  
    set HTTP_RESPONSE 0 
    set HTTP_RESPONSE_RELEASE 0
}
### Proc ### Do Not Edit End ###


when FLOW_INIT {
catch {

    ###User-Edit Variables start###
    set insert_response_header 1 ; #1 = enabled, 0 = disabled 
    set remote_log 1 ; #1 = enabled, 0 = disabled
    set local_log 1 ; #1 = enabled, 0 = disabled !MONITOR CPU AFTER ENABLING!
    set remote_log_pool logging-pool ; #Name of LTM pool to use for remote logging servers 
    set remote_log_protocol UDP ; #UDP or TCP
    set string_limit 100 ; #How many characters to collect from user-supplied HTTP values like HTTP host, version, referrer. 
    set uri_string_limit 600 ; #How many characters to collect from HTTP value of URI
    ###User-Edit Variables end###

    #Don't edit these system variables 
    set FLOW_INIT [clock clicks -milliseconds]
    set tcpID [TMM::cmp_unit][clock clicks]
    set CLIENT_ACCEPTED 0
    set CLIENTSSL_CLIENTHELLO 0
    set CLIENTSSL_HANDSHAKE 0 
    set http_request_count 0
    set HTTP_REQUEST 0 
    set ASM_REQUEST_DONE 0 
    set LB_SELECTED 0 
    set HTTP_REQUEST_RELEASE 0 
    set SERVER_CONNECTED 0 
    set SERVERSSL_CLIENTHELLO_SEND 0 
    set SERVERSSL_HANDSHAKE 0 
    set HTTP_RESPONSE 0 
    set HTTP_RESPONSE_RELEASE 0
    set debugTiming 0  
}
}
when CLIENT_ACCEPTED priority 10 {
    catch { 
    set CLIENT_ACCEPTED [clock clicks -milliseconds] 
    set hsl [HSL::open -proto $remote_log_protocol -pool $remote_log_pool]
    }
}
when CLIENTSSL_CLIENTHELLO {
    catch { set CLIENTSSL_CLIENTHELLO [clock clicks -milliseconds] }
}
when CLIENTSSL_HANDSHAKE {
    catch { set CLIENTSSL_HANDSHAKE [clock clicks -milliseconds] }
}
when HTTP_REQUEST priority 10 {
catch {
#Check if this HTTP request indicates further timing events should be collected. 
#Currently all HTTP requests with the enable timings header will be collected altough this could be modified in the future to a sampling %. 
if { [HTTP::header value "X-Enable-Server-Timing"] equals 1 } {
    set debugTiming 1
    incr http_request_count
    set HTTP_REQUEST [clock clicks -milliseconds]
    
    
    #If logging is enabled, collect helpful HTTP Request values. Uses $string_limit to prevent large string abuse. 
    if { $remote_log equals 1 or $local_log equals 1 } {
        set virtual_server [virtual name]
        set http_host [string range [HTTP::host] 0 $string_limit]
        set http_uri [string range [HTTP::uri] 0 $uri_string_limit]
        set http_method [string range [HTTP::method] 0 $string_limit]
        set http_referrer [string range [HTTP::header "Referer"] 0 $string_limit]
        set http_content_type [string range [HTTP::header "Content-Type"] 0 $string_limit]
        set http_user_agent [string range [HTTP::header "User-Agent"] 0 $string_limit]
        set http_version [string range [HTTP::version] 0 $string_limit]
        set vip [IP::local_addr]
        if { [HTTP::header Content-Length] > 0 } then {
            set req_length [string range [HTTP::header "Content-Length"] 0 $string_limit]
        } else {
            set req_length 0
        }
    }
} else {
    #Exit gracefully if request does not contain required server timing enable header. 
    return 
}
}
}
#Requires ASM profile to have iRule events enabled to populate data. It wont cause failures if its disabled in the ASM policy and still uncommented here but it will cause stat collection to be skipped.   
when ASM_REQUEST_DONE {
    catch { if { $debugTiming equals 1 } { set ASM_REQUEST_DONE [clock clicks -milliseconds] } }
}
when LB_SELECTED {
    catch { 
    if { $debugTiming equals 1 } { set LB_SELECTED [clock clicks -milliseconds] } 
    set pool [LB::server]
    } 
}
when SERVER_CONNECTED {
    catch { if { $debugTiming equals 1 } { set SERVER_CONNECTED [clock clicks -milliseconds] } }
}
when SERVERSSL_CLIENTHELLO_SEND {
    catch { if { $debugTiming equals 1 } { set SERVERSSL_CLIENTHELLO_SEND [clock clicks -milliseconds] } } 
}
when SERVERSSL_HANDSHAKE {
    catch { if { $debugTiming equals 1 } { set SERVERSSL_HANDSHAKE [clock clicks -milliseconds] } } 
}
when HTTP_REQUEST_RELEASE {
    catch { if { $debugTiming equals 1 } { set HTTP_REQUEST_RELEASE [clock clicks -milliseconds] } }
}
when HTTP_RESPONSE priority 10 {
    catch {
    if { $debugTiming equals 1 } {
        set HTTP_RESPONSE [clock clicks -milliseconds] 
        #If logging is enabled, collect helpful HTTP Response values. Uses $string_limit to prevent large string abuse. 
        if { $remote_log equals 1 or $local_log equals 1 } {
            set http_status [string range [HTTP::status] 0 $string_limit]
            if { [HTTP::header Content-Length] > 0 } then {
                set res_length [string range [HTTP::header "Content-Length"] 0 $string_limit]
            } else {
                set res_length 0
            }
        }
    }
    } 
}

when HTTP_REQUEST priority 1000 {
    #Run at priority 1000 (very last) to see if another iRule has responded to the HTTP request. If so, send a log with the request data we have.
    #Exit gracefully if request does not contain required server timing enable header.
    catch {
    if { $debugTiming equals 0 } {
    return
    }

    #If another iRule has responded to this request, calculate the stats we have collected so far and send a partial log. 
    if {[HTTP::has_responded]} {
    
    # Log additional connection level stats if this is the first http request In this TCP session. 
    if { $http_request_count equals 1 } {

        set a [expr { $CLIENT_ACCEPTED - $FLOW_INIT } ] ; #measure time spent in Client TCP 3WHS. 
        set b [expr { $CLIENTSSL_HANDSHAKE - $CLIENTSSL_CLIENTHELLO } ] ; #measure time spent in client side ssl handshake.
        
        if { $remote_log equals 1 } { 
            HSL::send $hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$a\",cTLS=\"$b\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",vs=\"$virtual_server\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\",iRuleBlock=\"True\"" 
        } 
        
        if { $local_log equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$a\",cTLS=\"$b\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",vs=\"$virtual_server\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\",iRuleBlock=\"True\""
        } 
} else {
        #Only log request Level stats when this is not the first http Request in the TCP session 
        if { $remote_log equals 1 } { 
            HSL::send $hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",vs=\"$virtual_server\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\",iRuleBlock=\"True\""
        }
        
        if { $local_log equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",vs=\"$virtual_server\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\",iRuleBlock=\"True\""
        }
        }
    #Clean up variables for next HTTP request incase there is TCP reuse. 
    call cleanupVars cleanupVars
    #Set debug timing to 0 (disable) so that remaining events in this iRule will not execute further. I avoided using event disable here incase there are other iRules executing at these events.  
    set debugTiming 0
     }

}
}

when ASM_REQUEST_BLOCKING {
    #Requires ASM policy "raise iRule event" setting to be enabled in ASM policy. This event is raised when ASM has triggered a block action for the request. If so, send a log with the request data we have.
    #Exit gracefully if request does not contain required server timing enable header.
    catch {
    if { $debugTiming equals 0 } {
    return
    }
    # Log additional connection level stats if this is the first http request In this TCP session. 
    if { $http_request_count equals 1 } {

        set a [expr { $CLIENT_ACCEPTED - $FLOW_INIT } ] ; #measure time spent in Client TCP 3WHS. 
        set b [expr { $CLIENTSSL_HANDSHAKE - $CLIENTSSL_CLIENTHELLO } ] ; #measure time spent in client side ssl handshake.
        set c [expr { $ASM_REQUEST_DONE - $HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.
        
        if { $remote_log equals 1 } { 
            HSL::send $hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$a\",cTLS=\"$b\",f5Req=\"$c\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",vs=\"$virtual_server\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\",asmBlock=\"True\"" 
        } 
        
        if { $local_log equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$a\",cTLS=\"$b\",f5Req=\"$c\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",vs=\"$virtual_server\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\",asmBlock=\"True\""
        } 
} else {
        set c [expr { $ASM_REQUEST_DONE - $HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.

        #Only log request Level stats when this is not the first http Request in the TCP session 
        if { $remote_log equals 1 } { 
            HSL::send $hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$c\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",vs=\"$virtual_server\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\",asmBlock=\"True\""
        }
        
        if { $local_log equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$c\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",vs=\"$virtual_server\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\",asmBlock=\"True\""
        }
        }
    #Clean up variables for next HTTP request incase there is TCP reuse. 
    call cleanupVars cleanupVars
    #Set debug timing to 0 (disable) so that remaining events in this iRule will not execute further. I avoided using event disable here incase there are other iRules executing at these events.  
    set debugTiming 0
     }
}
when HTTP_RESPONSE_RELEASE {
    #Exit gracefully if request does not contain required server timing enable header.
    catch {
    if { $debugTiming equals 0 } {
    return
    }

    set HTTP_RESPONSE_RELEASE [clock clicks -milliseconds]

    # catch if important stats are missing and exit gracefully
    if { ($HTTP_REQUEST_RELEASE equals 0) || ($ASM_REQUEST_DONE equals 0 ) } {
        #Check if local logging is enabled before error messages are logged. 
        if { $local_log equals 1 } {
        log local0. "Stats Collection Skipped. Request likely blocked or ASM bypassed,tcpID=$tcpID,Start_Client_IP=[IP::client_addr],Start_Client_Port=[TCP::client_port]" 
        }
        return 
    }

    # Log additional connection level stats if this is the first http request In this TCP session. 
    if { $http_request_count equals 1 } {

        set a [expr { $CLIENT_ACCEPTED - $FLOW_INIT } ] ; #measure time spent in Client TCP 3WHS. 
        set b [expr { $CLIENTSSL_HANDSHAKE - $CLIENTSSL_CLIENTHELLO } ] ; #measure time spent in client side ssl handshake.
        set c [expr { $ASM_REQUEST_DONE - $HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time. 
        set d [expr { $SERVER_CONNECTED - $LB_SELECTED } ] ; #measure time spent in Server TCP 3WHS.
        set e [expr { $SERVERSSL_HANDSHAKE - $SERVERSSL_CLIENTHELLO_SEND } ] ; #measure time spent in side ssl handshake.
        set f [expr { $HTTP_RESPONSE - $HTTP_REQUEST_RELEASE } ] ; #measure time spent in pool HTTP response latency.
        set g [expr { $HTTP_RESPONSE_RELEASE - $HTTP_RESPONSE } ] ; #measure time spent in F5 HTTP response processing time. 
        set overhead [expr { $c + $g } ] ; #Combine HTTP Request and Response F5 processing time 

        
        if { $insert_response_header equals 1 } { 
            #Insert Server-Timing HTTP header into the HTTP response. Formatting per https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing. These labels can be adjusted as needed.   
            HTTP::header insert Server-Timing "waf, overhead;dur=$overhead, origin;dur=$f, client-ssl;dur=$b, server-ssl;dur=$e, client-tcp;dur=$a, server-tcp;dur=$d" 
        }   

        if { $remote_log equals 1 } { 
            HSL::send $hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$a\",cTLS=\"$b\",f5Req=\"$c\",sTCP=\"$d\",sTLS=\"$e\",poolRes=\"$f\",f5Res=\"$g\",overhead=\"$overhead\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",statusCode=\"$http_status\",resLength=\"$res_length\",vs=\"$virtual_server\",pool=\"$pool\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\"" 
        } 
        
        if { $local_log equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$a\",cTLS=\"$b\",f5Req=\"$c\",sTCP=\"$d\",sTLS=\"$e\",poolRes=\"$f\",f5Res=\"$g\",overhead=\"$overhead\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",statusCode=\"$http_status\",resLength=\"$res_length\",vs=\"$virtual_server\",pool=\"$pool\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\"" 
        } 
} else {
        #Only log request Level stats when this is not the first http Request in the TCP session.
        set c [expr { $ASM_REQUEST_DONE - $HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.
        set f [expr { $HTTP_RESPONSE - $HTTP_REQUEST_RELEASE } ] ; #measure time spent in pool HTTP response latency.
        set g [expr { $HTTP_RESPONSE_RELEASE - $HTTP_RESPONSE } ] ; #measure time spent in F5 HTTP response processing time.
        set overhead [expr { $c + $g } ] ; #Combine HTTP Request and Response F5 processing time 

        if { $insert_response_header equals 1 } { 
            #Insert Server-Timing HTTP header into the HTTP response. Formatting per https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing. These labels can be adjusted as needed.   
            HTTP::header insert Server-Timing "waf, overhead;dur=$overhead, origin;dur=$f" 
        } 
        
        if { $remote_log equals 1 } { 
            HSL::send $hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$c\",poolRes=\"$f\",f5Res=\"$g\",overhead=\"$overhead\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",statusCode=\"$http_status\",resLength=\"$res_length\",vs=\"$virtual_server\",pool=\"$pool\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\"" 
        }
        
        if { $local_log equals 1 } { 
            log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$c\",poolRes=\"$f\",f5Res=\"$g\",overhead=\"$overhead\",uri=\"$http_uri\",host=\"$http_host\",method=\"$http_method\",reqLength=\"$req_length\",statusCode=\"$http_status\",resLength=\"$res_length\",vs=\"$virtual_server\",pool=\"$pool\",referrer=\"$http_referrer\",cType=\"$http_content_type\",userAgent=\"$http_user_agent\",httpv=\"$http_version\",vip=\"$vip\"" 
        }
        }
        

    #Clean up variables for next HTTP request incase there is TCP reuse. 
    call cleanupVars cleanupVars
}
}