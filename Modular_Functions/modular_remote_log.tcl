## Made with heart by Matt Stovall 2/2024. 
## version 0.1 

## This iRule: 
##  1.  Checks for presence od existing variables containing information populated from other modular iRules. 
##  2.  Generates and transmits a TCP or UDP messages using those variables. The three conditions to trigger sending the logs are:
##      a. When the HTTP response has been received from the pool member (successful transaction)
##      b. When the HTTP request has been blocked by ASM WAF
##      c. When the HTTP request is being responded to by a different iRule 

## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. 
## See https://github.com/megamattzilla/iRules/blob/master/Modular_Functions/README.md for more details

## Modular iRule dependency: 
##      requires:   data_collector
##      optional:   measure_latency 
##      optional:   traceparent

when FLOW_INIT  {
catch {

    ###User-Edit Variables start###
    #set rl_logSampleRate 0 ; #Sample rate (Integer) of logging performed. Value of 0= log all requests. Other values= log every x request. 
    set rl_remoteLoggingPool logging-pool ; #Name of LTM pool to use for remote logging servers 
    set rl_remoteLogProtocol UDP ; #UDP or TCP
    set rl_iruleBlockResponseCode 403 ; #HTTP status code to report when an iRule block has taken place  
    set rl_asmBlockResponseCode 403 ; #HTTP status code to report when an ASM/WAF block has taken place
    set rl_debugLog 1 ;#1 = debug logging enabled, 0 = debug logging disabled. 
    ###User-Edit Variables end###
}
}
when CLIENT_ACCEPTED priority 540 {
    catch { set rl_hsl [HSL::open -proto $rl_remoteLogProtocol -pool $rl_remoteLoggingPool] }
}

## Run at priority 1000 to be the very last iRule to execute in this event.
when HTTP_REQUEST priority 1000 {


    ## First Log Generation Check - If another iRule has responded to this request, check the variables we have collected so far and send a partial log.
    if {[HTTP::has_responded]} {
        ##TODO: reorder these statements so that if its the 2nd HTTP request only the mml_b variables would be set. otherwise its the same 
        ## Check if data collector iRule has run for this HTTP request.
                if { !([info exists dc_vip]) && !([string length $dc_vip] >= 1) } { 
                    ## If $dc_vip value does not exist or is less than 1 character, exit gracefully.
                    if  { $rl_debugLog equals 1} { log local0. "No data collector values found for request: [IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port] [HTTP::method] [HTTP::uri]" }
                    return 
                }
                
        ## Set base log string with fields from data_collector iRule. All HTTP requests will have these fields logged.  
        set rl_logstring "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$dc_tcpID\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",uri=\"$dc_http_uri\",host=\"$dc_http_host\",method=\"$dc_http_method\",reqLength=\"$dc_req_length\",vs=\"$dc_virtual_server\",referrer=\"$dc_http_referrer\",cType=\"$dc_http_content_type\",userAgent=\"$dc_http_user_agent\",httpv=\"$dc_http_version\",statusCode=\"$rl_iruleBlockResponseCode\",vip=\"$dc_vip\",iRuleBlock=\"True\""

        ## First Check for additional information to log: Is first HTTP request in TCP session? 
        if { [HTTP::request_num] == 1 } { 
            
            ## This is the first HTTP request in this TCP session. Add extra TCP latency information into the log string.
            append rl_logstring ",tcpReuse=\"False\"" 
            
            ## Second Check for additional information to log: Has latency data been collected? 
            if { ([info exists mml_b]) && ([string length $mml_b] >= 1) } { 
            
                ## Add latency data to the log string
                append rl_logstring ",cTCP=\"$mml_a\",cTLS=\"$mml_b\""
            }
        } else { 
           ## This is NOT the first HTTP request in this TCP session.
           append rl_logstring ",tcpReuse=\"True\""  
        }
        ## Third Check for additional information to log: Has traceparent ID been generated?
        if { ([info exists traceparent]) && ([string length $traceparent] >= 1) } {
            append rl_logstring ",traceparent=\"$traceparent\""
        }

        ## Send the log to remote log server 
        HSL::send $rl_hsl $rl_logstring
        if  { $rl_debugLog equals 1} { log local0. "$rl_logstring" }

    }
}


# when ASM_REQUEST_BLOCKING {

#     ## Second Log Generation Check - ASM Block
#     #Requires ASM policy "raise iRule event" setting to be enabled in ASM policy. This event is raised when ASM has triggered a block action for the request. If so, send a log with the request data we have.
#     #Exit gracefully if request does not contain required server timing enable header.
#     catch {
#     if { $rl_debugTiming equals 0 } {
#     return
#     }
#     # Log additional connection level stats if this is the first http request In this TCP session. 
#     if { $rl_http_req_count equals 1 } {

#         set rl_a [expr { $rl_CLIENT_ACCEPTED - $rl_FLOW_INIT } ] ; #measure time spent in Client TCP 3WHS. 
#         set rl_b [expr { $rl_CLIENTSSL_HANDSHAKE - $rl_CLIENTSSL_CLIENTHELLO } ] ; #measure time spent in client side ssl handshake.
#         set rl_c [expr { $rl_ASM_REQUErl_DONE - $rl_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.
        
#         if { $rl_enableRemoteLog equals 1 and $rl_triggerLogging equals 1 } { 
#             HSL::send $rl_hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$rl_tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$rl_a\",cTLS=\"$rl_b\",f5Req=\"$rl_c\",uri=\"$rl_http_uri\",host=\"$rl_http_host\",method=\"$rl_http_method\",reqLength=\"$rl_req_length\",vs=\"$rl_virtual_server\",referrer=\"$rl_http_referrer\",cType=\"$rl_http_content_type\",userAgent=\"$rl_http_user_agent\",httpv=\"$rl_http_version\",statusCode=\"$rl_asmBlockResponseCode\",vip=\"$rl_vip\",asmBlock=\"True\"" 
#         } 
        
#         if { $rl_enableLocalLog equals 1 and $rl_triggerLogging equals 1 } { 
#             log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$rl_tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$rl_a\",cTLS=\"$rl_b\",f5Req=\"$rl_c\",uri=\"$rl_http_uri\",host=\"$rl_http_host\",method=\"$rl_http_method\",reqLength=\"$rl_req_length\",vs=\"$rl_virtual_server\",referrer=\"$rl_http_referrer\",cType=\"$rl_http_content_type\",userAgent=\"$rl_http_user_agent\",httpv=\"$rl_http_version\",statusCode=\"$rl_asmBlockResponseCode\",vip=\"$rl_vip\",asmBlock=\"True\""
#         } 
# } else {
#         set rl_c [expr { $rl_ASM_REQUErl_DONE - $rl_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.

#         #Only log request Level stats when this is not the first http Request in the TCP session 
#         if { $rl_enableRemoteLog equals 1 and $rl_triggerLogging equals 1 } { 
#             HSL::send $rl_hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$rl_tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$rl_c\",uri=\"$rl_http_uri\",host=\"$rl_http_host\",method=\"$rl_http_method\",reqLength=\"$rl_req_length\",vs=\"$rl_virtual_server\",referrer=\"$rl_http_referrer\",cType=\"$rl_http_content_type\",userAgent=\"$rl_http_user_agent\",httpv=\"$rl_http_version\",statusCode=\"$rl_asmBlockResponseCode\",vip=\"$rl_vip\",asmBlock=\"True\""
#         }
        
#         if { $rl_enableLocalLog equals 1 and $rl_triggerLogging equals 1 } { 
#             log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$rl_tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$rl_c\",uri=\"$rl_http_uri\",host=\"$rl_http_host\",method=\"$rl_http_method\",reqLength=\"$rl_req_length\",vs=\"$rl_virtual_server\",referrer=\"$rl_http_referrer\",cType=\"$rl_http_content_type\",userAgent=\"$rl_http_user_agent\",httpv=\"$rl_http_version\",statusCode=\"$rl_asmBlockResponseCode\",vip=\"$rl_vip\",asmBlock=\"True\""
#         }
#         }
#      }
# }

# when HTTP_RESPONSE_RELEASE {
#     #Exit gracefully if request does not contain required server timing enable header.
#     catch {
#     if { $rl_debugTiming equals 0 } {
#     return
#     }

#     set rl_HTTP_RESPONSE_RELEASE [clock clicks -milliseconds]

#     # catch if important stats are missing and exit gracefully
#     if { ($rl_HTTP_REQUErl_RELEASE equals 0) || ($rl_ASM_REQUErl_DONE equals 0 ) } {
#         #Check if local logging is enabled before error messages are logged. 
#         if { $rl_enableLocalLog equals 1 and $rl_triggerLogging equals 1 } {
#         log local0. "Stats Collection Skipped. Request likely blocked or ASM bypassed,tcpID=$rl_tcpID,Start_Client_IP=[IP::client_addr],Start_Client_Port=[TCP::client_port]" 
#         }
#         return 
#     }

#     # Log additional connection level stats if this is the first http request In this TCP session. 
#     if { $rl_http_req_count equals 1 } {

#         set rl_a [expr { $rl_CLIENT_ACCEPTED - $rl_FLOW_INIT } ] ; #measure time spent in Client TCP 3WHS. 
#         set rl_b [expr { $rl_CLIENTSSL_HANDSHAKE - $rl_CLIENTSSL_CLIENTHELLO } ] ; #measure time spent in client side ssl handshake.
#         set rl_c [expr { $rl_ASM_REQUErl_DONE - $rl_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time. 
#         set rl_d [expr { $rl_SERVER_CONNECTED - $rl_LB_SELECTED } ] ; #measure time spent in Server TCP 3WHS.
#         set rl_e [expr { $rl_SERVERSSL_HANDSHAKE - $rl_SERVERSSL_CLIENTHELLO_SEND } ] ; #measure time spent in side ssl handshake.
#         set rl_f [expr { $rl_HTTP_RESPONSE - $rl_HTTP_REQUErl_RELEASE } ] ; #measure time spent in pool HTTP response latency.
#         set rl_g [expr { $rl_HTTP_RESPONSE_RELEASE - $rl_HTTP_RESPONSE } ] ; #measure time spent in F5 HTTP response processing time. 
#         set rl_overhead [expr { $rl_c + $rl_g } ] ; #Combine HTTP Request and Response F5 processing time 

        
#         if { $rl_enableInsertResponseHeader equals 1 and $rl_triggerInsertHeader equals 1 } { 
#             #Insert Server-Timing HTTP header into the HTTP response. Formatting per https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing. These labels can be adjusted as needed.   
#             HTTP::header insert $rl_serverTimingHeaderName "waf, overhead;dur=$rl_overhead, origin;dur=$rl_f, client-ssl;dur=$rl_b, server-ssl;dur=$rl_e, client-tcp;dur=$rl_a, server-tcp;dur=$rl_d" 
#         }   

#         if { $rl_enableRemoteLog equals 1 and $rl_triggerLogging equals 1 } { 
#             HSL::send $rl_hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$rl_tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$rl_a\",cTLS=\"$rl_b\",f5Req=\"$rl_c\",sTCP=\"$rl_d\",sTLS=\"$rl_e\",poolRes=\"$rl_f\",f5Res=\"$rl_g\",overhead=\"$rl_overhead\",uri=\"$rl_http_uri\",host=\"$rl_http_host\",method=\"$rl_http_method\",reqLength=\"$rl_req_length\",statusCode=\"$rl_http_status\",resLength=\"$rl_res_length\",vs=\"$rl_virtual_server\",pool=\"$rl_pool\",referrer=\"$rl_http_referrer\",cType=\"$rl_http_content_type\",userAgent=\"$rl_http_user_agent\",httpv=\"$rl_http_version\",vip=\"$rl_vip\"" 
#         } 
        
#         if { $rl_enableLocalLog equals 1 and $rl_triggerLogging equals 1 } { 
#             log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$rl_tcpID\",tcpReuse=\"False\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",cTCP=\"$rl_a\",cTLS=\"$rl_b\",f5Req=\"$rl_c\",sTCP=\"$rl_d\",sTLS=\"$rl_e\",poolRes=\"$rl_f\",f5Res=\"$rl_g\",overhead=\"$rl_overhead\",uri=\"$rl_http_uri\",host=\"$rl_http_host\",method=\"$rl_http_method\",reqLength=\"$rl_req_length\",statusCode=\"$rl_http_status\",resLength=\"$rl_res_length\",vs=\"$rl_virtual_server\",pool=\"$rl_pool\",referrer=\"$rl_http_referrer\",cType=\"$rl_http_content_type\",userAgent=\"$rl_http_user_agent\",httpv=\"$rl_http_version\",vip=\"$rl_vip\"" 
#         } 
# } else {
#         #Only log request Level stats when this is not the first http Request in the TCP session.
#         set rl_c [expr { $rl_ASM_REQUErl_DONE - $rl_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.
#         set rl_f [expr { $rl_HTTP_RESPONSE - $rl_HTTP_REQUErl_RELEASE } ] ; #measure time spent in pool HTTP response latency.
#         set rl_g [expr { $rl_HTTP_RESPONSE_RELEASE - $rl_HTTP_RESPONSE } ] ; #measure time spent in F5 HTTP response processing time.
#         set rl_overhead [expr { $rl_c + $rl_g } ] ; #Combine HTTP Request and Response F5 processing time 

#         if { $rl_enableInsertResponseHeader equals 1 and $rl_triggerInsertHeader equals 1 } { 
#             #Insert Server-Timing HTTP header into the HTTP response. Formatting per https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing. These labels can be adjusted as needed.   
#             HTTP::header insert $rl_serverTimingHeaderName "waf, overhead;dur=$rl_overhead, origin;dur=$rl_f" 
#         } 
        
#         if { $rl_enableRemoteLog equals 1 and $rl_triggerLogging equals 1 } { 
#             HSL::send $rl_hsl "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$rl_tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$rl_c\",poolRes=\"$rl_f\",f5Res=\"$rl_g\",overhead=\"$rl_overhead\",uri=\"$rl_http_uri\",host=\"$rl_http_host\",method=\"$rl_http_method\",reqLength=\"$rl_req_length\",statusCode=\"$rl_http_status\",resLength=\"$rl_res_length\",vs=\"$rl_virtual_server\",pool=\"$rl_pool\",referrer=\"$rl_http_referrer\",cType=\"$rl_http_content_type\",userAgent=\"$rl_http_user_agent\",httpv=\"$rl_http_version\",vip=\"$rl_vip\"" 
#         }
        
#         if { $rl_enableLocalLog equals 1 and $rl_triggerLogging equals 1 } { 
#             log local0. "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$rl_tcpID\",tcpReuse=\"True\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",f5Req=\"$rl_c\",poolRes=\"$rl_f\",f5Res=\"$rl_g\",overhead=\"$rl_overhead\",uri=\"$rl_http_uri\",host=\"$rl_http_host\",method=\"$rl_http_method\",reqLength=\"$rl_req_length\",statusCode=\"$rl_http_status\",resLength=\"$rl_res_length\",vs=\"$rl_virtual_server\",pool=\"$rl_pool\",referrer=\"$rl_http_referrer\",cType=\"$rl_http_content_type\",userAgent=\"$rl_http_user_agent\",httpv=\"$rl_http_version\",vip=\"$rl_vip\"" 
#         }
#         }
 
# }
# }