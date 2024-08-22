## Made with heart by Matt Stovall 2/2024. 
## version 1.0

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
    set rl_skip2xxlogging 0                 ; #(Boolean) 0 = log all requests, 1 = only log 3xx, 4xx, 5xx HTTP response codes. 
    set rl_remoteLoggingPool logging-pool   ; #(String) Name of LTM pool to use for remote logging servers 
    set rl_remoteLogProtocol UDP            ; #(String) UDP or TCP
    set rl_iruleBlockResponseCode 403       ; #(Integer) HTTP status code to report when an iRule block has taken place  
    set rl_asmBlockResponseCode 403         ; #(Integer) HTTP status code to report when an ASM/WAF block has taken place
    set rl_debugLog 1                       ; #(Boolean) 0 = debug logging disabled, 1 = debug logging enabled, 
    ###User-Edit Variables end###
}
}
when CLIENT_ACCEPTED priority 1000 {
    catch { set rl_hsl [HSL::open -proto $rl_remoteLogProtocol -pool $rl_remoteLoggingPool] }
}

## Run at priority 1000 to be the very last iRule to execute in this event.
when HTTP_REQUEST priority 1000 {
catch {
    ## Check if data collector iRule has run for this HTTP request. 
    if { !([info exists dc_vip]) } { 
        ## If $dc_vip value does not exist exit gracefully.
        if  { $rl_debugLog equals 1 } { log local0. "No data collector values found for request: [IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port]" }
        set rl_exit 1
        return 
    } 

    ## Set base log string with fields from data_collector iRule. All HTTP requests will have these fields logged.  
    set rl_logstring "hostname=\"$static::tcl_platform(machine)\",tcpID=\"$dc_tcpID\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",uri=\"$dc_http_uri\",host=\"$dc_http_host\",method=\"$dc_http_method\",reqLength=\"$dc_req_length\",vs=\"$dc_virtual_server\",referrer=\"$dc_http_referrer\",cType=\"$dc_http_content_type\",userAgent=\"$dc_http_user_agent\",httpv=\"$dc_http_version\""

    ## First Log Generation Check - If another iRule has responded to this request, check the variables we have collected so far and send a partial log.
    if {[HTTP::has_responded]} {
                        
        ## Append base log string with fields indicating an iRule block has occurred.  
        append rl_logstring ",statusCode=\"$rl_iruleBlockResponseCode\",vip=\"$dc_vip\",iRuleBlock=\"True\""

        ## First Check for additional information to log: Is first HTTP request in TCP session? 
        if { [HTTP::request_num] == 1 } { 
            
            ## This is the first HTTP request in this TCP session. Add extra TCP latency information into the log string.
            append rl_logstring ",tcpReuse=\"False\"" 
            
            ## Second Check for additional information to log: Has latency data been collected? 
            if { ([info exists mml_b]) && ([string length $mml_b] >= 1) } { 
            
                ## Add TCP + TLS latency data to the log string
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
}


when ASM_REQUEST_BLOCKING priority 1000 {
catch {
    ## Second Log Generation Check - If ASM blocked this request, check the variables we have collected so far and send a partial log.
    ## Requires ASM policy "raise iRule event" setting to be enabled in ASM policy. 

    ## Check if this event should exit due to missing data.  
    if { ([info exists rl_exit]) } {
    return
    }

    ## Append base log string with fields indicating an ASM block has occurred.  
    append rl_logstring ",statusCode=\"$rl_asmBlockResponseCode\",vip=\"$dc_vip\",asmBlock=\"True\""

    ## First Check for additional information to log: Is first HTTP request in TCP session? 
    if { [HTTP::request_num] == 1 } { 
        
        ## This is the first HTTP request in this TCP session. Add extra TCP latency information into the log string.
        append rl_logstring ",tcpReuse=\"False\"" 
        
        ## Second Check for additional information to log: Has latency data been collected? 
        if { ([info exists mml_b]) && ([string length $mml_b] >= 1) } { 
        
            ## Add TCP + TLS + request latency data to the log string
            append rl_logstring ",cTCP=\"$mml_a\",cTLS=\"$mml_b\",f5Req=\"$mml_c\""
        }
    } else { 
        ## This is NOT the first HTTP request in this TCP session.
        append rl_logstring ",tcpReuse=\"True\""  

        ## Second Check for additional information to log: Has latency data been collected? 
        if { ([info exists mml_c]) && ([string length $mml_c] >= 1) } {        
            
            ## Add request-only latency data to the log string
            append rl_logstring ",f5Req=\"$mml_c\""
        }
        }

        ## Third Check for additional information to log: Has traceparent ID been generated?
        if { ([info exists traceparent]) && ([string length $traceparent] >= 1) } {
            append rl_logstring ",traceparent=\"$traceparent\""
        }

        ## Send the log to remote log server 
        HSL::send $rl_hsl $rl_logstring
        if  { $rl_debugLog equals 1} { log local0. "$rl_logstring" }

        ## Set flag indicating ASM has blocked request and a log was sent.
        set rl_exit 1 
}
}

when HTTP_RESPONSE_RELEASE priority 1000 {
catch {
    ## Third Log Generation Check - HTTP response is about to sent to client.

    ## Check if this event should exit due to missing data or ASM blocked request.  
    if { ([info exists rl_exit]) } {
    return
    }

    ## If 2xx logging is enabled and if this is a 2xx request exit gracefully. 
    if { ($rl_skip2xxlogging == 1) && ( $dc_http_status starts_with 2) } {
    return
    }

    ## Add pool and HTTP response data to log string
    append rl_logstring ",statusCode=\"$dc_http_status\",http.response_content_length=\"$dc_res_length\",pool=\"$dc_pool\""

    ## First Check for additional information to log: Is first HTTP request in TCP session? 
    if { [HTTP::request_num] == 1 } { 
        
        ## This is the first HTTP request in this TCP session. Add extra TCP latency information into the log string.
        append rl_logstring ",tcpReuse=\"False\"" 

        ## Second Check for additional information to log: Has latency data been collected? 
        if { ([info exists mml_b]) && ([string length $mml_b] >= 1) } { 
        
            ## Add TCP + TLS + request + response latency data to the log string
            append rl_logstring ",cTCP=\"$mml_a\",cTLS=\"$mml_b\",f5Req=\"$mml_c\",sTCP=\"$mml_d\",sTLS=\"$mml_e\",poolRes=\"$mml_f\",f5Res=\"$mml_g\",overhead=\"$mml_overhead\""
        }
    } else { 
        ## This is NOT the first HTTP request in this TCP session.
        append rl_logstring ",tcpReuse=\"True\""  

        ## Second Check for additional information to log: Has latency data been collected? 
        if { ([info exists mml_c]) && ([string length $mml_c] >= 1) } {        
            
            ## Add request + response latency data to the log string
            append rl_logstring ",f5Req=\"$mml_c\",poolRes=\"$mml_f\",f5Res=\"$mml_g\",overhead=\"$mml_overhead\""
        }
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