## Made with heart by Matt Stovall 2/2024. 
## version 1.1.0 Updated 12/2024

## This iRule calculates latency at various TCP, TLS, HTTP, ASM events and calculates the latency between each stage. Others iRules can query this information stored in variables. 
#All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. 
#See https://github.com/megamattzilla/iRules/blob/master/Modular_Functions/README.md for more details

## Modular iRule dependency: none

## Requirements: 
## Event CLIENTSSL_HANDSHAKE requires clientssl profile on virtual
## Event SERVERSSL_HANDSHAKE requires serverssl profile on virtual
## Requires ASM profile on virtual server with iRule events enabled (this is common for most ASM deployments)

when FLOW_INIT priority 10 {
if {[catch {
    ###User-Edit Variables start###
    set mml_measureWithoutHeader 1 ; #1 = Measure all HTTP requests, 0 = only measure latency for HTTP requests that contain HTTP header name $mml_clientEnableTimingHeaderName and header value $mml_clientEnableTimingHeaderValue
    set mml_clientEnableTimingHeaderName X-Enable-Server-Timing ; #Client HTTP header name that triggers debug timing to take place.
    set mml_clientEnableTimingHeaderValue 1 ; #Recommend an integer. Client HTTP header value that triggers debug timing to take place. 
    set mml_enableInsertResponseHeader 1 ; #1 = enabled, 0 = disabled. Insert response HTTP header named $mml_serverTimingHeaderName with server-timing data. 
    set mml_serverTimingHeaderName Server-Timing ; #specify the HTTP response header name to be inserted.
    set mml_serverTimingLabel f5 ; #specify the root label name in server timing value. Example: "Server-Timing: $thisvalue, overhead;dur=1, origin;dur=2"
    ###User-Edit Variables end###

    #Don't edit these system variables 
    set mml_FLOW_INIT [clock clicks -milliseconds]
    set mml_CLIENT_ACCEPTED 0
    set mml_CLIENTSSL_CLIENTHELLO 0
    set mml_CLIENTSSL_HANDSHAKE 0 
    set mml_HTTP_REQUEST 0 
    set mml_ASM_REQUEST_DONE 0 
    set mml_LB_SELECTED 0 
    set mml_HTTP_REQUEST_RELEASE 0 
    set mml_SERVER_CONNECTED 0 
    set mml_SERVERSSL_CLIENTHELLO_SEND 0 
    set mml_SERVERSSL_HANDSHAKE 0 
    set mml_HTTP_RESPONSE 0 
    set mml_HTTP_RESPONSE_RELEASE 0
    set mml_debugTiming 0
} err]} { log local0.error "Error in FLOW_INIT: $err" }
}

when CLIENT_ACCEPTED priority 10 {
catch { set mml_CLIENT_ACCEPTED [clock clicks -milliseconds] }
}
when CLIENTSSL_CLIENTHELLO priority 10 {
catch { set mml_CLIENTSSL_CLIENTHELLO [clock clicks -milliseconds] }
}
when CLIENTSSL_HANDSHAKE priority 10 {
catch { set mml_CLIENTSSL_HANDSHAKE [clock clicks -milliseconds] }
}

when HTTP_REQUEST priority 10 {
if {[catch {
#Check if this HTTP request indicates further timing events should be collected. 
if { $mml_measureWithoutHeader equals 1 or [HTTP::header value $mml_clientEnableTimingHeaderName ] equals $mml_clientEnableTimingHeaderValue } {
    set mml_debugTiming 1
    set mml_HTTP_REQUEST [clock clicks -milliseconds]
} 
} err]} { log local0.error "Error in HTTP_REQUEST: $err" }
}


#Requires ASM profile to have iRule events enabled to populate data. It wont cause failures if its disabled in the ASM policy and still uncommented here but it will cause stat collection to be skipped.   
when ASM_REQUEST_DONE priority 10  {
catch { if { $mml_debugTiming equals 1 } { set mml_ASM_REQUEST_DONE [clock clicks -milliseconds] } }
}
when LB_SELECTED priority 10  {
catch { if { $mml_debugTiming equals 1 } { set mml_LB_SELECTED [clock clicks -milliseconds] } }
}
when SERVER_CONNECTED priority 10  {
catch { if { $mml_debugTiming equals 1 } { set mml_SERVER_CONNECTED [clock clicks -milliseconds] } }
}
when SERVERSSL_CLIENTHELLO_SEND priority 10  {
catch { if { $mml_debugTiming equals 1 } { set mml_SERVERSSL_CLIENTHELLO_SEND [clock clicks -milliseconds] } } 
}
when SERVERSSL_HANDSHAKE priority 10  {
catch { if { $mml_debugTiming equals 1 } { set mml_SERVERSSL_HANDSHAKE [clock clicks -milliseconds] } }
}
when HTTP_REQUEST_RELEASE priority 10  {
catch { if { $mml_debugTiming equals 1 } { set mml_HTTP_REQUEST_RELEASE [clock clicks -milliseconds] } }
}
when HTTP_RESPONSE priority 10 {
catch { if { $mml_debugTiming equals 1 } { set mml_HTTP_RESPONSE [clock clicks -milliseconds] } }
}

when HTTP_REQUEST priority 999 {
if {[catch {
    #Run at priority 999 (almost very last) to see if another iRule has responded to the HTTP request. If so, generate partial latency data. 
    
    #Exit gracefully if request does not contain required server timing enable header.
    if { $mml_debugTiming equals 0 } {
    return
    }

    #If another iRule has responded to this request, calculate the stats we have collected so far.
    if {[HTTP::has_responded]} {
    
    # Check if this is the first http request In this TCP session. If its a re-used TCP session, we have no helpful latency data for this request and just exit gracefully. 
    if { [HTTP::request_num] == 1 } {

        set mml_a [expr { $mml_CLIENT_ACCEPTED - $mml_FLOW_INIT } ] ; #measure time spent in Client TCP 3WHS. 
        set mml_b [expr { $mml_CLIENTSSL_HANDSHAKE - $mml_CLIENTSSL_CLIENTHELLO } ] ; #measure time spent in client side ssl handshake.
    }
    #Clean up variables for next HTTP request incase there is TCP reuse. 
    #Dont edit these system Variables 
    set mml_FLOW_INIT [clock clicks -milliseconds]
    set mml_CLIENT_ACCEPTED 0
    set mml_CLIENTSSL_CLIENTHELLO 0
    set mml_CLIENTSSL_HANDSHAKE 0 
    set mml_HTTP_REQUEST 0 
    set mml_ASM_REQUEST_DONE 0 
    set mml_HTTP_REQUEST_RELEASE 0 
    set mml_SERVER_CONNECTED 0 
    set mml_SERVERSSL_CLIENTHELLO_SEND 0 
    set mml_SERVERSSL_HANDSHAKE 0  
    set mml_HTTP_RESPONSE 0 
    set mml_HTTP_RESPONSE_RELEASE 0
    set mml_debugTiming 0
     }

} err]} { log local0.error "Error in HTTP_REQUEST: $err" }
}


when ASM_REQUEST_BLOCKING priority 520 {
if {[catch {
    #Requires ASM policy "raise iRule event" setting to be enabled in ASM policy. This event is raised when ASM has triggered a block action for the request.
    #Exit gracefully if request does not contain required server timing enable header.

    if { $mml_debugTiming equals 0 } {
    return
    }
    # collect additional connection level stats if this is the first http request In this TCP session. 
    if { [HTTP::request_num] == 1} {

        set mml_a [expr { $mml_CLIENT_ACCEPTED - $mml_FLOW_INIT } ] ; #measure time spent in Client TCP 3WHS. 
        set mml_b [expr { $mml_CLIENTSSL_HANDSHAKE - $mml_CLIENTSSL_CLIENTHELLO } ] ; #measure time spent in client side ssl handshake.
        set mml_c [expr { $mml_ASM_REQUEST_DONE - $mml_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.

} else {
        set mml_c [expr { $mml_ASM_REQUEST_DONE - $mml_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.
        }
    #Clean up variables for next HTTP request incase there is TCP reuse. 
    #Dont edit these system Variables 
    set mml_FLOW_INIT [clock clicks -milliseconds]
    set mml_CLIENT_ACCEPTED 0
    set mml_CLIENTSSL_CLIENTHELLO 0
    set mml_CLIENTSSL_HANDSHAKE 0 
    set mml_HTTP_REQUEST 0 
    set mml_ASM_REQUEST_DONE 0 
    set mml_HTTP_REQUEST_RELEASE 0 
    set mml_SERVER_CONNECTED 0 
    set mml_SERVERSSL_CLIENTHELLO_SEND 0 
    set mml_SERVERSSL_HANDSHAKE 0  
    set mml_HTTP_RESPONSE 0 
    set mml_HTTP_RESPONSE_RELEASE 0
    set mml_debugTiming 0
} err]} { log local0.error "Error in ASM_REQUEST_BLOCKING: $err" }
}
when HTTP_RESPONSE_RELEASE priority 520 {
if {[catch {
    #Exit gracefully if request does not contain required server timing enable header.

    if { $mml_debugTiming equals 0 } {
    return
    }

    set mml_HTTP_RESPONSE_RELEASE [clock clicks -milliseconds]

    # catch if important stats are missing and exit gracefully
    if { ($mml_HTTP_REQUEST_RELEASE equals 0) || ($mml_ASM_REQUEST_DONE equals 0 ) } {

        log local0. "Stats Collection Skipped. Request likely blocked or ASM bypassed,Start_Client_IP=[IP::client_addr],Start_Client_Port=[TCP::client_port]" 

        return 
    }

    # Collect additional connection level stats if this is the first http request In this TCP session. 
    if { [HTTP::request_num] == 1 } {

        set mml_a [expr { $mml_CLIENT_ACCEPTED - $mml_FLOW_INIT } ] ; #measure time spent in Client TCP 3WHS. 
        set mml_b [expr { $mml_CLIENTSSL_HANDSHAKE - $mml_CLIENTSSL_CLIENTHELLO } ] ; #measure time spent in client side ssl handshake.
        set mml_c [expr { $mml_ASM_REQUEST_DONE - $mml_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time. 
        set mml_d [expr { $mml_SERVER_CONNECTED - $mml_LB_SELECTED } ] ; #measure time spent in Server TCP 3WHS.
        set mml_e [expr { $mml_SERVERSSL_HANDSHAKE - $mml_SERVERSSL_CLIENTHELLO_SEND } ] ; #measure time spent in side ssl handshake.
        set mml_f [expr { $mml_HTTP_RESPONSE - $mml_HTTP_REQUEST_RELEASE } ] ; #measure time spent in pool HTTP response latency.
        set mml_g [expr { $mml_HTTP_RESPONSE_RELEASE - $mml_HTTP_RESPONSE } ] ; #measure time spent in F5 HTTP response processing time. 
        set mml_overhead [expr { $mml_c + $mml_g } ] ; #Combine HTTP Request and Response F5 processing time 

        if { $mml_enableInsertResponseHeader equals 1 } { 
            #Insert Server-Timing HTTP header into the HTTP response. Formatting per https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing. These labels can be adjusted as needed.   
            HTTP::header insert $mml_serverTimingHeaderName "$mml_serverTimingLabel, overhead;dur=$mml_overhead, origin;dur=$mml_f, client-ssl;dur=$mml_b, server-ssl;dur=$mml_e, client-tcp;dur=$mml_a, server-tcp;dur=$mml_d" 
        }  
} else {
        #Only Collect request Level stats when this is not the first http Request in the TCP session.
        set mml_c [expr { $mml_ASM_REQUEST_DONE - $mml_HTTP_REQUEST } ] ; #measure time spent in F5 HTTP request processing time.
        set mml_f [expr { $mml_HTTP_RESPONSE - $mml_HTTP_REQUEST_RELEASE } ] ; #measure time spent in pool HTTP response latency.
        set mml_g [expr { $mml_HTTP_RESPONSE_RELEASE - $mml_HTTP_RESPONSE } ] ; #measure time spent in F5 HTTP response processing time.
        set mml_overhead [expr { $mml_c + $mml_g } ] ; #Combine HTTP Request and Response F5 processing time 

        if { $mml_enableInsertResponseHeader equals 1 } { 
            #Insert Server-Timing HTTP header into the HTTP response. Formatting per https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing. These labels can be adjusted as needed.   
            HTTP::header insert $mml_serverTimingHeaderName "$mml_serverTimingLabel, overhead;dur=$mml_overhead, origin;dur=$mml_f" 
        } 
    #Clean up variables for next HTTP request incase there is TCP reuse. 
    #Dont edit these system Variables 
    set mml_FLOW_INIT [clock clicks -milliseconds]
    set mml_CLIENT_ACCEPTED 0
    set mml_CLIENTSSL_CLIENTHELLO 0
    set mml_CLIENTSSL_HANDSHAKE 0 
    set mml_HTTP_REQUEST 0 
    set mml_ASM_REQUEST_DONE 0 
    set mml_HTTP_REQUEST_RELEASE 0 
    set mml_SERVER_CONNECTED 0 
    set mml_SERVERSSL_CLIENTHELLO_SEND 0 
    set mml_SERVERSSL_HANDSHAKE 0  
    set mml_HTTP_RESPONSE 0 
    set mml_HTTP_RESPONSE_RELEASE 0
    set mml_debugTiming 0
}
} err]} { log local0.error "Error in HTTP_RESPONSE_RELEASE: $err" }
}
