#Note: TCL clock clicks -milliseconds can only measure in increments of 1ms, so timing events in sub-millisecond increments does not work. 
#All sub-millisecond timing events are rounded to 1 millisecond. 
when HTTP_REQUEST priority 7 {
#Run at high priority (7). Check if Server-Timings metrics should be gathered for this HTTP request based on the existence of a debugging header. Replace X-Debug-Timing with your desired header name. 
if { [HTTP::header exists "X-Debug-Timing"] } {
    #Debugging header has been found. Initialize variables.  
    #Set variable for later iRule events to mark this HTTP request as needing timing metrics. 
    set debugTiming 1 
    set http_request_start_time 0
    set http_request_release_time 0 
    set http_response_start_time 0 
    set http_response_release_time 0 
    set http_request_send 0
    #Set variable indicating the full HTTP request has been received but not processed by LTM/iRules/ASM. 
    set http_request_start_time [clock clicks -milliseconds]
} else {
    #Debugging header was not found. Set debugTiming variable to 0 for this TCP session and exit gracefully.      
    set debugTiming 0 
    return
    }
}
when HTTP_REQUEST_RELEASE priority 7 {
#If debugTiming variable is equal to 1, collect timing metrics for this event.    
if { $debugTiming equals 1 } {
    set http_request_release_time [clock clicks -milliseconds]
    }
}
when HTTP_REQUEST_SEND priority 7 {
#If debugTiming variable is equal to 1, collect timing metrics for this event.    
if { $debugTiming equals 1 } {
  set http_request_send [clock clicks -milliseconds]
    }
}
when HTTP_RESPONSE priority 7 {
#If debugTiming variable is equal to 1, collect timing metrics for this event.    
if { $debugTiming equals 1 } {
    set http_response_start_time [clock clicks -milliseconds]
    }
}
when HTTP_RESPONSE_RELEASE priority 7 { 
#If debugTiming variable is equal to 1, collect timing metrics for this event.    
if { $debugTiming equals 1 } {
    set http_response_release_time [clock clicks -milliseconds]
    }
}
when HTTP_RESPONSE_RELEASE priority 1000 { 
#If debugTiming variable is equal to 1, collect timing metrics for this event. If any variable fails to exist because the event did not fire, exit gracefully (catch).      
if { $debugTiming equals 1 } {
    #Data Processing. Ideally this could be delegated to external system reading these raw variables.
    #Calculate HTTP Request processing time     
    catch { set request_time [expr { $http_request_release_time - $http_request_start_time } ] }
    #Calculate HTTP Response processing time
    catch { set response_time [expr { $http_response_release_time - $http_response_start_time } ] }
    #HTTP Request backend processing time
    catch { set backend_time [expr { $http_response_start_time - $http_request_send } ] } 

    #Correct 0ms metrics when timing happened within 1ms. Round 0ms to 1ms. 
    catch { if { $request_time equals 0 } { incr request_time  } } 
    catch { if { $response_time equals 0 } { incr response_time  } }
    catch { if { $backend_time equals 0 } { incr backend_time  } }

    #Uncomment below line for debug logging:
    #catch { log local0. "Request time: $request_time, Response time: $response_time, Backend Time: $backend_time, http_request_start_time: $http_request_start_time, http_request_release_time: $http_request_release_time, http_request_send: $http_request_send, http_response_start_time: $http_response_start_time, http_response_release_time: $http_response_release_time" }

    #Insert Server-Timings HTTP header into the HTTP response. Formatting per https://developer.    mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing. These labels can be adjusted as needed.   
    catch { HTTP::header insert Server-Timings "f5-request;dur=$request_time, f5-response;dur=$response_time, f5-backend;dur=$backend_time" } 
    }
}