## Made with care by Matt Stovall 3/2024.
## Version 0.9
## This iRule: 
##  1.   TBD 

## TBD: All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of iss_ has been added to each variable to make them globally unique. 
## See https://github.com/megamattzilla/iRules/blob/master/SSLO_Sideband/README.md for more details

## Requirements: 
##  1. TBD

when HTTP_REQUEST priority 300 { 

    ###User-Edit Variables start###
    set static::iss_sidebandPool "mcafee-api-scp" ; #LTM pool containing nodes to send the sideband HTTP request
    set iss_overridePoolPort 2083 ; #0 = Disabled. Use pools port (0) or override with your own port number.
    set iss_requiredHeaderName "X-SWEB-AuthCustID" ; #Required HTTP header for this sideband to function.  
    set iss_requiredHeaderValue "42" ; #Required HTTP value for this sideband to function.  
    set iss_debugLogging 1 ; #0 = Disabled, 1 = Enabled
    set iss_errorLoggingString "CRIT:" ; #Keyword string to be included in error logs. 
    set iss_sidebandHostHeader "sideband.example.com" ; #HTTP host header value to use in the sideband call.
    set iss_sidebandRetryCount 3 ; #Number of times to retry the sideband pool when any failure is observed. 
    set iss_sidebandConnectTimeout 50 ; #the time in milliseconds to wait to establish the connection to the sideband pool member.    
    set iss_sidebandIdleTimeout 30 ; #the time in seconds to leave the connection open if it is unused.
    set iss_sidebandSendTimeout 50 ; #the time in milliseconds to transmit the HTTP request to the sideband pool member.  
    set iss_sidebandReceiveTimeout 30 ; #the time in milliseconds to wait for the HTTP response to be received from the sideband pool member. 
    ###User-Edit Variables end###

    ## Check if required HTTP header name and value is present. Exit gracefully if not found. 
    if { !([HTTP::header value $iss_requiredHeaderName] equals "$iss_requiredHeaderValue")} {
        if { $iss_debugLogging == 1 } { log local0. "DEBUG: Skipping SCP sideband" }   
        return
    }

    ## Set variable containing explicit proxy request URI (this contains full http://fqdn/uri per the RFC) 
    set iss_httpURI [HTTP::uri] 

    ## Set variable containing FQDN 
    set iss_httpHost [HTTP::host]

    ## Set variables for common SCP header values
    set iss_X_SWEB_AuthVersion [HTTP::header value X-SWEB-AuthVersion]
    set iss_X_SWEB_AuthCustID [HTTP::header value X-SWEB-AuthCustID]
    set iss_X_SWEB_AuthUser [HTTP::header value X-SWEB-AuthUser]
    set iss_X_SWEB_AuthGroups [HTTP::header value X-SWEB-AuthGroups]
    set iss_X_SWEB_AuthTS [HTTP::header value X-SWEB-AuthTS]
    set iss_X_SWEB_AuthToken [HTTP::header value X-SWEB-AuthToken]
    set iss_X_SWEB_ClientIP [HTTP::header value X-SWEB-ClientIP]


    ## Initialize variable to store decrypt decision (expecting bypass/intercept after lookup)
    set iss_decryptDecision 0 

    ## Start loop for retry. Set a loop control variable to 0     
    set iss_loop 0 
    
    ## While the loop control variable is less than $iss_sidebandRetryCount, keep looping. 
    while { $iss_loop < $iss_sidebandRetryCount } {
        ## Log Retry attempt (if debug logging is enabled.)
        if { $iss_debugLogging == 1 } { log local0. "DEBUG: starting sideband attempt [expr {$iss_loop + 1}] for $iss_httpHost" }      

        ## Check if sideband pool exists
        if { [catch { set iss_members [active_members -list $static::iss_sidebandPool]}] } { 
            log local0. "$iss_errorLoggingString LTM pool $static::iss_sidebandPool does not exist!"
            return 
        }

        ## Get the list of active members in the sideband pool  
        set iss_members [active_members -list $static::iss_sidebandPool] 

        ## Count the number of members  
        set iss_count [llength $iss_members]

        ## Check if there are any healthy nodes. If there is no healthy nodes, log and exit gracefully. 
        if { $iss_count equals 0 } { 
            log local0. "$iss_errorLoggingString no healthy nodes in sideband pool!" 
            return
            } else { 
            if { $iss_debugLogging == 1 } { log local0. "DEBUG: active members of $static::iss_sidebandPool pool is $iss_count" }    
            }
        
        ## Initialize iRule table entry for load balancing round robin pool members if it does not exist.
        table set -excl iss_poolRotatingIndex 0

        ## Lookup iRule table entry for load balancing round robin pool members.
        set iss_poolRotatingIndex [table lookup -notouch iss_poolRotatingIndex]

        ## If iRule table entry does not have a value within the range of expected values, reset the table to 0. 
         if {  !($iss_poolRotatingIndex >= 0) or !($iss_poolRotatingIndex <= $iss_count) } { 
            
            ## Set table entry for load balancing round robin pool members if it does not exist. 
            table set iss_poolRotatingIndex 0
            set iss_poolRotatingIndex 0 
            if { $iss_debugLogging == 1 } { log local0. "DEBUG: resetting round robin table for pool $static::iss_sidebandPool to 0" }  
        } 

        ## Check if pool port should be overwritten. 
        if { $iss_overridePoolPort > 0 } { 
            ## Format IP:port for the member that is selected. Override pool port.     
            set iss_memberToUse "[getfield [lindex $iss_members $iss_poolRotatingIndex] " " 1]:$iss_overridePoolPort"
        } else { 
            ## Format IP:port for the member that is selected. Using pools port number    
            set iss_memberToUse "[string map {" " ":"}[lindex $iss_members $iss_poolRotatingIndex]]" 
        }

        ## Increment rotating pool index variable 
        incr iss_poolRotatingIndex

        ## Update iRule table entry with new rotating index number
        if { $iss_poolRotatingIndex >= $iss_count } { 
            ## Reset rotating index to 0 now that the last pool member in the index has been used. 
            table set iss_poolRotatingIndex 0
        } else { 
            ## Use next pool member
            table set iss_poolRotatingIndex $iss_poolRotatingIndex
        }

        ## Open the TCP connection to the sideband pool member
        set iss_connID [connect -timeout $iss_sidebandConnectTimeout -idle $iss_sidebandIdleTimeout -status conn_status $iss_memberToUse] 

        ## Check if TCP connection was successful. If not, try again with a different pool member.  
        if { !($iss_connID contains "connect") } { 
            log local0. "$iss_errorLoggingString cannot connect sideband to $iss_memberToUse."
            
            ## This attempt has failed. Increment the loop control variable
            incr iss_loop
            
            ## If retry count has exceeded, log CRIT message, and stop looping. 
            if { $iss_loop >= $iss_sidebandRetryCount } { 
                log local0. "$iss_errorLoggingString sideband retry limit exceeded. Decrypting $iss_httpHost"
                break 
                } 
            ## If within the retry limit, start the retry loop again. 
            continue
        }
        
        ## Format HTTP Request to sideband with Host FQDN from the explicit proxy request  
        set iss_data "[HTTP::method] [HTTP::uri] HTTP/1.0\r\nX-SWEB-AuthVersion: $iss_X_SWEB_AuthVersion\r\nX-SWEB-AuthCustID: $iss_X_SWEB_AuthCustID\r\nX-SWEB-AuthUser: $iss_X_SWEB_AuthUser\r\nX-SWEB-AuthGroups: $iss_X_SWEB_AuthGroups\r\nX-SWEB-AuthTS: $iss_X_SWEB_AuthTS\r\nX-SWEB-AuthToken: $iss_X_SWEB_AuthToken\r\nX-SWEB-ClientIP: $iss_X_SWEB_ClientIP\r\n\r\n"
        
        ## Send HTTP Request to sideband pool member 
        set iss_sendBytes [send -timeout $iss_sidebandSendTimeout -status send_status $iss_connID $iss_data]

        ## Check HTTP Request was sent successfully 
        if { $iss_debugLogging == 1 } {  log local0. "DEBUG: Sent $iss_sendBytes bytes out of [string length $iss_data] bytes to $iss_memberToUse. Full Request was $iss_data" }
        if { !($iss_sendBytes == [string length $iss_data]) } { 
            log local0. "$iss_errorLoggingString unable to send sideband call to $iss_memberToUse. Sent $iss_sendBytes bytes out of [string length $iss_data] bytes"
            
            ## This attempt has failed. Increment the loop control variable
            incr iss_loop
            
            ## If retry count has exceeded, log CRIT message, and stop looping. 
            if { $iss_loop >= $iss_sidebandRetryCount } { 
                log local0. "$iss_errorLoggingString sideband retry limit exceeded. Decrypting $iss_httpHost"
                break 
                } 
            
            ## If within the retry limit, start the retry loop again. 
            continue
        }

        ## Check HTTP Response was received from sideband pool member
        set iss_recv_data [recv -peek -timeout $iss_sidebandReceiveTimeout -status recv_status $iss_connID]
        if { $iss_debugLogging == 1 } {  log local0. "DEBUG: Received Response: $iss_recv_data from $iss_memberToUse." }

        ## Check if response is empty
        if { [string length $iss_recv_data] <= 1 } { 
            log local0. "$iss_errorLoggingString empty response from $iss_memberToUse"
            
            ## This attempt has failed. Increment the loop control variable
            incr iss_loop
            
            ## If retry count has exceeded, log CRIT message, and stop looping. 
            if { $iss_loop >= $iss_sidebandRetryCount } { 
                log local0. "$iss_errorLoggingString sideband retry limit exceeded. Decrypting $iss_httpHost"
                break 
                } 
            
            ## If within the retry limit, start the retry loop again. 
            continue
        }
        
        ## Check if response contains a decrypted username. We assume a value greater than 5 characters is the decrypted username. 
        if {  !([string length [findstr [lsearch -inline [split $iss_recv_data "\r\n"] X-Authenticated-User*] ": " 2] ] >= 5)  } { 
            log local0. "$iss_errorLoggingString RECEIVE - invalid sideband response from $iss_memberToUse"
            
            ## This attempt has failed. Increment the loop control variable
            incr iss_loop
            
            ## If retry count has exceeded, log CRIT message, and stop looping. 
            if { $iss_loop >= $iss_sidebandRetryCount } { 
                log local0. "$iss_errorLoggingString RECEIVE - sideband retry limit exceeded. Decrypting $iss_httpHost"
                break 
                } 
            
            ## If within the retry limit, start the retry loop again. 
            continue
        
        } else { 
        
        if { $iss_debugLogging == 1 } {  log local0. "DEBUG: Found decrypted user: [findstr [lsearch -inline [split $iss_recv_data "\r\n"] X-Authenticated-User*] ": " 2] " }
        }
        
        ## Write sideband results to client HTTP request
        HTTP::header insert X-Authenticated-User [findstr [lsearch -inline [split $iss_recv_data "\r\n"] X-Authenticated-User*] ": " 2] 
        HTTP::header insert X-Authenticated-Groups [findstr [lsearch -inline [split $iss_recv_data "\r\n"] X-Authenticated-UserGroups*] ": " 2]
        
        ## Start Workaround to accommodate when X-CLIENT-IP is not set by client. Will re-visit later. 
        if {[HTTP::header exists X-SWEB-ClientIP]} {
            ## Use decrypted client IP value as X-Client-IP
            HTTP::header insert X-Client-IP [findstr [lsearch -inline [split $iss_recv_data "\r\n"] X-Client-IP*] ": " 2] 
        } else {
            ## Use source IP from IP header as X-Client-IP
            HTTP::header insert X-Client-IP [IP::client_addr]
        }
        ##End workaroud

        ## Removing All SCP Headers
        foreach X_SWEB [HTTP::header names] {
            if { $X_SWEB starts_with "X-SWEB" } { HTTP::header remove $X_SWEB }
        } 

    ## End retry loop on success
    break
    }
}