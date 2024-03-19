## Made with care by Matt Stovall 3/2024.
## Version 0.5
## This iRule: 
##  1.   Collects HTTP information (HTTP host FQDN) from an explicit proxy HTTP request.
##  2.   Checks iRule table cache for this FQDN for a recent Bypass/Intercept decision from the sideband pool. 
##  3.   Makes a sideband HTTP call to a HTTP proxy with this FQDN information in the URI as a query string. (/ ?url=$FQDN).  
##  4.   Inspects HTTP response from the sideband pool (HTTP proxy) for HTTP headers indicating the explicit proxy request should be SSL intercepted. Caches that response. 
##  5.   Based on that response, send the explicit proxy HTTP request to the appropriate virtual server that either intercepts or bypasses SSL decryption. 

## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of is_ has been added to each variable to make them globally unique. 
## See https://github.com/megamattzilla/iRules/blob/master/SSLO_Sideband/README.md for more details

## Requirements: 
##  1. To be applied to a vip-targeting-vip which points to an explicit proxy virtual server.
##  2. Configure a LTM pool with your sideband pool members.
##  3. Configure those sideband pool members to reply with the Bypass/Intercept strings this iRule is looking for.   

when HTTP_REQUEST priority 200 { 

    ###User-Edit Variables start###
    set static::is_sidebandPool "mcafee-api" ; #LTM pool containing nodes to send the sideband HTTP request
    set is_debugLogging 1 ; #0 = Disabled, 1 = Enabled
    set is_errorLoggingString "CRIT:" ; #Keyword string to be included in error logs. 
    set is_cacheTimeout 3600 ; #Number of seconds to cache a bypass/intercept decision for a given FQDN. 
    set is_cachePurgeHeader "X-SSLO-URL-PURGE" ; #HTTP request header name that will purge the cache for a given FQDN
    set is_sslBypassVirtualServer "sslo_noAuth.app/sslo_noAuth-xp-4" ; #Virtual server path/name to send explicit proxy requests that should NOT be SSL intercepted. 
    set is_sidebandHostHeader "sideband.example.com" ; #HTTP host header value to use in the sideband call.
    set is_sidebandRetryCount 3 ; #Number of times to retry the sideband pool when any failure is observed. 
    set is_sidebandConnectTimeout 50 ; #the time in milliseconds to wait to establish the connection to the sideband pool member.    
    set is_sidebandIdleTimeout 30 ; #the time in seconds to leave the connection open if it is unused.
    set is_sidebandSendTimeout 50 ; #the time in milliseconds to transmit the HTTP request to the sideband pool member.  
    set is_sidebandReceiveTimeout 30 ; #the time in milliseconds to wait for the HTTP response to be received from the sideband pool member. 
    ###User-Edit Variables end###

## Set variable containing explicit proxy request URI (this contains full http://fqdn/uri per the RFC) 
set is_httpURI [HTTP::uri] 

## Set variable containing just FQDN without port or scheme
       if { ${is_httpURI} starts_with "http://" } {  
           set is_httpHost [string trimright [string trimleft ${is_httpURI} "http://"] "/"]  
       } else { 
           set is_httpHost [findstr ${is_httpURI} "" 0 ":"]     
       } 
## Set variables for SCP header values
set is_X_SWEB_AuthVersion [HTTP::header value X-SWEB-AuthVersion]
set is_X_SWEB_AuthCustID [HTTP::header value X-SWEB-AuthCustID]
set is_X_SWEB_AuthUser [HTTP::header value X-SWEB-AuthUser]
set is_X_SWEB_AuthGroups [HTTP::header value X-SWEB-AuthGroups]
set is_X_SWEB_AuthTS [HTTP::header value X-SWEB-AuthTS]
set is_X_SWEB_AuthToken [HTTP::header value X-SWEB-AuthToken]
set is_X_SWEB_ClientIP [HTTP::header value X-SWEB-ClientIP]


    ## Initialize variable to store decrypt decision (expecting bypass/intercept after lookup)
    set is_decryptDecision 0 

    ## Start loop for retry. Set a loop control variable to 0     
    set is_loop 0 
    
    ## While the loop control variable is less than $is_sidebandRetryCount, keep looping. 
    while { $is_loop < $is_sidebandRetryCount } {
        ## Log Retry attempt (if debug logging is enabled.)
        if { $is_debugLogging == 1 } { log local0. "DEBUG: starting sideband attempt [expr {$is_loop + 1}] for $is_httpHost" }      

        ## Check if sideband pool exists
        if { [catch { set is_members [active_members -list $static::is_sidebandPool]}] } { 
            log local0. "$is_errorLoggingString LTM pool $static::is_sidebandPool does not exist!"
            return 
        }

        ## Get the list of active members in the sideband pool  
        set is_members [active_members -list $static::is_sidebandPool] 

        ## Count the number of members  
        set is_count [llength $is_members]

        ## Check if there are any healthy nodes. If there is no healthy nodes, log and exit gracefully. 
        if { $is_count equals 0 } { 
            log local0. "$is_errorLoggingString no healthy nodes in sideband pool!" 
            return
            } else { 
            if { $is_debugLogging == 1 } { log local0. "DEBUG: active members of $static::is_sidebandPool pool is $is_count" }    
            }
        
        ## Initialize iRule table entry for load balancing round robin pool members if it does not exist.
        table set -excl is_poolRotatingIndex 0

        ## Lookup iRule table entry for load balancing round robin pool members.
        set is_poolRotatingIndex [table lookup -notouch is_poolRotatingIndex]

        ## If iRule table entry does not have a value within the range of expected values, reset the table to 0. 
         if {  !($is_poolRotatingIndex >= 0) or !($is_poolRotatingIndex <= $is_count) } { 
            
            ## Set table entry for load balancing round robin pool members if it does not exist. 
            table set is_poolRotatingIndex 0
            set is_poolRotatingIndex 0 
            if { $is_debugLogging == 1 } { log local0. "DEBUG: resetting round robin table for pool $static::is_sidebandPool to 0" }  
        } 

        ## Format IP:port for the member that is selected.    
        set is_memberToUse "[string map {" " ":"}[lindex $is_members $is_poolRotatingIndex]]"

        ## Increment rotating pool index variable 
        incr is_poolRotatingIndex

        ## Update iRule table entry with new rotating index number
        if { $is_poolRotatingIndex >= $is_count } { 
            ## Reset rotating index to 0 now that the last pool member in the index has been used. 
            table set is_poolRotatingIndex 0
        } else { 
            ## Use next pool member
            table set is_poolRotatingIndex $is_poolRotatingIndex
        }

        ## Open the TCP connection to the sideband pool member
        set is_connID [connect -timeout $is_sidebandConnectTimeout -idle $is_sidebandIdleTimeout -status conn_status $is_memberToUse] 

        ## Check if TCP connection was successful. If not, try again with a different pool member.  
        if { !($is_connID contains "connect") } { 
            log local0. "$is_errorLoggingString cannot connect sideband to $is_memberToUse."
            
            ## This attempt has failed. Increment the loop control variable
            incr is_loop
            
            ## If retry count has exceeded, log CRIT message, and stop looping. 
            if { $is_loop >= $is_sidebandRetryCount } { 
                log local0. "$is_errorLoggingString sideband retry limit exceeded. Decrypting $is_httpHost"
                break 
                } 
            ## If within the retry limit, start the retry loop again. 
            continue
        }
## Format HTTP Request to sideband with Host FQDN from the explicit proxy request  
#set is_data "HEAD /?url=${is_httpHost} HTTP/1.1\r\nHost: $is_sidebandHostHeader\r\n\r\n" 
set is_data "HEAD /?url=${is_httpHost} HTTP/1.1\r\nHost: $is_sidebandHostHeader\r\nX-SWEB-AuthVersion: $is_X_SWEB_AuthVersion\r\nX-SWEB-AuthCustID: $is_X_SWEB_AuthCustID\r\nX-SWEB-AuthUser: $is_X_SWEB_AuthUser\r\nX-SWEB-AuthGroups: $is_X_SWEB_AuthGroups\r\nX-SWEB-AuthTS: $is_X_SWEB_AuthTS\r\nX-SWEB-AuthToken: $is_X_SWEB_AuthToken\r\nX-SWEB-ClientIP: $is_X_SWEB_ClientIP\r\n\r\n" 

        ## Send HTTP Request to sideband pool member 
        set is_sendBytes [send -timeout $is_sidebandSendTimeout -status send_status $is_connID $is_data]

        ## Check HTTP Request was sent successfully 
        if { $is_debugLogging == 1 } {  log local0. "DEBUG: Sent $is_sendBytes bytes out of [string length $is_data] bytes to $is_memberToUse. Full Request was $is_data" }
        if { !($is_sendBytes == [string length $is_data]) } { 
            log local0. "$is_errorLoggingString unable to send sideband call to $is_memberToUse. Sent $is_sendBytes bytes out of [string length $is_data] bytes"
            
            ## This attempt has failed. Increment the loop control variable
            incr is_loop
            
            ## If retry count has exceeded, log CRIT message, and stop looping. 
            if { $is_loop >= $is_sidebandRetryCount } { 
                log local0. "$is_errorLoggingString sideband retry limit exceeded. Decrypting $is_httpHost"
                break 
                } 
            
            ## If within the retry limit, start the retry loop again. 
            continue
        }

        ## Check HTTP Response was received from sideband pool member
        set is_recv_data [recv -peek -timeout $is_sidebandReceiveTimeout -status recv_status $is_connID]
        if { $is_debugLogging == 1 } {  log local0. "DEBUG: Received Response: $is_recv_data from $is_memberToUse." }

        ## Check if response is empty
        if { [string length $is_recv_data] <= 1 } { 
            log local0. "$is_errorLoggingString empty response from $is_memberToUse"
            
            ## This attempt has failed. Increment the loop control variable
            incr is_loop
            
            ## If retry count has exceeded, log CRIT message, and stop looping. 
            if { $is_loop >= $is_sidebandRetryCount } { 
                log local0. "$is_errorLoggingString sideband retry limit exceeded. Decrypting $is_httpHost"
                break 
                } 
            
            ## If within the retry limit, start the retry loop again. 
            continue
        }


    ## End retry loop on success
    break
    }
## End not-cached if condition
}