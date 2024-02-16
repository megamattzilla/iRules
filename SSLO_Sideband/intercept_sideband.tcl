## Made with care by Matt Stovall 2/2024.
## Version 1.3
## This iRule: 
##  1.   collects HTTP information (HTTP host FQDN) from an explicit proxy HTTP request
##  2.   makes a sideband HTTP call to a HTTP proxy with this FQDN information in the URI as a query string. (/?url=${is_httpHost})  
##  3.   inspects HTTP response from HTTP proxy for HTTP headers indicating the explicit proxy request should be SSL intercepted
##  4.   based on that response, send the explicit proxy HTTP request to the appropriate virtual server that either intercepts or bypasses SSL decryption

## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of is_ has been added to each variable to make them globally unique. 
## See https://github.com/megamattzilla/iRules/blob/master/SSLO_Sideband/README.md for more details

## Requirements: 
##  1. To be applied to a vip-targeting-vip which points to an explicit proxy virtual server.
##  2. Configure a LTM pool with your sideband pool members.
##  3. Configure those sideband pool members to reply with the Bypass/Intercept strings this iRule is looking for.   

when HTTP_REQUEST priority 200 { 

    ###User-Edit Variables start###
    set is_sidebandPool "mcafee-api" ; #LTM pool containing nodes to send the sideband HTTP request
    set is_debugLogging 1 ; #0 = Disabled, 1 = Enabled
    set is_errorLoggingString "CRIT:" ; #Keyword string to be included in error logs. 
    set is_cacheTimeout 3600 ; #Number of seconds to cache a bypass/intercept decision for a given FQDN. 
    set is_cachePurgeHeader "X-SSLO-URL-PURGE" ; #HTTP request header name that will purge the cache for a given FQDN
    set is_sslBypassVirtualServer "sslo_noAuth.app/sslo_noAuth-xp-4" ; #Virtual server path/name to send explicit proxy requests that should NOT be SSL intercepted. 
    set is_sidebandHostHeader "sideband.example.com" ; #HTTP host header value to use in the sideband call.
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

## Check if purge cache header exists. If true, delete the cache entry. Note: this HTTP header would be on the explicit proxy request (CONNECT) which is uncommon.   
if { [HTTP::header exists $is_cachePurgeHeader] } {
    if { $is_debugLogging == 1 } { log local0. "DEBUG: PURGE cache $is_httpHost" } 
    table delete $is_httpHost 
}

## Check if this is a CONNECT request to see if its necessary to lookup URL category for SSL bypass decisions. Exit gracefully if its not a CONNECT request.
if { !([HTTP::method] equals "CONNECT") } {
    return 
} 

## Perform iRule cache lookup for $is_httpHost
    set is_cacheLookup [table lookup $is_httpHost]

## Check if  cache (iRule table) has entry for $is_httpHost.  Expecting is_data to contain "Bypass" or "Intercept".  If found, set is_urlCategory and is_decryptDecision using table is_data. Then skip calling the sideband.  
if { $is_cacheLookup contains "Bypass"  or $is_cacheLookup contains "Intercept" } {
    ## Cache HIT
       if { $is_debugLogging == 1 } { log local0. "DEBUG: HIT cache $is_httpHost = $is_cacheLookup" }
    #Set decrypt decision based on cached iRule table is_data 
    set is_decryptDecision [getfield $is_cacheLookup "|" 1]
    set is_urlCategory [getfield $is_cacheLookup "|" 2]

} else {

    ## Cache MISS
        if { $is_debugLogging == 1 } { log local0. "DEBUG: MISS cache $is_httpHost = $is_cacheLookup" }

    ## Get the list of active members in the sideband pool  
    set is_members [active_members -list $is_sidebandPool] 

    ## Count the number of members  
    set is_count [llength $is_members]
    
    ## Check if there are any healthy nodes. If there is no healthy nodes, log and exit gracefully. 
    if { $is_count equals 0 } { 
        log local0. "$is_errorLoggingString no healthy nodes in sideband pool!" 
        return
        }

    ## Select a random member index from the pool 
    set is_randomMemberIndex [expr {int(rand()*$is_count)}]  


    ## Format IP:port for the member that is selected.    
    set is_memberToUse "[string map {" " ":"}[lindex $is_members $is_randomMemberIndex]]"

    
    ## Open the TCP connection to the sideband pool member
    set is_connID [connect -timeout $is_sidebandConnectTimeout -idle $is_sidebandIdleTimeout -status conn_status $is_memberToUse] 

    ## Check if TCP connection was successful. If not, try again with a different pool member.  
    if { !($is_connID contains "connect") } { 
        log local0. "$is_errorLoggingString cannot connect sideband to $is_memberToUse. Retrying."
        
        ## In a pool with 2 or more active sideband nodes try 10 times to select a different pool member or give up and try the same pool member.
        if { $is_count >= 2 } { 
            ## Set a loop control variable to 0     
            set is_loop 0 
            ## While the loop control variable is less than 10, keep looping. 
            while { $is_loop < 10 } { 
                ## Select another random member index from the pool 
                set is_nextRandomMemberIndex [expr {int(rand()*$is_count)}]
                ## Check if this new random member is the same as the previous member. 
                if {($is_nextRandomMemberIndex != $is_randomMemberIndex)} { 
                    ## A new sideband pool member has been selected. Set variables and Stop looping.
                    ## Format IP:port for the member that is selected.    
                    set is_memberToUse "[string map {" " ":"}[lindex $is_members $is_nextRandomMemberIndex]]"
                    if { $is_debugLogging == 1 } { log local0. "DEBUG: Selected new sideband member $is_memberToUse on attempt $is_loop" }
                    break
                ## If this new random member is the same as the previous member, keep looping.     
                } else { incr is_loop }
            }
        }

    
        ## Open the RETRY TCP connection to the sideband pool member
        set is_connID [connect -timeout $is_sidebandConnectTimeout -idle $is_sidebandIdleTimeout -status conn_status $is_memberToUse] 

        ## Check if the RETRY TCP connection was successful. If not, log a message and exit gracefully.   
        if { !($is_connID contains "connect") } { 
            log local0. "$is_errorLoggingString cannot connect sideband to $is_memberToUse after RETRY."
            return 
        }  
    }

    ## Format HTTP Request to sideband with Host FQDN from the explicit proxy request  
    set is_data "HEAD /?url=${is_httpHost} HTTP/1.1\r\nHost: $is_sidebandHostHeader\r\n\r\n" 

    ## Send HTTP Request to sideband pool member 
    set is_sendBytes [send -timeout $is_sidebandSendTimeout -status send_status $is_connID $is_data]
    
    ## Check HTTP Request was sent successfully 
    if { $is_debugLogging == 1 } {  log local0. "DEBUG: Sent $is_sendBytes bytes out of [string length $is_data] bytes" }
    if { !($is_sendBytes == [string length $is_data]) } { 
        log local0. "$is_errorLoggingString unable to send sideband call to $is_memberToUse. Sent $is_sendBytes bytes out of [string length $is_data] bytes"
        return
    }

    ## Check HTTP Response was received from sideband pool member
    set is_recv_data [recv -peek -timeout $is_sidebandReceiveTimeout -status recv_status $is_connID]
    if { $is_debugLogging == 1 } {  log local0. "DEBUG: Received Response: $is_recv_data" }
    
    ## Check if response is empty
    if { [string length $is_recv_data] <= 1 } { 
        log local0. "$is_errorLoggingString empty response from $is_memberToUse"
        return
        }
    
    ## Check if response does not contain expected strings     
    if { !($is_recv_data contains "Bypass") and !($is_recv_data contains "Intercept") } { 
        log local0. "$is_errorLoggingString invalid sideband response from $is_memberToUse"
        return
        }

    ## Add sideband results to variables 
    set is_urlCategory [findstr [lsearch -inline [split $is_recv_data "\r\n"] X-Categories*] ": " 2] 
    set is_decryptDecision [findstr [lsearch -inline [split $is_recv_data "\r\n"] X-Decrypt-Decision*] ": " 2] 
    
    ## Set cache entry for this HTTP FQDN
    table set $is_httpHost "$is_decryptDecision|$is_urlCategory" $is_cacheTimeout $is_cacheTimeout
    if { $is_debugLogging == 1 } { log local0. "DEBUG: Added Cache entry $is_httpURI is_decryptDecision: $is_decryptDecision  is_urlCategory: $is_urlCategory" }

}
    ## If HTTP FQDN should be bypassed, send the explicit proxy HTTP request to a different virtual server. 
    if { ${is_decryptDecision} eq "Bypass" } { 
        virtual $is_sslBypassVirtualServer
    }       
}