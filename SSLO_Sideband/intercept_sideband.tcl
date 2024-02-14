# Made with care by Matt Stovall 2/2024.
#This iRule: 
#   1.   collects HTTP information (HTTP host FQDN) from an explicit proxy HTTP request
#   2.   makes a sideband HTTP call to a HTTP proxy with this information
#   3.   inspects HTTP response from HTTP proxy for HTTP headers indicating the explicit proxy request should be SSL intercepted
#   4.   based on that response, send the explicit proxy HTTP request to the appropriate virtual server that either intercepts or bypasses SSL decryption

#All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of z1_ has been added to each variable to make them globally unique. 
#See https://github.com/megamattzilla/iRules/blob/master/SSLO_Sideband/README.md for more details
#Version 1.2
#Requirements: TBD

when HTTP_REQUEST priority 200 { 

    #TODO: add variables including custom string in message.
    ###User-Edit Variables start###
    set is_sidebandPool "mcafee-api" ; #LTM pool containing nodes to send the sideband HTTP request
    set is_debugLogging 1 ; #0 = Disabled, 1 = Enabled

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
if { [HTTP::header exists "X-SSLO-URL-PURGE"] } {
    if { $is_debugLogging == 1 } { log local0. "DEBUG: PURGE cache $is_httpHost" } 
    table delete $is_httpHost 
}

## Check if this is a CONNECT request to see if its necessary to lookup URL category for SSL bypass decisions. Exit gracefully if its not a CONNECT request.
if { !([HTTP::method] equals "CONNECT") } {
    return 
} 

## Perform iRule cache lookup for $is_httpHost
    set is_cacheLookup [table lookup $is_httpHost]

## Check if  cache (iRule table) has entry for $is_httpHost.  Expecting data to contain "Bypass" or "Intercept".  If found, set X_CATEGORY and X_DECRYPT_DECISION using table data. Then skip calling the sideband.  
if { $is_cacheLookup contains "Bypass"  or $is_cacheLookup contains "Intercept" } {
    ## Cache HIT
       if { $is_debugLogging == 1 } { log local0. "DEBUG: HIT cache $is_httpHost = $is_cacheLookup" }
    #Set decrypt decision based on cached iRule table data 
    set X_DECRYPT_DECISION [getfield $is_cacheLookup "|" 1]
    set X_CATEGORY [getfield $is_cacheLookup "|" 2]

} else {

    ## Cache MISS
        if { $is_debugLogging == 1 } { log local0. "DEBUG: MISS cache $is_httpHost = $is_cacheLookup" }

    ## Get the list of active members in the sideband pool  
    set is_members [active_members -list $is_sidebandPool] 

    ## Count the number of members  
    set is_count [llength $is_members]
    
    ## Check if there are any healthy nodes. If there is no healthy nodes, log and exit gracefully. 
    if { $is_count equals 0 } { 
        log local0. "CRIT: no healthy nodes in sideband pool!" 
        return
        }

    ## Select a random member index from the pool 
    set is_randomMemberIndex [expr {int(rand()*$is_count)}]  


    ## Format IP:port for the member that is selected.    
    set member_to_use "[string map {" " ":"}[lindex $is_members $is_randomMemberIndex]]"

    
    ## Open the TCP connection to the sideband pool member
    set conn_id [connect -timeout 100 -idle 30 -status conn_status $member_to_use] 

    ## Check if TCP connection was successful. If not, try again with a different pool member.  
    if { !($conn_id contains "connect") } { 
        log local0. "CRIT: cannot connect sideband to $member_to_use. Retrying."
        
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
                    set member_to_use "[string map {" " ":"}[lindex $is_members $is_nextRandomMemberIndex]]"
                    if { $is_debugLogging == 1 } { log local0. "DEBUG: Selected new sideband member $member_to_use on attempt $is_loop" }
                    break
                ## If this new random member is the same as the previous member, keep looping.     
                } else { incr is_loop }
            }
        }

    
        ## Open the RETRY TCP connection to the sideband pool member
        set conn_id [connect -timeout 100 -idle 30 -status conn_status $member_to_use] 

        ## Check if the RETRY TCP connection was successful. If not, log a message and exit gracefully.   
        if { !($conn_id contains "connect") } { 
            log local0. "CRIT: cannot connect sideband to $member_to_use after RETRY."
            return 
        }  
    }

    ## Format HTTP Request to sideband with Host FQDN from the explicit proxy request  
    set data "HEAD /?url=${is_httpHost} HTTP/1.1\r\nHost: 10.5.20.245\r\n\r\n" 

    ## Send HTTP Request to sideband pool member 
    set send_bytes [send -timeout 500 -status send_status $conn_id $data]
    
    ## Check HTTP Request was sent successfully 
    if { $is_debugLogging == 1 } {  log local0. "DEBUG: Sent $send_bytes bytes out of [string length $data] bytes" }
    if { !($send_bytes == [string length $data]) } { 
        log local0. "CRIT: unable to send sideband call to $member_to_use. Sent $send_bytes bytes out of [string length $data] bytes"
        return
    }

    ## Check HTTP Response was received from sideband pool member
    set recv_data [recv -peek -timeout 500 -status recv_status $conn_id]
    if { $is_debugLogging == 1 } {  log local0. "DEBUG: Received Response: $recv_data" }
    
    ## Check if response is empty
    if { [string length $recv_data] <= 1 } { 
        log local0. "CRIT: empty response from $member_to_use"
        return
        }
    
    ## Check if response does not contain expected strings     
    if { !($recv_data contains "Bypass") and !($recv_data contains "Intercept") } { 
        log local0. "CRIT: invalid sideband response from $member_to_use"
        return
        }

    ## Add sideband results to variables 
    set X_CATEGORY [findstr [lsearch -inline [split $recv_data "\r\n"] X-Categories*] ": " 2] 
    set X_DECRYPT_DECISION [findstr [lsearch -inline [split $recv_data "\r\n"] X-Decrypt-Decision*] ": " 2] 
    
    ## Set cache entry for this HTTP FQDN
    table set $is_httpHost "$X_DECRYPT_DECISION|$X_CATEGORY" 3600 3600 
    if { $is_debugLogging == 1 } { log local0. "DEBUG: Added Cache entry $is_httpURI X_DECRYPT_DECISION: $X_DECRYPT_DECISION  X_CATEGORY: $X_CATEGORY" }

}
    ## If HTTP FQDN should be bypassed, send the explicit proxy HTTP request to a different virtual server. 
    if { ${X_DECRYPT_DECISION} eq "Bypass" } { 
        virtual sslo_noAuth.app/sslo_noAuth-xp-4
    }       
}