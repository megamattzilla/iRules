# Made with care by Matt Stovall 2/2024.
#This iRule: 
#   1.   collects HTTP information (HTTP host FQDN) from an explicit proxy HTTP request
#   2.   makes a sideband HTTP call to a HTTP proxy with this information
#   3.   inspects HTTP response from HTTP proxy for HTTP headers indicating the explicit proxy request should be SSL intercepted
#   4.   based on that response, send the explicit proxy HTTP request to the appropriate virtual server that either intercepts or bypasses SSL decryption

#All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of z1_ has been added to each variable to make them globally unique. 
#See https://github.com/megamattzilla/iRules/blob/master/SSLO_Sideband/README.md for more details
#Version 1.0
#Requirements: TBD

when HTTP_REQUEST { 
## Set request URL 
sharedvar THIS_HOST 
set THIS_HOST [HTTP::uri] 
## parse incoming request URL 
       if { ${THIS_HOST} starts_with "http://" } {  
           set this_url [string trimright [string trimleft ${THIS_HOST} "http://"] "/"]  
       } else { 
           set this_url [findstr ${THIS_HOST} "" 0 ":"]     
       } 

#Check if purge cache header exists. If true, delete the cache entry. Note: this HTTP header would be on the explicit proxy request (CONNECT) which is uncommon.   
if { [HTTP::header exists "X-SSLO-URL-PURGE"] } {
    log local0. "PURGE cache $this_url" 
    table delete $this_url 
}

#Check if this is a CONNECT request to see if its necessary to lookup URL category for SSL bypass decisions. 
if { [HTTP::method] equals "CONNECT" } { 

    #Perform iRule cache lookup for $this_urll
    set cachelookup [table lookup $this_url]

    #Check if iRule table has entry for $this_url.  Expecting data to contain "Bypass" or "Intercept".  If found, set X_CATEGORY and X_DECRYPT_DECISION using table data. Skip calling sideband.  
    if { $cachelookup contains "Bypass"  or $cachelookup contains "Intercept" } {
        log local0. "HIT cache $this_url = $cachelookup"  
        #Set decrypt decision based on cached iRule table data 
        set X_DECRYPT_DECISION [getfield $cachelookup "|" 1]
        set X_CATEGORY [getfield $cachelookup "|" 2]

    } else {
        log local0. "MISS cache $this_url = $cachelookup"  
        ## issue MWG API sideband call 


      # Get the list of active members in the pool  
      set members [active_members -list mcafee-api]  
      #Count the number of members  
      set count [llength $members]
      if { $count equals 0 } { log local0. "CRITICAL no healthy nodes in sideband pool!" }
      # Select a random member  
      set random_member_index [expr {int(rand()*$count)}]  
      # Get the member  
      set member_to_use "[getfield [lindex $members $random_member_index] " " 1]:2082" 
      log local0. "$member_to_use"



        set conn_id [connect -timeout 100 -idle 30 -status conn_status $member_to_use] ; ## Use MWG IP and appropriate port
        log local0. "conn_id= $conn_id"
        if { !($conn_id contains "connect") } { 
            log local0. "CRITICAL cannot connect sideband to $member_to_use"
            virtual sslo_noAuth.app/sslo_noAuth-xp-4
            return
        }

        set data "HEAD /?url=${this_url} HTTP/1.1\r\nHost: 10.5.20.245\r\n\r\n" 
        set send_bytes [send -timeout 500 -status send_status $conn_id $data]
        log local0. "send_bytes= $send_bytes"
        if { !($send_bytes >= "2") } { 
            log local0. "CRITICAL unable to send sideband call to $member_to_use"
            virtual sslo_noAuth.app/sslo_noAuth-xp-4
            return
        }
        
        set recv_data [recv -peek -timeout 500 -status recv_status $conn_id]
        log local0. "recv_data= $recv_data"
        if { !($recv_data contains "Bypass") and !($recv_data contains "Intercept") } { 
            log local0. "CRITICAL invalid sideband response from $member_to_use"
            virtual sslo_noAuth.app/sslo_noAuth-xp-4
            return
            }
        
        ## parse sideband results 
        set X_CATEGORY [findstr [lsearch -inline [split $recv_data "\r\n"] X-Categories*] ": " 2] 
        set X_DECRYPT_DECISION [findstr [lsearch -inline [split $recv_data "\r\n"] X-Decrypt-Decision*] ": " 2] 
        table set $this_url "$X_DECRYPT_DECISION|$X_CATEGORY" 3600 3600 
        log local0. "$THIS_HOST X_DECRYPT_DECISION: $X_DECRYPT_DECISION  X_CATEGORY: $X_CATEGORY"
        if { ${X_DECRYPT_DECISION} eq "Intercept" } { 
            virtual sslo_noAuth.app/sslo_noAuth-xp-4 
            }
        if { ${X_DECRYPT_DECISION} eq "Bypass" } { 
                virtual sslo_noAuth.app/sslo_noAuth-xp-4
                }           

}
}
virtual sslo_noAuth.app/sslo_noAuth-xp-4
}