#Disable ASM policy for HTTP requests that match an entry in the IP and User-Agent datagroup 
when HTTP_REQUEST {
    #First check for source IP match against our address datagroup. First check IPv4 source IP header for match then check for the first IP in the XFF header (if present) for a match.  
    if { 
    ([class match [IP::client_addr] equals "ASM_IP_Whitelist" ]) || 
    ( [HTTP::header exists "X-Forwarded-For"] && [class match [string trim [lindex [HTTP::header X-Forwarded-For] 0] ,] equals "ASM_IP_Whitelist" ]) 
    } then { 
        #If IP match is found, then check if the user-agent string matches the string datagroup 
        if { [class match [HTTP::header "User-Agent"] contains "ASM_UA_Whitelist"] } { ; #Datagroup matching operators are equals, starts_with, ends_with, and contains.  
        ASM::disable ; #Disables ASM policy for this HTTP Request only. 
        #log local0. "Bypassed ASM policy for Flow ([IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port]) found User-Agent:[HTTP::header "User-Agent"] X-Forwarded-For:[HTTP::header "X-Forwarded-For"] for request [HTTP::host][HTTP::uri]" ; #Un-comment this line to enable logging to /var/log/ltm for troubleshooting only.
        }
    }
}