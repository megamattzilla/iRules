# Made with ❤ by Matt Stovall 2/2024.
#This iRule logs HTTP request and response header data that is readily available. 
#All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of z1_ has been added to each variable to make them globally unique. 
#See https://github.com/megamattzilla/iRules/blob/master/LTM_Logging/README.md for more details
#Version 1.0
#Requirements: http and client-ssl profile attached to virtual server. 

when CLIENT_ACCEPTED  {
catch {
    ###User-Edit Variables start###
    set z1_http_content_type logging-pool ; #Name of LTM pool to use for remote logging servers 
    set z1_remoteLogProtocol UDP ; #UDP or TCP
    set z1_globalStringLimit 100 ; #How many characters to collect from user-supplied HTTP values like HTTP host, version, referrer. 
    set z1_uriStringLimit 600 ; #How many characters to collect from HTTP value of URI
    ###User-Edit Variables end###
    
    #Open socket to remote log destination 
    set z1_hsl [HSL::open -proto $z1_remoteLogProtocol -pool $z1_http_content_type]
}
}

when HTTP_REQUEST priority 10 {
catch { 
#Collect HTTP request data for every request and move on. 
    set z1_virtual_server [virtual name]
    set z1_clientsslprofile [PROFILE::clientssl name]
    set z1_http_host [string range [HTTP::host] 0 $z1_globalStringLimit]
    set z1_http_uri [string range [HTTP::uri] 0 $z1_uriStringLimit]
    set z1_http_method [string range [HTTP::method] 0 $z1_globalStringLimit]
    set z1_http_referrer [string range [HTTP::header "Referer"] 0 $z1_globalStringLimit]
    set z1_http_content_type [string range [HTTP::header "Content-Type"] 0 $z1_globalStringLimit]
    set z1_http_user_agent [string range [HTTP::header "User-Agent"] 0 $z1_globalStringLimit]
    set z1_http_version [string range [HTTP::version] 0 $z1_globalStringLimit]
    set z1_vip [IP::local_addr]
    if { [HTTP::header Content-Length] > 0 } then {
        set z1_req_length [string range [HTTP::header "Content-Length"] 0 $z1_globalStringLimit]
    } else {
        set z1_req_length 0
    }
}
}

when LB_SELECTED {
catch { 
    #Collect Pool and node data for every request and move on. 
    set z1_pool [LB::server]
    } 
}
when HTTP_RESPONSE priority 10 {
catch { 
#Collect HTTP request data for every request and move on. 
   set z1_http_status [string range [HTTP::status] 0 $z1_globalStringLimit]
    if { [HTTP::header Content-Length] > 0 } then {
       set z1_res_length [string range [HTTP::header "Content-Length"] 0 $z1_globalStringLimit]
    } else {
       set z1_res_length 0
    }
    #Generate asynchronous (UDP or TCP) remote log. 
    HSL::send $z1_hsl "hostname=\"$static::tcl_platform(machine)\",cIP=\"[IP::client_addr]\",cPort=\"[TCP::client_port]\",uri=\"$z1_http_uri\",host=\"$z1_http_host\",method=\"$z1_http_method\",reqLength=\"$z1_req_length\",statusCode=\"$z1_http_status\",resLength=\"$z1_res_length\",vs=\"$z1_virtual_server\",pool=\"$z1_pool\",referrer=\"$z1_http_referrer\",cType=\"$z1_http_content_type\",userAgent=\"$z1_http_user_agent\",httpv=\"$z1_http_version\",vip=\"$z1_vip\",clientsslprofile=\"$z1_clientsslprofile\"" 
    
    #clear all variables. Prevents stale data if there is TCP re-use. 
    set z1_hsl 0
    set z1_http_uri 0
    set z1_http_host 0 
    set z1_http_method 0
    set z1_req_length 0
    set z1_http_status 0
    set z1_res_length 0
    set z1_virtual_server 0
    set z1_pool 0
    set z1_http_referrer 0 
    set z1_http_content_type 0 
    set z1_http_user_agent 0
    set z1_http_version 0
    set z1_vip 0 
    set z1_clientsslprofile 0
}
}