# Made with ❤ by Matt Stovall @ F5 8/2023.
when CLIENT_ACCEPTED {
    set default_pool [LB::server pool]
} 
when HTTP_REQUEST priority 200 {

###User-Edit Variables start###
set enableLogging 1 ; #1 = enabled, 0 = disabled. When enable log for troubleshooting. This should be disabled in production. 
set static::bypassService "ssloS_SQID2-D-0-t-4" ; #Specify name for in-line service re-entry virtual server. Example: ssloS_exampleService-D-0-t-4
set static::SERVICE_FILTER_NAME_EQUALS "service_bypass_hostname_equals" ; #Name of data group to exact match FQDNs. Matching traffic will be bypassed from the service. Example DG string: mattisprettycool.local
set static::SERVICE_FILTER_NAME_ENDS_WITH "service_bypass_hostname" ; #Name of data group to ends_with match FQDNs. Matching traffic will be bypassed from the service. Example DG string: .mattisprettycool.local 
set static::SERVICE_FILTER_NAME_ENDS_WITH_REFERER "service_bypass_hostname_referer" ; #Name of data group to exact match HTTP referrer header. Matching traffic will be bypassed from the service. Example DG string: https://mattisprettycool.local/some/SAML/thing 
set collectAmount 512 ; #Amount of HTTP request body data to collect when SAML content type is detected 
set samlDetectionString "SAMLRequest:" ; #String to search in the HTTP Request body to detect a SAML assertion 
set samlDetectionStingLength 11 ; #If a string match is found in HTTP Request body, how much data to return as the "matched" string. Set this to the string length of $samlDetectionString
set samlContentType "application/x-www-form-urlencoded" ; #HTTP request content type to trigger additional HTTP::collect and check for the saml string $samlDetectionString.
###User-Edit Variables end###

#Check If HTTP request method is POST or PUT. If a match is NOT found, bypass this request from the service. 
if { ([HTTP::method] == "POST" ) || ([HTTP::method] == "PUT" ) }  {
    #HTTP POST or PUT detected. Log that we found one.   
    if { $enableLogging equals 1 } { log local0. "Checking content-length for IP [IP::client_addr] HTTP [HTTP::host] [HTTP::uri] [HTTP::method] content-length [HTTP::header "content-length"]" } 
    set refererValue [HTTP::header value "Referer" ]
    
    #First Sub Conditional
    #Check if the content length header is less than 1096 bytes OR more than 50MB (52428800 bytes). If a match is found, bypass this request from the service. 
    if { ([HTTP::header "Content-Length"] <= "1096" ) || ([HTTP::header "Content-Length"] >= "52428800") } {
        #HTTP request is type POST or PUT but smaller than 1096 or larger than 50MB. Bypass in-line service for this request
        if { $enableLogging equals 1 } { log local0. "Not in KB range. Bypassing in-line service for IP [IP::client_addr] HTTP [HTTP::host] [HTTP::uri] [HTTP::method] content-length [HTTP::header "content-length"]" }
        #Disable in-line service by directing traffic to the re-entry virtual server which bypasses the entry virtual server for this service. 
        virtual $static::bypassService

    #Second Sub Conditional
    #Check if HTTP URI matches the exact match data group. If a match is found, bypass this request from the service.      
    } elseif { [class match  [HTTP::host] equals $static::SERVICE_FILTER_NAME_EQUALS] } {
        if { $enableLogging equals 1 } { log local0. "ConnFlow ([IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port]) matched exact match data group [HTTP::host]" } 
        virtual $static::bypassService
        return
        
    #Third Sub Conditional. If HTTP URI matches the ends with data group. If a match is found, bypass this request from the service.      
    } elseif { [class match  [HTTP::host] equals $static::SERVICE_FILTER_NAME_ENDS_WITH] } {
        if { $enableLogging equals 1 } { log local0. "ConnFlow ([IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port]) matched ends_with data group [HTTP::host]" } 
        virtual $static::bypassService
        return
     
    #Fourth Sub Conditional. Check if HTTP Referer header value matches data group. If a match is found, bypass this request from the service. 
    } elseif { [class match  $refererValue equals $static::SERVICE_FILTER_NAME_ENDS_WITH_REFERER] } {
        if { $enableLogging equals 1 } { log local0. "ConnFlow ([IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port]) matched referer exact match data group [HTTP::header value "Referer" ] " } 
        virtual $static::bypassService
        return

    #Fifth Sub Conditional. If content type is correct for SAML, collect $collectAmount of bytes from the HTTP request body. 
    } elseif { [HTTP::header value "Content-Type" ] equals $samlContentType } { 
        HTTP::collect $collectAmount
        if { $enableLogging equals 1 } { log local0. "SAML Content Type Detected. Collecting $collectAmount bytes" } 

    } else {
    #If no conditionals match
    if { $enableLogging equals 1 } { log local0. "PUT or POST but did not match any conditionals. Sending to Service." } 
    pool $default_pool
    return }

} else {
#If HTTP request method is NOT POST or PUT method.
if { $enableLogging equals 1 } { log local0. "Not POST or PUT. Bypassing in-line service for IP [IP::client_addr] HTTP [HTTP::host] [HTTP::uri] [HTTP::method]" } 
#Disable in-line service by directing traffic to the re-entry virtual server which bypasses the entry virtual server for this service.
virtual $static::bypassService 
}
}

when HTTP_REQUEST_DATA {
if { [string length [findstr [HTTP::payload] "$samlDetectionString" 0 $samlDetectionStingLength]] > 1  } { 
virtual $static::bypassService  
if { $enableLogging equals 1 } { log local0. "Found SAML Post. Bypassing in-line service for IP [IP::client_addr] HTTP [HTTP::host] [HTTP::uri] [HTTP::method] content-length [HTTP::header "content-length"] Referer $refererValue"} 
} else {
    #If HTTP request body does not contain SAML string.
    if { $enableLogging equals 1 } { log local0. "Did not find SAML Post. Sending to Service for IP [IP::client_addr] HTTP [HTTP::host] [HTTP::uri] [HTTP::method] content-length [HTTP::header "content-length"]" } 
    pool $default_pool
    return }
}