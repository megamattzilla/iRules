when HTTP_REQUEST priority 200 {
###User-Edit Variables start###
#Specify name for in-line service re-entry virtual server. Example: ssloS_exampleService-D-0-t-4
set static::bypassService "ssloS_exampleService-D-0-t-4"
###User-Edit Variables end###

#Check If HTTP request method is POST or PUT.
if { ([HTTP::method] == "POST" ) || ([HTTP::method] == "PUT" ) }  {
    #HTTP POST or PUT detected. Log that we found one.   
    log local0. "Checking content-length for IP [IP::client_addr] HTTP [HTTP::host] [HTTP::uri] [HTTP::method] content-length [HTTP::header "content-length"]"
    #Check if the content length header is less than 1096 bytes OR more than 50MB (52428800 bytes).
    if { ([HTTP::header "Content-Length"] <= "1096" ) || ([HTTP::header "Content-Length"] >= "52428800") } {
        #HTTP request is type POST or PUT but smaller than 1096 or larger than 50MB. Bypass in-line service for this request
        log local0. "Bypassing in-line service for IP [IP::client_addr] HTTP [HTTP::host] [HTTP::uri] [HTTP::method] content-length [HTTP::header "content-length"]"
        #Disable in-line service by directing traffic to the re-entry virtual server which bypasses the entry virtual server for this service. 
        virtual $static::bypassService
        }
} else {
#If HTTP request method is NOT POST or PUT do something here.
log local0. "Fallback: Bypassing in-line service for IP [IP::client_addr] HTTP [HTTP::host] [HTTP::uri] [HTTP::method]"
#Disable in-line service by directing traffic to the re-entry virtual server which bypasses the entry virtual server for this service.
virtual $static::bypassService 
}
}