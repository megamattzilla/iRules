when HTTP_REQUEST priority 200 {
#Check If HTTP request method is POST or PUT.
if { ([HTTP::method] == "POST" ) || ([HTTP::method] == "PUT" ) }  {
    #HTTP POST or PUT detected. Log that we found one.   
    log local0. "Checking content-length for IP [IP::client_addr] HTTP [HTTP::host] [HTTP::uri] [HTTP::method] content-length [HTTP::header "content-length"]"
    #Check if the content length header is less than 1096 bytes OR more than 50MB (52428800 bytes).
    if { ([HTTP::header "Content-Length"] <= "1096" ) || ([HTTP::header "Content-Length"] >= "52428800") } {
        #HTTP request is type POST or PUT but smaller than 1096 or larger than 50MB. Bypass ICAP for this request
        log local0. "Bypassing ICAP for IP [IP::client_addr] HTTP [HTTP::host] [HTTP::uri] [HTTP::method] content-length [HTTP::header "content-length"]"
        #Disable ICAP request mod profile. For some reason the command is ADAPT::enable but the 0 means its disable (1 = enable). 
        ADAPT::enable request 0 
        }
} else {
#If HTTP request method is NOT POST or PUT do something here.
log local0. "Fallback: Bypassing ICAP for IP [IP::client_addr] HTTP [HTTP::host] [HTTP::uri] [HTTP::method]"
#Disable ICAP request mod profile. For some reason the command is ADAPT::enable but the 0 means its disable (1 = enable). 
ADAPT::enable request 0 
}
}