#If HTTP request is content type json and length is over 750KB (750000 bytes) log the request details. 
#HTTP request body will not be logged 
when HTTP_REQUEST {
 catch { if { ([HTTP::header "content-length"] >= 750000 ) && ([HTTP::header "Content-Type"] contains "json") } { 
    log local0. "large json detected for Request: [HTTP::request]" 
    }
 }
}