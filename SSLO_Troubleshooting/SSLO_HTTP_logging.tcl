when HTTP_REQUEST priority 200 {
set clientip 10.5.20.103

if { [IP::client_addr] == "$clientip" } {
   set LogString "Client [IP::client_addr]:[TCP::client_port] -> [IP::local_addr]:[TCP::local_port] HTTP: [HTTP::method] [HTTP::host][HTTP::uri]"
   log local0. "============================================="
   log local0. "$LogString (request)"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="
}
}

when HTTP_RESPONSE priority 200 {
if { [IP::client_addr] == "$clientip" } {
   set LogString "Client [IP::client_addr]:[TCP::client_port] -> [IP::remote_addr]:[TCP::remote_port] HTTP status [HTTP::status]"
   log local0. "============================================="
   log local0. "$LogString (Response)"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="
}
}