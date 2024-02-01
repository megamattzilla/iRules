#Log HTTP request as soon as its decoded from client-side session. Before most F5 modules. 
when HTTP_REQUEST {
   set LogString "Client [IP::client_addr]:[TCP::client_port] -> [HTTP::host][HTTP::uri]"
   log local0. "============================================="
   log local0. "$LogString (request)"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="
}
#Log HTTP request before its transmitted server-side. After most F5 modules. 
when HTTP_REQUEST_RELEASE {
   set LogString "Client [IP::client_addr]:[TCP::client_port] -> [HTTP::host][HTTP::uri]"
   log local0. "============================================="
   log local0. "$LogString (request)"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="
}
#Log HTTP response as soon as its decoded from server-side session. Before most F5 modules. 
when HTTP_RESPONSE {
   log local0. "============================================="
   log local0. "$LogString (response) - status: [HTTP::status]"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="  
}
#Log HTTP response before its transmitted client-side. After most F5 modules. 
when HTTP_RESPONSE_RELEASE {
   log local0. "============================================="
   log local0. "$LogString (response) - status: [HTTP::status]"
   foreach aHeader [HTTP::header names] {
      log local0. "$aHeader: [HTTP::header value $aHeader]"
   }
   log local0. "============================================="  
}