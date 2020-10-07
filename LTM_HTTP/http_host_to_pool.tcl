when HTTP_REQUEST {
  #Requires datagroup called header_to_pool to be configured first. 
  #Extract HTTP host header value from HTTP request. Remove :{port} if present and only extract the host fqdn. 
  set host_hdr [getfield [HTTP::host] ":" 1]
  #Search datagroup for matching pool based on the HTTP host header value stored in tcl variable $host_hdr
  set ltm_pool [class match -value [string tolower $host_hdr] equals header_to_pool]
  #Check if HTTP Host value matched datagroup and a ltm pool value has been returned. 
  if { $ltm_pool ne "" } {
    #Datagroup match was successful. Load Balance request to the pool chosen by the data group. 
    #log local0. "DEBUG: Client [IP::client_addr]:[TCP::client_port] -> [HTTP::host][HTTP::uri] to pool $ltm_pool"
    pool $ltm_pool
  } else {
     #Host header did NOT match the Datagroup. Do something with HTTP requests that dont match. Reponse page, reset etc... 
    #log local0. "DEBUG: Client [IP::client_addr]:[TCP::client_port] -> [HTTP::host][HTTP::uri] rejecting"
    reject
  }
}