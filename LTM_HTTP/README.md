### Choose between iRule http_host_to_pool_equals.tcl or http_host_to_pool_ends_with.tcl (wildcard)  

http_host_to_pool will match the HTTP Host header against strings using equals operator.  
- requires only data group header_to_pool_equals.
- refer to header_to_pool_equals.tmsh for example configuration. 

http_host_to_pool_ends_with will match the HTTP Host header against strings using equals operator first. If no match is found a second data group using an ends_with match will be evaluated.  
- requires both data groups header_to_pool_equals and header_to_pool_ends_with. 
- refer to header_to_pool_equals.tmsh and header_to_pool_ends_with.tmsh for example configuration. 

