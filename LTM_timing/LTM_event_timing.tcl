#Timing of each common iRule Events. Summary provided for noteable milestones. 
#CLIENTSSL_HANDSHAKE requires clientssl profile on virtual
#SERVERSSL_HANDSHAKE requires serverssl profile on virtual
when FLOW_INIT {
    set flow_init_time [clock clicks -milliseconds]
    set log_string "flow_init_time=$flow_init_time"
    log local0. "::New_Session_Details::"
    log local0. $log_string
}
when CLIENT_ACCEPTED priority 100 {
    set client_accept_start_time [clock clicks -milliseconds]
    set log_string "client_accept_start_time=$client_accept_start_time"
    log local0. $log_string
}
when CLIENT_ACCEPTED priority 1000 {
    set client_accept_time [clock clicks -milliseconds]
    set log_string "client_accept_time=$client_accept_time"
    log local0. $log_string
}
#when CLIENTSSL_HANDSHAKE {
#    set client_ssl_time [clock clicks -milliseconds]
#    set log_string "client_ssl_time=$client_ssl_time"
#    log local0. $log_string
#}
when HTTP_REQUEST priority 100 {
    set http_request_start_time [clock clicks -milliseconds]
    set log_string "http_request_start_time=$http_request_start_time"
    log local0. $log_string
}
when HTTP_REQUEST priority 1000 {
    set http_request_time [clock clicks -milliseconds]
    set log_string "http_request_time=$http_request_time"
    log local0. $log_string
}
when HTTP_REQUEST_DATA {
    set http_request_data_time [clock clicks -milliseconds]
    set log_string "http_request_data_time=$http_request_data_time"
    log local0. $log_string
}
#Uncomment below lines to add ASM timing. Requires ASM profile to have iRule events disabled. 
#when ASM_REQUEST_DONE {
#    set asm_request_done_time [clock clicks -milliseconds]
#    set log_string "asm_request_done_time=$asm_request_done_time"
#    log local0. $log_string
#}
when LB_SELECTED {
    set lb_selected_time [clock clicks -milliseconds]
    set log_string "lb_selected_time=$lb_selected_time"
    log local0. $log_string
}
when LB_FAILED {
    set lb_failed_time [clock clicks -milliseconds]
    set log_string "lb_failed_time=$lb_failed_time"
    log local0. $log_string
}
when LB_QUEUED {
    set lb_queued_time [clock clicks -milliseconds]
    set log_string "lb_queued_time=$lb_queued_time"
    log local0. $log_string
}
when HTTP_REQUEST_SEND {
    set http_request_send_time [clock clicks -milliseconds]
    set log_string "http_request_send_time=$http_request_send_time"
    log local0. $log_string
}
when HTTP_REQUEST_RELEASE {
    set http_request_release_time [clock clicks -milliseconds]
    set log_string "http_request_release_time=$http_request_release_time"
    log local0. $log_string
}
when SERVER_CONNECTED {
    set server_connect_time [clock clicks -milliseconds]
    set log_string "server_connect_time=$server_connect_time"
    log local0. $log_string
}
#when SERVERSSL_HANDSHAKE {
#    set client_ssl_time [clock clicks -milliseconds]
#    set log_string "client_ssl_time=$client_ssl_time"
#    log local0. $log_string
#}
when HTTP_RESPONSE priority 100 {
    set http_response_start_time [clock clicks -milliseconds]
    set log_string "http_response_start_time=$http_response_start_time"
    log local0. $log_string
}
when HTTP_RESPONSE priority 1000 {
    set http_response_time [clock clicks -milliseconds]
    set log_string "http_response_time=$http_response_time"
    log local0. $log_string
}
when HTTP_RESPONSE_RELEASE { 
    set http_response_release_time [clock clicks -milliseconds]
    set log_string "http_response_release_time=$http_response_release_time"
    log local0. $log_string
}
when SERVER_CLOSED { 
    set server_closed_time [clock clicks -milliseconds]
    set log_string "server_closed_time=$server_closed_time"
    log local0. $log_string
}
when CLIENT_CLOSED { 
    set client_closed_time [clock clicks -milliseconds]
    log local0. client_closed_time=$client_closed_time
    #set clientip [IP::remote_addr]
    #set local_hostname [info hostname]
#    set a [expr { $http_response_time - $http_request_send_time } ]
#    set b [expr { $http_request_send_time - $lb_selected_time } ]
    set c [expr { $lb_selected_time - $http_request_time } ] ; #Time_spent_in_LB_selected
    #set d [expr { $http_request_data_time - $http_request_time } ]
#    set e [expr { $http_response_time - $http_request_time } ]
    set f [expr { $http_request_release_time - $http_request_time } ] ; #Time_spent_in_All_Modules
    set g [expr { $client_accept_time - $flow_init_time } ] ; #Time_spent_in_Client_3WHS
    set h [expr { $server_connect_time - $lb_selected_time } ] ; #Time_spent_in_Server_3WHS
    set i [expr { $client_closed_time - $flow_init_time } ] ; #Total_Client_lifetime
    set j [expr { $server_closed_time - $server_connect_time } ] ; #Total_Server_Lifetime
    set log_string "::Session_Summary:: Start_Client_IP:[IP::client_addr] Start_Client_Port:[TCP::client_port] Time_spent_in_Client_3WHS:$g Time_spent_in_All_Modules:$f Time_spent_in_LB_selected:$c Time_spent_in_Server_3WHS:$h Total_Server_Lifetime:$j Total_Client_lifetime:$i"
    foreach log_loop $log_string {
        log local0. $log_loop
    }
}
