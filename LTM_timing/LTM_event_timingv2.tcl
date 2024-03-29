#Timing of each common iRule Events. Summary provided for notable milestones. 
#CLIENTSSL_HANDSHAKE requires clientssl profile on virtual
#SERVERSSL_HANDSHAKE requires serverssl profile on virtual
when FLOW_INIT {
    #Init Variables 
    set flow_init_time [clock clicks -milliseconds]
    set uniqueID [TMM::cmp_unit][clock clicks]
    set client_accept_start_time 0
    set client_accept_time 0
    set CLIENTSSL_CLIENTHELLO_SEND 0
    set CLIENTSSL_SERVERHELLO_SEND 0
    set client_ssl_time 0 
    set http_request_count 0
    set http_request_start_time 0 
    set http_request_time 0
    set asm_request_done_time 0 
    set lb_selected_time 0 
    set lb_failed_time 0 
    set lb_queued_time 0 
    set lb_poolmember_ip 0
    set lb_failmember_ip 0 
    set http_request_send_time 0 
    set http_request_release_time 0 
    set server_connect_time 0 
    set SERVERSSL_CLIENTHELLO_SEND 0 
    set SERVERSSL_SERVERHELLO 0 
    set SERVERSSL_SERVERCERT 0 
    set server_ssl_time 0 
    set http_response_count 0 
    set http_response_start_time 0 
    set http_response_time 0 
    set http_response_release_time 0 
    set server_closed_time 0 
}
when CLIENT_ACCEPTED priority 100 {
    set client_accept_start_time [clock clicks -milliseconds]
}
when CLIENT_ACCEPTED priority 1000 {
    set client_accept_time [clock clicks -milliseconds]
}
when CLIENTSSL_CLIENTHELLO {
    set CLIENTSSL_CLIENTHELLO_SEND [clock clicks -milliseconds]
}
when CLIENTSSL_SERVERHELLO_SEND {
    set CLIENTSSL_SERVERHELLO_SEND [clock clicks -milliseconds]
}
when CLIENTSSL_HANDSHAKE {
    set client_ssl_time [clock clicks -milliseconds]
}
when HTTP_REQUEST priority 100 {
    incr http_request_count
    set http_request_start_time [clock clicks -milliseconds]
}
when HTTP_REQUEST priority 1000 {
    set http_request_time [clock clicks -milliseconds]
}
#Requires ASM profile to have iRule events enabled to populate data. Its ok if its disabled in the ASM policy and still uncommented here.   
when ASM_REQUEST_DONE {
    set asm_request_done_time [clock clicks -milliseconds]
}
when LB_SELECTED {
    set lb_selected_time [clock clicks -milliseconds]
    set lb_poolmember_ip [LB::server addr]
}
when LB_FAILED {
    set lb_failed_time [clock clicks -milliseconds]
    set lb_failmember_ip [LB::server addr]
}
when LB_QUEUED {
    set lb_queued_time [clock clicks -milliseconds]
}
when SERVER_CONNECTED {
    set server_connect_time [clock clicks -milliseconds]
}
when SERVERSSL_CLIENTHELLO_SEND {
    set SERVERSSL_CLIENTHELLO_SEND [clock clicks -milliseconds]
}
when SERVERSSL_SERVERHELLO {
    set SERVERSSL_SERVERHELLO [clock clicks -milliseconds]     
}
when SERVERSSL_SERVERCERT {
    set SERVERSSL_SERVERCERT [clock clicks -milliseconds]
}
when SERVERSSL_HANDSHAKE {
    set server_ssl_time [clock clicks -milliseconds]
}
when HTTP_REQUEST_SEND {
    set http_request_release_time [clock clicks -milliseconds]
}
when HTTP_REQUEST_RELEASE {
    incr http_response_count
    set http_request_release_time [clock clicks -milliseconds]
}
when HTTP_RESPONSE priority 100 {
    set http_response_start_time [clock clicks -milliseconds]
}
when HTTP_RESPONSE priority 1000 {
    set http_response_time [clock clicks -milliseconds]
}
when HTTP_RESPONSE_RELEASE { 
    set http_response_release_time [clock clicks -milliseconds]

    # catch if important stats are missing
    if { ($http_request_release_time equals 0) || ($asm_request_done_time equals 0 ) } {
        catch { log local0. "Stats Collection error. Request likely blocked or ASM bypassed,uniqueID=$uniqueID,Start_Client_IP=[IP::client_addr],Start_Client_Port=[TCP::client_port]" }
        return
    }

    #moved logging to here to fix HTTP TCP reuse breaking stats in some situations
    # Log TCP level stats if this is the first http request In this TCP session. 
    if { $http_request_count equals 1 } {
        catch {
        set a [expr { $client_accept_time - $flow_init_time } ] ; #Time_spent_in_Client_3WHS
        set b [expr { $client_ssl_time - $CLIENTSSL_CLIENTHELLO_SEND } ] ; #measure client side ssl handshake time.
        set c [expr { $asm_request_done_time - $http_request_start_time } ] ; #F5_HTTP_Request_Processing_Request
        set d [expr { $server_connect_time - $lb_selected_time } ] ; #Time_spent_in_Server_3WHS
        set e [expr { $server_ssl_time - $SERVERSSL_CLIENTHELLO_SEND } ] ; #measure server side ssl handshake time.
        set f [expr { $http_response_start_time - $http_request_release_time } ] ; #Pool_HTTP_response_latency
        set g [expr { $http_response_release_time - $http_response_start_time } ] ; #F5_HTTP_Response_Processing

        log local0. "uniqueID=$uniqueID,Start_Client_IP=[IP::client_addr],Start_Client_Port=[TCP::client_port],Client_TCP_Handshake=$a,Client_SSL_Handshake=$b,F5_HTTP_Request_Processing=$c,Server_TCP_Handshake=$d,Server_SSL_Handshake=$e,Pool_HTTP_response_latency=$f,F5_HTTP_Response_Processing=$g"
        #uncomment below for absolute timings
        #log local0. "uniqueID=$uniqueID,Start_Client_IP=[IP::client_addr],Start_Client_Port=[TCP::client_port],FLOW_INIT=$flow_init_time,CLIENT_ACCEPTED_START=$client_accept_start_time,CLIENT_ACCEPT_DONE=$client_accept_time,HTTP_REQUEST_START=$http_request_start_time,HTTP_REQUEST_DONE=$http_request_time,ASM_REQUEST_DONE=$asm_request_done_time,LB_SELECTED=$lb_selected_time,LB_FAILED=$lb_failed_time,LB_QUEUED=$lb_queued_time,LB_POOL_MEMBER=$lb_poolmember_ip,LB_FAILED_IP=$lb_failmember_ip,HTTP_REQUEST_SEND=$http_request_send_time,HTTP_REQUEST_RELEASE=$http_request_release_time,SERVER_CONNECTED=$server_connect_time,HTTP_RESPONSE_START=$http_response_start_time,HTTP_RESPONSE_DONE=$http_response_time,HTTP_RESPONSE_RELEASE=$http_response_release_time" 
        } 
} else {
        #Only log http Level stats when this is not the first http Request.
        catch {
        set c [expr { $asm_request_done_time - $http_request_start_time } ] ; #F5_HTTP_Request_Processing_Request
        set f [expr { $http_response_start_time - $http_request_release_time } ] ; #Pool_HTTP_response_latency
        set g [expr { $http_response_release_time - $http_response_start_time } ] ; #F5_HTTP_Response_Processing
        log local0. "uniqueID=$uniqueID,HTTP-REUSE,Start_Client_IP=[IP::client_addr],Start_Client_Port=[TCP::client_port],F5_HTTP_Request_Processing=$c,Pool_HTTP_response_latency=$f,F5_HTTP_Response_Processing=$g"
        #uncomment below for absolute timings
        #log local0. "uniqueID=$uniqueID,HTTP-REUSE,Start_Client_IP=[IP::client_addr],Start_Client_Port=[TCP::client_port],FLOW_INIT=$flow_init_time,CLIENT_ACCEPTED_START=$client_accept_start_time,CLIENT_ACCEPT_DONE=$client_accept_time,HTTP_REQUEST_START=$http_request_start_time,HTTP_REQUEST_DONE=$http_request_time,ASM_REQUEST_DONE=$asm_request_done_time,LB_SELECTED=$lb_selected_time,LB_FAILED=$lb_failed_time,LB_QUEUED=$lb_queued_time,LB_POOL_MEMBER=$lb_poolmember_ip,LB_FAILED_IP=$lb_failmember_ip,HTTP_REQUEST_SEND=$http_request_send_time,HTTP_REQUEST_RELEASE=$http_request_release_time,SERVER_CONNECTED=$server_connect_time,HTTP_RESPONSE_START=$http_response_start_time,HTTP_RESPONSE_DONE=$http_response_time,HTTP_RESPONSE_RELEASE=$http_response_release_time" 
        }
    }
}

when SERVER_CLOSED { 
    set server_closed_time [clock clicks -milliseconds]
    # log server-side TCP Close information
    catch {
    set serverLifetime [expr { $server_closed_time - $server_connect_time } ] ; #Total_Server_TCP_Lifetime
    log local0. "uniqueID=$uniqueID,LB_POOL_MEMBER=$lb_poolmember_ip,serverLifetime=$serverLifetime,HTTP_Response_Count=$http_response_count"
    }
}
when CLIENT_CLOSED { 
    set client_closed_time [clock clicks -milliseconds]
    # log client-side TCP Close information
    catch {
    set i [expr { $client_closed_time - $flow_init_time } ] ; #Total_Client_lifetime
    set clientLifetime [expr { $client_closed_time - $flow_init_time } ] ; #Total_Client_TCP_Lifetime
    log local0. "uniqueID=$uniqueID,Start_Client_IP=[IP::client_addr],Start_Client_Port=[TCP::client_port],VS_IP=[IP::local_addr],Port=[TCP::local_port],clientLifetime=$clientLifetime,HTTP_Request_Count=$http_request_count"
    }
}