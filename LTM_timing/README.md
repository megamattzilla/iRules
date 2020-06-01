### Timing of common iRule Events in milliseconds. 
### Summary provided for noteable milestones. 
 
 HTTP Events require a client and server HTTP profile on virtual
 
 CLIENTSSL_HANDSHAKE requires clientssl profile on virtual
 
 SERVERSSL_HANDSHAKE requires serverssl profile on virtual 
 
### Expected output
```bash
<FLOW_INIT>:::New_Session_Details::
<FLOW_INIT>:flow_init_time=1591046533637
<CLIENT_ACCEPTED>:client_accept_time=1591046533637
<HTTP_REQUEST>:http_request_time=1591046533637
<LB_SELECTED>:lb_selected_time=1591046533639
<SERVER_CONNECTED>:server_connect_time=1591046533639
<HTTP_REQUEST_SEND>:http_request_send_time=1591046533639
<HTTP_REQUEST_RELEASE>:http_request_release_time=1591046533639
<HTTP_RESPONSE>:http_response_time=1591046533640
<HTTP_RESPONSE_RELEASE>:http_response_release_time=1591046533640
<SERVER_CLOSED>:server_closed_time=1591046533641
<CLIENT_CLOSED>:client_closed_time=1591046533641
<CLIENT_CLOSED>:::Session_Summary::
<CLIENT_CLOSED>:Start_Client_IP:10.5.20.129
<CLIENT_CLOSED>:Start_Client_Port:35450
<CLIENT_CLOSED>:Time_spent_in_Client_3WHS:0
<CLIENT_CLOSED>:Time_spent_in_All_Modules:1
<CLIENT_CLOSED>:Time_spent_in_LB_selected:1
<CLIENT_CLOSED>:Time_spent_in_Server_3WHS:0
<CLIENT_CLOSED>:Total_Server_Lifetime:2
<CLIENT_CLOSED>:Total_Client_lifetime:4
```
