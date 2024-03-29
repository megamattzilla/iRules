## Use v2 for best results. 

Calculates timings more accurately. Also works if OneConnect or HTTP TCP reuse is enabled.  

Expected output:
```bash
Jul 25 10:58:03 slot3/13-1-demo info tmm[12606]: Rule /Common/ltm_timing_v2 <HTTP_RESPONSE_RELEASE>: uniqueID=01658764683040489,Start_Client_IP=10.5.20.23,Start_Client_Port=8544,Client_TCP_Handshake=1,Client_SSL_Handshake=1,F5_HTTP_Request_Processing=0,Server_TCP_Handshake=0,Server_SSL_Handshake=2,Pool_HTTP_response_latency=3,F5_HTTP_Response_Processing=0
Jul 25 10:58:03 slot3/13-1-demo info tmm[12606]: Rule /Common/ltm_timing_v2 <HTTP_RESPONSE_RELEASE>: uniqueID=01658764683040489,HTTP-REUSE,Start_Client_IP=10.5.20.23,Start_Client_Port=8544,F5_HTTP_Request_Processing=0,Pool_HTTP_response_latency=3,F5_HTTP_Response_Processing=0
Jul 25 10:58:03 slot3/13-1-demo info tmm[12606]: Rule /Common/ltm_timing_v2 <HTTP_RESPONSE_RELEASE>: uniqueID=01658764683040489,HTTP-REUSE,Start_Client_IP=10.5.20.23,Start_Client_Port=8544,F5_HTTP_Request_Processing=1,Pool_HTTP_response_latency=3,F5_HTTP_Response_Processing=0
Jul 25 10:58:03 slot3/13-1-demo info tmm[12606]: Rule /Common/ltm_timing_v2 <HTTP_RESPONSE_RELEASE>: uniqueID=01658764683040489,HTTP-REUSE,Start_Client_IP=10.5.20.23,Start_Client_Port=8544,F5_HTTP_Request_Processing=0,Pool_HTTP_response_latency=3,F5_HTTP_Response_Processing=0
Jul 25 10:58:03 slot3/13-1-demo info tmm[12606]: Rule /Common/ltm_timing_v2 <HTTP_RESPONSE_RELEASE>: uniqueID=01658764683040489,HTTP-REUSE,Start_Client_IP=10.5.20.23,Start_Client_Port=8544,F5_HTTP_Request_Processing=0,Pool_HTTP_response_latency=2,F5_HTTP_Response_Processing=0
```

## server-timings.tcl Notes  
Apply to virtual server to insert a HTTP response header server-timings when a debug HTTP request header is received.  
Note: TCL clock clicks -milliseconds can only measure in increments of 1ms, so timing events in sub-millisecond increments does not work.  
All sub-millisecond timing events are rounded to 1 millisecond.  
## LTM_event_timing.tcl Notes   
### Timing of common iRule Events in milliseconds throughout the lifetime of a TCP session. 

### Summary provided for noteable milestones. 
 
 HTTP Events require a client and server HTTP profile on virtual
 
 **ONECONNECT will skew some of the results**
 
 CLIENTSSL_HANDSHAKE requires clientssl profile on virtual
 
 SERVERSSL_HANDSHAKE requires serverssl profile on virtual 
 
### Example output

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
