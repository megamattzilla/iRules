#### This iRule collect timing information at multiple events to determine latency between many client and server side F5 events. If logging is enabled, it will also provide HTTP data values in the logs to provide valuable insight into dataplane traffic.  

- You can use variable flags to log local, log remote, or insert response headers in any combination that you want.

- The iRule was designed for HTTPS virtual servers. It will fail to apply to HTTP virtual servers because certain SSL events will not be enabled. We would need to fork a HTTP version if you need that.

- Requests blocked by iRules or ASM or bypassed from ASM inspection will be gracefully skipped- no metrics for those requests. We could expand that into a later version.

- All iRule code is wrapped in catch statements, so any unexpected runtime error will gracefully fail open- you won't get metrics for that request and no impact to data plane traffic due to runtime errors.
- The iRule is looking for a HTTP request header “X-Enable-Server-Timing: 1” in order to generate the metrics.
- If this is the first HTTP request in a given TCP/TLS session, additional connection-based metrics will be included like tcp and ssl handshake time.
- All time is in milliseconds. A value of 0 means sub-millisecond. It is not currently feasible to collect sub-milliseconds in current TCL framework. 


#### Example Output: 

Local or Remote Log:  
  
*line breaks added for example*
```bash
hostname="15-1-demo.f5kc.com",
tcpID="11687535666331168",
TCP_REUSE="False",
Start_Client_IP="10.5.5.3",
Start_Client_Port="24256",
Client_TCP_Handshake="31",
Client_SSL_Handshake="99",
F5_HTTP_Request_Processing="1",
Server_TCP_Handshake="0",
Server_SSL_Handshake="32",
Pool_HTTP_response_latency="1",
F5_HTTP_Response_Processing="1",
overhead="2",
http.target="/",
http.host="www.example.local",
http_method="GET",
http.request_content_length="0",
http.status_code="200",
http.response_content_length="612",
pool_node="10.5.20.143",
virtual_server="/Common/server-timingsv2.tcl"
```

Response HTTP Headers:
```json
Server-Timings: waf, overhead;dur=2, origin;dur=1, client-ssl;dur=99, server-ssl;dur=32, client-tcp;dur=31, server-tcp;dur=0
```