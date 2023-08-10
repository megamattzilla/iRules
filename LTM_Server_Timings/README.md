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
tcpID="11691678033746348",
tcpReuse="False",
cIP="10.5.5.3",
cPort="39892",
cTCP="65",
cTLS="122",
f5Req="1",
sTCP="1",
sTLS="28",
poolRes="1",
f5Res="0",
overhead="1",
uri="/",
host="10.5.20.245:9003",
method="HEAD",
reqLength="0",
statusCode="200",
resLength="612",
vs="/Common/server-timingsv2.tcl",
pool="/Common/nginx-ssl 10.5.20.143 443",
referrer="http://example.com",
cType="application/json",
userAgent="curl/7.88.1",
httpv="1.1",
vip="10.5.20.245"
```

Response HTTP Headers:
```json
Server-Timings: waf, overhead;dur=2, origin;dur=1, client-ssl;dur=99, server-ssl;dur=32, client-tcp;dur=31, server-tcp;dur=0
```