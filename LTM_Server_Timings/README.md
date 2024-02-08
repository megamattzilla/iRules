#### This iRule collect timing information at multiple events to determine latency between many client and server side F5 events. If logging is enabled, it will also provide HTTP data values in the logs to provide valuable insight into dataplane traffic.  

- You can use variable flags to log local, log remote, or insert response headers in any combination that you want.

- The iRule was designed for HTTPS virtual servers. It will fail to apply to HTTP virtual servers because certain SSL events will not be enabled. We would need to fork a HTTP version if you need that.

- Requests blocked by iRules or ASM or bypassed from ASM inspection will be gracefully skipped- no metrics for those requests. We could expand that into a later version.

- All iRule code is wrapped in catch statements, so any unexpected runtime error will gracefully fail open- you won't get metrics for that request and no impact to data plane traffic due to runtime errors.
- The iRule is looking for a HTTP request header “X-Enable-Server-Timing: 1” in order to generate the metrics.
- If this is the first HTTP request in a given TCP/TLS session, additional connection-based metrics will be included like tcp and ssl handshake time.
- All time is in milliseconds. A value of 0 means sub-millisecond. It is not currently feasible to collect sub-milliseconds in current TCL framework. 

#### Version History

#### v5

New Features:  
- Modified all variables with prefix `st_` to decrease probability of overlapping names with other iRules. 

Issues Fixed: 
- Requests blocked by ASM and iRules were still getting a server-timing response header inserted with erroneous values. Now blocked requests will not have server-timings response header as expected. 

#### v4

New Features:  
- Added iRule variable `enableLogWithoutHeader` to enable logging for all HTTP requests and responses regardless of HTTP request header X-Enable-Server-Timing being present. The log local and remote variables still need to be enabled in order for the relevant logging to take place. 
- Added iRule variable `serverTimingHeaderName` to specify the HTTP response header name to be inserted versus a static name.
- Added iRule variables `iruleBlockResponseCode` and `asmBlockResponseCode` to append an HTTP status code to the iRule and ASM blocked logs. 
- Added iRule variables `clientEnableTimingHeaderName` and `clientEnableTimingHeaderValue` Client HTTP header name and value that triggers debug timing to take place. 

Issues Fixed: 
- Renamed user editable variable names to camel case. 

#### v3
Issues Fixed: 
- In version 2 the log fields were shortened but only for the first HTTP request in a TCP session. Now all HTTP request logs are following the shortened format.

New Features:  
- Changed HTTP response header name `Server-Timings` to `Server-Timing`
- Detect when another iRule has issued a HTTP::respond action and trigger a log to be generated with partial stats
    - A log field `iRuleBlock= True` will be added to these logs otherwise this field is omitted. 
- Detect when ASM has blocked a request and trigger a log to be generated with partial stats
    - A log field `asmBlock= True` will be added to these logs otherwise this field is omitted.

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
The response HTTP Header will be inserted as a new header regardless if there is any existing server-timings headers supplied by the pool members. RFC https://www.w3.org/TR/server-timing/#examples 
