# SSLO Troubleshooting iRules  
SSLO_HTTP_logging.tcl can be placed on SSLO Service virtual servers that have an HTTP profile such as dummy ICAP VS, HTTP Proxy service, ICAP Service, or the SSLO -in-t-4 virtual server.   

Example logging output:  

```
Rule /Common/log_only_http_request <HTTP_REQUEST>: =============================================
Rule /Common/log_only_http_request <HTTP_REQUEST>: Client 10.5.20.103:53436 -> 172.217.6.179:443 HTTP: GET server.test-cors.s=200&credentials=false (request)
Rule /Common/log_only_http_request <HTTP_REQUEST>: Host: server.test-cors.org
Rule /Common/log_only_http_request <HTTP_REQUEST>: Connection: keep-alive
Rule /Common/log_only_http_request <HTTP_REQUEST>: Pragma: no-cache
Rule /Common/log_only_http_request <HTTP_REQUEST>: Cache-Control: no-cache
Rule /Common/log_only_http_request <HTTP_REQUEST>: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 5 Safari/537.36
Rule /Common/log_only_http_request <HTTP_REQUEST>: Accept: */*
Rule /Common/log_only_http_request <HTTP_REQUEST>: Origin: https://www.test-cors.org
Rule /Common/log_only_http_request <HTTP_REQUEST>: Sec-Fetch-Site: same-site
Rule /Common/log_only_http_request <HTTP_REQUEST>: Sec-Fetch-Mode: cors
Rule /Common/log_only_http_request <HTTP_REQUEST>: Sec-Fetch-Dest: empty
Rule /Common/log_only_http_request <HTTP_REQUEST>: Referer: https://www.test-cors.org/
Rule /Common/log_only_http_request <HTTP_REQUEST>: Accept-Encoding: gzip, deflate, br
Rule /Common/log_only_http_request <HTTP_REQUEST>: Accept-Language: en-US,en;q=0.9
Rule /Common/log_only_http_request <HTTP_REQUEST>: =============================================
Rule /Common/log_only_http_request <HTTP_RESPONSE>: =============================================
Rule /Common/log_only_http_request <HTTP_RESPONSE>: Client 10.5.20.103:53436 -> 172.217.6.179:443 HTTP status code 200 
Rule /Common/log_only_http_request <HTTP_RESPONSE>: Cache-Control: no-cache
Rule /Common/log_only_http_request <HTTP_RESPONSE>: Content-Type: application/json
Rule /Common/log_only_http_request <HTTP_RESPONSE>: Access-Control-Allow-Origin: https://www.test-cors.org
Rule /Common/log_only_http_request <HTTP_RESPONSE>: Set-Cookie: cookie-from-server=noop
Rule /Common/log_only_http_request <HTTP_RESPONSE>: Content-Encoding: gzip
Rule /Common/log_only_http_request <HTTP_RESPONSE>: X-Cloud-Trace-Context: 1977f1a05c4e33081318736c6ab52faf;o=1
Rule /Common/log_only_http_request <HTTP_RESPONSE>: Vary: Accept-Encoding
Rule /Common/log_only_http_request <HTTP_RESPONSE>: Date: Fri, 31 Jul 2020 16:40:44 GMT
Rule /Common/log_only_http_request <HTTP_RESPONSE>: Server: Google Frontend
Rule /Common/log_only_http_request <HTTP_RESPONSE>: Expires: Fri, 31 Jul 2020 16:40:44 GMT
Rule /Common/log_only_http_request <HTTP_RESPONSE>: Transfer-Encoding: chunked
Rule /Common/log_only_http_request <HTTP_RESPONSE>: =============================================
```
