# Overview
### Generate custom metrics in iRule events and deliver the data to a prometheus endpoint (virtual server)!!!!!

This demo will utilize two iRules. 

- One iRule to collect the data for the custom f5_fqdn metric and store the data in an iRule session table.
    - The custom metric f5_fqdn is the # of times a dynamic HTTP::host value has been requested. There are three labels on the metric that provide the HTTP::host value, the clientSSL profile, and name of the LTM virtual server. 
- One iRule to listen for prometheus scrape requests. Upon receiving a request, the iRule will query the data in the iRule session table and deliver the data in a compatible format for prometheus. 

Example output from the prometheus_response_generator iRule:
```
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Server: BigIP
* HTTP/1.0 connection set to keep alive
< Connection: Keep-Alive
< Content-Length: 485
< 

# TYPE f5_fqdn_ counter
f5_fqdn{virtualServer="/Common/asm-demo-https",sslProfile="/Common/example.f5kc.lab.local",fqdn="jane.f5.com"} 21
f5_fqdn{virtualServer="/Common/asm-demo-https",sslProfile="/Common/example.f5kc.lab.local",fqdn="bob.f5.com"} 11
f5_fqdn{virtualServer="/Common/asm-demo-https",sslProfile="/Common/example.f5kc.lab.local",fqdn="ToddMcTodderson.f5.com"} 16
f5_fqdn{virtualServer="/Common/asm-demo-https",sslProfile="/Common/example.f5kc.lab.local",fqdn="matt.f5.com"} 26
```

To setup these iRules:
1. Place the iRule `prometheus_data_collector.tcl` on an existing virtual server with an HTTP and SSL profile where you would like to start collecting metrics.
2.  Create a net-new virtual server `prometheus_response_generator` with a default HTTP profile and SSL profile of your choice on a unique port such as 9090.
3. Place the iRule `prometheus_response_generator.tcl` on virtual server `prometheus_response_generator` you just created.
4. Edit variables in  `prometheus_data_collector.tcl` and `prometheus_response_generator.tcl` if desired.
 - `prometheus_response_generator.tcl` by default will limit the dynamic collection to 1,000 FQDNs.
 - `prometheus_response_generator.tcl` by default will NOT require authentication. This can be enabled by using `useAuthentiation` with a value of 1. Also set `basicAuthSHA256` to your required SHA256 value. 

# Updates 


## 2/1/2024 
* Version 1.0
