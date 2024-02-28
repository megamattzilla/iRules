# Made with care by Matt Stovall 2/2024.

This iRule builds upon the F5 DevCentral Article "Traffic Steering with 3rd party Policy Manager (Layered Architecture with Explicit Proxy)" https://community.f5.com/kb/technicalarticles/traffic-steering-with-3rd-party-policy-manager-layered-architecture-with-explici/278814


 This iRule: 
  1.   collects HTTP information (HTTP host FQDN) from an explicit proxy HTTP request
  2.   makes a sideband HTTP call to a HTTP proxy with this FQDN information in the URI as a query string. (/?url=${is_httpHost})  
  3.   inspects HTTP response from HTTP proxy for HTTP headers indicating the explicit proxy request should be SSL intercepted
  4.   based on that response, send the explicit proxy HTTP request to the appropriate virtual server that either intercepts or bypasses SSL decryption



# Updates 


## 2.1
* Modified variable `is_sidebandPool` to be a static variable. This will allow the iRule to be applied before the pool is created if needed.
* Added check to see if the LTM pool exists.   
* Added new CRIT log statements when number of retries has exceeded. 
* Added additional comments to retry loop.


## 2.0
* Modified sideband calls to be round robin instead of randomly selected. 
* Added retry loop with variable `is_sidebandRetryCount` to control number of retry attempts. 
  
