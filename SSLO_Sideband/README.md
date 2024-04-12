# Made with care by Matt Stovall 2/2024.

This iRule builds upon the F5 DevCentral Article "Traffic Steering with 3rd party Policy Manager (Layered Architecture with Explicit Proxy)" https://community.f5.com/kb/technicalarticles/traffic-steering-with-3rd-party-policy-manager-layered-architecture-with-explici/278814

Features added:
* Performance improvement by Caching sideband responses 
* Load balance (Round robin) requests to a pool of sideband devices
* Retry logic
* Error and Debug logging
* Moved common configuration values to easy to change variables

Actions This iRule performs: 
1.   Collects HTTP information (HTTP host FQDN) from an explicit proxy HTTP request.
2.   Checks iRule table cache for this FQDN for a recent Bypass/Intercept decision from the sideband pool. 
3.   Makes a sideband HTTP call to a HTTP proxy with this FQDN information in the URI as a query string. (/ url=$FQDN).  
4.   Inspects HTTP response from the sideband pool (HTTP proxy) for HTTP headers indicating the explicit proxy request should be SSL intercepted. Caches that response. 
5.   Based on that response, send the explicit proxy HTTP request to the appropriate virtual server that either intercepts or bypasses SSL decryption. 

# Updates 
## 3.5
* Fixed a potential issue where the progressive check passes and subsequent iRule processing occurs before the complete HTTP response has been received.
* Added debug log when progressive check passes. Now there is a log for pass/fail/summary (after progressive check).   

# Updates 
## 3.0
* Modified logs to be more clear about what function they are coming from.  
* Added progressive check for validating we received sideband response. More details to come. 


## 2.1
* Modified variable `is_sidebandPool` to be a static variable. This will allow the iRule to be applied before the pool is created if needed.
* Added check to see if the LTM pool exists.   
* Added new CRIT log statements when number of retries has exceeded. 
* Added additional comments to retry loop.

## 2.0
* Modified sideband calls to be round robin instead of randomly selected. 
* Added retry loop with variable `is_sidebandRetryCount` to control number of retry attempts. 
  
