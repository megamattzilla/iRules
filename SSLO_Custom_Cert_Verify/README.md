# These iRules will enrich HTTP request to service chain devices with an HTTP header containing origin server cetificate status.
## Note: This iRule has 2 parts.
## Requires SSLO 6.x or later

## Prequsites
- SSL Orchestrator SSL configuration has Expire Certificate Response set to ignore
- SSL Orchestrator SSL configuration has Untrusted Certificate Authority set to ignore
- SSL Orchestrator Security Policy has Server Certificate Status Check disabled

1.) First choose only one of these iRules depending on if a 7 day grace period is desired:  
interceptionvs_certverity.tcl  
interceptionvs_certverity_graceperiod.tcl

Then apply the iRule to your relevant SSLO topologies -in-t-4 Interception Rule in the SSL Orchestrator wizard. 

2.) Create a dummy ICAP service in SSLO wizard and remove ICAP profiles, or use an existing dummy ICAP service. Then icapvs_certverify.tcl code should be merged into your existing dummy ICAP services iRule ssloS_<name>/ssloS_<name>-ic  
**This iRule could be modified to sent a static response from F5 instead of insert the custom HTTP header.  

![SSLO ICAP iRule](https://raw.githubusercontent.com/megamattzilla/iRules/master/SSLO_Custom_Cert_Verify/irule_example.png)


