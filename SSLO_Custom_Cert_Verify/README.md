# These iRules will enrich HTTP request to service chain devices with an HTTP header containing origin server cetificate status.
## Note: This iRule has 2 parts.
## Requires SSLO 6.x or later  
1.) First choose only one of these iRules depending on if a 7 day grace period is desired:  
interceptionvs_certverity.tcl  
interceptionvs_certverity_graceperiod.tcl

Then apply the iRule to your relevant SSLO topologies -in-t-4 Interception Rule in the SSL Orchestrator wizard. 

2.) Create a dummy ICAP service in SSLO wizard and remove ICAP profiles, or use an existing dummy ICAP service. Then icapvs_certverify.tcl code should be merged into your existing dummy ICAP services iRule ssloS_<name>/ssloS_<name>-ic  

![SSLO ICAP iRule](https://raw.githubusercontent.com/megamattzilla/iRules/master/SSLO_Custom_Cert_Verify/irule_example.png)


