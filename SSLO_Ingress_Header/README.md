# These iRules will enrich HTTP request with additional information such as the original ingress destination TCP port when using a vip targeting vip aka frontend VS.

These iRules should be places on the vip targeting vip VS (frontend), proxy interception rule in SSL Orchestrator, and dummy ICAP services respectively. The dummy ICAP service are created within the SSLO wizard and then have strict updates disabled. Remove ICAP profiles of the "dummy" ICAP virtual servers and add these iRules to the corresponding first/last ICAP services.  

It is important to remove sensitive enriched header information after security inspection devices so that the headers are not leaked to external servers.  
