# This iRule will perform SNAT persistance on connections leaving SSL Orchestrator on egress. 

## Note: Do not apply SNAT via the SSL Orchestrator egress settings in the wizard if SNAT persistance is desired. 
When using a SNAT pool with SSL Orchestrator there is no concept of SNAT persistence. This iRule provides the logic to persist SNAT addresses based on client address/client address and remote port/client address and remote address. Uncomment the line specified in the iRule to perform the desired SNAT. 

Then apply the iRule to your relevant SSLO topologies -in-t-4 Interception Rule in the SSL Orchestrator wizard. 

