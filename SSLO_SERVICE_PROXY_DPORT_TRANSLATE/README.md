### SSLO Service Transparent Proxy destination port translation ( "Super Port Remap" ) 

This iRule can be applied to a SSLO Service transparent inline proxy to translate the destination port of ALL traffic to the service device (decrypted and native HTTP). Similar to port remap however it also changes the destination port of traffic to the in-line proxy that is native HTTP.  

If you have an in-line proxy that expects to see traffic on certain ports, this is useful to override the real traffic port to a port of your choosing. The "inside" port in the HTTP request payload remains the real traffic port. Traffic processed outside of this service chain device such as other SSLO services and upstream connection to origin server retains the real client destination port. 

The iRule is applied to the service VS `ssloS_{{ NAME }}-t-4` manually in TMOS 16.1+ or applied directly to the service using the SSLO Orchestrator wizard under Service -> ServiceName -> iRules in all modern SSLO versions.  

