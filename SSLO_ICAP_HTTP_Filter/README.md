### This iRule will filter HTTP requests that are being sent to an SSL Orchestrator ICAP service.
- This iRule only disables the ICAP REQUEST MOD profile for a virtual server. 
- Add RESPONSE MOD action to the iRule if you also need to disable ICAP HTTP response scanning as well (unless its disabled somewhere else).

Apply this iRule to the LTM virtual server for the ICAP **ssloS_{ICAP Service Name}-t-4** virtual server. 
- You may need to disable strictness on the ICAP service only. 