### This iRule will filter HTTP requests that are being sent to an SSL Orchestrator in-line service.
- This iRule bypasses the entry virtual service for an in-line service by directing traffic directly to the re-entry virtual server. 

Apply this iRule to the LTM virtual server for the in-line service **ssloS_{In-line Service Name}-t-4** virtual server. 
- The iRule can also be added via SSLO Orchestrator UI Services section. 