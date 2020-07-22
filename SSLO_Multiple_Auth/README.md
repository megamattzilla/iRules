## This iRule allows you to perform multiple authentication (kerberos and then captive portal) with F5 SSL Orchestrator in Explicit Proxy interception. 

A manually created "front end" virtual server must exist to intercept HTTP requests before the SSL Orchestrator Explicit proxy virtual servers. 
Point users proxy to this front end virtual IP and port first. The iRule will direct traffic to the SSLO virtual server with authentication profiles corresponding to the clients authentication preference.    

### Prerequisite: 
Edit the variables in the iRule for the virtual server names to fit your environment.   
Create SSLO Topology with access profile performing Kerberos authentication  
Create SSLO Topology with access profile performing captive portal auth (SSLO access profile)  
- Create an SWG-Transparent access profile. This profile will be attached to the separate captive portal “login” virtual server.
- ProfileType:selectSWG-Transparent.
- ProfileScope:SSLO introduces a new profile scope(named)for captive portal authentication that must match between it and the SWG-Transparent access profile Select Named.
- Named Scope: Enter a unique name here to represent the “authentication domain” shared between the two access profiles. For this lab, use something like “sslo”.
- CaptivePortal:leave this as disabled.It is only enabled inthe SSL Orchestrator access profile.
- Language:select the desired language.  
Create LTM Virtual server to perform the captive portal login page with captive portal access policy (SWG-transparent profile)
- ProfileType:selectSSLOrchestrator.
- ProfileScope:select Named to match the SWG-Transparent access profile.
- NamedScope:enter the same named scope used in the SWG-Transparent profile(ex.“sslo”). o CaptivePortal:set this to enabled.
- PrimaryAuthenticationURI:this is the URL that the SSLO transparent proxy will redirect new users to, represented by and resolving to the separate virtual server instance and SWG-Transparent access profile. This would be a full URL, example: https://login.f5labs.com.
- Language:select the desired language.
### The iRule was written to be as fast as feasibly possible, sacrificing some human readability.  

### iRule Workflow: 
![iRule Workflow](https://raw.githubusercontent.com/megamattzilla/iRules/master/SSLO_Multiple_Auth/irule_flow.jpeg)
