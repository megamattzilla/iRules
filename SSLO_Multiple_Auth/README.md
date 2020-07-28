# Version 1.3
## This iRule allows you to perform multiple authentication methods (kerberos and then captive portal) with F5 SSL Orchestrator in Explicit Proxy interception. 

A manually created "front end" virtual server must exist to intercept explicit proxy HTTP requests before the SSL Orchestrator Explicit proxy virtual servers.   
Point users proxy to this front end virtual IP and port first. The iRule will direct traffic to the SSLO virtual server with relevant authentication profiles.    

All clients will be directed to authenticate with a 407 Proxy Authentication first. 
If they fail to authenticate with kerberos, APM will redirect their explicit proxy HTTP (or HTTPS) request to the captive portal login page. 

### Prerequisites: 
Edit the variables in the **SSLO_vip_target_vip_multiple_auth.tcl** iRule for the virtual server names to fit your environment.   

Create SSLO Topology with access profile performing explicit proxy 407  Kerberos authentication.  
The VPE should have a raise iRule event (ID = 42) on the fallback branch on the Kerberos object.     
![VPE Raise iRule](https://raw.githubusercontent.com/megamattzilla/iRules/master/SSLO_Multiple_Auth/vpe_raise_irule.png)
  
Create LTM Virtual server to perform the captive portal login page with captive portal access policy (SWG-transparent profile)  
- Create an SWG-Transparent access profile. This profile will be attached to the separate captive portal “login” virtual server.
- Profile Type: selectSWG-Transparent.
- Profile Scope: SSLO introduces a new profile scope(named)for captive portal authentication that must match between it and the SWG-Transparent access profile Select Named.
- Named Scope: Enter a unique name here to represent the “authentication domain” shared between the two access profiles. For this lab, use something like “sslo”.
- CaptivePortal: leave this as disabled. It is only enabled in the SSL Orchestrator access profile.
- Language:select the desired language.
- Attach the SWG-Transparent profile to the LTM captive portal virtual server

  
Create SSLO Topology with access profile performing captive portal auth (SSLO access profile).      
- ProfileType: select SSL Orchestrator.
- ProfileScope: select Named to match the SWG-Transparent access profile.
- NamedScope: enter the same named scope used in the SWG-Transparent profile(ex.“sslo”).   
- CaptivePortal: set this to enabled.
- Primary Authentication URI: this is the URL that the SSLO transparent proxy will redirect new users to, represented by and resolving to the separate virtual server instance and SWG-Transparent access profile. This would be a full URL, example: https://login.f5labs.com.
- Language:select the desired language.
- Modify the interception rule for the -in-t-4 VS to include the SSL Orchestrator profile


Attach iRules
- Attach iRule SSLO_vip_target_vip_multiple_auth.tcl to the LTM front end vip-targeting-vip virtual server (proxy IP and port that clients point to)
- Attach iRule SSLO_captive_ltm_vs_multiple_auth.tcl to the LTM captive portal virtual server (not SSLO)
- Attach iRule SSLO_captiveportal-in-t-4_vs_multiple_auth.tcl to the captive portal -in-t-4 virtual server
- Attach iRule SSLO_kerberos-xp-4_vs_multiple_auth.tcll to the kerberos SSLO -in-t-4 virtual server
- Attach iRule SSLO_add_user_and_group_vs.tcl to the SSLO service VS that inserts username/usergroup into HTTP headers

### Upcoming Features
- Add a no-auth URL whitelist to the SSLO_vip_target_vip_multiple_auth.tcl iRule
- Add a check to see if users fail to redirect to the captive portal (servers that dont support captive portal) and create an option to fail-open 

### The iRule was written to be as fast as feasibly possible, sacrificing some human readability.  

### iRule Workflow: 
![iRule Workflow](https://raw.githubusercontent.com/megamattzilla/iRules/master/SSLO_Multiple_Auth/irule_flow.jpeg)
