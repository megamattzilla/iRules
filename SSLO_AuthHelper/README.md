# This iRule allows you to perform layered Kerberos and NTLM authentication with F5 SSL Orchestrator v14.1. 
### A manually created virtual server must be created to intercept HTTP requests before the SSLo Explicit proxy VS servers. Point users proxy to this virtual IP and port first. The iRule will direct traffic to the SSLO virtual server with authentication profiles corresponding to the clients authentication preference.  
### Prerequisite: Edit the virtual statements in the iRule corresponding to your virtual server names. 
### The iRule was written to be as fast as feasibly possible, sacrificing some human readability.  
![iRule Workflow](https://raw.githubusercontent.com/megamattzilla/iRules/master/SSLO_AuthHelper/irule_flow.png)
