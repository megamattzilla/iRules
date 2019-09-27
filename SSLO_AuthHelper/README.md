# This iRule allows you to perform layered authentication (kerberos/ntlm/no authentication) with F5 SSL Orchestrator. 
### A manually created "front end" virtual server must exist to intercept HTTP requests before the SSL Orchestrator Explicit proxy virtual servers. Point users proxy to this front end virtual IP and port first. The iRule will direct traffic to the SSLO virtual server with authentication profiles corresponding to the clients authentication preference.  
### Prerequisite: Edit the variables for the virtual server names to fit your enviroment. 
### The iRule was written to be as fast as feasibly possible, sacrificing some human readability.  
![iRule Workflow](https://raw.githubusercontent.com/megamattzilla/iRules/master/SSLO_AuthHelper/irule_flow.png)
