# Table of contents

1.  [iRules Index](#introduction)
2.  [SSL Orchestrator](#sslo)
3.  [SSLO_AD_with_SRV](#subparagraph1)
4.  [SSLO_Auth_insert_user_and_group](#subparagraph2)
5.  [SSLO_Custom_Cert_Verify](#subparagraph3)
6.  [SSLO_Custom_DNS](#SSLO_Custom_DNS)
7.  [SSLO_Ingress_Header](#SSLO_Ingress_Header)
8.  [SSLO_Layered_Auth](#subparagraph4)
9.  [SSLO_SNAT_Persistance](#subparagraph5)


# iRules Index <a name="introduction"></a>

Various iRules for custom deployments.  

## SSL Orchestrator iRules <a name="sslo"></a>

### [SSLO_AD_with_SRV](https://github.com/megamattzilla/iRules/tree/master/SSLO_AD_with_SRV) <a name="subparagraph1"></a>

I lied... \^_^ this is actually a bash script that is intended to be executed via crontab. When you defined NTLM servers in Big-IP you can only define by IP versus DNS names. The purpose of the script is to query DNS SRV records for NTLM servers at an interval and update the IP Addresses of existing NTLM domain server objects via TMSH. The script was created to loop through multiple active directory domains if needed.    

### [SSLO_Auth_insert_user_and_group](https://github.com/megamattzilla/iRules/tree/master/SSLO_Auth_insert_user_and_group) <a name="subparagraph2"></a>
These iRules will insert and remove username and/or group membership information into HTTP requests being sent to service chain devices. The ability to identify users requires that authentication is being performed in APM. These iRules will pull the APM session variables to insert the appropriate information into HTTP requests for service chain devices. 

There is also TCL code to be applied to an APM Visual Policy Editor -> Variable Assign action to format the users group membership at time of session creation to comma seperated groups. 
Example:
```
adgroup1,adgroup2,adgroup3
``` 
Additional documentation can be found in the project folder.  

### [SSLO_Custom_Cert_Verify](https://github.com/megamattzilla/iRules/tree/master/SSLO_Custom_Cert_Verify) <a name="subparagraph3"></a>
In SSL Orchestrator <6.x you can only block or ignore an expired origin server SSL certificate. In SSL Orchestrator >6.x there is a "Server Certificate Status Check" that can be enabled in Security Policy, however it is difficult to customize this page. 

These iRules will provide a third option to insert an HTTP header into service chain requests when the origin servers certificate is expired and the blocking page should be sent by a security inspection device in the service chain. There is a second version of the iRule provided that allows a 7 day grace period on expired origin server certificates before a blocking page is sent. The HTTP header is named:
```
X-Origin-BlockCertificate" <reason>
``` 
Any HTTP request a security inspection device in the service chain analyzes that contain the X-Origin-BlockCertificate HTTP header must be blocked regardless of reason. Reason can be showed to a user if desired in the blocking page. 

### [SSLO_Custom_DNS](https://github.com/megamattzilla/iRules/tree/master/SSLO_Custom_DNS) <a name="SSLO_Custom_DNS"></a>
This iRule, when applied to an an eplicit proxy interception rule ending in xp-4 will override the default "Cannot resolve hostname" error message with a custom response page. As a variable is epanded to supply the URL to the end user, some methods of specifying the HTML content cannot be used such as wrapping in curly braces or iFile.   

### [SSLO_Ingress_Header](https://github.com/megamattzilla/iRules/tree/master/SSLO_Ingress_Header) <a name="SSLO_Ingress_Header"></a>
These iRules will enrich HTTP request with additional information such as the original ingress destination TCP port when using a vip targeting vip aka frontend VS.

These iRules should be places on the vip targeting vip VS (frontend), proxy interception rule in SSL Orchestrator, and dummy ICAP services respectively. The dummy ICAP service are created within the SSLO wizard and then have strict updates disabled. Remove ICAP profiles of the "dummy" ICAP virtual servers and add these iRules to the corresponding first/last ICAP services.  

It is important to remove sensitive enriched header information after security inspection devices so that the headers are not leaked to external servers.  

### [SSLO_Layered_Auth](https://github.com/megamattzilla/iRules/tree/master/SSLO_Layered_Auth) <a name="subparagraph4"></a>

This iRule allows you to perform layered explicit proxy authentication (kerberos/ntlm/no authentication/basic) with F5 SSL Orchestrator. 

Additional documentation can be found in the project folder. 

### [SSLO_SNAT_Persistance](https://github.com/megamattzilla/iRules/tree/master/SSLO_SNAT_Persistance) <a name="subparagraph5"></a>

When using a SNAT pool with SSL Orchestrator there is no concept of SNAT persistence. This iRule provides the logic to persist SNAT addresses based on client address/client address and remote port/client address and remote address. 

