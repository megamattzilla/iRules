### This collection of iRules will allow you to do a few neat things:
- Perform SAML explicit proxy authentication for a specified client OS type (Mac for example). 
- Perform layered Kerberos/NTLM authentication for everything else
    - See [Layered Auth](https://github.com/megamattzilla/iRules/tree/master/SSLO_Layered_Auth) for the iRule code to do that.  

iRules in this collection:
- FrontDoor-SAML.tcl applied to front door VIP to flip things to SAML SSLO topology for SAML auth
- (Placeholder SSLO_AuthHelper.tcl) also applied to front door VIP to perform the authentication for everything else (see fine print below for more details)
- APM-SAML-VS.tcl applied to LTM + APM front door virtual server 
- APM-SAML-Filter-VS.tcl applied to vip-targeting-vip for the LTM + APM front door virtual server
- functionJS.tcl applied to either 1.) both of the functionJS VS or option #2.) to the SSLO functionJS topology virtual servers (-xp and -in-t-4) if you go that route. 

### How to install (Under Construction)
- Create SSLO SAML topology. Assign SSLO captive portal access policy (points to APM Vip-target-vip port)
    - No iRules Needed
- Create APM Vip-targeting-vip. Listens on the port specified by SSLO captive portal access policy 
    - Attach APM-SAML-Filter-VS.tcl iRule
- Create APM VS. Listens on a dummy port. Is fed traffic by the APM Vip-targeting-vip. Has APM access policy applied to do SAML auth.
    - Attach APM-SAML-VS.tcl iRule
- Create Explicit proxy front door VS
    - Attach FrontDoor-SAML.tcl and SSLO_AuthHelper.tcl ((with fine print edit to auth helper))
- Create functionJS virtual servers. You can use a dummmy SSLO topology but it will create alot of objects you wont need. Follow functionJS.tmsh file to set these up. 
    - Attach functionJS.tcl iRule to both functionJS-xp and functionJS-in-t-4

### Fine Print
To work effectively, whatever the user-agent matching condition present in FrontDoor-SAML.tcl, you need to add the same conditional to SSLO_AuthHelper.tcl at the very top with only a return statement as the matching action. This prevents from needing to do complicated event disabling so that both frontdoor iRule logic can exist on the same frontdoor VS. 
