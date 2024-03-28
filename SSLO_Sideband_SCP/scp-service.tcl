## Made with care by Matt Stovall 3/2024.
## Version 0.6
## This iRule: 
##  1.   Collects HTTP information (HTTP host FQDN) from an explicit proxy HTTP request.
##  2.   Checks iRule table cache for this FQDN for a recent Bypass/Intercept decision from the sideband pool. 
##  3.   Makes a sideband HTTP call to a HTTP proxy with this FQDN information in the URI as a query string. (/ ?url=$FQDN).  
##  4.   Inspects HTTP response from the sideband pool (HTTP proxy) for HTTP headers indicating the explicit proxy request should be SSL intercepted. Caches that response. 
##  5.   Based on that response, send the explicit proxy HTTP request to the appropriate virtual server that either intercepts or bypasses SSL decryption. 

## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of is_ has been added to each variable to make them globally unique. 
## See https://github.com/megamattzilla/iRules/blob/master/SSLO_Sideband/README.md for more details

## Requirements: 
##  1. To be applied to a vip-targeting-vip which points to an explicit proxy virtual server.
##  2. Configure a LTM pool with your sideband pool members.
##  3. Configure those sideband pool members to reply with the Bypass/Intercept strings this iRule is looking for.   
#TODO: exit if there is no headers to decrypt.

when HTTP_REQUEST {

sharedvar connectHeaderClientIP
sharedvar connectHeaderUserGroups
sharedvar connectHeaderUser 
sharedvar APMSID 

if {[info exists connectHeaderClientIP]} { 

HTTP::header insert X-Authenticated-User $connectHeaderUser  
HTTP::header insert X-Client-IP $connectHeaderClientIP
HTTP::header insert X-APM-SID $APMSID
log local0. "plz work $connectHeaderClientIP $connectHeaderUser $connectHeaderUserGroups "
}
if {[info exists APMSID ]} { 
    if  { [ catch { [string length [ACCESS::session data get -sid $APMSID "session.ad.last.attr.memberOf"]] > 0 } ] } {
            #Insert found group into HTTP Header
            HTTP::header insert X-Authenticated-Groups [ACCESS::session data get -sid $APMSID "session.ad.last.attr.memberOf"]
            }
}
}