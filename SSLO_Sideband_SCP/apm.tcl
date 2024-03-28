## Made with care by Matt Stovall 3/2024.
## Version 0.6
## This iRule: 
##  1.  TBD 

## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of is_ has been added to each variable to make them globally unique. 
## See https://github.com/megamattzilla/iRules/blob/master/SSLO_Sideband_SCP/README.md for more details

## Requirements: 
##  1. TBD 

when HTTP_REQUEST priority 400 {
#log local0. "plz work "
#set insert_uuid_header 0 
ECA::disable
set user_key "[HTTP::header value X-Authenticated-User]:[HTTP::header value X-Client-IP]"

set user_uuid [ ACCESS::user getsid $user_key ]

if {  [string length $user_uuid ] >= 10 } { 
log local0. "Found existing session for $user_key = $user_uuid. Skipping APM."
sharedvar APMSID
set APMSID $user_uuid 
ACCESS::disable
}
}



when ACCESS_SESSION_STARTED {
log local0. "Starting session for $user_key"
ACCESS::session data set session.user.clientip [HTTP::header value X-Client-IP]
ACCESS::session data set session.custom.scp.groups [HTTP::header value X-Authenticated-UserGroups]
ACCESS::session data set session.custom.scp.username [HTTP::header value X-Authenticated-User]
#ACCESS::session data set session.login.last.username [HTTP::header value X-Authenticated-User]
ACCESS::session data set session.login.last.originalIP [IP::client_addr]
#ACCESS::session data set session.logon.last.result 1
ACCESS::session data set session.user.uuid $user_key
ACCESS::session data set session.ntlm.last.result 1
#ACCESS::session data set session.user.ip_session apm.session.ip.192.168.254.100/Common/scp
}