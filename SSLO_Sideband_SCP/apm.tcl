## Made with care by Matt Stovall 3/2024.
## Version 0.6
## This iRule: 
##  1.  TBD 

## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of is_ has been added to each variable to make them globally unique. 
## See https://github.com/megamattzilla/iRules/blob/master/SSLO_Sideband_SCP/README.md for more details

## Requirements: 
##  1. TBD 

when HTTP_REQUEST priority 400 {
log local0. "plz work "
#set insert_uuid_header 0 
ECA::disable
set user_key "unknown:unknown" 
set user_key "[HTTP::header value X-Authenticated-User]:[HTTP::header value X-Client-IP]"

set test [ ACCESS::user getsid $user_key ]

if {  [string length $test ] >= 10 } { 
    log local0. "Found existing APM session for $user_key = $test. Skipping APM."
    sharedvar APMSID
    set APMSID $test
    ## Increment bytes in
    set bytes [ACCESS::session data get -sid $APMSID "session.stats.bytes.in"]
    set newbytes [expr { [string length [HTTP::request]] + $bytes }]
    log local0. "IN: Old bytes $bytes new bytes $newbytes"
    ACCESS::session data set -sid $APMSID "session.stats.bytes.in" $newbytes 
    ACCESS::disable

} else { 
    ## Check if session is in progress
    if { [table lookup $user_key] == 1 } {
        log local0. "Session in-progress for $user_key. Adding this request to the que. "
        ## Check for session to finish in a loop 
        ## Set a loop control variable to 0     
        set loop 0
        while { $loop < 100 } { 
            incr loop
            ## Sleep 500 miliseconds
            after 500
            ## Check if APM session is finished now
            set test [ ACCESS::user getsid $user_key ]
            if {  [string length $test ] >= 10 } { 
                log local0. "Found existing APM session for $user_key = $test. Flushing request from que."
                sharedvar APMSID
                set APMSID $test 
                ACCESS::disable
                break
            } else { continue } 
        }
    } else {
        ## New APM session 
        log local0. "Starting new session for $user_key"
        table set $user_key 1 
    }
}
}



when ACCESS_SESSION_STARTED {
log local0. "sleeping"
after 5000
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

when ACCESS_POLICY_COMPLETED { 
table delete $user_key 
}

when HTTP_RESPONSE { 
log local0. "plz work "



if {  [info exists APMSID] } { 
    log local0. "Found existing APM session for $user_key = $APMSID"
    ## Increment bytes in
    set rbytes [ACCESS::session data get -sid $APMSID "session.stats.bytes.out"]
    set rnewbytes [expr { [string length [HTTP::response]] + $rbytes }]
    log local0. "OUT: Old bytes $rbytes new bytes $rnewbytes"
    ACCESS::session data set -sid $APMSID "session.stats.bytes.out" $rnewbytes 

}
}