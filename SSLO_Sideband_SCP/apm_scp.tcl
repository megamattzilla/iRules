
## Made with care by Matt Stovall 3/2024.
## Version 0.9
## This iRule: 
##  1.  TBD 

## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of is_ has been added to each variable to make them globally unique. 
## See https://github.com/megamattzilla/iRules/blob/master/SSLO_Sideband_SCP/README.md for more details
## Requirements: 
##  1. TBD 
when HTTP_REQUEST priority 10 {
    ECA::disable
    ACCESS::disable
}
when HTTP_REQUEST priority 400 {
    ###User-Edit Variables start###
    set is_debugLogging 1 ; #0 = Disabled, 1 = Enabled
    set static::prod_scp_sslo "/Common/sslo_noAuth.app/sslo_noAuth-xp-4"
    ###User-Edit Variables end###

    ###User-Edit Variables end###

    ACCESS::enable
    ECA::disable
    set user_key "[HTTP::header value X-Authenticated-User]:[HTTP::header value X-Client-IP]"
    
    if { $user_key eq ":"} {
        HTTP::header insert X-Client-IP [IP::client_addr]
        HTTP::header insert X-Authenticated-User NoMCPHeader
        set user_key "NOMCPHEADER:[IP::client_addr]"
    }

    set user_uuid [lindex [lsort [ACCESS::user getsid $user_key] ] 0]


    if { $is_debugLogging == 1 } {log local0. "CHECKING USER $user_key $user_uuid"}
    if { $is_debugLogging == 1 } {log local0. "I AM HIITING APM IRULE LOGIC and USER_KEY is : [table lookup $user_key]"}

    if {  [string length $user_uuid ] >= 10 } { 
        if { $is_debugLogging == 1 } {log local0. "Found existing APM session for $user_key = $user_uuid. Skipping APM."}
        sharedvar APMSID
        set APMSID $user_uuid
        #TODO:move to seperate iRule for bytes
        ## Increment bytes in
        set bytes [ACCESS::session data get -sid $APMSID "session.stats.bytes.in"]
        set newbytes [expr { [string length [HTTP::request]] + $bytes }]
        if { $is_debugLogging == 1 } {log local0. "IN: Old bytes $bytes new bytes $newbytes"}
        ACCESS::session data set -sid $APMSID "session.stats.bytes.in" $newbytes 
        ACCESS::disable

    } else { 
        ## Check if session is in progress
        if { [table lookup $user_key] == 1 } {
            if { $is_debugLogging == 1 } {log local0. "Session in-progress for $user_key. Adding this request to the queue"}
            ## Check for session to finish in a loop 
            ## Set a loop control variable to 0     
            set loop 0
            while { $loop < 200 } { 
                incr loop
                ## Sleep 500 milliseconds
                after 500
                ## Check if APM session is finished now
                set user_uuid [lindex [lsort [ACCESS::user getsid $user_key] ] 0]
                if {  [string length $user_uuid ] >= 10 } { 
                    if { $is_debugLogging == 1 } {log local0. "Found existing APM session for $user_key = $user_uuid. Flushing request from queue"}
                    sharedvar APMSID
                    set APMSID $user_uuid 
                    ACCESS::disable
                    break
                #TODO: if last loop disable APM to fail open versus dumping a bunch of requests into APM.
                } else { continue } 
            }
        } else {
            ## New APM session 
            if { $is_debugLogging == 1 } {log local0. "Starting new session for $user_key"}
            table set $user_key 1
        }
    }
            sharedvar connectHeaderClientIP
            sharedvar connectHeaderGroups
            sharedvar connectHeaderUser 
            sharedvar AMPSID
            set connectHeaderClientIP [HTTP::header value X-Client-IP]
            set connectHeaderGroups [HTTP::header value X-Authenticated-Groups]
            set connectHeaderUser [HTTP::header value X-Authenticated-User]
            virtual $static::prod_scp_sslo
}



when ACCESS_SESSION_STARTED {
if { $is_debugLogging == 1 } {log local0. "Starting session for $user_key"}
    ACCESS::session data set session.user.clientip [HTTP::header value X-Client-IP]
    ACCESS::session data set session.custom.scp.groups [HTTP::header value X-Authenticated-Groups]
    ACCESS::session data set session.custom.scp.username [HTTP::header value X-Authenticated-User]
    ACCESS::session data set session.login.last.originalIP [IP::client_addr]
    ACCESS::session data set session.custom.uuid $user_key
    ACCESS::session data set session.user.uuid $user_key
    ACCESS::session data set session.ntlm.last.result 1
}

when ACCESS_POLICY_COMPLETED {     
    ## Get first SID
    set user_uuid [lindex [lsort [ACCESS::user getsid $user_key] ] 0]
    if {  [string length $user_uuid ] >= 10 } {  
        ## Get this TCP sessions ACCESS SID
        set sidOfThisTCP [ACCESS::session sid]
        
        ## Convert external SID to internal
        set internalFirstSID [ACCESS::user getkey $user_uuid]

        ## Check if this session is a duplicate
        if { $sidOfThisTCP != $internalFirstSID } {
            log local0. "deleting this SID $sidOfThisTCP because $internalFirstSID is first"
            #ACCESS::session data set session.max_session_timeout 1
            #ACCESS::session remove
        }
    }
    
    ## Cleanup table that triggers request to Que. 
    table delete $user_key 

}