## Made with care by Matt Stovall 3/2024.
## Version 0.96
## This iRule: 
##  1.  TBD 

## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of scpa_ has been added to each variable to make them globally unique. 
## See https://github.com/megamattzilla/iRules/blob/master/SSLO_Sideband_SCP/README.md for more details
## Requirements: 
##  1. TBD 

## Disable APM for all HTTP traffic incase there is other iRules applied to this virtual server. 
when HTTP_REQUEST priority 10 {
    ECA::disable
    ACCESS::disable
}
## Start the HTTP_REQUEST event proccessing for this iRule.
when HTTP_REQUEST priority 400 {
    
    ###User-Edit Variables start###
    set scpa_debugLogging 1 ; #0 = Disabled, 1 = Enabled
    set static::scpa_prod_scp_sslo "/Common/sslo_noAuth.app/sslo_noAuth-xp-4"
    ###User-Edit Variables end###

    ###User-Edit Variables end###
    
    ## Enable APM for this HTTP Request
    ACCESS::enable
    
    ## Disable NTLM authentication for this HTTP Request. We are borrowing the per-request authentication the NTLM Access Profile provides but we do not need NTLM auth. 
    ECA::disable
    
    ## Set variable containing decrypted Username:IP combination. 
    set scpa_userKey "[HTTP::header value X-Authenticated-User]:[HTTP::header value X-Client-IP]"

    ## If decrypted Username:IP combination is empty, set value to NOMCPHEADER. 
    if { $scpa_userKey eq ":"} {
        ## Insert HTTP header for service chain indicating the real IPv4 source address. 
        HTTP::header insert X-Client-IP [IP::client_addr]
        ## Insert HTTP header for service chain indicating the user is NOMCPHEADER.  
        HTTP::header insert X-Authenticated-User NoMCPHeader
        ## Update the userKey variable with NOMCPHEADER and real IPv4 source address.
        set scpa_userKey "NOMCPHEADER:[IP::client_addr]"
    }

    ## Set variable containing existing APM session (if established) by using the known userKey value as UUID. 
    set scpa_userUUID [lindex [lsort [ACCESS::user getsid $scpa_userKey] ] 0]
    
    ## Debug log the result of checking for existing APM session.
    if { $scpa_debugLogging == 1 } {log local0. "CONNID: [IP::client_addr]:[TCP::client_port] Checking User $scpa_userKey for UUID $scpa_userUUID table lookup is [table lookup $scpa_userKey]"}

    ## If the returned APM session ID is more than 10 characters its likely we have a valid session ID versus lookup failure. 
    if {  [string length $scpa_userUUID ] >= 10 } { 
        ## Log debug log indicating an existing APM session was found for this userKey. 
        if { $scpa_debugLogging == 1 } {log local0. "CONNID: [IP::client_addr]:[TCP::client_port] Found existing APM session for $scpa_userKey = $scpa_userUUID. Skipping APM."}
        ## Declare a shared variable so other virtual servers can access these variables. 
        sharedvar APMSID
        ## Write the users APM session ID to the shared variable. 
        set APMSID $scpa_userUUID
        ## This userKey is already authenticated, disable APM. 
        ACCESS::disable

    } else { 
        ## Existing APM session was NOT found. Check if there is a APM session in-progress
        if { [table lookup $scpa_userKey] == 1 } {
            ## In-progress APM session found. Issue a debug log. 
            if { $scpa_debugLogging == 1 } {log local0. "CONNID: [IP::client_addr]:[TCP::client_port] Session in-progress for $scpa_userKey. Adding this request to the queue"}
            ## Add this HTTP request to a virtual que. Check for session to in-progress session to finish in a loop. 
            ## Set a loop control variable to 0     
            set scpa_loop 0
            ## While the loop control variable is less than 200, keep looping. 
            while { $scpa_loop < 200 } { 
                ## Increase loop control variable. 
                incr scpa_loop
                ## Sleep 500 milliseconds
                after 500
                ## Check if APM session is finished now
                set scpa_userUUID [lindex [lsort [ACCESS::user getsid $scpa_userKey] ] 0]
                ## If the returned APM session ID is more than 10 characters its likely we have a valid session ID versus lookup failure. 
                if {  [string length $scpa_userUUID ] >= 10 } { 
                    ## Log debug log indicating an existing APM session was found for this userKey. 
                    if { $scpa_debugLogging == 1 } {log local0. "CONNID: [IP::client_addr]:[TCP::client_port] Found existing APM session for $scpa_userKey = $scpa_userUUID. Flushing request from queue and skipping APM."}
                    ## Declare a shared variable so other virtual servers can access these variables. 
                    sharedvar APMSID
                    ## Write the users APM session ID to the shared variable. 
                    set APMSID $scpa_userUUID
                    ## This userKey is already authenticated, disable APM. 
                    ACCESS::disable
                    break
                } else {
                    ## If this is the last loop and in-progress APM session is not finished 
                    if {$scpa_loop equals 200 } { 
                    ## Issue a debug log indicating virtual que expired. 
                    if { $scpa_debugLogging == 1 } {log local0. "CONNID: [IP::client_addr]:[TCP::client_port] Queue expired for user $scpa_userKey in-progress APM session $scpa_userUUID. Failing back to APM."}
                    }
                    ## Keep looping
                    continue 
                } 
            }
        } else {
            ## New APM session. Issue debug log this HTTP request is starting an APM session.  
            if { $scpa_debugLogging == 1 } {log local0. "CONNID: [IP::client_addr]:[TCP::client_port] Starting new session for $scpa_userKey"}
            ## Set a table value to recall later to check if this userKey has started APM auth. 
            table set $scpa_userKey 1
        }
    }
    ## Declare shared variables so other virtual servers can access these variables.
    sharedvar connectHeaderClientIP
    sharedvar connectHeaderGroups
    sharedvar connectHeaderUser 
    sharedvar AMPSID
    
    ## Write the users APM session ID, client IP, groups to the shared variables.
    set connectHeaderClientIP [HTTP::header value X-Client-IP]
    set connectHeaderGroups [HTTP::header value X-Authenticated-Groups]
    set connectHeaderUser [HTTP::header value X-Authenticated-User]
    
    ## Send this authenticated HTTP request to SCP SSLO topology.
    virtual $static::scpa_prod_scp_sslo
}



when ACCESS_SESSION_STARTED {
    ## Issue debug log that APM session is starting. 
    if { $scpa_debugLogging == 1 } {log local0. "CONNID: [IP::client_addr]:[TCP::client_port] Starting session for $scpa_userKey"}
    ## Set various APM session DB values to be used in VPE policy 
    ACCESS::session data set session.user.clientip [HTTP::header value X-Client-IP]
    ACCESS::session data set session.custom.scp.groups [HTTP::header value X-Authenticated-Groups]
    ACCESS::session data set session.custom.scp.username [HTTP::header value X-Authenticated-User]
    ACCESS::session data set session.login.last.originalIP [IP::client_addr]
    ACCESS::session data set session.custom.uuid $scpa_userKey
    ## Overwrite the default UUID with the value of the userKey. 
    ACCESS::session data set session.user.uuid $scpa_userKey
    ## Set NTLM auth to successful. We are borrowing the per-request authentication the NTLM Access Profile provides but we do not need NTLM auth. 
    ACCESS::session data set session.ntlm.last.result 1
}

when ACCESS_POLICY_COMPLETED {     

    ## Detect if there are simultaneous requests that caused duplicate APM sessions. AKA the "Highlander Function" ^_^ 
    if { $scpa_debugLogging == 1 } { log local0. "CONNID: [IP::client_addr]:[TCP::client_port] Highlander Check - Starting for $scpa_userKey found APM session(s) [lsort [ACCESS::user getsid $scpa_userKey] ]"}
    ## Check how many APM sessions have been returned after querying with the userKey
    set scpa_userUUIDLength [llength [lsort [ACCESS::user getsid $scpa_userKey] ]] 
    if { $scpa_userUUIDLength > 1 } {
        ## More than one APM session ID has been returned for the same userKey. Issue debug log. 
        if { $scpa_debugLogging == 1 } { log local0. "CONNID: [IP::client_addr]:[TCP::client_port] Highlander Check - Detected $scpa_userUUIDLength duplicate APM sessions. THERE CAN BE ONLY ONE"}
        ## Iterate through each duplicate APM session starting at 1 (index 0 is first APM Session which will be kept) to end of the list. 
        foreach scpa_duplicate [lrange [lsort [ACCESS::user getsid $scpa_userKey] ] 1 $scpa_userUUIDLength] {
            if { $scpa_debugLogging == 1 } { log local0. "CONNID: [IP::client_addr]:[TCP::client_port] Highlander Check - Removing duplicate APM Session $scpa_duplicate - It's better to burn out than to fade away!"}
            ## Set APM Max Session Timeout to 1 second (smallest possible value). 
            ACCESS::session data set -sid $scpa_duplicate session.max_session_timeout 1
            ## Try to explicitly remove the access session (belt and suspenders approach). 
            ACCESS::session remove -sid $scpa_duplicate 
        }
    }


    ## Cleanup table that triggers request to enter virtual queue. 
    table delete $scpa_userKey 

}