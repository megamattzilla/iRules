## Made with care by Matt Stovall 3/2024.
## Version 0.96
## This iRule: 
##  1.  TBD 

## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of scpb_ has been added to each variable to make them globally unique. 
## See https://github.com/megamattzilla/iRules/blob/master/SSLO_Sideband_SCP/README.md for more details
## Requirements: 
##  1. TBD 

when HTTP_REQUEST priority 400 {
    ###User-Edit Variables start###
    set scpb_debugLogging 1 ; #0 = Disabled, 1 = Enabled
    ###User-Edit Variables end###
    
    ## Check if APM session exists for this TCP flow (populated by scp_auth iRule)
    sharedvar APMSID
    if {  [info exists APMSID] } { 
        ## Increment bytes in
        set scpb_bytes [ACCESS::session data get -sid $APMSID "session.stats.bytes.in"]
        set scpb_newbytes [expr { [string length [HTTP::request]] + $scpb_bytes }]
        if { $scpb_debugLogging == 1 } {log local0. "IN: Old bytes $scpb_bytes new bytes $scpb_newbytes for APM SID $APMSID"}
        ACCESS::session data set -sid $APMSID "session.stats.bytes.in" $scpb_newbytes 
    }
}
when HTTP_RESPONSE priority 400 { 
    
    ## Check if APM session exists for this TCP flow (populated by scp_auth iRule)
    sharedvar APMSID
    if {  [info exists APMSID] } { 
        ## Increment bytes out. Include content length value if present. 
        if { [HTTP::header Content-Length] > 0 } then {
                    set scpb_resLength [HTTP::header "Content-Length"] 
                } else {
                    set scpb_resLength 0
        }
        set scpb_rbytes [ACCESS::session data get -sid $APMSID "session.stats.bytes.out"]
        set scpb_rnewbytes [expr { [string length [HTTP::response]] + $scpb_rbytes + $scpb_resLength }]
        if { $scpb_debugLogging == 1 } {log local0. "OUT: Old bytes $scpb_rbytes new bytes $scpb_rnewbytes Content-Length $scpb_resLength for APM SID $APMSID"}
        ACCESS::session data set -sid $APMSID "session.stats.bytes.out" $scpb_rnewbytes  
    }
}
