## Made with heart by Matt Stovall 5/2025.
## version 1.0.0

##
## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements.
## See https://github.com/megamattzilla/iRules/blob/master/APM_Session_Replication/README.md for more details

when RULE_INIT {
array unset asr_apmInventory

###User-Edit Variables start###
set static::asr2_debugLogging 1 ; #Set to 1 to enable debug logging. Set to 0 to disable debug logging.
set static::asr_sidebandport 9001 ; #destination port of peer APM devices
set static::asr_sidebandIdleTimeout 30 ; #the time in seconds to leave the connection open if it is unused.
set static::asr_sidebandSendTimeout 100 ; #the time in milliseconds to transmit the HTTP request to the sideband pool member.
set static::asr_sidebandConnectTimeout 50 ; #the time in milliseconds to wait to establish the connection to the sideband pool member.
set static::asr_sendKey "AES 128 43047ad71173be644498b98de6a11fe3"
set static::asr_apmTrustKey "53047ad71173be644498b98de6a11fe3" ; #Used to verify the sideband to peer APM devices if needed in peer Access Policy VPE.
set static::asr_apmVars "session.server.landinguri session.server.network.name session.user.clientip session.logon.last.username session.user.agent session.policy.result" ; #Type: String #Space separated name(s) of APM vars to send to remote APM. Name and value of variable will be logged.
set static::asr_apmInactivityTimeout 3600; #longer session.inactivity_timeout for peer APM devices
###User-Edit Variables end###

set asr_apmInventory [class get asr_apm_inventory]

set static::asr_apmTargets ""
set asr_localmachinepresent 0
#compute APM group without self
foreach asr_apm $asr_apmInventory {
    if { [lindex $asr_apm 0] != $static::tcl_platform(machine) } {
        if { $static::asr2_debugLogging == 1 } {log local0.debug "Adding peer machine [lindex $asr_apm 0] to APM targets" }
        append static::asr_apmTargets "[lindex $asr_apm 1] "
    } else {
    set asr_localmachinepresent 1
if { $static::asr2_debugLogging == 1 } {log local0.debug "Found local machine $static::tcl_platform(machine) in inventory as expected. Safety check will pass." }
    }
}

if { $asr_localmachinepresent == 0 } {
set static::asr_apmTargets 0
log local0.crit "APM Session replication stopped - Failed safety check. local machine $static::tcl_platform(machine) not found in inventory. Its possible local machine is defined in inventory with different hostname. This safety check prevents this iRule from sending sidebands to itself."
}

if { $static::asr2_debugLogging == 1 } {log local0.debug "apm targets: $static::asr_apmTargets"}

}

when HTTP_REQUEST {
## if HTTP request has no MRHSession Cookie, exit graceful to allow APM module to proceed as usual.
if {!([HTTP::cookie exists "MRHSession"] == 1)} {
    if { $static::asr2_debugLogging == 1 } {log local0.debug "CONNID: [IP::client_addr]:[TCP::client_port] has no MRHSession Cookie"}
    return
}

## Set variable containing MRHSession cookie value
set apm_cookie "[HTTP::cookie value "MRHSession"]"

## if HTTP request has invalid format MRHSession Cookie, exit graceful to allow APM module to proceed as usual.
if { !([string length $apm_cookie ] == "32") } {
    if { $static::asr2_debugLogging == 1 } {log local0.debug "CONNID: [IP::client_addr]:[TCP::client_port] has invalid MRHSession Cookie. Cookie value: $apm_cookie"}
    return
    }

## If this is an MRHSession Cookie for an existing access session, exit graceful to allow APM module to proceed as usual.
if { [ACCESS::session exists $apm_cookie] } {
    if { $static::asr2_debugLogging == 1 } {log local0.debug "CONNID: [IP::client_addr]:[TCP::client_port] has existing session. Cookie value: $apm_cookie found sessionID: [ACCESS::session exists $apm_cookie]"}
    return
    }

## Check if this MRHSession cookie has a valid pointer session learned from another APM device.
set asr_currentSID [ACCESS::user getsid $apm_cookie]

## If no APM pointer session was found, exit graceful to allow APM module to proceed as usual.
if { !([string length $asr_currentSID] == "32") } {
log local0.err "CONNID: [IP::client_addr]:[TCP::client_port] No pointer session found for $apm_cookie"
return
}

## Collect the new MRHSession value from the pointer session
set asr_newMRHcookie [ACCESS::session data get -sid $asr_currentSID "session.keydb.encryption"]

## Debug log old cookie value + pointer session ID + new cookie ID
if { $static::asr2_debugLogging == 1 } {log local0.debug "CONNID: [IP::client_addr]:[TCP::client_port] old cookie: $apm_cookie found SID: $asr_currentSID found new cookie: $asr_newMRHcookie"}

## Remove old MRHSession cookie
HTTP::cookie remove "MRHSession"

## Add MRHSession cookie for current APM session ID
HTTP::cookie insert name "MRHSession" value $asr_newMRHcookie
}

when ACCESS_POLICY_COMPLETED {

## Check if access policy result is "allow". If not, exit graceful to skip sending a sideband request.
if { !([ACCESS::policy result] == "allow") } {
    if { $static::asr2_debugLogging == 1 } {log local0.debug "CONNID: [IP::client_addr]:[TCP::client_port] SID [ACCESS::session sid] access policy result is not allow, exit gracefully and skip sending sideband request."}
    return
}

## Collect User-Defined list of APM Vars and values. Add all that were found to array asr_apmVars.
    foreach asr_apmVar $static::asr_apmVars {
        if { [string length [ACCESS::session data get $asr_apmVar]] >= 1 } {
            ##Syntax is set [array name]([name of array entry]) [value of array entry]
            set asr_userDefinedAPMVars($asr_apmVar) [ACCESS::session data get $asr_apmVar]
    if { $static::asr2_debugLogging == 1 } {log local0.debug "CONNID: [IP::client_addr]:[TCP::client_port] found APM variable $asr_apmVar [ACCESS::session data get $asr_apmVar]"}
        }
    }

#Add custom APM variables to array for remote APM devices to import
set asr_userDefinedAPMVars(session.user.uuid) [ACCESS::session sid] ; ## Add APM SID to array under variable name session.user.uuid
set asr_userDefinedAPMVars(session.original.sessionid) [string range [ACCESS::session sid] end-7 end]
set asr_userDefinedAPMVars(session.user.sessiontype) [string range [ACCESS::session sid] end-7 end]
set asr_userDefinedAPMVars(session.original.apmHost) $static::tcl_platform(machine)
set asr_userDefinedAPMVars(session.inactivity_timeout) $static::asr_apmInactivityTimeout
set asr_userDefinedAPMVars(session.apmTrust.key) $static::asr_apmTrustKey

## Get list of keys from the final array
set asr_arrayKeys [array names asr_userDefinedAPMVars]
set asr_arrayKeysTotal [llength $asr_arrayKeys]
set asr_arrayKeysCount 0
###  Serialize final array for transmission to remote APM devices.
foreach asr_finalArray [array names asr_userDefinedAPMVars] {
    incr asr_arrayKeysCount
append asr_serializedFinalArray "${asr_finalArray}=$asr_userDefinedAPMVars($asr_finalArray)"
    # Only append '&' if not the last element
    if {$asr_arrayKeysCount < $asr_arrayKeysTotal} {
        append asr_serializedFinalArray "|"
    }
}

if { $static::asr2_debugLogging == 1 } { log local0.debug "cleartext array: $asr_serializedFinalArray"}
if { $static::asr2_debugLogging == 1 } { log local0.debug "encrypted array: [b64encode [AES::encrypt $static::asr_sendKey $asr_serializedFinalArray]]"}

## Format Sideband HTTP Request. Be careful modifying this, as it is used to send the session data to the remote APM devices.
set asr_customData [subst {GET / HTTP/1.1
Host: session-receiver.local
Accept: */*
User-Agent: Big-IP iRule
X-sessionData: [b64encode [AES::encrypt $static::asr_sendKey $asr_serializedFinalArray]]
clientless-mode: 1


}]

## For each peer APM device, open a TCP connection and send the sideband HTTP request.
foreach asr_peerAPM $static::asr_apmTargets {
        ## Open the TCP connection to the remote APM device
        set asr_connID [connect -timeout $static::asr_sidebandConnectTimeout -idle $static::asr_sidebandIdleTimeout -status conn_status $asr_peerAPM:$static::asr_sidebandport]

        ## Check if TCP connection was successful. If not, try again with a different pool member.
        if { !($asr_connID contains "connect") } {
        log local0.error  "Cannot connect sideband to peer APM $asr_peerAPM"
        }
        ## Send HTTP Request to sideband pool member
        set asr_sendBytes [send -timeout $static::asr_sidebandSendTimeout -status send_status $asr_connID $asr_customData]

        ## Check HTTP Request was sent successfully
        if { $static::asr2_debugLogging == 1 } {  log local0.debug "Sent $asr_sendBytes bytes out of [string length $asr_customData] bytes to $asr_peerAPM." }
        if { !($asr_sendBytes == [string length $asr_customData]) } {
            log local0.error "Unable to send sideband call to $asr_peerAPM. Sent $asr_sendBytes bytes out of [string length $asr_customData] bytes"
        }
}
}