## Made with heart by Matt Stovall 5/2025.
## version 1.0.0

##
## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements.
## See https://github.com/megamattzilla/iRules/blob/master/APM_Session_Replication/README.md for more details


when ACCESS_SESSION_STARTED {
    ###User-Edit Variables start###
    set asr_receiveKey "AES 128 43047ad71173be644498b98de6a11fe3" ; #AES Encryption key used to decrypt session data. Must match the key used in the send_apm_sideband iRule.Document example: https://clouddocs.f5.com/api/irules/AES__key.html
    set asr1_debugLogging 1 ; #Set to 1 to enable debug logging. Set to 0 to disable debug logging.
    ###User-Edit Variables end###

set asr_sessionDataArray [AES::decrypt $asr_receiveKey [b64decode [HTTP::header value X-sessionData]]]

#add decrypt failure check
if { [string length $asr_sessionDataArray] < 1 } {
log local0.error "decryption error from [IP::client_addr] header value: [HTTP::header value X-sessionData]"
return
}

if { $asr1_debugLogging == 1 } {log local0.debug "decrypted session data: $asr_sessionDataArray"}

foreach asr_pair [split $asr_sessionDataArray "|"] {
set asr_parts [split $asr_pair "="]
if { $asr1_debugLogging == 1 } {log local0.debug "[lindex $asr_parts 0] = [lindex $asr_parts 1]"}
ACCESS::session data set [lindex $asr_parts 0] [lindex $asr_parts 1]
}
}

when ACCESS_POLICY_COMPLETED {
## Side band request has created the session data, so we can now drop the request.
if { $asr1_debugLogging == 1 } {log local0.debug "ACCESS_POLICY_COMPLETED: Session data has been set, dropping request."}
drop
}