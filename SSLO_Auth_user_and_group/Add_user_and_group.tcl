when HTTP_REQUEST {
    if { [HTTP::header exists X-Authenticated-User] } {
        HTTP::header remove X-Authenticated-User
    }
    if { [HTTP::header exists X-Authenticated-Groups] } {
        HTTP::header remove X-Authenticated-Groups
    }
    if { [string length [ACCESS::session data get "session.logon.last.username"]] > 0  } {
        HTTP::header insert "X-Authenticated-User" [ACCESS::session data get "session.logon.last.username"]
    }
    if { [string length [ACCESS::session data get "session.ad.last.attr.memberOf"]] > 0 } {
        HTTP::header insert "X-Authenticated-Groups" [ACCESS::session data get "session.ad.last.attr.memberOf"]
    }
}