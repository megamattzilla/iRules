when HTTP_REQUEST {
    if { [HTTP::header exists X-Authenticated-User] } {
        HTTP::header remove X-Authenticated-User
    }
    if { [ACCESS::session exists] } {
        HTTP::header insert "X-Authenticated-User" [ACCESS::session data get "session.logon.last.username"]
    }
}