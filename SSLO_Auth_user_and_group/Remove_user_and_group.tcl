when HTTP_REQUEST {
    if { [HTTP::header exists X-Authenticated-User] } {
        HTTP::header remove X-Authenticated-User
    }