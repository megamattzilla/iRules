when HTTP_REQUEST {
    HTTP::header remove X-Authenticated-User
    HTTP::header remove X-Authenticated-Groups
    sharedvar ctx
    if { ( [info exists ctx(headers)] ) and ( $ctx(headers) ne "" ) and ( [expr { [llength $ctx(headers)] % 2 }] == 0 ) } {

        foreach {h_name h_value} $ctx(headers) {

            HTTP::header remove ${h_name}
        }

    }

}