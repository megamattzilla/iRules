when HTTP_REQUEST {
    if { [ACCESS::session exists] } {
        set user [ACCESS::session data get "session.logon.last.username"]
		set groups [ACCESS::session data get "session.ad.last.attr.memberOf"]
		#Optional XFF header. 
        #set cip [IP::client_addr]
        HTTP::header insert "X-Authenticated-User" $user
		HTTP::header insert "X-Authenticated-Groups" $groups
		#HTTP::header insert "X-Forwarded-For" "$cip"
    }
}
