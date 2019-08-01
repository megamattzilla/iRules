when HTTP_REQUEST {
   # loop through and remove all instances of the unwanted
   # headers from the server response
   # (X-Authenticated-User, X-Authenticated-Group in this example)
   foreach header {X-Authenticated-User X-Authenticated-Group} {
      log local0. "Removing $header: [HTTP::header value $header]"
      HTTP::header remove $header
   }
   # If access session exists for this flow, insert the X-Authenticated-User and X-Authenticated-Groups HTTP headers 
   if { [ACCESS::session exists] } {
        HTTP::header insert "X-Authenticated-User" [ACCESS::session data get "session.logon.last.username"]
        HTTP::header insert "X-Authenticated-Groups" [ACCESS::session data get "session.ad.last.attr.memberOf"]
   }
}