when HTTP_REQUEST {
   # loop through and remove all instances of the unwanted
   # headers from the server response
   # (X-Authenticated-User, X-Authenticated-Groups in this example)
   foreach header {X-Authenticated-User X-Authenticated-Groups} {
      log local0. "Removing $header: [HTTP::header value $header]"
      HTTP::header remove $header
   }
}