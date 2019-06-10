when HTTP_REQUEST {
 #timeoutvalue is how long in seconds requests stay in the table
 set timeoutvalue 1
 #maxattempts is the number of requests that can happen within the timeoutvalue before redirecting some traffic
 set maxattempts 70000
 #redirect location - where the request will be redirected to
 set lightweightURL "https://example.com/lightweight-site.html"

 if { [table keys -subtable "L7-rate-limit" -count] > $maxattempts } {
  HTTP::redirect $lightweightURL
  table incr -subtable "L7-rate-limit" "total-redirects"
  #Log every time 10,000 redirects have occured for visability. 
  if { { [table keys -subtable "L7-rate-limit" "total-redirects" ] % 10000 } == 1 } {
   log local0. "Redirecting traffic - Message that makes sense."
  }
 } else {
  #get large random number for table placeholder - key collisions are not too detrimental
  set randkey [expr { int(1000000000 * rand()) } ]
  table set -subtable "L7-rate-limit" $randkey 1 $timeoutvalue
 }
}
