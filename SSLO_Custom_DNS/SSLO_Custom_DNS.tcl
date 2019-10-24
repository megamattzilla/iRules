when HTTP_PROXY_REQUEST priority 400 {
set qry [expr {([set af [IP::version]] == 4) ? "-a" : "-aaaa"}]
set dom [string tolower [URI::host [HTTP::uri]]]

if {[catch "RESOLV::lookup ${qry} ${dom}" addrs] || ([set addr [lindex $addrs 0]] eq "")} {
HTTP::respond 200 content "<html><head><title>Host Not Resolvable</title></head><body>LOGO HERE<p>NICE BANNER HERE<p>The site you are trying to connect to is not resolvable. This is generally due to a mustyped URL.<br>Please verify spelling and try again.<p>URL: $dom<p>ANOTHER NICE BANNER</body></html>"   
}
}