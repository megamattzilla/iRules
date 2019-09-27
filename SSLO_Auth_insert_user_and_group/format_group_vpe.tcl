set g [list]
if {[set s [mcget {session.ad.last.attr.memberOf}]] eq ""} { return ""}
foreach u [lrange [split $s "|"] 1 end] {
set u [string trim $u]
if {[string range $u 0 1] eq "0x"} {
 set u [binary format H* [string range $u 2 end]]
}
if {[regexp -nocase {CN=([^,]+)} $u junk cn]} {
  lappend g $cn
}
}
return [join $g ","]