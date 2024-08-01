# Made with heart by Jason Rahm (github.com/f5-rahm) and Matt Stovall 7/2024
#See https://github.com/megamattzilla/iRules/tree/master/IPv6_Library for more info. 

# Jason rewrote the appropriate procedures from the TCL ip package official source to be iRules compliant from: https://github.com/tcltk/tcllib/blob/master/modules/dns/ip.tcl

# Uses from other irules:
# 1. Expand an IPv6 address: [call irule_library::normalize <short IPv6 addr>]
# 2. Contract an IPv6 address: [call irule_library::contract <long IPv6 addr>]
# 3. Get the network address of an IPv6/mask: [call irule_library::prefix <IPv6 addr (short or long)>/<CIDR mask>] This will return long

proc normalize {ip {Ip4inIp6 0}} {
    foreach {ip mask} [call irule_library::SplitIp $ip] break
    set version [call irule_library::version $ip]
    set s [call irule_library::ToString [call irule_library::Normalize $ip $version] $Ip4inIp6]
    if {($version == 6 && $mask != 128) || ($version == 4 && $mask != 32)} {
        append s /$mask
    }
    return $s
}
proc SplitIp {spec} {
    set slash [string last / $spec]
    if {$slash != -1} {
        incr slash -1
        set ip [string range $spec 0 $slash]
        incr slash 2
        set bits [string range $spec $slash end]
    } else {
        set ip $spec
        if {[string length $ip] > 0 && [call irule_library::version $ip] == 6} {
            set bits 128
        } else {
            set bits 32
        }
    }
    return [list $ip $bits]
}
proc version {ip} {
    set version -1
    if {[string equal $ip {}]} { return $version}
    foreach {addr mask} [split $ip /] break
    if {[call irule_library::IPv4? $addr]} {
        set version 4
    } elseif {[call irule_library::IPv6? $addr]} {
        set version 6
    }
    return $version
}
proc IPv4? {ip} {
    if {[string first : $ip] >= 0} {
        return 0
    }
    if {[catch {call irule_library::Normalize4 $ip}]} {
        return 0
    }
    return 1
}
proc IPv6? {ip} {
    set octets [split $ip :]
    if {[llength $octets] < 3 || [llength $octets] > 8} {
        return 0
    }
    set ndx 0
    foreach octet $octets {
        incr ndx
        if {[string length $octet] < 1} continue
        if {[regexp {^[a-fA-F\d]{1,4}$} $octet]} continue
        if {$ndx >= [llength $octets] && [call irule_library::IPv4? $octet]} continue
        if {$ndx == 2 && [lindex $octets 0] == 2002 && [call irule_library::IPv4? $octet]} continue
        log local0. "proc IPv6: Invalid IPv6 address $ip"
        return 0
    }
    if {[regexp {^:[^:]} $ip]} {
        log local0. "proc IPv6: Invalid ipv6 address $ip (starts with :)"
        return 0
    }
    if {[regexp {[^:]:$} $ip]} {
        log local0. "proc IPv6: Invalid IPv6 address $ip (ends with :)"
        return 0
    }
    if {[regsub -all :: $ip "|" junk] > 1} {
        log local0. "proc IPv6: Invalid IPv6 address $ip (more than one :: pattern)"
        return 0
    }
    return 1
}
proc ToString {bin {Ip4inIp6 0}} {
    set len [string length $bin]
    set r ""
    if {$len == 4} {
        binary scan $bin c4 octets
        foreach octet $octets {
            lappend r [expr {$octet & 0xff}]
        }
        return [join $r .]
    } elseif {$len == 16} {
        if {$Ip4inIp6 == 0} {
            binary scan $bin H32 hex
            for {set n 0} {$n < 32} {incr n} {
                append r [string range $hex $n [incr n 3]]:
            }
            return [string trimright $r :]
        } else {
            binary scan $bin H24c4 hex octets
            for {set n 0} {$n < 24} {incr n} {
                append r [string range $hex $n [incr n 3]]:
            }
            foreach octet $octets {
                append r [expr {$octet & 0xff}].
            }
            return [string trimright $r .]
        }
    } else {
        log local0. "proc ToString: invalid binary address: argument is neither an IPv4 nor an IPv6 address"
        return 0
    }
}
proc Normalize {ip {version 0}} {
    if {$version < 0} {
        set version [call irule_library::version $ip]
        if {$version < 0} {
            log local0. "proc Normalize: invalid address ${ip}: value must be a valid IPv4 or IPv6 address"
            return 0
        }
    }
    return [call irule_library::Normalize$version $ip]
}
proc Normalize4 {ip} {
    set octets [split $ip .]
    if {[llength $octets] > 4} {
        log local0. "proc Normalize4: invalid ip address $ip"
        return 0
    } elseif {[llength $octets] < 4} {
        set octets [lrange [concat $octets 0 0 0] 0 3]
    }
    foreach oct $octets {
        if {$oct < 0 || $oct > 255} {
            log local0. "proc Normalize4: invalid ip address"
            return 0
        }
    }
    return [binary format c4 $octets]
}
proc Normalize6 {ip} {
    set octets [split $ip :]
    set ip4embed [string first . $ip]
    set len [llength $octets]
    if {$len < 0 || $len > 8} {
        log local0. "proc Normalize6: invalid address: this is not an IPv6 address"
        return 0
    }
    set result ""
    for {set n 0} {$n < $len} {incr n} {
        set octet [lindex $octets $n]
        if {$octet == {}} {
            if {$n == 0 || $n == ($len - 1)} {
                set octet \0\0
            } else {
                set missing [expr {9 - $len}]
                if {$ip4embed != -1} {incr missing -1}
                set octet [string repeat \0\0 $missing]
            }
        } elseif {[string first . $octet] != -1} {
            set octet [call irule_library::normalize4 $octet]
        } else {
            set m [expr {4 - [string length $octet]}]
            if {$m != 0} {
                set octet [string repeat 0 $m]$octet
            }
            set octet [binary format H4 $octet]
        }
        append result $octet
    }
    if {[string length $result] != 16} {
        log local0. "proc Normalize6: invalid address: $ip is not an IPv6 address"
        return 0

    }
    return $result
}
proc contract {ip} {
    foreach {ip mask} [call irule_library::SplitIp $ip] break
    set version [call irule_library::version $ip]
    set s [call irule_library::ToString [call irule_library::Normalize $ip $version]]
    if {$version == 6} {
        set r ""
        foreach o [split $s :] { 
            append r [format %x: 0x$o] 
        }
        set r [string trimright $r :]
        regsub {(?:^|:)0(?::0)+(?::|$)} $r {::} r
    } else {
        set r [string trimright $s .0]
    }
    return $r
}
proc prefix {ip} {
    foreach {addr mask} [call irule_library::SplitIp $ip] break
    set version [call irule_library::version $addr]
    set addr [call irule_library::Normalize $addr $version]
    if { $addr == 0 } { return 0 }
    return [call irule_library::ToString [call irule_library::Mask$version $addr $mask]]
}
proc Mask6 {ip {bits {}}} {
    if {[string length $bits] < 1} { set bits 128 }
    if {[string is integer $bits]} {
        set mask [binary format B128 [string repeat 1 $bits]]
    } else {
        binary scan [call irule_library::Normalize6 $bits] I4 mask
    }
    binary scan $ip I4 Addr
    binary scan $mask I4 Mask
    foreach A $Addr M $Mask {
        lappend r [expr {$A & $M}]
    }
    #return [getfield [binary format I4 $r] \0\0 1]
    return [binary format I4 $r]
}