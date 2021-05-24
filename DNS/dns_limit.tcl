when RULE_INIT {
    # Max DNS queries during detection period per source IP / destination domain
    set static::maxq 180
    # Detection & Blocking Period
    set static::btime 60
}
when DNS_REQUEST {
    set srcip [IP::remote_addr]
    set qtype [DNS::question type]
    set DomOrigen [domain [DNS::question name] 4]
    set key "$srcip:$DomOrigen"
if { ([class match $qtype equals TunnelType]) and [DNS::len] > 512 } {
    if {[class match $DomOrigen ends_with DNSAllowList] }{
        return
    } elseif {[class match $DomOrigen ends_with DNSDenyList] }{
        #Un-comment drop to enable blocking mode
        #DNS::drop
        log local2. "Matched DenyList - IP: $srcip - $qtype - $DomOrigen"
        return
    } elseif {[table lookup $key] ne ""} {
        set count [table incr $key]
        if {$count > $static::maxq} {
            #Un-comment drop to enable blocking mode
            #DNS::drop
            if {$count == $static::maxq} {
                #only log when we match the first maxq
                log local2. "DNS Tunnel Suspected - IP: $srcip - $qtype - $DomOrigen"
            }
            return
        }
    } else {
        table add $key 1 indef $static::btime
        }
    }
}