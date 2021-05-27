when RULE_INIT {
    # Max DNS queries during detection period per source IP / destination domain
    set static::maxq 180
    # Detection & Blocking Period
    set static::btime 60
}
##when CLIENT_ACCEPTED {
# create logging connection. 
# POOLS MUST EXIST BEFORE ENABLING. Pool points to ltm pool containing log server. 
     #Un-comment below after adding desired LTM pool and remove double ## on lines 7 & 12 & 27 & 39. 
     ##set hsludp [HSL::open -proto UDP -pool /Common/logging-pool]
##}
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
        #Un-comment below for local GTM logging
        log local2. "Matched DenyList - IP: $srcip - $qtype - $DomOrigen"
        #Un-comment below for remote logging
        ##HSL::send $hsludp "<190>,message=Matched_DenyList,src_ip=$srcip,query_type=$qtype,query_name=$DomOrigen\r\n"
        return
    } elseif {[table lookup $key] ne ""} {
        set count [table incr $key]
        if {$count > $static::maxq} {
            #Un-comment drop to enable blocking mode
            #DNS::drop
            if {$count == $static::maxq} {
                #only log when we match the first maxq
                #Un-comment below for local GTM logging
                log local2. "DNS Tunnel Suspected - IP: $srcip - $qtype - $DomOrigen"
                #Un-comment below for remote logging
                ##HSL::send $hsludp "<190>,message=DNS_Tunnel_Suspected,src_ip=$srcip,query_type=$qtype,query_name=$DomOrigen\r\n"
            }
            return
        }
    } else {
        table add $key 1 indef $static::btime
        }
    }
}