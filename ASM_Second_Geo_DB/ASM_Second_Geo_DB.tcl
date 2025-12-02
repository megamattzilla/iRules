##  Purpose: attempt a safe "geo override" for false-positive illegal geo-location violations.
##  High-level flow:
##   1) Only act when ASM decided to block (IF1)
##   2) Determine source IP (XFF or client_addr) (IF2)
##   3) Ensure the specific geo violation exists (IF3)
##   4) Re-check geo against a secondary geo class (IF4)
##   5) If only geo violation and secondary DB shows an allowed country and there are no other violations, unblock (IF5)

##  RULE_INIT sets module-level debug flag.
##  - This flag controls verbose logging throughout the iRule.
##  - Keep it off (0) in production or high-volume environments.
when RULE_INIT {
    # 1 = verbose debug; 0 = quiet
    set static::geo_dbg 1
}

when ASM_REQUEST_DONE {
##  ASM_REQUEST_DONE is triggered after ASM finishes evaluating the request.
if {[catch {
    set dg_name "geo-dg"
    set support_id [ASM::support_id]

    if { $static::geo_dbg } {
        log local3.debug "ASM GEO OVERRIDE: start; support_id=$support_id ASM::status=[ASM::status]; client_addr=[IP::client_addr]; XFF=[HTTP::header value X-Forwarded-For]"
    }

    ##  IF1 - Skip unless ASM explicitly marked request as 'blocked'.
    ##  - We don't want to interfere with allowed requests.
    if { [ASM::status] ne "blocked" } {
        if { $static::geo_dbg } {
            log local3.debug "ASM GEO OVERRIDE: exit; support_id=$support_id IF1 - ASM::status is not blocked ([ASM::status])"
        }
        return
    } else {
        if { $static::geo_dbg } {
            log local3.debug "ASM GEO OVERRIDE: support_id=$support_id IF1 - ASM::status is blocked; continuing"
        }
    }

    # XFF / src_ip selection
    set src_ip ""
    set xff_raw [HTTP::header value "X-Forwarded-For"]

    ##  IF2 - Prefer the first IP in X-Forwarded-For when present.
    ##  - We trim and validate that the candidate is a valid IP.
    ##  - If invalid, fall back to the direct client_addr.
    if { $xff_raw ne "" } {
        set candidate_ip [string trim [lindex [split $xff_raw ","] 0]]

        if { [catch { IP::addr $candidate_ip equals $candidate_ip }] } {
            if { $static::geo_dbg } {
                log local3.debug "ASM GEO OVERRIDE: support_id=$support_id IF2 - XFF first entry '$candidate_ip' invalid; falling back to client_addr"
            }
            set src_ip [IP::client_addr]
        } else {
            set src_ip $candidate_ip
            if { $static::geo_dbg } {
                log local3.debug "ASM GEO OVERRIDE: support_id=$support_id IF2 - XFF present: '$xff_raw'; src_ip='$src_ip'"
            }
        }
    } else {
        set src_ip [IP::client_addr]
        if { $static::geo_dbg } {
            log local3.debug "ASM GEO OVERRIDE: support_id=$support_id IF2 - XFF missing; fallback src_ip='$src_ip'"
        }
    }

    # Violations
    set viol_names  [ASM::violation names]
    set viol_count  [ASM::violation count]
    if { $static::geo_dbg } {
        log local3.debug "ASM GEO OVERRIDE: support_id=$support_id Violations: names='$viol_names' count=$viol_count"
    }

    # IF3: Must contain VIOLATION_ILLEGAL_GEOLOCATION
    ##  IF3 - Only attempt override when the illegal-geolocation violation exists.
    ##  - If other violations are present, those could justify blocking; don't override.
    if { [lsearch -exact $viol_names "VIOLATION_ILLEGAL_GEOLOCATION"] < 0 } {
        if { $static::geo_dbg } {
            log local3.debug "ASM GEO OVERRIDE: exit; support_id=$support_id IF3 - VIOLATION_ILLEGAL_GEOLOCATION NOT present"
        }
        return
    } else {
        if { $static::geo_dbg } {
            log local3.debug "ASM GEO OVERRIDE: support_id=$support_id IF3 - VIOLATION_ILLEGAL_GEOLOCATION present; continuing"
        }
    }

    ##  IF4 - Query a secondary 'geo-dg' data-group to re-evaluate country for src_ip.
    ##  - `class match -value` returns a two-letter country code defined in the datagroup.
    ##  - If no match, we conservatively keep the block.
    set value [class match -value $src_ip equals $dg_name]

    if { $value eq "" } {
        if { $static::geo_dbg } {
            log local3.debug "ASM GEO OVERRIDE: exit; support_id=$support_id IF4 - no geo-dg match for $src_ip; keeping blocked"
        }
        return
    }

    ##  Interpret certain country codes as 'definite block'. 
    ##  - These entries short-circuit the override and keep the ASM request blocked. 
    switch -exact $value { 
      "RU" {
           if { $static::geo_dbg } {
               log local3.debug "ASM GEO OVERRIDE: exit; support_id=$support_id IF4 - 2nd GEO DB == ($value) KEEP BLOCKED"
           }
           return
      }
      default {
           if { $static::geo_dbg } {
               log local3.debug "ASM GEO OVERRIDE: support_id=$support_id IF4 - 2nd GEO DB == ($value) POTENTIAL FALSE POSITIVE checking for other violations."
           }
      }
    }

    ##  IF5 - If the request has more than one violation, do not unblock.
    ##  - Multiple violations imply additional problems beyond geo; preserve the block and log.
    if { $viol_count > 1 } {
            log local3.error "ASM GEO OVERRIDE: exit; Blocking due to unrelated ASM violation [HTTP::method] [HTTP::uri] src_ip='$src_ip' XFF='$xff_raw' SecondGeoCheck='$value' support_id=$support_id violations='$viol_names'"
        return
    } else {
        if { $static::geo_dbg } {
            log local3.debug "ASM GEO OVERRIDE: support_id=$support_id IF5 - Only geo violation present; will continue"
        }
    }

    ##  At this point we've determined it's likely a false-positive geo block.
    ##  - Call `ASM::unblock` to allow the request through.
    ##  - Audit via debug log so operators can trace overrides.
    ASM::unblock
    if { $static::geo_dbg } {
        log local3.debug "ASM GEO OVERRIDE: Unblocked [HTTP::method] [HTTP::uri] src_ip='$src_ip' XFF='$xff_raw'  SecondGeoCheck='$value' support_id=$support_id"
    }
} err] == 1 } {
    log local3.err "ASM GEO OVERRIDE DBGERR: Error in ASM_REQUEST_DONE: $err"
}
}