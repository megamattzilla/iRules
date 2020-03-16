when RULE_INIT {
    ## user-defined: SSLO Bypass Virtual
    set static::SSLO_FUNCTION_BYPASS "sslo_prod_ssl_bypass.app/sslo_prod_ssl_bypass-xp-4"
    ## user-defined:: set of HTTP Host data groups
    set static::DG_FILTER_NAME_EQUALS "ssl_bypass_hostname_equals" ; #exact match data group
    set static::DG_FILTER_NAME_ENDS_WITH "ssl_bypass_hostname" ; #ends_with data group
}
when HTTP_REQUEST priority 250 {

if { [HTTP::method] equals "CONNECT" } {
    log local0. "Found CONNECT ([IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port]) with URI [lindex [split [HTTP::uri] ":" ] 0 ]"
    if { [class match  [lindex [split [HTTP::uri] ":" ] 0 ] equals $static::DG_FILTER_NAME_EQUALS] } {
        log local0. "ConnFlow ([IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port]) matched exact match data group [lindex [split [HTTP::uri] ":" ] 0 ]"
        virtual $static::SSLO_FUNCTION_BYPASS
        event disable
        return
    }
    if { [class match  [lindex [split [HTTP::uri] ":" ] 0 ] ends_with $static::DG_FILTER_NAME_ENDS_WITH] } {
        log local0. "ConnFlow ([IP::client_addr]:[TCP::client_port]-[IP::local_addr]:[TCP::local_port]) matched ends_with data group [lindex [split [HTTP::uri] ":" ] 0 ]"
        virtual $static::SSLO_FUNCTION_BYPASS
        event disable
        return
        }
    }
}