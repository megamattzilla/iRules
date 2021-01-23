when RULE_INIT {
    ##This iRule should be applied to your SSLO intercaption rule ending with in-t-4. 
    unset -nocomplain static::snat_ips    
    
    #For each SNAT IP needed define the IP versus dynamically looking it up for now. These need to be in the real SNAT pool as well so ARP works. 
    set static::snat_ips(0) 10.5.5.101
    set static::snat_ips(1) 10.5.5.100
    
    #Set to how many SNAT IPs were added
    set static::array_size 2
    unset static::snatpool_name  static::snat_ip

}

when CLIENT_ACCEPTED priority 100 {
     ## Select and uncomment only one of the below SNAT persistence options
    snat $static::snat_ips([expr {[crc32 [IP::client_addr]] % $static::array_size}])


}
