when RULE_INIT {
    ##This iRule should be applied to your SSLO intercaption rule ending with in-t-4. 
    ## User-defined: enter the name of the SNAT Pool List
    ##replace "sslosnat" with desired snat pool name
    set static::snatpool_name "sslosnat"

 

    set static::members_cmd "members -list $static::snatpool_name"

    unset -nocomplain static::snat_ips

    set static::i 0

    foreach static::snat_ip [eval $static::members_cmd] {

        set static::snat_ips($static::i) [lindex $static::snat_ip 0]

        incr static::i

    }

    set static::array_size [array size static::snat_ips]

    unset static::snatpool_name static::members_cmd static::i static::snat_ip

}

when CLIENT_ACCEPTED priority 100 {

     ## Select and uncomment only one of the below SNAT persistence options

 

    ## Uncomment this line to persist SNAT based on client address only

    snat $static::snat_ips([expr {[crc32 [IP::client_addr]] % $static::array_size}])
    #log local0. "client IP [IP::client_addr] translated to $static::snat_ips([expr {[crc32 [IP::client_addr]] % $static::array_size}])"
 

    ## Uncomment this line to persist SNAT based on client address and remote port

    #snat $static::snat_ips([expr {[crc32 [IP::client_addr][TCP::remote_port]] % $static::array_size}])

   

    ## Uncomment this line to persist SNAT based on client address and remote address

    #snat $static::snat_ips([expr {[crc32 [IP::client_addr][IP::local_addr]] % $static::array_size}])
    #log local0. "client IP [IP::client_addr] translated to $static::snat_ips([expr {[crc32 [IP::client_addr][IP::local_addr]] % $static::array_size}])"

}