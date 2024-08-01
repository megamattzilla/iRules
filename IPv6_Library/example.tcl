# Made with heart by Jason Rahm (github.com/f5-rahm) and Matt Stovall 7/2024
#See https://github.com/megamattzilla/iRules/tree/master/IPv6_Library for more info. 

when RULE_INIT {
## Example IPv6 data

set static::ip2_long "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
set static::ip2_short "2001:db8:85a3::8a2e:370:7334"

if { [TMM::cmp_unit] == 0 } {
    ## Expand Demo
    log local0. "Before Expand: $static::ip2_short"             
    log local0. "Expanded IPv6 addr: [call irule_library::normalize $static::ip2_short]"

    ## Contract Demo
    log local0. "Before Contract: $static::ip2_long"      
    log local0. "Contracted IPv6 addr: [call irule_library::contract $static::ip2_long]"

    ## Mask Demo
    set mask "/64" 
    log local0. "Before /64 Mask $static::ip2_long"  
    log local0. "Mask IPv6 addr at $mask :  [call irule_library::prefix ${static::ip2_short}/${mask}]" 
    
    ## Error Handling Demo
    set badData "sdfsdgfrgfbgfgfade4r454t45 2001:0db8:85a3:0000:0000:8a2e:0370:7334:2001 2001:0db8:85a3:0000:0000:8a2e:0370 1:1:1/64 ...... $$$$$ //64" 
    foreach junk $badData {
    log local0. "Testing irule_library::normalize with bad data $junk [call irule_library::normalize $junk]"
    log local0. "Testing irule_library::contract with bad data $junk [call irule_library::contract $junk]"
    log local0. "Testing irule_library::prefix with bad data $junk [call irule_library::prefix $junk]"
    }
}
}