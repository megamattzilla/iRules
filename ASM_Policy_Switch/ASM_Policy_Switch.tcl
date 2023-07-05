#Created by Matt Stovall @ F5 7/2023
#Assumes the virtual server has the default (fallback) ASM profile attached. 
#This iRule will deterministically send traffic to an alternate ASM profile by use of a HTTP header or sampling

when HTTP_REQUEST { 
#Wrap all code in a catch to avoid any blocking TCL errors. Remove to log TCL execution errors. 
catch { 
### Edit these variables start ###
set asm_header_name "X-Enable-ASM-Test" ; #Name of HTTP header to signal the request should be sent to alternate ASM policy
set asm_test_policy_name "/Common/v15" ; #name of alternate ASM policy including partition 
set sampling_enable "false" ; #enable sampling: true or false
set sampling_rate "1000" ; #Set rate in which any % of HTTP requests (without test HTTP header) are sent to alternate ASM policy. Value of 10 = 1/10 should be sent to alternate ASM policy. 100 = 1/100 and so on. 
### Edit these variables stop ###

if { [HTTP::header exists "$asm_header_name"] } { 
    ASM::enable $asm_test_policy_name
}

if { $sampling_enable == "true" } {
    #Check if count table exists. If not, initialize with 1 to avoid null errors. Auto-reset count after 180 seconds to keep the table data small.  
    if { [table lookup -notouch "countHTTP"] < 1 } { table set "countHTTP" 1 180 180 } 
    #Start counting HTTP request. 
    set count [table incr -notouch "countHTTP"]
    #Apply modulus math to the count. For example, a value of 1000 will only send 1 of every 1000 HTTP requests to alternate ASM profile. 
    set mod [ expr { $count % $sampling_rate } ]
    #If $mod equals one send this request to the alternate ASM policy 
    if { $mod == 1 } { ASM::enable $asm_test_policy_name }
    }

}
}