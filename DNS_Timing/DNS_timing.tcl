when FLOW_INIT {
#Init Variables 
set dns_request 0
set dns_response 0 
}

when DNS_REQUEST { 
set dns_request [clock clicks -milliseconds] 
set dns_name [DNS::question name]
}
when DNS_RESPONSE { 
set dns_response [clock clicks -milliseconds]
#Modulus math below to exit this iRule unless its 1:100 or 1:1000
#Check if count table exists. If not, initalize with 1 to avoid null errors. Auto-reset count after 180 seconds to keep the table small.  
if { [table lookup -notouch "countStatus"] < 1 } { table set "countStatus" 1 180 180 } 
#Start counting. 
set count [table incr -notouch "countStatus"]
#Apply modulus math to the count. For example, % 100 will only log 1 of every 100 HTTP requests
set mod [ expr { $count % 100 } ]
#If $mod does not equal one (catch the 99% we dont want to log) stop proccessing only this iRule (return). Allow the 1% (1:100) to be logged below. 
if { $mod != 1 } { return }

set dns_time [expr { $dns_response - $dns_request } ]

log local0. "Pool_Member: [LB::server addr] DNS_NAME: $dns_name DNS_time: $dns_time"

}