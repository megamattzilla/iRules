#To be placed on a SSLO Service iRule. 
#Comment lines 4 and 6 to apply persistence for all IPs.
#Persistence records will be stored for one hour (3600 seconds) 
when CLIENT_ACCEPTED {
    if { [class match [IP::client_addr] equals service_persistence] } {
    persist source_addr 255.255.255.255 3600
    }
}