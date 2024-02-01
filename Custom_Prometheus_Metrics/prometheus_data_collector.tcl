# Made with ❤ by Matt Stovall @ F5 1/2024.
#Collects data at HTTP_REQUEST event and store in a string formatted for prometheus in an iRule session table. 
#See https://github.com/megamattzilla/iRules/blob/master/Custom_Prometheus_Metrics/README.md for more details
#Version 1.0 

when HTTP_REQUEST {
#Wrap entire iRule in catch to be non-traffic impacting
catch {

###User-Edit Variables start###
set fqdnLimit 1000 ; #Number of unique "FQDN-SSLprofile-virtualserver" combinations to store in the iRule table. This protects against fuzzing. 
###User-Edit Variables end###
 
#Check if more than x number of FQDNs have been collected. If true, exit this iRule gracefully. 
if { [table keys -subtable "fqdns" -count] >= $fqdnLimit } { 

#Exit gracefully
return
} 

#Set the string to use for the entire prometheus metric name including labels with dynamic values. 
set metricString "f5_fqdn\{virtualServer=\"[virtual name]\",sslProfile=\"[PROFILE::clientssl name]\",fqdn=\"[HTTP::host]\"\}"

#Rendered Example:
#f5_fqdn{virtualServer="/Common/asm-demo-https",sslProfile="/Common/clientssl",fqdn="matt.f5.com"}

#If table does not exists, initalize with lifetime of 180 seconds.  
if { [table lookup -notouch -subtable "fqdns" "$metricString"] < 1 } { table set  -subtable "fqdns" "$metricString" 1 180 180 }
#If table exists, increment the value of the metricSrring by 1.
table incr -subtable "fqdns" "$metricString"
}
}