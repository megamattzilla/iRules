#Check if XFF header exists. If it does, pull the first IP value listed into a new custom HTTP header. 
#Assuming comma seperated IP addresses if multiple IPs are present. If only one IP is listed, it will be pulled into the new header. 
when HTTP_REQUEST {
if { [HTTP::header exists "X-Forwarded-For"] } {
    set XFF [string trim [lindex [HTTP::header X-Forwarded-For] 0] ,]
    HTTP::header insert "X-Trusted-IP" $XFF
    #log local0. "inserted X-Trusted-IP: $XFF" ; #Un-comment this line to enable logging to /var/log/ltm for troubleshooting only. 
    }
}