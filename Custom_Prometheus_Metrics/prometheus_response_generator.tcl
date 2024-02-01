# Made with ❤ by Matt Stovall @ F5 1/2024.
#Collects data (string formatted for prometheus in an iRule session table) and delivers that data in a HTTP response. The resulting HTTP response looks like output from a prometheus /metric endpoint.
#See https://github.com/megamattzilla/iRules/blob/master/Custom_Prometheus_Metrics/README.md for more details 
#Version 1.0  

when HTTP_REQUEST priority 600 {

###User-Edit Variables start###
set useAuthentiation 0 ; #Require authentication. 0 = No. 1 = True. If 1 is selected please set the basicAuthSHA256 below. 
set basicAuthSHA256 "4f56b2726ea77e6ff582c4706150f5c9f82c5d073d82dde94f921e1345c828ad" ; #SHA256 hash of the value of expected basic auth header value (just the base64 encoded string). 
###User-Edit Variables end###

if { $useAuthentiation equals 1 } {
#If authentication is enabled, parse the basic auth header to isolate the base64 value. Then perform a SHA256 sum of that value. 
#We are expecting the basic auth header follows the conventional format: Authorization: Basic YWRtaW46YWRtaW4=   
#In this example, the value YWRtaW46YWRtaW4= is extracted and then a SHA256 sum of that value is produced: 12d8d9ea56a1acfb1a0acb463af53fdf460e9a0e88f8ea1aab487b6b91e6ff92.  
binary scan [sha256 [getfield [HTTP::header value Authorization] " " 2]] H* key

#If the SHA256 of the basic auth value does not match expected value, log the failed login attempt and send a HTTP 401 Unauthorized response. If the value matches, do nothing and move on. 
if { $key != $basicAuthSHA256 } { 

#Log the failed login and SHA256 values. 
log local0. "Prometheus iRule authentication failed. Expected SHA256 $basicAuthSHA256 but got $key" 

#Send the HTTP 401 Unauthorized response. 
HTTP::respond 401 content {

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html>

<head>
    <title>401 Unauthorized</title>
</head>

<body>
    <h1>Unauthorized</h1>
    <p>This server could not verify that you
        are authorized to access the document
        requested. Either you supplied the wrong
        credentials (e.g., bad password), or your
        browser doesn't understand how to supply
        the credentials required.</p>
</body>

</html>
}
#Exit iRule gracefully 
return

}
}

#Check if FQDN iRule session table exists. If true, extract the data and send the payload as a HTTP response. If not, send an empty prometheus metric to prevent a scrape error.  
if { [table keys -subtable "fqdns" -count] >1 } { 
    #Check the table data for keys. 
    foreach key_value [table keys -notouch -subtable fqdns] {
#Loop through each key. Append the key name and value to a new variable fqdnData. 
append fqdnData "${key_value} [table lookup -notouch -subtable fqdns ${key_value}]
" ; #Dont move this- it needs to make a newline
}
        

    #Set a HTTP response payload into existing variable customData with the data from fqdnData.  
set customData [subst {
# TYPE f5_fqdn_ counter
$fqdnData
}]
    
    
    #Unset the fqdnData variable. 
    unset fqdnData

} else {  

    #Initialize non-empty prometheus response to use if there is no table data. 
set customData [subst {
# HELP f5_fqdn
# TYPE f5_fqdn counter
}]
}

#Send the HTTP response back to the prometheus client 
HTTP::respond 200 content $customData

}