# Made with ❤ by Matt Stovall and Shane Levin @ F5 9/2023.
#This iRule will count the number of SNI domain names over a period of time in a sliding window. If the count is greater than a desired value, the TCP session will be reset. If no SNI is found, the iRule will gracefully exit. 
#All code is wrapped in catch statements so that any TCL execution failure will be non-blocking. When the rate limit is exceeded on a particular SNI FQDN, it will indeed reset the TCP stream. If making changes to the code, please ensure its still covered by the catch statements. 
 
when CLIENTSSL_HANDSHAKE {
catch { 
    ###User-Edit Variables start###
    set sniLimit 500 ; #How many SNI FQDNs to permit over a period of time defined in $sniWindow
    set sniWindow 15 ; #Sets the duration of the sliding window to which $sniLimit is measured.
    set tuningMode 1 ; #1 = enabled, 0 = disabled. Enable detect only tuning mode. When enabled this code will not reject TCP sessions if the limit is exceeded and will log current values for every request. This may log alot of requests. Helpful for tuning purposes. Disable tunining mode to start enforcement of values.  
    ###User-Edit Variables end###

    # Pull SNI information and create local vars. If no SNI is found, exit gracefully. 
    if { [SSL::extensions exists -type 0] } then {
            set SNI_Name [string range [SSL::extensions -type 0] 9 end]
        } else {
            return
        }

    #Query the existing number of keys in the sub table for this SNI FQDN  
    set currentSNI [table keys -count -subtable "$SNI_Name"]

    #Check if the threshold has been exceeded. If not, increment the table and exit gracefully.     
    if { $currentSNI >= $sniLimit } { 
        #If tuning mode is enabled, print the current SNI threshold value for help with tuning then exit. 
        if { $tuningMode equals 1 } { 
            log local0. "Tuning SNI. SNI: $SNI_Name: Current: $currentSNI Exceeds: $sniLimit over $sniWindow seconds"
            set random [TMM::cmp_unit][clock clicks] 
            table set -notouch -subtable "$SNI_Name" $random "" $sniWindow $sniWindow
            return
        } 
        #Threshold has been exceeded. Reset the TCP session.     
        log local0. "Rejecting SNI! SNI: $SNI_Name: Exceeds: $sniLimit over $sniWindow seconds"
        reject
    } else { 
        #Start counting SNI by fqdn. 
        set random [TMM::cmp_unit][clock clicks] 
        table set -notouch -subtable "$SNI_Name" $random "" $sniWindow $sniWindow
        return
        }
    }
}
