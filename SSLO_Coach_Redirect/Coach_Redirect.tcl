## Made with care by Matt Stovall 1/2025.
## Version 1.1.1
## This iRule: 
##  1. Checks if a HTTP request is made to a GenAI LLM website
##  2. Redirects the HTTP request (per website, per IP, and per User) to an internal URL
##  3. After internal URL redirects page back to origin, Allows the HTTP request to GenAI LLM website
##  4. Uses HTTP headers and iRule table to detect redirect and returning users 

## All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. A prefix of cr_ has been added to each variable to make them globally unique. 
## See https://github.com/megamattzilla/iRules/blob/master/SSLO_Coach_Redirect for more details
## Requirements: Create string-type datagroup with name specified in static::cr_genAIDatagroupNameExact with exact names of GenAI LLM websites to match. 

when HTTP_REQUEST priority 450 {
if {[catch {

    ### User-Edit Variables start ###
    set cr_debugLogging 1                               ; #Integer. 0 = Disabled, 1 = Enabled
    set cr_redirectLocation "internal-fqdn.com"         ; #String. Name of HTTP header to check that coaching redirect has taken place.
    set cr_redirectHeaderName "Referer"                 ; #String. Name of HTTP header to check that coaching redirect has taken place. 
    set cr_redirectHeaderValue "example.com"            ; #String. Lowercase value of $cr_redirectHeaderName to check coaching redirect has taken place.
    set static::cr_genAIDatagroupNameExact "cr_genAI_sites_FQDN"  ; #String. Name of exact match datagroup containing genAI websites.
    set static::cr_genAIDatagroupNameEndsWith "cr_genAI_sites_ends_with"  ; #String. Name of ends_with match datagroup containing genAI websites.
    set cr_idleTime "300"                               ; #Integer. Idle lifetime of users session to genAI website. 
    set cr_lifeTime "3600"                              ; #Integer. Max lifetime of users session to genAI website before they should be redirected to coaching page again. 
    ### User-Edit Variables end ###

    ## Exit gracefully if HTTP request has no host header
    if {!([string length [HTTP::host]] >= 2)} { return 0 } 

    ## Set variable to host header with port removed (if there is one). 
    set cr_httpHost [lindex [split [HTTP::host] ":" ] 0 ]

    ## Exit gracefully if HTTP request is not for GenAI LLM website
    ## Check exact match datagroup first, then ends_with datagroup.  
    if { !([class match [HTTP::host] equals $static::cr_genAIDatagroupNameExact] ) and !([class match [HTTP::host] ends_with $static::cr_genAIDatagroupNameEndsWith] )} {
            if { $cr_debugLogging == 1 } { log local0.debug "Exit graceful for non-GenAI website: $cr_httpHost IP: [IP::client_addr]" } 
            return 0 
    }

    ## Collect username if it exists otherwise set to undefined
    if {[string length [HTTP::header X-Authenticated-User]] >=1 }{ 
        set cr_userName [HTTP::header X-Authenticated-User]
    } else { 
        set cr_userName "undefined"
    }

    ## Parse Apex domain from HTTP host value (remote any sub-domains from cr_httpHost)
        ## First, split splits the string by . and adds all fields to a list. For example value www.chatgpt.com would be now a list of { www chatgpt com } 
        ## Second, lrange selects from the list the values end-1 and end. For example value { www chatgpt com } would now be { chatgpt com } 
        ## Third, join creates a string from the list using "." as a delimiter. For example value { chatgpt com } would now be a string "chatgpt.com" 
    set cr_httpHostApex [join [lrange [split $cr_httpHost "." ] end-1 end ] "."]

    ## Check if iRule table exists for this HTTP host and IP_username
    set cr_tableLookup [table lookup -subtable $cr_httpHostApex [IP::client_addr]_${cr_userName}]
    if { [string length $cr_tableLookup] == 1 } {
       if { $cr_debugLogging == 1 } { log local0.debug "Allow website: $cr_httpHost IP: [IP::client_addr] user: $cr_userName Session table: $cr_httpHostApex " } 
       return 0 
    }
 
    ## Check if this HTTP request was redirected if the $cr_redirectHeaderName header exists and contains $cr_redirectHeaderValue
    if { [HTTP::header exists $cr_redirectHeaderName] and [string tolower [HTTP::header $cr_redirectHeaderName]] contains $cr_redirectHeaderValue } {
        

        ## Create table entry (for apex domain) to allow this IP and username to access the genAI LLM site
        table set -subtable $cr_httpHostApex [IP::client_addr]_${cr_userName} 1 $cr_idleTime $cr_lifeTime 
        log local0.info "Passed Internal Redirect: $cr_httpHost IP: [IP::client_addr] user: $cr_userName created session in table $cr_httpHostApex for idle time: $cr_idleTime max time: $cr_lifeTime" 

        ## Allow HTTP request to proceed to SSLO chain by exiting gracefully 
        return 0 
    }

    ## Redirect to $cr_redirectLocation
    if { $cr_debugLogging == 1 } { log local0.debug "Redirecting website: $cr_httpHost IP: [IP::client_addr] user: $cr_userName" } 
    HTTP::redirect https://${cr_redirectLocation}

## Close catch statement 
} err]} { if {$err != 0 } { log local0.error "Error in HTTP_REQUEST: $err" } }
}