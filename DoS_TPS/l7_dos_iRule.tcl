when HTTP_REQUEST {


#
# Initialized variables
#

set req_path "default"
set host_header "undefined"

# Get request info for client IP and HOST: header with defaults
set XFF [call irule_library::validate_xff]
catch {set host_header [getfield [HTTP::host] ":" 1]}



# Default client TPS
set client_TPS .5
# Default window size in seconds
set WINDOW 30
# Default Static block timer in seconds
set STATIC_BLOCK 300


#
#Switches to turn on/off features
#

# Host/path based rates
set PATH_ENABLE on
# Rolling Window (on) vs static 10 minute block (off)
set ROLLING_WINDOW off
# Log to Splunk
set OFFBOX_LOG on
# Log to Local
set DEBUG_LOG on



#
#	Fetch config information from DDOS_Path data group, and get host, path, TSP, and 
# Window size information.
#
# $req_path = path in data group to be handled differently. Defaults to 'default' if
#	no path info is available from datagroup
#
# Set $client_TPS and $WINDOW if available in datagroup. Otherwise use defaults above
#

if {$PATH_ENABLE} {
    catch {
    if { [HTTP::path] ne "" } {
        catch {set req_path [HTTP::path]}
        set ddos_target "$host_header#$req_path"
        set req_path [class match -name $ddos_target contains DDOS_Path]
        if {$req_path eq ""} { set req_path "default"} 
            set tps_tmp [class match -value $ddos_target contains DDOS_Path]
        if {[getfield $tps_tmp "#" 1]} {set client_TPS [getfield $tps_tmp "#" 1]}
        if {[getfield $tps_tmp "#" 2]} {set WINDOW [getfield $tps_tmp "#" 2]}
                            }
        } 
}



# Set Transactions Per Window (TPW) period
set TPW [expr {int($WINDOW * $client_TPS)}]

#
#log local0. "$client_TPS:$WINDOW:$TPW:$host_header:$req_path:$ddos_target"
#


##
##     iRule logic starts here!
##



# Check if the IP address is whitelisted the defined list of addresses to throttle
if { ! [class match $XFF equals IP_Whitelist] } {

	# Check if there is an entry for the client_addr in the table
    if { [ table lookup -notouch $XFF:$req_path ] != "" } {

	##
  	## Detection loop
  	##
  	
  	# Log debugging
  	    if {$DEBUG_LOG} {log local0. "DDOS_DEBUG: Value present for $XFF:$req_path"}
  	    # Is current number of hits below WINDOW TPS threshold?
        if { [ table lookup -notouch $XFF:$req_path ] < $TPW } {
    
    	    # In detection mode (under window TPS), increase counter and return.
	  	    if {$DEBUG_LOG} { log local0. "DDOS_DEBUG: Number of requests from client = [ table lookup -notouch $XFF:$req_path ] $XFF:$req_path:$TPW:$WINDOW:[ table timeout -remaining $XFF:$req_path ]:[ table lifetime -remaining $XFF:$req_path ]"}
            table incr -notouch $XFF:$req_path 1

    } else {
				
		##
        ## In blocking mode. 
        ##
        # Increment the XFF/path table entry for counting, touch to update timestamp.     
        table incr $XFF:$req_path 1
        	
        if {$ROLLING_WINDOW} {
          ##
          ## Rolling window block mode. Client will only unblock when tps is below
          ## 80% of the violation tps value for 1 $WINDOW
          ##
            
          # create reqno counter to generate unique 'serial number' for entries
          # create new subtable that will hold each request for $WINDOW seconds 
          set reqno [table incr "reqs:$XFF$req_path"]
          table lifetime "reqs:$XFF$req_path" [expr {$WINDOW * 2}]
          table set -subtable "reqrate:$req_path:$XFF" $reqno "0" indefinite $WINDOW
          
          # Since the new table count starts at 0 requests, wait until IP counter
          # is 2x $TPW before checking if the current actual TPS is
          # below threshold. 
        if { [table lookup -notouch $XFF:$req_path] > ($TPW * 2 + 1) } {
          	# Count the entries in the subtable to get Transactions per window
          	# If below TPS threshold * modifier, delete the tables. 
          	if {[table keys -count -subtable "reqrate:$req_path:$XFF"] < ($TPW * .8) } {
                table delete $XFF:$req_path
                table delete -subtable "reqrate:$req_path:$XFF" -all
                        
            }
          }
          if {$DEBUG_LOG} { log local0. "DDOS_DEBUG: ROLLING_BLOCK - $XFF:$req_path made [table keys -count -subtable "reqrate:$req_path:$XFF"] requests in the past $WINDOW seconds. Total requests: [table lookup -notouch "$XFF:$req_path"] $TPW:$WINDOW"}

        } else {
        	##
        	## Static block for $STATIC_BLOCK-ish seconds. Set lifetime and timeout to $STATIC_BLOCK + 1/2 window size seconds
			##

            if {[table lifetime -remaining "$XFF:$req_path"] == -1} { 
        	    table lifetime $XFF:$req_path [expr {$STATIC_BLOCK + ($WINDOW / 2)} ]
        	    table timeout $XFF:$req_path [expr {$STATIC_BLOCK + ($WINDOW / 2)} ]
                }

        	if {$DEBUG_LOG} { log local0. "DDOS_DEBUG: STATIC_BLOCK - $XFF:$req_path Total requests: [table lookup -notouch "$XFF:$req_path"] $TPW:$WINDOW Time in block left: [table timeout -remaining "$XFF:$req_path"]:[table lifetime -remaining "$XFF:$req_path"] of $STATIC_BLOCK"}
        }
                             
        
		#Return error page and exit irule
        catch {call irule_library::return_html_error "999999999997" }
        return
      }
    } else {
			if {$DEBUG_LOG} {log local0. "DDOS_DEBUG: Table created for $XFF:$req_path"}
    	table set $XFF:$req_path 0 $WINDOW 
    }

} 
}