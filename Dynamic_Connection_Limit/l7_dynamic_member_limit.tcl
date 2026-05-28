when HTTP_REQUEST_RELEASE priority 350 {
    if {[catch {
        if {[HTTP::has_responded]} { return }
        # ===================================================================
        # LOCAL ADMINISTRATOR CONFIGURATION
        # ===================================================================
        
        # static_rps_limit
        # Description: The baseline maximum Requests Per Second (RPS) allowed 
        #              per backend node under normal conditions (no errors).
        # Valid Options: Any positive integer (e.g., 50, 100, 500).
        set static_rps_limit 100
        
        # min_rps_limit
        # Description: The absolute lowest RPS limit a node can be throttled down 
        #              to. This "Safety Floor" ensures a node is never completely 
        #              locked out of receiving traffic, even under a heavy error storm.
        # Valid Options: Any positive integer. MUST BE LOWER than static_rps_limit.
        set min_rps_limit 15      
        
        # error_penalty
        # Description: The number of RPS capacity subtracted from the static limit 
        #              for every 4xx/5xx error observed in the previous second.
        # Valid Options: Any positive integer.
        set error_penalty 15       
        
        # enforce_mode
        # Description: Determines whether the iRule actively mitigates traffic 
        #              or just observes and logs capacity breaches.
        # Valid Options: 1 (Enforce/Block traffic), 0 (Detect/Log Only).
        set enforce_mode 0

        # enforce_action
        # Description: The specific action taken against the client request when 
        #              enforce_mode is 1 and the dynamic limit is breached.
        # Valid Options: 
        #   - "http429" (Returns an HTTP 429 Too Many Requests response)
        #   - "reject"  (Sends a TCP RST to actively close the connection)
        #   - "drop"    (Silently discards the packet, forcing client timeout)
        set enforce_action "http429"

        # response_payload
        # Description: The HTML/Text message body returned to the client. 
        #              This only applies when enforce_action is set to "http429".
        # Valid Options: Any string.
        set response_payload "Too Many Requests - The assigned backend node is currently at capacity."
        
        # enable_logging
        # Description: Toggles whether capacity breach events are written to /var/log/ltm.
        # Valid Options: 1 (Enable Logging), 0 (Disable Logging).
        set enable_logging 1

        # log_interval
        # Description: The rate limit for the logging itself (in seconds). This 
        #              prevents log spam and disk fill-up if a node stays over capacity.
        # Valid Options: Any positive integer representing seconds.
        set log_interval 5
        # ===================================================================
        
        # 1. Identify the specific backend node selected by the F5
        set node_ip [LB::server addr]
        
        # Safety catch: If WAF/APM intercepted the flow, or no pool member 
        # exists, bypass the rate limit logic.
        if { $node_ip eq "" } { return }
        
        # 2. Get current time for the rolling time windows
        set current_time [clock seconds]
        
        # -------------------------------------------------------------------
        # DYNAMIC LIMIT CALCULATION
        # -------------------------------------------------------------------
        # Look back at the previous second's error count for this specific node
        set prev_time [expr {$current_time - 1}]
        set prev_err_key "err_${node_ip}_${prev_time}"
        set recent_errors [table lookup -notouch $prev_err_key]
        
        # Default to 0 if no errors are found in the previous second
        if { $recent_errors eq "" } { set recent_errors 0 }
        
        # Calculate the dynamic limit: (Static Limit - (Errors * Penalty))
        set dynamic_rps_limit [expr {$static_rps_limit - ($recent_errors * $error_penalty)}]
        
        # Apply the safety floor so we never lock out a node entirely
        if { $dynamic_rps_limit < $min_rps_limit } {
            set dynamic_rps_limit $min_rps_limit
        }

        # -------------------------------------------------------------------
        # TRACK & EVALUATE CAPACITY
        # -------------------------------------------------------------------
        # Track Requests Per Second (RPS) for this specific node
        set rps_key "rps_${node_ip}_${current_time}"
        set current_rps [table incr -notouch $rps_key]

        # Short lifetime to prevent F5 memory bloat (keeps RAM footprint tiny)
        if { $current_rps == 1 } { table lifetime $rps_key 2 }

        # Evaluate node capacity against our dynamically calculated limit
        if { $current_rps > $dynamic_rps_limit } {

        # -------------------------------------------------------------------
        # HIGH-WATER MARK (HWM) TRACKING (For Tuning)
        # -------------------------------------------------------------------
        set hwm_rps_key "hwm_rps_${node_ip}"
        set hwm_err_key "hwm_err_${node_ip}"
        set timer_key "hwm_timer_${node_ip}"
        
        # 1. Get the currently recorded peak values (default to 0)
        set peak_rps [table lookup -notouch $hwm_rps_key]
        if { $peak_rps eq "" } { set peak_rps 0 }

        set peak_err [table lookup -notouch $hwm_err_key]
        if { $peak_err eq "" } { set peak_err 0 }

        # 2. If the current RPS is a new record, update it
        if { $current_rps > $peak_rps } {
            table set $hwm_rps_key $current_rps indefinite 60
            set peak_rps $current_rps
        }

        # 3. If the current Error Rate (Errors-Per-Second) is a new record, update it
        if { $recent_errors > $peak_err } {
            table set $hwm_err_key $recent_errors indefinite 60
            set peak_err $recent_errors
        }

        # 4. Check if the 60-second timer has expired. If so, log and reset.
        if { [table lookup -notouch $timer_key] eq "" } {
            
            # Log both the peak RPS and peak EPS observed over the last minute
            log local0. "TUNING METRIC: Node $node_ip (Last 60s) -> Peak RPS: $peak_rps | Peak Error Rate: $peak_err errors/sec."
            
            # Reset the 60-second timer
            table add $timer_key "1" indefinite 60
            
            # Clear the high-water marks so we measure fresh for the next minute
            table delete $hwm_rps_key
            table delete $hwm_err_key
        }
        # -------------------------------------------------------------------
            
            set log_key "cap_log_${node_ip}"
            
            if { $enforce_mode } {
                
                # ENFORCE MODE: Log and Block
                if { $enable_logging } {
                    if { [table lookup -notouch $log_key] eq "" } {
                        log local0. "ENFORCE: Node $node_ip at capacity. RPS: $current_rps / Limit: $dynamic_rps_limit (Recent Errors: $recent_errors). Action: $enforce_action."
                        table add $log_key "1" indefinite $log_interval
                    }
                }
                
                # Apply enforcement natively (no clientside{} wrapper needed here)
                switch $enforce_action {
                    "http429" {
                        HTTP::respond 429 content $response_payload "Retry-After" "5" "Connection" "Close"
                    }
                    "reject" {
                        reject
                    }
                    "drop" {
                        drop
                    }
                }
                
                return
                
            } else {
                
                # DETECT MODE: Log Only
                if { $enable_logging } {
                    if { [table lookup -notouch $log_key] eq "" } {
                        log local0. "DETECT: Node $node_ip at capacity. RPS: $current_rps / Limit: $dynamic_rps_limit (Recent Errors: $recent_errors). Traffic permitted."
                        table add $log_key "1" indefinite $log_interval
                    }
                }
            }
        }
    } err] == 1} { log local0.error "Error in HTTP_REQUEST_RELEASE: $err" }
}

when HTTP_RESPONSE {
    if {[catch {
        
        # 1. Grab the status code from the server
        set status [HTTP::status]
        
        # 2. Check if the response is a 4xx or 5xx error
        if { $status >= 400 } {
            
            set node_ip [LB::server addr]
            if { $node_ip eq "" } { return }
            
            set current_time [clock seconds]
            set err_key "err_${node_ip}_${current_time}"
            
            # 3. Increment the error counter for this node for the current second
            set err_count [table incr -notouch $err_key]
            
            # Keep table clean
            if { $err_count == 1 } { table lifetime $err_key 2 }
        }
        
    } err] == 1} { log local0.error "Error in HTTP_RESPONSE: $err" }
}