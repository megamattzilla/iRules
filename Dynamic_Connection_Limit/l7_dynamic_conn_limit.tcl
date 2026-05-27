when HTTP_REQUEST {
    if {[catch {
        
        # ===================================================================
        # LOCAL ADMINISTRATOR CONFIGURATION
        # ===================================================================
        # Connections allotted per active pool member
        set conn_per_member 1000
        
        # Minimum absolute connection limit (Safety Floor)
        set min_conn_limit 5000
        
        # Operational Mode (1 = Enforce Block, 0 = Detect Only / Do Not Block)
        set enforce_mode 0

        # HTTP Response Customization (Only applies if enforce_mode is 1)
        set response_code 503
        set response_payload "Service Unavailable - The system is currently at capacity. Please try again later."
        
        # Logging Configuration
        # enable_logging: 1 = Enabled, 0 = Disabled
        set enable_logging 1
        
        # log_interval: Seconds to silence the log after a capacity event triggers
        set log_interval 5
        # ===================================================================

        # 1. Safety check: If another policy/iRule has already responded, exit gracefully
        if {[HTTP::has_responded]} { return }

        # 2. Safety check: Bypass limits for subsequent requests on established Keep-Alive connections
        if { [HTTP::request_num] > 1 } { return }

        # 3. Dynamically retrieve the default pool and the current virtual server name
        set target_pool [LB::server pool]
        set target_vs [virtual name]
        
        # 4. Safety check: Ensure a pool actually exists on the VS
        if { $target_pool eq "" } { return }

        # 5. Check active pool members and calculate the base dynamic limit
        set active_nodes [active_members $target_pool]
        set calculated_limit [expr {$active_nodes * $conn_per_member}]

        # 6. Apply the safety minimum: Use whichever value is higher
        if { $calculated_limit > $min_conn_limit } {
            set dynamic_limit $calculated_limit
        } else {
            set dynamic_limit $min_conn_limit
        }

        # 7. Explicitly check flows ONLY for this specific virtual server
        set current_flows [FLOWTABLE::count virtual $target_vs]

        # 8. Evaluate capacity
        if { $current_flows >= $dynamic_limit } {
            
            # Define the key name for memory state tracking
            set log_key "cap_log_$target_vs"
            
            # --- EVALUATE OPERATIONAL MODE ---
            
            if { $enforce_mode } {
                
                # ENFORCE MODE: Log the event (if not rate-limited) and block the traffic
                if { $enable_logging } {
                    if { [table lookup -notouch $log_key] eq "" } {
                        log local0. "ENFORCE MODE: Capacity reached on $target_vs: $current_flows flows / $dynamic_limit limit. Sending $response_code."
                        # Add the key name with a timeout to silence logs until it expires
                        table add $log_key "1" indefinite $log_interval
                    }
                }
                
                # Graceful but aggressive connection teardown
                HTTP::respond $response_code content $response_payload "Connection" "Close"
                
                # Prevent further event processing
                return
                
            } else {
                
                # DETECT MODE: Log the event (if not rate-limited), do not block, allow traffic to pass
                if { $enable_logging } {
                    if { [table lookup -notouch $log_key] eq "" } {
                        log local0. "DETECT MODE: Capacity reached on $target_vs: $current_flows flows / $dynamic_limit limit. Traffic permitted."
                        # Add the key name with a timeout to silence logs until it expires
                        table add $log_key "1" indefinite $log_interval
                    }
                }
                
                # Exit the iRule to let BIG-IP process the request normally
                return
            }
        }

    } err] == 1 } { log local0.error "Error in HTTP_REQUEST: $err" }
}