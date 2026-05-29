when CLIENT_ACCEPTED {
    # Wrap the logic in a catch block to prevent connection drops if the logging pool fails
    if { [catch {
        
        # --- CONFIGURATION SECTION ---
        # The exact name of your F5 pool containing the inspection device(s)
        set hsl_pool "remote_dns_logger_pool"

        # Set to 1 to enable sampling, or 0 to send 100% of packets
        set sampling_enabled 1
        
        # Percent rate (e.g., 10 = 10%, 42 = 42%, 100 = 100%)
        # Must be an integer between 1 and 100
        set percent_rate 42
        # -----------------------------

        set log_packet 0

        if { $sampling_enabled } {
            # rand() * 100 generates a decimal from 0.0 to 99.999
            # int() drops the decimal, leaving an integer from 0 to 99
            set roll [expr { int(rand() * 100) }]
            
            # Check if the roll falls within the target percentage
            if { $roll < $percent_rate } {
                set log_packet 1
            }
        } else {
            # If sampling is disabled, capture everything
            set log_packet 1
        }

        # If selected, send the duplicated payload to the inspection pool
        if { $log_packet } {
            set hsl [HSL::open -proto UDP -pool $hsl_pool]
            HSL::send $hsl [UDP::payload]
        }
        
    } err] == 1} { 
        # Log failure locally but allow the standard client traffic to proceed
        log local0.error "Error in DNS HSL iRule during CLIENT_ACCEPTED: $err" 
    }
}