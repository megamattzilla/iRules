## Made with heart by Matt Stovall 4/2025.
when RULE_INIT {
    ## User-edit variables start ##
    # Maximum number of frames allowed per TCP session per second
    set static::wsfl_maxRate 5

    # Enable debug logging (set to 0 to disable)
    set static::wsfl_debugLog 1
    ## User-edit variables end ##

    # Auto Calculate delay in milliseconds to introduce when rate is exceeded
    # (e.g., 1000ms / 5 = 200ms delay between allowed frames)
    set static::wsfl_autoRateLimitValue [expr {1000 / $static::wsfl_maxRate}]
}

when WS_CLIENT_FRAME priority 600 {
    # Use catch to handle any runtime errors gracefully
    if {[catch {
        # Try to increment existing frame counter for this client IP and TCP source port
        if { [set wsfl_frameCount [table incr -mustexist "[IP::client_addr]_[TCP::client_port]"]] ne "" } then {

            # If frame count exceeds allowed maxRate, delay and return
            if { $wsfl_frameCount > $static::wsfl_maxRate } then {
                if { $static::wsfl_debugLog == 1 } {
                    log local0. "[IP::client_addr] exceeded max WS frames per second. Rate-Limiting to ${static::wsfl_maxRate}/second"
                }

                # Delay further processing to enforce rate limit (acts as throttling)
                after $static::wsfl_autoRateLimitValue
                return
            }
        } else {
            # No existing entry: this is the first frame in this window
            # Initialize the frame count with TTL = 1 second
            table set "[IP::client_addr]_[TCP::client_port]" 1 indef 1
        }

        # Optionally log current frame count for debugging
        if { $static::wsfl_debugLog == 1 } {
            log local0. "[IP::client_addr]: frameCount=$wsfl_frameCount"
        }

    } err] == 1 } {
        # Catch and log any unexpected errors in the logic above
        log local0.error "Error in WS_CLIENT_FRAME: $err"
    }
}