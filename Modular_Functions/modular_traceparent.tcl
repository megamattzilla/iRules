## Made with heart by Matt Stovall 2/2024. Traceparent code borrowed from Granville Schmidt.
## Version 1.0 

# This iRule generates a unique traceparent ID and inserts that value as a HTTP request header. 
#All code is wrapped in catch statements so that any failure will be non-blocking. If making changes to the code, please ensure its still covered by the catch statements. 
#See https://github.com/megamattzilla/iRules/blob/master/Modular_Functions/README.md for more details

#Modular iRule dependency: none

# W3C Trace Context specification:
#   Ref: https://www.w3.org/TR/trace-context-1/
#   Level: 1
#   W3C Recommendation 06 February 2020
#
# Author: 
#
# Automated test harnes: https://github.com/w3c/trace-context/tree/master/test
#
# Headers:
#   traceparent ( https://www.w3.org/TR/trace-context-1/#traceparent-header ):
#     Fields:
#       version-format   = trace-id "-" parent-id "-" trace-flags
#       trace-id         = 32HEXDIGLC  ; 16 bytes array identifier. All zeroes forbidden
#       parent-id        = 16HEXDIGLC  ; 8 bytes array identifier. All zeroes forbidden
#       trace-flags       = 2HEXDIGLC   ; 8 bit flags. Currently, only one bit is used. See below for details
#
#     EXAMPLE> traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00
#
# Generating a W3C Trace Context 'trace-id'
#   Ref: https://www.w3.org/TR/trace-context-1/#considerations-for-trace-id-field-generation
proc generate_trace_id {} {
  # Trace IDs are 16 random bytes
  return [call gen_rand_hex_str 16]
}
# Generating a W3C Trace Context 'parent-id'
#   Refs:
#     - https://www.w3.org/TR/trace-context-1/#parent-id
#     - https://www.w3.org/TR/trace-context-1/#privacy-of-traceparent-field
proc generate_parent_id {} {
  # Parent IDs are 8 random bytes
  return [call gen_rand_hex_str 8]
}
# Generates a random N-byte string
proc gen_rand_hex_str {num_bytes} {
  # Seeded via srand() in RULE_INIT
  for { set i 0 } {$i < $num_bytes * 2} { incr i } {
    append rand_hex [format {%x} [expr {int(rand()*16)}]]
  }
  return $rand_hex
}
# Protecting against Denial-of-Service attacks
#   Ref: https://www.w3.org/TR/trace-context-1/#denial-of-service
proc is_safe_to_propagate_trace_context {} {
  return true
}
# Generates a new 'traceparent' header
# Ref: https://www.w3.org/TR/trace-context-1/#traceparent-header
proc generate_new_traceparent {} {
  set version [format {%02x} 0x00]
  set trace_id [call generate_trace_id]
  set parent_id [call generate_parent_id]
  set trace_flags [format {%02x} 0x01]
  return [call format_traceparent $version $trace_id $parent_id $trace_flags]
}
proc format_traceparent {version trace_id parent_id trace_flags} {
  return [format "%s-%s-%s-%s" $version $trace_id $parent_id $trace_flags]
}
proc try_propagate_traceparent_header {traceparent_header} {
  #############################################################################
  # Ref: https://www.w3.org/TR/trace-context-1/#a-traceparent-is-received     #
  #############################################################################
  if {[regexp -- {^\s*([0-9a-f]{2})-\s*([a-f0-9]{16,32})\s*-([a-f0-9]{16})-([a-f0-9]{2})(?:-*)\s*?$} $traceparent_header a b c d e]} then {
    set version $b
    set trace_id $c
    set parent_id $d
    set trace_flags $e
    # Version 0xff is invalid.
    # Refs:
    #   - https://www.w3.org/TR/trace-context-1/#versioning-of-traceparent
    #   - https://www.w3.org/TR/trace-context/#a-traceparent-is-received
    if {$b == "ff"} {
      return ""
    }
    # If the existing "trace-id" uses a shorter identifier, left pad the original identifier with zeroes,
    # so that the resulting identifier is a compliant 16-byte identifier.
    #
    # Ref: https://www.w3.org/TR/trace-context-1/#interoperating-with-existing-systems-which-use-shorter-identifiers
    set trace_id [format "%0*s" 32 $trace_id]
    # All bytes as zero (00000000000000000000000000000000) are considered an invalid value. If the trace-id value is
    # invalid (for example if it contains non-allowed characters or all zeros), vendors MUST ignore the traceparent.
    if {$trace_id eq "00000000000000000000000000000000"} {
      return ""
    }
    # All bytes as zero (0000000000000000) is considered an invalid value. Vendors MUST ignore the traceparent when the
    # parent-id is invalid (for example, if it contains non-lowercase hex characters).
    if {$parent_id eq "0000000000000000"} {
      return ""
    }
    # Update the 'parent-id' with a new identifier for this operation.
    # Ref: https://www.w3.org/TR/trace-context-1/#a-traceparent-is-received (7.1)
    set parent_id [call generate_parent_id]
    return [call format_traceparent $version $trace_id $parent_id $trace_flags]
  }
  return ""
}


when HTTP_REQUEST priority 510 {
catch {
  if {[HTTP::header count traceparent] == 1 && [call is_safe_to_propagate_trace_context]} then {
    set traceparent [call try_propagate_traceparent_header [HTTP::header "traceparent"]]
    if {$traceparent eq ""} {
      set traceparent [call generate_new_traceparent]
    }
    #       Until validated and parsed, pass the header through.
    if {[HTTP::header exists tracestate] && [HTTP::header tracestate] eq ""} {
      HTTP::header remove tracestate
    } else {
      HTTP::header replace tracestate [string trim [HTTP::header tracestate]]
    }
  } else {
    #############################################################################
    # Ref: https://www.w3.org/TR/trace-context-1/#no-traceparent-received       #
    #############################################################################
    HTTP::header remove tracestate
    set traceparent [call generate_new_traceparent]
  }
  # Append W3C Trace Context Headers
  # Ref: https://www.w3.org/TR/trace-context-1/#other-risks
  HTTP::header remove traceparent
  HTTP::header insert traceparent $traceparent
}
}