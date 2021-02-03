#Place on internal VS ssloS_<topology name>-req with ICAP profile only (not ADAPT profiles VS)
#Logs the ICAP Server IP when the ICAP response code is not 200 (ok)
when ICAP_RESPONSE {
if { [ICAP::status] != "200"} {
    log local0. "Found ICAP Response Code [ICAP::status] from ICAP Server [IP::server_addr]"
    }
}