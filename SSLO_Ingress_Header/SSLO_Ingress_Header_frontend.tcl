#Capture the ingress destination TCP port of an incoming connection and store it in a table with the client IP. 
#Another iRule further in the chain can lookup the table. 
when CLIENT_ACCEPTED {
    log local0. "VIP port is: [TCP::local_port clientside]"
    table set -subtable "[IP::client_addr]" ingressport [TCP::local_port clientside]
    set ingresslookup [table lookup -subtable [IP::client_addr] ingressport]
    log local0. "client IP [IP::client_addr] ingress port is $ingresslookup"
}