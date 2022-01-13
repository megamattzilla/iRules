#During client accepted, enable port translation on the virtual server otherwise you cannot translate the port later. 
when CLIENT_ACCEPTED {
translate port enable
}
#During the load balancing event, reselect a pool member but on the port of your choosing. 
when LB_SELECTED {
#Example for translating all traffic to port 3128. Change the uncommented line to a port of your choosing. 
#LB::reselect node [LB::server addr] 3128
LB::reselect node [LB::server addr] 3128
}