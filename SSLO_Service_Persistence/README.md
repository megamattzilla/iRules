## Add Service Inspection Device Persistence to SSLO 

#### By default SSLO will load balance client requests to all pools members within the service.

- This can make troubleshooting security inspection devices difficult if a certain client request traffic is constantly load balancing between multiple security inspection devices. 

- Adding this iRule to a the SSL Orchestrator Service iRule configuration will provide a mechanism to add Service Inspection device persistence for specific client IPs. 

- The iRule references an IP address data group called **service_persistence** in which a client IP address can be added to enabled persistence for just this client device. 

Datagroup example:
```
ltm data-group internal service_persistence {
    records {
        10.5.20.129/32 { }
    }
    type ip
}
```

### Checking Persistence Records
Once the iRule is added and data group is populated with the desired IP addresses, you can check the persistence records to show which security inspection device has been persisted for this client IP. 
```
(tmos)# show ltm persistence persist-records
Sys::Persistent Connections
source-address  10.5.20.129  any:any  198.19.97.10:9090  (tmm: 3)
Total records returned: 1
```

### Deleting Persistence Records
Once the persistence record is created it can also be deleted before the persistence timeout has been reached. 
```
(tmos)# delete ltm persistence persist-records client-addr 10.5.20.129
```