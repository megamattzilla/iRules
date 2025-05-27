### Latest Version: 0.5

### Overview
This iRule provides session replication functionality for APM.
It allows for the replication of user sessions across n-number Active/Active BIG-IP APM devices, ensuring that user sessions remain active and consistent even in the event of an APM or persistence failure.

![alt text](2025-05-23_14-24-34.png)

### Requirements
- Enough architectural session persistence to establish a session with the BIG-IP APM (reach ACCESS_POLICY_COMPLETED event).
- BIG-IP APM version 17.1 or later.
- `send_apm_sideband.tcl` iRule must be applied to the virtual server that is handling APM traffic.
- `receive_apm_sideband.tcl` iRule must be applied to the special sideband virtual server created for this iRule.


#### Version History

#### 0.5
New Features:
- initial release
