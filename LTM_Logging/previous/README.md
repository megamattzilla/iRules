### ltm_http_log_remote.tcl
Collects HTTP metrics and transmits per-request loggs to a high speed logging destination. 

Example log:  
u.service.name="bigip",service.namespace="",service.instance.id="",http.client_ip="10.5.5.2",net.host.ip="10.5.20.17",http_method="GET",http.host="10.5.20.17:80",http.target="/",http_url="10.5.20.17:80/",http.flavor="1.1",http.user_agent="curl/7.64.1",http.content_type="",http.referrer="",req_start_time="1626751119312",virtual_server="/Common/maintenance_pool 0",http.request_content_length="0",res_start_time="1626751119313",node="10.5.5.20",node_port="80",http.status_code="200",http.response_content_length="24"  

### Prerequisite
Create an LTM pool with your log server IP and port defined. This example uses a ltm pool named `logging-pool`. 