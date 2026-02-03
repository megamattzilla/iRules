# F5 LTM: Dynamic Route Advertisement Controller

## Overview
This **F5 iCall script** provides advanced control over Dynamic Routing (BGP/OSPF) advertisement based on the specific health percentage of an LTM Pool. 

By default, F5 TMOS withdraws a route only when the Virtual Server goes completely DOWN (0 active members). This script allows you to withdraw the route **prematurely** (e.g., when 50% of servers are down), preventing a degraded pool from receiving traffic in a multi-site active/active architecture.

## How It Works
1.  **Monitors Health:** The script checks the *actual* monitor status of the pool members every 15 seconds.
2.  **Counts Active Members:** It calculates the number of healthy nodes (ignoring "Admin Down" states that might mask failures).
3.  **Enforces Threshold:** If the active count drops below your defined `min_active` threshold, it **Disables Route Advertisement** on the Virtual Address.
4.  **Auto-Recovery:** When the members recover, it automatically re-enables Route Advertisement (setting it to `selective`).
5.  **Visibility:** logs actions taken to /var/log/ltm and has an optional debug logging toggled on/off with variable. 

## Installation

### 1. Configure the iCall Script

Obtain the contents of the script from [icall_script.tmsh](icall_script.tmsh) then edit your variables as needed. 

Default variables:
```bash
 # 1. Configuration Variables
 set pool_name "/Common/nginx-http"
 set min_active 3
 set vip_addr "/Common/10.6.1.41"
 
 # DEBUG FLAG: Set to 1 to enable verbose logging, 0 to disable
 set debug 1
```

### 2. Create the iCall Script on Big-IP

Run the following command in `tmsh`.

`load sys config from-terminal merge`

Paste the contents of the script with your variables. 

`CTL + D` to load the script.  

### 3. Create the iCall Handler on Big-IP
Run the following command in `tmsh`.

`load sys config from-terminal merge`

paste contents of the handler from [icall_handler.tmsh](icall_handler.tmsh)

`CTL + D` to load the handler.  The script will start running at the configured interval. 

`save sys config` to save all changes. 