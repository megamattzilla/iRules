# Old Version - See README.md in parent directory for latest version

# Dynamic Virtual Server Capacity Limiter

## Overview
This F5 BIG-IP iRule provides dynamic, automated connection limiting for HTTP virtual servers. Rather than relying on a static maximum connection threshold, this script calculates the virtual server's capacity on the fly based on the number of currently active pool members. 

If the connection count exceeds the calculated threshold, the iRule can either silently log the event for observation or actively reject new connections with a customizable HTTP response.

## Key Features

### 🚀 Portable & Administrator-Friendly
* **Zero Hardcoding Required:** The iRule automatically derives the current Virtual Server name and the attached default Pool name. It can be applied to any virtual server without modifying the core logic.
* **Centralized Configuration:** All adjustable parameters are clearly defined in a single, easily accessible local variable block at the top of the event.

### ⚙️ Flexible Enforcement
* **Detect-Only Mode:** Deploy without impacting traffic. Tune your `conn_per_member` variable by observing syslog events before enabling active blocking.
* **Customizable HTTP Responses:** Easily define the exact HTTP status code (e.g., `503`, `429`) and the HTML/text payload returned to the client when capacity is reached.

### 🛡️ Safety Controls
* **Global Exception Handling:** The entire execution block is wrapped in a native Tcl `catch` statement. If a runtime error occurs, it is logged locally, and the traffic is allowed to pass normally, preventing an iRule crash from dropping traffic.
* **Pre-Execution Check:** Safely exits if `[HTTP::has_responded]` is true, preventing TCL errors caused by conflicts with Local Traffic Policies or previously executed iRules in the priority chain.
* **Safety Floor (Minimum Limit):** Includes a hardcoded minimum capacity limit to ensure the virtual server continues to accept a baseline of traffic even if monitor failures temporarily report 0 active pool members.
* **iRule Log Rate Limiting:** Utilizes configurable logging rate limit for high traffic capacity (e.g., maximum one log per minute). This prevents CPU spikes and protects the `syslog-ng` daemon during high request rates.

---

## Installation & Usage

1. Navigate to **Local Traffic** > **iRules** > **iRule List** and click **Create**.
2. Name the iRule (e.g., `rule_dynamic_capacity_limiter`) and paste the code.
3. Modify the variables in the `LOCAL ADMINISTRATOR CONFIGURATION` section to match your environment's baseline requirements.
4. Navigate to your target Virtual Server and attach the iRule under the **Resources** tab. 

### Configuration Variables

| Variable | Type | Description |
| :--- | :--- | :--- |
| `conn_per_member` | Integer | The number of concurrent connections permitted per active pool member. |
| `min_conn_limit` | Integer | The absolute minimum connection limit (Safety Floor). Protects against math errors or 0 active members. |
| `enforce_mode` | Boolean | `1` = Block traffic and send HTTP response. `0` = Detect only, log event, and allow traffic. |
| `response_code` | Integer | The HTTP status code returned to the client (e.g., `503`). Active only when `enforce_mode` is `1`. |
| `response_payload`| String | Avoid TCL control characters. The text or HTML body returned to the client alongside the HTTP response code. If complex text is needed, this can be specified differently as a multi-line input. |
| `enable_logging` | Boolean | `1` = Write capacity events to `/var/log/ltm`. `0` = Disable logging entirely. |
| `log_interval` | Integer | The rate limit timeout in seconds. Suppresses duplicate capacity log messages for this duration. |