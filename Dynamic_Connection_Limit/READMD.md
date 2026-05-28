# Dynamic Adaptive Rate Limiter (F5 iRule)

## Under Construction pending testing and feedback. 

## Overview
This script is an intelligent traffic management tool designed to protect individual backend servers (nodes) from being overwhelmed. Unlike traditional static rate limiters that apply a flat limit across the entire application, this solution monitors the health of each individual server in real-time. If a server begins struggling and throwing HTTP errors, the rate limiter dynamically chokes back the amount of traffic sent to that specific server until it recovers.

## Core Features

* **Per-Node Tracking:** Traffic and capacity are measured for each specific backend server independently. If Server A is struggling but Server B is healthy, only Server A will have its traffic throttled.
* **Dynamic Error-Based Throttling:** The system watches for backend HTTP errors (4xx and 5xx status codes). When errors spike, the allowed Requests Per Second (RPS) limit for that server is automatically reduced.
* **Safety Floor Protection:** To prevent a struggling server from being permanently removed from rotation during an error storm, a hard minimum limit (Safety Floor) ensures the server always receives at least a trickle of traffic to test its recovery.
* **Flexible Enforcement Actions:** When a server reaches its maximum capacity, the system can gracefully handle excess traffic by:
  * Returning an HTTP 429 "Too Many Requests" page to the client.
  * Resetting the connection (TCP RST).
  * Silently dropping the connection.
* **Memory Efficient:** Built specifically for high-performance load balancers, the tracking tables use ultra-short memory lifespans to prevent RAM bloat.

## How it Works (The Logic)

1. **Baseline Traffic:** Under normal conditions, a server is allowed a `Static Base Limit` of Requests Per Second (e.g., 100 RPS).
2. **Error Detection:** If the server returns a 500 Internal Server Error, the script detects this.
3. **Penalty Application:** In the very next second, the server's allowed RPS limit is reduced by an `Error Penalty` amount (e.g., -15 RPS). Its new temporary limit becomes 85 RPS.
4. **Capacity Enforcement:** If the server receives more than 85 requests in that second, the excess requests are blocked or delayed.
5. **Recovery:** As the server catches up and stops throwing errors, the penalty is removed, and the limit naturally floats back up to the baseline 100 RPS.

## Configuration Parameters

Administrators can easily tune the following parameters without changing the core code logic:

* **Static RPS Limit:** The maximum traffic allowed per server when it is perfectly healthy.
* **Minimum RPS Limit (Safety Floor):** The lowest the limit can drop, regardless of how many errors occur.
* **Error Penalty:** How aggressively to reduce the limit for every error observed.
* **Enforce Mode:** Toggles between actively blocking traffic or just logging capacity warnings.
* **Action:** The method used to reject traffic (HTTP 429, Reject, Drop).
* **Payload:** The custom text/HTML shown to the user when blocked.

---

## ⚠️ Recommended Deployment Strategy: Start in Detect Mode (Default)

**Do not deploy this script directly into Enforce Mode.** Guessing the correct Requests Per Second (RPS) limits for an application often leads to accidentally blocking legitimate user traffic. 

To safely deploy this tool:

1. **Set `enforce_mode` to `0` (Detect Only. Default setting.).**
2. Apply the script to your lab/non-prod virtual server during normal business hours or a load test.
3. **Monitor `/var/log/ltm`.** The script features built-in **High-Water Mark (HWM) Tracking**. Every 60 seconds, it will print a tuning metric log showing the absolute highest RPS and highest Error Rate observed for each node over the last minute.
   * *Example Log:* `TUNING METRIC: Node 10.0.0.5 (Last 60s) -> Peak RPS: 84 | Peak Error Rate: 2 errors/sec.`
4. Use these logs to establish your baseline. Set your `Static RPS Limit` slightly above your highest observed peak RPS, and tune your `Error Penalty` based on the peak error rates.
5. Once tuned, flip `enforce_mode` to `1` to begin actively protecting your servers.


## Example Scenario
Let's say your static limit is 100 RPS and the penalty is 5.

At 12:00:01: The backend node throws 4 HTTP 500 errors.

At 12:00:02: A new request comes in. The F5 checks the bucket for 12:00:01 and sees the 4 errors.

The Math: 4 errors * 5 penalty = 20 RPS penalty.

The Result: For the entire duration of 12:00:02, that node's limit drops from 100 to 80 RPS.

At 12:00:03: If no errors occurred during 12:00:02, the limit instantly recovers back to 100 RPS.

Because the F5 session table flushes these keys every 2 seconds (table lifetime $err_key 2), this creates a highly aggressive, self-healing penalty loop. If a node starts throwing errors, its traffic is instantly throttled for the next second, giving it a brief moment to catch its breath and recover before the limit raises again.