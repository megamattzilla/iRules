# ASM Second Geo DB iRule

Overview
--------
This iRule (`ASM_Second_Geo_DB.tcl`) is an ASM post-evaluation override that attempts to reduce false-positive "illegal geolocation" blocks by performing a secondary geo check using an external data-group (named `geo-dg` in the iRule).

Purpose
-------
- Only applies when ASM has already decided to *block* a request because of an illegal-geolocation violation.
- Re-evaluates the source IP against a secondary geo data-group and, for likely false-positives, unblocks the request.
- Preserves blocks when other violations are present or when the second geo DB explicitly maps the IP to disallowed/sanctioned countries.

High-level flow
---------------
1. Only run when `ASM::status` is `blocked` (IF1).
2. Determine the source IP:
   - Prefer the first IP from `X-Forwarded-For` (trimmed and validated).
   - Fall back to `[IP::client_addr]` when XFF is missing/invalid (IF2).
3. Check that the ASM violation list contains `VIOLATION_ILLEGAL_GEOLOCATION` (IF3).
4. Perform a class match lookup against `geo-dg` for the selected source IP. If there is no match, keep the block. (IF4)
5. If `geo-dg` returns a country that is explicitly blocked keep the block.
6. If more than one ASM violation exists, keep the block (IF5).
7. Otherwise, call `ASM::unblock` and log the unblock action.

Data-group requirements (`geo-dg`)
----------------------------------
- The iRule performs `class match -value $src_ip equals geo-dg` and expects the data-group to return a short value (two-letter country code) when an IP or network matches.
- Use an **external** data-group of type `ip` (address records) where each record's `data` is the country code.

Example `geo-dg.txt` content:
```
network 10.0.1.0/24 := "US",
network 10.0.2.0/24 := "US",
network 10.0.3.0/24 := "US",
```

Example TMSH create:

`tmsh create /sys file data-group geo-dg separator ":=" source-path file:/<path_to_geo-dg.txt> type ip`  
Note: TMSH syntax can vary across versions; validate the command on your BIG-IP before applying.

Deployment
----------
1. Create the `geo-dg` data-group as shown above and maintain it as your secondary source of truth for geolocation overrides.
2. Upload `ASM_Second_Geo_DB.tcl` to the BIG-IP and add it as an iRule in the GUI or via `tmsh`.
3. Attach the iRule to the appropriate virtual server (usually the one running ASM policy evaluation or the relevant HTTP/HTTPS listener).

Configuration & tuning
----------------------
- Debugging flag: the iRule defines `set static::geo_dbg 1` in `RULE_INIT`. Set to `0` to disable verbose logging in production.
- The list of countries that always keep the block is in the `switch` statement inside the iRule. Edit that list carefully if you need to treat other countries as always-block.
- Keep your `geo-dg` up to date: if an IP/network isn't present, the iRule will keep the ASM block.

Logging & troubleshooting
-------------------------
- The iRule logs to `/var/log/asm` at `local3.debug` for debug messages and `local3.error` for some conditions.

Safety & caveats
----------------
- This iRule intentionally overrides ASM blocks only in narrow, auditable circumstances. It is conservative by design: missing `geo-dg` matches or multiple violations preserve the block.
- Do **not** set `static::geo_dbg` to `1` in high-volume production unless you need to troubleshoot (verbose logging can impact performance and log storage).
- Test changes on a staging device before applying to production.

Example Debug logs
------------
- When no violation is detected:
```
ASM GEO OVERRIDE: start; support_id=4395987022746051704 ASM::status=alarmed; client_addr=10.6.0.100; XFF=10.0.0.1
ASM GEO OVERRIDE: exit; support_id=4395987022746051704 IF1 - ASM::status is not blocked (alarmed)
```
- When an unblock happens (with debug enabled):
```
ASM GEO OVERRIDE: start; support_id=4395987022746051720 ASM::status=blocked; client_addr=10.6.0.100; XFF=10.0.0.1
ASM GEO OVERRIDE: support_id=4395987022746051720 IF1 - ASM::status is blocked; continuing
ASM GEO OVERRIDE: support_id=4395987022746051720 IF2 - XFF present: '10.0.0.1'; src_ip='10.0.0.1'
ASM GEO OVERRIDE: support_id=4395987022746051720 Violations: names='VIOLATION_ILLEGAL_GEOLOCATION' count=1
ASM GEO OVERRIDE: support_id=4395987022746051720 IF3 - VIOLATION_ILLEGAL_GEOLOCATION present; continuing
ASM GEO OVERRIDE: support_id=4395987022746051720 IF4 - 2nd GEO DB == (CA) POTENTIAL FALSE POSITIVE checking for 
ASM GEO OVERRIDE: support_id=4395987022746051720 IF5 - Only geo violation present; will continue
ASM GEO OVERRIDE: Unblocked GET / src_ip='10.0.0.1' XFF='10.0.0.1'  SecondGeoCheck='CA' support_id=4395987022746051720
```
- When 2nd geo provider could have unblocked, but there are unrelated violations: 
```
ASM GEO OVERRIDE: start; support_id=4395987022746051712 ASM::status=blocked; client_addr=10.6.0.100; XFF=10.0.0.1
ASM GEO OVERRIDE: support_id=4395987022746051712 IF1 - ASM::status is blocked; continuing
ASM GEO OVERRIDE: support_id=4395987022746051712 IF2 - XFF present: '10.0.0.1'; src_ip='10.0.0.1'
ASM GEO OVERRIDE: support_id=4395987022746051712 Violations: names='VIOLATION_EVASION_DETECTED VIOLATION_ILLEGAL_GEOLOCATION' count=2
ASM GEO OVERRIDE: support_id=4395987022746051712 IF3 - VIOLATION_ILLEGAL_GEOLOCATION present; continuing
ASM GEO OVERRIDE: support_id=4395987022746051712 IF4 - 2nd GEO DB == (CA) POTENTIAL FALSE POSITIVE checking for other violations.
ASM GEO OVERRIDE: exit; Blocking due to unrelated ASM violation GET //etc/passwd src_ip='10.0.0.1' XFF='10.0.0.1' SecondGeoCheck='CA' support_id=4395987022746051712 violations='VIOLATION_EVASION_DETECTED VIOLATION_ILLEGAL_GEOLOCATION'
```
- When 2nd geo provider confirms blocked country 
```
ASM GEO OVERRIDE: start; support_id=4395987022746051728 ASM::status=blocked; client_addr=10.6.0.100; XFF=10.0.0.1
ASM GEO OVERRIDE: support_id=4395987022746051728 IF1 - ASM::status is blocked; continuing
ASM GEO OVERRIDE: support_id=4395987022746051728 IF2 - XFF present: '10.0.0.1'; src_ip='10.0.0.1'
ASM GEO OVERRIDE: support_id=4395987022746051728 Violations: names='VIOLATION_ILLEGAL_GEOLOCATION' count=1
ASM GEO OVERRIDE: support_id=4395987022746051728 IF3 - VIOLATION_ILLEGAL_GEOLOCATION present; continuing
ASM GEO OVERRIDE: exit; support_id=4395987022746051728 IF4 - 2nd GEO DB == (RU) KEEP BLOCKED
```
