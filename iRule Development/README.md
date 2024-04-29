# Evaluating iRule Performance 

### 1.) Check CPU cycle statistics for an iRule
By default any configured iRule will provide min/max/avg CPU cycle execution which can be shown via GUI or with `tmsh show ltm rule` command. 

Example Output:
```
----------------------------------------
Ltm::Rule Event: after_test:HTTP_REQUEST
----------------------------------------
Priority                      2
Executions             
  Total                      26
  Failures                    0
  Aborts                      0
CPU Cycles on Executing
  Average                830.0K
  Maximum                  1.0M
  Minimum                     0
```

### 2.) Determine how many CPU cycles you have 
You can use a command such as `cat /proc/cpuinfo | grep "model name" | tee >(wc -l)` to determine the speed of your processor and number of CPU threads. 

Example Output:
``` 
model name      : Intel(R) Xeon(R) CPU E5-2660 0 @ 2.20GHz
model name      : Intel(R) Xeon(R) CPU E5-2660 0 @ 2.20GHz
model name      : Intel(R) Xeon(R) CPU E5-2660 0 @ 2.20GHz
model name      : Intel(R) Xeon(R) CPU E5-2660 0 @ 2.20GHz
model name      : Intel(R) Xeon(R) CPU E5-2660 0 @ 2.20GHz
model name      : Intel(R) Xeon(R) CPU E5-2660 0 @ 2.20GHz
model name      : Intel(R) Xeon(R) CPU E5-2660 0 @ 2.20GHz
model name      : Intel(R) Xeon(R) CPU E5-2660 0 @ 2.20GHz
8
``` 
This system has 8 x 2.20GHz CPU threads. 

### 3.) Putting this all together
The iRule is taking 830,000 CPU cycles on average to execute... that sounds like alot!  

...well, yes and no...

You can compare the number of iRule cycles taken with your number of available cycles to better put this value into perspective. 

Our output tells us that each Xeon(R) CPU E5-2660 has 2,200,000,000 cycles (2.2GHz) per second. 

We can now calculate what percent of overall CPU cycles this iRule is consuming:  

`830,000 / 2,200,000,000 × 100 =` 0.037 % 

This iRule is consuming `0.037%` of 1 CPU thread. 

On a real world device, this load is distributed across all TMM threads so the percent of system-wide utilization for this 8 CPU thread system much lower:  

`830,000 / (2,200,000,000 * 8) × 100 =` 0.004%

We can now state this iRule is consuming a very, very small % of overall system CPU, .004%, and its utility value likely compensates for this CPU expenditure. 

# Additional timing 

Sometimes iRules can do things like wait for sideband connection or call explicit `after` commands which perform a sleep action. The default iRule timing only looks at CPU cycles on iRule start/finish and doesn't account for any time spent in sleep where no action is taking place. 


To acquire a more accurate CPU cycle count for those types of situations, you can add explicit `[clock clicks]` timestamps into your code and then tally them up at the end.   

Example iRule with long after (sleep) command and checking timing manually:

```json
when HTTP_REQUEST priority 2 {
set total_start_time [clock clicks]

set pre_start_time [clock clicks]

set wait 7000 ; #This is adding a 7 second sleep. Default timing assumes this is time spent doing something.

set pre_end_time [clock clicks]

after $wait

set post_start_time [clock clicks]

log local0. "waited $wait"

set post_end_time [clock clicks]
set total_end_time [clock clicks]

log local0. "Time Taken pre-wait: [expr { $pre_end_time - $pre_start_time }]"
log local0. "Time Taken post-wait: [expr { $post_end_time - $post_start_time }]"
log local0. "Time Taken with wait: [expr { $total_end_time - $total_start_time }]"
}
``` 
The default iRule timing shows this iRule took 830k CPU cycles to execute:

```json 
----------------------------------------
Ltm::Rule Event: after_test:HTTP_REQUEST
----------------------------------------
Priority                      2
Executions             
  Total                      26
  Failures                    0
  Aborts                      0
CPU Cycles on Executing
  Average                830.0K
  Maximum                  1.0M
  Minimum                     0
```
However looking at the log output using our own timestamps, the time spent outside the after (sleep) command was very low, around 191 CPU cycles.  

```json 
<HTTP_REQUEST>: waited 7000
<HTTP_REQUEST>: Time Taken pre-wait: 1
<HTTP_REQUEST>: Time Taken post-wait: 190
<HTTP_REQUEST>: Time Taken with wait: 7000087
``` 

The log output tells us there were about 191 CPU cycles worth of "real" work, while the rest was spent in sleep. 

This is a big difference from the 830k CPU cycles the default timing tells us!

