# SSLO TMOS 15.1 -> 17.1 upgrade steps: 
Last Updated: 6/27/2024 @ 4pm 

Change Notes:
- 6/27/24 - modified grep command to search all restnoded logs, not just the current file. 

I have added my tips and links to the official upgrade steps. 

Because we are jumping major TMOS versions (which greatly improve the SSLO configuration architecture), The upgrade involves two phases: 
1. upgrading the TMOS .ISO from 15.1.x to 17.1.x 
2. upgrade of the SSLO RPM from 7.x to 11.x.  When this happens, a one-time migration occurs of the SSLO configuration in Section 4. 

### Section 1.) Pre-Upgrade prep
1. All non-SSLO references to SSLO objects must be removed. Under local traffic -> Virtual Servers -> Frontdoor -> Resources, notice there is no pool configured. Static variable references in iRules is safe.
2. Complete Pre-Upgrade Checklist here: https://my.f5.com/manage/s/article/K64003555#link_02_01 Stop when you get to **Upgrade procedure**
- Verify SSL Orchestrator configuration readiness
- Perform a UCS backup of all SSL Orchestrator systems
- Verify HA state readiness - `PROTIP!`- use the restcurl commands in this section to do this: https://my.f5.com/manage/s/article/K64003555#link_03_01_02 

### Section 2.) Upgrade TMOS .ISO (Phase 1)
Upgrade steps here: https://my.f5.com/manage/s/article/K64003555#link_03_01 Stop at **Verify the gossip protocol is working between the HA devices**
1. Perform the upgrade on the standby device.
2. Force the standby device offline.
3. Restart the forced-offline device and boot to the newly upgraded software volume.
4. Perform the upgrade on the active device.
5. Restart the active device and boot to the newly upgraded software volume.
6. Release the forced-offline device and reactivate it to standby. 

### Section 3.) Post-TMOS .ISO Upgrade Check
1. Because the system has upgraded past 15.1.7, we need to address a behavior change with the way restjavad is given extra memory. To do that, just run these commands:  
`tmsh modify sys db provision.restjavad.extramb value 600`  
`bigstart restart restjavad`  
`tmsh list sys db provision.restjavad.extramb ` should show updated value of 600  

2. Follow the verification steps here before proceeding with RPM upgrade: https://my.f5.com/manage/s/article/K64003555#link_03_01_02 Stop at **Update the SSL Orchestrator software and configuration**

### Section 4.) Upgrade SSLO .RPM (Phase 2) 
1. Review Upgrade Flowchart here: https://clouddocs.f5.com/sslo-troubleshooting-guide/procs/troubleshooting-upgrade.html 
  
2. Log in to the Configuration utility of the active SSL Orchestrator device.
3. Log in to the Configuration utility of the standby SSL Orchestrator device.
4. Open SSH session to active SSL Orchestrator device. (OPTIONAL) Run command `tail -f /var/log/restnoded/restnoded.log` to watch SSLO log file. 
5. Open SSH session to standby SSL Orchestrator device. (OPTIONAL) Run command `tail -f /var/log/restnoded/restnoded.log` to watch SSLO log file.    
  
6. Perform steps 7 and 8 in close succession (few seconds ideally):
7. On the active SSL Orchestrator device, Go to SSL Orchestrator > Configuration. Doing so starts the SSL Orchestrator rpm upgrade automatically on the current device
8. On the standby SSL Orchestrator device, Go to SSL Orchestrator > Configuration. Doing so starts the SSL Orchestrator rpm upgrade automatically on the current device
9. Go grab a coffee and come back in 10 minutes. The GUI is going to make you think the upgrade failed for the next ~10 minutes, when it's actually still running fine and shouldn't be interrupted.  
10. After 10 minutes, Check which device is the upgrade pilot with this command: `grep "Responsible For Upgrade" /var/log/restnoded/restnoded*` and look for `Responsible For Upgrade: true`  
11. On the device responsible for the upgrade (true) run this command to see if the upgrade finished successfully: `grep "Upgrade Finished" /var/log/restnoded/restnoded*` and look for `[upgradeWorker] --- Upgrade Finished ---`
12. IMPORTANT: perform a config sync FROM upgrade pilot device (device that said `Responsible For Upgrade: true`) TO non-upgrade pilot (device that said `Responsible For Upgrade: false`) 

### Section 5.) Post-upgrade action items (loose ends I'm working on)
1. Redeploy all SSLO topologies with no functional changes (change description of each topology) 
HTTPS traffic works fine after upgrade. HTTP-only works after re-deploying the topology and changing the description. No functional changes needed to topology. Replicated this twice now. Reboot without re-deploy of topology does NOT fix the issue.

2. On each topology in-t-4 VS remove the "copy" clientSSL profile and attach the profile created by SSLO
SSLO upgrade is removing the clientSSL profile and replacing it with a “copy” of the CA certificate. I then have to modify the virtual server to put the SSLO authored CA certificate back on.  Until I do that, SSLO GUI will not let me modify the CA certificate for the topology. 

