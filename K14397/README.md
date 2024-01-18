### Example for K14397 to send a webhook notification to a teams channel based on a trigger from a matching log message 

1. Create an alert script which defines the action to take for the alert. 
  
    In this example its sending a message to teams channel. This can be any action you create in a bash script email/sms    gateway etc/webhook...   

    a. copy alertd_action.sh to your Big-IP to a location of your choosing such as `/shared/tmp/`  

    b. make the script executable with `chmod +x alertd_action.sh`   

    c. test the alert manually by running `./alertd_action.sh`  

2. Create the trigger in `/config/user_alert.conf`  

    a. Edit `/config/user_alert.conf` with the suggested contents. This example will detect when the string `VF unregistering: f5slave` is logged by any syslog message.  

3. Test alert by creating a dummy log message:  
    `logger "VF unregistering: f5slave"`  
    You should see the webhook/alert configured in step #1.  

Your custom alert is now configured!