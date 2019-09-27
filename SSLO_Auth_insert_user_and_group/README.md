# These iRules will enrich HTTP request with additional information such as username and group.

### These iRules should be places on "dummy" ICAP services which are created within the SSLO wizard and then have strict updates disabled. Remove ICAP profiles of the "dummy" ICAP virtual servers and add these iRules to the corresponding first/last ICAP services. 
### It is important to remove sensitive enriched header information after security inspection devices so that the headers are not leaked to external servers.  

![SSLO ICAP Services](https://raw.githubusercontent.com/megamattzilla/iRules/master/SSLO_Auth_insert_user_and_group/Auth_headers.png)
