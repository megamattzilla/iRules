# Overview 
This iRule logs HTTP request and response header data that is readily available as variables to a remote TCP/UDP log server. 
    
- All code is wrapped in catch statements so that any failure will be non-blocking.  
- If making changes to the code, please ensure its still covered by the catch statements.  
- A prefix of z1_ has been added to each variable to make them globally unique.  

### Requirements:
1. http and client-ssl profile attached to existing virtual server.
2. LTM pool created containing your UDP or TCP remote log servers 
3. Edit the variables inside `###User-Edit Variables` with your LTM logging pool name and protocol

Example log:
```
hostname="15-1-demo.f5kc.com", 
cIP="10.5.5.3", 
cPort="34276", 
uri="/", 
host="matt.f5.com", 
method="HEAD", 
reqLength="0", 
statusCode="200", 
resLength="612", 
vs="/Common/asm-demo-https", 
pool="/Common/nginx-https 10.6.0.100 443", 
referrer="", 
cType="", 
userAgent="curl/8.1.2", 
httpv="1.1", 
vip="10.6.1.10", 
clientsslprofile="/Common/example.f5kc.lab.local"
```