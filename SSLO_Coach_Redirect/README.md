# Coaching Redirect iRule

This iRule:  
1. Checks if a HTTP request is made to a GenAI LLM website  
2. Redirects the HTTP request (per website, per IP, and per User) to an internal URL  
3. After internal URL redirects page back to origin, Allows the HTTP request to GenAI LLM website  
4. Uses HTTP headers and iRule table to detect redirect and returning users  

#### Version History

#### 1.1.1

Changes:
- Replaced the exact match datagroup variable name `cr_genAIDatagroupName` with `cr_genAIDatagroupNameExact`.  

New Feature:  
- Added datagroup that uses an ends_with operator so that wildcard domains can be used. 
- Added suggested datagroups from https://raw.githubusercontent.com/f5devcentral/sslo-script-tools/main/sslo-generative-ai-categories/ai-category-chat  
- Table is now created per apex domain and ignores subdomain. For example, www.chatgpt.com would be added to a subtable named `chatgpt.com`.  
- If there is a port in HTTP host header such as example.com:8080, the variable used for HTTP host will have the port removed.  

#### 1.0.1

Fixed:  
- Idle timeout was being ignored because `-notouch` was being set. Removed `-notouch` from table set command. Confirmed idle and lifetime values work as expected.  

#### 1.0.0

Initial Version. 
