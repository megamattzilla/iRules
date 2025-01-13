# Coaching Redirect iRule

This iRule:  
1. Checks if a HTTP request is made to a GenAI LLM website  
2. Redirects the HTTP request (per website, per IP, and per User) to an internal URL  
3. After internal URL redirects page back to origin, Allows the HTTP request to GenAI LLM website  
4. Uses HTTP headers and iRule table to detect redirect and returning users  

#### Version History

#### 1.0.1

Fixed:  
- Idle timeout was being ignored because `-notouch` was being set. Removed `-notouch` from table set command. Confirmed idle and lifetime values work as expected.  

#### 1.0.0

Initial Version. 
