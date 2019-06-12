when HTTP_REQUEST {
#
#Users will be authenticated once at session start. If no traffic has been observed in 180 seconds we will re-request their authentication preference with a 407 Proxy Authentication Required. Note- this will simple pass traffic to the SSLO VS for that auth type. An existing access session may not be re-authenticated every time.    
#
##Optional Debug mode to clear table entries##
#switch [HTTP::uri]  {
#  "http://neverssl.com/debug" {
#  table delete -subtable "[IP::client_addr]" authstatus
#  table delete -subtable "[IP::client_addr]" attempt
#	log local0. "Purged table entries for [IP::client_addr]"
#  }
#}

#set variable called authlookup with the current authstatus of this session 
set authlookup [table lookup -subtable [IP::client_addr] authstatus]
#log local0. "client IP [IP::client_addr] auth status is $authlookup for URI [HTTP::uri]"
#Definition of all authstatus
#1 = known ntlm client
#2 = known kerberos client
#3 = known unauthenticated
#4 = pending - HTTP 407 sent to request authenticaiton method 

#known user lookup
switch $authlookup  {
  "1" {
  #set the SSLO NTLM virtual server name
  virtual sslo_ntlm.app/sslo_ntlm-xp-4
  #log local0. "known IP [IP::client_addr] sent to VS $ntlm"
	return
  }
  "2" {
  #set the SSLO Kerberos virtual server name
  virtual sslo_explcitproxy.app/sslo_explcitproxy-xp-4
  #log local0. "known IP [IP::client_addr] sent to VS $kerberos"
	return
  }
  "3" {
  #set the no auth virtual server name
	virtual sslo_noauth.app/sslo_noauth-xp-4
  #log local0. "known IP [IP::client_addr] sent to VS $noauth"
	return
  } 
}

#set variable called attempt with the current auth attempt number for this client  
set attempt [table lookup -subtable [IP::client_addr] attempt]
#log local0. "client IP [IP::client_addr] starting auth attempt $attempt"

#unknown user lookup
switch -glob "$authlookup|[HTTP::header "Proxy-Authorization"]|$attempt"  {
  "4|NTLM*|*" {
  table set -subtable "[IP::client_addr]" authstatus 1
	virtual sslo_ntlm.app/sslo_ntlm-xp-4
  #log local0. "discovered IP [IP::client_addr] with header [HTTP::header "Proxy-Authorization"] sent to VS $ntlm"
  }
  "4|Negotiate*|*" {
	table set -subtable "[IP::client_addr]" authstatus 2
	virtual sslo_explcitproxy.app/sslo_explcitproxy-xp-4
  #log local0. "discovered IP [IP::client_addr] with header [HTTP::header "Proxy-Authorization"] sent to VS $kerberos"
  }
  "4|*|4" {
	table set -subtable "[IP::client_addr]" authstatus 3
	virtual sslo_noauth.app/sslo_noauth-xp-4
  #log local0. "discovered IP [IP::client_addr] with header [HTTP::header "Proxy-Authorization"] sent to VS $noauth"
  }  
  default {
  #log local0. "new IP [IP::client_addr] sending HTTP 407"
	table incr -subtable "[IP::client_addr]" attempt
	table set -subtable "[IP::client_addr]" authstatus 4
  HTTP::respond 407 -version auto content "<html><title>Authentication Required</title><body>Error: Authentication Failure</body></html>" Proxy-Authenticate "Negotiate" Proxy-Authenticate "NTLM" Proxy-Authenticate "Basic"
  }
}
}