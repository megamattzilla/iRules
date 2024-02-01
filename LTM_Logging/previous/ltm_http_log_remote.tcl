when CLIENT_ACCEPTED {
  set hsl [HSL::open -proto TCP -pool logging-pool]
  set client_address [IP::client_addr]
  set vip [IP::local_addr]
}

when HTTP_REQUEST {
  set http_host [HTTP::host]:[TCP::local_port]
  set http_uri [HTTP::uri]
  set http_url $http_host$http_uri
  set http_method [HTTP::method]
  set http_version [HTTP::version]
  set http_user_agent [HTTP::header "User-Agent"]
  set http_content_type [HTTP::header "Content-Type"]
  set http_referrer [HTTP::header "Referer"]
  set req_start_time [clock clicks -milliseconds]
  set virtual_server [LB::server]

  if { [HTTP::header Content-Length] > 0 } then {
    set req_length [HTTP::header "Content-Length"]
  } else {
    set req_length 0
  }

}

when HTTP_RESPONSE {
    set res_start_time [clock clicks -milliseconds]
    set node [IP::server_addr]
    set node_port [TCP::server_port]
    set http_status [HTTP::status]
    if { [HTTP::header Content-Length] > 0 } then {
        set res_length [HTTP::header "Content-Length"]
    } else {
        set res_length 0
    }

    # Matches OpenTelemetry Conventions: https://github.com/open-telemetry/opentelemetry-specification/blob/main/semantic_conventions/trace/http.yaml
    HSL::send $hsl "service.name=\"bigip\",service.namespace=\"\",service.instance.id=\"\",http.client_ip=\"$client_address\",net.host.ip=\"$vip\",http_method=\"$http_method\",http.host=\"$http_host\",http.target=\"$http_uri\",http_url=\"$http_url\",http.flavor=\"$http_version\",http.user_agent=\"$http_user_agent\",http.content_type=\"$http_content_type\",http.referrer=\"$http_referrer\",req_start_time=\"$req_start_time\",virtual_server=\"$virtual_server\",http.request_content_length=\"$req_length\",res_start_time=\"$res_start_time\",node=\"$node\",node_port=\"$node_port\",http.status_code=\"$http_status\",http.response_content_length=\"$res_length\""
}
when CLIENT_CLOSED {
  unset hsl
}