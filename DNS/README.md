### DNS tunnel mitigation 
https://devcentral.f5.com/s/articles/DNS-Tunnel-Mitigation-v2

### 1. Create data groups
create ltm data-group internal TunnelType records replace-all-with { CNAME { } } type string
modify ltm data-group internal TunnelType records add { TXT { } }
modify ltm data-group internal TunnelType records add { SRV { } }
modify ltm data-group internal TunnelType records add { KEY { } }

create ltm data-group internal DNSAllowList records replace-all-with { facebook.com { data facebook.com } } type string
modify ltm data-group internal DNSAllowList records add { instagram.com { data instagram.com } }
modify ltm data-group internal DNSAllowList records add { fbcdn.net { data fbcdn.net } }
modify ltm data-group internal DNSAllowList records add { google.com { data google.com } }
modify ltm data-group internal DNSAllowList records add { googleapis.com { data googleapis.com } }

create ltm data-group internal DNSDenyList records replace-all-with { dnstunnel.de { data dnstunnel.de } } type string
modify ltm data-group internal DNSDenyList records add { cutheatergroup.cn { data cutheatergroup.cn } }
modify ltm data-group internal DNSDenyList records add { demodomain.cz { data demodomain.cz } }
modify ltm data-group internal DNSDenyList records add { buo.cc { data buo.cc } }
modify ltm data-group internal DNSDenyList records add { pdk.lcn.cc { data pdk.lcn.cc } }