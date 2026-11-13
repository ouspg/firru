: Windows_advfirewall in Policy
: $Id:$
: $Date:$
: $Revision:$
: mixed
netsh advfirewall set allprofiles firewallpolicy blockinbound,notconfigured
netsh advfirewall firewall add rule name=i_allow-icmp enable=yes interfacetype=any dir=in remoteip=any localip=any protocol=icmpv4 action=allow
netsh advfirewall firewall add rule name=i_allow-icmpv6 enable=yes interfacetype=any dir=in remoteip=any localip=any protocol=icmpv6 action=allow
netsh advfirewall firewall add rule name=i_allow-tcp-SSH enable=yes interfacetype=any dir=in remoteip=192.168.150.0/28 localip=any localport=22 protocol=tcp action=allow
netsh advfirewall firewall add rule name=i_allow-tcp-WINDOWS-RPC-ENDPOINT-MAPPER enable=yes interfacetype=any dir=in remoteip=any localip=any localport=135 protocol=tcp action=allow
netsh advfirewall firewall add rule name=i_allow-tcp-NETBIOS-SSN-LEGACY enable=yes interfacetype=any dir=in remoteip=any localip=any localport=139 protocol=tcp action=allow
netsh advfirewall firewall add rule name=i_allow-tcp-WINDOWS-SMB enable=yes interfacetype=any dir=in remoteip=any localip=any localport=445 protocol=tcp action=allow
netsh advfirewall firewall add rule name=i_allow-tcp-WINRM-HTTP enable=yes interfacetype=any dir=in remoteip=any localip=any localport=5985 protocol=tcp action=allow
netsh advfirewall firewall add rule name=i_allow-tcp-WINDOWS-WINRM-UNCONFIGURED enable=yes interfacetype=any dir=in remoteip=any localip=any localport=47001 protocol=tcp action=allow
netsh advfirewall firewall add rule name=i_allow-udp-NTP enable=yes interfacetype=any dir=in remoteip=any localip=any localport=123 protocol=udp action=allow
netsh advfirewall firewall add rule name=i_allow-udp-NETBIOS-NS-LEGACY enable=yes interfacetype=any dir=in remoteip=any localip=any localport=137 protocol=udp action=allow
netsh advfirewall firewall add rule name=i_allow-udp-NETBIOS-DGM-LEGACY enable=yes interfacetype=any dir=in remoteip=any localip=any localport=138 protocol=udp action=allow
netsh advfirewall firewall add rule name=i_allow-udp-MDNS enable=yes interfacetype=any dir=in remoteip=169.254.0.0/16,224.0.0.251/32,fe80::/10,ff02::fb/128 localip=any localport=5353 protocol=udp action=allow
netsh advfirewall firewall add rule name=i_allow-udp-LLMNR enable=yes interfacetype=any dir=in remoteip=169.254.0.0/16,224.0.0.252/32,fe80::/10,ff02::1:3/128 localip=any localport=5355 protocol=udp action=allow
: Windows_advfirewall out Policy
: $Id:$
: $Date:$
: $Revision:$
: mixed
netsh advfirewall firewall add rule name=o_allow-icmp enable=yes interfacetype=any dir=out localip=any remoteip=any protocol=icmpv4 action=allow
netsh advfirewall firewall add rule name=o_allow-icmpv6 enable=yes interfacetype=any dir=out localip=any remoteip=any protocol=icmpv6 action=allow
netsh advfirewall firewall add rule name=o_allow-ANY enable=yes interfacetype=any dir=out localip=any remoteip=any protocol=any action=allow
