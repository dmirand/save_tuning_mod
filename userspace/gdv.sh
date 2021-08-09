
sysctl net.core.rmem_max > /tmp/default_sysctl_config
sysctl net.core.wmem_max >> /tmp/default_sysctl_config

sysctl net.ipv4.tcp_rmem >> /tmp/default_sysctl_config
sysctl net.ipv4.tcp_wmem >> /tmp/default_sysctl_config
#sysctl net.ipv4.tcp_mem >> /tmp/default_sysctl_config

#sysctl net.ipv4.tcp_available_congestion_control >> /tmp/default_sysctl_config
sysctl net.ipv4.tcp_congestion_control >> /tmp/default_sysctl_config

sysctl net.ipv4.tcp_mtu_probing >> /tmp/default_sysctl_config
sysctl net.core.default_qdisc >> /tmp/default_sysctl_config
