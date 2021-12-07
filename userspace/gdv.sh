#get default values
sysctl net.core.rmem_max > /tmp/current_config.orig
sysctl net.core.wmem_max >> /tmp/current_config.orig

#net.ipv4.tcp_available_congestion_control *MUST be checked before* net.ipv4.tcp_congestion_control
sysctl net.ipv4.tcp_available_congestion_control >> /tmp/current_config.orig
sysctl net.ipv4.tcp_congestion_control >> /tmp/current_config.orig

sysctl net.ipv4.tcp_mtu_probing >> /tmp/current_config.orig
sysctl net.core.default_qdisc >> /tmp/current_config.orig

sysctl net.ipv4.tcp_rmem >> /tmp/current_config.orig
sysctl net.ipv4.tcp_wmem >> /tmp/current_config.orig

