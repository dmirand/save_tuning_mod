/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

struct int_telemetry {
  __u32 switch_id;
  __u16 egress_port_id;
  __u16 ingress_port_id;
  __u32 unknown; //possibly Hop Latency
  __u32 queue_id:8;
  __u32 queue_occupancy:24;
  __u32 ingress_time;
  __u32 egress_time;
};

#define ARR_LEN 8
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
