#define MAX_ENTRIES 8192

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
