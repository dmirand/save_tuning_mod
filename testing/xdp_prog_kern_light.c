/* SPDX-License-Identifier: GPL-2.0 */
#include "/usr/include/linux/bpf.h"
#include <bpf/bpf_helpers.h>


#include "../userspace/common_kern_user_light.h" 

#if 0
struct bpf_map_def SEC("maps") int_ring_buffer = {
        .type        = BPF_MAP_TYPE_RINGBUF,
        .max_entries = 1 << 14,
};
#endif

#if 1
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} int_ring_buffer SEC(".maps");
#endif

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

SEC("xdp_test_ringbuf")
int  xdp_test_ringbuf_func(struct xdp_md *ctx)
{
	static __u64 count = 0;
	__u32 action = XDP_PASS;

	//struct int_telemetry *ev = bpf_ringbuf_reserve(&int_ring_buffer, sizeof(struct int_telemetry), 0);
	struct int_telemetry ev;
#if 0 
	if (!ev) {
		bpf_printk("xdp_test_ringbuf: Could not reserve event, count = %llu\n",count);
   		return action;
  }
  ev->switch_id = count+3;
  ev->egress_port_id = (count + 2)/2;
  ev->ingress_port_id = (count + 5)/2;
  ev->unknown = count + 77;
  ev->queue_id = count;
  ev->queue_occupancy = count + 155;
  ev->ingress_time = count * 77;
  ev->egress_time = count * 88;
#endif
  //bpf_ringbuf_submit(ev, 0);
  
  ev.switch_id = count+3;
  ev.egress_port_id = (count + 2)/2;
  ev.ingress_port_id = (count + 5)/2;
  ev.unknown = count + 77;
  ev.queue_id = count;
  ev.queue_occupancy = count + 155;
  ev.ingress_time = count * 77;
  ev.egress_time = count * 88;
  bpf_perf_event_output(ctx, &int_ring_buffer, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

	count++;
	return action;
}

char _license[] SEC("license") = "GPL";

