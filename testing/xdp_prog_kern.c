/* SPDX-License-Identifier: GPL-2.0 */
//#include <linux/bpf.h>
#include "/usr/include/linux/bpf.h"
#include <bpf/bpf_helpers.h>

#include "common_kern_user.h" /* defines: struct datarec; */

/* Lesson#1: See how a map is defined.
 * - Here an array with XDP_ACTION_MAX (max_)entries are created.
 * - The idea is to keep stats per (enum) xdp_action
 */
#if 1
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};
#endif

//DM added for testing
#if 0
struct bpf_map_def SEC("maps") xdp_stats_map = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(__u32),
        .value_size  = sizeof(struct datarec),
        .max_entries = XDP_ACTION_MAX,
};
#endif
#if 1
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 14);
} int_ring_buffer SEC(".maps");
#endif
/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp_stats1")
int  xdp_stats1_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	__u32 action = XDP_PASS;

	if (action >= XDP_ACTION_MAX) 
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* Calculate packet length */
	__u64 bytes = data_end - data;
	/* Multiple CPUs can access data record. Thus, the accounting needs to
	 * use an atomic operation.
	 */

	lock_xadd(&rec->rx_packets, 1);
	lock_xadd(&rec->rx_bytes, bytes); //Assign 1
	lock_xadd(&rec->rx_tests, 19); //mytests
	/*
	 * No need for lock since we are using per cpu array map type - Assign 3
	lock_xadd(&rec->rx_packets, 1);
	lock_xadd(&rec->rx_bytes, bytes); //Assign 1
	*/
        /* Assignment#1: Add byte counters
         * - Hint look at struct xdp_md *ctx (copied below)
         *
         * Assignment#3: Avoid the atomic operation
         * - Hint there is a map type named BPF_MAP_TYPE_PERCPU_ARRAY
         */
	return action;
}

static __always_inline
int  xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	if (action >= XDP_ACTION_MAX) 
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* Calculate packet length */
	__u64 bytes = data_end - data;
        /* Assignment#1: Add byte counters
         * - Hint look at struct xdp_md *ctx (copied below)
         *
         * Assignment#3: Avoid the atomic operation
         * - Hint there is a map type named BPF_MAP_TYPE_PERCPU_ARRAY
         */
	//Assign 3
	
	//DM added for testing
	rec->rx_packets++;
	rec->rx_bytes += bytes;
	rec->rx_tests += 19;

	return action;
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	__u32  action = XDP_PASS; /* XDP_PASS  = 2 */

	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_drop")
int xdp_drop_func(struct xdp_md *ctx)
{
	__u32  action = XDP_DROP; 

	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_abort")
int xdp_abort_func(struct xdp_md *ctx)
{
	__u32  action = XDP_ABORTED; 

	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";

/* Copied from: $KERNEL/include/uapi/linux/bpf.h
 *
 * User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 *
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

 * user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 *
struct xdp_md {
	// (Note: type __u32 is NOT the real-type)
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	// Below access go through struct xdp_rxq_info
	__u32 ingress_ifindex; // rxq->dev->ifindex
	__u32 rx_queue_index;  // rxq->queue_index
};
*/
