#include "/usr/include/linux/bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
const volatile int filter_ports_len = 0;
const volatile uid_t filter_uid = -1;
const volatile pid_t filter_pid = 0;
const volatile bool do_count = 0;


struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_ENTRIES);
        __type(key, u32);
        __type(value, struct int_telemetry *);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} sockets SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
} events SEC(".maps");


static __always_inline int
enter_tcp_ack_update_rtt(struct pt_regs *ctx, struct sock *sk)
{
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        __u32 pid = pid_tgid >> 32;
        __u32 tid = pid_tgid;
        __u32 uid;

        if (filter_pid && pid != filter_pid)
                return 0;

        uid = bpf_get_current_uid_gid();
        if (filter_uid != (uid_t) -1 && uid != filter_uid)
                return 0;

        bpf_map_update_elem(&sockets, &tid, &sk, 0);
        return 0;
}

static __always_inline int
exit_tcp_ack_update_rtt(struct pt_regs *ctx, int ret, int ip_ver)
{
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        __u32 pid = pid_tgid >> 32;
        __u32 tid = pid_tgid;
        struct sock **skpp;
        struct sock *sk;
        __u16 dport;

        skpp = bpf_map_lookup_elem(&sockets, &tid);
        if (!skpp)
                return 0;

        if (ret)
                goto end;

        sk = *skpp;

        BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
        if (filter_port(dport))
                goto end;

        if (do_count) {
                if (ip_ver == 4)
                        count_v4(sk, dport);
                else
                        count_v6(sk, dport);
        } else {
                if (ip_ver == 4)
                        trace_v4(ctx, pid, sk, dport);
                else
                        trace_v6(ctx, pid, sk, dport);
        }

end:
        bpf_map_delete_elem(&sockets, &tid);
        return 0;
}


SEC("kprobe/tcp_ack_update_rtt")
int BPF_KPROBE(tcp_ack_update_rtt, struct sock *sk)
{
        return enter_tcp_ack_update_rtt(ctx, sk);
}


EC("kretprobe/tcp_ack_update_rtt")
int BPF_KRETPROBE(tcp_ack_update_rtt_ret, int ret)
{
        return exit_tcp_ack_update_rtt(ctx, ret, 4);
}

