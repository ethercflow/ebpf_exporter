#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

#define MAX_ENTRIES 10240
#define TASK_RUNNING 0

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT 27

struct runq_latency_key_t {
    u32 pid;
    u64 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct runq_latency_key_t);
    __type(value, u64);
} runq_latency_seconds SEC(".maps");

/**
 * commit 2f064a59a1 ("sched: Change task_struct::state") changes
 * the name of task_struct::state to task_struct::__state
 * see:
 *     https://github.com/torvalds/linux/commit/2f064a59a1
 */
struct task_struct___o {
    volatile long int state;
} __attribute__((preserve_access_index));

struct task_struct___x {
    unsigned int __state;
} __attribute__((preserve_access_index));

static __always_inline __s64 get_task_state(void *task)
{
    struct task_struct___x *t = task;

    if (bpf_core_field_exists(t->__state))
        return BPF_CORE_READ(t, __state);
    return BPF_CORE_READ((struct task_struct___o *) task, state);
}

static int trace_enqueue(struct task_struct *p)
{
    u32 pid;
    u64 ts;

    pid = p->pid;

    if (!pid)
        return 0;

    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tp_btf/sched_wakeup")
int sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{

    return trace_enqueue((void *) ctx->args[0]);
}

SEC("tp_btf/sched_wakeup_new")
int sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx)
{
    return trace_enqueue((void *) ctx->args[0]);
}

SEC("tp_btf/sched_switch")
int sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    struct runq_latency_key_t key = {};
    struct task_struct *prev, *next;
    s64 delta;
    u64 *tsp;
    u32 pid;

    prev = (void *) ctx->args[1];
    next = (void *) ctx->args[2];

    if (get_task_state(prev) == TASK_RUNNING)
        trace_enqueue(prev);

    pid = next->pid;

    tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp)
        return 0;
    delta = bpf_ktime_get_ns() - *tsp;
    if (delta < 0)
        goto cleanup;

    key.pid = pid;

    increment_exp2_histogram(&runq_latency_seconds, key, delta / 1000U, MAX_LATENCY_SLOT);

cleanup:
    bpf_map_delete_elem(&start, &pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
