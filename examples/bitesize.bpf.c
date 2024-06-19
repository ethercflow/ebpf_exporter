// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

// Max number of disks we expect to see on the host
#define MAX_DISKS 255
#define DISK_NAME_LEN 32

// Max number of different request ops we expect to see in use.
// As of 6.9-rc2, Linux defines 14 REQ_OP_* in include/linux/blk_types.h
#define MAX_REQ_OPS 14

// 27 buckets for issue size
#define MAX_ISSUE_SIZE_SLOT 27

#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

struct disk_issue_size_key_t {
    u32 dev;
    u8 op;
    u64 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, (MAX_ISSUE_SIZE_SLOT + 1) * MAX_DISKS * MAX_REQ_OPS);
    __type(key, struct disk_issue_size_key_t);
    __type(value, u64);
} bio_issue_sizes SEC(".maps");

/**
 * commit d152c682f03c ("block: add an explicit ->disk backpointer to the
 * request_queue") and commit f3fa33acca9f ("block: remove the ->rq_disk
 * field in struct request") make some changes to `struct request` and
 * `struct request_queue`. Now, to get the `struct gendisk *` field in a CO-RE
 * way, we need both `struct request` and `struct request_queue`.
 * see:
 *     https://github.com/torvalds/linux/commit/d152c682f03c
 *     https://github.com/torvalds/linux/commit/f3fa33acca9f
 */
struct request_queue___x {
    struct gendisk *disk;
} __attribute__((preserve_access_index));

struct request___x {
    struct request_queue___x *q;
    struct gendisk *rq_disk;
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_disk(void *request)
{
    struct request___x *r = request;

    if (bpf_core_field_exists(r->rq_disk))
        return BPF_CORE_READ(r, rq_disk);
    return BPF_CORE_READ(r, q, disk);
}

static int trace_rq_issue(struct request *rq)
{
    struct disk_issue_size_key_t key = {};
    struct gendisk *disk;
    u64 flags;

    disk = get_disk(rq);
    flags = BPF_CORE_READ(rq, cmd_flags);

    key.dev = disk ? MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor)) : 0;
    key.op = flags & REQ_OP_MASK;

    increment_exp2_histogram(&bio_issue_sizes, key, rq->__data_len / 1024, MAX_ISSUE_SIZE_SLOT);

    return 0;
}

SEC("tp_btf/block_rq_issue")
int block_rq_issue(struct bpf_raw_tracepoint_args *ctx)
{
    /**
     * commit a54895fa (v5.11-rc1) changed tracepoint argument list
     * from TP_PROTO(struct request_queue *q, struct request *rq)
     * to TP_PROTO(struct request *rq)
     */
    return trace_rq_issue((void *) ctx->args[0]);
}

char LICENSE[] SEC("license") = "GPL";
