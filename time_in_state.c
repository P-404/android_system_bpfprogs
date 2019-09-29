/*
 * time_in_state eBPF program
 *
 * Copyright (C) 2018 Google
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <bpf_helpers.h>

// Number of frequencies for which a UID's times can be tracked in a single map entry. If some CPUs
// have more than 32 freqs available, a single UID is tracked using 2 or more entries.
#define FREQS_PER_ENTRY 32
// Number of distinct CPU counts for which a UID's concurrent time stats can be tracked in a single
// map entry. On systems with more than 8 CPUs, a single UID is tracked using 2 or more entries.
#define CPUS_PER_ENTRY 8

typedef struct {
    uint32_t uid;
    uint32_t bucket;
} time_key;

typedef struct {
    uint64_t ar[FREQS_PER_ENTRY];
} time_in_state_val;

DEFINE_BPF_MAP(uid_time_in_state_map, PERCPU_HASH, time_key, time_in_state_val, 1024)

typedef struct {
    uint64_t active[CPUS_PER_ENTRY];
    uint64_t policy[CPUS_PER_ENTRY];
} concurrent_val;

DEFINE_BPF_MAP(uid_concurrent_times_map, PERCPU_HASH, time_key, concurrent_val, 1024)

DEFINE_BPF_MAP(cpu_last_update_map, PERCPU_ARRAY, uint32_t, uint64_t, 1)

DEFINE_BPF_MAP(cpu_policy_map, ARRAY, uint32_t, uint32_t, 1024)
DEFINE_BPF_MAP(policy_freq_idx_map, ARRAY, uint32_t, uint8_t, 1024)

typedef struct {
	uint32_t policy;
	uint32_t freq;
} freq_idx_key;

DEFINE_BPF_MAP(freq_to_idx_map, HASH, freq_idx_key, uint8_t, 2048)

DEFINE_BPF_MAP(nr_active_map, ARRAY, uint32_t, uint32_t, 1)
DEFINE_BPF_MAP(policy_nr_active_map, ARRAY, uint32_t, uint32_t, 1024)

struct switch_args {
    unsigned long long ignore;
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int tp_sched_switch(struct switch_args* args) {
    uint32_t zero = 0;
    uint64_t* last = bpf_cpu_last_update_map_lookup_elem(&zero);
    if (!last) return 0;
    uint64_t old_last = *last;
    uint64_t time = bpf_ktime_get_ns();
    *last = time;

    uint32_t* active = bpf_nr_active_map_lookup_elem(&zero);
    if (!active) return 0;

    uint32_t cpu = bpf_get_smp_processor_id();
    uint32_t* policyp = bpf_cpu_policy_map_lookup_elem(&cpu);
    if (!policyp) return 0;
    uint32_t policy = *policyp;

    uint32_t* policy_active = bpf_policy_nr_active_map_lookup_elem(&policy);
    if (!policy_active) return 0;

    uint32_t nactive = *active - 1;
    uint32_t policy_nactive = *policy_active - 1;

    if (!args->prev_pid || (!old_last && args->next_pid)) {
        __sync_fetch_and_add(active, 1);
        __sync_fetch_and_add(policy_active, 1);
    }

    // Return here in 2 scenarios:
    // 1) prev_pid == 0, so we're exiting idle. No UID stats need updating, and active CPUs can't be
    //    decreasing.
    // 2) old_last == 0, so this is the first time we've seen this CPU. Any delta will be invalid,
    //    and our active CPU counts don't include this CPU yet so we shouldn't decrement them even
    //    if we're going idle.
    if (!args->prev_pid || !old_last) return 0;

    if (!args->next_pid) {
        __sync_fetch_and_add(active, -1);
        __sync_fetch_and_add(policy_active, -1);
    }

    uint8_t* freq_idxp = bpf_policy_freq_idx_map_lookup_elem(&policy);
    if (!freq_idxp || !*freq_idxp) return 0;
    // freq_to_idx_map uses 1 as its minimum index so that *freq_idxp == 0 only when uninitialized
    uint8_t freq_idx = *freq_idxp - 1;

    uint32_t uid = bpf_get_current_uid_gid();
    time_key key = {.uid = uid, .bucket = freq_idx / FREQS_PER_ENTRY};
    time_in_state_val* val = bpf_uid_time_in_state_map_lookup_elem(&key);
    if (!val) {
        time_in_state_val zero_val = {.ar = {0}};
        bpf_uid_time_in_state_map_update_elem(&key, &zero_val, BPF_NOEXIST);
        val = bpf_uid_time_in_state_map_lookup_elem(&key);
    }
    uint64_t delta = time - old_last;
    if (val) val->ar[freq_idx % FREQS_PER_ENTRY] += delta;

    key.bucket = nactive / CPUS_PER_ENTRY;
    concurrent_val* ct = bpf_uid_concurrent_times_map_lookup_elem(&key);
    if (!ct) {
        concurrent_val zero_val = {.active = {0}, .policy = {0}};
        bpf_uid_concurrent_times_map_update_elem(&key, &zero_val, BPF_NOEXIST);
        ct = bpf_uid_concurrent_times_map_lookup_elem(&key);
    }
    if (ct) ct->active[nactive % CPUS_PER_ENTRY] += delta;

    if (policy_nactive / CPUS_PER_ENTRY != key.bucket) {
        key.bucket = policy_nactive / CPUS_PER_ENTRY;
        ct = bpf_uid_concurrent_times_map_lookup_elem(&key);
        if (!ct) {
            concurrent_val zero_val = {.active = {0}, .policy = {0}};
            bpf_uid_concurrent_times_map_update_elem(&key, &zero_val, BPF_NOEXIST);
            ct = bpf_uid_concurrent_times_map_lookup_elem(&key);
        }
    }
    if (ct) ct->policy[policy_nactive % CPUS_PER_ENTRY] += delta;
    return 0;
}

struct cpufreq_args {
    unsigned long long ignore;
    unsigned int state;
    unsigned int cpu_id;
};

SEC("tracepoint/power/cpu_frequency")
int tp_cpufreq(struct cpufreq_args* args) {
    uint32_t cpu = args->cpu_id;
    unsigned int new = args->state;
    uint32_t* policyp = bpf_cpu_policy_map_lookup_elem(&cpu);
    if (!policyp) return 0;
    uint32_t policy = *policyp;
    freq_idx_key key = {.policy = policy, .freq = new};
    uint8_t* idxp = bpf_freq_to_idx_map_lookup_elem(&key);
    if (!idxp) return 0;
    uint8_t idx = *idxp;
    bpf_policy_freq_idx_map_update_elem(&policy, &idx, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
