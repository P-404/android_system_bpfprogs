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

#define FREQS_PER_ENTRY 32

typedef struct {
    uint32_t uid;
    uint32_t bucket;
} time_key;

typedef struct {
    uint64_t ar[FREQS_PER_ENTRY];
} time_val;

DEFINE_BPF_MAP(uid_times_map, PERCPU_HASH, time_key, time_val, 1024)
DEFINE_BPF_MAP(cpu_last_update_map, PERCPU_ARRAY, uint32_t, uint64_t, 1)

DEFINE_BPF_MAP(cpu_policy_map, ARRAY, uint32_t, uint32_t, 1024)
DEFINE_BPF_MAP(policy_freq_idx_map, ARRAY, uint32_t, uint8_t, 1024)

typedef struct {
	uint32_t policy;
	uint32_t freq;
} freq_idx_key;

DEFINE_BPF_MAP(freq_to_idx_map, HASH, freq_idx_key, uint8_t, 2048)

DEFINE_BPF_MAP(zero_map, ARRAY, uint32_t, time_val, 1)

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

    if (!args->prev_pid || !old_last) return 0;

    uint32_t cpu = bpf_get_smp_processor_id();
    uint32_t* policyp = bpf_cpu_policy_map_lookup_elem(&cpu);
    if (!policyp) return 0;
    uint32_t policy = *policyp;
    uint8_t* freq_idxp = bpf_policy_freq_idx_map_lookup_elem(&policy);
    if (!freq_idxp || !*freq_idxp) return 0;
    // freq_to_idx_map uses 1 as its minimum index so that *freq_idxp == 0 only when uninitialized
    uint8_t freq_idx = *freq_idxp - 1;

    uint32_t uid = bpf_get_current_uid_gid();
    time_key key = {.uid = uid, .bucket = freq_idx / FREQS_PER_ENTRY};
    time_val* val = bpf_uid_times_map_lookup_elem(&key);
    if (!val) {
        time_val* zero_valp = bpf_zero_map_lookup_elem(&zero);
        if (!zero_valp) return 0;
        time_val zero_val = *zero_valp;
        bpf_uid_times_map_update_elem(&key, &zero_val, BPF_NOEXIST);
        val = bpf_uid_times_map_lookup_elem(&key);
    }
    uint64_t delta = time - old_last;
    if (val) val->ar[freq_idx % FREQS_PER_ENTRY] += delta;
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
