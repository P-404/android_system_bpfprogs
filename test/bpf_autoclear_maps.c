#include <bpf_helpers.h>

DEFINE_BPF_MAP_CLEAR(autoclear_hash, HASH, uint32_t, uint32_t, 4, true)
DEFINE_BPF_MAP_CLEAR(autoclear_percpu_hash, PERCPU_HASH, uint32_t, uint32_t, 4, true)
DEFINE_BPF_MAP_CLEAR(autoclear_array, ARRAY, uint32_t, uint32_t, 4, true)
DEFINE_BPF_MAP_CLEAR(autoclear_percpu_array, PERCPU_ARRAY, uint32_t, uint32_t, 4, true)

char _license[] SEC("license") = "GPL";
