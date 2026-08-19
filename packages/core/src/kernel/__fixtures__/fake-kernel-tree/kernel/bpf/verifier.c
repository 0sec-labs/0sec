/* Fake BPF verifier for testing */
#include <linux/bpf.h>

static const struct bpf_verifier_ops socket_filter_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
};

static const struct bpf_verifier_ops tracing_verifier_ops = {
	.get_func_proto = tracing_func_proto,
};
