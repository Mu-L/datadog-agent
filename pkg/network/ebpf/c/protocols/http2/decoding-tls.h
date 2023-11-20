#ifndef __DECODING_TLS_H
#define __DECODING_TLS_H

#include "bpf_builtins.h"
#include "bpf_helpers.h"

#include "protocols/http2/decoding-common.h"

SEC("uprobe/http2_tls_handle_first_frame")
int uprobe__http2_tls_handle_first_frame(struct pt_regs *ctx) {
    const u32 zero = 0;
    tls_dispatcher_arguments_t *info = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);
    if (info == NULL) {
        log_debug("[http2_tls_handle_first_frame] could not get tls info from map");
        return 0;
    }

    log_debug("[grpcdebug] ------> http2_tls_handle_first_frame: len %03lu <------", info->len);

    return 0;
}

SEC("uprobe/http2_tls_filter")
int uprobe__http2_tls_filter(struct pt_regs *ctx) {
    return 0;
}

SEC("uprobe/http2_tls_frames_parser")
int uprobe__http2_tls_frames_parser(struct __sk_buff *skb) {
    return 0;
}

SEC("uprobe/http2_tls_termination")
int uprobe__http2_tls_termination(struct pt_regs *ctx) {
    log_debug("[grpcdebug] tls termination");

    return 0;
}

#endif // __DECODING_TLS_H
