#ifndef __DECODING_TLS_H
#define __DECODING_TLS_H

#include "bpf_builtins.h"
#include "bpf_helpers.h"

#include "protocols/http/buffer.h"
#include "protocols/http2/decoding-common.h"

READ_INTO_USER_BUFFER_UNALIGNED(http2_1_bytes, 1)
READ_INTO_USER_BUFFER_UNALIGNED(http2_2_bytes, 2)
READ_INTO_USER_BUFFER_UNALIGNED(http2_3_bytes, 3)
READ_INTO_USER_BUFFER_UNALIGNED(http2_4_bytes, 4)
READ_INTO_USER_BUFFER_UNALIGNED(http2_5_bytes, 5)
READ_INTO_USER_BUFFER_UNALIGNED(http2_6_bytes, 6)
READ_INTO_USER_BUFFER_UNALIGNED(http2_7_bytes, 7)
READ_INTO_USER_BUFFER_UNALIGNED(http2_8_bytes, 8)

READ_INTO_USER_BUFFER(http2_preface, HTTP2_MARKER_SIZE)
READ_INTO_USER_BUFFER(http2_frame_header, HTTP2_FRAME_HEADER_SIZE)

// Helper macro to shorten calls to `READ_INTO_USER_BUFFER` generated functions
#define BUF_READ(Name, Dst, Src) (read_into_user_buffer_##Name((void *)Dst, (Src)))

// tls_skip_preface is a helper function to check for the HTTP2 magic sent at the beginning
// of an HTTP2 connection, and skip it if present.
static __always_inline void tls_skip_preface(tls_dispatcher_arguments_t *info) {
    char preface[HTTP2_MARKER_SIZE];
    bpf_memset((char *)preface, 0, HTTP2_MARKER_SIZE);
    BUF_READ(http2_preface, preface, info->buf + info->off);
    if (is_http2_preface(preface, HTTP2_MARKER_SIZE)) {
        log_debug("[grpcdebug] found preface");
        info->off += HTTP2_MARKER_SIZE;
    }
}

// The function is trying to read the remaining of a split frame header. We have the first part in
// `frame_state->buf` (from the previous packet), and now we're trying to read the remaining (`frame_state->remainder`
// bytes from the current packet).
static __always_inline void tls_fix_header_frame(tls_dispatcher_arguments_t *info, char *out, frame_header_remainder_t *frame_state) {
    bpf_memcpy(out, frame_state->buf, HTTP2_FRAME_HEADER_SIZE);

    // Verifier is unhappy with a single call to `bpf_skb_load_bytes` with a variable length (although checking boundaries)
    switch (frame_state->remainder) {
    case 1:
        BUF_READ(http2_1_bytes, out + HTTP2_FRAME_HEADER_SIZE - 1, info->buf + info->off);
        break;
    case 2:
        BUF_READ(http2_2_bytes, out + HTTP2_FRAME_HEADER_SIZE - 2, info->buf + info->off);
        break;
    case 3:
        BUF_READ(http2_3_bytes, out + HTTP2_FRAME_HEADER_SIZE - 3, info->buf + info->off);
        break;
    case 4:
        BUF_READ(http2_4_bytes, out + HTTP2_FRAME_HEADER_SIZE - 4, info->buf + info->off);
        break;
    case 5:
        BUF_READ(http2_5_bytes, out + HTTP2_FRAME_HEADER_SIZE - 5, info->buf + info->off);
        break;
    case 6:
        BUF_READ(http2_6_bytes, out + HTTP2_FRAME_HEADER_SIZE - 6, info->buf + info->off);
        break;
    case 7:
        BUF_READ(http2_7_bytes, out + HTTP2_FRAME_HEADER_SIZE - 7, info->buf + info->off);
        break;
    case 8:
        BUF_READ(http2_8_bytes, out + HTTP2_FRAME_HEADER_SIZE - 8, info->buf + info->off);
        break;
    }
    return;
}

static __always_inline bool tls_get_first_frame(tls_dispatcher_arguments_t *info, frame_header_remainder_t *frame_state, struct http2_frame *current_frame) {
    // No state, try reading a frame.
    if (frame_state == NULL) {
        // Checking we have enough bytes in the packet to read a frame header.
        if (info->off + HTTP2_FRAME_HEADER_SIZE > info->len) {
            // Not enough bytes, cannot read frame, so we have 0 interesting frames in that packet.
            return false;
        }

        // Reading frame, and ensuring the frame is valid.
        BUF_READ(http2_frame_header, current_frame, info->buf + info->off);
        info->off += HTTP2_FRAME_HEADER_SIZE;
        if (!format_http2_frame_header(current_frame)) {
            // Frame is not valid, so we have 0 interesting frames in that packet.
            return false;
        }
        return true;
    }

    // Getting here means we have a frame state from the previous packets.
    // Scenarios in order:
    //  1. Check if we have a frame-header remainder - if so, we must try and read the rest of the frame header.
    //     In case of a failure, we abort.
    //  2. If we don't have a frame-header remainder, then we're trying to read a valid frame.
    //     HTTP2 can send valid frames (like SETTINGS and PING) during a split DATA frame. If such a frame exists,
    //     then we won't have the rest of the split frame in the same packet.
    //  3. If we reached here, and we have a remainder, then we're consuming the remainder and checking we can read the
    //     next frame header.
    //  4. We failed reading any frame. Aborting.

    // Frame-header-remainder.
    if (frame_state->header_length > 0) {
        tls_fix_header_frame(info, (char *)current_frame, frame_state);
        if (format_http2_frame_header(current_frame)) {
            info->off += frame_state->remainder;
            frame_state->remainder = 0;
            return true;
        }

        // We couldn't read frame header using the remainder.
        return false;
    }

    // Checking if we can read a frame header.
    if (info->off + HTTP2_FRAME_HEADER_SIZE <= info->len) {
        BUF_READ(http2_frame_header, current_frame, info->buf + info->off);
        if (format_http2_frame_header(current_frame)) {
            // We successfully read a valid frame.
            info->off += HTTP2_FRAME_HEADER_SIZE;
            return true;
        }
    }

    // We failed to read a frame, if we have a remainder trying to consume it and read the following frame.
    if (frame_state->remainder > 0) {
        info->off += frame_state->remainder;
        // The remainders "ends" the current packet. No interesting frames were found.
        if (info->off == info->len) {
            frame_state->remainder = 0;
            return false;
        }
        reset_frame(current_frame);
        BUF_READ(http2_frame_header, current_frame, info->buf + info->off);
        if (format_http2_frame_header(current_frame)) {
            frame_state->remainder = 0;
            info->off += HTTP2_FRAME_HEADER_SIZE;
            return true;
        }
    }

    // still not valid / does not have a remainder - abort.
    return false;
}

// find_relevant_frames iterates over the packet and finds frames that are
// relevant for us. The frames info and location are stored in the `frames_array` array,
// and the number of frames found is returned.
//
// We consider frames as relevant if they are either:
// - HEADERS frames
// - RST_STREAM frames
// - DATA frames with the END_STREAM flag set
static __always_inline __u8 tls_find_relevant_frames(tls_dispatcher_arguments_t *info, http2_frame_with_offset *frames_array, __u8 original_index) {
    bool is_headers_or_rst_frame, is_data_end_of_stream;
    __u8 interesting_frame_index = 0;
    struct http2_frame current_frame = {};

    // We may have found a relevant frame already in http2_handle_first_frame,
    // so we need to adjust the index accordingly. We do not set
    // interesting_frame_index to original_index directly, as this will confuse
    // the verifier, leading it into thinking the index could have an arbitrary
    // value.
    if (original_index == 1) {
        interesting_frame_index = 1;
    }

#pragma unroll(TLS_HTTP2_MAX_FRAMES_TO_FILTER)
    for (__u32 iteration = 0; iteration < TLS_HTTP2_MAX_FRAMES_TO_FILTER; ++iteration) {
        // Checking we can read HTTP2_FRAME_HEADER_SIZE from the skb.
        if (info->off + HTTP2_FRAME_HEADER_SIZE > info->len) {
            break;
        }

        BUF_READ(http2_frame_header, &current_frame, info->buf + info->off);
        info->off += HTTP2_FRAME_HEADER_SIZE;
        if (!format_http2_frame_header(&current_frame)) {
            break;
        }

        // END_STREAM can appear only in Headers and Data frames.
        // Check out https://datatracker.ietf.org/doc/html/rfc7540#section-6.1 for data frame, and
        // https://datatracker.ietf.org/doc/html/rfc7540#section-6.2 for headers frame.
        is_headers_or_rst_frame = current_frame.type == kHeadersFrame || current_frame.type == kRSTStreamFrame;
        is_data_end_of_stream = ((current_frame.flags & HTTP2_END_OF_STREAM) == HTTP2_END_OF_STREAM) && (current_frame.type == kDataFrame);
        if (interesting_frame_index < HTTP2_MAX_FRAMES_ITERATIONS && (is_headers_or_rst_frame || is_data_end_of_stream)) {
            frames_array[interesting_frame_index].frame = current_frame;
            frames_array[interesting_frame_index].offset = info->off;
            interesting_frame_index++;
        }
        info->off += current_frame.length;
    }

    return interesting_frame_index;
}

SEC("uprobe/http2_tls_handle_first_frame")
int uprobe__http2_tls_handle_first_frame(struct pt_regs *ctx) {
    const u32 zero = 0;
    struct http2_frame current_frame = { 0 };
    tls_dispatcher_arguments_t info_copy = { 0 };

    tls_dispatcher_arguments_t *info = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);
    if (info == NULL) {
        log_debug("[http2_tls_handle_first_frame] could not get tls info from map");
        return 0;
    }
    info_copy = *info;

    log_debug("[grpcdebug] ------> http2_tls_handle_first_frame: len %03lu <------", info->len);

    // A single packet can contain multiple HTTP/2 frames, due to instruction limitations we have divided the
    // processing into multiple tail calls, where each tail call process a single frame. We must have context when
    // we are processing the frames, for example, to know how many bytes have we read in the packet, or it we reached
    // to the maximum number of frames we can process. For that we are checking if the iteration context already exists.
    // If not, creating a new one to be used for further processing
    http2_tail_call_state_t *iteration_value = bpf_map_lookup_elem(&http2_frames_to_process, &zero);
    if (iteration_value == NULL) {
        return 0;
    }
    iteration_value->frames_count = 0;
    iteration_value->iteration = 0;

    // skip HTTP2 magic, if present
    tls_skip_preface(&info_copy);

    frame_header_remainder_t *frame_state = bpf_map_lookup_elem(&http2_remainder, &info_copy.tup);

    if (!tls_get_first_frame(&info_copy, frame_state, &current_frame)) {
        return 0;
    }

    // If we have a state and we consumed it, then delete it.
    if (frame_state != NULL && frame_state->remainder == 0) {
        bpf_map_delete_elem(&http2_remainder, &info_copy.tup);
    }

    bool is_headers_or_rst_frame = current_frame.type == kHeadersFrame || current_frame.type == kRSTStreamFrame;
    bool is_data_end_of_stream = ((current_frame.flags & HTTP2_END_OF_STREAM) == HTTP2_END_OF_STREAM) && (current_frame.type == kDataFrame);
    if (is_headers_or_rst_frame || is_data_end_of_stream) {
        iteration_value->frames_array[0].frame = current_frame;
        iteration_value->frames_array[0].offset = info_copy.off;
        iteration_value->frames_count = 1;
    }
    info_copy.off += current_frame.length;
    // Overriding the off field of the cached info. The next prog will start from the offset of the next valid
    // frame.
    info->off = info_copy.off;
    bpf_tail_call_compat(ctx, &tls_process_progs, TLS_HTTP2_FILTER);

    return 0;
}

SEC("uprobe/http2_tls_filter")
int uprobe__http2_tls_filter(struct pt_regs *ctx) {
    const u32 zero = 0;

    tls_dispatcher_arguments_t *info = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);
    if (info == NULL) {
        log_debug("[http2_tls_handle_first_frame] could not get tls info from map");
        return 0;
    }

    log_debug("[grpcdebug] > frame filter: off=%lu", info->off);

    // A single packet can contain multiple HTTP/2 frames, due to instruction limitations we have divided the
    // processing into multiple tail calls, where each tail call process a single frame. We must have context when
    // we are processing the frames, for example, to know how many bytes have we read in the packet, or it we reached
    // to the maximum number of frames we can process. For that we are checking if the iteration context already exists.
    // If not, creating a new one to be used for further processing
    http2_tail_call_state_t *iteration_value = bpf_map_lookup_elem(&http2_frames_to_process, &zero);
    if (iteration_value == NULL) {
        return 0;
    }

    // Some functions might change and override fields in dispatcher_args_copy.skb_info. Since it is used as a key
    // in a map, we cannot allow it to be modified. Thus, having a local copy of skb_info.
    tls_dispatcher_arguments_t info_copy = *info;

    // The verifier cannot tell if `iteration_value->frames_count` is 0 or 1, so we have to help it. The value is
    // 1 if we have found an interesting frame in `socket__http2_handle_first_frame`, otherwise it is 0.
    // filter frames
    iteration_value->frames_count = tls_find_relevant_frames(&info_copy, iteration_value->frames_array, iteration_value->frames_count);
    // TODO log_debug("[grpcdebug] > frame filter: frames_count=%u", iteration_value->frames_count);

    frame_header_remainder_t new_frame_state = { 0 };
    if (info_copy.off > info_copy.len) {
        // We have a remainder
        new_frame_state.remainder = info_copy.off - info_copy.len;
        bpf_map_update_elem(&http2_remainder, &info_copy.tup, &new_frame_state, BPF_ANY);
    }

    if (info_copy.off < info_copy.len && info_copy.off + HTTP2_FRAME_HEADER_SIZE > info_copy.len) {
        // We have a frame header remainder
        new_frame_state.remainder = HTTP2_FRAME_HEADER_SIZE - (info_copy.len - info_copy.off);
        bpf_memset(new_frame_state.buf, 0, HTTP2_FRAME_HEADER_SIZE);
#pragma unroll(HTTP2_FRAME_HEADER_SIZE)
        for (__u32 iteration = 0; iteration < HTTP2_FRAME_HEADER_SIZE && new_frame_state.remainder + iteration < HTTP2_FRAME_HEADER_SIZE; ++iteration) {
            BUF_READ(http2_1_bytes, new_frame_state.buf + iteration, info_copy.buf + info_copy.off + iteration);
        }
        new_frame_state.header_length = HTTP2_FRAME_HEADER_SIZE - new_frame_state.remainder;
        bpf_map_update_elem(&http2_remainder, &info_copy.tup, &new_frame_state, BPF_ANY);
    }

    if (iteration_value->frames_count == 0) {
        return 0;
    }

    log_debug("[grpcdebug] > frame filter: frames_count=%u", iteration_value->frames_count);

    // We have interesting headers, launching tail calls to handle them.
    if (bpf_map_update_elem(&tls_http2_iterations, &info_copy, iteration_value, BPF_NOEXIST) >= 0) {
        // We managed to cache the iteration_value in the http2_iterations map.
        bpf_tail_call_compat(ctx, &tls_process_progs, TLS_HTTP2_PARSER);
    }

    return 0;
}

SEC("uprobe/http2_tls_frames_parser")
int uprobe__http2_tls_frames_parser(struct __sk_buff *skb) {
    log_debug("[grpcdebug] > frame parser");

    return 0;
}

SEC("uprobe/http2_tls_termination")
int uprobe__http2_tls_termination(struct pt_regs *ctx) {
    log_debug("[grpcdebug] tls termination");
    const u32 zero = 0;

    tls_dispatcher_arguments_t *info = bpf_map_lookup_elem(&tls_dispatcher_arguments, &zero);
    if (info == NULL) {
        log_debug("[http2_tls_termination] could not get tls info from map");
        return 0;
    }

    // Deleting the entry for the original tuple.
    bpf_map_delete_elem(&http2_dynamic_counter_table, &info->tup);
    // In case of local host, the protocol will be deleted for both (client->server) and (server->client),
    // so we won't reach for that path again in the code, so we're deleting the opposite side as well.
    flip_tuple(&info->tup);
    bpf_map_delete_elem(&http2_dynamic_counter_table, &info->tup);

    return 0;
}

#endif // __DECODING_TLS_H
