/* packet-btpu.c
 * Routines for Bundle Transfer Protocol - Unidirectional dissection.
 * References:
 *     BTP-U draft: https://www.ietf.org/archive/id/draft-ietf-dtn-btpu-02.html
 *
 * Copyright 2026, Brian Sipos <brian.sipos@gmail.com>
 */
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/exceptions.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <inttypes.h>

#if defined(WIRESHARK_HAS_VERSION_H)
#include <ws_version.h>
#else
#include <config.h>
#define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
#define WIRESHARK_VERSION_MINOR VERSION_MINOR
#endif

#if defined(WIRESHARK_NEW_FLAGSPTR)
#define WS_FIELDTYPE int *const
#else
#define WS_FIELDTYPE const int *
#endif

/// Protocol column name
static const char *const proto_name_btpu = "BTP-U";
// Default bindings
static const char *const BTPU_ETHERTYPE = "0x88b5";
// Protocol preferences
static bool btpu_desegment_transfer = TRUE;
static bool btpu_analyze_sequence = TRUE;
static bool btpu_decode_bundle = TRUE;

/// Protocol handles
static int proto_btpu = -1;

/// Dissector handles
static dissector_handle_t handle_btpu = NULL;
static dissector_handle_t handle_cbor = NULL;
static dissector_handle_t handle_bpv7 = NULL;

/// Dissect extension items
static dissector_table_t table_ext = NULL;

/// Fragment reassembly
static reassembly_table btpu_reassembly_table;

static int hf_padding = -1;
static int hf_msg_type = -1;
static int hf_msg_flags = -1;
static int hf_msg_flags_hint = -1;
static int hf_msg_len = -1;
static int hf_hints_count = -1;
static int hf_hint_type = -1;
static int hf_hint_hflag = -1;
static int hf_hint_len = -1;
static int hf_hint_value_raw = -1;
static int hf_hint_value_blen = -1;

static int hf_bundle_size = -1;
static int hf_bundle_data = -1;

static int hf_seg_xfer = -1;
static int hf_seg_idx = -1;
static int hf_seg_size = -1;
static int hf_seg_data = -1;

static int hf_cancel_xfer = -1;

static int hf_xferload_segments = -1;
static int hf_xferload_segment = -1;
static int hf_xferload_segment_overlap = -1;
static int hf_xferload_segment_overlap_conflicts = -1;
static int hf_xferload_segment_multiple_tails = -1;
static int hf_xferload_segment_too_long_segment = -1;
static int hf_xferload_segment_error = -1;
static int hf_xferload_segment_count = -1;
static int hf_xferload_reassembled_in = -1;
static int hf_xferload_reassembled_length = -1;
static int hf_xferload_reassembled_data = -1;
static gint ett_xferload_segment = -1;
static gint ett_xferload_segments = -1;

static const value_string btpu_msg_type_vals[]={
    {0, "Reserved (padding)"},
    {2, "Bundle"},
    {3, "Transfer Segment"},
    {4, "Transfer End"},
    {5, "Transfer Cancel"},
    {0, NULL},
};

static int *const msg_flags_fields[] = {
    &hf_msg_flags_hint,
    NULL
};

typedef enum {
    BTPU_MSG_FLAG_HINT = 0x8,
} BtpuMsgFlags;

static const value_string btpu_hint_type_vals[]={
    {0, "Bundle Length"},
    {0, NULL},
};

/// Field definitions
static hf_register_info fields[] = {
    {&hf_padding, {"Padding, Length", "btpu.padding", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_msg_type, {"Type", "btpu.msg.type", FT_UINT8, BASE_DEC, VALS(btpu_msg_type_vals), 0x0, NULL, HFILL}},
    {&hf_msg_flags, {"Flags", "btpu.msg.flags", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}},
    {&hf_msg_flags_hint, {"Has Hint", "btpu.msg.flags.hint", FT_BOOLEAN, 8, TFS(&tfs_set_notset), BTPU_MSG_FLAG_HINT << 4, "Flag is set when there are hint items in the header", HFILL}},
    {&hf_msg_len, {"Length", "btpu.msg.length", FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, "Length of the message excluding 4-octet header", HFILL}},

    {&hf_hints_count, {"Hints Count", "btpu.msg.hint_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_hint_type, {"Type", "btpu.hint.type", FT_UINT8, BASE_DEC, VALS(btpu_hint_type_vals), 0x0, NULL, HFILL}},
    {&hf_hint_hflag, {"Next Hint", "btpu.hint.hflag", FT_BOOLEAN, 8, TFS(&tfs_more_nomore), 0x1, "Flag is set when there is a following hint item", HFILL}},
    {&hf_hint_len, {"Length", "btpu.hint.length", FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, "Length of the hint value", HFILL}},
    {&hf_hint_value_raw, {"Value", "btpu.hint.value_raw", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_hint_value_blen, {"Bundle Length", "btpu.hint.bundle_len", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, "Total length of bundle PDU", HFILL}},

    {&hf_bundle_size, {"Payload Size", "btpu.bundle.size", FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_bundle_data, {"Payload Data", "btpu.bundle.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_seg_xfer, {"Transfer Number", "btpu.seg.xfer_num", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_seg_idx, {"Segment Index", "btpu.seg.seg_idx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_seg_size, {"Segment Size", "btpu.seg.size", FT_UINT32, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_seg_data, {"Segment Data", "btpu.seg.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_cancel_xfer, {"Transfer Number", "btpu.cancel.xfer_num", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},

    {&hf_xferload_segments,
        {"Transfer segments", "btpu.xferload.segments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_segment,
        {"Transfer segment", "btpu.xferload.segment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_segment_overlap,
        {"Transfer segment overlap", "btpu.xferload.segment.overlap",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_segment_overlap_conflicts,
        {"Transfer segment overlapping with conflicting data",
        "btpu.xferload.segment.overlap.conflicts",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_segment_multiple_tails,
        {"Message has multiple tail segments",
        "btpu.xferload.segment.multiple_tails",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_segment_too_long_segment,
        {"Transfer segment too long", "btpu.xferload.segment.too_long_segment",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_segment_error,
        {"Transfer desegmentation error", "btpu.xferload.segment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_segment_count,
        {"Transfer segment count", "btpu.xferload.segment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_reassembled_in,
        {"Reassembled in", "btpu.xferload.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_reassembled_length,
        {"Reassembled length", "btpu.xferload.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_reassembled_data,
        {"Reassembled data", "btpu.xferload.reassembled.data",
        FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
};

static const fragment_items xferload_frag_items = {
    /* Fragment subtrees */
    &ett_xferload_segment,
    &ett_xferload_segments,
    /* Fragment fields */
    &hf_xferload_segments,
    &hf_xferload_segment,
    &hf_xferload_segment_overlap,
    &hf_xferload_segment_overlap_conflicts,
    &hf_xferload_segment_multiple_tails,
    &hf_xferload_segment_too_long_segment,
    &hf_xferload_segment_error,
    &hf_xferload_segment_count,
    /* Reassembled in field */
    &hf_xferload_reassembled_in,
    &hf_xferload_reassembled_length,
    &hf_xferload_reassembled_data,
    /* Tag */
    "Transfer segments"
};

static int ett_btpu = -1;
static int ett_msg = -1;
static int ett_msg_flags = -1;
static int ett_hints = -1;
static int ett_hint = -1;
/// Tree structures
static int *ett[] = {
    &ett_btpu,
    &ett_msg,
    &ett_msg_flags,
    &ett_hints,
    &ett_hint,
    &ett_xferload_segment,
    &ett_xferload_segments,
};

static expert_field ei_pad_nonzero = EI_INIT;
static expert_field ei_msg_type_unknown = EI_INIT;
static expert_field ei_msg_content_invalid = EI_INIT;
static expert_field ei_hint_type_unknown = EI_INIT;
static expert_field ei_hint_value_invalid = EI_INIT;
static expert_field ei_segment_reassemble_size = EI_INIT;
static expert_field ei_segment_tot_mismatch = EI_INIT;
static expert_field ei_non_bundle_data = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_pad_nonzero, { "btpu.padding.nonzero", PI_MALFORMED, PI_WARN, "Padding has non-zero-value octet", EXPFILL}},
    {&ei_msg_type_unknown, {"btpu.msg_type_unknown", PI_UNDECODED, PI_WARN, "Message Type is unknown", EXPFILL}},
    {&ei_msg_content_invalid, {"btpu.msg_content_invalid", PI_MALFORMED, PI_ERROR, "Message Content is invalid", EXPFILL}},
    {&ei_hint_type_unknown, {"btpu.hint_type_unknown", PI_UNDECODED, PI_WARN, "Hint Type is unknown", EXPFILL}},
    {&ei_hint_value_invalid, {"btpu.hint_value_invalid", PI_MALFORMED, PI_ERROR, "Hint value is invalid", EXPFILL}},
    {&ei_segment_reassemble_size, {"btpu.segment_reassemble_size", PI_REASSEMBLE, PI_ERROR, "Cannot desegment this size (wireshark limitation)", EXPFILL}},
    {&ei_segment_tot_mismatch, {"btpu.segment_tot_mismatch", PI_REASSEMBLE, PI_ERROR, "Inconsistent total length between segments", EXPFILL}},
    {&ei_non_bundle_data, { "btpu.non_bundle_data", PI_UNDECODED, PI_WARN, "Non-bundle data present", EXPFILL}},
};

/// Dissecting context information
typedef struct {
    /// Total PDU size
    int total_len;
    /// Raw offset of the end of the PDU
    unsigned pdu_raw_end;
} btpu_context_t;

/** Dissect pure bundle data.
 */
static int dissect_bundle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    gint sublen = 0;

    if (btpu_decode_bundle && handle_bpv7) {
        sublen = call_dissector(
            handle_bpv7,
            tvb,
            pinfo,
            tree
        );
    }
    if (sublen == 0) {
        TRY {
            sublen = call_dissector(handle_cbor, tvb, pinfo, tree);
        }
        CATCH_ALL {}
        ENDTRY;
    }

    return sublen;
}

/// Show tree items representing the bundle data
static int dissect_msg_bundle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_msg, btpu_context_t *ctx) {
    const int tvb_len = tvb_reported_length(tvb);
    proto_item *item_size = proto_tree_add_uint(tree_msg, hf_bundle_size, tvb, 0, tvb_len, tvb_len);
    proto_item_set_generated(item_size);
    proto_tree_add_item(tree_msg, hf_bundle_data, tvb, 0, tvb_len, ENC_NA);

    if (tvb_raw_offset(tvb) + tvb_len == ctx->pdu_raw_end) {
        // fully encapsulated bundles treate BTPU as pure header
        proto_tree *tree_btpu = proto_tree_get_parent_tree(tree_msg);
        proto_item *item_btpu = proto_tree_get_parent(tree_btpu);
        proto_item_set_end(item_btpu, tvb, 0);
    }

    // return actual size used
    return dissect_bundle(tvb, pinfo, proto_tree_get_root(tree_msg));
}

/// Show tree items representing the a segment
static int dissect_msg_segment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_msg, btpu_context_t *ctx _U_, uint8_t msg_type) {
    int offset = 0;

    uint32_t xfer_num = 0;
    proto_tree_add_item_ret_uint32(tree_msg, hf_seg_xfer, tvb, offset, 4, ENC_BIG_ENDIAN, &xfer_num);
    offset += 4;

    uint32_t seg_idx = 0;
    proto_tree_add_item_ret_uint32(tree_msg, hf_seg_idx, tvb, offset, 4, ENC_BIG_ENDIAN, &seg_idx);
    offset += 4;

    tvbuff_t *seg = tvb_new_subset_remaining(tvb, offset);
    const int seg_len = tvb_reported_length(seg);
    proto_item *item_size = proto_tree_add_uint(tree_msg, hf_seg_size, seg, 0, 0, seg_len);
    proto_item_set_generated(item_size);

    proto_tree_add_item(tree_msg, hf_seg_data, seg, 0, -1, ENC_NA);
    offset += seg_len;

    if (btpu_desegment_transfer) {
        const bool more_seg = (msg_type == 3);

        fragment_head *frag_msg = fragment_add_seq_check(
            &btpu_reassembly_table,
            seg, 0,
            pinfo, xfer_num, NULL,
            seg_idx,
            seg_len,
            more_seg
        );

        proto_tree *tree_root = proto_tree_get_root(tree_msg);
        tvbuff_t *xferload = process_reassembled_data(
            seg, 0, pinfo,
            "Reassembled Transfer",
            frag_msg,
            &xferload_frag_items,
            NULL,
            tree_root
        );
        if (xferload)
        {
            dissect_bundle(xferload, pinfo, tree_root);
        }
    }

    return offset;
}

static int dissect_msg_cancel(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree_msg, btpu_context_t *ctx _U_) {
    int offset = 0;

    uint32_t xfer_num = 0;
    proto_tree_add_item_ret_uint32(tree_msg, hf_cancel_xfer, tvb, offset, 4, ENC_BIG_ENDIAN, &xfer_num);
    offset += 4;

    return offset;
}

static int dissect_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_btpu, btpu_context_t *ctx) {
    int offset = 0;

    proto_item *item_msg;
    proto_tree *tree_msg = proto_tree_add_subtree(tree_btpu, tvb, offset, 0, ett_msg, &item_msg, "Message");

    uint8_t msg_type = 0;
    proto_item *item_type = proto_tree_add_item_ret_uint8(tree_msg, hf_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN, &msg_type);
    offset += 1;
    // annotate the parent
    const char *type_name = try_val_to_str(msg_type, btpu_msg_type_vals);
    const char *proto_name = col_get_text(pinfo->cinfo, COL_PROTOCOL);
    const bool info_is_btpu = (g_strcmp0(proto_name, proto_name_btpu) == 0);
    if (type_name) {
        proto_item_append_text(item_msg, ": %s", type_name);
        if (info_is_btpu) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", type_name);
        }
    }
    else
    {
        proto_item_append_text(item_msg, ": Type %" PRIu8, msg_type);
        if (info_is_btpu) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Type %"PRIu8, msg_type);
        }
    }

    uint64_t msg_flags = 0;
    proto_tree_add_bitmask_ret_uint64(tree_msg, tvb, offset, hf_msg_flags, ett_msg_flags, msg_flags_fields, ENC_BIG_ENDIAN, &msg_flags);

//    proto_tree_add_boolean(tree_flags, hf_msg_flags_hint, tvb, offset, 1, msg_flags);

    uint64_t msg_len = 0;
    proto_tree_add_bits_ret_val(tree_msg, hf_msg_len, tvb, offset * 8 + 4, 20, &msg_len, ENC_BIG_ENDIAN);
    offset += 3;

    proto_item *item_hints;
    proto_tree *tree_hints = proto_tree_add_subtree(tree_msg, tvb, offset, 0, ett_hints, &item_hints, "Hint Items");

    bool more_hint = msg_flags & BTPU_MSG_FLAG_HINT;
    uint32_t hints_count = 0;
    const int hints_start = offset;
    while (more_hint) {
        proto_item *item_hint;
        proto_tree *tree_hint = proto_tree_add_subtree(tree_hints, tvb, offset, 0, ett_hint, &item_hint, "Hint");

        uint64_t hint_type = 0;
        proto_item *item_htype = proto_tree_add_bits_ret_val(tree_hint, hf_hint_type, tvb, offset * 8, 7, &hint_type, ENC_BIG_ENDIAN);
        proto_item_append_text(item_hint, ", Type: %" PRIu64, hint_type);

        proto_tree_add_boolean(tree_hint, hf_hint_hflag, tvb, offset, 1, msg_flags);
        more_hint = false;
        offset += 1;

        uint8_t hint_len = 0;
        proto_tree_add_item_ret_uint8(tree_hint, hf_hint_len, tvb, offset, 1, ENC_BIG_ENDIAN, &hint_len);
        offset += 1;

        bool type_known = true;
        bool value_known = true;
        switch (hint_type) {
            case 0: {
                uint64_t total_len;
                switch (hint_len) {
                    case 1:
                        total_len = tvb_get_uint8(tvb, offset);
                        break;
                    case 2:
                        total_len = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
                        break;
                    case 4:
                        total_len = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
                        break;
                    case 8:
                        total_len = tvb_get_uint64(tvb, offset, ENC_BIG_ENDIAN);
                        break;
                    default:
                        value_known = false;
                        break;
                }
                if (value_known) {
                    proto_tree_add_uint64(tree_hint, hf_hint_value_blen, tvb, offset, hint_len, total_len);
                }
                break;
            }
            default:
                type_known = false;
                break;
        }
        if (!type_known) {
            expert_add_info(pinfo, item_htype, &ei_hint_type_unknown);
        }
        if (!type_known || !value_known) {
            // show the raw value
            proto_item *item_val = proto_tree_add_item(tree_hint, hf_hint_value_raw, tvb, offset, hint_len, ENC_NA);
            if (!value_known) {
                expert_add_info(pinfo, item_val, &ei_hint_value_invalid);
            }
        }

        offset += hint_len;

        proto_item_set_end(item_hint, tvb, offset);
        hints_count += 1;
    }
    proto_item *item_count = proto_tree_add_uint(tree_hints, hf_hints_count, tvb, hints_start, offset - hints_start, hints_count);
    proto_item_set_generated(item_count);

    proto_item_append_text(item_hints, ", Count: %" PRIu32, hints_count);
    proto_item_set_end(item_hints, tvb, offset);

    const int content_len = 4 + msg_len - offset;
    tvbuff_t *content = tvb_new_subset_length(tvb, offset, content_len);

    int sublen = 0;
    switch (msg_type) {
        case 0:
            // Reserved for padding
            break;

        case 2:
            // no other content prefix
            sublen = dissect_msg_bundle(content, pinfo, tree_msg, ctx);
            break;
        case 3:
        case 4:
            sublen = dissect_msg_segment(content, pinfo, tree_msg, ctx, msg_type);
            break;
        case 5:
            sublen = dissect_msg_cancel(content, pinfo, tree_msg, ctx);
            break;
        default:
            expert_add_info(pinfo, item_type, &ei_msg_type_unknown);
            // do not add additional error, treat as fully dissected
            sublen = content_len;
            break;
    }
    if (sublen != content_len)
    {
        expert_add_info(pinfo, item_msg, &ei_msg_content_invalid);
        return 0;
    }
    offset += sublen;
    proto_item_set_len(item_msg, offset);

    return offset;
}

/// Top-level protocol dissector
static int dissect_btpu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    {
        const char *proto_name = col_get_text(pinfo->cinfo, COL_PROTOCOL);
        if (g_strcmp0(proto_name, proto_name_btpu) != 0) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_btpu);
            col_clear(pinfo->cinfo, COL_INFO);
        }
    }

    const unsigned buflen = tvb_captured_length(tvb);
    gint offset = 0;
    proto_item *item_btpu = proto_tree_add_item(tree, proto_btpu, tvb, 0, -1, ENC_NA);
    proto_tree *tree_btpu = proto_item_add_subtree(item_btpu, ett_btpu);

    btpu_context_t ctx = {
        .total_len = buflen,
        .pdu_raw_end = tvb_raw_offset(tvb) + buflen,
    };

    while ((unsigned)offset < buflen) {
        // Peek at first octet
        const guint8 first_octet = tvb_get_uint8(tvb, offset);

        if (first_octet == 0x00) {
            const unsigned padlen = buflen - offset;
            {
                const char *proto_name = col_get_text(pinfo->cinfo, COL_PROTOCOL);
                if (g_strcmp0(proto_name, proto_name_btpu) == 0) {
                    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Padding[len=%" PRIu32 "]", padlen);
                }
            }

            proto_item *item_ka = proto_tree_add_uint64(tree_btpu, hf_padding, tvb, offset, padlen, padlen);
            for (unsigned ix = offset + 1; ix < buflen; ++ix) {
                if (tvb_get_uint8(tvb, ix) != 0x0) {
                    expert_add_info(pinfo, item_ka, &ei_pad_nonzero);
                    break;
                }
            }

            offset = buflen;
            proto_item_set_len(item_btpu, offset);
        }
        else
        {
            tvbuff_t *remain = tvb_new_subset_remaining(tvb, offset);
            int sublen = dissect_msg(remain, pinfo, tree_btpu, &ctx);
            if (sublen <= 0)
            {
                break;
            }
            offset += sublen;
        }
    }

    return offset;
}

/// Initialize for a new file load
static void btpu_init(void) {
}

/// Cleanup after a file
static void btpu_cleanup(void) {
}

/// Re-initialize after a configuration change
static void btpu_reinit(void) {
}

/// Overall registration of the protocol
static void proto_register_btpu(void) {
    proto_btpu = proto_register_protocol(
        "Bundle Transfer Protocol - Unidirectional", /* name */
        "BTP-U", /* short name */
        "btpu" /* abbrev */
    );
    register_init_routine(&btpu_init);
    register_cleanup_routine(&btpu_cleanup);

    proto_register_field_array(proto_btpu, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_btpu);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

    handle_btpu = register_dissector("btpu", dissect_btpu, proto_btpu);
    table_ext = register_dissector_table("btpu.hint", "BTP-U Hint", proto_btpu, FT_UINT8, BASE_DEC);

    module_t *module_btpu = prefs_register_protocol(proto_btpu, btpu_reinit);
    prefs_register_bool_preference(
        module_btpu,
        "analyze_sequence",
        "Analyze message sequences",
        "Whether the dissector should analyze the sequencing of "
        "the messages within each conversation.",
        &btpu_analyze_sequence
    );
    prefs_register_bool_preference(
        module_btpu,
        "desegment_transfer",
        "Reassemble the segments of each transfer",
        "Whether the dissector should combine the segments "
        "of a transfer into the full bundle being transfered.",
        &btpu_desegment_transfer
    );
    prefs_register_bool_preference(
        module_btpu,
        "decode_bundle",
        "Decode bundle data",
        "If enabled, the bundle will be decoded as BPv7 content. "
        "Otherwise, it is assumed to be plain CBOR.",
        &btpu_decode_bundle
    );

    reassembly_table_register(
        &btpu_reassembly_table,
        &addresses_ports_reassembly_table_functions
    );
}

static void proto_reg_handoff_btpu(void) {
    dissector_add_uint_range_with_preference("ethertype", BTPU_ETHERTYPE, handle_btpu);

    handle_cbor = find_dissector_add_dependency("cbor", proto_btpu);
    handle_bpv7 = find_dissector_add_dependency("bpv7", proto_btpu);

    /* Packaged extensions */
#if 0
    {
        dissector_handle_t dis_h = create_dissector_handle_with_name_and_description(dissect_transfer, proto_btpu, NULL, "Transfer");
        dissector_add_uint("btpu.ext", 2, dis_h);
    }
#endif

    btpu_reinit();
}

#define PP_STRINGIZE_I(text) #text

/// Interface for wireshark plugin
WS_DLL_PUBLIC_DEF const char plugin_type[] = "epan_plugin";
/// Interface for wireshark plugin
WS_DLL_PUBLIC_DEF const char plugin_version[] = "0.0";
/// Interface for wireshark plugin
WS_DLL_PUBLIC_DEF const char plugin_release[] = PP_STRINGIZE_I(WIRESHARK_VERSION_MAJOR) "." PP_STRINGIZE_I(WIRESHARK_VERSION_MINOR);
/// Interface for wireshark plugin
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
/// Interface for wireshark plugin
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;
/// Interface for wireshark plugin
WS_DLL_PUBLIC_DEF void plugin_register(void) {
    static proto_plugin plugin_btpu;
    plugin_btpu.register_protoinfo = proto_register_btpu;
    plugin_btpu.register_handoff = proto_reg_handoff_btpu;
    proto_register_plugin(&plugin_btpu);
}
