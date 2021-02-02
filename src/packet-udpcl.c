#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/tvbuff-int.h>
#include <epan/dissectors/packet-tcp.h>
#include <stdio.h>
#include <inttypes.h>
#include "bp_cbor.h"
#include "packet-udpcl.h"

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

/// Glib logging "domain" name
static const char *LOG_DOMAIN = "udpcl";
/// Protocol column name
const char *const proto_name_udpcl = "UDPCL";

/// Protocol preferences and defaults
static const guint UDPCL_PORT_NUM = 4556;
static gboolean udpcl_decode_bundle = TRUE;

/// Protocol handles
static int proto_udpcl = -1;

/// Dissector handles
static dissector_handle_t handle_udpcl = NULL;
static dissector_handle_t handle_bpv6 = NULL;
static dissector_handle_t handle_bpv7 = NULL;

/// Dissect opaque CBOR parameters/results
static dissector_table_t dissect_media = NULL;

/// Fragment reassembly
static reassembly_table udpcl_reassembly_table;

static int hf_udpcl = -1;
static int hf_padding = -1;
static int hf_ctrl = -1;
static int hf_xfer_id = -1;
static int hf_xfer_frag_offset = -1;
static int hf_xfer_total_length = -1;
static int hf_xfer_data = -1;

static int hf_xferload_fragments = -1;
static int hf_xferload_fragment = -1;
static int hf_xferload_fragment_overlap = -1;
static int hf_xferload_fragment_overlap_conflicts = -1;
static int hf_xferload_fragment_multiple_tails = -1;
static int hf_xferload_fragment_too_long_fragment = -1;
static int hf_xferload_fragment_error = -1;
static int hf_xferload_fragment_count = -1;
static int hf_xferload_reassembled_in = -1;
static int hf_xferload_reassembled_length = -1;
static int hf_xferload_reassembled_data = -1;
static gint ett_xferload_fragment = -1;
static gint ett_xferload_fragments = -1;

/// Field definitions
static hf_register_info fields[] = {
    {&hf_udpcl, {"UDP Convergence Layer", "udpcl", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_padding, {"Padding", "udpcl.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_ctrl, {"Control", "udpcl.control", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_id, {"Transfer ID", "udpcl.xfer.id", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_frag_offset, {"Fragment Offset", "udpcl.xfer.frag_offset", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_xfer_total_length, {"Transfer Length", "udpcl.xfer.total_len", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_xfer_data, {"Transfer Data", "udpcl.xfer.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_xferload_fragments,
        {"Transfer fragments", "udpcl.xferload.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment,
        {"Transfer fragment", "udpcl.xferload.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_overlap,
        {"Transfer fragment overlap", "udpcl.xferload.fragment.overlap",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_overlap_conflicts,
        {"Transfer fragment overlapping with conflicting data",
        "udpcl.xferload.fragment.overlap.conflicts",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_multiple_tails,
        {"Message has multiple tail fragments",
        "udpcl.xferload.fragment.multiple_tails",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_too_long_fragment,
        {"Transfer fragment too long", "udpcl.xferload.fragment.too_long_fragment",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_error,
        {"Transfer defragmentation error", "udpcl.xferload.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_fragment_count,
        {"Transfer fragment count", "udpcl.xferload.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_reassembled_in,
        {"Reassembled in", "udpcl.xferload.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_reassembled_length,
        {"Reassembled length", "udpcl.xferload.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    {&hf_xferload_reassembled_data,
        {"Reassembled data", "udpcl.xferload.reassembled.data",
        FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
};

static const fragment_items xferload_frag_items = {
    /* Fragment subtrees */
    &ett_xferload_fragment,
    &ett_xferload_fragments,
    /* Fragment fields */
    &hf_xferload_fragments,
    &hf_xferload_fragment,
    &hf_xferload_fragment_overlap,
    &hf_xferload_fragment_overlap_conflicts,
    &hf_xferload_fragment_multiple_tails,
    &hf_xferload_fragment_too_long_fragment,
    &hf_xferload_fragment_error,
    &hf_xferload_fragment_count,
    /* Reassembled in field */
    &hf_xferload_reassembled_in,
    &hf_xferload_reassembled_length,
    &hf_xferload_reassembled_data,
    /* Tag */
    "Transfer fragments"
};

static int ett_udpcl = -1;
static int ett_ctrl = -1;
/// Tree structures
static int *ett[] = {
    &ett_udpcl,
    &ett_ctrl,
    &ett_xferload_fragment,
    &ett_xferload_fragments,
};

static expert_field ei_pad_nonzero = EI_INIT;
static expert_field ei_pad_size = EI_INIT;
static expert_field ei_transfer_id_size = EI_INIT;
static expert_field ei_fragment_reassemble_size = EI_INIT;
static expert_field ei_fragment_tot_mismatch = EI_INIT;
static expert_field ei_non_bundle_data = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_pad_nonzero, { "udpcl.padding.nonzero", PI_MALFORMED, PI_WARN, "Padding has non-zero octet", EXPFILL}},
    {&ei_pad_size, { "udpcl.padding.size", PI_MALFORMED, PI_WARN, "Padding has size other than 4", EXPFILL}},
    {&ei_transfer_id_size, {"udpcl.transfer_id_size", PI_REASSEMBLE, PI_ERROR, "Cannot defragment this Transfer ID (wireshark limitation)", EXPFILL}},
    {&ei_fragment_reassemble_size, {"udpcl.fragment_reassemble_size", PI_REASSEMBLE, PI_ERROR, "Cannot defragment this size (wireshark limitation)", EXPFILL}},
    {&ei_fragment_tot_mismatch, {"udpcl.fragment_tot_mismatch", PI_REASSEMBLE, PI_ERROR, "Inconsistent total length between fragments", EXPFILL}},
    {&ei_non_bundle_data, { "udpcl.non_bundle_data", PI_UNDECODED, PI_WARN, "Non-bundle data present", EXPFILL}},
};

/** Dissect pure bundle data.
 * This may contain either BPv6 or BPv7.
 */
static int dissect_bundle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    gint sublen = 0;
    const guint8 first_octet = tvb_get_guint8(tvb, 0);
    bp_cbor_chunk_t *first_head = bp_scan_cbor_chunk(tvb, 0);
    if (first_octet == 0x06) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Bundle v6]");
        if (udpcl_decode_bundle) {
            if (handle_bpv6) {
                sublen = call_dissector(
                    handle_bpv6,
                    tvb,
                    pinfo,
                    tree
                );
            }
        }
    }
    else if (first_head->type_major == CBOR_TYPE_ARRAY) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Bundle v7]");
        if (udpcl_decode_bundle) {
            if (handle_bpv7) {
                sublen = call_dissector(
                    handle_bpv7,
                    tvb,
                    pinfo,
                    tree
                );
            }
        }
        if (sublen == 0) {
            if (dissect_media) {
                sublen = dissector_try_string(
                    dissect_media,
                    "application/cbor",
                    tvb,
                    pinfo,
                    tree,
                    NULL
                );
            }
        }
    }
    else {
        expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_non_bundle_data);
    }
    bp_cbor_chunk_delete(first_head);
    return sublen;
}

/// Top-level protocol dissector
static int dissect_udpcl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    {
        const gchar *proto_name = col_get_text(pinfo->cinfo, COL_PROTOCOL);
        if (g_strcmp0(proto_name, proto_name_udpcl) != 0) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_udpcl);
            col_clear(pinfo->cinfo, COL_INFO);
        }
    }

    const guint buflen = tvb_captured_length(tvb);
    guint caplen = 0;
    proto_item *item_udpcl = proto_tree_add_item(tree, hf_udpcl, tvb, 0, 0, ENC_NA);
    proto_tree *tree_udpcl = proto_item_add_subtree(item_udpcl, ett_udpcl);

    col_append_str(pinfo->cinfo, COL_INFO, "UDPCL");

    const guint8 first_octet = tvb_get_guint8(tvb, 0);
    bp_cbor_chunk_t *first_head = bp_scan_cbor_chunk(tvb, 0);
    if (first_octet == 0x00) {
        proto_item_append_text(item_udpcl, ", Padding");

        proto_item *item_pad = proto_tree_add_item(tree_udpcl, hf_padding, tvb, 0, buflen, ENC_NA);
        if (buflen != 4) {
            expert_add_info(pinfo, item_pad, &ei_pad_size);
        }
        for (guint ix = 1; ix < buflen; ++ix) {
            if (tvb_get_guint8(tvb, ix) != 0x0) {
                expert_add_info(pinfo, item_pad, &ei_pad_nonzero);
                break;
            }
        }
        caplen = buflen;
        proto_item_set_len(item_udpcl, caplen);
    }
    else if (first_head->type_major == CBOR_TYPE_MAP) {
        proto_item_append_text(item_udpcl, ", Control Data");
        gint offset = 1;

        proto_item *item_ctrl = proto_tree_add_item(tree_udpcl, hf_ctrl, tvb, 0, 0, ENC_NA);
        proto_tree *tree_ctrl = proto_item_add_subtree(item_ctrl, ett_ctrl);

        guint64 *xfer_id = NULL;
        guint64 *xfer_frag_offset = NULL;
        guint64 *xfer_tot_len = NULL;
        tvbuff_t *xfer_fragment = NULL;

        const gint64 count = 2 * first_head->head_value;
        for (gint64 ix = 0; ix < count; ++ix) {
            bp_cbor_chunk_t *key_chunk = bp_scan_cbor_chunk(tvb, offset);
            offset += key_chunk->data_length;
            gint64 *key = cbor_require_int64(key_chunk);
            bp_cbor_chunk_delete(key_chunk);

            switch (*key) {
                case UDPCL_CTRL_XFER_ID: {
                    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, offset);
                    offset += chunk->data_length;
                    xfer_id = cbor_require_uint64(chunk);
                    proto_tree_add_cbor_uint64(tree_ctrl, hf_xfer_id, pinfo, tvb, chunk, xfer_id);
                    bp_cbor_chunk_delete(chunk);
                    break;
                }
                case UDPCL_CTRL_XFER_LEN: {
                    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, offset);
                    offset += chunk->data_length;
                    xfer_tot_len = cbor_require_uint64(chunk);
                    proto_tree_add_cbor_uint64(tree_ctrl, hf_xfer_total_length, pinfo, tvb, chunk, xfer_tot_len);
                    bp_cbor_chunk_delete(chunk);
                    break;
                }
                case UDPCL_CTRL_XFER_FRAG_OFFSET: {
                    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, offset);
                    offset += chunk->data_length;
                    xfer_frag_offset = cbor_require_uint64(chunk);
                    proto_tree_add_cbor_uint64(tree_ctrl, hf_xfer_frag_offset, pinfo, tvb, chunk, xfer_frag_offset);
                    bp_cbor_chunk_delete(chunk);
                    break;
                }
                case UDPCL_CTRL_XFER_FRAG_DATA: {
                    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, offset);
                    offset += chunk->data_length;
                    xfer_fragment = cbor_require_string(tvb, chunk);
//                    proto_tree_add_cbor_string(tree_ctrl, hf_xfer_data, pinfo, xfer_fragment, chunk);
                    bp_cbor_chunk_delete(chunk);
                    break;
                }
                default:
                    cbor_skip_next_item(tvb, &offset);
                    break;
            }
            bp_cbor_require_delete(key);
        }
        proto_item_set_len(item_ctrl, offset);

        caplen = offset;
        proto_item_set_len(item_udpcl, caplen);

        if (xfer_id && xfer_tot_len && xfer_frag_offset) {
            proto_item_append_text(item_udpcl, ", Transfer ID: %" PRId64 ", Fragment offset: %" PRId64, *xfer_id, *xfer_frag_offset);

            const guint32 corr_id = *xfer_id;
            const gboolean overflow_corr_id = (
                (corr_id != *xfer_id)
            );
            if (overflow_corr_id) {
                expert_add_info(pinfo, item_udpcl, &ei_transfer_id_size);
            }

            const guint32 frag_offset = *(xfer_frag_offset);
            const guint32 total_len = *(xfer_tot_len);
            const gboolean overflow_frag_size = (
                (frag_offset != *(xfer_frag_offset))
                || (total_len != *(xfer_tot_len))
            );
            if (overflow_frag_size) {
                expert_add_info(pinfo, item_udpcl, &ei_fragment_reassemble_size);
            }

            if (!overflow_corr_id && !overflow_frag_size) {
                fragment_head *payload_frag_msg = fragment_add_check(
                    &udpcl_reassembly_table,
                    xfer_fragment, 0,
                    pinfo, corr_id, NULL,
                    frag_offset,
                    tvb_captured_length(xfer_fragment),
                    TRUE
                );
                const guint32 old_total_len = fragment_get_tot_len(
                    &udpcl_reassembly_table,
                    pinfo, corr_id, NULL
                );
                if (old_total_len > 0) {
                    if (total_len != old_total_len) {
                        expert_add_info(pinfo, item_ctrl, &ei_fragment_tot_mismatch);
                    }
                }
                else {
                    fragment_set_tot_len(
                        &udpcl_reassembly_table,
                        pinfo, corr_id, NULL,
                        total_len
                    );
                }
                tvbuff_t *tvb_bundle = process_reassembled_data(
                    tvb, 0, pinfo,
                    "Reassembled Transfer",
                    payload_frag_msg,
                    &xferload_frag_items,
                    NULL,
                    tree_udpcl
                );
                if (tvb_bundle) {
                    dissect_bundle(tvb_bundle, pinfo, tree);
                }
            }
        }
    }
    else {
        proto_item_append_text(item_udpcl, ", Bundle Data");
        // Captured data but not part of item_udpcl
        caplen = dissect_bundle(tvb, pinfo, tree);
    }
    bp_cbor_chunk_delete(first_head);

    return caplen;
}

/// Initialize for a new file load
static void udpcl_init(void) {
}

/// Cleanup after a file
static void udpcl_cleanup(void) {
}

/// Re-initialize after a configuration change
static void reinit_udpcl(void) {
}

/// Overall registration of the protocol
static void proto_register_udpcl(void) {
    g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "proto_register_udpcl()\n");
    proto_udpcl = proto_register_protocol(
        "DTN UDP Convergence Layer Protocol", /* name */
        "UDPCL", /* short name */
        "udpcl" /* abbrev */
    );
    register_init_routine(&udpcl_init);
    register_cleanup_routine(&udpcl_cleanup);

    proto_register_field_array(proto_udpcl, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_udpcl);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

    handle_udpcl = register_dissector("udpcl", dissect_udpcl, proto_udpcl);

    module_t *module_udpcl = prefs_register_protocol(proto_udpcl, reinit_udpcl);
    prefs_register_bool_preference(
        module_udpcl,
        "decode_bundle",
        "Decode bundle data",
        "If enabled, the bundle will be decoded as BPv7 content. "
        "Otherwise, it is assumed to be plain CBOR.",
        &udpcl_decode_bundle
    );

    reassembly_table_register(
        &udpcl_reassembly_table,
        &addresses_ports_reassembly_table_functions
    );
}

static void proto_reg_handoff_udpcl(void) {
    g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "proto_reg_handoff_udpcl()\n");
    dissector_add_uint_with_preference("udp.port", UDPCL_PORT_NUM, handle_udpcl);

    dissect_media = find_dissector_table("media_type");
    handle_bpv7 = find_dissector_add_dependency("bpv7", proto_udpcl);

    reinit_udpcl();
}

#define PP_STRINGIZE_I(text) #text

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
    static proto_plugin plugin_udpcl;
    plugin_udpcl.register_protoinfo = proto_register_udpcl;
    plugin_udpcl.register_handoff = proto_reg_handoff_udpcl;
    proto_register_plugin(&plugin_udpcl);
}
