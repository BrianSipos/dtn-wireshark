#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/dissectors/packet-udp.h>
#include <epan/dissectors/packet-dtls.h>
#include <epan/exceptions.h>
#include <stdio.h>
#include <inttypes.h>
#include "epan/wscbor.h"
#include "packet-udpcl.h"

#if defined(WIRESHARK_HAS_VERSION_H)
#include <ws_version.h>
#else
#include <config.h>
#define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
#define WIRESHARK_VERSION_MINOR VERSION_MINOR
#endif

#if defined(WIRESHARK_HAS_TLS)
#include <epan/dissectors/packet-tls.h>
#include <epan/dissectors/packet-tls-utils.h>
#define DTLS_DISSECTOR_NAME "dtls"
#else
#include <epan/dissectors/packet-ssl.h>
#include <epan/dissectors/packet-ssl-utils.h>
#define DTLS_DISSECTOR_NAME "dtls"
#endif

#if defined(WIRESHARK_NEW_FLAGSPTR)
#define WS_FIELDTYPE int *const
#else
#define WS_FIELDTYPE const int *
#endif

/// Glib logging "domain" name
static const char *LOG_DOMAIN = "udpcl";
/// Protocol column name
static const char *const proto_name_udpcl = "UDPCL";

/// Protocol preferences and defaults
static const guint UDPCL_PORT_NUM = 4556;
static gboolean udpcl_desegment_transfer = TRUE;
static gboolean udpcl_decode_bundle = TRUE;

/// Protocol handles
static int proto_udpcl = -1;

/// Dissect opaque CBOR data
static dissector_handle_t handle_cbor = NULL;
/// Dissector handles
static dissector_handle_t handle_udpcl = NULL;
static dissector_handle_t handle_dtls = NULL;
static dissector_handle_t handle_bpv6 = NULL;
static dissector_handle_t handle_bpv7 = NULL;

/// Dissect extension items
static dissector_table_t table_ext = NULL;

/// Fragment reassembly
static reassembly_table udpcl_reassembly_table;

const unit_name_string units_item_items = { " item", " items" };

static int hf_padding = -1;
static int hf_ext_map = -1;
static int hf_ext_id = -1;

static int hf_ext_xfer = -1;
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

static int hf_ext_rtn = -1;
static int hf_rtn_interval = -1;

static int hf_ext_nodeid = -1;
static int hf_nodeid_str = -1;

static int hf_ext_starttls = -1;

/// Field definitions
static hf_register_info fields[] = {
    {&hf_padding, {"Padding", "udpcl.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_ext_map, {"Extension Map", "udpcl.ext", FT_INT64, BASE_DEC | BASE_UNIT_STRING, &units_item_items, 0x0, NULL, HFILL}},
    {&hf_ext_id, {"Extension ID", "udpcl.ext.id", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},

    {&hf_ext_xfer, {"Transfer", "udpcl.ext.xfer", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_id, {"Transfer ID", "udpcl.ext.xfer.id", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_total_length, {"Transfer Length", "udpcl.ext.xfer.total_len", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_xfer_frag_offset, {"Fragment Offset", "udpcl.ext.xfer.frag_offset", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_xfer_data, {"Fragment Data", "udpcl.ext.xfer.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_ext_rtn, {"Sender Listen", "udpcl.ext.rtn", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_rtn_interval, {"Interval", "udpcl.ext.rtn.interval", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},

    {&hf_ext_nodeid, {"Sender Node ID", "udpcl.ext.nodeid", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_nodeid_str, {"Node ID", "udpcl.ext.nodeid.str", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL}},

    {&hf_ext_starttls, {"Initiate DTLS", "udpcl.ext.starttls", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},

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
static int ett_ext_map = -1;
static int ett_ext_item = -1;
static int ett_ext_xfer = -1;
static int ett_ext_rtn = -1;
static int ett_ext_nodeid = -1;
/// Tree structures
static int *ett[] = {
    &ett_udpcl,
    &ett_ext_map,
    &ett_ext_item,
    &ett_ext_xfer,
    &ett_ext_rtn,
    &ett_ext_nodeid,
    &ett_xferload_fragment,
    &ett_xferload_fragments,
};

static expert_field ei_pad_nonzero = EI_INIT;
static expert_field ei_ext_key_unknown = EI_INIT;
static expert_field ei_transfer_id_size = EI_INIT;
static expert_field ei_fragment_reassemble_size = EI_INIT;
static expert_field ei_fragment_tot_mismatch = EI_INIT;
static expert_field ei_non_bundle_data = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_pad_nonzero, { "udpcl.padding.nonzero", PI_MALFORMED, PI_WARN, "Padding has non-zero octet", EXPFILL}},
    {&ei_ext_key_unknown, {"bpv7.ext_key_unknown", PI_UNDECODED, PI_WARN, "Unknown extension ID", EXPFILL}},
    {&ei_transfer_id_size, {"udpcl.transfer_id_size", PI_REASSEMBLE, PI_ERROR, "Cannot defragment this Transfer ID (wireshark limitation)", EXPFILL}},
    {&ei_fragment_reassemble_size, {"udpcl.fragment_reassemble_size", PI_REASSEMBLE, PI_ERROR, "Cannot defragment this size (wireshark limitation)", EXPFILL}},
    {&ei_fragment_tot_mismatch, {"udpcl.fragment_tot_mismatch", PI_REASSEMBLE, PI_ERROR, "Inconsistent total length between fragments", EXPFILL}},
    {&ei_non_bundle_data, { "udpcl.non_bundle_data", PI_UNDECODED, PI_WARN, "Non-bundle data present", EXPFILL}},
};

/** Dissect pure bundle data.
 * This may contain either BPv6 or BPv7.
 */
static int dissect_bundle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_udpcl) {
    gint sublen = 0;
    proto_item *item_udpcl = proto_tree_get_parent(tree_udpcl);
    proto_item *tree = proto_tree_get_root(tree_udpcl);

    // Peek at first octet
    const guint8 first_octet = tvb_get_guint8(tvb, 0);
    wscbor_chunk_t *first_head = wscbor_chunk_read(wmem_packet_scope(), tvb, &sublen);
    sublen = 0;

    if (first_octet == 0x06) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Bundle v6");
        proto_item_append_text(item_udpcl, ", Bundle v6");
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
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Bundle v7");
        proto_item_append_text(item_udpcl, ", Bundle v7");
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
            TRY {
                sublen = call_dissector(handle_cbor, tvb, pinfo, tree);
            }
            CATCH_ALL {}
            ENDTRY;
        }
    }
    else {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Non-bundle data");
        proto_item_append_text(item_udpcl, ", Non-bundle data");
        expert_add_info(pinfo, item_udpcl, &ei_non_bundle_data);
    }
    return sublen;
}

/// Dissect transfer extension item
static int dissect_transfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_ext_item, void *data _U_) {
    gint offset = 0;
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Transfer");

    proto_item *item_xfer = proto_tree_add_item(tree_ext_item, hf_ext_xfer, tvb, offset, -1, ENC_NA);
    proto_tree *tree_xfer = proto_item_add_subtree(item_xfer, ett_ext_xfer);

    wscbor_chunk_t *chunk_xfer = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_array_size(chunk_xfer, 4, 4);
    if (wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_xfer)) {
        proto_item_set_len(item_xfer, offset);
        return offset;
    }

    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    guint64 *xfer_id = wscbor_require_uint64(wmem_packet_scope(), chunk);
    proto_tree_add_cbor_uint64(tree_xfer, hf_xfer_id, pinfo, tvb, chunk, xfer_id);

    chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    guint64 *xfer_tot_len = wscbor_require_uint64(wmem_packet_scope(), chunk);
    proto_tree_add_cbor_uint64(tree_xfer, hf_xfer_total_length, pinfo, tvb, chunk, xfer_tot_len);

    chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    guint64 *xfer_frag_offset = wscbor_require_uint64(wmem_packet_scope(), chunk);
    proto_tree_add_cbor_uint64(tree_xfer, hf_xfer_frag_offset, pinfo, tvb, chunk, xfer_frag_offset);

    chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    tvbuff_t *xfer_fragment = wscbor_require_bstr(tvb, chunk);
    proto_tree_add_cbor_bstr(tree_xfer, hf_xfer_data, pinfo, tvb, chunk);

    if (udpcl_desegment_transfer
        && xfer_id && xfer_tot_len && xfer_frag_offset && xfer_fragment) {
        proto_tree *tree_ext_map = proto_tree_get_parent_tree(tree_ext_item);
        proto_tree *tree_udpcl = proto_tree_get_parent_tree(tree_ext_map);
        proto_item *item_udpcl = proto_tree_get_parent(tree_udpcl);

        proto_item_append_text(item_udpcl, ", Transfer (ID: %" PRId64 ", Fragment offset: %" PRId64 ")", *xfer_id, *xfer_frag_offset);

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
                    expert_add_info(pinfo, item_xfer, &ei_fragment_tot_mismatch);
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
                col_append_str(pinfo->cinfo, COL_INFO, " (reassembled)");
                dissect_bundle(tvb_bundle, pinfo, tree_udpcl);
            }
            else {
                col_append_str(pinfo->cinfo, COL_INFO, " (fragment)");
            }
        }
    }

    proto_item_set_len(item_xfer, offset);
    return offset;
}

static int dissect_return_accept(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_ext_item, void *data _U_) {
    gint offset = 0;

    proto_item *item_rtn = proto_tree_add_item(tree_ext_item, hf_ext_rtn, tvb, offset, -1, ENC_NA);
    proto_tree *tree_rtn = proto_item_add_subtree(item_rtn, ett_ext_rtn);

    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    guint64 *interval = wscbor_require_uint64(wmem_packet_scope(), chunk);
    proto_tree_add_cbor_uint64(tree_rtn, hf_rtn_interval, pinfo, tvb, chunk, interval);

    proto_tree *tree_ext_map = proto_tree_get_parent_tree(tree_ext_item);
    proto_tree *tree_udpcl = proto_tree_get_parent_tree(tree_ext_map);
    proto_item *item_udpcl = proto_tree_get_parent(tree_udpcl);
    proto_item_append_text(item_udpcl, ", Sender Listen");

    proto_item_set_len(item_rtn, offset);
    return offset;
}

static int dissect_nodeid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_ext_item, void *data _U_) {
    gint offset = 0;

    proto_item *item_nodeid = proto_tree_add_item(tree_ext_item, hf_ext_nodeid, tvb, offset, -1, ENC_NA);
    proto_tree *tree_nodeid = proto_item_add_subtree(item_nodeid, ett_ext_nodeid);

    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_major_type(chunk, CBOR_TYPE_STRING);
    proto_tree_add_cbor_tstr(tree_nodeid, hf_nodeid_str, pinfo, tvb, chunk);

    proto_tree *tree_ext_map = proto_tree_get_parent_tree(tree_ext_item);
    proto_tree *tree_udpcl = proto_tree_get_parent_tree(tree_ext_map);
    proto_item *item_udpcl = proto_tree_get_parent(tree_udpcl);
    proto_item_append_text(item_udpcl, ", Source Node ID");

    proto_item_set_len(item_nodeid, offset);
    return offset;
}

static int dissect_starttls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_ext_item, void *data _U_) {
    gint offset = 0;
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Initiate DTLS");

    wscbor_skip_next_item(wmem_packet_scope(), tvb, &offset);
    // no real value
    proto_tree_add_item(tree_ext_item, hf_ext_starttls, tvb, 0, offset, ENC_NA);

    ssl_starttls_ack(handle_dtls, pinfo, handle_udpcl);
    return offset;
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
    gint offset = 0;
    proto_item *item_udpcl = proto_tree_add_item(tree, proto_udpcl, tvb, 0, -1, ENC_NA);
    proto_tree *tree_udpcl = proto_item_add_subtree(item_udpcl, ett_udpcl);

    while ((guint)offset < buflen) {
        // Peek at first octet
        const guint8 first_octet = tvb_get_guint8(tvb, offset);
        wscbor_chunk_t *first_head = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
        offset -= first_head->data_length;

        if (first_octet == 0x00) {
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Padding");
            proto_item_append_text(item_udpcl, ", Padding");

            proto_item *item_ka = proto_tree_add_item(tree_udpcl, hf_padding, tvb, offset, buflen - offset, ENC_NA);
            for (guint ix = offset + 1; ix < buflen; ++ix) {
                if (tvb_get_guint8(tvb, ix) != 0x0) {
                    expert_add_info(pinfo, item_ka, &ei_pad_nonzero);
                    break;
                }
            }

            offset = buflen;
            proto_item_set_len(item_udpcl, offset);
        }
        else if (first_octet == SSL_ID_HANDSHAKE) {
            g_log(LOG_DOMAIN, G_LOG_LEVEL_WARNING, "Unexpected DTLS in frame %d\n", pinfo->num);
            ssl_starttls_post_ack(handle_dtls, pinfo, handle_udpcl);
        }
        else if (first_head->type_major == CBOR_TYPE_MAP) {
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Extension Map");
            proto_item_append_text(item_udpcl, ", Extension Map");
            offset += 1;

            const gint64 count = first_head->head_value;
            proto_item *item_ext_map = proto_tree_add_cbor_int64(tree_udpcl, hf_ext_map, pinfo, tvb, first_head, &count);
            proto_tree *tree_ext_map = proto_item_add_subtree(item_ext_map, ett_ext_map);

            for (gint64 ix = 0; ix < count; ++ix) {
                wscbor_chunk_t *key_chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
                gint64 *key = wscbor_require_int64(wmem_packet_scope(), key_chunk);
                proto_item *item_ext_item = proto_tree_add_cbor_int64(tree_ext_map, hf_ext_id, pinfo, tvb, key_chunk, key);
                proto_tree *tree_ext_item = proto_item_add_subtree(item_ext_item, ett_ext_item);

                // Skip the item to detect its length for subset TVB
                const guint init_offset = offset;
                wscbor_skip_next_item(wmem_packet_scope(), tvb, &offset);
                if (!key) {
                    continue;
                }
                tvbuff_t *tvb_item = tvb_new_subset_length(tvb, init_offset, offset - init_offset);
                int sublen = dissector_try_uint(table_ext, *key, tvb_item, pinfo, tree_ext_item);
                if (sublen == 0) {
                    expert_add_info(pinfo, item_ext_item, &ei_ext_key_unknown);
                    sublen = call_dissector(handle_cbor, tvb_item, pinfo, tree_ext_item);
                }
            }
            proto_item_set_len(item_ext_map, offset);

            proto_item_set_len(item_udpcl, offset);
        }
        else {
            // Captured data but not part of item_udpcl
            offset += dissect_bundle(tvb, pinfo, tree_udpcl);
            proto_item_set_len(item_udpcl, 0);
        }
    }

    return offset;
}

/// Initialize for a new file load
static void udpcl_init(void) {
}

/// Cleanup after a file
static void udpcl_cleanup(void) {
}

/// Re-initialize after a configuration change
static void udpcl_reinit(void) {
}

/// Overall registration of the protocol
static void proto_register_udpcl(void) {
    proto_udpcl = proto_register_protocol(
        "DTN UDP Convergence Layer", /* name */
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
    table_ext = register_dissector_table("udpcl.ext", "UDPCL Extension", proto_udpcl, FT_UINT16, BASE_DEC);

    module_t *module_udpcl = prefs_register_protocol(proto_udpcl, udpcl_reinit);
    prefs_register_bool_preference(
        module_udpcl,
        "desegment_transfer",
        "Reassemble the segments of each transfer",
        "Whether the UDPCL dissector should combine the fragments "
        "of a transfer into the full bundle being transfered.",
        &udpcl_desegment_transfer
    );
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
    dissector_add_uint_with_preference("udp.port", UDPCL_PORT_NUM, handle_udpcl);

    handle_cbor = find_dissector("cbor");
    handle_dtls = find_dissector_add_dependency(DTLS_DISSECTOR_NAME, proto_udpcl);
    handle_bpv6 = find_dissector_add_dependency("bundle", proto_udpcl);
    handle_bpv7 = find_dissector_add_dependency("bpv7", proto_udpcl);

    /* Packaged extensions */
    {
        dissector_handle_t dis_h = create_dissector_handle(dissect_transfer, proto_udpcl);
        dissector_add_uint("udpcl.ext", UDPCL_EXT_TRANSFER, dis_h);
    }
    {
        dissector_handle_t dis_h = create_dissector_handle(dissect_return_accept, proto_udpcl);
        dissector_add_uint("udpcl.ext", UDPCL_EXT_RETURN_ACCEPT, dis_h);
    }
    {
        dissector_handle_t dis_h = create_dissector_handle(dissect_nodeid, proto_udpcl);
        dissector_add_uint("udpcl.ext", UDPCL_EXT_NODEID, dis_h);
    }
    {
        dissector_handle_t dis_h = create_dissector_handle(dissect_starttls, proto_udpcl);
        dissector_add_uint("udpcl.ext", UDPCL_EXT_STARTTLS, dis_h);
    }

    udpcl_reinit();
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
