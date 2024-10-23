#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/dissectors/packet-udp.h>
#include <epan/dissectors/packet-dtls.h>
#include <epan/exceptions.h>
#include <wsutil/wmem/wmem_map.h>
#include <wsutil/wmem/wmem_tree.h>
#include <wsutil/wmem/wmem_interval_tree.h>
#include <stdio.h>
#include <inttypes.h>
#include "epan/wscbor.h"

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
static const unsigned UDPCL_PORT_NUM = 4556;
static bool udpcl_desegment_transfer = TRUE;
static bool udpcl_analyze_sequence = TRUE;
static bool udpcl_decode_bundle = TRUE;

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

static int hf_ext_sender_listen = -1;
static int hf_sender_listen_interval = -1;

static int hf_ext_nodeid = -1;
static int hf_nodeid_str = -1;

static int hf_ext_starttls = -1;

static int hf_ext_peer_probe = -1;
static int hf_probe_nonce = -1;
static int hf_probe_seqno = -1;
static int hf_probe_delay = -1;
static int hf_probe_confirm_ref = -1;

static int hf_ext_peer_confirm = -1;
static int hf_confirm_nonce = -1;
static int hf_confirm_offset = -1;
static int hf_confirm_length = -1;
static int hf_confirm_gap = -1;
static int hf_confirm_probe_ref = -1;
static int hf_confirm_probe_tlp = -1;

static int hf_ext_ecn_counts = -1;
static int hf_ecn_ect0 = -1;
static int hf_ecn_ect1 = -1;
static int hf_ecn_ce = -1;

/// Field definitions
static hf_register_info fields[] = {
    {&hf_padding, {"Padding, Length", "udpcl.padding", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_ext_map, {"Extension Map, Count", "udpcl.ext", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_ext_id, {"Extension ID", "udpcl.ext.id", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},

    {&hf_ext_xfer, {"Transfer", "udpcl.ext.xfer", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_id, {"Transfer ID", "udpcl.ext.xfer.id", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_xfer_total_length, {"Transfer Length", "udpcl.ext.xfer.total_len", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_xfer_frag_offset, {"Fragment Offset", "udpcl.ext.xfer.frag_offset", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_xfer_data, {"Fragment Data", "udpcl.ext.xfer.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_ext_sender_listen, {"Sender Listen", "udpcl.ext.rtn", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_sender_listen_interval, {"Interval", "udpcl.ext.rtn.interval", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},

    {&hf_ext_nodeid, {"Sender Node ID", "udpcl.ext.nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_nodeid_str, {"Node ID", "udpcl.ext.nodeid.str", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_ext_starttls, {"DTLS Initiation", "udpcl.ext.starttls", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_ext_peer_probe, {"Peer Probe", "udpcl.ext.peer_probe", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_probe_nonce, {"Nonce", "udpcl.ext.peer_probe.nonce", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_probe_seqno, {"Sequence Number", "udpcl.ext.peer_probe.seqno", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_probe_delay, {"Confirmation Delay", "udpcl.ext.peer_probe.delay", FT_UINT64, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0, NULL, HFILL}},
    {&hf_probe_confirm_ref, {"Confirmation in frame", "udpcl.ext.peer_probe.confirm_rev", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0, NULL, HFILL}},

    {&hf_ext_peer_confirm, {"Peer Confirmation", "udpcl.ext.peer_confirm", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_confirm_nonce, {"Nonce", "udpcl.ext.peer_confirm.nonce", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_confirm_offset, {"Offset", "udpcl.ext.peer_confirm.offset", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_confirm_length, {"Length", "udpcl.ext.peer_confirm.length", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_confirm_gap, {"Gap Length", "udpcl.ext.peer_confirm.gap_length", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_confirm_probe_ref, {"Probe in frame", "udpcl.ext.peer_confirm.probe_rev", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0, NULL, HFILL}},
    {&hf_confirm_probe_tlp, {"Time since latest Probe", "udpcl.ext.peer_confirm.time_last_probe", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_ext_ecn_counts, {"ECN Counts", "udpcl.ext.ecn_counts", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_ecn_ect0, {"ECT(0) Count", "udpcl.ext.ecn_counts.ect0", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_ecn_ect1, {"ECT(1) Count", "udpcl.ext.ecn_counts.ect1", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_ecn_ce, {"CE Count", "udpcl.ext.ecn_counts.ce", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},

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
static int ett_ext_sender_listen = -1;
static int ett_ext_nodeid = -1;
static int ett_ext_ecn_counts = -1;
static int ett_ext_peer_probe = -1;
static int ett_ext_peer_confirm = -1;
static int ett_confirm_intvl = -1;
/// Tree structures
static int *ett[] = {
    &ett_udpcl,
    &ett_ext_map,
    &ett_ext_item,
    &ett_ext_xfer,
    &ett_ext_sender_listen,
    &ett_ext_nodeid,
    &ett_ext_ecn_counts,
    &ett_ext_peer_probe,
    &ett_ext_peer_confirm,
    &ett_confirm_intvl,
    &ett_xferload_fragment,
    &ett_xferload_fragments,
};

static expert_field ei_pad_nonzero = EI_INIT;
static expert_field ei_ext_key_invalid = EI_INIT;
static expert_field ei_ext_key_unknown = EI_INIT;
static expert_field ei_transfer_id_size = EI_INIT;
static expert_field ei_fragment_reassemble_size = EI_INIT;
static expert_field ei_fragment_tot_mismatch = EI_INIT;
static expert_field ei_non_bundle_data = EI_INIT;
static expert_field ei_probe_no_confirm = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_pad_nonzero, { "udpcl.padding.nonzero", PI_MALFORMED, PI_WARN, "Padding has non-zero-value octet", EXPFILL}},
    {&ei_ext_key_invalid, {"udpcl.ext_key_invalid", PI_PROTOCOL, PI_WARN, "Extension ID is not in the valid range", EXPFILL}},
    {&ei_ext_key_unknown, {"udpcl.ext_key_unknown", PI_UNDECODED, PI_WARN, "Extension ID is unknown", EXPFILL}},
    {&ei_transfer_id_size, {"udpcl.transfer_id_size", PI_REASSEMBLE, PI_ERROR, "Cannot defragment this Transfer ID (wireshark limitation)", EXPFILL}},
    {&ei_fragment_reassemble_size, {"udpcl.fragment_reassemble_size", PI_REASSEMBLE, PI_ERROR, "Cannot defragment this size (wireshark limitation)", EXPFILL}},
    {&ei_fragment_tot_mismatch, {"udpcl.fragment_tot_mismatch", PI_REASSEMBLE, PI_ERROR, "Inconsistent total length between fragments", EXPFILL}},
    {&ei_non_bundle_data, { "udpcl.non_bundle_data", PI_UNDECODED, PI_WARN, "Non-bundle data present", EXPFILL}},
    {&ei_probe_no_confirm, { "udpcl.peer_probe_no_confirm", PI_PROTOCOL, PI_CHAT, "Peer Probe has no associated Peer Confirmation", EXPFILL}},
};

typedef struct {
    /// Original frame number
    uint32_t frame_num;
    /// Timestamp on the frame
    nstime_t frame_time;
} udpcl_frameinfo_t;

typedef struct {
    /// Map from uint64* nonce to wmem_tree_t* mapping sequence-number to udpcl_frameinfo_t*
    wmem_map_t *peer_probe;
    /// Map from uint64* nonce to wmem_itree_t* mapping sequence-number to udpcl_frameinfo_t*
    wmem_map_t *peer_confirm;
} udpcl_convo_t;

/** Dissect pure bundle data.
 * This may contain either BPv6 or BPv7.
 */
static int dissect_bundle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_udpcl) {
    gint sublen = 0;
    proto_item *item_udpcl = proto_tree_get_parent(tree_udpcl);
    proto_item *tree = proto_tree_get_root(tree_udpcl);

    // Peek at first octet
    const guint8 first_octet = tvb_get_uint8(tvb, 0);
    wscbor_chunk_t *first_head = wscbor_chunk_read(pinfo->pool, tvb, &sublen);
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

    proto_item *item_ext = proto_tree_add_item(tree_ext_item, hf_ext_xfer, tvb, offset, -1, ENC_NA);
    proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_ext_xfer);

    wscbor_chunk_t *chunk_xfer = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array_size(chunk_xfer, 2, 4);
    if (wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_xfer)) {
        proto_item_set_len(item_ext, offset);
        return 0;
    }

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *xfer_id = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree_ext, hf_xfer_id, pinfo, tvb, chunk, xfer_id);

    uint64_t *xfer_tot_len = NULL;
    uint64_t *xfer_frag_offset = NULL;
    if (chunk->head_value == 4) {
        chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        xfer_tot_len = wscbor_require_uint64(pinfo->pool, chunk);
        proto_tree_add_cbor_uint64(tree_ext, hf_xfer_total_length, pinfo, tvb, chunk, xfer_tot_len);

        chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        xfer_frag_offset = wscbor_require_uint64(pinfo->pool, chunk);
        proto_tree_add_cbor_uint64(tree_ext, hf_xfer_frag_offset, pinfo, tvb, chunk, xfer_frag_offset);
    }

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    tvbuff_t *xfer_fragment = wscbor_require_bstr(pinfo->pool, chunk);
    proto_tree_add_cbor_bstr(tree_ext, hf_xfer_data, pinfo, tvb, chunk);

    if (udpcl_desegment_transfer
        && xfer_id && xfer_fragment) {
        proto_tree *tree_ext_map = proto_tree_get_parent_tree(tree_ext_item);
        proto_tree *tree_udpcl = proto_tree_get_parent_tree(tree_ext_map);
        proto_item *item_udpcl = proto_tree_get_parent(tree_udpcl);

        proto_item_append_text(item_udpcl, ", Transfer (ID: %" PRId64 ", Fragment offset: %" PRId64 ")", *xfer_id, *xfer_frag_offset);

        const uint32_t corr_id = *xfer_id;
        const bool overflow_corr_id = (
            (corr_id != *xfer_id)
        );
        if (overflow_corr_id) {
            expert_add_info(pinfo, item_udpcl, &ei_transfer_id_size);
        }

        const uint32_t frag_offset = xfer_frag_offset ? *xfer_frag_offset : 0;
        const uint32_t total_len = xfer_tot_len ? *xfer_tot_len : tvb_reported_length(xfer_fragment);

        bool overflow_frag_size = FALSE;
        if (xfer_frag_offset && xfer_tot_len) {
            overflow_frag_size = (
                (frag_offset != *(xfer_frag_offset))
                || (total_len != *(xfer_tot_len))
            );
            if (overflow_frag_size) {
                expert_add_info(pinfo, item_udpcl, &ei_fragment_reassemble_size);
            }
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
            const uint32_t old_total_len = fragment_get_tot_len(
                &udpcl_reassembly_table,
                pinfo, corr_id, NULL
            );
            if (old_total_len > 0) {
                if (total_len != old_total_len) {
                    expert_add_info(pinfo, item_ext, &ei_fragment_tot_mismatch);
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

    proto_item_set_len(item_ext, offset);
    return offset;
}

static int dissect_sender_listen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_ext_item, void *data _U_) {
    gint offset = 0;

    proto_item *item_ext = proto_tree_add_item(tree_ext_item, hf_ext_sender_listen, tvb, offset, -1, ENC_NA);
    proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_ext_sender_listen);

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *interval = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree_ext, hf_sender_listen_interval, pinfo, tvb, chunk, interval);

    proto_tree *tree_ext_map = proto_tree_get_parent_tree(tree_ext_item);
    proto_tree *tree_udpcl = proto_tree_get_parent_tree(tree_ext_map);
    proto_item *item_udpcl = proto_tree_get_parent(tree_udpcl);
    proto_item_append_text(item_udpcl, ", Sender Listen");

    proto_item_set_len(item_ext, offset);
    return offset;
}

static int dissect_nodeid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_ext_item, void *data _U_) {
    gint offset = 0;

    proto_item *item_ext = proto_tree_add_item(tree_ext_item, hf_ext_nodeid, tvb, offset, -1, ENC_NA);
    proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_ext_nodeid);

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_major_type(chunk, CBOR_TYPE_STRING);
    proto_tree_add_cbor_tstr(tree_ext, hf_nodeid_str, pinfo, tvb, chunk);

    proto_tree *tree_ext_map = proto_tree_get_parent_tree(tree_ext_item);
    proto_tree *tree_udpcl = proto_tree_get_parent_tree(tree_ext_map);
    proto_item *item_udpcl = proto_tree_get_parent(tree_udpcl);
    proto_item_append_text(item_udpcl, ", Source Node ID");

    proto_item_set_len(item_ext, offset);
    return offset;
}

static int dissect_starttls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_ext_item, void *data _U_) {
    gint offset = 0;

    wscbor_skip_next_item(pinfo->pool, tvb, &offset);
    // no real value
    proto_tree_add_item(tree_ext_item, hf_ext_starttls, tvb, 0, offset, ENC_NA);

    ssl_starttls_ack(handle_dtls, pinfo, handle_udpcl);
    return offset;
}

static int dissect_peer_probe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_ext_item, void *data) {
    udpcl_convo_t *clconvo = data;
    gint offset = 0;

    proto_item *item_ext = proto_tree_add_item(tree_ext_item, hf_ext_peer_probe, tvb, offset, -1, ENC_NA);
    proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_ext_peer_probe);

    wscbor_chunk_t *chunk_ext = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array_size(chunk_ext, 3, 3);
    if (wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_ext)) {
        proto_item_set_len(item_ext, offset);
        return 0;
    }

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *nonce = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree_ext, hf_probe_nonce, pinfo, tvb, chunk, nonce);

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *seqno = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree_ext, hf_probe_seqno, pinfo, tvb, chunk, seqno);

    if (udpcl_analyze_sequence && nonce && seqno) {
        wmem_tree_t *probe_nums = wmem_map_lookup(clconvo->peer_probe, nonce);
        if (!probe_nums) {
            uint64_t *key = wmem_new0(wmem_file_scope(), uint64_t);
            *key = *nonce;
            probe_nums = wmem_tree_new(wmem_file_scope());
            wmem_map_insert(clconvo->peer_probe, key, probe_nums);
        }
        if (!wmem_tree_contains32(probe_nums, *seqno)) {
            udpcl_frameinfo_t *uinfo = wmem_new0(wmem_file_scope(), udpcl_frameinfo_t);
            uinfo->frame_num = pinfo->num;
            uinfo->frame_time = pinfo->abs_ts;
            wmem_tree_insert32(probe_nums, *seqno, uinfo);
        }

        wmem_itree_t *confirm_nums = wmem_map_lookup(clconvo->peer_confirm, nonce);
        bool confirm_found = FALSE;
        if (confirm_nums) {
            wmem_list_t *intvls = wmem_itree_find_intervals(confirm_nums, pinfo->pool, *seqno, *seqno);
            for (wmem_list_frame_t *it = wmem_list_head(intvls); it;
                    it = wmem_list_frame_next(it)) {
                udpcl_frameinfo_t *uinfo = wmem_list_frame_data(it);
                confirm_found = TRUE;

                proto_item_set_generated(
                    proto_tree_add_uint(tree_ext, hf_probe_confirm_ref, NULL, 0, 0, uinfo->frame_num)
                );
            }
            wmem_destroy_list(intvls);
        }
        if (!confirm_found) {
            expert_add_info(pinfo, item_ext, &ei_probe_no_confirm);
        }
    }

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *delay = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree_ext, hf_probe_delay, pinfo, tvb, chunk, delay);

    proto_item_set_len(item_ext, offset);
    return offset;
}

static int dissect_peer_confirm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_ext_item, void *data) {
    udpcl_convo_t *clconvo = data;
    gint offset = 0;

    proto_item *item_ext = proto_tree_add_item(tree_ext_item, hf_ext_peer_confirm, tvb, offset, -1, ENC_NA);
    proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_ext_peer_confirm);

    wscbor_chunk_t *chunk_ext = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array_size(chunk_ext, 2, 2);
    if (wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_ext)) {
        proto_item_set_len(item_ext, offset);
        return 0;
    }

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *nonce = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree_ext, hf_confirm_nonce, pinfo, tvb, chunk, nonce);

    wmem_itree_t *confirm_nums = NULL;
    wmem_tree_t *probe_nums = NULL;
    if (udpcl_analyze_sequence && nonce) {
        confirm_nums = wmem_map_lookup(clconvo->peer_confirm, nonce);
        if (!confirm_nums) {
            uint64_t *key = wmem_new0(wmem_file_scope(), uint64_t);
            *key = *nonce;
            confirm_nums = wmem_itree_new(wmem_file_scope());
            wmem_map_insert(clconvo->peer_confirm, key, confirm_nums);
        }

        probe_nums = wmem_map_lookup(clconvo->peer_probe, nonce);
    }

    wscbor_chunk_t *chunk_seen = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array(chunk_seen);
    if (wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_seen)) {
        proto_item_set_len(item_ext, offset);
        return 0;
    }

    uint64_t last_intvl = 0;
    /// Time of latest probe acknowledged by this confirmation
    nstime_t last_probe = NSTIME_INIT_UNSET;
    for (uint64_t ix = 0; ix < chunk_seen->head_value; ix += 2) {
        const unsigned init_offset = offset;

        // decode data first to spot a gap
        wscbor_chunk_t *chunk_offset = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        uint64_t *intvl_offset = wscbor_require_uint64(pinfo->pool, chunk_offset);
        wscbor_chunk_t *chunk_length = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        uint64_t *intvl_length = wscbor_require_uint64(pinfo->pool, chunk_length);

        if (intvl_offset && (*intvl_offset > 0)) {
            PROTO_ITEM_SET_GENERATED(
                proto_tree_add_uint64(tree_ext, hf_confirm_gap, tvb, 0, 0, *intvl_offset)
            );
        }

        proto_item *item_intvl;
        proto_tree *tree_intvl = proto_tree_add_subtree(tree_ext, tvb, init_offset, offset - init_offset, ett_confirm_intvl, &item_intvl, "Seen Interval");
        proto_tree_add_cbor_uint64(tree_intvl, hf_confirm_offset, pinfo, tvb, chunk_offset, intvl_offset);
        proto_tree_add_cbor_uint64(tree_intvl, hf_confirm_length, pinfo, tvb, chunk_length, intvl_length);

        if (intvl_offset && intvl_length) {
            const uint64_t intvl_fst = last_intvl + *intvl_offset;
            const uint64_t intvl_lst = intvl_fst + *intvl_length - 1;
            last_intvl = intvl_lst + 1;
            proto_item_append_text(item_intvl,
                ": %" PRIu64 "-%" PRIu64 " (%" PRIu64 " items)",
                intvl_fst, intvl_lst, *intvl_length
            );

            if (confirm_nums) {
                wmem_list_t *intvls = wmem_itree_find_intervals(confirm_nums, pinfo->pool, intvl_fst, intvl_lst);
                if (wmem_list_count(intvls) == 0) {
                    udpcl_frameinfo_t *uinfo = wmem_new0(wmem_file_scope(), udpcl_frameinfo_t);
                    uinfo->frame_num = pinfo->num;
                    uinfo->frame_time = pinfo->abs_ts;
                    wmem_itree_insert(confirm_nums, intvl_fst, intvl_lst, uinfo);
                }
                wmem_destroy_list(intvls);
            }
            if (probe_nums) {
                for (uint64_t seqno = intvl_fst; seqno <= intvl_lst; ++seqno) {
                    udpcl_frameinfo_t *uinfo = wmem_tree_lookup32(probe_nums, seqno);
                    if (uinfo) {
                        if (nstime_is_unset(&last_probe)
                                || (nstime_cmp(&last_probe, &(uinfo->frame_time)) > 0)) {
                            nstime_copy(&last_probe, &(uinfo->frame_time));
                        }
                        proto_item_set_generated(
                            proto_tree_add_uint(tree_intvl, hf_confirm_probe_ref, NULL, 0, 0, uinfo->frame_num)
                        );
                    }
                }
            }
        }
    }

    if (!nstime_is_unset(&last_probe)) {
        nstime_t delta;
        nstime_delta(&delta, &(pinfo->abs_ts), &last_probe);
        proto_item_set_generated(
            proto_tree_add_time(tree_ext, hf_confirm_probe_tlp, NULL, 0, 0, &delta)
        );
    }

    proto_item_set_len(item_ext, offset);
    return offset;
}

static int dissect_ecn_counts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_ext_item, void *data _U_) {
    gint offset = 0;

    proto_item *item_ext = proto_tree_add_item(tree_ext_item, hf_ext_ecn_counts, tvb, offset, -1, ENC_NA);
    proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_ext_ecn_counts);

    wscbor_chunk_t *chunk_ext = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array_size(chunk_ext, 3, 3);
    if (wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_ext)) {
        proto_item_set_len(item_ext, offset);
        return 0;
    }

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *ect0 = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree_ext, hf_ecn_ect0, pinfo, tvb, chunk, ect0);

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *ect1 = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree_ext, hf_ecn_ect1, pinfo, tvb, chunk, ect1);

    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *ce = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree_ext, hf_ecn_ce, pinfo, tvb, chunk, ce);

    proto_item_set_len(item_ext, offset);
    return offset;
}

static int dissect_extmap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_udpcl, wscbor_chunk_t *first_head) {
    gint offset = first_head->start;
    const gint init_offset = offset;

    // Ignore the destination address for multicast compatibility
    gint copts = 0;
    if (pinfo->dst.type == AT_IPv4) {
        const ws_in4_addr *dst = pinfo->dst.data;
        if (in4_addr_is_multicast(*dst)) {
            copts |= NO_ADDR_B;
        }
    }
    else if (pinfo->dst.type == AT_IPv6) {
        const ws_in6_addr *dst = pinfo->dst.data;
        if (in6_addr_is_multicast(dst)) {
            copts |= NO_ADDR_B;
        }
    }
    // the UDP conversation should already exist
    conversation_t *convo = find_conversation_pinfo(pinfo, copts);

    udpcl_convo_t *clconvo;
    clconvo = conversation_get_proto_data(convo, proto_udpcl);
    if (!clconvo)
    {
        wmem_allocator_t *alloc = wmem_file_scope();
        clconvo = wmem_new0(alloc, udpcl_convo_t);
        clconvo->peer_probe = wmem_map_new(alloc, g_int64_hash, g_int64_equal);
        clconvo->peer_confirm = wmem_map_new(alloc, g_int64_hash, g_int64_equal);

        conversation_add_proto_data(convo, proto_udpcl, clconvo);
    }

    col_append_str(pinfo->cinfo, COL_INFO, "[");
    offset += 1;

    const gint64 count = first_head->head_value;
    proto_item *item_ext_map = proto_tree_add_cbor_int64(tree_udpcl, hf_ext_map, pinfo, tvb, first_head, &count);
    proto_tree *tree_ext_map = proto_item_add_subtree(item_ext_map, ett_ext_map);

    for (gint64 ix = 0; ix < count; ++ix) {
        wscbor_chunk_t *key_chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        gint64 *key = wscbor_require_int64(pinfo->pool, key_chunk);
        proto_item *item_ext_item = proto_tree_add_cbor_int64(tree_ext_map, hf_ext_id, pinfo, tvb, key_chunk, key);
        proto_tree *tree_ext_item = proto_item_add_subtree(item_ext_item, ett_ext_item);

        // Restrict to valid range
        if (key && ((*key == 0) || (*key < -32768) || (*key >= 32768))) {
            expert_add_info(pinfo, item_ext_item, &ei_ext_key_invalid);
            key = NULL;
        }

        // Skip the item to detect its length for subset TVB
        const unsigned init_offset = offset;
        wscbor_skip_next_item(pinfo->pool, tvb, &offset);
        if (!key) {
            continue;
        }

        dissector_handle_t dissector = NULL;
        if (*key >= 0) {
            dissector = dissector_get_uint_handle(table_ext, *key);
        }

        tvbuff_t *tvb_item = tvb_new_subset_length(tvb, init_offset, offset - init_offset);
        int sublen = 0;
        const char *dis_name = NULL;
        if (dissector) {
            sublen = call_dissector_only(dissector, tvb_item, pinfo, tree_ext_item, clconvo);
            dis_name = dissector_handle_get_dissector_name(dissector);
        }
        else if (*key >= 0) {
            // negative keys are private use
            expert_add_info(pinfo, item_ext_item, &ei_ext_key_unknown);
        }

        if (ix > 0) {
            col_append_str(pinfo->cinfo, COL_INFO, ",");
        }
        if (dis_name) {
            proto_item_set_text(item_ext_item, "Extension ID: %s (%" PRId64 ")", dis_name, *key);
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s (%" PRId64 ")", dis_name, *key);
        }
        else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%" PRIu64, *key);
        }

        // show something even if known dissector failed
        if (sublen == 0) {
            sublen = call_dissector(handle_cbor, tvb_item, pinfo, tree_ext_item);
        }
    }
    proto_item_set_len(item_ext_map, offset - init_offset);

    col_append_str(pinfo->cinfo, COL_INFO, "]");
    return offset - init_offset;
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

    const unsigned buflen = tvb_captured_length(tvb);
    gint offset = 0;
    proto_item *item_udpcl = proto_tree_add_item(tree, proto_udpcl, tvb, 0, -1, ENC_NA);
    proto_tree *tree_udpcl = proto_item_add_subtree(item_udpcl, ett_udpcl);

    while ((unsigned)offset < buflen) {
        // Peek at first octet
        const guint8 first_octet = tvb_get_uint8(tvb, offset);
        gint peek_offset = offset;
        wscbor_chunk_t *first_head = wscbor_chunk_read(pinfo->pool, tvb, &peek_offset);

        if (first_octet == 0x00) {
            const unsigned padlen = buflen - offset;
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Padding[len=%" PRIu32 "]", padlen);
            proto_item_append_text(item_udpcl, ", Padding");

            proto_item *item_ka = proto_tree_add_uint64(tree_udpcl, hf_padding, tvb, offset, padlen, padlen);
            for (unsigned ix = offset + 1; ix < buflen; ++ix) {
                if (tvb_get_uint8(tvb, ix) != 0x0) {
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

            const int sublen = dissect_extmap(tvb, pinfo, tree_udpcl, first_head);
            if (sublen > 0) {
                offset += sublen;
            }
            proto_item_set_len(item_udpcl, offset);
        }
        else {
            // Captured data but not part of item_udpcl
            const int sublen = dissect_bundle(tvb, pinfo, tree_udpcl);
            if (sublen > 0) {
                offset += sublen;
            }
            else {
                break;
            }
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
        "analyze_sequence",
        "Analyze message sequences",
        "Whether the UDPCL dissector should analyze the sequencing of "
        "the messages within each conversation.",
        &udpcl_analyze_sequence
    );
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
        dissector_handle_t dis_h = create_dissector_handle_with_name_and_description(dissect_transfer, proto_udpcl, NULL, "Transfer");
        dissector_add_uint("udpcl.ext", 2, dis_h);
    }
    {
        dissector_handle_t dis_h = create_dissector_handle_with_name_and_description(dissect_sender_listen, proto_udpcl, NULL, "Sender Listen");
        dissector_add_uint("udpcl.ext", 3, dis_h);
    }
    {
        dissector_handle_t dis_h = create_dissector_handle_with_name_and_description(dissect_nodeid, proto_udpcl, NULL, "Node ID");
        dissector_add_uint("udpcl.ext", 4, dis_h);
    }
    {
        dissector_handle_t dis_h = create_dissector_handle_with_name_and_description(dissect_starttls, proto_udpcl, NULL, "DTLS Initiation");
        dissector_add_uint("udpcl.ext", 5, dis_h);
    }
    {
        dissector_handle_t dis_h = create_dissector_handle_with_name_and_description(dissect_peer_probe, proto_udpcl, NULL, "Peer Probe");
        dissector_add_uint("udpcl.ext", 6, dis_h);
    }
    {
        dissector_handle_t dis_h = create_dissector_handle_with_name_and_description(dissect_peer_confirm, proto_udpcl, NULL, "Peer Confirmation");
        dissector_add_uint("udpcl.ext", 7, dis_h);
    }
    {
        dissector_handle_t dis_h = create_dissector_handle_with_name_and_description(dissect_ecn_counts, proto_udpcl, NULL, "ECN Counts");
        dissector_add_uint("udpcl.ext", 8, dis_h);
    }

    udpcl_reinit();
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
    static proto_plugin plugin_udpcl;
    plugin_udpcl.register_protoinfo = proto_register_udpcl;
    plugin_udpcl.register_handoff = proto_reg_handoff_udpcl;
    proto_register_plugin(&plugin_udpcl);
}
