#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <stdio.h>
#include <inttypes.h>
#include "epan/wscbor.h"
#include "packet-cose.h"

#if defined(WIRESHARK_HAS_VERSION_H)
#include <ws_version.h>
#else
#include <config.h>
#define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
#define WIRESHARK_VERSION_MINOR VERSION_MINOR
#endif

/// Glib logging "domain" name
static const char *LOG_DOMAIN = "COSE";
/// Protocol column name
static const char *const proto_name_cose = "COSE";

/// Protocol preferences and defaults

/// Protocol handles
static int proto_cose = -1;

/// Dissect opaque CBOR data
static dissector_handle_t handle_cbor = NULL;
/// Dissector handles
static dissector_handle_t handle_cose_msg_hdr = NULL;
static dissector_handle_t handle_cose_msg_tagged = NULL;
static dissector_handle_t handle_cose_sign = NULL;
static dissector_handle_t handle_cose_sign1 = NULL;
static dissector_handle_t handle_cose_encrypt = NULL;
static dissector_handle_t handle_cose_encrypt0 = NULL;
static dissector_handle_t handle_cose_mac = NULL;
static dissector_handle_t handle_cose_mac0 = NULL;

/// Dissect opaque data
static dissector_table_t table_media = NULL;
/// Dissect extension items
static dissector_table_t table_cose_msg_tag = NULL;
static dissector_table_t table_header_int = NULL;
static dissector_table_t table_header_tstr = NULL;

static const val64_string alg_vals[] = {
    {-65535, "RS1"},
    {-259, "RS512"},
    {-258, "RS384"},
    {-257, "RS256"},
    {-47, "ES256K"},
    {-45, "SHAKE256"},
    {-44, "SHA-512"},
    {-43, "SHA-384"},
    {-39, "PS512"},
    {-38, "PS384"},
    {-37, "PS256"},
    {-36, "ES512"},
    {-35, "ES384"},
    {-18, "SHAKE128"},
    {-17, "SHA-512/256"},
    {-16, "SHA-256"},
    {-15, "SHA-256/64"},
    {-14, "SHA-1"},
    {-8, "EdDSA"},
    {-7, "ES256"},
    {-6, "direct"},
    {-5, "A256KW"},
    {-4, "A192KW"},
    {-3, "A128KW"},
    {0, "Reserved"},
    {1, "A128GCM"},
    {2, "A192GCM"},
    {3, "A256GCM"},
    {4, "HMAC 256/64"},
    {5, "HMAC 256/256"},
    {6, "HMAC 384/384"},
    {7, "HMAC 512/512"},
    {0, NULL},
};

static int hf_hdr_prot_bstr = -1;
static int hf_hdr_unprot = -1;
static int hf_payload_null = -1;
static int hf_payload_bstr = -1;
static int hf_signature_list = -1;
static int hf_signature = -1;
static int hf_ciphertext_null = -1;
static int hf_ciphertext_bstr = -1;
static int hf_recipient_list = -1;
static int hf_recipient = -1;
static int hf_tag = -1;

static int hf_hdr_label_int = -1;
static int hf_hdr_label_tstr = -1;

static int hf_hdr_alg_int = -1;
static int hf_hdr_alg_tstr = -1;
static int hf_hdr_crit_list = -1;
static int hf_hdr_ctype_uint = -1;
static int hf_hdr_ctype_tstr = -1;
static int hf_hdr_kid = -1;
static int hf_hdr_iv = -1;
static int hf_hdr_piv = -1;
static int hf_hdr_x5bag = -1;
static int hf_hdr_x5chain = -1;
static int hf_hdr_x5t = -1;
static int hf_hdr_x5t_hash = -1;
static int hf_hdr_x5u = -1;

/// Field definitions
static hf_register_info fields[] = {
    {&hf_hdr_prot_bstr, {"Protected Headers (bstr)", "cose.msg.prot_bstr", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_unprot, {"Unprotected Headers", "cose.msg.unprot", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_payload_null, {"Payload Detached", "cose.msg.detached_payload", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_payload_bstr, {"Payload", "cose.msg.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_signature_list, {"Signature List, Count", "cose.msg.signature_list", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_signature, {"Signature", "cose.msg.signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_ciphertext_null, {"Ciphertext Detached", "cose.msg.detached_ciphertext", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_ciphertext_bstr, {"Ciphertext", "cose.msg.ciphertext", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_recipient_list, {"Recipient List, Count", "cose.msg.recipient_list", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_recipient, {"Recipient", "cose.msg.recipient", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_tag, {"Tag", "cose.msg.tag", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_hdr_label_int, {"Label", "cose.header_label.int", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_label_tstr, {"Label", "cose.header_label.tstr", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL}},

    {&hf_hdr_alg_int, {"Algorithm", "cose.alg.int", FT_INT64, BASE_DEC | BASE_VAL64_STRING, VALS64(alg_vals), 0x0, NULL, HFILL}},
    {&hf_hdr_alg_tstr, {"Algorithm", "cose.alg.tstr", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_crit_list, {"Critical Headers, Count", "cose.crit", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_ctype_uint, {"Content-Format", "cose.content-type.uint", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_ctype_tstr, {"Content-Type", "cose.content-type.tstr", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_kid, {"Key identifier", "cose.kid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_iv, {"IV", "cose.iv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_piv, {"Partial IV", "cose.piv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_hdr_x5bag, {"X509 Bag (x5bag)", "cose.x5bag", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_x5chain, {"X509 Chain (x5chain)", "cose.x5chain", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_x5t, {"X509 Thumbprint (x5t)", "cose.x5t", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_x5t_hash, {"Hash Value", "cose.x5t.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_hdr_x5u, {"X509 URI (x5u)", "cose.x5u", FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL}},
};

static int ett_msg = -1;
static int ett_sig_list = -1;
static int ett_recip_list = -1;
static int ett_recip = -1;
static int ett_prot_bstr = -1;
static int ett_unprot = -1;
static int ett_hdr_map = -1;
static int ett_hdr_label = -1;
static int ett_hdr_crit_list = -1;
static int ett_hdr_x5cert_list = -1;
static int ett_hdr_x5t_list = -1;
/// Tree structures
static int *ett[] = {
    &ett_msg,
    &ett_sig_list,
    &ett_recip_list,
    &ett_recip,
    &ett_prot_bstr,
    &ett_unprot,
    &ett_hdr_map,
    &ett_hdr_label,
    &ett_hdr_crit_list,
    &ett_hdr_x5cert_list,
    &ett_hdr_x5t_list,
};

static expert_field ei_value_partial_decode = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_value_partial_decode, { "cose.partial_decode", PI_MALFORMED, PI_WARN, "Value is only partially decoded", EXPFILL}},
};

/** Dissect an ID-value pair within a context.
 *
 * @param dis_int The integer-key dissector table.
 * @param dis_tstr The text-string dissector table.
 * @return The total length dissected, or -1 if failed.
 */
static gint dissect_header_pair(dissector_table_t dis_int, dissector_table_t dis_tstr, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset) {
    wscbor_chunk_t *chunk_label = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);

    proto_item *item_label = NULL;
    dissector_handle_t dissector = NULL;
    switch (chunk_label->type_major) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NEGINT: {
            gint64 *label = wscbor_require_int64(wmem_packet_scope(), chunk_label);
            item_label = proto_tree_add_cbor_int64(tree, hf_hdr_label_int, pinfo, tvb, chunk_label, label);
            dissector = dissector_get_custom_table_handle(dis_int, label);
            break;
        }
        case CBOR_TYPE_STRING: {
            char *label = wscbor_require_tstr(wmem_packet_scope(), tvb, chunk_label);
            item_label = proto_tree_add_cbor_tstr(tree, hf_hdr_label_tstr, pinfo, tvb, chunk_label);
            dissector = dissector_get_string_handle(dis_tstr, label);
            break;
        }
        default:
            break;
    }
    proto_tree *tree_label = proto_item_add_subtree(item_label, ett_hdr_label);

    // Peek into the value as tvb
    const gint offset_value = *offset;
    wscbor_skip_next_item(wmem_packet_scope(), tvb, offset);
    tvbuff_t *tvb_value = tvb_new_subset_length(tvb, offset_value, *offset - offset_value);

    gint sublen = 0;
    if (dissector) {
        sublen = call_dissector_with_data(dissector, tvb_value, pinfo, tree_label, chunk_label);
        if ((sublen < 0) || ((guint)sublen < tvb_captured_length(tvb_value))) {
            expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_value_partial_decode);
        }
    }
    if (sublen == 0) {
        TRY {
            sublen = call_dissector(handle_cbor, tvb_value, pinfo, tree_label);
        }
        CATCH_ALL {}
        ENDTRY;
    }
    return sublen;
}

/** Dissect an entire header map, either for messages, recipients, or keys.
 *
 * @param dis_int The integer-key dissector table.
 * @param dis_tstr The text-string dissector table.
 * @param tvb The source data.
 * @param tree The parent of the header map.
 * @param[in,out] offset The data offset.
 * @return The total length dissected, or -1 if failed.
 */
static void dissect_header_map(dissector_table_t dis_int, dissector_table_t dis_tstr, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset) {
    wscbor_chunk_t *chunk_hdr_map = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);
    wscbor_require_map(chunk_hdr_map);
    proto_item *item_hdr_map = proto_tree_get_parent(tree);
    wscbor_chunk_mark_errors(pinfo, item_hdr_map, chunk_hdr_map);
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, offset, chunk_hdr_map)) {
        proto_tree *tree_hdr_map = proto_item_add_subtree(item_hdr_map, ett_hdr_map);

        dissect_header_pair(dis_int, dis_tstr, tvb, pinfo, tree_hdr_map, offset);
    }

    proto_item_set_len(item_hdr_map, *offset - chunk_hdr_map->start);
}

int dissect_cose_msg_header_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    dissect_header_map(table_header_int, table_header_tstr, tvb, pinfo, tree, &offset);
    return offset;
}

/** Common behavior for pair of header maps.
 */
static void dissect_headers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset) {
    // Protected in bstr
    wscbor_chunk_t *chunk_prot_bstr = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);
    tvbuff_t *tvb_prot = wscbor_require_bstr(tvb, chunk_prot_bstr);
    proto_item *item_prot_bstr = proto_tree_add_cbor_bstr(tree, hf_hdr_prot_bstr, pinfo, tvb, chunk_prot_bstr);
    if (tvb_prot) {
        proto_tree *tree_prot = proto_item_add_subtree(item_prot_bstr, ett_prot_bstr);

        dissect_cose_msg_header_map(tvb_prot, pinfo, tree_prot, NULL);
    }

    // Unprotected
    tvbuff_t *tvb_unprot = tvb_new_subset_remaining(tvb, *offset);
    proto_item *item_unprot = proto_tree_add_item(tree, hf_hdr_unprot, tvb_unprot, *offset, -1, ENC_NA);
    proto_tree *tree_unprot = proto_item_add_subtree(item_unprot, ett_unprot);
    const int sublen = dissect_cose_msg_header_map(tvb_unprot, pinfo, tree_unprot, NULL);
    *offset += sublen;
    proto_item_set_len(item_unprot, sublen);
}

/** Common behavior for payload.
 */
static void dissect_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset) {
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);
    if (chunk->type_major == CBOR_TYPE_FLOAT_CTRL) {
        proto_tree_add_cbor_ctrl(tree, hf_payload_null, pinfo, tvb, chunk);
    }
    else {
        wscbor_require_bstr(tvb, chunk);
        proto_tree_add_cbor_bstr(tree, hf_payload_bstr, pinfo, tvb, chunk);
    }
}
static void dissect_signature(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset) {
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);
    wscbor_require_bstr(tvb, chunk);
    proto_tree_add_cbor_bstr(tree, hf_signature, pinfo, tvb, chunk);
}
static void dissect_ciphertext(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset) {
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);
    if (chunk->type_major == CBOR_TYPE_FLOAT_CTRL) {
        proto_tree_add_cbor_ctrl(tree, hf_ciphertext_null, pinfo, tvb, chunk);
    }
    else {
        wscbor_require_bstr(tvb, chunk);
        proto_tree_add_cbor_bstr(tree, hf_ciphertext_bstr, pinfo, tvb, chunk);
    }
}
static void dissect_recipient(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset);
static void dissect_recipient_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset) {
    wscbor_chunk_t *chunk_list = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);
    wscbor_require_array(chunk_list);
    proto_item *item_list = proto_tree_add_cbor_container(tree, hf_recipient_list, pinfo, tvb, chunk_list);
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, offset, chunk_list)) {
        proto_tree *tree_recip_list = proto_item_add_subtree(item_list, ett_recip_list);

        for (guint64 ix = 0; ix < chunk_list->head_value; ++ix) {
            dissect_recipient(tvb, pinfo, tree_recip_list, offset);
        }
    }
    proto_item_set_len(item_list, *offset - chunk_list->start);
}
static void dissect_recipient(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset) {

    wscbor_chunk_t *chunk_recip = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);
    wscbor_require_array_size(chunk_recip, 3, 4);
    proto_item *item_recip = proto_tree_add_cbor_container(tree, hf_recipient, pinfo, tvb, chunk_recip);
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, offset, chunk_recip)) {
        proto_tree *tree_recip = proto_item_add_subtree(item_recip, ett_recip);

        dissect_headers(tvb, pinfo, tree_recip, offset);
        dissect_ciphertext(tvb, pinfo, tree_recip, offset);
        if (chunk_recip->head_value > 3) {
            dissect_recipient_list(tvb, pinfo, tree_recip, offset);
        }
    }
    proto_item_set_len(item_recip, *offset - chunk_recip->start);

}
static void dissect_tag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset) {
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);
    wscbor_require_bstr(tvb, chunk);
    proto_tree_add_cbor_bstr(tree, hf_tag, pinfo, tvb, chunk);
}

// Top-level protocol dissectors
static int dissect_cose_sign(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk_msg = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_array_size(chunk_msg, 4, 4);
    proto_item *item_msg = proto_tree_add_cbor_container(tree, proto_cose, pinfo, tvb, chunk_msg);
    proto_item_append_text(item_msg, ": COSE_Sign");
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_msg)) {
        proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_msg);

        dissect_headers(tvb, pinfo, tree_msg, &offset);
        dissect_payload(tvb, pinfo, tree_msg, &offset);

        wscbor_chunk_t *chunk_sig_list = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
        wscbor_require_array(chunk_sig_list);
        proto_item *item_sig_list = proto_tree_add_cbor_container(tree, hf_signature_list, pinfo, tvb, chunk_sig_list);
        if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_sig_list)) {
            proto_tree *tree_sig_list = proto_item_add_subtree(item_sig_list, ett_sig_list);

            for (guint64 ix = 0; ix < chunk_sig_list->head_value; ++ix) {
                dissect_signature(tvb, pinfo, tree_sig_list, &offset);
            }
        }
        proto_item_set_len(item_sig_list, offset - chunk_sig_list->start);
    }

    return offset;
}
static int dissect_cose_sign1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk_msg = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_array_size(chunk_msg, 4, 4);
    proto_item *item_msg = proto_tree_add_cbor_container(tree, proto_cose, pinfo, tvb, chunk_msg);
    proto_item_append_text(item_msg, ": COSE_Sign1");
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_msg)) {
        proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_msg);

        dissect_headers(tvb, pinfo, tree_msg, &offset);
        dissect_payload(tvb, pinfo, tree_msg, &offset);
        dissect_signature(tvb, pinfo, tree_msg, &offset);
    }

    return offset;
}
static int dissect_cose_encrypt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk_msg = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_array_size(chunk_msg, 4, 4);
    proto_item *item_msg = proto_tree_add_cbor_container(tree, proto_cose, pinfo, tvb, chunk_msg);
    proto_item_append_text(item_msg, ": COSE_Encrypt");
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_msg)) {
        proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_msg);

        dissect_headers(tvb, pinfo, tree_msg, &offset);
        dissect_ciphertext(tvb, pinfo, tree_msg, &offset);
        dissect_recipient_list(tvb, pinfo, tree_msg, &offset);
    }

    return offset;
}
static int dissect_cose_encrypt0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk_msg = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_array_size(chunk_msg, 3, 3);
    proto_item *item_msg = proto_tree_add_cbor_container(tree, proto_cose, pinfo, tvb, chunk_msg);
    proto_item_append_text(item_msg, ": COSE_Encrypt0");
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_msg)) {
        proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_msg);

        dissect_headers(tvb, pinfo, tree_msg, &offset);
        dissect_ciphertext(tvb, pinfo, tree_msg, &offset);
    }

    return offset;
}
static int dissect_cose_mac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk_msg = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_array_size(chunk_msg, 5, 5);
    proto_item *item_msg = proto_tree_add_cbor_container(tree, proto_cose, pinfo, tvb, chunk_msg);
    proto_item_append_text(item_msg, ": COSE_Mac");
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_msg)) {
        proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_msg);

        dissect_headers(tvb, pinfo, tree_msg, &offset);
        dissect_payload(tvb, pinfo, tree_msg, &offset);
        dissect_tag(tvb, pinfo, tree_msg, &offset);
        dissect_recipient_list(tvb, pinfo, tree_msg, &offset);
    }

    return offset;
}
static int dissect_cose_mac0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk_msg = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_array_size(chunk_msg, 3, 3);
    proto_item *item_msg = proto_tree_add_cbor_container(tree, proto_cose, pinfo, tvb, chunk_msg);
    proto_item_append_text(item_msg, ": COSE_Mac0");
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_msg)) {
        proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_msg);

        dissect_headers(tvb, pinfo, tree_msg, &offset);
        dissect_payload(tvb, pinfo, tree_msg, &offset);
        dissect_tag(tvb, pinfo, tree_msg, &offset);
    }

    return offset;
}

/** Dissect a tagged COSE message.
 */
int dissect_cose_msg_tagged(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    // All messages have the same base structure, attempt all tags
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    for (wmem_list_frame_t *it = wmem_list_head(chunk->tags); it;
            it = wmem_list_frame_next(it)) {
        guint64 *tag = wmem_list_frame_data(it);
        // first usable tag wins
        dissector_handle_t dissector = dissector_get_uint_handle(table_cose_msg_tag, *tag);
        int sublen = call_dissector_with_data(dissector, tvb, pinfo, tree, tag);
        if (sublen > 0) {
            return sublen;
        }
    }

    return -1;
}

void dissect_value_alg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset) {
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);
    switch (chunk->type_major) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NEGINT: {
            gint64 *val = wscbor_require_int64(wmem_packet_scope(), chunk);
            proto_tree_add_cbor_int64(tree, hf_hdr_alg_int, pinfo, tvb, chunk, val);
            break;
        }
        case CBOR_TYPE_STRING: {
            proto_tree_add_cbor_tstr(tree, hf_hdr_alg_tstr, pinfo, tvb, chunk);
            break;
        }
        default:
            break;
    }
}

static int dissect_header_alg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    dissect_value_alg(tvb, pinfo, tree, &offset);

    return offset;
}

static int dissect_header_crit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk_list = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_array(chunk_list);
    proto_item *item_list = proto_tree_add_cbor_container(tree, hf_hdr_crit_list, pinfo, tvb, chunk_list);
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_list)) {
        proto_tree *tree_list = proto_item_add_subtree(item_list, ett_hdr_crit_list);

        for (guint64 ix = 0; ix < chunk_list->head_value; ++ix) {
            wscbor_chunk_t *chunk_label = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
            switch (chunk_label->type_major) {
                case CBOR_TYPE_UINT:
                case CBOR_TYPE_NEGINT: {
                    gint64 *label = wscbor_require_int64(wmem_packet_scope(), chunk_label);
                    proto_tree_add_cbor_int64(tree_list, hf_hdr_label_int, pinfo, tvb, chunk_label, label);
                    break;
                }
                case CBOR_TYPE_STRING: {
                    proto_tree_add_cbor_tstr(tree_list, hf_hdr_label_tstr, pinfo, tvb, chunk_label);
                    break;
                }
                default:
                    break;
            }
        }
    }

    return offset;
}

static int dissect_header_ctype(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    switch (chunk->type_major) {
        case CBOR_TYPE_UINT: {
            guint64 *val = wscbor_require_uint64(wmem_packet_scope(), chunk);
            proto_tree_add_cbor_uint64(tree, hf_hdr_ctype_uint, pinfo, tvb, chunk, val);
            break;
        }
        case CBOR_TYPE_STRING: {
            proto_tree_add_cbor_tstr(tree, hf_hdr_ctype_tstr, pinfo, tvb, chunk);
            break;
        }
        default:
            break;
    }

    return offset;
}

static int dissect_header_kid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_bstr(tvb, chunk);
    proto_tree_add_cbor_bstr(tree, hf_hdr_kid, pinfo, tvb, chunk);

    return offset;
}

static int dissect_header_iv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_bstr(tvb, chunk);
    proto_tree_add_cbor_bstr(tree, hf_hdr_iv, pinfo, tvb, chunk);

    return offset;
}

static int dissect_header_piv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_bstr(tvb, chunk);
    proto_tree_add_cbor_bstr(tree, hf_hdr_piv, pinfo, tvb, chunk);

    return offset;
}

static void dissect_value_x5cert(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset) {
    wscbor_chunk_t *chunk_item = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);
    tvbuff_t *tvb_item = wscbor_require_bstr(tvb, chunk_item);

    if (tvb_item) {
        // disallow column text rewrite
        gchar *info_text = g_strdup(col_get_text(pinfo->cinfo, COL_INFO));

        TRY {
            dissector_try_string(
                table_media,
                "application/pkix-cert",
                tvb_item,
                pinfo,
                tree,
                NULL
            );
        }
        CATCH_ALL {}
        ENDTRY;

        col_add_str(pinfo->cinfo, COL_INFO, info_text);
        g_free(info_text);
    }

}
static void dissect_value_cosex509(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int hfindex, gint *offset) {
    proto_item *item_ctr = proto_tree_add_item(tree, hfindex, tvb, 0, -1, ENC_NA);
    proto_tree *tree_ctr = proto_item_add_subtree(item_ctr, ett_hdr_x5cert_list);

    wscbor_chunk_t *chunk_ctr = wscbor_chunk_read(wmem_packet_scope(), tvb, offset);
    switch (chunk_ctr->type_major) {
        case CBOR_TYPE_ARRAY: {
            wscbor_require_array(chunk_ctr);
            if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, offset, chunk_ctr)) {
                for (guint64 ix = 0; ix < chunk_ctr->head_value; ++ix) {
                    dissect_value_x5cert(tvb, pinfo, tree_ctr, offset);
                }
            }
            break;
        }
        case CBOR_TYPE_BYTESTRING: {
            // re-read this chunk as cert
            *offset = chunk_ctr->start;
            dissect_value_x5cert(tvb, pinfo, tree_ctr, offset);
            break;
        }
        default:
            break;
    }

}
static int dissect_header_x5bag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    dissect_value_cosex509(tvb, pinfo, tree, hf_hdr_x5bag, &offset);
    return offset;
}
static int dissect_header_x5chain(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    dissect_value_cosex509(tvb, pinfo, tree, hf_hdr_x5chain, &offset);
    return offset;
}

static int dissect_header_x5t(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk_list = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_array_size(chunk_list, 2, 2);
    proto_item *item_list = proto_tree_add_cbor_container(tree, hf_hdr_x5t, pinfo, tvb, chunk_list);
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_list)) {
        proto_tree *tree_list = proto_item_add_subtree(item_list, ett_hdr_x5t_list);

        dissect_value_alg(tvb, pinfo, tree_list, &offset);

        wscbor_chunk_t *chunk_hash = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
        wscbor_require_bstr(tvb, chunk_hash);
        proto_tree_add_cbor_bstr(tree_list, hf_hdr_x5t_hash, pinfo, tvb, chunk_hash);

    }

    return offset;
}

static int dissect_header_x5u(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_major_type(chunk, CBOR_TYPE_STRING);
    proto_tree_add_cbor_tstr(tree, hf_hdr_x5u, pinfo, tvb, chunk);

    return offset;
}


/** Register a header dissector.
 */
static void register_header_dissector(dissector_t dissector, gint64 label_int, const char *label_tstr) {
    dissector_handle_t dis_h = create_dissector_handle(dissector, proto_cose);

    gint64 *key_int = g_new(gint64, 1);
    *key_int = label_int;
    dissector_add_custom_table_handle("cose.header.int", key_int, dis_h);

    if (label_tstr) {
        dissector_add_string("cose.header.tstr", label_tstr, dis_h);
    }
}

/// Initialize for a new file load
static void cose_init(void) {
}

/// Cleanup after a file
static void cose_cleanup(void) {
}

/// Re-initialize after a configuration change
static void cose_reinit(void) {
}

/// Overall registration of the protocol
static void proto_register_cose(void) {
    g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "proto_register_cose()\n");
    proto_cose = proto_register_protocol(
        "CBOR Object Signing and Encryption", /* name */
        proto_name_cose, /* short name */
        "cose" /* abbrev */
    );
    register_init_routine(&cose_init);
    register_cleanup_routine(&cose_cleanup);

    proto_register_field_array(proto_cose, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_cose);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

    handle_cose_msg_hdr = register_dissector("cose.msg.headers", dissect_cose_msg_header_map, proto_cose);
    handle_cose_msg_tagged = register_dissector("cose", dissect_cose_msg_tagged, proto_cose);
    handle_cose_sign = register_dissector("cose_sign", dissect_cose_sign, proto_cose);
    handle_cose_sign1 = register_dissector("cose_sign1", dissect_cose_sign1, proto_cose);
    handle_cose_encrypt = register_dissector("cose_encrypt", dissect_cose_encrypt, proto_cose);
    handle_cose_encrypt0 = register_dissector("cose_encrypt0", dissect_cose_encrypt0, proto_cose);
    handle_cose_mac = register_dissector("cose_mac", dissect_cose_mac, proto_cose);
    handle_cose_mac0 = register_dissector("cose_mac0", dissect_cose_mac0, proto_cose);

    table_cose_msg_tag = register_dissector_table("cose.msgtag", "COSE Message Tag", proto_cose, FT_UINT32, BASE_NONE);
    table_header_int = register_custom_dissector_table("cose.header.int", "COSE Header Parameter (int)", proto_cose, g_int64_hash, g_int64_equal);
    table_header_tstr = register_dissector_table("cose.header.tstr", "COSE Header Parameter (tstr)", proto_cose, FT_STRING, STR_UNICODE);

    module_t *module_cose = prefs_register_protocol(proto_cose, cose_reinit);
    (void)module_cose;
}

static void proto_reg_handoff_cose(void) {
    table_media = find_dissector_table("media_type");
    handle_cbor = find_dissector("cbor");

    dissector_add_string("media_type", "application/cose", handle_cose_msg_tagged);
    // RFC 8152 tags and names (Table 26)
    dissector_add_uint("cose.msgtag", 98, handle_cose_sign);
    dissector_add_string("media_type", "application/cose; cose-type=\"cose-sign\"", handle_cose_sign);
    dissector_add_uint("cose.msgtag", 18, handle_cose_sign1);
    dissector_add_string("media_type", "application/cose; cose-type=\"cose-sign1\"", handle_cose_sign1);
    dissector_add_uint("cose.msgtag", 96, handle_cose_encrypt);
    dissector_add_string("media_type", "application/cose; cose-type=\"cose-encrypt\"", handle_cose_encrypt);
    dissector_add_uint("cose.msgtag", 16, handle_cose_encrypt0);
    dissector_add_string("media_type", "application/cose; cose-type=\"cose-encrypt0\"", handle_cose_encrypt0);
    dissector_add_uint("cose.msgtag", 97, handle_cose_mac);
    dissector_add_string("media_type", "application/cose; cose-type=\"cose-mac\"", handle_cose_mac);
    dissector_add_uint("cose.msgtag", 17, handle_cose_mac0);
    dissector_add_string("media_type", "application/cose; cose-type=\"cose-mac0\"", handle_cose_mac0);

    // RFC 8152 header keys
    register_header_dissector(dissect_header_alg, 1, NULL);
    register_header_dissector(dissect_header_crit, 2, NULL);
    register_header_dissector(dissect_header_ctype, 3, NULL);
    register_header_dissector(dissect_header_kid, 4, NULL);
    register_header_dissector(dissect_header_iv, 5, NULL);
    register_header_dissector(dissect_header_piv, 6, NULL);
    // draft-ietf-cose-x509 header keys
    register_header_dissector(dissect_header_x5bag, 32, NULL);
    register_header_dissector(dissect_header_x5chain, 33, NULL);
    register_header_dissector(dissect_header_x5t, 34, NULL);
    register_header_dissector(dissect_header_x5u, 35, NULL);

    cose_reinit();
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
    static proto_plugin plugin_cose;
    plugin_cose.register_protoinfo = proto_register_cose;
    plugin_cose.register_handoff = proto_reg_handoff_cose;
    proto_register_plugin(&plugin_cose);
}
