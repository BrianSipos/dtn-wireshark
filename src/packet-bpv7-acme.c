#include "packet-bpv7.h"
#include "bp_cbor.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <stdio.h>
#include <inttypes.h>

#if defined(WIRESHARK_HAS_VERSION_H)
#include <ws_version.h>
#else
#include <config.h>
#define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
#define WIRESHARK_VERSION_MINOR VERSION_MINOR
#endif

/// Protocol column name
const char *const proto_name_bp = "BPv7 ACME";

/// Protocol handles
static int proto_bp_acme = -1;

/// Dissect opaque CBOR parameters/results
static dissector_table_t dissect_media = NULL;

typedef enum {
    ACME_TOKEN_PART1 = 1,
    ACME_KEY_AUTH_DIGEST = 2,
} AcmeKey;

static int hf_acme_key = -1;
static int hf_token_part1 = -1;
static int hf_key_auth_digest = -1;
/// Field definitions
static hf_register_info fields[] = {
    {&hf_acme_key, {"Item Key", "bpv7.acme.item_key", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_token_part1, {"Token Part-1", "bpv7.acme.token_part1", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_key_auth_digest, {"Key Auth. Digest", "bpv7.acme.key_auth_digest", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
};

static int ett_acme = -1;
static int ett_acme_key = -1;
/// Tree structures
static int *ett[] = {
    &ett_acme,
    &ett_acme_key,
};

static expert_field ei_acme_key_unknown = EI_INIT;
static expert_field ei_no_token_part1 = EI_INIT;
static expert_field ei_unexpected_key_auth_hash = EI_INIT;
static expert_field ei_missing_key_auth_hash = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_acme_key_unknown, {"bpv7.acme.key_unknown", PI_UNDECODED, PI_WARN, "Unknown key code", EXPFILL}},
    {&ei_no_token_part1, {"bpv7.acme.no_token_part1", PI_PROTOCOL, PI_ERROR, "Missing token-part1", EXPFILL}},
    {&ei_unexpected_key_auth_hash, {"bpv7.acme.unexpected_key_auth_hash", PI_PROTOCOL, PI_ERROR, "Unexpected key authorization hash", EXPFILL}},
    {&ei_missing_key_auth_hash, {"bpv7.acme.missing_key_auth_hash", PI_PROTOCOL, PI_ERROR, "Missing key authorization hash", EXPFILL}},
};

static int dissect_bp_acme(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    bp_dissector_data_t *context = (bp_dissector_data_t *)data;
    if (!context) {
        return -1;
    }
    const gint offset_start = 0;
    gint offset = 0;

    proto_item_append_text(proto_tree_get_parent(tree), ", ACME Message");

    // Status Information array head
    proto_item *item_acme = proto_tree_add_item(tree, proto_bp_acme, tvb, offset_start, -1, ENC_NA);
    proto_tree *tree_acme = proto_item_add_subtree(item_acme, ett_acme);

    proto_item *item_token_part1 = NULL;
    proto_item *item_key_auth_digest = NULL;

    bp_cbor_chunk_t *chunk_msg = cbor_require_map(tvb, pinfo, item_acme, &offset);
    if (chunk_msg) {
        for (gint64 ix = 0; ix < chunk_msg->head_value; ++ix) {
            bp_cbor_chunk_t *key_chunk = bp_scan_cbor_chunk(tvb, offset);
            offset += key_chunk->data_length;
            gint64 *key = cbor_require_int64(key_chunk);
            proto_item *item_key = proto_tree_add_cbor_int64(tree_acme, hf_acme_key, pinfo, tvb, key_chunk, key);
            proto_tree *tree_key = proto_item_add_subtree(item_key, ett_acme_key);
            bp_cbor_chunk_delete(key_chunk);

            if (!key) {
                cbor_skip_next_item(tvb, &offset);
                continue;
            }
            switch (*key) {
                case ACME_TOKEN_PART1: {
                    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, offset);
                    offset += chunk->data_length;
                    item_token_part1 = proto_tree_add_cbor_string(tree_key, hf_token_part1, pinfo, tvb, chunk);
                    bp_cbor_chunk_delete(chunk);
                    break;
                }
                case ACME_KEY_AUTH_DIGEST: {
                    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, offset);
                    offset += chunk->data_length;
                    item_key_auth_digest = proto_tree_add_cbor_string(tree_key, hf_key_auth_digest, pinfo, tvb, chunk);
                    bp_cbor_chunk_delete(chunk);
                    break;
                }
                default: {
                    guint init_offset = offset;
                    cbor_skip_next_item(tvb, &offset);
                    expert_add_info(pinfo, item_key, &ei_acme_key_unknown);

                    tvbuff_t *tvb_item = tvb_new_subset_length(tvb, init_offset, offset);
                    offset += dissector_try_string(
                        dissect_media,
                        "application/cbor",
                        tvb_item,
                        pinfo,
                        tree_key,
                        NULL
                    );
                    break;
                }
            }
        }
    }

    if (!item_token_part1) {
        expert_add_info(pinfo, item_acme, &ei_no_token_part1);
    }
    const gboolean is_req = context->bundle->primary->flags & BP_BUNDLE_USER_APP_ACK;
    if (is_req && item_key_auth_digest) {
        expert_add_info(pinfo, item_acme, &ei_missing_key_auth_hash);
    }
    if (!is_req && !item_key_auth_digest) {
        expert_add_info(pinfo, item_acme, &ei_unexpected_key_auth_hash);
    }

    proto_item_set_len(item_acme, offset - offset_start);
    bp_cbor_chunk_delete(chunk_msg);
    return offset;
}

/// Clear state when new file scope is entered
static void history_init(void) {}

static void history_cleanup(void) {}

/// Re-initialize after a configuration change
static void reinit_bp_acme(void) {}


/// Overall registration of the protocol
static void proto_register_bp_acme(void) {
    proto_bp_acme = proto_register_protocol(
        "BP ACME Node ID Validation", /* name */
        "BPv7 ACME", /* short name */
        "bpv7.acme" /* abbrev */
    );
    register_init_routine(&history_init);
    register_cleanup_routine(&history_cleanup);

    proto_register_field_array(proto_bp_acme, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_bp_acme);
    bp_cbor_init(expert);
    expert_register_field_array(expert, expertitems, array_length(expertitems));
}

static void proto_reg_handoff_bp_acme(void) {
    dissect_media = find_dissector_table("media_type");

    /* Packaged extensions */
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_bp_acme, proto_bp_acme);
        dissector_add_uint("bpv7.admin_record_type", 99, hdl);
    }

    reinit_bp_acme();
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
    static proto_plugin plugin_bp;
    plugin_bp.register_protoinfo = proto_register_bp_acme;
    plugin_bp.register_handoff = proto_reg_handoff_bp_acme;
    proto_register_plugin(&plugin_bp);
}
