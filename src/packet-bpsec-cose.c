#include "packet-bpsec.h"
#include "packet-bpv7.h"
#include "bp_cbor.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <inttypes.h>

#if defined(WIRESHARK_HAS_VERSION_H)
#include <ws_version.h>
#else
#include <config.h>
#define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
#define WIRESHARK_VERSION_MINOR VERSION_MINOR
#endif

/** AAD Scope parameter.
 * Section 3.2.2.
 */
typedef enum {
    HAS_PRIMARY_CTX = 0x01,
    HAS_TARGET_CTX = 0x02,
    HAS_SECURITY_CTX = 0x04,
} AadScopeFlag;

/// Protocol handles
static int proto_bpsec_cose = -1;

/// Dissect opaque CBOR parameters/results
static dissector_table_t dissect_media = NULL;

static int hf_aad_scope = -1;
static int hf_aad_scope_primary = -1;
static int hf_aad_scope_target = -1;
static int hf_aad_scope_security = -1;
static int hf_cose_x509 = -1;
static int hf_cert = -1;
static int hf_cose_msg = -1;
/// Field definitions
static hf_register_info fields[] = {
    {&hf_aad_scope, {"AAD Scope", "bpsec.cose.aad_scope", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_aad_scope_primary, {"Primary Block", "bpsec.cose.aad_scope.primary", FT_UINT8, BASE_DEC, NULL, HAS_PRIMARY_CTX, NULL, HFILL}},
    {&hf_aad_scope_target, {"Target Block", "bpsec.cose.aad_scope.target", FT_UINT8, BASE_DEC, NULL, HAS_TARGET_CTX, NULL, HFILL}},
    {&hf_aad_scope_security, {"BPSec Block", "bpsec.cose.aad_scope.security", FT_UINT8, BASE_DEC, NULL, HAS_SECURITY_CTX, NULL, HFILL}},
    {&hf_cose_x509, {"COSE Certificates", "bpsec.cose.x509", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_cert, {"PKIX Certificate", "bpsec.cose.cert", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_cose_msg, {"COSE Message", "bpsec.cose.msg", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
};

static WS_FIELDTYPE aad_scope[] = {
    &hf_aad_scope_primary,
    &hf_aad_scope_target,
    &hf_aad_scope_security,
    NULL
};

static int ett_aad_scope = -1;
static int ett_cose_x509 = -1;
static int ett_cose_msg = -1;
/// Tree structures
static int *ett[] = {
    &ett_aad_scope,
    &ett_cose_x509,
    &ett_cose_msg,
};

/** Dissector for AAD Scope parameter.
 */
static int dissect_param_scope(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    bp_cbor_chunk_t *chunk_flags = bp_scan_cbor_chunk(tvb, offset);
    guint64 *flags = cbor_require_uint64(chunk_flags);
    proto_tree_add_cbor_bitmask(tree, hf_aad_scope, ett_aad_scope, aad_scope, pinfo, tvb, chunk_flags, flags);
    offset += chunk_flags->data_length;
    bp_cbor_chunk_delete(chunk_flags);

    return offset;
}

/** Dissector for CDDL type COSE_X509.
 */
static int dissect_cose_x509(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    proto_item *item_list = proto_tree_add_item(tree, hf_cose_x509, tvb, 0, 0, ENC_NA);
    proto_tree *tree_list = proto_item_add_subtree(item_list, ett_cose_x509);

    bp_cbor_chunk_t *head = cbor_require_array(tvb, pinfo, item_list, &offset);
    const gint64 count = (head ? head->head_value : 0);
    for (gint64 cert_ix = 0; cert_ix < count; ++cert_ix) {
        bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, offset);
        tvbuff_t *tvb_data = cbor_require_string(tvb, chunk);
        offset += chunk->data_length;

        if (tvb_data) {
            // disallow name rewrite
            gchar *info_text = g_strdup(col_get_text(pinfo->cinfo, COL_INFO));

            dissector_try_string(
                dissect_media,
                "application/pkix-cert",
                tvb_data,
                pinfo,
                tree_list,
                NULL
            );

            col_add_str(pinfo->cinfo, COL_INFO, info_text);
            g_free(info_text);
        }
    }

    return offset;
}

/** Dissector for bstr-wrapped CBOR.
 */
static int dissect_cose_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    proto_item *item_msg = proto_tree_add_item(tree, hf_cose_msg, tvb, 0, 0, ENC_NA);
    proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_cose_msg);

    bp_cbor_chunk_t *chunk = bp_scan_cbor_chunk(tvb, 0);
    tvbuff_t *tvb_data = cbor_require_string(tvb, chunk);
    offset += chunk->data_length;

    if (tvb_data) {
        dissector_try_string(
            dissect_media,
            "application/cbor", // should really be "application/cose"
            tvb_data,
            pinfo,
            tree_msg,
            NULL
        );
    }

    return offset;
}

/// Re-initialize after a configuration change
static void reinit_bpsec_cose(void) {
}

/// Overall registration of the protocol
static void proto_register_bpsec_cose(void) {
    proto_bpsec_cose = proto_register_protocol(
        "BPSec COSE", /* name */
        "BPSec COSE", /* short name */
        "bpsec-cose" /* abbrev */
    );

    proto_register_field_array(proto_bpsec_cose, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));

    prefs_register_protocol(proto_bpsec_cose, reinit_bpsec_cose);
}

static void proto_reg_handoff_bpsec_cose(void) {
    dissect_media = find_dissector_table("media_type");

    /* Packaged extensions */
    const gint64 ctxid = 99;
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_cose_msg, proto_bpsec_cose);
        {
            bpsec_id_t *key = bpsec_id_new(NULL, ctxid, 1);
            dissector_add_custom_table_handle("bpsec.param", key, hdl);
        }
        {
            bpsec_id_t *key = bpsec_id_new(NULL, ctxid, 2);
            dissector_add_custom_table_handle("bpsec.param", key, hdl);
        }
    }
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_cose_x509, proto_bpsec_cose);
        {
            bpsec_id_t *key = bpsec_id_new(NULL, ctxid, 3);
            dissector_add_custom_table_handle("bpsec.param", key, hdl);
        }
        {
            bpsec_id_t *key = bpsec_id_new(NULL, ctxid, 4);
            dissector_add_custom_table_handle("bpsec.param", key, hdl);
        }
    }
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_param_scope, proto_bpsec_cose);
        {
            bpsec_id_t *key = bpsec_id_new(NULL, ctxid, 5);
            dissector_add_custom_table_handle("bpsec.param", key, hdl);
        }
    }
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_cose_msg, proto_bpsec_cose);

        const gint64 cose_msg_ids[] = {16, 17, 18, 96, 97, 98};
        for (const gint64 *it = cose_msg_ids; it != cose_msg_ids + 6; ++it) {
            bpsec_id_t *key = bpsec_id_new(NULL, ctxid, *it);
            dissector_add_custom_table_handle("bpsec.result", key, hdl);
        }
    }

    reinit_bpsec_cose();
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
    static proto_plugin plugin;
    plugin.register_protoinfo = proto_register_bpsec_cose;
    plugin.register_handoff = proto_reg_handoff_bpsec_cose;
    proto_register_plugin(&plugin);
}