#include <epan/dissectors/packet-bpsec.h>
#include <epan/dissectors/packet-bpv7.h>
#include <epan/dissectors/packet-cose.h>
#include <epan/wscbor.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <inttypes.h>

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
static dissector_table_t table_cose_msg = NULL;

static dissector_handle_t handle_cose_msg_hdr = NULL;

static int hf_aad_scope = -1;
static int hf_aad_scope_primary = -1;
static int hf_aad_scope_target = -1;
static int hf_aad_scope_security = -1;
static int hf_addl_prot_bstr = -1;
static int hf_addl_unprot = -1;
static int hf_cose_msg = -1;
/// Field definitions
static hf_register_info fields[] = {
    {&hf_aad_scope, {"AAD Scope", "bpsec.cose.aad_scope", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_aad_scope_primary, {"Primary Block", "bpsec.cose.aad_scope.primary", FT_BOOLEAN, 8, TFS(&tfs_set_notset), HAS_PRIMARY_CTX, NULL, HFILL}},
    {&hf_aad_scope_target, {"Target Block", "bpsec.cose.aad_scope.target", FT_BOOLEAN, 8, TFS(&tfs_set_notset), HAS_TARGET_CTX, NULL, HFILL}},
    {&hf_aad_scope_security, {"BPSec Block", "bpsec.cose.aad_scope.security", FT_BOOLEAN, 8, TFS(&tfs_set_notset), HAS_SECURITY_CTX, NULL, HFILL}},
    {&hf_addl_prot_bstr, {"Additional Protected Headers (bstr)", "bpsec.cose.addl_proected_bstr", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_addl_unprot, {"Additional Unprotected Headers", "bpsec.cose.addl_unprotected", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_cose_msg, {"COSE Message (bstr)", "bpsec.cose.msg", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
};

static int *const aad_scope[] = {
    &hf_aad_scope_primary,
    &hf_aad_scope_target,
    &hf_aad_scope_security,
    NULL
};

static int ett_aad_scope = -1;
static int ett_addl_prot_bstr = -1;
static int ett_addl_prot = -1;
static int ett_addl_unprot = -1;
static int ett_cose_msg = -1;
/// Tree structures
static int *ett[] = {
    &ett_aad_scope,
    &ett_addl_prot_bstr,
    &ett_addl_prot,
    &ett_addl_unprot,
    &ett_cose_msg,
};

/** Dissector for AAD Scope parameter.
 */
static int dissect_param_scope(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk_flags = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    guint64 *flags = wscbor_require_uint64(wmem_packet_scope(), chunk_flags);
    proto_tree_add_cbor_bitmask(tree, hf_aad_scope, ett_aad_scope, aad_scope, pinfo, tvb, chunk_flags, flags);

    return offset;
}

/** Dissector for COSE protected header.
 */
static int dissect_addl_protected(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;

    wscbor_chunk_t *chunk_prot_bstr = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    tvbuff_t *prot_bstr = wscbor_require_bstr(wmem_packet_scope(), chunk_prot_bstr);
    proto_item *item_prot_bstr = proto_tree_add_cbor_bstr(tree, hf_addl_prot_bstr, pinfo, tvb, chunk_prot_bstr);
    if (prot_bstr) {
        proto_tree *tree_prot_bstr = proto_item_add_subtree(item_prot_bstr, ett_addl_prot_bstr);

        int sublen = call_dissector(handle_cose_msg_hdr, prot_bstr, pinfo, tree_prot_bstr);
        if (sublen < 0) {
            return sublen;
        }
        offset += sublen;
    }

    return offset;
}

/** Dissector for COSE unprotected header.
 */
static int dissect_addl_unprotected(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item *item_hdr = proto_tree_add_item(tree, hf_addl_unprot, tvb, 0, -1, ENC_NA);
    proto_tree *tree_hdr = proto_item_add_subtree(item_hdr, ett_addl_prot);
    int sublen = call_dissector(handle_cose_msg_hdr, tvb, pinfo, tree_hdr);
    return sublen;
}

/** Dissector for bstr-wrapped CBOR.
 */
static int dissect_cose_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    gint64 *typeid = data;
    DISSECTOR_ASSERT(typeid != NULL);
    gint offset = 0;

    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    tvbuff_t *tvb_data = wscbor_require_bstr(wmem_packet_scope(), chunk);

    proto_item *item_msg = proto_tree_add_cbor_bstr(tree, hf_cose_msg, pinfo, tvb, chunk);
    proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_cose_msg);

    if (tvb_data) {
        dissector_handle_t dissector = dissector_get_custom_table_handle(table_cose_msg, typeid);
        int sublen = call_dissector(dissector, tvb_data, pinfo, tree_msg);
        if (sublen < 0) {
            return sublen;
        }
    }

    return offset;
}

/// Re-initialize after a configuration change
static void reinit_bpsec_cose(void) {
}

/// Overall registration of the protocol
void proto_register_bpsec_cose(void) {
    proto_bpsec_cose = proto_register_protocol(
        "BPSec COSE", /* name */
        "BPSec COSE", /* short name */
        "bpsec-cose" /* abbrev */
    );

    proto_register_field_array(proto_bpsec_cose, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));

    prefs_register_protocol(proto_bpsec_cose, reinit_bpsec_cose);
}

void proto_reg_handoff_bpsec_cose(void) {
    table_cose_msg = find_dissector_table("cose.msgtag");
    handle_cose_msg_hdr = find_dissector_add_dependency("cose.msg.headers", proto_bpsec_cose);

    /* Packaged extensions */
    const gint64 ctxid = 99;
    {
        bpsec_id_t *key = bpsec_id_new(NULL, ctxid, 1);
        dissector_handle_t hdl = find_dissector_add_dependency("cose_key", proto_bpsec_cose);
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = bpsec_id_new(NULL, ctxid, 2);
        dissector_handle_t hdl = find_dissector_add_dependency("cose_key_set", proto_bpsec_cose);
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = bpsec_id_new(NULL, ctxid, 3);
        dissector_handle_t hdl = create_dissector_handle_with_name(dissect_addl_protected, proto_bpsec_cose, "Additional Protected Headers");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = bpsec_id_new(NULL, ctxid, 4);
        dissector_handle_t hdl = create_dissector_handle_with_name(dissect_addl_unprotected, proto_bpsec_cose, "Additional Unprotected Headers");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = bpsec_id_new(NULL, ctxid, 5);
        dissector_handle_t hdl = create_dissector_handle_with_name(dissect_param_scope, proto_bpsec_cose, "Scope");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        const gint64 cose_msg_ids[] = {16, 17, 18, 96, 97, 98};
        for (const gint64 *it = cose_msg_ids; it != cose_msg_ids + 6; ++it) {
            bpsec_id_t *key = bpsec_id_new(NULL, ctxid, *it);
            char *name = wmem_strdup_printf(wmem_epan_scope(), "COSE message type %" PRId64, *it);
            dissector_handle_t hdl = create_dissector_handle_with_name(dissect_cose_msg, proto_bpsec_cose, name);
            dissector_add_custom_table_handle("bpsec.result", key, hdl);
        }
    }

    reinit_bpsec_cose();
}
