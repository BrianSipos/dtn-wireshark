#include "packet-bpv7.h"
#include "epan/wscbor.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <stdio.h>
#include <inttypes.h>

typedef struct {
    void *data;
    guint64 len;
} bp_acme_bytes_t;

static void bp_acme_bytes_init(wmem_allocator_t *alloc, bp_acme_bytes_t *bytes, tvbuff_t *tvb) {
    bytes->len = tvb_reported_length(tvb);
    bytes->data = tvb_memdup(alloc, tvb, 0, bytes->len);
}

gboolean bp_acme_bytes_equal(const bp_acme_bytes_t *a, const bp_acme_bytes_t *b) {
    if (a->len != b->len) {
        return FALSE;
    }
    return memcmp(a->data, b->data, a->len) == 0;
}

guint bp_acme_bytes_hash(const bp_acme_bytes_t *bytes) {
    GBytes *conv = g_bytes_new_static(bytes->data, bytes->len);
    const guint val = g_bytes_hash(conv);
    g_bytes_unref(conv);
    return val;
}

/// Challenge--response correlation
typedef struct {
    /// EID of the challenge source or response destination
    const gchar *server_nodeid;
    /// EID of the challenge source or response destination
    const gchar *client_nodeid;
    /// ACME token-part1 as a nonce
    bp_acme_bytes_t token_part1;
} bp_acme_corr_t;

static bp_acme_corr_t * bp_acme_corr_new(wmem_allocator_t *alloc, const bp_bundle_t *bundle) {
    bp_acme_corr_t *obj = wmem_new0(alloc, bp_acme_corr_t);
    const gboolean is_req = bundle->primary->flags & BP_BUNDLE_USER_APP_ACK;
    if (is_req) {
        obj->server_nodeid = bundle->primary->src_nodeid->uri;
        obj->client_nodeid = bundle->primary->dst_eid->uri;
    }
    else {
        obj->client_nodeid = bundle->primary->src_nodeid->uri;
        obj->server_nodeid = bundle->primary->dst_eid->uri;

    }
    return obj;
}

/** Function to match the GCompareFunc signature.
 */
static gboolean bp_acme_corr_equal(gconstpointer a, gconstpointer b) {
    const bp_acme_corr_t *aobj = a;
    const bp_acme_corr_t *bobj = b;
    return (
        (aobj->server_nodeid && bobj->server_nodeid
            && g_str_equal(aobj->server_nodeid, bobj->server_nodeid))
        && bp_acme_bytes_equal(&(aobj->token_part1), &(bobj->token_part1))
    );
}

/** Function to match the GHashFunc signature.
 */
static guint bp_acme_corr_hash(gconstpointer key) {
    const bp_acme_corr_t *obj = key;
    return (
        g_str_hash(obj->server_nodeid ? obj->server_nodeid : "")
        ^ bp_acme_bytes_hash(&(obj->token_part1))
    );
}


/// Challenge--response pair
typedef struct {
    bp_bundle_t *server_msg;
    bp_bundle_t *client_msg;
} bp_acme_exchange_t;

/// Metadata for an entire file
typedef struct {
    /// Map from a bundle ID (bp_bundle_ident_t) to
    /// exchange (bp_acme_exchange_t) pointer.
    wmem_map_t *exchange;

} bp_acme_history_t;

/// Protocol column name
const char *const proto_name_bp = "BPv7 ACME";

/// Protocol handles
static int proto_bp_acme = -1;
/// Protocol-level data
static bp_acme_history_t *bp_acme_history = NULL;

/// Dissect opaque CBOR data
static dissector_handle_t handle_cbor = NULL;

typedef enum {
    ACME_TOKEN_PART1 = 1,
    ACME_KEY_AUTH_DIGEST = 2,
} AcmeKey;

static int hf_acme_key = -1;
static int hf_token_part1 = -1;
static int hf_key_auth_digest = -1;
static int hf_related_resp = -1;
static int hf_related_chal = -1;
/// Field definitions
static hf_register_info fields[] = {
    {&hf_acme_key, {"Item Key", "bpv7.acme.item_key", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_token_part1, {"Token Part-1", "bpv7.acme.token_part1", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_key_auth_digest, {"Key Auth. Digest", "bpv7.acme.key_auth_digest", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_related_resp, {"Related response bundle", "bpv7.acme.related_resp", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0, NULL, HFILL}},
    {&hf_related_chal, {"Related challenge bundle", "bpv7.acme.related_chall", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0, NULL, HFILL}},
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
    gint offset = 0;

    proto_item_append_text(proto_tree_get_parent(tree), ", ACME Message");

    const gboolean is_req = context->bundle->primary->flags & BP_BUNDLE_USER_APP_ACK;
    tvbuff_t *token_part1 = NULL;
    proto_item *item_token_part1 = NULL;
    proto_item *item_key_auth_digest = NULL;

    wscbor_chunk_t *chunk_msg = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_map(chunk_msg);
    proto_item *item_acme = proto_tree_add_cbor_container(tree, proto_bp_acme, pinfo, tvb, chunk_msg);
    proto_item_append_text(item_acme, ": %s Bundle", is_req ? "Challenge" : "Response");
    proto_tree *tree_acme = proto_item_add_subtree(item_acme, ett_acme);
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_msg)) {
        for (guint64 ix = 0; ix < chunk_msg->head_value; ++ix) {
            wscbor_chunk_t *chunk_key = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
            gint64 *key = wscbor_require_int64(wmem_packet_scope(), chunk_key);
            proto_item *item_key = proto_tree_add_cbor_int64(tree_acme, hf_acme_key, pinfo, tvb, chunk_key, key);
            proto_tree *tree_key = proto_item_add_subtree(item_key, ett_acme_key);

            if (!key) {
                wscbor_skip_next_item(wmem_packet_scope(), tvb, &offset);
                continue;
            }
            switch (*key) {
                case ACME_TOKEN_PART1: {
                    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
                    token_part1 = wscbor_require_bstr(tvb, chunk);
                    item_token_part1 = proto_tree_add_cbor_bstr(tree_key, hf_token_part1, pinfo, tvb, chunk);
                    break;
                }
                case ACME_KEY_AUTH_DIGEST: {
                    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
                    item_key_auth_digest = proto_tree_add_cbor_bstr(tree_key, hf_key_auth_digest, pinfo, tvb, chunk);
                    break;
                }
                default: {
                    guint init_offset = offset;
                    wscbor_skip_next_item(wmem_packet_scope(), tvb, &offset);
                    expert_add_info(pinfo, item_key, &ei_acme_key_unknown);

                    tvbuff_t *tvb_item = tvb_new_subset_length(tvb, init_offset, offset);
                    const int sublen = call_dissector(handle_cbor, tvb_item, pinfo, tree_key);
                    if (sublen > 0) {
                        offset += sublen;
                    }
                    break;
                }
            }
        }
    }

    if (!item_token_part1) {
        expert_add_info(pinfo, item_acme, &ei_no_token_part1);
    }
    if (is_req && item_key_auth_digest) {
        expert_add_info(pinfo, item_acme, &ei_missing_key_auth_hash);
    }
    if (!is_req && !item_key_auth_digest) {
        expert_add_info(pinfo, item_acme, &ei_unexpected_key_auth_hash);
    }

    bp_acme_corr_t *corr = bp_acme_corr_new(wmem_file_scope(), context->bundle);
    bp_acme_bytes_init(wmem_file_scope(), &(corr->token_part1), token_part1);

    bp_acme_exchange_t *exc = wmem_map_lookup(bp_acme_history->exchange, corr);
    if (!exc) {
        exc = wmem_new0(wmem_file_scope(), bp_acme_exchange_t);
        wmem_map_insert(bp_acme_history->exchange, corr, exc);
    }
    else {
        wmem_free(wmem_file_scope(), corr);
    }

    bp_bundle_t **self = (is_req ? &(exc->client_msg) : &(exc->server_msg));
    bp_bundle_t **other = (is_req ? &(exc->server_msg) : &(exc->client_msg));
    if (!*self) {
        *self = context->bundle;
    }
    if (*other) {
        const int hf_related = (is_req ? hf_related_resp : hf_related_chal);
        proto_item *item_rel = proto_tree_add_uint(tree_acme, hf_related, tvb, 0, 0, (*other)->frame_num);
        PROTO_ITEM_SET_GENERATED(item_rel);
    }

    proto_item_set_len(item_acme, offset);
    return offset;
}

/// Clear state when new file scope is entered
static void bp_acme_init(void) {
    bp_acme_history = wmem_new0(wmem_file_scope(), bp_acme_history_t);
    bp_acme_history->exchange = wmem_map_new(wmem_file_scope(), bp_acme_corr_hash, bp_acme_corr_equal);
}

static void bp_acme_cleanup(void) {}

/// Re-initialize after a configuration change
static void bp_acme_reinit_config(void) {}


/// Overall registration of the protocol
void proto_register_bp_acme(void) {
    proto_bp_acme = proto_register_protocol(
        "BP ACME Node ID Validation", /* name */
        "BPv7 ACME", /* short name */
        "bpv7.acme" /* abbrev */
    );
    register_init_routine(&bp_acme_init);
    register_cleanup_routine(&bp_acme_cleanup);

    proto_register_field_array(proto_bp_acme, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_bp_acme);
    expert_register_field_array(expert, expertitems, array_length(expertitems));
}

void proto_reg_handoff_bp_acme(void) {
    handle_cbor = find_dissector("cbor");

    /* Packaged extensions */
    {
        dissector_handle_t hdl = create_dissector_handle(dissect_bp_acme, proto_bp_acme);
        dissector_add_uint("bpv7.admin_record_type", 99, hdl);
    }

    bp_acme_reinit_config();
}
