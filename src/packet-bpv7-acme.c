#include <epan/dissectors/packet-bpv7.h>
#include <epan/wscbor.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <wsutil/utf8_entities.h>
#include <stdio.h>
#include <inttypes.h>

typedef struct {
    void *data;
    guint64 len;
} bp_acme_bytes_t;

static GBytes * bp_acme_bytes_init(tvbuff_t *tvb) {
    if (tvb) {
        const gsize len = tvb_reported_length(tvb);
        gpointer data = tvb_memdup(NULL, tvb, 0, len);
        return g_bytes_new_take(data, len);
    }
    else {
        return NULL;
    }
}

/// Challenge--response correlation
typedef struct {
    /// ACME id-chal as a nonce
    GBytes *id_chal;
    /// ACME token-bundle as a nonce
    GBytes *token_bundle;
    /// EID of the challenge source or response destination
    address server_nodeid;
    /// EID of the challenge source or response destination
    address client_nodeid;
} bp_acme_corr_t;

static bp_acme_corr_t * bp_acme_corr_new(wmem_allocator_t *alloc, const bp_bundle_t *bundle) {
    bp_acme_corr_t *obj = wmem_new0(alloc, bp_acme_corr_t);
    const gboolean is_req = bundle->primary->flags & BP_BUNDLE_USER_APP_ACK;
    if (is_req) {
        copy_address_shallow(&(obj->server_nodeid), &(bundle->primary->src_nodeid->uri));
        copy_address_shallow(&(obj->client_nodeid), &(bundle->primary->dst_eid->uri));
    }
    else {
        copy_address_shallow(&(obj->client_nodeid), &(bundle->primary->src_nodeid->uri));
        copy_address_shallow(&(obj->server_nodeid), &(bundle->primary->dst_eid->uri));

    }
    return obj;
}

static void bp_acme_corr_free(wmem_allocator_t *alloc, bp_acme_corr_t *obj) {
    g_bytes_unref(obj->id_chal);
    g_bytes_unref(obj->token_bundle);
    wmem_free(alloc, obj);
}

/** Function to match the GCompareFunc signature.
 */
static gboolean bp_acme_corr_equal(gconstpointer a, gconstpointer b) {
    const bp_acme_corr_t *aobj = a;
    const bp_acme_corr_t *bobj = b;
    return (
        addresses_equal(&(aobj->server_nodeid), &(bobj->server_nodeid))
        && g_bytes_equal(&(aobj->id_chal), &(bobj->id_chal))
        && g_bytes_equal(&(aobj->token_bundle), &(bobj->token_bundle))
    );
}

/** Function to match the GHashFunc signature.
 */
static guint bp_acme_corr_hash(gconstpointer key) {
    const bp_acme_corr_t *obj = key;
    return (
        add_address_to_hash(0, &(obj->server_nodeid))
        ^ g_bytes_hash(obj->id_chal)
        ^ g_bytes_hash(obj->token_bundle)
    );
}

/// Challenge--response pair
typedef struct {
    bp_bundle_t *server_msg;
    bp_bundle_t *client_msg;
    /// Priority list of acceptable alg ID (GVariant *)
    wmem_list_t *req_algs;
} bp_acme_exchange_t;

/// Metadata for an entire file
typedef struct {
    /// Map from a correlation ID (bp_acme_corr_t*) to
    /// exchange (bp_acme_exchange_t) pointer.
    wmem_map_t *exchange;

} bp_acme_history_t;

/// Match the GFunc signature
static void gvariant_free(gpointer value, gpointer user_data _U_) {
    g_variant_unref((GVariant*)value);
}

static void bp_acme_alg_list_free(wmem_list_t *list) {
    wmem_list_foreach(list, gvariant_free, NULL);
    wmem_destroy_list(list);
}

/** Function to match the GHFunc signature.
 */
static void bp_acme_history_cleanup(gpointer key, gpointer value, gpointer user_data) {
    bp_acme_corr_t *corr = key;
    bp_acme_exchange_t *exc = value;
    wmem_allocator_t *alloc = user_data;

    bp_acme_corr_free(alloc, corr);
    if (exc->req_algs) {
        bp_acme_alg_list_free(exc->req_algs);
    }
}

static proto_item * proto_tree_add_bytes_base64url(proto_tree *tree, int hfindex, tvbuff_t *tvb,
                                         gint start, gint length) {
    if (length < 0) {
        length = tvb_reported_length(tvb);
    }
    void *data = tvb_memdup(wmem_packet_scope(), tvb, start, length);
    gchar *str = g_base64_encode((guint8 *)data, length);
    // convert to base64url
    for (gchar *it = str; *it != '\0'; ++it) {
        switch (*it) {
            case '+':
                *it = '-';
                break;
            case '/':
                *it = '_';
                break;
            case '=':
                *it = '\0';
                break;
        }
    }
    proto_item *item = proto_tree_add_string(tree, hfindex, tvb, start, length, str);
    g_free(str);
    wmem_free(wmem_packet_scope(), data);
    return item;
}

/// Protocol handles
static int proto_bp_acme = -1;
/// Protocol-level data
static bp_acme_history_t *bp_acme_history = NULL;

/// Dissect opaque CBOR data
static dissector_handle_t handle_cbor = NULL;
static dissector_handle_t handle_cose_alg = NULL;

typedef enum {
    ACME_ID_CHAL = 1,
    ACME_TOKEN_BUNDLE = 2,
    ACME_KEY_AUTH_DIGEST = 3,
    ACME_HASH_LIST = 4,
} AcmeKey;

static const val64_string key_vals[] = {
    {1, "id-chal"},
    {2, "token-bundle" },
    {3, "key-auth-digest" },
    {4, "hash-list" },
    {0, NULL }
};

static int hf_acme_key = -1;
static int hf_id_chal = -1;
static int hf_token_bundle = -1;
static int hf_key_auth = -1;
static int hf_key_auth_digest = -1;
static int hf_hash_list = -1;
//static int hf_hash_alg_tstr = -1;
static int hf_as_b64 = -1;
static int hf_related_resp = -1;
static int hf_related_chal = -1;
/// Field definitions
static hf_register_info fields[] = {
    {&hf_acme_key, {"Item Key", "bpv7.acme.item_key", FT_INT64, BASE_DEC|BASE_VAL64_STRING, VALS64(key_vals), 0x0, NULL, HFILL}},
    {&hf_id_chal, {"Validation id-chal", "bpv7.acme.id_chal", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_token_bundle, {"Validation token-bundle", "bpv7.acme.token_bundle", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_key_auth, {"Key Authorization", "bpv7.acme.key_auth", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_key_auth_digest, {"Hash Value", "bpv7.acme.key_auth_digest", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_hash_list, {"Acceptable Hash List, Count", "bpv7.acme.hash_list", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_as_b64, {"Data as base64url", "bpv7.acme.b64", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_related_resp, {"Related response bundle", "bpv7.acme.related_resp", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0, NULL, HFILL}},
    {&hf_related_chal, {"Related challenge bundle", "bpv7.acme.related_chall", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0, NULL, HFILL}},
};

static int ett_acme = -1;
static int ett_acme_key = -1;
static int ett_hash_list = -1;
static int ett_key_auth = -1;
/// Tree structures
static int *ett[] = {
    &ett_acme,
    &ett_acme_key,
    &ett_hash_list,
    &ett_key_auth,
};

static expert_field ei_acme_key_unknown = EI_INIT;
static expert_field ei_no_id_chal = EI_INIT;
static expert_field ei_no_token_bundle = EI_INIT;
static expert_field ei_missing_hash_list = EI_INIT;
static expert_field ei_unexpected_key_auth_hash = EI_INIT;
static expert_field ei_missing_key_auth = EI_INIT;
static expert_field ei_unacceptable_hash_alg = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_acme_key_unknown, {"bpv7.acme.key_unknown", PI_UNDECODED, PI_WARN, "Unknown key code", EXPFILL}},
    {&ei_no_id_chal, {"bpv7.acme.no_id_chal", PI_PROTOCOL, PI_ERROR, "Missing id-chal", EXPFILL}},
    {&ei_no_token_bundle, {"bpv7.acme.no_token_bundle", PI_PROTOCOL, PI_ERROR, "Missing token-bundle", EXPFILL}},
    {&ei_missing_hash_list, {"bpv7.acme.missing_hash_list", PI_PROTOCOL, PI_ERROR, "Missing acceptable hash list", EXPFILL}},
    {&ei_unexpected_key_auth_hash, {"bpv7.acme.unexpected_key_auth_hash", PI_PROTOCOL, PI_ERROR, "Unexpected key authorization hash", EXPFILL}},
    {&ei_missing_key_auth, {"bpv7.acme.missing_key_auth", PI_PROTOCOL, PI_ERROR, "Missing key authorization hash", EXPFILL}},
    {&ei_unacceptable_hash_alg, {"bpv7.acme.unacceptable_hash_alg", PI_PROTOCOL, PI_WARN, "Unacceptable key authorization hash", EXPFILL}},
};

static void dissect_value_alg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint *offset, GVariant **value) {
    if (value) {
        *value = NULL;
    }
    tvbuff_t *subtvb = tvb_new_subset_remaining(tvb, *offset);
    int sublen = 0;
    if (handle_cose_alg) {
        sublen = call_dissector_only(handle_cose_alg, subtvb, pinfo, tree, value);
    }
    if (sublen == 0) {
        sublen = call_dissector_only(handle_cbor, subtvb, pinfo, tree, value);
    }
    if (sublen > 0) {
        *offset += sublen;
    }
}

static int dissect_bp_acme(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    bp_dissector_data_t *context = (bp_dissector_data_t *)data;
    if (!context) {
        return -1;
    }
    gint offset = 0;

    proto_item_append_text(proto_tree_get_parent(tree), ", ACME Validation");

    const gboolean is_req = context->bundle->primary->flags & BP_BUNDLE_USER_APP_ACK;
    proto_item *item_id_chal = NULL;
    proto_item *item_token_bundle = NULL;
    proto_item *item_key_auth = NULL;
    proto_item *item_hash_list = NULL;

    bp_acme_corr_t *corr = bp_acme_corr_new(wmem_file_scope(), context->bundle);
    wmem_list_t *req_algs = NULL;
    GVariant *resp_alg = NULL;

    wscbor_chunk_t *chunk_msg = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_map(chunk_msg);
    proto_item *item_acme = proto_tree_add_cbor_container(tree, proto_bp_acme, pinfo, tvb, chunk_msg);
    proto_tree *tree_acme = proto_item_add_subtree(item_acme, ett_acme);

    const char *name = wmem_strdup_printf(pinfo->pool, "ACME %s Bundle", is_req ? "Challenge" : "Response");
    proto_item_append_text(item_acme, ": %s", name);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", name);

    if (!wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_msg)) {
        for (guint64 ix = 0; ix < chunk_msg->head_value; ++ix) {
            wscbor_chunk_t *chunk_key = wscbor_chunk_read(pinfo->pool, tvb, &offset);
            gint64 *key = wscbor_require_int64(pinfo->pool, chunk_key);
            proto_item *item_key = proto_tree_add_cbor_int64(tree_acme, hf_acme_key, pinfo, tvb, chunk_key, key);
            proto_tree *tree_key = proto_item_add_subtree(item_key, ett_acme_key);

            if (!key) {
                wscbor_skip_next_item(pinfo->pool, tvb, &offset);
                continue;
            }
            switch (*key) {
                case ACME_ID_CHAL: {
                    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
                    tvbuff_t *data = wscbor_require_bstr(pinfo->pool, chunk);
                    item_id_chal = proto_tree_add_cbor_bstr(tree_key, hf_id_chal, pinfo, tvb, chunk);
                    PROTO_ITEM_SET_GENERATED(
                        proto_tree_add_bytes_base64url(tree_key, hf_as_b64, data, 0, -1)
                    );
                    corr->id_chal = bp_acme_bytes_init(data);
                    break;
                }
                case ACME_TOKEN_BUNDLE: {
                    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
                    tvbuff_t *data = wscbor_require_bstr(pinfo->pool, chunk);
                    item_token_bundle = proto_tree_add_cbor_bstr(tree_key, hf_token_bundle, pinfo, tvb, chunk);
                    PROTO_ITEM_SET_GENERATED(
                        proto_tree_add_bytes_base64url(tree_key, hf_as_b64, data, 0, -1)
                    );
                    corr->token_bundle = bp_acme_bytes_init(data);
                    break;
                }
                case ACME_KEY_AUTH_DIGEST: {
                    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
                    wscbor_require_array_size(chunk, 2, 2);
                    item_key_auth = proto_tree_add_cbor_container(tree_key, hf_key_auth, pinfo, tvb, chunk);
                    if (!wscbor_has_errors(chunk)) {
                        proto_tree *tree_digest = proto_item_add_subtree(item_key_auth, ett_hash_list);

                        dissect_value_alg(tvb, pinfo, tree_digest, &offset, &resp_alg);

                        chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
                        tvbuff_t *data = wscbor_require_bstr(pinfo->pool, chunk);
                        proto_tree_add_cbor_bstr(tree_digest, hf_key_auth_digest, pinfo, tvb, chunk);
                        PROTO_ITEM_SET_GENERATED(
                                proto_tree_add_bytes_base64url(tree_digest, hf_as_b64, data, 0, -1)
                        );
                    }
                    proto_item_set_end(item_key_auth, tvb, offset);
                    break;
                }
                case ACME_HASH_LIST: {
                    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
                    wscbor_require_array(chunk);
                    item_hash_list = proto_tree_add_cbor_container(tree_key, hf_hash_list, pinfo, tvb, chunk);
                    if (!wscbor_has_errors(chunk)) {
                        const guint64 count = chunk->head_value;
                        proto_tree *tree_list = proto_item_add_subtree(item_hash_list, ett_hash_list);
                        req_algs = wmem_list_new(wmem_file_scope());
                        for (guint64 alg_ix = 0; alg_ix < count; ++alg_ix) {
                            GVariant *algid = NULL;
                            dissect_value_alg(tvb, pinfo, tree_list, &offset, &algid);
                            if (algid) {
                                wmem_list_append(req_algs, algid);
                            }
                        }
                    }
                    proto_item_set_end(item_hash_list, tvb, offset);
                    break;
                }
                default: {
                    guint init_offset = offset;
                    wscbor_skip_next_item(pinfo->pool, tvb, &offset);
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

    bp_acme_exchange_t *exc = wmem_map_lookup(bp_acme_history->exchange, corr);
    if (!exc) {
        exc = wmem_new0(wmem_file_scope(), bp_acme_exchange_t);
        wmem_map_insert(bp_acme_history->exchange, corr, exc);
    }
    else {
        bp_acme_corr_free(wmem_file_scope(), corr);
    }

    if (req_algs) {
        if (!(exc->req_algs)) {
            exc->req_algs = req_algs;
        }
        else {
            bp_acme_alg_list_free(req_algs);
        }
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

    if (!item_id_chal) {
        expert_add_info(pinfo, item_acme, &ei_no_id_chal);
    }
    if (!item_token_bundle) {
        expert_add_info(pinfo, item_acme, &ei_no_token_bundle);
    }
    if (is_req) {
        if (item_key_auth) {
            expert_add_info(pinfo, item_acme, &ei_unexpected_key_auth_hash);
        }
        if (!item_hash_list) {
            expert_add_info(pinfo, item_acme, &ei_missing_hash_list);
        }
    }
    else {
        if (!item_key_auth) {
            expert_add_info(pinfo, item_acme, &ei_missing_key_auth);
        }
        else if (exc->req_algs) {
            wmem_list_frame_t *found =
                wmem_list_find_custom(exc->req_algs, resp_alg, g_variant_compare);
            printf("%s found %p\n", g_variant_print(resp_alg, TRUE), (void*)found);
            if (!found) {
                expert_add_info(pinfo, item_key_auth, &ei_unacceptable_hash_alg);
            }
        }
    }

    if (resp_alg) {
        g_variant_unref(resp_alg);
    }
    proto_item_set_len(item_acme, offset);
    return offset;
}

/// Clear state when new file scope is entered
static void bp_acme_init(void) {
    bp_acme_history = wmem_new0(wmem_file_scope(), bp_acme_history_t);
    bp_acme_history->exchange = wmem_map_new(wmem_file_scope(), bp_acme_corr_hash, bp_acme_corr_equal);
}

static void bp_acme_cleanup(void) {
    wmem_map_foreach(bp_acme_history->exchange, bp_acme_history_cleanup, wmem_file_scope());
}

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
    handle_cose_alg = find_dissector("cose.alg");

    /* Packaged extensions */
    {
        guint64 *key = g_new(guint64, 1);
        *key = 65536;
        dissector_handle_t hdl = create_dissector_handle(dissect_bp_acme, proto_bp_acme);
        dissector_add_custom_table_handle("bpv7.admin_record_type", key, hdl);
    }

    bp_acme_reinit_config();
}
