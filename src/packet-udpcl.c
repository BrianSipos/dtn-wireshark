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
static dissector_handle_t handle_bp = NULL;

/// Dissect opaque CBOR parameters/results
static dissector_table_t dissect_media = NULL;

static int hf_udpcl = -1;
static int hf_padding = -1;
/// Field definitions
static hf_register_info fields[] = {
    {&hf_udpcl, {"UDP Convergence Layer", "udpcl", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_padding, {"padding", "udpcl.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
};

static int ett_udpcl = -1;
/// Tree structures
static int *ett[] = {
    &ett_udpcl,
};

static expert_field ei_pad_nonzero = EI_INIT;
static expert_field ei_pad_size = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_pad_nonzero, { "udpcl.padding.nonzero", PI_MALFORMED, PI_WARN, "Padding has non-zero octet", EXPFILL}},
    {&ei_pad_size, { "udpcl.padding.size", PI_MALFORMED, PI_WARN, "Padding has size other than 4", EXPFILL}},
};

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
    proto_item *item_udpcl = proto_tree_add_item(tree, hf_udpcl, tvb, 0, 0, ENC_NA);
    proto_tree *tree_udpcl = proto_item_add_subtree(item_udpcl, ett_udpcl);

    col_append_str(pinfo->cinfo, COL_INFO, "UDPCL");

    if (tvb_get_gint8(tvb, 0) == '\0') {
        proto_item *item_pad = proto_tree_add_item(tree_udpcl, hf_udpcl, tvb, 0, buflen, ENC_NA);
        expert_add_info(pinfo, item_pad, &ei_pad_size);

        for (guint ix = 1; ix < buflen; ++ix) {
            if (tvb_get_gint8(tvb, ix) != '\0') {
                expert_add_info(pinfo, item_pad, &ei_pad_nonzero);
                break;
            }
        }

    }
    else {
        // A real bundle
        col_append_str(pinfo->cinfo, COL_INFO, " [Bundle]");
        gint sublen = 0;

        if (udpcl_decode_bundle) {
            if (handle_bp) {
                sublen = call_dissector(
                    handle_bp,
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
                    data
                );
            }
        }
        if (sublen == 0) {
            call_data_dissector(
                tvb,
                pinfo,
                tree
            );
        }
    }

    return buflen;
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
}

static void proto_reg_handoff_udpcl(void) {
    g_log(LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "proto_reg_handoff_udpcl()\n");
    dissector_add_uint_with_preference("udp.port", UDPCL_PORT_NUM, handle_udpcl);

    dissect_media = find_dissector_table("media_type");
    handle_bp = find_dissector_add_dependency("bpv7", proto_udpcl);

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
