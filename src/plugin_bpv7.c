
#include <ws_symbol_export.h>
#include <epan/proto.h>
#if defined(WIRESHARK_HAS_VERSION_H)
#include <ws_version.h>
#else
#include <config.h>
#define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
#define WIRESHARK_VERSION_MINOR VERSION_MINOR
#endif

void proto_register_bp_acme(void);
void proto_reg_handoff_bp_acme(void);
void proto_register_bpsec_cose(void);
void proto_reg_handoff_bpsec_cose(void);

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
    {
        static proto_plugin plugin_bp_acme;
        plugin_bp_acme.register_protoinfo = proto_register_bp_acme;
        plugin_bp_acme.register_handoff = proto_reg_handoff_bp_acme;
        proto_register_plugin(&plugin_bp_acme);
    }
    {
        static proto_plugin plugin_bpsec_cose;
        plugin_bpsec_cose.register_protoinfo = proto_register_bpsec_cose;
        plugin_bpsec_cose.register_handoff = proto_reg_handoff_bpsec_cose;
        proto_register_plugin(&plugin_bpsec_cose);
    }
}
