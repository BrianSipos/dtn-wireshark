#ifndef WIRESHARK_PLUGIN_SRC_PACKET_UDPCL_H_
#define WIRESHARK_PLUGIN_SRC_PACKET_UDPCL_H_

/// Keys in the extension map.
/// All are unsigned integers.
typedef enum {
    UDPCL_EXT_RESERVED = 0,
    /// Fragmented transfer
    UDPCL_EXT_TRANSFER = 2,
    /// Return-Path Accept
    UDPCL_EXT_RETURN_ACCEPT = 3,
    /// Sender Node ID
    UDPCL_EXT_NODEID = 4,
    /// Client-initiated DTLS
    UDPCL_EXT_STARTTLS = 5,
} UdpclExtensionType;

#endif /* WIRESHARK_PLUGIN_SRC_PACKET_UDPCL_H_ */
