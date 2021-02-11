#ifndef WIRESHARK_PLUGIN_SRC_PACKET_UDPCL_H_
#define WIRESHARK_PLUGIN_SRC_PACKET_UDPCL_H_

/// Keys in the extension map.
/// All are unsigned integers.
typedef enum {
    /// Advertise Node ID
    UDPCL_EXT_NODEID = 0x01,
    /// Fragmented transfer
    UDPCL_EXT_TRANSFER = 0x02,
    /// Client-initiated DTLS
    UDPCL_EXT_STARTTLS = 0x05,
} UdpclExtensionType;

#endif /* WIRESHARK_PLUGIN_SRC_PACKET_UDPCL_H_ */
