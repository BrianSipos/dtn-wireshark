#ifndef __PACKET_COSE_H__
#define __PACKET_COSE_H__

#include <glib.h>

/**
 * COSE message dissectors are registered multiple ways:
 * 1. The unit-keyed dissector table "cose.msgtag" with keys being
 *    IANA-registered CBOR tag values (e.g., 18 is COSE_Sign1).
 * 2. The string-keyed dissector table "media_type" with keys being
 *    IANA-registered media type IDs
 *    (e.g., application/cose; cose-type="cose-sign1" is COSE_Sign1).
 * 3. The registered dissectors for names "cose" and message names in
 *    all-lowercase form (e.g., "cose_sign1").
 * There is currently no CoAP dissector table to register with.
 *
 * COSE message dissectors use the tag (wscbor_tag_t *) value, if used to
 * discriminate the message type, as the user data pointer.
 *
 * COSE header label dissectors are registered with the dissector table
 * "cose.header" and key parameter dissectors with the table "cose.keyparam"
 * both with cose_param_key_t* keys.
 * The header/parameter dissectors use a cose_header_context_t* as the user
 * data pointer.
 *
 * An additional dissector "cose.msg.headers" will dissect an individual
 * header map structure outside of a COSE message.
 */

// A header parameter or key-type parameter key
typedef struct {
    /// The Algorithm or Key Type context or NULL for
    /// all-context keys.
    GVariant *principal;

    /// Label simple value (int or tstr) as variant.
    /// Object owned by this struct.
    GVariant *label;
} cose_param_key_t;

/** Compatible with GHashFunc signature.
 */
guint cose_param_key_hash(gconstpointer ptr);

/** Compatible with GEqualFunc signature.
 */
gboolean cose_param_key_equal(gconstpointer a, gconstpointer b);

/// User data for header/key-parameter dissectors
typedef struct {
    /// Principal value (alg or kty) of the map, if defined.
    GVariant *principal;
    /// Current label being processed
    GVariant *label;
} cose_header_context_t;

#endif /* __PACKET_COSE_H__ */
