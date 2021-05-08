
#ifndef WIRESHARK_PLUGIN_SRC_PACKET_BPSEC_H_
#define WIRESHARK_PLUGIN_SRC_PACKET_BPSEC_H_

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <glib.h>

/** Abstract Security Block Security Context Flags.
 * Section 3.6.
 */
typedef enum {
    /// Security Parameters present
    ASB_HAS_PARAMS = 0x01,
} AsbFlag;

/// Parameter/Result dissector lookup
typedef struct {
    /// Security context ID
    gint64 context_id;
    /// Parameter/Result ID
    gint64 type_id;
} bpsec_id_t;

/** Construct a new ID.
 */
bpsec_id_t * bpsec_id_new(wmem_allocator_t *alloc, gint64 context_id, gint64 type_id);

/** Function to match the GDestroyNotify signature.
 */
void bpsec_id_free(wmem_allocator_t *alloc, gpointer ptr);

/** Function to match the GCompareFunc signature.
 */
gboolean bpsec_id_equal(gconstpointer a, gconstpointer b);

/** Function to match the GHashFunc signature.
 */
guint bpsec_id_hash(gconstpointer key);

#endif /* WIRESHARK_PLUGIN_SRC_PACKET_BPSEC_H_ */
