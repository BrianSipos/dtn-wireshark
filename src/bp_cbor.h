
#ifndef WIRESHARK_PLUGIN_SRC_BP_CBOR_H_
#define WIRESHARK_PLUGIN_SRC_BP_CBOR_H_

#include <ws_symbol_export.h>
#include <epan/tvbuff.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/wmem/wmem_list.h>

#if defined(WIRESHARK_NEW_FLAGSPTR)
#define WS_FIELDTYPE int *const
#else
#define WS_FIELDTYPE const int *
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern expert_field ei_cbor_wrong_type;
extern expert_field ei_cbor_array_wrong_size;
extern expert_field ei_item_missing;

/** Register expert info and other wireshark data.
 * @param expert The parent module object.
 */
void bp_cbor_init(expert_module_t *expert);

/// The basic header structure of CBOR encoding
typedef struct {
    /// The start offset of this header
    gint start;
    /// The length of just this header
    gint length;
    /// The expert info object (if error)
    expert_field *error;

    /// Major type of this item (cbor_type)
    guint8 type_major;
    /// Minor type of this item
    guint8 type_minor;
    /// Raw head "value" which may be from the @c type_minor
    guint64 rawvalue;
} bp_cbor_head_t;

/** Read just the CBOR head integer.
 */
bp_cbor_head_t * bp_cbor_head_read(wmem_allocator_t *alloc, tvbuff_t *tvb, gint start);

/** Force a head to be freed.
 */
void bp_cbor_head_free(wmem_allocator_t *alloc, bp_cbor_head_t *head);

/// The same enumeration from libcbor-0.5
typedef enum cbor_type {
    CBOR_TYPE_UINT = 0, ///< positive integers
    CBOR_TYPE_NEGINT = 1, ///< negative integers
    CBOR_TYPE_BYTESTRING = 2, ///< byte strings
    CBOR_TYPE_STRING = 3, ///< text strings
    CBOR_TYPE_ARRAY = 4, ///< arrays
    CBOR_TYPE_MAP = 5, ///< maps
    CBOR_TYPE_TAG = 6, ///< tags
    CBOR_TYPE_FLOAT_CTRL = 7, ///< decimals and special values (true, false, nil, ...)
} cbor_type;

/// The same enumeration from libcbor-0.5
typedef enum {
    CBOR_CTRL_NONE = 0,
    CBOR_CTRL_FALSE = 20,
    CBOR_CTRL_TRUE = 21,
    CBOR_CTRL_NULL = 22,
    CBOR_CTRL_UNDEF = 23
} _cbor_ctrl;

/// Decoding or require_* error
typedef struct {
    /// The associated expert info
    expert_field *ei;
    /// Optional specific text
    const char *msg;
} bp_cbor_error_t;

/** Construct a new error object.
 *
 * @param alloc The allocator to use.
 * @param ei The specific error type.
 * @param format If non-NULL, a message format string.
 * @return The new object.
 */
bp_cbor_error_t * bp_cbor_error_new(wmem_allocator_t *alloc, expert_field *ei, const char *format, ...);

/// A data-containing, optionally-tagged chunk of CBOR
typedef struct {
    /// The allocator used for #errors and #tags
    wmem_allocator_t *_alloc;

    /// The start offset of this chunk
    gint start;
    /// The length of just this header any any preceding tags
    gint head_length;
    /// The length of this chunk and its immediate definite data (i.e. strings)
    gint data_length;
    /// Errors processing this chunk (type bp_cbor_error_t*)
    wmem_list_t *errors;
    /// Tags on this chunk, in encoded order (type guint64*)
    wmem_list_t *tags;

    /// Major type of this block.
    /// This will be one of the cbor_type values.
    cbor_type type_major;
    /// Minor type of this item
    guint8 type_minor;
    /// The header-encoded value
    guint64 head_value;
} bp_cbor_chunk_t;

/** Scan for a tagged chunk of headers.
 * The chunk of byte string and text string items includes the data content
 * in its @c offset.
 *
 * @param alloc The allocator to use.
 * @param tvb The TVB to read from.
 * @param[in,out] offset The offset with in @c tvb.
 * @return The chunk of data found, including any errors.
 * This never returns NULL.
 */
bp_cbor_chunk_t * bp_cbor_chunk_read(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset);

/** Free a chunk and its lists.
 */
void bp_cbor_chunk_free(bp_cbor_chunk_t *chunk);

/** After both reading and decoding a chunk, report on any errors found.
 * @param pinfo The associated packet.
 * @param item The associated tree item.
 * @param chunk The chunk with possible errors.
 */
void bp_cbor_chunk_mark_errors(packet_info *pinfo, proto_item *item, const bp_cbor_chunk_t *chunk);

/** Determine if a chunk has errors.
 * @param chunk The chunk with possible errors.
 * @return The error count.
 */
guint64 bp_cbor_has_errors(const bp_cbor_chunk_t *chunk);

/** Determine if an indefinite break is present.
 *
 * @param chunk The chunk to check.
 * @return True if it's an indefinite break.
 */
gboolean bp_cbor_is_indefinite_break(const bp_cbor_chunk_t *chunk);

/** Recursively skip items from a stream.
 *
 * @param alloc The allocator to use.
 * @param tvb The data buffer.
 * @param[in,out] offset The initial offset to read and skip over.
 * @return True if the skipped item was an indefinite break.
 */
gboolean bp_cbor_skip_next_item(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset);

/** Skip over an item if a chunk has errors.
 *
 * @param alloc The allocator to use.
 * @param tvb The data buffer.
 * @param[in,out] offset The initial offset to read and skip over.
 * @param chunk The chunk with possible errors.
 * @return True if there were errors and the item skipped.
 */
gboolean bp_cbor_skip_if_errors(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset, const bp_cbor_chunk_t *chunk);


/** Require a specific item major type.
 *
 * @param[in,out] chunk The chunk to check (and mark errors on).
 * @param major The required major type.
 * @return True if the item is that type.
 */
gboolean cbor_require_major_type(bp_cbor_chunk_t *chunk, cbor_type major);

/** Require an array item.
 *
 * @param[in,out] chunk The chunk to check (and mark errors on).
 * @return True if the item is an array.
 */
gboolean cbor_require_array(bp_cbor_chunk_t *chunk);

/** Require an array have a specific ranged size.
 *
 * @param[in,out] chunk The chunk to check (and mark errors on).
 * @param count_min The minimum acceptable size.
 * @param count_max The maximum acceptable size.
 * @return True if the size is acceptable.
 */
gboolean cbor_require_array_size(bp_cbor_chunk_t *chunk, guint64 count_min, guint64 count_max);

/** Require a map item.
 *
 * @param[in,out] chunk The chunk to check (and mark errors on).
 * @return True if the item is a map.
 */
gboolean cbor_require_map(bp_cbor_chunk_t *chunk);

/** Require a CBOR item to have a boolean value.
 *
 * @param chunk The chunk to read from.
 * @return Pointer to the boolean value, if the item was boolean.
 * The value can be deleted with bp_cbor_require_delete().
 */
gboolean * cbor_require_boolean(wmem_allocator_t *alloc, bp_cbor_chunk_t *chunk);

/** Require a CBOR item to have an unsigned-integer value.
 * @note This reader will clip the most significant bit of the value.
 *
 * @param chunk The chunk to read from.
 * @return Pointer to the boolean value, if the item was an integer.
 * The value can be deleted with bp_cbor_require_delete().
 */
guint64 * cbor_require_uint64(wmem_allocator_t *alloc, bp_cbor_chunk_t *chunk);

/** Require a CBOR item to have an signed- or unsigned-integer value.
 * @note This reader will clip the most significant bit of the value.
 *
 * @param chunk The chunk to read from.
 * @return Pointer to the value, if the item was an integer.
 * The value can be deleted with bp_cbor_require_delete().
 */
gint64 * cbor_require_int64(wmem_allocator_t *alloc, bp_cbor_chunk_t *chunk);

/** Require a CBOR item to have a text- or byte-string value.
 *
 * @param parent The containing buffer.
 * @param chunk The chunk to read size from.
 * @return Pointer to the value, if the item was an string.
 * The value is memory managed by wireshark.
 */
tvbuff_t * cbor_require_string(tvbuff_t *parent, bp_cbor_chunk_t *chunk);


proto_item * proto_tree_add_cbor_container(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk);

proto_item * proto_tree_add_cbor_boolean(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const gboolean *value);

proto_item * proto_tree_add_cbor_uint64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const guint64 *value);

proto_item * proto_tree_add_cbor_int64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const gint64 *value);

proto_item * proto_tree_add_cbor_bitmask(proto_tree *tree, int hfindex, const gint ett, WS_FIELDTYPE *fields, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const guint64 *value);

proto_item * proto_tree_add_cbor_string(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *head);

#ifdef __cplusplus
}
#endif

#endif /* WIRESHARK_PLUGIN_SRC_BP_CBOR_H_ */
