
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

/// A data-containing, optionally-tagged chunk of CBOR
typedef struct {
    /// The start offset of this chunk
    gint start;
    /// The length of just this header any any preceding tags
    gint head_length;
    /// The length of this chunk and its immediate definite data (i.e. strings)
    gint data_length;
    /// Additional blocks in order (type expert_field*)
    wmem_list_t *errors;
    /// Additional blocks in order (type guint64)
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
 */
bp_cbor_chunk_t * bp_cbor_chunk_read(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset);

void bp_cbor_chunk_mark_errors(packet_info *pinfo, proto_item *item, const bp_cbor_chunk_t *chunk);

/** Function to match the GDestroyNotify signature.
 */
void bp_cbor_chunk_free(wmem_allocator_t *alloc, bp_cbor_chunk_t *chunk);

/** Determine if an indefinite break is present.
 *
 * @param chunk The chunk to check.
 * @return True if it's an indefinite break.
 */
gboolean cbor_is_indefinite_break(const bp_cbor_chunk_t *chunk);

/** Recursively skip items from a stream.
 *
 * @param tvb The data buffer.
 * @param offset The initial offset to read and skip over.
 * @return True if the skipped item was an indefinite break.
 */
gboolean cbor_skip_next_item(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset);

/** Require an array item.
 *
 * @return The array head chunk or NULL.
 */
bp_cbor_chunk_t * cbor_read_head_array(wmem_allocator_t *alloc, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, gint *offset);

/** Make some assertions about a CBOR array.
 *
 * @param[in,out] offset The starting offset within @c tvb.
 * @param count_read The number of items read so far.
 * @param count_min The minimum required array size.
 * @param count_max The maximum required array size.
 * @return The array header chunk, if the array is valid.
 * The chunk can be deleted with bp_cbor_chunk_delete().
 */
bp_cbor_chunk_t * cbor_read_head_array_with_size(wmem_allocator_t *alloc, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, gint *offset, guint64 count_min, guint64 count_max);

/** Require a map item.
 *
 * @return The array head chunk or NULL.
 */
bp_cbor_chunk_t * cbor_read_head_map(wmem_allocator_t *alloc, tvbuff_t *tvb, packet_info *pinfo, proto_item *item, gint *offset);


/** Require a known array have a specific ranged size.
 *
 * @param count_min The minimum acceptable size.
 * @param count_max The maximum acceptable size.
 * @return The true if the size is acceptable.
 */
gboolean cbor_require_array_size(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, const bp_cbor_chunk_t *head, guint64 count_min, guint64 count_max);

/** Require a CBOR item to have a boolean value.
 *
 * @param chunk The chunk to read from.
 * @return Pointer to the boolean value, if the item was boolean.
 * The value can be deleted with bp_cbor_require_delete().
 */
gboolean * cbor_require_boolean(wmem_allocator_t *alloc, const bp_cbor_chunk_t *chunk);

/** Require a CBOR item to have an unsigned-integer value.
 * @note This reader will clip the most significant bit of the value.
 *
 * @param chunk The chunk to read from.
 * @return Pointer to the boolean value, if the item was an integer.
 * The value can be deleted with bp_cbor_require_delete().
 */
guint64 * cbor_require_uint64(wmem_allocator_t *alloc, const bp_cbor_chunk_t *chunk);

/** Require a CBOR item to have an signed- or unsigned-integer value.
 * @note This reader will clip the most significant bit of the value.
 *
 * @param chunk The chunk to read from.
 * @return Pointer to the value, if the item was an integer.
 * The value can be deleted with bp_cbor_require_delete().
 */
gint64 * cbor_require_int64(wmem_allocator_t *alloc, const bp_cbor_chunk_t *chunk);

/** Require a CBOR item to have a text- or byte-string value.
 *
 * @param parent The containing buffer.
 * @param chunk The chunk to read size from.
 * @return Pointer to the value, if the item was an string.
 * The value is memory managed by wireshark.
 */
tvbuff_t * cbor_require_string(tvbuff_t *parent, const bp_cbor_chunk_t *chunk);

proto_item * proto_tree_add_cbor_boolean(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const gboolean *value);

proto_item * proto_tree_add_cbor_uint64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const guint64 *value);

proto_item * proto_tree_add_cbor_int64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const gint64 *value);

proto_item * proto_tree_add_cbor_bitmask(proto_tree *tree, int hfindex, const gint ett, WS_FIELDTYPE *fields, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const guint64 *value);

proto_item * proto_tree_add_cbor_string(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *head);

#ifdef __cplusplus
}
#endif

#endif /* WIRESHARK_PLUGIN_SRC_BP_CBOR_H_ */
