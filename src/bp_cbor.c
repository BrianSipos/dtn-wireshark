#include "bp_cbor.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <stdio.h>
#include <inttypes.h>

static expert_field ei_cbor_invalid = EI_INIT;
static expert_field ei_cbor_overflow = EI_INIT;
expert_field ei_cbor_wrong_type = EI_INIT;
expert_field ei_cbor_array_wrong_size = EI_INIT;
expert_field ei_item_missing = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_cbor_invalid, {"bp_cbor.cbor_invalid", PI_MALFORMED, PI_ERROR, "CBOR cannot be decoded", EXPFILL}},
    {&ei_cbor_overflow, {"bp_cbor.cbor_overflow", PI_UNDECODED, PI_ERROR, "CBOR overflow of Wireshark value", EXPFILL}},
    {&ei_cbor_wrong_type, {"bp_cbor.cbor_wrong_type", PI_MALFORMED, PI_ERROR, "CBOR is wrong type", EXPFILL}},
    {&ei_cbor_array_wrong_size, {"bp_cbor.array_wrong_size", PI_MALFORMED, PI_WARN, "CBOR array is the wrong size", EXPFILL}},
    {&ei_item_missing, {"bp_cbor.item_missing", PI_MALFORMED, PI_ERROR, "CBOR item is missing or incorrect type", EXPFILL}},
};

/** Read the raw value from a CBOR head.
 * @param[in,out] head The head to read into.
 * @param tvb The buffer to read from.
 */
static void bp_cbor_read_unsigned(bp_cbor_head_t *head, tvbuff_t *tvb) {
    switch (head->type_minor) {
        case 0x18:
            head->rawvalue = tvb_get_guint8(tvb, head->start + head->length);
            head->length += 1;
            break;
        case 0x19:
            head->rawvalue = tvb_get_guint16(tvb, head->start + head->length, ENC_BIG_ENDIAN);
            head->length += 2;
            break;
        case 0x1A:
            head->rawvalue = tvb_get_guint32(tvb, head->start + head->length, ENC_BIG_ENDIAN);
            head->length += 4;
            break;
        case 0x1B:
            head->rawvalue = tvb_get_guint64(tvb, head->start + head->length, ENC_BIG_ENDIAN);
            head->length += 8;
            break;
        default:
            if (head->type_minor <= 0x17) {
                head->rawvalue = head->type_minor;
            }
            break;
    }
}

bp_cbor_head_t * bp_cbor_head_read(wmem_allocator_t *alloc, tvbuff_t *tvb, gint start) {
    bp_cbor_head_t *head = wmem_new0(alloc, bp_cbor_head_t);

    head->start = start;
    const guint8 first = tvb_get_guint8(tvb, head->start);
    head->length += 1;

    // Match libcbor enums
    head->type_major = (first & 0xe0) >> 5;
    head->type_minor = (first & 0x1f);
    switch ((cbor_type)(head->type_major)) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NEGINT:
        case CBOR_TYPE_TAG:
            bp_cbor_read_unsigned(head, tvb);
            if (head->type_minor > 0x1B) {
                head->error = &ei_cbor_invalid;
            }
            break;
        case CBOR_TYPE_BYTESTRING:
        case CBOR_TYPE_STRING:
        case CBOR_TYPE_ARRAY:
        case CBOR_TYPE_MAP:
        case CBOR_TYPE_FLOAT_CTRL:
            bp_cbor_read_unsigned(head, tvb);
            if ((head->type_minor > 0x1B) && (head->type_minor < 0x1F)) {
                head->error = &ei_cbor_invalid;
            }
            break;

        default:
            head->error = &ei_cbor_invalid;
            break;
    }

    return head;
}

void bp_cbor_head_free(wmem_allocator_t *alloc, bp_cbor_head_t *head) {
    wmem_free(alloc, head);
}

bp_cbor_error_t * bp_cbor_error_new(wmem_allocator_t *alloc, expert_field *ei, const char *format, ...) {
    bp_cbor_error_t *err = wmem_new0(alloc, bp_cbor_error_t);
    err->ei = ei;
    if (format) {
        wmem_strbuf_t *buf = wmem_strbuf_new(alloc, "");

        va_list ap;
        va_start(ap, format);
        wmem_strbuf_append_vprintf(buf, format, ap);
        va_end(ap);

        err->msg = wmem_strbuf_finalize(buf);
    }
    return err;
}

bp_cbor_chunk_t * bp_cbor_chunk_read(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset) {
    DISSECTOR_ASSERT(alloc != NULL);
    DISSECTOR_ASSERT(offset != NULL);
    DISSECTOR_ASSERT(tvb != NULL);
    const gint buflen = tvb_captured_length(tvb);

    bp_cbor_chunk_t *chunk = wmem_new0(alloc, bp_cbor_chunk_t);
    chunk->_alloc = alloc;
    chunk->errors = wmem_list_new(alloc);
    chunk->tags = wmem_list_new(alloc);
    chunk->start = *offset;

    int used_head = 0;
    while (*offset < buflen) {
        bp_cbor_head_t *head = bp_cbor_head_read(alloc, tvb, *offset);
        if (!head) {
            break;
        }
        *offset += head->length;
        chunk->head_length += head->length;
        if (head->error) {
            wmem_list_append(chunk->errors, bp_cbor_error_new(alloc, head->error, NULL));
        }
        if (head->type_major == CBOR_TYPE_TAG) {
            guint64 *tag = wmem_new(alloc, guint64);
            *tag = head->rawvalue;
            wmem_list_append(chunk->tags, tag);
            // same chunk, next part
            bp_cbor_head_free(alloc, head);
            continue;
        }

        // An actual (non-tag) header
        chunk->type_major = head->type_major;
        chunk->type_minor = head->type_minor;
        chunk->head_value = head->rawvalue;

        chunk->data_length = chunk->head_length;
        switch ((cbor_type)(head->type_major)) {
            case CBOR_TYPE_BYTESTRING:
            case CBOR_TYPE_STRING:
                if (chunk->type_minor != 31) {
                    // skip over definite data
                    *offset += chunk->head_value;
                    chunk->data_length += chunk->head_value;
                }
                break;
            default:
                break;
        }

        used_head += 1;
        bp_cbor_head_free(alloc, head);
        break;
    }

    if (used_head == 0) {
        wmem_list_append(chunk->errors, bp_cbor_error_new(alloc, &ei_item_missing, NULL));
        chunk->type_major = 0xFF;
        chunk->type_minor = 0xFF;
        chunk->head_value = 0;
    }

    return chunk;
}

void bp_cbor_chunk_free(bp_cbor_chunk_t *chunk) {
    DISSECTOR_ASSERT(chunk);
    wmem_allocator_t *alloc = chunk->_alloc;
    wmem_destroy_list(chunk->errors);
    wmem_destroy_list(chunk->tags);
    wmem_free(alloc, chunk);
}

void bp_cbor_chunk_mark_errors(packet_info *pinfo, proto_item *item, const bp_cbor_chunk_t *chunk) {
    for (wmem_list_frame_t *it = wmem_list_head(chunk->errors); it;
            it = wmem_list_frame_next(it)) {
        bp_cbor_error_t *err = wmem_list_frame_data(it);
        if (err->msg) {
            expert_add_info_format(pinfo, item, err->ei, "%s", err->msg);
        }
        else {
            expert_add_info(pinfo, item, err->ei);
        }
    }
}

guint64 bp_cbor_has_errors(const bp_cbor_chunk_t *chunk) {
    return wmem_list_count(chunk->errors);
}

gboolean bp_cbor_is_indefinite_break(const bp_cbor_chunk_t *chunk) {
    return (
        (chunk->type_major == CBOR_TYPE_FLOAT_CTRL)
        && (chunk->type_minor == 31)
    );
}

gboolean bp_cbor_skip_next_item(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset) {
    bp_cbor_chunk_t *chunk = bp_cbor_chunk_read(alloc, tvb, offset);
    switch (chunk->type_major) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NEGINT:
        case CBOR_TYPE_TAG:
        case CBOR_TYPE_FLOAT_CTRL:
            break;
        case CBOR_TYPE_BYTESTRING:
        case CBOR_TYPE_STRING:
            if (chunk->type_minor == 31) {
                // wait for indefinite break
                while (!bp_cbor_skip_next_item(alloc, tvb, offset)) {}
            }
            // bp_cbor_read_chunk() sets offset past definite value
            break;
        case CBOR_TYPE_ARRAY: {
            if (chunk->type_minor == 31) {
                // wait for indefinite break
                while (!bp_cbor_skip_next_item(alloc, tvb, offset)) {}
            }
            else {
                const guint64 count = chunk->head_value;
                for (guint64 ix = 0; ix < count; ++ix) {
                    bp_cbor_skip_next_item(alloc, tvb, offset);
                }
            }
            break;
        }
        case CBOR_TYPE_MAP: {
            if (chunk->type_minor == 31) {
                // wait for indefinite break
                while (!bp_cbor_skip_next_item(alloc, tvb, offset)) {}
            }
            else {
                const guint64 count = chunk->head_value;
                for (guint64 ix = 0; ix < count; ++ix) {
                    bp_cbor_skip_next_item(alloc, tvb, offset);
                    bp_cbor_skip_next_item(alloc, tvb, offset);
                }
            }
            break;
        }
    }
    const gboolean is_break = bp_cbor_is_indefinite_break(chunk);
    bp_cbor_chunk_free(chunk);
    return is_break;
}

gboolean bp_cbor_skip_if_errors(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset, const bp_cbor_chunk_t *chunk) {
    if (bp_cbor_has_errors(chunk) == 0) {
        return FALSE;
    }

    *offset = chunk->start;
    bp_cbor_skip_next_item(alloc, tvb, offset);
    return TRUE;
}

void bp_cbor_init(expert_module_t *expert) {
    expert_register_field_array(expert, expertitems, array_length(expertitems));
}

gboolean cbor_require_major_type(bp_cbor_chunk_t *chunk, cbor_type major) {
    if (chunk->type_major == major) {
        return TRUE;
    }
    wmem_list_append(chunk->errors, bp_cbor_error_new(
            chunk->_alloc, &ei_cbor_wrong_type,
            "Item has major type %d, should be %d",
            chunk->type_major, major
    ));
    return FALSE;
}

gboolean cbor_require_array(bp_cbor_chunk_t *chunk) {
    return cbor_require_major_type(chunk, CBOR_TYPE_ARRAY);
}

gboolean cbor_require_array_size(bp_cbor_chunk_t *chunk, guint64 count_min, guint64 count_max) {
    if (!cbor_require_array(chunk)) {
        return FALSE;
    }
    if ((chunk->head_value < count_min) || (chunk->head_value > count_max)) {
        wmem_list_append(chunk->errors, bp_cbor_error_new(
                chunk->_alloc, &ei_cbor_array_wrong_size,
                "Array has %" PRId64 " items, should be within [%"PRId64", %"PRId64"]",
                chunk->head_value, count_min, count_max
        ));
        return FALSE;
    }
    return TRUE;
}

gboolean cbor_require_map(bp_cbor_chunk_t *chunk) {
    return cbor_require_major_type(chunk, CBOR_TYPE_MAP);
}

gboolean * cbor_require_boolean(wmem_allocator_t *alloc, bp_cbor_chunk_t *chunk) {
    if (!cbor_require_major_type(chunk, CBOR_TYPE_FLOAT_CTRL)) {
        return NULL;
    }

    switch (chunk->type_minor) {
        case CBOR_CTRL_TRUE:
        case CBOR_CTRL_FALSE: {
            gboolean *value = NULL;
            value = wmem_new(alloc, gboolean);
            *value = (chunk->type_minor == CBOR_CTRL_TRUE);
            return value;
        }
        default:
            wmem_list_append(chunk->errors, bp_cbor_error_new(
                    chunk->_alloc, &ei_cbor_wrong_type,
                    "Item has minor type %d, should be %d or %d",
                    chunk->type_minor, CBOR_CTRL_TRUE, CBOR_CTRL_FALSE
            ));
            break;
    }
    return NULL;
}

guint64 * cbor_require_uint64(wmem_allocator_t *alloc, bp_cbor_chunk_t *chunk) {
    if (!cbor_require_major_type(chunk, CBOR_TYPE_UINT)) {
        return NULL;
    }

    guint64 *result = wmem_new(alloc, guint64);
    *result = chunk->head_value;
    return result;
}

gint64 * cbor_require_int64(wmem_allocator_t *alloc, bp_cbor_chunk_t *chunk) {
    gint64 *result = NULL;
    switch (chunk->type_major) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NEGINT: {
            guint64 clamped = chunk->head_value;
            if (clamped > INT64_MAX) {
                clamped = INT64_MAX;
                wmem_list_append(chunk->errors, bp_cbor_error_new(
                        chunk->_alloc, &ei_cbor_overflow,
                        NULL
                ));
            }

            result = wmem_new(alloc, gint64);
            if (chunk->type_major == CBOR_TYPE_NEGINT) {
                *result = -clamped - 1;
            }
            else {
                *result = clamped;
            }
            break;
        }
        default:
            wmem_list_append(chunk->errors, bp_cbor_error_new(
                    chunk->_alloc, &ei_cbor_wrong_type,
                    "Item has major type %d, should be %d or %d",
                    chunk->type_major, CBOR_TYPE_UINT, CBOR_TYPE_NEGINT
            ));
            break;
    }
    return result;
}

char * cbor_require_tstr(wmem_allocator_t *alloc, tvbuff_t *parent, bp_cbor_chunk_t *chunk) {
    if (!cbor_require_major_type(chunk, CBOR_TYPE_STRING)) {
        return NULL;
    }

    return (char *)tvb_get_string_enc(alloc, parent, chunk->start + chunk->head_length, chunk->head_value, ENC_UTF_8);
}

tvbuff_t * cbor_require_bstr(tvbuff_t *parent, bp_cbor_chunk_t *chunk) {
    if (!cbor_require_major_type(chunk, CBOR_TYPE_BYTESTRING)) {
        return NULL;
    }

    return tvb_new_subset_length(parent, chunk->start + chunk->head_length, chunk->head_value);
}

proto_item * proto_tree_add_cbor_container(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk) {
    const header_field_info *hfinfo = proto_registrar_get_nth(hfindex);
    proto_item *item;
    if (IS_FT_UINT(hfinfo->type)) {
        item = proto_tree_add_uint64(tree, hfindex, tvb, chunk->start, chunk->head_length, chunk->head_value);
    }
    else if (IS_FT_INT(hfinfo->type)) {
        item = proto_tree_add_int64(tree, hfindex, tvb, chunk->start, chunk->head_length, chunk->head_value);
    }
    else {
        item = proto_tree_add_item(tree, hfindex, tvb, chunk->start, -1, ENC_NA);
    }
    bp_cbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_ctrl(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk) {
    proto_item *item = proto_tree_add_item(tree, hfindex, tvb, chunk->start, chunk->head_length, ENC_NA);
    bp_cbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_boolean(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const gboolean *value) {
    proto_item *item = proto_tree_add_boolean(tree, hfindex, tvb, chunk->start, chunk->data_length, value ? *value : FALSE);
    bp_cbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_uint64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const guint64 *value) {
    proto_item *item = proto_tree_add_uint64(tree, hfindex, tvb, chunk->start, chunk->head_length, value ? *value : 0);
    bp_cbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_int64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const gint64 *value) {
    proto_item *item = proto_tree_add_int64(tree, hfindex, tvb, chunk->start, chunk->head_length, value ? *value : 0);
    bp_cbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_bitmask(proto_tree *tree, int hfindex, const gint ett, WS_FIELDTYPE *fields, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk, const guint64 *value) {
    header_field_info *field = proto_registrar_get_nth(hfindex);
    size_t flagsize = 0;
    switch (field->type) {
        case FT_UINT8:
            flagsize = 1;
            break;
        case FT_UINT16:
            flagsize = 2;
            break;
        case FT_UINT32:
            flagsize = 4;
            break;
        case FT_UINT64:
            flagsize = 8;
            break;
        default:
            fprintf(stderr, "Unhandled bitmask size: %d", field->type);
            return NULL;
    }

    // Fake TVB data for these functions
    guint8 *flags = wmem_alloc0(wmem_packet_scope(), flagsize);
    { // Inject big-endian value directly
        guint64 buf = (value ? *value : 0);
        for (gint ix = flagsize - 1; ix >= 0; --ix) {
            flags[ix] = buf & 0xFF;
            buf >>= 8;
        }
    }
    tvbuff_t *tvb_flags = tvb_new_child_real_data(tvb, flags, flagsize, flagsize);

    proto_item *item = proto_tree_add_item(tree, hfindex, tvb_flags, 0, flagsize, ENC_BIG_ENDIAN);
    proto_tree *subtree = proto_item_add_subtree(item, ett);
    proto_tree_add_bitmask_list_value(subtree, tvb_flags, 0, flagsize, fields, value ? *value : 0);
    bp_cbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_tstr(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk) {
    proto_item *item = proto_tree_add_item(tree, hfindex, tvb, chunk->start + chunk->head_length, chunk->head_value, ENC_NA);
    bp_cbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_bstr(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const bp_cbor_chunk_t *chunk) {
    proto_item *item = proto_tree_add_item(tree, hfindex, tvb, chunk->start + chunk->head_length, chunk->head_value, ENC_NA);
    bp_cbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}
