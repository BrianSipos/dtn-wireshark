/* wscbor.c
 * Wireshark CBOR item decoding API.
 * References:
 *     RFC 8949: https://tools.ietf.org/html/rfc8949
 *
 * Copyright 2019-2021, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <stdio.h>
#include <inttypes.h>
#include "wscbor.h"

#if defined(WIRESHARK_HAS_VERSION_H)
#include <ws_version.h>
#else
#include <config.h>
#define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
#define WIRESHARK_VERSION_MINOR VERSION_MINOR
#endif

/// Pseudo-protocol to register expert info
static int proto_wscbor = -1;

static expert_field ei_cbor_invalid = EI_INIT;
static expert_field ei_cbor_overflow = EI_INIT;
static expert_field ei_cbor_wrong_type = EI_INIT;
static expert_field ei_cbor_array_wrong_size = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_cbor_invalid, {"_ws.wscbor.cbor_invalid", PI_MALFORMED, PI_ERROR, "CBOR cannot be decoded", EXPFILL}},
    {&ei_cbor_overflow, {"_ws.wscbor.cbor_overflow", PI_UNDECODED, PI_ERROR, "CBOR overflow of Wireshark value", EXPFILL}},
    {&ei_cbor_wrong_type, {"_ws.wscbor.cbor_wrong_type", PI_MALFORMED, PI_ERROR, "CBOR is wrong type", EXPFILL}},
    {&ei_cbor_array_wrong_size, {"_ws.wscbor.array_wrong_size", PI_MALFORMED, PI_WARN, "CBOR array is the wrong size", EXPFILL}},
};

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
} wscbor_head_t;

/** Read the raw value from a CBOR head.
 * @param[in,out] head The head to read into.
 * @param tvb The buffer to read from.
 */
static void wscbor_read_unsigned(wscbor_head_t *head, tvbuff_t *tvb) {
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

/** Read just the CBOR head octet.
 * @post Will throw wireshark exception if read fails.
 */
static wscbor_head_t * wscbor_head_read(wmem_allocator_t *alloc, tvbuff_t *tvb, gint start) {
    wscbor_head_t *head = wmem_new0(alloc, wscbor_head_t);

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
            wscbor_read_unsigned(head, tvb);
            if (head->type_minor > 0x1B) {
                head->error = &ei_cbor_invalid;
            }
            break;
        case CBOR_TYPE_BYTESTRING:
        case CBOR_TYPE_STRING:
        case CBOR_TYPE_ARRAY:
        case CBOR_TYPE_MAP:
        case CBOR_TYPE_FLOAT_CTRL:
            wscbor_read_unsigned(head, tvb);
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

/** Force a head to be freed.
 */
static void wscbor_head_free(wmem_allocator_t *alloc, wscbor_head_t *head) {
    wmem_free(alloc, head);
}

/** Get a clamped string length suitable for tvb functions.
 * @param[in,out] chunk The chunk to read and set errors on.
 * @return The clamped length value.
 */
static gint wscbor_get_length(const wscbor_chunk_t *chunk) {
    gint length;
    if (chunk->head_value > G_MAXINT) {
        wmem_list_append(chunk->errors, wscbor_error_new(
                chunk->_alloc, &ei_cbor_overflow,
                NULL
        ));
        length = G_MAXINT;
    }
    else {
        length = (gint) chunk->head_value;
    }
    return length;
}

wscbor_error_t * wscbor_error_new(wmem_allocator_t *alloc, expert_field *ei, const char *format, ...) {
    wscbor_error_t *err = wmem_new0(alloc, wscbor_error_t);
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

wscbor_chunk_t * wscbor_chunk_read(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset) {
    DISSECTOR_ASSERT(alloc != NULL);
    DISSECTOR_ASSERT(offset != NULL);
    DISSECTOR_ASSERT(tvb != NULL);

    wscbor_chunk_t *chunk = wmem_new0(alloc, wscbor_chunk_t);
    chunk->_alloc = alloc;
    chunk->errors = wmem_list_new(alloc);
    chunk->tags = wmem_list_new(alloc);
    chunk->start = *offset;

    // Read a sequence of tags followed by an item header
    while (TRUE) {
        // This will break out of the loop if it runs out of buffer
        wscbor_head_t *head = wscbor_head_read(alloc, tvb, *offset);
        *offset += head->length;
        chunk->head_length += head->length;
        if (head->error) {
            wmem_list_append(chunk->errors, wscbor_error_new(alloc, head->error, NULL));
        }
        if (head->type_major == CBOR_TYPE_TAG) {
            wscbor_tag_t *tag = wmem_new(alloc, wscbor_tag_t);
            tag->start = head->start;
            tag->length = head->length;
            tag->value = head->rawvalue;
            wmem_list_append(chunk->tags, tag);
            // same chunk, next part
            wscbor_head_free(alloc, head);
            continue;
        }

        // An actual (non-tag) header
        chunk->type_major = (cbor_type)head->type_major;
        chunk->type_minor = head->type_minor;
        chunk->head_value = head->rawvalue;

        chunk->data_length = chunk->head_length;
        switch ((cbor_type)(head->type_major)) {
            case CBOR_TYPE_BYTESTRING:
            case CBOR_TYPE_STRING:
                if (chunk->type_minor != 31) {
                    const gint datalen = wscbor_get_length(chunk);
                    // skip over definite data
                    *offset += datalen;
                    chunk->data_length += datalen;
                }
                break;
            default:
                break;
        }

        wscbor_head_free(alloc, head);
        break;
    }

    return chunk;
}

static void wscbor_subitem_free(gpointer data, gpointer userdata) {
    wmem_allocator_t *alloc = (wmem_allocator_t *) userdata;
    wmem_free(alloc, data);
}

void wscbor_chunk_free(wscbor_chunk_t *chunk) {
    DISSECTOR_ASSERT(chunk);
    wmem_allocator_t *alloc = chunk->_alloc;
    wmem_list_foreach(chunk->errors, wscbor_subitem_free, alloc);
    wmem_destroy_list(chunk->errors);
    wmem_list_foreach(chunk->tags, wscbor_subitem_free, alloc);
    wmem_destroy_list(chunk->tags);
    wmem_free(alloc, chunk);
}

guint64 wscbor_chunk_mark_errors(packet_info *pinfo, proto_item *item, const wscbor_chunk_t *chunk) {
    for (wmem_list_frame_t *it = wmem_list_head(chunk->errors); it;
            it = wmem_list_frame_next(it)) {
        wscbor_error_t *err = (wscbor_error_t *) wmem_list_frame_data(it);
        if (err->msg) {
            expert_add_info_format(pinfo, item, err->ei, "%s", err->msg);
        }
        else {
            expert_add_info(pinfo, item, err->ei);
        }
    }
    return wmem_list_count(chunk->errors);
}

guint wscbor_has_errors(const wscbor_chunk_t *chunk) {
    return wmem_list_count(chunk->errors);
}

gboolean wscbor_is_indefinite_break(const wscbor_chunk_t *chunk) {
    return (
        (chunk->type_major == CBOR_TYPE_FLOAT_CTRL)
        && (chunk->type_minor == 31)
    );
}

gboolean wscbor_skip_next_item(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset) {
    wscbor_chunk_t *chunk = wscbor_chunk_read(alloc, tvb, offset);
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
                while (!wscbor_skip_next_item(alloc, tvb, offset)) {}
            }
            // wscbor_read_chunk() sets offset past definite value
            break;
        case CBOR_TYPE_ARRAY: {
            if (chunk->type_minor == 31) {
                // wait for indefinite break
                while (!wscbor_skip_next_item(alloc, tvb, offset)) {}
            }
            else {
                const guint64 count = chunk->head_value;
                for (guint64 ix = 0; ix < count; ++ix) {
                    wscbor_skip_next_item(alloc, tvb, offset);
                }
            }
            break;
        }
        case CBOR_TYPE_MAP: {
            if (chunk->type_minor == 31) {
                // wait for indefinite break
                while (!wscbor_skip_next_item(alloc, tvb, offset)) {}
            }
            else {
                const guint64 count = chunk->head_value;
                for (guint64 ix = 0; ix < count; ++ix) {
                    wscbor_skip_next_item(alloc, tvb, offset);
                    wscbor_skip_next_item(alloc, tvb, offset);
                }
            }
            break;
        }
    }
    const gboolean is_break = wscbor_is_indefinite_break(chunk);
    wscbor_chunk_free(chunk);
    return is_break;
}

gboolean wscbor_skip_if_errors(wmem_allocator_t *alloc, tvbuff_t *tvb, gint *offset, const wscbor_chunk_t *chunk) {
    if (wscbor_has_errors(chunk) == 0) {
        return FALSE;
    }

    *offset = chunk->start;
    wscbor_skip_next_item(alloc, tvb, offset);
    return TRUE;
}

void wscbor_init(void) {
    proto_wscbor = proto_register_protocol(
        "CBOR Item Decoder",
        "CBOR Item Decoder",
        "_ws.wscbor"
    );

    expert_module_t *expert_wscbor = expert_register_protocol(proto_wscbor);
    /* This isn't really a protocol, it's an error indication;
       disabling them makes no sense. */
    proto_set_cant_toggle(proto_wscbor);

    expert_register_field_array(expert_wscbor, expertitems, array_length(expertitems));
}

gboolean wscbor_require_major_type(wscbor_chunk_t *chunk, cbor_type major) {
    if (chunk->type_major == major) {
        return TRUE;
    }
    wmem_list_append(chunk->errors, wscbor_error_new(
            chunk->_alloc, &ei_cbor_wrong_type,
            "Item has major type %d, should be %d",
            chunk->type_major, major
    ));
    return FALSE;
}

gboolean wscbor_require_array(wscbor_chunk_t *chunk) {
    return wscbor_require_major_type(chunk, CBOR_TYPE_ARRAY);
}

gboolean wscbor_require_array_size(wscbor_chunk_t *chunk, guint64 count_min, guint64 count_max) {
    if (!wscbor_require_array(chunk)) {
        return FALSE;
    }
    if ((chunk->head_value < count_min) || (chunk->head_value > count_max)) {
        wmem_list_append(chunk->errors, wscbor_error_new(
                chunk->_alloc, &ei_cbor_array_wrong_size,
                "Array has %" PRId64 " items, should be within [%"PRId64", %"PRId64"]",
                chunk->head_value, count_min, count_max
        ));
        return FALSE;
    }
    return TRUE;
}

gboolean wscbor_require_map(wscbor_chunk_t *chunk) {
    return wscbor_require_major_type(chunk, CBOR_TYPE_MAP);
}

gboolean * wscbor_require_boolean(wmem_allocator_t *alloc, wscbor_chunk_t *chunk) {
    if (!wscbor_require_major_type(chunk, CBOR_TYPE_FLOAT_CTRL)) {
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
            wmem_list_append(chunk->errors, wscbor_error_new(
                    chunk->_alloc, &ei_cbor_wrong_type,
                    "Item has minor type %d, should be %d or %d",
                    chunk->type_minor, CBOR_CTRL_TRUE, CBOR_CTRL_FALSE
            ));
            break;
    }
    return NULL;
}

guint64 * wscbor_require_uint64(wmem_allocator_t *alloc, wscbor_chunk_t *chunk) {
    if (!wscbor_require_major_type(chunk, CBOR_TYPE_UINT)) {
        return NULL;
    }

    guint64 *result = wmem_new(alloc, guint64);
    *result = chunk->head_value;
    return result;
}

gint64 * wscbor_require_int64(wmem_allocator_t *alloc, wscbor_chunk_t *chunk) {
    gint64 *result = NULL;
    switch (chunk->type_major) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NEGINT: {
            gint64 clamped;
            if (chunk->head_value > INT64_MAX) {
                clamped = INT64_MAX;
                wmem_list_append(chunk->errors, wscbor_error_new(
                        chunk->_alloc, &ei_cbor_overflow,
                        NULL
                ));
            }
            else {
                clamped = chunk->head_value;
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
            wmem_list_append(chunk->errors, wscbor_error_new(
                    chunk->_alloc, &ei_cbor_wrong_type,
                    "Item has major type %d, should be %d or %d",
                    chunk->type_major, CBOR_TYPE_UINT, CBOR_TYPE_NEGINT
            ));
            break;
    }
    return result;
}

char * wscbor_require_tstr(wmem_allocator_t *alloc, tvbuff_t *parent, wscbor_chunk_t *chunk) {
    if (!wscbor_require_major_type(chunk, CBOR_TYPE_STRING)) {
        return NULL;
    }

    return (char *)tvb_get_string_enc(alloc, parent, chunk->start + chunk->head_length, wscbor_get_length(chunk), ENC_UTF_8);
}

tvbuff_t * wscbor_require_bstr(tvbuff_t *parent, wscbor_chunk_t *chunk) {
    if (!wscbor_require_major_type(chunk, CBOR_TYPE_BYTESTRING)) {
        return NULL;
    }

    return tvb_new_subset_length(parent, chunk->start + chunk->head_length, wscbor_get_length(chunk));
}

proto_item * proto_tree_add_cbor_container(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk) {
    const header_field_info *hfinfo = proto_registrar_get_nth(hfindex);
    proto_item *item;
    if (IS_FT_UINT(hfinfo->type)) {
        item = proto_tree_add_uint64(tree, hfindex, tvb, chunk->start, chunk->head_length, chunk->head_value);
    }
    else if (IS_FT_INT(hfinfo->type)) {
        item = proto_tree_add_int64(tree, hfindex, tvb, chunk->start, chunk->head_length, chunk->head_value);
    }
    else {
        item = proto_tree_add_item(tree, hfindex, tvb, chunk->start, -1, 0);
    }
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_ctrl(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk) {
    proto_item *item = proto_tree_add_item(tree, hfindex, tvb, chunk->start, chunk->head_length, 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_boolean(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const gboolean *value) {
    proto_item *item = proto_tree_add_boolean(tree, hfindex, tvb, chunk->start, chunk->data_length, value ? *value : FALSE);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_uint64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const guint64 *value) {
    proto_item *item = proto_tree_add_uint64(tree, hfindex, tvb, chunk->start, chunk->head_length, value ? *value : 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_int64(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const gint64 *value) {
    proto_item *item = proto_tree_add_int64(tree, hfindex, tvb, chunk->start, chunk->head_length, value ? *value : 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_bitmask(proto_tree *tree, int hfindex, const gint ett, WS_FIELDTYPE *fields, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk, const guint64 *value) {
    header_field_info *field = proto_registrar_get_nth(hfindex);
    gint flagsize = 0;
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
    guint8 *flags = (guint8 *) wmem_alloc0(wmem_packet_scope(), flagsize);
    { // Inject big-endian value directly
        guint64 buf = (value ? *value : 0);
        for (gint ix = flagsize - 1; ix >= 0; --ix) {
            flags[ix] = buf & 0xFF;
            buf >>= 8;
        }
    }
    tvbuff_t *tvb_flags = tvb_new_child_real_data(tvb, flags, flagsize, flagsize);

    proto_item *item = proto_tree_add_bitmask_value(tree, tvb_flags, 0, hfindex, ett, fields, value ? *value : 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_tstr(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk) {
    proto_item *item = proto_tree_add_item(tree, hfindex, tvb, chunk->start + chunk->head_length, wscbor_get_length(chunk), 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
}

proto_item * proto_tree_add_cbor_bstr(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, const wscbor_chunk_t *chunk) {
    proto_item *item = proto_tree_add_item(tree, hfindex, tvb, chunk->start + chunk->head_length, wscbor_get_length(chunk), 0);
    wscbor_chunk_mark_errors(pinfo, item, chunk);
    return item;
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
    static proto_plugin plugin_wscbor;
    plugin_wscbor.register_protoinfo = wscbor_init;
    plugin_wscbor.register_handoff = NULL;
    proto_register_plugin(&plugin_wscbor);
}
