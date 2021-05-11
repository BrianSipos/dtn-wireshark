/**
 * COSE message dissectors are registered multiple ways:
 * 1. The unit-keyed dissector table "cose.msgtag" with keys being
 *    IANA-registered CBOR tag values (e.g., 18 is COSE_Sign1).
 * 2. The string-keyed dissector table "media_type" with keys being
 *    IANA-registered media type IDs
 *    (e.g., application/cose; cose-type="cose-sign1" is COSE_Sign1).
 * 3. The registered dissectors for names "cose" and message names in
 *    all-lowercase form (e.g., "cose_sign1").
 *
 * COSE header label dissectors are registered with the dissector table
 * "cose.header_key.int" for int values and "cose.header_key.tstr" for
 * tstr values.
 *
 * An additional dissector "cose.msg.headers" will dissect an individual
 * header map structure outside of a COSE message.
 */
