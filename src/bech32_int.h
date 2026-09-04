#ifndef LIBWALLY_CORE_BECH32_INT_H
#define LIBWALLY_CORE_BECH32_INT_H

#include <stdlib.h>

#include <include/wally_address.h>
#include <include/wally_descriptor.h>

/* The longest BIP-392 key expression is "tspspend" (8 chars) + separator +
 * version + 104 data chars + 6 checksum chars = 120. Round up for the buffers.
 */
#define BECH32M_SP_KEY_MAX_LEN 128

/* An spscan payload: ser256(b_scan) || serP(B_spend) */
#define BECH32M_SP_SCAN_KEY_LEN WALLY_SP_SCAN_KEY_LEN
/* An spspend payload: ser256(b_scan) || ser256(b_spend) */
#define BECH32M_SP_SPEND_KEY_LEN WALLY_SP_SPEND_KEY_LEN
#define BECH32M_SP_KEY_MAX_PAYLOAD_LEN BECH32M_SP_SCAN_KEY_LEN

/* The largest silent payment payload of any kind: a BIP-352 address, which
 * carries both public keys and so is one byte longer than an spscan key.
 */
#define BECH32M_SP_MAX_PAYLOAD_LEN WALLY_SP_V0_INFO_LEN

/**
 * Encode a silent payment v0 payload as bech32m.
 *
 * :param bytes: The payload, e.g. a BIP-352 address or BIP-392 key expression.
 * :param bytes_len: Length of ``bytes`` in bytes.
 * :param hrp: The human-readable part, e.g. "sp" or "spscan".
 * :param hrp_len: Length of ``hrp`` in bytes.
 * :param output: Destination for the encoded string.
 */
int bech32m_sp_from_bytes(const unsigned char *bytes, size_t bytes_len,
                          const char *hrp, size_t hrp_len, char **output);

/**
 * Decode a BIP-392 silent payment key expression.
 *
 * :param str: The key expression, e.g. "spscan1q...". Not NUL terminated.
 * :param str_len: Length of ``str`` in bytes.
 * :param hrp: The expected human-readable part, e.g. "spscan".
 * :param hrp_len: Length of ``hrp`` in bytes.
 * :param bytes_out: Destination for the decoded payload.
 * :param len: Length of ``bytes_out``, which must be the payload length
 *|    expected for ``hrp``: ``BECH32M_SP_SCAN_KEY_LEN`` for spscan keys or
 *|    ``BECH32M_SP_SPEND_KEY_LEN`` for spspend keys.
 *
 * Only silent payments version 0 is accepted.
 */
int bech32m_sp_key_to_bytes(const char *str, size_t str_len,
                            const char *hrp, size_t hrp_len,
                            unsigned char *bytes_out, size_t len);

#endif /* LIBWALLY_CORE_BECH32_INT_H */
