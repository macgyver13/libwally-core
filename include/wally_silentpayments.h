#ifndef LIBWALLY_CORE_SILENTPAYMENTS_H
#define LIBWALLY_CORE_SILENTPAYMENTS_H

#include "wally_core.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wally_psbt;

/** The BIP-352 outpoint of an input: its txid followed by a 4 byte LE vout */
#define WALLY_SP_OUTPOINT_LEN 36

/** Shares or proofs are missing, contradictory or invalid: refuse to sign */
#define WALLY_SP_INVALID 0
/** The outputs are not resolved yet, and what is present is valid */
#define WALLY_SP_INCOMPLETE 1
/** The outputs are resolved, every share is covered and every proof verifies */
#define WALLY_SP_COMPLETE 2

/**
 * Determine whether a PSBT input can contribute to a silent payment.
 *
 * :param psbt: The PSBT containing the input to check.
 * :param index: The zero-based index of the input to check.
 * :param written: 1 if the input is eligible, otherwise 0.
 *
 * BIP-352 senders may only spend to a silent payment using P2PKH, P2WPKH,
 * P2SH-P2WPKH or P2TR inputs, and not a P2TR input whose internal key is the
 * BIP-341 NUMS point, since such an input has no key path to sign with.
 *
 * .. note:: The input's UTXO must be present in the PSBT. An input whose
 *|    script cannot be classified at all, such as an unknown future witness
 *|    version, returns `WALLY_ERROR`: a sender must not treat it as merely
 *|    ineligible, because doing so would make the payment undetectable.
 */
WALLY_CORE_API int wally_psbt_get_input_sp_eligible(
    const struct wally_psbt *psbt,
    size_t index,
    size_t *written);

/**
 * Get the BIP-352 smallest outpoint of a PSBT's inputs.
 *
 * :param psbt: The PSBT to get the smallest outpoint of. Must have inputs.
 * :param bytes_out: Destination for the outpoint.
 * FIXED_SIZED_OUTPUT(len, bytes_out, WALLY_SP_OUTPOINT_LEN)
 *
 * The smallest outpoint is committed to by the BIP-352 input hash, which is
 * what makes the derived outputs unique to this transaction.
 */
WALLY_CORE_API int wally_psbt_get_sp_smallest_outpoint(
    const struct wally_psbt *psbt,
    unsigned char *bytes_out,
    size_t len);

/**
 * Resolve a PSBT's silent payment outputs, as the sender.
 *
 * :param psbt: The PSBT to resolve. Directly modifies this PSBT.
 * :param priv_keys: The private keys of the PSBT's eligible inputs,
 *|    concatenated in input order, one `EC_PRIVATE_KEY_LEN` key per input
 *|    that `wally_psbt_get_input_sp_eligible` reports as eligible.
 * :param priv_keys_len: Length of ``priv_keys`` in bytes.
 * :param entropy: Randomness for the DLEQ proofs. One proof is created per
 *|    unique recipient scan key, each using entropy derived from this value,
 *|    so it must be unpredictable and must not be reused.
 * :param entropy_len: Length of ``entropy`` in bytes. Must be 32.
 * :param flags: For future use. Must be 0.
 *
 * For each output carrying ``PSBT_OUT_SP_V0_INFO``, derives the BIP-352
 * output and stores it as the output's scriptPubKey, replacing any script
 * already present. One BIP-375 global ECDH share and DLEQ proof is stored per
 * unique recipient scan key.
 *
 * .. note:: Only the BIP-375 *global* share is produced, which covers the sum
 *|    of every eligible input, so the caller must hold every eligible input's
 *|    key. Collaborative sending, where signers publish per-input shares, is
 *|    not supported.
 *
 * .. note:: The caller is responsible for BIP-352's requirement that the
 *|    inputs it signs use SIGHASH_ALL, and for refusing to sign if the
 *|    resulting outputs are not what it expects.
 */
WALLY_CORE_API int wally_psbt_sp_resolve(
    struct wally_psbt *psbt,
    const unsigned char *priv_keys,
    size_t priv_keys_len,
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t flags);

/**
 * Get the status of a PSBT's BIP-375 ECDH shares and DLEQ proofs.
 *
 * :param psbt: The PSBT to check. Not modified.
 * :param flags: For future use. Must be 0.
 * :param written: `WALLY_SP_INVALID`, `WALLY_SP_INCOMPLETE` or
 *|    `WALLY_SP_COMPLETE`, as described below.
 *
 * Checks that every share is accompanied by a proof, that every proof verifies
 * against the public key(s) it covers, and that the shares present cover every
 * eligible input and every recipient scan key. Requires no private keys, so a
 * signer can check work done by other signers.
 *
 * The verdict depends on whether the silent payment outputs have been resolved:
 *
 * - `WALLY_SP_INVALID`: a share without its proof, a proof that does not
 *|   verify, a share whose input has no key to verify it against, or - when the
 *|   outputs are already resolved - incomplete coverage. Do not sign.
 * - `WALLY_SP_INCOMPLETE`: the outputs are not resolved and coverage is not yet
 *|   complete. Everything present is valid; more signers must contribute.
 * - `WALLY_SP_COMPLETE`: the outputs are resolved, coverage is complete and
 *|   every proof verifies.
 *
 * .. note:: `WALLY_SP_COMPLETE` does *not* mean the outputs were derived
 *|    correctly, only that the shares and proofs are internally consistent.
 *|    Confirming that a scriptPubKey is what BIP-352 derives requires either
 *|    the inputs' private keys (see `wally_psbt_sp_resolve`) or the recipient's
 *|    scan key. A signer that does not hold them is trusting whoever resolved
 *|    the outputs, and should show the recipient addresses to its user.
 *
 * .. note:: An input that cannot be classified at all, such as an unknown
 *|    future witness version, returns `WALLY_ERROR`, as it does from
 *|    `wally_psbt_get_input_sp_eligible`.
 */
WALLY_CORE_API int wally_psbt_get_sp_status(
    const struct wally_psbt *psbt,
    uint32_t flags,
    size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_SILENTPAYMENTS_H */
