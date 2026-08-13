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
 *|    that `wally_psbt_get_input_sp_eligible` reports as eligible. For a
 *|    taproot input this must be the key of the taproot *output* key, i.e.
 *|    the BIP-341 tweaked key, not the untweaked internal key.
 * :param priv_keys_len: Length of ``priv_keys`` in bytes.
 * :param entropy: Randomness for the DLEQ proofs. One proof is created per
 *|    unique recipient scan key, each using entropy derived from this value,
 *|    so it must be unpredictable and must not be reused.
 * :param entropy_len: Length of ``entropy`` in bytes. Must be 32.
 * :param flags: For future use. Must be 0.
 *
 * For each output carrying ``PSBT_OUT_SP_V0_INFO``, derives the BIP-352
 * output and stores it as the output's scriptPubKey. An existing script must
 * match the derived script or the operation fails. One BIP-375 global ECDH
 * share and DLEQ proof is stored per unique recipient scan key.
 *
 * The operation is transactional: on failure, ``psbt`` is not modified.
 *
 * .. note:: This produces the BIP-375 *global* share, which covers the sum of
 *|    every eligible input, so the caller must hold every eligible input's key.
 *|    For collaborative sending, where each signer holds only some of the
 *|    inputs, see `wally_psbt_sp_contribute` and `wally_psbt_sp_resolve_shares`.
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
 * Contribute BIP-375 per-input ECDH shares to a PSBT, as one of several senders.
 *
 * :param psbt: The PSBT to contribute to. Directly modifies this PSBT.
 * :param indices: The zero-based indices of the inputs to contribute for, in
 *|    ascending order without duplicates. Every one must be eligible per
 *|    `wally_psbt_get_input_sp_eligible`.
 * :param num_indices: The number of elements in ``indices``.
 * :param priv_keys: The private keys of the inputs named by ``indices``, in the
 *|    same order, one `EC_PRIVATE_KEY_LEN` key each. For a taproot input this
 *|    must be the key of the taproot *output* key, i.e. the BIP-341 tweaked
 *|    key, not the untweaked internal key.
 * :param priv_keys_len: Length of ``priv_keys`` in bytes. Must be
 *|    ``num_indices`` * `EC_PRIVATE_KEY_LEN`.
 * :param entropy: Randomness for the DLEQ proofs. One proof is created per
 *|    input per unique recipient scan key, each using entropy derived from this
 *|    value, so it must be unpredictable and must not be reused.
 * :param entropy_len: Length of ``entropy`` in bytes. Must be 32.
 * :param flags: For future use. Must be 0.
 *
 * For each named input, stores a ``PSBT_IN_SP_ECDH_SHARE`` and its
 * ``PSBT_IN_SP_DLEQ`` proof for every unique recipient scan key, replacing any
 * already present for that input and scan key. No output script is derived and
 * no private key is revealed: the outputs cannot be derived until every
 * eligible input carries a share, at which point any party can call
 * `wally_psbt_sp_resolve_shares`.
 *
 * The operation is transactional: on failure, ``psbt`` is not modified.
 *
 * .. note:: Each key must match the public key its input is spent with, or
 *|    `WALLY_EINVAL` is returned: a share proven against the wrong key would
 *|    make the transaction unresolvable for everyone.
 *
 * .. note:: A signer holding every eligible input should call
 *|    `wally_psbt_sp_resolve` instead, which produces a single global share.
 */
WALLY_CORE_API int wally_psbt_sp_contribute(
    struct wally_psbt *psbt,
    const size_t *indices,
    size_t num_indices,
    const unsigned char *priv_keys,
    size_t priv_keys_len,
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t flags);

/** An aggregate key that a PSBT input is spent with.
 *
 * BIP-375 assumes one party holds each eligible input's whole secret key. An
 * aggregate key - MuSig2 or FROST - splits that secret across parties, so no
 * one of them can produce the input's share alone. These describe, for the
 * inputs that are aggregates, the public data needed to combine the parties'
 * partial shares back into the input's BIP-352 ECDH point.
 *
 * The participant keys are the untweaked account-level keys, i.e. those listed
 * in the input's ``PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS``, and the ones the
 * partial shares are keyed by. Any synthetic derivation belongs in ``path``,
 * not in the participant keys: it tweaks the aggregate, not any party's key.
 */
struct wally_sp_musig_input {
    size_t index; /** The zero-based index of the input */
    const unsigned char *pub_keys; /** Participant pubkeys, `EC_PUBLIC_KEY_LEN` each */
    size_t pub_keys_len; /** Length of ``pub_keys``; at least 2 keys */
    const uint32_t *path; /** Unhardened BIP-328 synthetic derivation path, or NULL */
    size_t path_len; /** The number of elements in ``path`` */
};

/**
 * Contribute this party's partial ECDH shares to a PSBT's aggregate inputs.
 *
 * :param psbt: The PSBT to contribute to. Directly modifies this PSBT.
 * :param musig_inputs: The aggregate inputs to contribute for, in ascending
 *|    index order without duplicates.
 * :param num_musig_inputs: The number of elements in ``musig_inputs``.
 * :param priv_keys: This party's participant private keys, one
 *|    `EC_PRIVATE_KEY_LEN` key per element of ``musig_inputs``, in the same
 *|    order. Each is the party's untweaked account-level secret, *not* a
 *|    taproot-tweaked key.
 * :param priv_keys_len: Length of ``priv_keys``. Must be
 *|    ``num_musig_inputs`` * `EC_PRIVATE_KEY_LEN`.
 * :param entropy: Randomness for the DLEQ proofs, as for
 *|    `wally_psbt_sp_contribute`. Must be unpredictable and must not be reused.
 * :param entropy_len: Length of ``entropy`` in bytes. Must be 32.
 * :param flags: For future use. Must be 0.
 *
 * Stores a ``PSBT_IN_SP_PARTIAL_ECDH_SHARE`` and its
 * ``PSBT_IN_SP_PARTIAL_DLEQ`` proof, keyed by scan key and by this party's
 * participant key, for every unique recipient scan key. No output script is
 * derived: the outputs cannot be derived until every participant of every
 * aggregate input has contributed.
 *
 * The operation is transactional: on failure, ``psbt`` is not modified.
 *
 * .. note:: Each key must be one of its input's participant keys, or
 *|    `WALLY_EINVAL` is returned: a share proven against a key outside the
 *|    aggregate would make the transaction unresolvable for everyone.
 */
WALLY_CORE_API int wally_psbt_sp_musig_contribute(
    struct wally_psbt *psbt,
    const struct wally_sp_musig_input *musig_inputs,
    size_t num_musig_inputs,
    const unsigned char *priv_keys,
    size_t priv_keys_len,
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t flags);

/**
 * Resolve a PSBT's silent payment outputs, combining any partial shares.
 *
 * :param psbt: The PSBT to resolve. Directly modifies this PSBT.
 * :param musig_inputs: The inputs whose keys are aggregates, or NULL.
 * :param num_musig_inputs: The number of elements in ``musig_inputs``.
 * :param flags: For future use. Must be 0.
 *
 * As `wally_psbt_sp_resolve_shares`, but additionally combines the partial
 * shares of each named input into that input's ECDH point, so that inputs
 * spent with an aggregate key contribute like any other. Requires no private
 * keys, and is the call every party makes to re-derive and check the outputs
 * before signing.
 *
 * Returns `WALLY_EINVAL` if the aggregate of an input's participant keys and
 * path is not the key that input is spent with, or if any partial share fails
 * its proof. The operation is transactional: on failure, ``psbt`` is not
 * modified.
 */
WALLY_CORE_API int wally_psbt_sp_musig_resolve_shares(
    struct wally_psbt *psbt,
    const struct wally_sp_musig_input *musig_inputs,
    size_t num_musig_inputs,
    uint32_t flags);

/**
 * Get the status of a PSBT's shares and proofs, including partial ones.
 *
 * :param psbt: The PSBT to check. Not modified.
 * :param musig_inputs: The inputs whose keys are aggregates, or NULL.
 * :param num_musig_inputs: The number of elements in ``musig_inputs``.
 * :param flags: For future use. Must be 0.
 * :param written: `WALLY_SP_INVALID`, `WALLY_SP_INCOMPLETE` or
 *|    `WALLY_SP_COMPLETE`, as for `wally_psbt_get_sp_status`.
 *
 * As `wally_psbt_get_sp_status`, but a named input is covered only when every
 * one of its participants has contributed a valid partial share. This is how a
 * party tells round 1 - still collecting shares - from round 2, where the
 * outputs are derived and can be checked before signing.
 */
WALLY_CORE_API int wally_psbt_get_sp_musig_status(
    const struct wally_psbt *psbt,
    const struct wally_sp_musig_input *musig_inputs,
    size_t num_musig_inputs,
    uint32_t flags,
    size_t *written);

/** Return the stable digest binding a two-round aggregate silent-payment session.
 *
 * The digest commits to the transaction version, inputs, calculated locktime,
 * output amounts and recipients. For a silent-payment output its 66-byte
 * ``PSBT_OUT_SP_V0_INFO`` replaces the not-yet-known script, so the digest is
 * unchanged when round 1 resolves that output.
 * FIXED_SIZED_OUTPUT(len, bytes_out, SHA256_LEN)
 */
WALLY_CORE_API int wally_psbt_get_sp_musig_session_digest(
    const struct wally_psbt *psbt,
    unsigned char *bytes_out,
    size_t len);

/** Contribute aggregate silent-payment shares and MuSig2 public nonces.
 *
 * ``entropy`` must contain 32 bytes used as the DLEQ-proof entropy seed,
 * followed by one independent 32-byte MuSig2 session random value per
 * aggregate input. Each session random value must be uniformly random, unique
 * and never reused. On success ``secnonces_out`` receives one owned secret
 * nonce per input and ``status_out`` is `WALLY_SP_INCOMPLETE` or
 * `WALLY_SP_COMPLETE`. A complete result also resolves all silent-payment
 * scripts and clears the PSBT input/output modifiable flags.
 *
 * The PSBT, ``secnonces_out`` and ``session_digest_out`` are unchanged on
 * failure; ``status_out`` is set to `WALLY_SP_INVALID`.
 */
WALLY_CORE_API int wally_psbt_sp_musig_round1(
    struct wally_psbt *psbt,
    const struct wally_sp_musig_input *musig_inputs,
    size_t num_musig_inputs,
    const unsigned char *priv_keys,
    size_t priv_keys_len,
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t flags,
    struct wally_musig_secnonce **secnonces_out,
    unsigned char *session_digest_out,
    size_t digest_len,
    size_t *status_out);

/** Verify and sign round 2 of an aggregate silent-payment session.
 *
 * The supplied digest must match the PSBT, every share and proof must be
 * present and valid, every resolved output must re-derive identically, and the
 * transaction's global tx-modifiable flags must all be zero. Signing consumes
 * the secret nonces. If any signing operation fails, callers must discard
 * every nonce in the session even though the PSBT itself remains unchanged.
 */
WALLY_CORE_API int wally_psbt_sp_musig_round2(
    struct wally_psbt *psbt,
    const struct wally_sp_musig_input *musig_inputs,
    size_t num_musig_inputs,
    const unsigned char *priv_keys,
    size_t priv_keys_len,
    struct wally_musig_secnonce **secnonces,
    const unsigned char *session_digest,
    size_t digest_len,
    uint32_t flags);

/**
 * Resolve a PSBT's silent payment outputs from the shares it already carries.
 *
 * :param psbt: The PSBT to resolve. Directly modifies this PSBT.
 * :param flags: For future use. Must be 0.
 *
 * Derives each silent payment output's scriptPubKey from the BIP-375 shares
 * present, and stores it. An existing script must match the derived script or
 * the operation fails, as it does in `wally_psbt_sp_resolve`.
 *
 * Requires no private keys: the shares are DLEQ-proven against the inputs'
 * public keys, and BIP-352 needs nothing beyond the share, the transaction's
 * smallest outpoint and the recipient's spend key to reach the output. This is
 * the final step of a collaborative send, and may be performed by any party.
 *
 * Returns `WALLY_EINVAL` unless the shares present are valid and cover every
 * eligible input for every recipient scan key, i.e. unless
 * `wally_psbt_get_sp_status` reports `WALLY_SP_INCOMPLETE` only for want of the
 * output scripts. The operation is transactional: on failure, ``psbt`` is not
 * modified.
 */
WALLY_CORE_API int wally_psbt_sp_resolve_shares(
    struct wally_psbt *psbt,
    uint32_t flags);

/**
 * Get the status of a PSBT's BIP-375 ECDH shares and DLEQ proofs.
 *
 * :param psbt: The PSBT to check. Not modified.
 * :param flags: For future use. Must be 0.
 * :param written: `WALLY_SP_INVALID`, `WALLY_SP_INCOMPLETE` or
 *|    `WALLY_SP_COMPLETE`, as described below.
 *
 * Checks that every share for a recipient of this PSBT is accompanied by a
 * proof, that every such proof verifies against the public key(s) it covers,
 * and that the shares present cover every eligible input and every recipient
 * scan key. Where the outputs are resolved, also checks that each one holds
 * the scriptPubKey that BIP-352 derives from the shares. Requires no private
 * keys, so a signer can check work done by other signers.
 *
 * The verdict depends on whether the silent payment outputs have been resolved:
 *
 * - `WALLY_SP_INVALID`: a share without its proof, a proof that does not
 *|   verify, a share whose input has no key to verify it against, or - when the
 *|   outputs are already resolved - incomplete coverage or a scriptPubKey that
 *|   is not the one BIP-352 derives. Do not sign.
 * - `WALLY_SP_INCOMPLETE`: the outputs are not resolved and coverage is not yet
 *|   complete. Everything present is valid; more signers must contribute.
 * - `WALLY_SP_COMPLETE`: the outputs are resolved, coverage is complete, every
 *|   proof verifies and every resolved scriptPubKey is the derived one.
 *
 * .. note:: The derived check uses only public data: the shares are DLEQ-proven
 *|    against the inputs' public keys, and BIP-352 needs nothing more than the
 *|    share, the transaction's smallest outpoint and the recipient's spend key
 *|    to reach the output. A signer holding none of the eligible inputs can
 *|    therefore still confirm that what it is asked to sign pays the recipient.
 *
 * .. note:: Shares and proofs stored under a scan key that no recipient of this
 *|    PSBT uses are ignored. BIP-375 does not forbid them and they cannot
 *|    affect the derived outputs.
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
