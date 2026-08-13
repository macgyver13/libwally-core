#include "internal.h"
#include "psbt_io.h"
#include "script_int.h"
#include "tx_io.h"

#include <include/wally_address.h>
#include <include/wally_crypto.h>
#include <include/wally_psbt.h>
#include <include/wally_psbt_members.h>
#include <include/wally_script.h>
#include <include/wally_silentpayments.h>
#include <include/wally_transaction.h>

#include <stdlib.h>

#ifndef BUILD_STANDARD_SECP
#include <include/wally_bip32.h>
#include <include/wally_musig.h>

#include <secp256k1_dleq.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_silentpayments.h>

/* The largest redeem script worth inspecting is a segwit witness program */
#define SP_MAX_REDEEM_SCRIPT_LEN 42

/* BIP-341 unspendable NUMS point 'H', as an x-only pubkey. A taproot input
 * using this as its internal key has no key path, so it cannot sign.
 */
static const unsigned char BIP341_NUMS_XONLY[EC_XONLY_PUBLIC_KEY_LEN] = {
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60,
    0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0
};

/* The public factors relating an aggregate input key to its participants.
 *
 * Where a single party's silent payment share is x*B_scan, an aggregate key's
 * is assembled from one share per party. BIP-327 writes the aggregate secret
 * that a taproot input spends with as
 *
 *   a_Q = g_v * (gacc * sum(a_i * x_i) + tacc)
 *
 * so multiplying through by B_scan gives the BIP-352 ECDH point in terms of
 * the per-party shares, using only public values:
 *
 *   a_Q*B_scan = (g_v*gacc) * sum(a_i * share_i) + (g_v*tacc) * B_scan
 *
 * 'negate' holds g_v*gacc, which is only ever +/-1, and 'tweak' holds
 * g_v*tacc reduced into a scalar. No party's secret is involved.
 */
struct sp_musig_factors {
    unsigned char tweak[EC_PRIVATE_KEY_LEN]; /* g_v * tacc */
    bool negate;                             /* g_v * gacc == -1 */
};

/* A recipient, and the PSBT output index it was read from */
struct sp_recipient {
    unsigned char scan_pubkey[EC_PUBLIC_KEY_LEN];
    unsigned char spend_pubkey[EC_PUBLIC_KEY_LEN];
    size_t output_index;
};

/* BIP-375 orders recipients by scan pubkey, then spend pubkey, then output
 * index. Ordering by scan pubkey first also makes duplicate scan keys
 * adjacent, which is what lets us emit one share and proof per scan key.
 */
static int sp_recipient_cmp(const void *lhs_ptr, const void *rhs_ptr)
{
    const struct sp_recipient *lhs = lhs_ptr, *rhs = rhs_ptr;
    int ret = memcmp(lhs->scan_pubkey, rhs->scan_pubkey, EC_PUBLIC_KEY_LEN);
    if (!ret)
        ret = memcmp(lhs->spend_pubkey, rhs->spend_pubkey, EC_PUBLIC_KEY_LEN);
    if (!ret)
        ret = (lhs->output_index > rhs->output_index) - (lhs->output_index < rhs->output_index);
    return ret;
}

/* Collect a PSBT's silent payment recipients into a newly allocated array, in
 * BIP-375 order. Returns NULL and sets *num_recipients to 0 if there are none,
 * or on allocation failure, which the caller distinguishes via *ret.
 */
static struct sp_recipient *sp_collect_recipients(const struct wally_psbt *psbt,
                                                  size_t *num_recipients, int *ret)
{
    struct sp_recipient *recipients;
    size_t i, num = 0;

    *num_recipients = 0;
    *ret = WALLY_OK;

    for (i = 0; i < psbt->num_outputs; ++i) {
        size_t info_len = 0;
        if (wally_psbt_get_output_sp_v0_info_len(psbt, i, &info_len) == WALLY_OK && info_len)
            ++num;
    }
    if (!num)
        return NULL; /* No silent payment outputs */

    if (!(recipients = wally_calloc(num * sizeof(*recipients)))) {
        *ret = WALLY_ENOMEM;
        return NULL;
    }

    num = 0;
    for (i = 0; i < psbt->num_outputs; ++i) {
        unsigned char info[WALLY_SP_V0_INFO_LEN];
        size_t info_len = 0;
        if (wally_psbt_get_output_sp_v0_info(psbt, i, info, sizeof(info), &info_len) != WALLY_OK ||
            !info_len)
            continue;
        if (info_len != sizeof(info)) {
            wally_free(recipients);
            *ret = WALLY_EINVAL;
            return NULL;
        }
        memcpy(recipients[num].scan_pubkey, info, EC_PUBLIC_KEY_LEN);
        memcpy(recipients[num].spend_pubkey, info + EC_PUBLIC_KEY_LEN, EC_PUBLIC_KEY_LEN);
        recipients[num].output_index = i;
        ++num;
    }
    qsort(recipients, num, sizeof(*recipients), sp_recipient_cmp);
    *num_recipients = num;
    return recipients;
}

/* Return the witness version of a witness program, or -1 if not one.
 * NOTE: wally_scriptpubkey_get_type() cannot serve here: it reports witness
 * v2+ programs as WALLY_SCRIPT_TYPE_UNKNOWN, which would make them merely
 * ineligible. BIP-352 requires the sender to abort on an unclassifiable input.
 */
static int sp_witness_version(const unsigned char *script, size_t script_len)
{
    if (!script || script_len < 4 || script_len > 42 ||
        script[1] != script_len - 2 || script[1] < 2 || script[1] > 40)
        return -1;
    if (script[0] == 0x00)
        return 0;
    return script[0] >= OP_1 && script[0] <= OP_16 ? script[0] - 0x50 : -1;
}

/* Whether a P2SH prevout is in fact paid to the redeem script given for it.
 * The PSBT's redeem script is otherwise attacker-choosable on this path.
 */
static bool sp_p2sh_redeem_matches(const unsigned char *script,
                                   const unsigned char *redeem_script,
                                   size_t redeem_script_len)
{
    unsigned char hash[HASH160_LEN];
    return wally_hash160(redeem_script, redeem_script_len,
                         hash, sizeof(hash)) == WALLY_OK &&
           !memcmp(hash, script + 2, sizeof(hash)); /* OP_HASH160 [push] */
}

/* Classify an input, returning whether it is eligible, and if so whether it
 * is a taproot input (whose key must be parity-normalized before summing).
 */
static int sp_classify_input(const struct wally_psbt *psbt, size_t index,
                             bool *is_eligible, bool *is_taproot)
{
    unsigned char redeem_script[SP_MAX_REDEEM_SCRIPT_LEN];
    unsigned char taproot_key[EC_XONLY_PUBLIC_KEY_LEN];
    const struct wally_tx_output *utxo = NULL;
    size_t script_type = WALLY_SCRIPT_TYPE_UNKNOWN;
    size_t redeem_type = WALLY_SCRIPT_TYPE_UNKNOWN;
    size_t redeem_script_len = 0, taproot_key_len = 0, field_len = 0;
    int ret;

    *is_eligible = *is_taproot = false;

    if (wally_psbt_get_input_best_utxo(psbt, index, &utxo) != WALLY_OK ||
        !utxo || !utxo->script || !utxo->script_len)
        return WALLY_EINVAL; /* No UTXO to classify */

    /* A redeem script too large for the buffer is left unread: it can be
     * neither P2WPKH nor any witness program, so the input is simply not
     * eligible, which is not an error - BIP-352 senders may spend ineligible
     * inputs alongside eligible ones.
     */
    if (wally_psbt_get_input_redeem_script_len(psbt, index, &field_len) == WALLY_OK &&
        field_len && field_len <= sizeof(redeem_script)) {
        ret = wally_psbt_get_input_redeem_script(psbt, index, redeem_script,
                                                 sizeof(redeem_script),
                                                 &redeem_script_len);
        if (ret != WALLY_OK)
            return ret;
    }

    if (sp_witness_version(utxo->script, utxo->script_len) > 1 ||
        sp_witness_version(redeem_script, redeem_script_len) > 1)
        return WALLY_ERROR; /* Unknown witness version: refuse to guess */

    if (wally_psbt_get_input_taproot_internal_key_len(psbt, index, &field_len) == WALLY_OK &&
        field_len) {
        if (field_len != sizeof(taproot_key))
            return WALLY_EINVAL;
        ret = wally_psbt_get_input_taproot_internal_key(psbt, index, taproot_key,
                                                        sizeof(taproot_key),
                                                        &taproot_key_len);
        if (ret != WALLY_OK)
            return ret;
    }

    if (wally_scriptpubkey_get_type(utxo->script, utxo->script_len, &script_type) != WALLY_OK ||
        (redeem_script_len &&
         wally_scriptpubkey_get_type(redeem_script, redeem_script_len, &redeem_type) != WALLY_OK))
        return WALLY_EINVAL;

    switch (script_type) {
    case WALLY_SCRIPT_TYPE_P2PKH:
    case WALLY_SCRIPT_TYPE_P2WPKH:
        *is_eligible = true;
        break;
    case WALLY_SCRIPT_TYPE_P2SH:
        /* A redeem script the prevout does not pay to cannot be spent with,
         * so the input is simply not eligible, as an unreadable one is not
         */
        *is_eligible = redeem_type == WALLY_SCRIPT_TYPE_P2WPKH &&
                       sp_p2sh_redeem_matches(utxo->script, redeem_script,
                                              redeem_script_len);
        break;
    case WALLY_SCRIPT_TYPE_P2TR:
        /* A NUMS internal key means the key path is unspendable */
        *is_eligible = !taproot_key_len ||
                       memcmp(taproot_key, BIP341_NUMS_XONLY, sizeof(BIP341_NUMS_XONLY));
        *is_taproot = *is_eligible;
        break;
    }

    /* BIP-352 skips inputs spent with an uncompressed public key. Compression
     * is a property of the key, not of the prevout script, so it can only be
     * seen where the PSBT names the input's key.
     */
    if (*is_eligible && !*is_taproot) {
        const struct wally_map *keypaths = &psbt->inputs[index].keypaths;
        size_t i;
        for (i = 0; i < keypaths->num_items; ++i)
            if (keypaths->items[i].key_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN) {
                *is_eligible = false;
                break;
            }
    }
    return WALLY_OK;
}

int wally_psbt_get_input_sp_eligible(const struct wally_psbt *psbt, size_t index,
                                     size_t *written)
{
    bool is_eligible = false, is_taproot = false;
    int ret;

    if (written)
        *written = 0;
    if (!psbt || index >= psbt->num_inputs || !written)
        return WALLY_EINVAL;

    ret = sp_classify_input(psbt, index, &is_eligible, &is_taproot);
    if (ret == WALLY_OK)
        *written = is_eligible ? 1 : 0;
    return ret;
}

int wally_psbt_get_sp_smallest_outpoint(const struct wally_psbt *psbt,
                                        unsigned char *bytes_out, size_t len)
{
    unsigned char candidate[WALLY_SP_OUTPOINT_LEN];
    size_t i;

    if (!psbt || !psbt->num_inputs || !bytes_out || len != WALLY_SP_OUTPOINT_LEN)
        return WALLY_EINVAL;

    for (i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input *input = &psbt->inputs[i];
        size_t n;
        memcpy(candidate, input->txhash, WALLY_TXHASH_LEN);
        for (n = 0; n < sizeof(uint32_t); ++n)
            candidate[WALLY_TXHASH_LEN + n] = (input->index >> (n * 8)) & 0xff;
        if (!i || memcmp(candidate, bytes_out, sizeof(candidate)) < 0)
            memcpy(bytes_out, candidate, sizeof(candidate));
    }
    return WALLY_OK;
}

/* Normalize one input private key for BIP-352: a taproot key whose public key
 * has odd parity is negated, so that it matches the x-only output key that the
 * verifying side reads from the scriptPubKey.
 */
static bool sp_normalize_priv_key(const secp256k1_context *ctx,
                                  const unsigned char *priv_key, bool is_taproot,
                                  unsigned char *bytes_out)
{
    memcpy(bytes_out, priv_key, EC_PRIVATE_KEY_LEN);
    if (!secp256k1_ec_seckey_verify(ctx, bytes_out))
        return false;
    if (is_taproot) {
        secp256k1_pubkey pubkey;
        secp256k1_xonly_pubkey xonly;
        int parity = 0;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, bytes_out) ||
            !secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, &parity, &pubkey) ||
            (parity && !secp256k1_ec_seckey_negate(ctx, bytes_out)))
            return false;
    }
    return true;
}

/* Sum the input private keys into BIP-352's 'a_sum', negating any taproot key
 * whose public key has odd parity. This is the untweaked aggregate that the
 * BIP-375 share and proof are built from.
 */
static int sp_sum_priv_keys(const secp256k1_context *ctx,
                            const unsigned char *priv_keys, size_t num_keys,
                            const bool *is_taproot, unsigned char *sum_out)
{
    unsigned char normalized[EC_PRIVATE_KEY_LEN];
    size_t i;
    int ret = WALLY_ERROR;

    for (i = 0; i < num_keys; ++i) {
        if (!sp_normalize_priv_key(ctx, priv_keys + i * EC_PRIVATE_KEY_LEN,
                                   is_taproot[i], normalized))
            goto cleanup;
        if (!i)
            memcpy(sum_out, normalized, EC_PRIVATE_KEY_LEN);
        else if (wally_ec_scalar_add_to(sum_out, EC_PRIVATE_KEY_LEN,
                                        normalized, EC_PRIVATE_KEY_LEN) != WALLY_OK)
            goto cleanup;
    }
    /* Summing as scalars, rather than as private keys, is deliberate: an
     * intermediate sum of zero is not an error, only a final sum of zero is.
     */
    if (!secp256k1_ec_seckey_verify(ctx, sum_out))
        goto cleanup;
    ret = WALLY_OK;

cleanup:
    wally_clear(normalized, sizeof(normalized));
    return ret;
}

/* Whether an input's prevout commits to the public key given for it. A
 * non-taproot script commits only to hash160 of the key, so the PSBT must
 * name the key itself - and nothing stops it naming a key the prevout does
 * not pay to. A share proven against such a key is bound to nothing: the
 * proof verifies, A_sum is wrong, and the recipient scanning with the real
 * A_sum never finds the output.
 */
static bool sp_key_matches_script(const struct wally_psbt *psbt, size_t index,
                                  const unsigned char *key, size_t key_len)
{
    unsigned char redeem_script[WALLY_SCRIPTPUBKEY_P2WPKH_LEN];
    unsigned char hash[HASH160_LEN];
    const struct wally_tx_output *utxo = NULL;
    const unsigned char *committed;
    size_t script_type = WALLY_SCRIPT_TYPE_UNKNOWN;
    size_t redeem_script_len = 0, field_len = 0;

    if (wally_psbt_get_input_best_utxo(psbt, index, &utxo) != WALLY_OK || !utxo ||
        wally_scriptpubkey_get_type(utxo->script, utxo->script_len,
                                    &script_type) != WALLY_OK ||
        wally_hash160(key, key_len, hash, sizeof(hash)) != WALLY_OK)
        return false;

    switch (script_type) {
    case WALLY_SCRIPT_TYPE_P2PKH:
        committed = utxo->script + 3; /* OP_DUP OP_HASH160 [push] */
        break;
    case WALLY_SCRIPT_TYPE_P2WPKH:
        committed = utxo->script + 2; /* OP_0 [push] */
        break;
    case WALLY_SCRIPT_TYPE_P2SH:
        /* Both links must hold: the prevout pays to the redeem script, and
         * the redeem script pays to the key
         */
        if (wally_psbt_get_input_redeem_script_len(psbt, index, &field_len) != WALLY_OK ||
            field_len != sizeof(redeem_script) ||
            wally_psbt_get_input_redeem_script(psbt, index, redeem_script,
                                               sizeof(redeem_script),
                                               &redeem_script_len) != WALLY_OK ||
            !sp_p2sh_redeem_matches(utxo->script, redeem_script, redeem_script_len))
            return false;
        committed = redeem_script + 2; /* OP_0 [push] */
        break;
    default:
        return false;
    }
    return !memcmp(hash, committed, sizeof(hash));
}

/* Read the public key an eligible input is spent with. For taproot that is the
 * output key from the input's scriptPubKey; otherwise it is the input's sole
 * BIP32 keypath key, which must be the key the prevout pays to. Returns false
 * if the PSBT does not name a usable key, which leaves any share on that input
 * unverifiable.
 */
static bool sp_input_pub_key(const secp256k1_context *ctx,
                             const struct wally_psbt *psbt, size_t index,
                             bool is_taproot, secp256k1_pubkey *pubkey_out)
{
    const struct wally_map *keypaths = &psbt->inputs[index].keypaths;

    if (is_taproot) {
        unsigned char compressed[EC_PUBLIC_KEY_LEN];
        const struct wally_tx_output *utxo = NULL;
        if (wally_psbt_get_input_best_utxo(psbt, index, &utxo) != WALLY_OK ||
            !utxo || utxo->script_len != WALLY_SCRIPTPUBKEY_P2TR_LEN)
            return false;
        /* BIP-352 uses the taproot *output* key, ie. the key in the
         * scriptPubKey, not the internal key the PSBT may also carry: the
         * two differ whenever the output is tweaked, as BIP-86 outputs are.
         * An x-only key denotes the even-Y point, so it is already the
         * parity-normalized key that sp_sum_priv_keys() sums to.
         */
        compressed[0] = 0x02;
        memcpy(compressed + 1, utxo->script + 2, EC_XONLY_PUBLIC_KEY_LEN);
        return !!secp256k1_ec_pubkey_parse(ctx, pubkey_out, compressed,
                                           sizeof(compressed));
    }

    if (keypaths->num_items != 1 ||
        keypaths->items[0].key_len != EC_PUBLIC_KEY_LEN ||
        !sp_key_matches_script(psbt, index, keypaths->items[0].key,
                               EC_PUBLIC_KEY_LEN))
        return false;
    return !!secp256k1_ec_pubkey_parse(ctx, pubkey_out, keypaths->items[0].key,
                                       EC_PUBLIC_KEY_LEN);
}

/* Read an input's public key once, remembering that we have done so */
static bool sp_load_pub_key(const secp256k1_context *ctx,
                            const struct wally_psbt *psbt, size_t index,
                            bool is_taproot, secp256k1_pubkey *pubkey_out,
                            bool *loaded)
{
    if (!*loaded)
        *loaded = sp_input_pub_key(ctx, psbt, index, is_taproot, pubkey_out);
    return *loaded;
}

/* Sum the eligible inputs' public keys into BIP-352's 'A_sum', the public
 * counterpart of sp_sum_priv_keys(). Taproot output keys are read x-only and
 * so are already parity-normalized, which is what makes this agree with the
 * sender's aggregate without any private key. Computed once, on the first
 * global share that needs it.
 */
static bool sp_load_sum_pub_key(const secp256k1_context *ctx,
                                const struct wally_psbt *psbt,
                                const size_t *eligible, const bool *is_taproot,
                                size_t num_keys, secp256k1_pubkey *pubkeys,
                                bool *loaded, secp256k1_pubkey *sum_out,
                                bool *sum_loaded)
{
    const secp256k1_pubkey **ptrs;
    size_t i;
    bool ok;

    if (*sum_loaded)
        return true;
    for (i = 0; i < num_keys; ++i) {
        /* Every eligible input contributes to a global share, so unlike a
         * per-input share this needs all of their keys.
         */
        if (!sp_load_pub_key(ctx, psbt, eligible[i], is_taproot[eligible[i]],
                             &pubkeys[i], &loaded[i]))
            return false;
    }
    if (!(ptrs = wally_calloc(num_keys * sizeof(*ptrs))))
        return false;
    for (i = 0; i < num_keys; ++i)
        ptrs[i] = &pubkeys[i];
    ok = !!secp256k1_ec_pubkey_combine(ctx, sum_out, ptrs, num_keys);
    wally_free(ptrs);
    *sum_loaded = ok;
    return ok;
}

/* Look up a BIP-375 share and its proof for a scan key. Returns false if the
 * pair is malformed, which is invalid whether or not it was expected here.
 */
static bool sp_find_share(const struct wally_map *shares,
                          const struct wally_map *proofs,
                          const unsigned char *scan_pubkey_bytes,
                          const struct wally_map_item **share_out,
                          const struct wally_map_item **proof_out)
{
    *share_out = wally_map_get(shares, scan_pubkey_bytes, EC_PUBLIC_KEY_LEN);
    *proof_out = wally_map_get(proofs, scan_pubkey_bytes, EC_PUBLIC_KEY_LEN);
    if (!*share_out && !*proof_out)
        return true; /* Nothing here; the caller decides whether that is ok */
    /* A share without its proof, or vice versa, is invalid on its own */
    return *share_out && *proof_out &&
           (*share_out)->value_len == EC_PUBLIC_KEY_LEN &&
           (*proof_out)->value_len == SP_DLEQ_PROOF_LEN;
}

/* The BIP-327 KeyAgg coefficient a_i of one participant key.
 *
 * It weights that party's share in the aggregate, and is a hash of the whole
 * participant list, so it needs no secret and every signer computes the same
 * value. The "second" key - the first that differs from the first - takes the
 * constant 1, which is what stops a single key aggregating to itself.
 */
static bool sp_musig_keyagg_coef(const unsigned char *pub_keys,
                                 size_t num_keys, size_t index,
                                 unsigned char *bytes_out)
{
    unsigned char buff[SHA256_LEN + EC_PUBLIC_KEY_LEN];
    const unsigned char *first = pub_keys, *pk = pub_keys + index * EC_PUBLIC_KEY_LEN;
    size_t i;

    for (i = 1; i < num_keys; ++i) {
        const unsigned char *candidate = pub_keys + i * EC_PUBLIC_KEY_LEN;
        if (memcmp(candidate, first, EC_PUBLIC_KEY_LEN)) {
            if (!memcmp(pk, candidate, EC_PUBLIC_KEY_LEN)) {
                memset(bytes_out, 0, EC_PRIVATE_KEY_LEN);
                bytes_out[EC_PRIVATE_KEY_LEN - 1] = 1;
                return true; /* The second key's coefficient is 1 */
            }
            break;
        }
    }

    if (wally_bip340_tagged_hash(pub_keys, num_keys * EC_PUBLIC_KEY_LEN,
                                 "KeyAgg list", buff, SHA256_LEN) != WALLY_OK)
        return false;
    memcpy(buff + SHA256_LEN, pk, EC_PUBLIC_KEY_LEN);
    return wally_bip340_tagged_hash(buff, sizeof(buff), "KeyAgg coefficient",
                                    bytes_out, EC_PRIVATE_KEY_LEN) == WALLY_OK;
}

/* Accumulate the tweaks between the bare aggregate of 'pub_keys' and the
 * taproot output key of tr(musig(...)/<path>), and report the resulting
 * factors along with that output key.
 *
 * Two kinds of tweak are applied. The BIP-328 synthetic derivation steps are
 * plain tweaks, which simply add to tacc. The BIP-341 taproot tweak is an
 * x-only tweak, so it first negates the accumulators if the key it is applied
 * to has an odd Y. A final negation accounts for the output key's own parity,
 * since BIP-352 hashes the even-Y form.
 */
static bool sp_musig_derive_factors(const secp256k1_context *ctx,
                                    const unsigned char *pub_keys,
                                    size_t num_keys,
                                    const uint32_t *path, size_t path_len,
                                    struct sp_musig_factors *factors,
                                    secp256k1_xonly_pubkey *output_key)
{
    unsigned char agg_pk[EC_PUBLIC_KEY_LEN], tweak[EC_PRIVATE_KEY_LEN];
    unsigned char tap_tweak[SHA256_LEN], hmac[HMAC_SHA512_LEN];
    struct wally_musig_keyagg_cache *cache = NULL;
    struct ext_key *xpub = NULL, *child = NULL;
    secp256k1_pubkey internal, tweaked;
    bool have_tweak = false, ok = false;
    size_t i, len = EC_PUBLIC_KEY_LEN;
    int parity;

    if (wally_musig_pubkey_agg(pub_keys, num_keys * EC_PUBLIC_KEY_LEN,
                               NULL, 0, &cache) != WALLY_OK)
        return false;
    if (wally_musig_pubkey_get(cache, agg_pk, sizeof(agg_pk)) != WALLY_OK ||
        wally_musig_pubkey_to_xpub(agg_pk, sizeof(agg_pk),
                                   BIP32_VER_MAIN_PUBLIC, &xpub) != WALLY_OK)
        goto cleanup;

    /* Each synthetic step tweaks by the BIP-32 IL of the step it takes. wally
     * derives the key itself; only the scalar has to be recomputed here.
     */
    for (i = 0; i < path_len; ++i) {
        unsigned char data[EC_PUBLIC_KEY_LEN + sizeof(uint32_t)];
        if (path[i] >= BIP32_INITIAL_HARDENED_CHILD)
            goto cleanup; /* A public key cannot derive a hardened child */
        memcpy(data, xpub->pub_key, EC_PUBLIC_KEY_LEN);
        data[EC_PUBLIC_KEY_LEN] = (unsigned char)(path[i] >> 24);
        data[EC_PUBLIC_KEY_LEN + 1] = (unsigned char)(path[i] >> 16);
        data[EC_PUBLIC_KEY_LEN + 2] = (unsigned char)(path[i] >> 8);
        data[EC_PUBLIC_KEY_LEN + 3] = (unsigned char)path[i];
        if (wally_hmac_sha512(xpub->chain_code, sizeof(xpub->chain_code),
                              data, sizeof(data), hmac, sizeof(hmac)) != WALLY_OK)
            goto cleanup;
        if (!have_tweak) {
            memcpy(tweak, hmac, EC_PRIVATE_KEY_LEN);
            have_tweak = true;
        } else if (wally_ec_scalar_add_to(tweak, sizeof(tweak), hmac,
                                          EC_PRIVATE_KEY_LEN) != WALLY_OK)
            goto cleanup;
        if (bip32_key_from_parent_alloc(xpub, path[i], BIP32_FLAG_KEY_PUBLIC,
                                        &child) != WALLY_OK)
            goto cleanup;
        bip32_key_free(xpub);
        xpub = child;
        child = NULL;
    }
    if (!have_tweak)
        memset(tweak, 0, sizeof(tweak));

    if (!secp256k1_ec_pubkey_parse(ctx, &internal, xpub->pub_key,
                                   EC_PUBLIC_KEY_LEN))
        goto cleanup;

    /* The x-only taproot tweak negates the accumulators for an odd-Y key */
    factors->negate = xpub->pub_key[0] == 0x03;
    if (factors->negate && have_tweak &&
        !secp256k1_ec_seckey_negate(ctx, tweak))
        goto cleanup;

    if (wally_bip340_tagged_hash(xpub->pub_key + 1, EC_XONLY_PUBLIC_KEY_LEN,
                                 "TapTweak", tap_tweak, sizeof(tap_tweak)) != WALLY_OK)
        goto cleanup;
    if (!have_tweak)
        memcpy(tweak, tap_tweak, sizeof(tweak));
    else if (wally_ec_scalar_add_to(tweak, sizeof(tweak), tap_tweak,
                                    sizeof(tap_tweak)) != WALLY_OK)
        goto cleanup;

    /* Q = lift_x(P) + tap_tweak*G: BIP-341 tweaks the even-Y form of P, which
     * is what the negation of the accumulators above already accounts for.
     */
    tweaked = internal;
    if ((factors->negate && !secp256k1_ec_pubkey_negate(ctx, &tweaked)) ||
        !secp256k1_ec_pubkey_tweak_add(ctx, &tweaked, tap_tweak) ||
        !secp256k1_ec_pubkey_serialize(ctx, agg_pk, &len, &tweaked,
                                       SECP256K1_EC_COMPRESSED))
        goto cleanup;

    /* BIP-352 uses the even-Y output key, so an odd-Y Q negates everything */
    parity = agg_pk[0] == 0x03;
    if (parity) {
        factors->negate = !factors->negate;
        if (!secp256k1_ec_seckey_negate(ctx, tweak))
            goto cleanup;
    }
    if (output_key &&
        !secp256k1_xonly_pubkey_parse(ctx, output_key, agg_pk + 1))
        goto cleanup;

    memcpy(factors->tweak, tweak, sizeof(factors->tweak));
    ok = true;

cleanup:
    bip32_key_free(child);
    bip32_key_free(xpub);
    wally_musig_keyagg_cache_free(cache);
    wally_clear_3(agg_pk, sizeof(agg_pk), tweak, sizeof(tweak),
                  hmac, sizeof(hmac));
    return ok;
}

/* Verify one BIP-375 share and its proof against the key(s) the share covers */
static bool sp_verify_share(const secp256k1_context *ctx,
                            const struct wally_map_item *share_item,
                            const struct wally_map_item *proof_item,
                            const secp256k1_pubkey *scan_pubkey,
                            const secp256k1_pubkey *covered_pubkey)
{
    secp256k1_pubkey share_pubkey;

    return !!secp256k1_ec_pubkey_parse(ctx, &share_pubkey, share_item->value,
                                       share_item->value_len) &&
           !!secp256k1_dleq_verify(ctx, proof_item->value, covered_pubkey,
                                   scan_pubkey, &share_pubkey, NULL);
}

/* Find the aggregate description of an input, or NULL if it has none */
static const struct wally_sp_musig_input *sp_musig_find(
    const struct wally_sp_musig_input *musig_inputs, size_t num_musig_inputs,
    size_t index)
{
    size_t i;
    for (i = 0; i < num_musig_inputs; ++i)
        if (musig_inputs[i].index == index)
            return &musig_inputs[i];
    return NULL;
}

/* Check the caller's aggregate descriptions before any of them are used */
static int sp_musig_inputs_verify(const struct wally_psbt *psbt,
                                  const struct wally_sp_musig_input *musig_inputs,
                                  size_t num_musig_inputs)
{
    size_t i;

    if (!musig_inputs != !num_musig_inputs)
        return WALLY_EINVAL;
    for (i = 0; i < num_musig_inputs; ++i) {
        const struct wally_sp_musig_input *musig = &musig_inputs[i];
        if (musig->index >= psbt->num_inputs ||
            (i && musig->index <= musig_inputs[i - 1].index) ||
            !musig->pub_keys ||
            musig->pub_keys_len < 2 * EC_PUBLIC_KEY_LEN ||
            musig->pub_keys_len % EC_PUBLIC_KEY_LEN ||
            !musig->path != !musig->path_len)
            return WALLY_EINVAL;
    }
    return WALLY_OK;
}

/* Look up one participant's partial share and proof for a scan key */
static bool sp_find_partial_share(const struct wally_psbt_input *input,
                                  const unsigned char *scan_pubkey_bytes,
                                  const unsigned char *participant,
                                  const struct wally_map_item **share_out,
                                  const struct wally_map_item **proof_out)
{
    unsigned char key[EC_PUBLIC_KEY_LEN * 2];

    memcpy(key, scan_pubkey_bytes, EC_PUBLIC_KEY_LEN);
    memcpy(key + EC_PUBLIC_KEY_LEN, participant, EC_PUBLIC_KEY_LEN);
    *share_out = wally_map_get(&input->sp_partial_ecdh_shares, key, sizeof(key));
    *proof_out = wally_map_get(&input->sp_partial_dleq_proofs, key, sizeof(key));
    if (!*share_out && !*proof_out)
        return true; /* This party has not contributed yet */
    return *share_out && *proof_out &&
           (*share_out)->value_len == EC_PUBLIC_KEY_LEN &&
           (*proof_out)->value_len == SP_DLEQ_PROOF_LEN;
}

/* Bind an aggregate description to the taproot output key actually spent by
 * its input. This check must run before accepting a contribution, rather than
 * leaving a bad description for a later resolver to discover. */
static bool sp_musig_input_matches(const secp256k1_context *ctx,
                                   const struct wally_psbt *psbt,
                                   const struct wally_sp_musig_input *musig,
                                   struct sp_musig_factors *factors_out)
{
    struct sp_musig_factors factors;
    secp256k1_xonly_pubkey output_key, input_key;
    const struct wally_tx_output *utxo = NULL;
    const size_t num_keys = musig->pub_keys_len / EC_PUBLIC_KEY_LEN;

    if (!sp_musig_derive_factors(ctx, musig->pub_keys, num_keys, musig->path,
                                 musig->path_len, &factors, &output_key) ||
        wally_psbt_get_input_best_utxo(psbt, musig->index, &utxo) != WALLY_OK ||
        !utxo || utxo->script_len != WALLY_SCRIPTPUBKEY_P2TR_LEN ||
        !secp256k1_xonly_pubkey_parse(ctx, &input_key, utxo->script + 2) ||
        secp256k1_xonly_pubkey_cmp(ctx, &output_key, &input_key))
        return false;
    if (factors_out)
        *factors_out = factors;
    return true;
}

/* Combine an aggregate input's partial shares into the ECDH point that the
 * input contributes, i.e. a_Q*B_scan, verifying each party's proof on the way.
 *
 * Reports through 'covered' whether every participant has contributed; when
 * one has not, there is nothing to combine yet and the input simply waits on
 * the remaining parties. Returns false only for what can never become valid:
 * a share that fails its proof, or an aggregate that is not the key the input
 * is actually spent with.
 */
static bool sp_musig_input_share(const secp256k1_context *ctx,
                                 const struct wally_psbt *psbt,
                                 const struct wally_sp_musig_input *musig,
                                 const secp256k1_pubkey *scan_pubkey,
                                 const unsigned char *scan_pubkey_bytes,
                                 secp256k1_pubkey *share_out, bool *covered)
{
    const struct wally_psbt_input *input = &psbt->inputs[musig->index];
    const size_t num_keys = musig->pub_keys_len / EC_PUBLIC_KEY_LEN;
    const secp256k1_pubkey **ptrs = NULL;
    secp256k1_pubkey *weighted = NULL, combined, tweaked;
    struct sp_musig_factors factors;
    unsigned char coef[EC_PRIVATE_KEY_LEN];
    size_t i, num_shares = 0;
    bool ok = false;

    *covered = false;

    /* The aggregate must be the key the input is spent with, or the shares
     * combine to something that pays a script nobody can spend
     */
    if (!sp_musig_input_matches(ctx, psbt, musig, &factors))
        return false;

    weighted = wally_calloc(num_keys * sizeof(*weighted));
    ptrs = wally_calloc(num_keys * sizeof(*ptrs));
    if (!weighted || !ptrs)
        goto cleanup;

    for (i = 0; i < num_keys; ++i) {
        const unsigned char *participant = musig->pub_keys + i * EC_PUBLIC_KEY_LEN;
        const struct wally_map_item *share_item, *proof_item;
        secp256k1_pubkey participant_pubkey;

        if (!sp_find_partial_share(input, scan_pubkey_bytes, participant,
                                   &share_item, &proof_item))
            goto cleanup;
        if (!share_item) {
            ok = true; /* Waiting on this party, which is not an error */
            goto cleanup;
        }
        if (!secp256k1_ec_pubkey_parse(ctx, &participant_pubkey, participant,
                                       EC_PUBLIC_KEY_LEN) ||
            !sp_verify_share(ctx, share_item, proof_item, scan_pubkey,
                             &participant_pubkey) ||
            !secp256k1_ec_pubkey_parse(ctx, &weighted[num_shares],
                                       share_item->value, share_item->value_len))
            goto cleanup;
        /* Weight the share by its party's KeyAgg coefficient */
        if (!sp_musig_keyagg_coef(musig->pub_keys, num_keys, i, coef) ||
            !secp256k1_ec_pubkey_tweak_mul(ctx, &weighted[num_shares], coef))
            goto cleanup;
        ptrs[num_shares] = &weighted[num_shares];
        ++num_shares;
    }

    /* sum(a_i * share_i), then the accumulated tweak and parity that take it
     * from the bare aggregate to the taproot output key the input is spent with
     */
    if (!secp256k1_ec_pubkey_combine(ctx, &combined, ptrs, num_shares))
        goto cleanup;
    if (factors.negate && !secp256k1_ec_pubkey_negate(ctx, &combined))
        goto cleanup;
    tweaked = *scan_pubkey;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &tweaked, factors.tweak))
        goto cleanup;
    ptrs[0] = &combined;
    ptrs[1] = &tweaked;
    if (!secp256k1_ec_pubkey_combine(ctx, share_out, ptrs, 2))
        goto cleanup;
    *covered = ok = true;

cleanup:
    wally_free(ptrs);
    if (weighted)
        wally_clear(weighted, num_keys * sizeof(*weighted));
    wally_free(weighted);
    wally_clear_2(coef, sizeof(coef), &factors, sizeof(factors));
    return ok;
}

/* BIP-352's input_hash, which ties the outputs to this transaction's inputs:
 * tagged_hash("BIP0352/Inputs", smallest_outpoint || ser33(A_sum)).
 */
static bool sp_input_hash(const secp256k1_context *ctx,
                          const struct wally_psbt *psbt,
                          const secp256k1_pubkey *sum_pubkey,
                          unsigned char *bytes_out)
{
    unsigned char buff[WALLY_SP_OUTPOINT_LEN + EC_PUBLIC_KEY_LEN];
    size_t len = EC_PUBLIC_KEY_LEN;

    return wally_psbt_get_sp_smallest_outpoint(psbt, buff, WALLY_SP_OUTPOINT_LEN) == WALLY_OK &&
           !!secp256k1_ec_pubkey_serialize(ctx, buff + WALLY_SP_OUTPOINT_LEN, &len,
                                           sum_pubkey, SECP256K1_EC_COMPRESSED) &&
           wally_bip340_tagged_hash(buff, sizeof(buff), "BIP0352/Inputs",
                                    bytes_out, SHA256_LEN) == WALLY_OK;
}

/* Derive the BIP-352 output script of the k'th recipient sharing a scan key:
 *
 *   t_k = tagged_hash("BIP0352/SharedSecret", ser33(shared_secret) || ser32(k))
 *   P_k = B_spend + t_k*G
 *
 * where shared_secret = input_hash * ecdh_share. This needs no private key:
 * the share is public and DLEQ-proven, which is what lets a signer that owns
 * none of the eligible inputs check what another signer resolved.
 */
static bool sp_derive_script(const secp256k1_context *ctx,
                             const secp256k1_pubkey *shared_secret,
                             const unsigned char *spend_pubkey_bytes,
                             uint32_t k, unsigned char *bytes_out)
{
    unsigned char buff[EC_PUBLIC_KEY_LEN + sizeof(uint32_t)];
    unsigned char t_k[SHA256_LEN], xonly[EC_XONLY_PUBLIC_KEY_LEN];
    secp256k1_xonly_pubkey output_xonly;
    secp256k1_pubkey output;
    size_t len = EC_PUBLIC_KEY_LEN, written = 0, n;

    if (!secp256k1_ec_pubkey_serialize(ctx, buff, &len, shared_secret,
                                       SECP256K1_EC_COMPRESSED))
        return false;
    for (n = 0; n < sizeof(uint32_t); ++n)
        buff[EC_PUBLIC_KEY_LEN + n] = (k >> ((sizeof(uint32_t) - 1 - n) * 8)) & 0xff;

    if (wally_bip340_tagged_hash(buff, sizeof(buff), "BIP0352/SharedSecret",
                                 t_k, sizeof(t_k)) != WALLY_OK ||
        !secp256k1_ec_pubkey_parse(ctx, &output, spend_pubkey_bytes, EC_PUBLIC_KEY_LEN) ||
        !secp256k1_ec_pubkey_tweak_add(ctx, &output, t_k) ||
        !secp256k1_xonly_pubkey_from_pubkey(ctx, &output_xonly, NULL, &output) ||
        !secp256k1_xonly_pubkey_serialize(ctx, xonly, &output_xonly))
        return false;
    /* NOTE: as in sp_resolve, the output key is used as-is, not re-tweaked */
    return wally_scriptpubkey_p2tr_from_bytes(xonly, sizeof(xonly), 0, bytes_out,
                                              WALLY_SCRIPTPUBKEY_P2TR_LEN,
                                              &written) == WALLY_OK &&
           written == WALLY_SCRIPTPUBKEY_P2TR_LEN;
}

/* Check that an output holds the script BIP-352 derives for it, or where the
 * output has no script yet and 'resolve' is set, store the derived script.
 */
static bool sp_apply_script(const secp256k1_context *ctx,
                            struct wally_psbt *psbt,
                            const secp256k1_pubkey *shared_secret,
                            const struct sp_recipient *recipient, uint32_t k,
                            bool resolve)
{
    unsigned char expected[WALLY_SCRIPTPUBKEY_P2TR_LEN];
    unsigned char actual[WALLY_SCRIPTPUBKEY_P2TR_LEN];
    size_t written = 0, existing_len = 0;

    if (!sp_derive_script(ctx, shared_secret, recipient->spend_pubkey, k, expected) ||
        wally_psbt_get_output_script_len(psbt, recipient->output_index,
                                         &existing_len) != WALLY_OK)
        return false;

    if (!existing_len)
        return resolve &&
               wally_psbt_set_output_script(psbt, recipient->output_index,
                                            expected, sizeof(expected)) == WALLY_OK;

    /* An existing script must be the derived one, whoever wrote it */
    return wally_psbt_get_output_script(psbt, recipient->output_index, actual,
                                        sizeof(actual), &written) == WALLY_OK &&
           written == sizeof(actual) &&
           !memcmp(expected, actual, sizeof(expected));
}

/* Derive the aux randomness for the i'th DLEQ proof from the caller's entropy */
static int sp_proof_entropy(const unsigned char *entropy, size_t index,
                            unsigned char *bytes_out)
{
    unsigned char buff[SHA256_LEN + sizeof(uint32_t)];
    int ret;

    size_t n;
    memcpy(buff, entropy, SHA256_LEN);
    for (n = 0; n < sizeof(uint32_t); ++n)
        buff[SHA256_LEN + n] = (index >> ((sizeof(uint32_t) - 1 - n) * 8)) & 0xff;
    ret = wally_sha256(buff, sizeof(buff), bytes_out, SHA256_LEN);
    wally_clear(buff, sizeof(buff));
    return ret;
}

/* Store one BIP-375 global ECDH share and DLEQ proof for a recipient */
static int sp_store_share(struct wally_psbt *psbt, const secp256k1_context *ctx,
                          const secp256k1_pubkey *scan_pubkey,
                          const secp256k1_pubkey *sum_pubkey,
                          const unsigned char *scan_pubkey_bytes,
                          const unsigned char *sum_priv_key,
                          const unsigned char *entropy, size_t proof_index)
{
    unsigned char share[EC_PUBLIC_KEY_LEN], proof[SP_DLEQ_PROOF_LEN];
    unsigned char aux[SHA256_LEN];
    secp256k1_pubkey share_pubkey = *scan_pubkey;
    size_t share_len = sizeof(share);
    int ret = WALLY_ERROR;

    if (sp_proof_entropy(entropy, proof_index, aux) != WALLY_OK)
        goto cleanup;

    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &share_pubkey, sum_priv_key) ||
        !secp256k1_ec_pubkey_serialize(ctx, share, &share_len, &share_pubkey,
                                       SECP256K1_EC_COMPRESSED) ||
        share_len != sizeof(share) ||
        !secp256k1_dleq_prove(ctx, proof, sum_priv_key, scan_pubkey, aux, NULL) ||
        /* Check our own work: a bad proof makes the payment unusable */
        !secp256k1_dleq_verify(ctx, proof, sum_pubkey, scan_pubkey, &share_pubkey, NULL))
        goto cleanup;

    ret = wally_psbt_set_global_sp_ecdh_share(psbt, scan_pubkey_bytes,
                                              EC_PUBLIC_KEY_LEN, share, sizeof(share));
    if (ret == WALLY_OK)
        ret = wally_psbt_set_global_sp_dleq_proof(psbt, scan_pubkey_bytes,
                                                  EC_PUBLIC_KEY_LEN, proof, sizeof(proof));

cleanup:
    wally_clear_3(share, sizeof(share), proof, sizeof(proof), aux, sizeof(aux));
    return ret;
}

/* Store one BIP-375 per-input ECDH share and DLEQ proof for a recipient */
static int sp_store_input_share(struct wally_psbt_input *input,
                                const secp256k1_context *ctx,
                                const secp256k1_pubkey *scan_pubkey,
                                const secp256k1_pubkey *input_pubkey,
                                const unsigned char *scan_pubkey_bytes,
                                const unsigned char *priv_key,
                                const unsigned char *entropy, size_t proof_index)
{
    unsigned char share[EC_PUBLIC_KEY_LEN], proof[SP_DLEQ_PROOF_LEN];
    unsigned char aux[SHA256_LEN];
    secp256k1_pubkey share_pubkey = *scan_pubkey;
    size_t share_len = sizeof(share);
    int ret = WALLY_ERROR;

    if (sp_proof_entropy(entropy, proof_index, aux) != WALLY_OK)
        goto cleanup;

    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &share_pubkey, priv_key) ||
        !secp256k1_ec_pubkey_serialize(ctx, share, &share_len, &share_pubkey,
                                       SECP256K1_EC_COMPRESSED) ||
        share_len != sizeof(share) ||
        !secp256k1_dleq_prove(ctx, proof, priv_key, scan_pubkey, aux, NULL) ||
        /* Check our own work against the key the other signers will verify
         * with: a bad proof makes the payment unresolvable for all of them
         */
        !secp256k1_dleq_verify(ctx, proof, input_pubkey, scan_pubkey, &share_pubkey, NULL))
        goto cleanup;

    ret = wally_psbt_input_set_sp_ecdh_share(input, scan_pubkey_bytes,
                                             EC_PUBLIC_KEY_LEN, share, sizeof(share));
    if (ret == WALLY_OK)
        ret = wally_psbt_input_set_sp_dleq_proof(input, scan_pubkey_bytes,
                                                 EC_PUBLIC_KEY_LEN, proof, sizeof(proof));

cleanup:
    wally_clear_3(share, sizeof(share), proof, sizeof(proof), aux, sizeof(aux));
    return ret;
}

/* NOTE: the arguments are validated by the caller */
static int sp_contribute(struct wally_psbt *psbt,
                         const uint32_t *indices, size_t num_indices,
                         const unsigned char *priv_keys,
                         const unsigned char *entropy)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    struct sp_recipient *recipients = NULL;
    bool *is_taproot = NULL;
    unsigned char priv_key[EC_PRIVATE_KEY_LEN];
    size_t num_recipients = 0, proof_index = 0;
    size_t i, j, is_elements = 0;
    int ret = WALLY_EINVAL;

    if (psbt->version != WALLY_PSBT_VERSION_2 ||
        wally_psbt_is_elements(psbt, &is_elements) != WALLY_OK || is_elements)
        return WALLY_EINVAL; /* BIP-375 is PSBTv2 and bitcoin only */

    recipients = sp_collect_recipients(psbt, &num_recipients, &ret);
    if (!recipients)
        return ret == WALLY_OK ? WALLY_EINVAL : ret; /* Nothing to contribute to */

    ret = WALLY_ENOMEM;
    if (!(is_taproot = wally_calloc(psbt->num_inputs * sizeof(bool))))
        goto cleanup;

    /* Every input must classify, as it must for the signer that resolves */
    for (i = 0; i < psbt->num_inputs; ++i) {
        bool is_eligible = false;
        ret = sp_classify_input(psbt, i, &is_eligible, &is_taproot[i]);
        if (ret != WALLY_OK)
            goto cleanup;
    }

    for (i = 0; i < num_indices; ++i) {
        struct wally_psbt_input *input;
        secp256k1_pubkey input_pubkey, derived_pubkey;
        size_t is_eligible = 0;
        bool loaded = false;

        ret = WALLY_EINVAL;
        /* Ascending and unique keeps the caller's keys unambiguously paired
         * with their inputs, and makes a repeated index impossible
         */
        if (indices[i] >= psbt->num_inputs || (i && indices[i] <= indices[i - 1]))
            goto cleanup;
        if (wally_psbt_get_input_sp_eligible(psbt, indices[i], &is_eligible) != WALLY_OK ||
            !is_eligible)
            goto cleanup;

        if (!sp_normalize_priv_key(ctx, priv_keys + i * EC_PRIVATE_KEY_LEN,
                                   is_taproot[indices[i]], priv_key) ||
            !secp256k1_ec_pubkey_create(ctx, &derived_pubkey, priv_key) ||
            !sp_load_pub_key(ctx, psbt, indices[i], is_taproot[indices[i]],
                             &input_pubkey, &loaded) ||
            secp256k1_ec_pubkey_cmp(ctx, &derived_pubkey, &input_pubkey))
            goto cleanup; /* Not the key this input is spent with */

        input = &psbt->inputs[indices[i]];
        for (j = 0; j < num_recipients; ++j) {
            /* Duplicate scan keys are adjacent after the BIP-375 sort, and one
             * share covers them all, as it does in sp_resolve()
             */
            if (j && !memcmp(recipients[j].scan_pubkey, recipients[j - 1].scan_pubkey,
                             EC_PUBLIC_KEY_LEN))
                continue;
            if (!secp256k1_ec_pubkey_parse(ctx, &derived_pubkey,
                                           recipients[j].scan_pubkey, EC_PUBLIC_KEY_LEN)) {
                ret = WALLY_EINVAL;
                goto cleanup;
            }
            ret = sp_store_input_share(input, ctx, &derived_pubkey, &input_pubkey,
                                       recipients[j].scan_pubkey, priv_key,
                                       entropy, proof_index++);
            if (ret != WALLY_OK)
                goto cleanup;
        }
    }
    ret = WALLY_OK;

cleanup:
    wally_clear(priv_key, sizeof(priv_key));
    wally_free(is_taproot);
    wally_free(recipients);
    return ret;
}

/* Store one party's partial share and proof for a scan key. Unlike a BIP-375
 * share, this is proven against the party's own participant key rather than
 * the key the input is spent with: no party holds the latter's secret.
 */
static int sp_store_partial_share(struct wally_psbt_input *input,
                                  const secp256k1_context *ctx,
                                  const secp256k1_pubkey *scan_pubkey,
                                  const secp256k1_pubkey *participant_pubkey,
                                  const unsigned char *scan_pubkey_bytes,
                                  const unsigned char *participant,
                                  const unsigned char *priv_key,
                                  const unsigned char *entropy, size_t proof_index)
{
    unsigned char share[EC_PUBLIC_KEY_LEN], proof[SP_DLEQ_PROOF_LEN];
    unsigned char aux[SHA256_LEN];
    secp256k1_pubkey share_pubkey = *scan_pubkey;
    size_t share_len = sizeof(share);
    int ret = WALLY_ERROR;

    if (sp_proof_entropy(entropy, proof_index, aux) != WALLY_OK)
        goto cleanup;

    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &share_pubkey, priv_key) ||
        !secp256k1_ec_pubkey_serialize(ctx, share, &share_len, &share_pubkey,
                                       SECP256K1_EC_COMPRESSED) ||
        share_len != sizeof(share) ||
        !secp256k1_dleq_prove(ctx, proof, priv_key, scan_pubkey, aux, NULL) ||
        /* Check our own work against the key the other parties will verify
         * with, as sp_store_input_share() does
         */
        !secp256k1_dleq_verify(ctx, proof, participant_pubkey, scan_pubkey,
                               &share_pubkey, NULL))
        goto cleanup;

    ret = wally_psbt_input_set_sp_partial_ecdh_share(input, scan_pubkey_bytes,
                                                     EC_PUBLIC_KEY_LEN,
                                                     participant, EC_PUBLIC_KEY_LEN,
                                                     share, sizeof(share));
    if (ret == WALLY_OK)
        ret = wally_psbt_input_set_sp_partial_dleq_proof(input, scan_pubkey_bytes,
                                                         EC_PUBLIC_KEY_LEN,
                                                         participant, EC_PUBLIC_KEY_LEN,
                                                         proof, sizeof(proof));

cleanup:
    wally_clear_3(share, sizeof(share), proof, sizeof(proof), aux, sizeof(aux));
    return ret;
}

static int sp_musig_contribute(struct wally_psbt *psbt,
                               const struct wally_sp_musig_input *musig_inputs,
                               size_t num_musig_inputs,
                               const unsigned char *priv_keys,
                               const unsigned char *entropy)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    struct sp_recipient *recipients = NULL;
    unsigned char participant[EC_PUBLIC_KEY_LEN];
    size_t num_recipients = 0, proof_index = 0;
    size_t i, j, k, is_elements = 0;
    int ret = WALLY_EINVAL;

    if (psbt->version != WALLY_PSBT_VERSION_2 ||
        wally_psbt_is_elements(psbt, &is_elements) != WALLY_OK || is_elements)
        return WALLY_EINVAL;

    recipients = sp_collect_recipients(psbt, &num_recipients, &ret);
    if (!recipients)
        return ret == WALLY_OK ? WALLY_EINVAL : ret; /* Nothing to contribute to */

    for (i = 0; i < num_musig_inputs; ++i) {
        const struct wally_sp_musig_input *musig = &musig_inputs[i];
        const size_t num_keys = musig->pub_keys_len / EC_PUBLIC_KEY_LEN;
        const unsigned char *priv_key = priv_keys + i * EC_PRIVATE_KEY_LEN;
        struct wally_psbt_input *input = &psbt->inputs[musig->index];
        secp256k1_pubkey participant_pubkey, scan_pubkey;
        size_t participant_len = sizeof(participant), is_eligible = 0;

        ret = WALLY_EINVAL;
        if (wally_psbt_get_input_sp_eligible(psbt, musig->index, &is_eligible) != WALLY_OK ||
            !is_eligible)
            goto cleanup;

        /* Our key must be one of this input's participants: a share proven
         * against a key outside the aggregate combines to nothing
         */
        if (!secp256k1_ec_pubkey_create(ctx, &participant_pubkey, priv_key) ||
            !secp256k1_ec_pubkey_serialize(ctx, participant, &participant_len,
                                           &participant_pubkey,
                                           SECP256K1_EC_COMPRESSED) ||
            participant_len != sizeof(participant))
            goto cleanup;
        for (k = 0; k < num_keys; ++k)
            if (!memcmp(participant, musig->pub_keys + k * EC_PUBLIC_KEY_LEN,
                        EC_PUBLIC_KEY_LEN))
                break;
        if (k == num_keys)
            goto cleanup;

        for (j = 0; j < num_recipients; ++j) {
            /* One share covers every recipient sharing a scan key */
            if (j && !memcmp(recipients[j].scan_pubkey, recipients[j - 1].scan_pubkey,
                             EC_PUBLIC_KEY_LEN))
                continue;
            if (!secp256k1_ec_pubkey_parse(ctx, &scan_pubkey,
                                           recipients[j].scan_pubkey,
                                           EC_PUBLIC_KEY_LEN))
                goto cleanup;
            ret = sp_store_partial_share(input, ctx, &scan_pubkey,
                                         &participant_pubkey,
                                         recipients[j].scan_pubkey, participant,
                                         priv_key, entropy, proof_index++);
            if (ret != WALLY_OK)
                goto cleanup;
        }
    }
    ret = WALLY_OK;

cleanup:
    wally_free(recipients);
    return ret;
}

static void sp_hash_le32(struct sha256_ctx *ctx, uint32_t value)
{
    unsigned char bytes[sizeof(value)];
    sha256_update(ctx, bytes, uint32_to_le_bytes(value, bytes));
}

static void sp_hash_le64(struct sha256_ctx *ctx, uint64_t value)
{
    unsigned char bytes[sizeof(value)];
    sha256_update(ctx, bytes, uint64_to_le_bytes(value, bytes));
}

static void sp_hash_varint(struct sha256_ctx *ctx, uint64_t value)
{
    unsigned char bytes[9];
    sha256_update(ctx, bytes, varint_to_bytes(value, bytes));
}

int wally_psbt_get_sp_musig_session_digest(const struct wally_psbt *psbt,
                                           unsigned char *bytes_out, size_t len)
{
    struct sha256_ctx ctx;
    struct sha256 result;
    size_t locktime = 0, is_elements = 0, i;

    if (!psbt || psbt->version != WALLY_PSBT_VERSION_2 ||
        !bytes_out || len != SHA256_LEN || !psbt->num_inputs ||
        wally_psbt_is_elements(psbt, &is_elements) != WALLY_OK || is_elements ||
        wally_psbt_get_locktime(psbt, &locktime) != WALLY_OK)
        return WALLY_EINVAL;

    sha256_init(&ctx);
    sp_hash_le32(&ctx, psbt->tx_version);
    sp_hash_varint(&ctx, psbt->num_inputs);
    for (i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input *input = &psbt->inputs[i];
        sha256_update(&ctx, input->txhash, sizeof(input->txhash));
        sp_hash_le32(&ctx, input->index);
        sp_hash_le32(&ctx, input->sequence);
    }
    sp_hash_le32(&ctx, (uint32_t)locktime);
    sp_hash_varint(&ctx, psbt->num_outputs);
    for (i = 0; i < psbt->num_outputs; ++i) {
        const struct wally_psbt_output *output = &psbt->outputs[i];
        unsigned char info[WALLY_SP_V0_INFO_LEN];
        size_t info_len = 0;

        if (!output->has_amount ||
            wally_psbt_get_output_sp_v0_info(psbt, i, info, sizeof(info),
                                             &info_len) != WALLY_OK)
            return WALLY_EINVAL;
        sp_hash_le64(&ctx, output->amount);
        if (info_len) {
            if (info_len != sizeof(info))
                return WALLY_EINVAL;
            sha256_update(&ctx, info, sizeof(info));
        } else {
            sp_hash_varint(&ctx, output->script_len);
            if (output->script_len)
                sha256_update(&ctx, output->script, output->script_len);
        }
    }
    sha256_done(&ctx, &result);
    memcpy(bytes_out, result.u.u8, SHA256_LEN);
    wally_clear(&result, sizeof(result));
    return WALLY_OK;
}

/* Silent-payment shares describe the complete eligible input set, so every
 * eligible input must commit to all inputs and outputs when it is signed. */
static int sp_sighash_policy(const struct wally_psbt *psbt)
{
    size_t i;
    for (i = 0; i < psbt->num_inputs; ++i) {
        bool is_eligible = false, is_taproot = false;
        int ret = sp_classify_input(psbt, i, &is_eligible, &is_taproot);
        (void)is_taproot;
        if (ret != WALLY_OK)
            return ret;
        if (is_eligible && psbt->inputs[i].sighash != WALLY_SIGHASH_DEFAULT &&
            psbt->inputs[i].sighash != WALLY_SIGHASH_ALL)
            return WALLY_EINVAL;
    }
    return WALLY_OK;
}

/* Derive the bare aggregate/map key and this signer's participant key, while
 * ensuring the caller's participant list is the one registered by the PSBT. */
static int sp_musig_signer_keys(const struct wally_psbt *psbt,
                                const struct wally_sp_musig_input *musig,
                                const unsigned char *priv_key,
                                unsigned char *participant,
                                unsigned char *aggregate)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    struct wally_musig_keyagg_cache *cache = NULL;
    const struct wally_map_item *item;
    secp256k1_pubkey pubkey;
    size_t participant_len = EC_PUBLIC_KEY_LEN, i;
    int ret;

    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key) ||
        !secp256k1_ec_pubkey_serialize(ctx, participant, &participant_len, &pubkey,
                                       SECP256K1_EC_COMPRESSED) ||
        participant_len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;
    for (i = 0; i < musig->pub_keys_len; i += EC_PUBLIC_KEY_LEN)
        if (!memcmp(participant, musig->pub_keys + i, EC_PUBLIC_KEY_LEN))
            break;
    if (i == musig->pub_keys_len)
        return WALLY_EINVAL;

    ret = wally_musig_pubkey_agg(musig->pub_keys, musig->pub_keys_len,
                                 NULL, 0, &cache);
    if (ret == WALLY_OK)
        ret = wally_musig_pubkey_get(cache, aggregate, EC_PUBLIC_KEY_LEN);
    wally_musig_keyagg_cache_free(cache);
    if (ret != WALLY_OK)
        return ret;
    item = wally_map_get(&psbt->inputs[musig->index].musig2_pubkeys,
                         aggregate, EC_PUBLIC_KEY_LEN);
    return item && item->value_len == musig->pub_keys_len &&
           !memcmp(item->value, musig->pub_keys, musig->pub_keys_len) ?
           WALLY_OK : WALLY_EINVAL;
}

int wally_psbt_sp_musig_contribute(struct wally_psbt *psbt,
                                   const struct wally_sp_musig_input *musig_inputs,
                                   size_t num_musig_inputs,
                                   const unsigned char *priv_keys, size_t priv_keys_len,
                                   const unsigned char *entropy, size_t entropy_len,
                                   uint32_t flags)
{
    struct wally_psbt *staged = NULL;
    struct wally_psbt old;
    int ret;

    if (!psbt || !psbt->num_inputs || !musig_inputs || !num_musig_inputs ||
        !priv_keys || priv_keys_len != num_musig_inputs * EC_PRIVATE_KEY_LEN ||
        !entropy || entropy_len != SHA256_LEN || flags)
        return WALLY_EINVAL;
    ret = sp_musig_inputs_verify(psbt, musig_inputs, num_musig_inputs);
    if (ret != WALLY_OK)
        return ret;

    ret = wally_psbt_clone_alloc(psbt, 0, &staged);
    if (ret != WALLY_OK)
        return ret;
    ret = sp_musig_contribute(staged, musig_inputs, num_musig_inputs,
                              priv_keys, entropy);
    if (ret == WALLY_OK) {
        old = *psbt;
        *psbt = *staged;
        *staged = old;
    }
    wally_psbt_free(staged);
    return ret;
}

int wally_psbt_sp_contribute(struct wally_psbt *psbt,
                             const uint32_t *indices, size_t num_indices,
                             const unsigned char *priv_keys, size_t priv_keys_len,
                             const unsigned char *entropy, size_t entropy_len,
                             uint32_t flags)
{
    struct wally_psbt *staged = NULL;
    struct wally_psbt old;
    int ret;

    if (!psbt || !psbt->num_inputs || !indices || !num_indices || !priv_keys ||
        priv_keys_len != num_indices * EC_PRIVATE_KEY_LEN || !entropy ||
        entropy_len != SHA256_LEN || flags)
        return WALLY_EINVAL;

    ret = wally_psbt_clone_alloc(psbt, 0, &staged);
    if (ret != WALLY_OK)
        return ret;
    ret = sp_contribute(staged, indices, num_indices, priv_keys, entropy);
    if (ret == WALLY_OK) {
        old = *psbt;
        *psbt = *staged;
        *staged = old;
    }
    wally_psbt_free(staged);
    return ret;
}

/* NOTE: the arguments are validated by the caller */
static int sp_resolve(struct wally_psbt *psbt,
                      const unsigned char *priv_keys, size_t priv_keys_len,
                      const unsigned char *entropy)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    struct sp_recipient *recipients = NULL;
    secp256k1_silentpayments_recipient *recipient_objs = NULL;
    const secp256k1_silentpayments_recipient **recipient_ptrs = NULL;
    secp256k1_xonly_pubkey *output_objs = NULL;
    secp256k1_xonly_pubkey **output_ptrs = NULL;
    secp256k1_keypair *keypairs = NULL;
    const secp256k1_keypair **keypair_ptrs = NULL;
    const unsigned char **seckey_ptrs = NULL;
    bool *is_taproot = NULL;
    unsigned char outpoint[WALLY_SP_OUTPOINT_LEN];
    unsigned char sum_priv_key[EC_PRIVATE_KEY_LEN];
    secp256k1_pubkey sum_pubkey;
    size_t num_recipients = 0, num_keys = 0, num_keypairs = 0;
    size_t i, keypair_index = 0, seckey_index = 0, proof_index = 0;
    size_t is_elements = 0;
    int ret = WALLY_EINVAL;

    if (psbt->version != WALLY_PSBT_VERSION_2 ||
        wally_psbt_is_elements(psbt, &is_elements) != WALLY_OK || is_elements)
        return WALLY_EINVAL; /* BIP-375 is PSBTv2 and bitcoin only */

    /* Collect the recipients, in BIP-375 order */
    recipients = sp_collect_recipients(psbt, &num_recipients, &ret);
    if (!recipients)
        return ret == WALLY_OK ? WALLY_EINVAL : ret; /* Nothing to resolve */

    ret = WALLY_EINVAL;
    if (!(is_taproot = wally_calloc(psbt->num_inputs * sizeof(bool))))
        goto cleanup;

    /* One key per eligible input, in input order */
    for (i = 0; i < psbt->num_inputs; ++i) {
        bool is_eligible = false;
        ret = sp_classify_input(psbt, i, &is_eligible, &is_taproot[num_keys]);
        if (ret != WALLY_OK)
            goto cleanup;
        if (is_eligible)
            ++num_keys;
    }
    ret = WALLY_EINVAL;
    if (!num_keys || num_keys != priv_keys_len / EC_PRIVATE_KEY_LEN)
        goto cleanup; /* Wrong number of keys for the eligible inputs */

    for (i = 0; i < num_keys; ++i)
        num_keypairs += is_taproot[i] ? 1 : 0;

    recipient_objs = wally_calloc(num_recipients * sizeof(*recipient_objs));
    recipient_ptrs = wally_calloc(num_recipients * sizeof(*recipient_ptrs));
    output_objs = wally_calloc(num_recipients * sizeof(*output_objs));
    output_ptrs = wally_calloc(num_recipients * sizeof(*output_ptrs));
    if (num_keypairs) {
        keypairs = wally_calloc(num_keypairs * sizeof(*keypairs));
        keypair_ptrs = wally_calloc(num_keypairs * sizeof(*keypair_ptrs));
    }
    if (num_keys != num_keypairs)
        seckey_ptrs = wally_calloc((num_keys - num_keypairs) * sizeof(*seckey_ptrs));
    if (!recipient_objs || !recipient_ptrs || !output_objs || !output_ptrs ||
        (num_keypairs && (!keypairs || !keypair_ptrs)) ||
        (num_keys != num_keypairs && !seckey_ptrs)) {
        ret = WALLY_ENOMEM;
        goto cleanup;
    }

    ret = WALLY_ERROR;
    /* NOTE: sender_create_outputs() may permute recipient_ptrs, but not the
     * storage it points into, so indexing recipient_objs by our sorted order
     * remains valid. Setting index = i makes secp's sort preserve that order.
     */
    for (i = 0; i < num_recipients; ++i) {
        if (!secp256k1_ec_pubkey_parse(ctx, &recipient_objs[i].scan_pubkey,
                                       recipients[i].scan_pubkey, EC_PUBLIC_KEY_LEN) ||
            !secp256k1_ec_pubkey_parse(ctx, &recipient_objs[i].spend_pubkey,
                                       recipients[i].spend_pubkey, EC_PUBLIC_KEY_LEN))
            goto cleanup;
        recipient_objs[i].index = i;
        recipient_ptrs[i] = &recipient_objs[i];
        output_ptrs[i] = &output_objs[i];
    }

    for (i = 0; i < num_keys; ++i) {
        const unsigned char *priv_key = priv_keys + i * EC_PRIVATE_KEY_LEN;
        if (is_taproot[i]) {
            if (!secp256k1_keypair_create(ctx, &keypairs[keypair_index], priv_key))
                goto cleanup;
            keypair_ptrs[keypair_index] = &keypairs[keypair_index];
            ++keypair_index;
        } else
            seckey_ptrs[seckey_index++] = priv_key;
    }

    if (wally_psbt_get_sp_smallest_outpoint(psbt, outpoint, sizeof(outpoint)) != WALLY_OK ||
        !secp256k1_silentpayments_sender_create_outputs(ctx, output_ptrs, recipient_ptrs,
                                                        num_recipients, outpoint,
                                                        keypair_ptrs, num_keypairs,
                                                        seckey_ptrs, seckey_index) ||
        sp_sum_priv_keys(ctx, priv_keys, num_keys, is_taproot, sum_priv_key) != WALLY_OK ||
        !secp256k1_ec_pubkey_create(ctx, &sum_pubkey, sum_priv_key))
        goto cleanup;

    for (i = 0; i < num_recipients; ++i) {
        unsigned char xonly[EC_XONLY_PUBLIC_KEY_LEN];
        unsigned char script[WALLY_SCRIPTPUBKEY_P2TR_LEN];
        unsigned char existing[WALLY_SCRIPTPUBKEY_P2TR_LEN];
        size_t script_len = 0, existing_len = 0;

        /* NOTE: the output key is used as-is, ie. not re-tweaked per BIP-341 */
        if (!secp256k1_xonly_pubkey_serialize(ctx, xonly, &output_objs[i]))
            goto cleanup;
        ret = wally_scriptpubkey_p2tr_from_bytes(xonly, sizeof(xonly), 0, script,
                                                 sizeof(script), &script_len);
        if (ret != WALLY_OK)
            goto cleanup;

        ret = wally_psbt_get_output_script_len(psbt, recipients[i].output_index,
                                               &existing_len);
        if (ret != WALLY_OK)
            goto cleanup;
        if (existing_len) {
            if (existing_len != script_len ||
                wally_psbt_get_output_script(psbt, recipients[i].output_index,
                                             existing, sizeof(existing),
                                             &existing_len) != WALLY_OK ||
                existing_len != script_len ||
                memcmp(existing, script, script_len)) {
                ret = WALLY_EINVAL;
                goto cleanup;
            }
        } else {
            ret = wally_psbt_set_output_script(psbt, recipients[i].output_index,
                                               script, script_len);
        }
        if (ret != WALLY_OK)
            goto cleanup;

        /* Duplicate scan keys are adjacent after the BIP-375 sort */
        if (i && !memcmp(recipients[i].scan_pubkey, recipients[i - 1].scan_pubkey,
                         EC_PUBLIC_KEY_LEN))
            continue;
        ret = sp_store_share(psbt, ctx, &recipient_objs[i].scan_pubkey, &sum_pubkey,
                             recipients[i].scan_pubkey, sum_priv_key, entropy, proof_index++);
        if (ret != WALLY_OK)
            goto cleanup;
    }
    ret = WALLY_OK;

cleanup:
    wally_clear(sum_priv_key, sizeof(sum_priv_key));
    if (keypairs)
        wally_clear(keypairs, num_keypairs * sizeof(*keypairs));
    wally_free(seckey_ptrs);
    wally_free(keypair_ptrs);
    wally_free(keypairs);
    wally_free(output_ptrs);
    wally_free(output_objs);
    wally_free(recipient_ptrs);
    wally_free(recipient_objs);
    wally_free(recipients);
    wally_free(is_taproot);
    return ret;
}

int wally_psbt_sp_resolve(struct wally_psbt *psbt,
                          const unsigned char *priv_keys, size_t priv_keys_len,
                          const unsigned char *entropy, size_t entropy_len,
                          uint32_t flags)
{
    struct wally_psbt *staged = NULL;
    struct wally_psbt old;
    int ret;

    if (!psbt || !psbt->num_inputs || !priv_keys || !priv_keys_len ||
        priv_keys_len % EC_PRIVATE_KEY_LEN || !entropy ||
        entropy_len != SHA256_LEN || flags)
        return WALLY_EINVAL;

    ret = wally_psbt_clone_alloc(psbt, 0, &staged);
    if (ret != WALLY_OK)
        return ret;
    ret = sp_resolve(staged, priv_keys, priv_keys_len, entropy);
    if (ret == WALLY_OK) {
        old = *psbt;
        *psbt = *staged;
        *staged = old;
    }
    wally_psbt_free(staged);
    return ret;
}

/* Walk a PSBT's recipients, verifying every share and proof present against
 * the input public key(s) it covers, and checking each resolved output against
 * the script BIP-352 derives from those shares.
 *
 * With 'resolve' set, also stores the derived script on any output that has
 * none, which needs no private key - see wally_psbt_sp_resolve_shares(). In
 * that mode anything short of full coverage is an error rather than a verdict,
 * and the caller is responsible for the PSBT being a throwaway clone, since a
 * failure part way through leaves some scripts stored.
 *
 * NOTE: the arguments are validated by the callers.
 */
static int sp_status(struct wally_psbt *psbt,
                     const struct wally_sp_musig_input *musig_inputs,
                     size_t num_musig_inputs,
                     bool resolve, size_t *written)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    struct sp_recipient *recipients = NULL;
    secp256k1_pubkey *input_pubkeys = NULL, *share_pubkeys = NULL;
    size_t *eligible = NULL;
    bool *is_taproot = NULL, *loaded = NULL;
    secp256k1_pubkey sum_pubkey;
    unsigned char input_hash[SHA256_LEN];
    size_t num_recipients = 0, num_keys = 0;
    size_t i, j, group_end, is_elements = 0;
    bool all_resolved = true, all_covered = true, sum_loaded = false;
    int ret;

    *written = WALLY_SP_INVALID;

    if (psbt->version != WALLY_PSBT_VERSION_2 ||
        wally_psbt_is_elements(psbt, &is_elements) != WALLY_OK || is_elements)
        return WALLY_EINVAL; /* BIP-375 is PSBTv2 and bitcoin only */

    recipients = sp_collect_recipients(psbt, &num_recipients, &ret);
    if (!recipients)
        return ret == WALLY_OK ? WALLY_EINVAL : ret; /* Nothing to verify */

    ret = WALLY_ENOMEM;
    input_pubkeys = wally_calloc(psbt->num_inputs * sizeof(*input_pubkeys));
    share_pubkeys = wally_calloc(psbt->num_inputs * sizeof(*share_pubkeys));
    eligible = wally_calloc(psbt->num_inputs * sizeof(*eligible));
    is_taproot = wally_calloc(psbt->num_inputs * sizeof(*is_taproot));
    loaded = wally_calloc(psbt->num_inputs * sizeof(*loaded));
    if (!input_pubkeys || !share_pubkeys || !eligible || !is_taproot || !loaded)
        goto cleanup;

    /* Collect the eligible inputs. Their public keys are read only when a
     * share turns up that needs one, since a PSBT carrying no shares at all
     * is simply unresolved, not unverifiable.
     */
    for (i = 0; i < psbt->num_inputs; ++i) {
        bool is_eligible = false;
        ret = sp_classify_input(psbt, i, &is_eligible, &is_taproot[i]);
        if (ret != WALLY_OK)
            goto cleanup; /* Unclassifiable: WALLY_ERROR, as sp_resolve gives */
        if (is_eligible)
            eligible[num_keys++] = i;
    }

    /* BIP-352 cannot derive an output without an eligible input */
    if (!num_keys)
        goto invalid;

    /* Duplicate scan keys are adjacent after the BIP-375 sort, and one share
     * covers them all, so recipients are checked one scan key group at a time.
     */
    for (i = 0; i < num_recipients; i = group_end) {
        const struct wally_map_item *share_item, *proof_item;
        secp256k1_pubkey scan_pubkey, group_share;
        bool found_global, group_covered = true, group_resolved = true;
        size_t num_group_shares = 0;

        for (group_end = i + 1; group_end < num_recipients; ++group_end)
            if (memcmp(recipients[group_end].scan_pubkey, recipients[i].scan_pubkey,
                       EC_PUBLIC_KEY_LEN))
                break;

        for (j = i; j < group_end; ++j) {
            size_t script_len = 0;
            if (wally_psbt_get_output_script_len(psbt, recipients[j].output_index,
                                                 &script_len) != WALLY_OK)
                goto invalid;
            if (script_len != WALLY_SCRIPTPUBKEY_P2TR_LEN)
                group_resolved = false;
        }

        if (!secp256k1_ec_pubkey_parse(ctx, &scan_pubkey, recipients[i].scan_pubkey,
                                       EC_PUBLIC_KEY_LEN))
            goto invalid;

        /* A global share covers the sum of every eligible input */
        if (!sp_find_share(&psbt->global_sp_ecdh_shares, &psbt->global_sp_dleq_proofs,
                           recipients[i].scan_pubkey, &share_item, &proof_item))
            goto invalid;
        found_global = share_item != NULL;
        if (found_global) {
            if (!sp_load_sum_pub_key(ctx, psbt, eligible, is_taproot, num_keys,
                                     input_pubkeys, loaded, &sum_pubkey, &sum_loaded) ||
                !sp_verify_share(ctx, share_item, proof_item, &scan_pubkey, &sum_pubkey) ||
                !secp256k1_ec_pubkey_parse(ctx, &group_share, share_item->value,
                                           share_item->value_len))
                goto invalid;
        }

        /* Otherwise every eligible input must carry its own share and proof */
        for (j = 0; j < num_keys; ++j) {
            const struct wally_psbt_input *input = &psbt->inputs[eligible[j]];
            const struct wally_sp_musig_input *musig;

            /* An aggregate input's share is assembled from its participants'
             * partial shares rather than carried whole
             */
            musig = sp_musig_find(musig_inputs, num_musig_inputs, eligible[j]);
            if (musig) {
                secp256k1_pubkey musig_share;
                bool musig_covered = false;
                if (!sp_musig_input_share(ctx, psbt, musig, &scan_pubkey,
                                          recipients[i].scan_pubkey,
                                          &musig_share, &musig_covered))
                    goto invalid;
                if (!musig_covered) {
                    if (!found_global)
                        group_covered = false; /* Waiting on its participants */
                    continue;
                }
                if (!found_global)
                    share_pubkeys[num_group_shares++] = musig_share;
                continue;
            }

            if (!sp_find_share(&input->sp_ecdh_shares, &input->sp_dleq_proofs,
                               recipients[i].scan_pubkey, &share_item, &proof_item))
                goto invalid;
            if (!share_item) {
                if (!found_global)
                    group_covered = false; /* This input contributes nothing here */
                continue;
            }
            if (!sp_load_pub_key(ctx, psbt, eligible[j], is_taproot[eligible[j]],
                                 &input_pubkeys[j], &loaded[j]) ||
                !sp_verify_share(ctx, share_item, proof_item, &scan_pubkey,
                                 &input_pubkeys[j]))
                goto invalid;
            /* The per-input shares sum to what a global share would hold */
            if (!found_global &&
                !secp256k1_ec_pubkey_parse(ctx, &share_pubkeys[num_group_shares++],
                                           share_item->value, share_item->value_len))
                goto invalid;
        }
        if (!group_covered) {
            all_covered = false;
            /* Resolved outputs contradict shares that do not cover the inputs;
             * unresolved ones are simply waiting on the remaining signers,
             * which is not something we can resolve past.
             */
            if (group_resolved)
                goto invalid;
            all_resolved = false;
            if (resolve)
                goto invalid;
            continue;
        }
        if (!group_resolved && !resolve) {
            all_resolved = false;
            continue; /* Nothing to compare against yet */
        }

        /* Derive what BIP-352 gives for these outputs, to check the scripts
         * already stored - which is what makes them trustworthy to a signer
         * that did not resolve them itself - and, when resolving, to store the
         * scripts of the outputs that have none.
         */
        if (!found_global) {
            const secp256k1_pubkey **ptrs = wally_calloc(num_group_shares * sizeof(*ptrs));
            bool ok;
            if (!ptrs) {
                ret = WALLY_ENOMEM;
                goto cleanup;
            }
            for (j = 0; j < num_group_shares; ++j)
                ptrs[j] = &share_pubkeys[j];
            ok = !!secp256k1_ec_pubkey_combine(ctx, &group_share, ptrs, num_group_shares);
            wally_free(ptrs);
            if (!ok)
                goto invalid;
        }
        if (!sp_load_sum_pub_key(ctx, psbt, eligible, is_taproot, num_keys,
                                 input_pubkeys, loaded, &sum_pubkey, &sum_loaded) ||
            !sp_input_hash(ctx, psbt, &sum_pubkey, input_hash) ||
            !secp256k1_ec_pubkey_tweak_mul(ctx, &group_share, input_hash))
            goto invalid;
        for (j = i; j < group_end; ++j)
            if (!sp_apply_script(ctx, psbt, &group_share, &recipients[j],
                                 (uint32_t)(j - i), resolve))
                goto invalid;
    }

    /* Incomplete coverage contradicts a resolved output, but is simply work
     * still to do while the outputs are unresolved.
     */
    if (all_covered)
        *written = all_resolved ? WALLY_SP_COMPLETE : WALLY_SP_INCOMPLETE;
    else if (!all_resolved)
        *written = WALLY_SP_INCOMPLETE;
    ret = WALLY_OK;
    goto cleanup;

invalid:
    /* Resolving cannot proceed on what merely checking reports a verdict for */
    ret = resolve ? WALLY_EINVAL : WALLY_OK;

cleanup:
    wally_free(loaded);
    wally_free(is_taproot);
    wally_free(eligible);
    wally_free(share_pubkeys);
    wally_free(input_pubkeys);
    wally_free(recipients);
    return ret;
}

int wally_psbt_get_sp_status(const struct wally_psbt *psbt, uint32_t flags,
                             size_t *written)
{
    if (written)
        *written = WALLY_SP_INVALID;
    if (!psbt || !psbt->num_inputs || !written || flags)
        return WALLY_EINVAL;
    /* Checking stores nothing, so the cast away from const is not observable */
    return sp_status((struct wally_psbt *)psbt, NULL, 0, false, written);
}

/* Resolve into a clone, and adopt it only if that succeeds, so that a failed
 * resolve - which is how a signer rejects what it is asked to sign - cannot
 * leave the caller's psbt half-derived.
 */
static int sp_resolve_shares(struct wally_psbt *psbt,
                             const struct wally_sp_musig_input *musig_inputs,
                             size_t num_musig_inputs)
{
    struct wally_psbt *staged = NULL;
    struct wally_psbt old;
    size_t status = WALLY_SP_INVALID;
    int ret;

    ret = wally_psbt_clone_alloc(psbt, 0, &staged);
    if (ret != WALLY_OK)
        return ret;
    ret = sp_status(staged, musig_inputs, num_musig_inputs, true, &status);
    if (ret == WALLY_OK) {
        old = *psbt;
        *psbt = *staged;
        *staged = old;
    }
    wally_psbt_free(staged);
    return ret;
}

int wally_psbt_sp_resolve_shares(struct wally_psbt *psbt, uint32_t flags)
{
    if (!psbt || !psbt->num_inputs || flags)
        return WALLY_EINVAL;
    return sp_resolve_shares(psbt, NULL, 0);
}

int wally_psbt_get_sp_musig_status(const struct wally_psbt *psbt,
                                   const struct wally_sp_musig_input *musig_inputs,
                                   size_t num_musig_inputs, uint32_t flags,
                                   size_t *written)
{
    int ret;

    if (written)
        *written = WALLY_SP_INVALID;
    if (!psbt || !psbt->num_inputs || !written || flags)
        return WALLY_EINVAL;
    ret = sp_musig_inputs_verify(psbt, musig_inputs, num_musig_inputs);
    if (ret != WALLY_OK)
        return ret;
    /* Checking stores nothing, so the cast away from const is not observable */
    return sp_status((struct wally_psbt *)psbt, musig_inputs, num_musig_inputs,
                     false, written);
}

int wally_psbt_sp_musig_resolve_shares(struct wally_psbt *psbt,
                                       const struct wally_sp_musig_input *musig_inputs,
                                       size_t num_musig_inputs, uint32_t flags)
{
    int ret;

    if (!psbt || !psbt->num_inputs || flags)
        return WALLY_EINVAL;
    ret = sp_musig_inputs_verify(psbt, musig_inputs, num_musig_inputs);
    if (ret != WALLY_OK)
        return ret;
    return sp_resolve_shares(psbt, musig_inputs, num_musig_inputs);
}

int wally_psbt_sp_musig_round1(
    struct wally_psbt *psbt,
    const struct wally_sp_musig_input *musig_inputs, size_t num_musig_inputs,
    const unsigned char *priv_keys, size_t priv_keys_len,
    const unsigned char *entropy, size_t entropy_len, uint32_t flags,
    struct wally_musig_secnonce **secnonces_out,
    unsigned char *session_digest_out, size_t digest_len,
    size_t *status_out)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    struct wally_musig_secnonce **secnonces = NULL;
    struct wally_psbt *staged = NULL;
    struct wally_psbt old;
    unsigned char participant[EC_PUBLIC_KEY_LEN], aggregate[EC_PUBLIC_KEY_LEN];
    unsigned char digest[SHA256_LEN];
    size_t i, status = WALLY_SP_INVALID;
    int ret;

    if (status_out)
        *status_out = WALLY_SP_INVALID;
    if (!psbt || !psbt->num_inputs || !musig_inputs || !num_musig_inputs ||
        num_musig_inputs > (SIZE_MAX - SHA256_LEN) / SHA256_LEN ||
        !priv_keys || priv_keys_len != num_musig_inputs * EC_PRIVATE_KEY_LEN ||
        !entropy ||
        entropy_len != SHA256_LEN + num_musig_inputs * SHA256_LEN ||
        !secnonces_out || !session_digest_out || digest_len != SHA256_LEN ||
        !status_out || flags)
        return WALLY_EINVAL;
    ret = sp_musig_inputs_verify(psbt, musig_inputs, num_musig_inputs);
    if (ret != WALLY_OK || (ret = sp_sighash_policy(psbt)) != WALLY_OK)
        return ret;
    if (psbt->tx_modifiable_flags & ~(WALLY_PSBT_TXMOD_INPUTS |
                                      WALLY_PSBT_TXMOD_OUTPUTS))
        return WALLY_EINVAL;

    /* Front-load every validation that can fail before producing any nonce. */
    for (i = 0; i < num_musig_inputs; ++i) {
        const unsigned char *secrand = entropy + SHA256_LEN * (i + 1);
        if (mem_is_zero(secrand, SHA256_LEN) ||
            !sp_musig_input_matches(ctx, psbt, &musig_inputs[i], NULL) ||
            sp_musig_signer_keys(psbt, &musig_inputs[i],
                                 priv_keys + i * EC_PRIVATE_KEY_LEN,
                                 participant, aggregate) != WALLY_OK)
            return WALLY_EINVAL;
    }
    if ((ret = wally_psbt_get_sp_musig_session_digest(psbt, digest,
                                                       sizeof(digest))) != WALLY_OK)
        return ret;
    secnonces = wally_calloc(num_musig_inputs * sizeof(*secnonces));
    if (!secnonces)
        return WALLY_ENOMEM;
    ret = wally_psbt_clone_alloc(psbt, 0, &staged);
    if (ret != WALLY_OK)
        goto cleanup;

    ret = sp_musig_contribute(staged, musig_inputs, num_musig_inputs,
                              priv_keys, entropy);
    for (i = 0; ret == WALLY_OK && i < num_musig_inputs; ++i) {
        const struct wally_sp_musig_input *musig = &musig_inputs[i];
        ret = sp_musig_signer_keys(staged, musig,
                                   priv_keys + i * EC_PRIVATE_KEY_LEN,
                                   participant, aggregate);
        if (ret == WALLY_OK)
            ret = wally_psbt_musig2_agg_then_derive_add_nonce(
                staged, musig->index, entropy + SHA256_LEN * (i + 1), SHA256_LEN,
                priv_keys + i * EC_PRIVATE_KEY_LEN, EC_PRIVATE_KEY_LEN,
                participant, sizeof(participant), aggregate, sizeof(aggregate),
                musig->path, musig->path_len, digest, sizeof(digest), 0,
                &secnonces[i]);
    }
    if (ret == WALLY_OK)
        ret = sp_status(staged, musig_inputs, num_musig_inputs, false, &status);
    if (ret == WALLY_OK && status == WALLY_SP_INVALID)
        ret = WALLY_EINVAL;
    if (ret == WALLY_OK && status == WALLY_SP_COMPLETE) {
        /* Do not bless scripts that arrived resolved while the transaction
         * was still mutable. The valid last-contributor path resolves below
         * on this clone and clears the flags itself. */
        if (staged->tx_modifiable_flags)
            ret = WALLY_EINVAL;
    }
    else if (ret == WALLY_OK && status == WALLY_SP_INCOMPLETE) {
        size_t resolved = WALLY_SP_INVALID;
        int resolve_ret = sp_status(staged, musig_inputs, num_musig_inputs,
                                    true, &resolved);
        if (resolve_ret == WALLY_OK) {
            status = WALLY_SP_COMPLETE;
            staged->tx_modifiable_flags &= ~(WALLY_PSBT_TXMOD_INPUTS |
                                              WALLY_PSBT_TXMOD_OUTPUTS);
        } else if (resolve_ret != WALLY_EINVAL)
            ret = resolve_ret;
    }
    if (ret == WALLY_OK) {
        old = *psbt;
        *psbt = *staged;
        *staged = old;
        for (i = 0; i < num_musig_inputs; ++i) {
            secnonces_out[i] = secnonces[i];
            secnonces[i] = NULL;
        }
        memcpy(session_digest_out, digest, sizeof(digest));
        *status_out = status;
    }

cleanup:
    for (i = 0; secnonces && i < num_musig_inputs; ++i)
        wally_musig_secnonce_free(secnonces[i]);
    wally_free(secnonces);
    wally_psbt_free(staged);
    wally_clear_3(participant, sizeof(participant), aggregate, sizeof(aggregate),
                  digest, sizeof(digest));
    return ret;
}

int wally_psbt_sp_musig_round2(
    struct wally_psbt *psbt,
    const struct wally_sp_musig_input *musig_inputs, size_t num_musig_inputs,
    const unsigned char *priv_keys, size_t priv_keys_len,
    struct wally_musig_secnonce **secnonces,
    const unsigned char *session_digest, size_t digest_len, uint32_t flags)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    struct wally_psbt *staged = NULL;
    struct wally_psbt old;
    unsigned char participant[EC_PUBLIC_KEY_LEN], aggregate[EC_PUBLIC_KEY_LEN];
    unsigned char digest[SHA256_LEN];
    size_t i, status = WALLY_SP_INVALID;
    int ret;

    if (!psbt || !psbt->num_inputs || !musig_inputs || !num_musig_inputs ||
        num_musig_inputs > SIZE_MAX / EC_PRIVATE_KEY_LEN ||
        !priv_keys || priv_keys_len != num_musig_inputs * EC_PRIVATE_KEY_LEN ||
        !secnonces || !session_digest || digest_len != SHA256_LEN || flags)
        return WALLY_EINVAL;
    ret = sp_musig_inputs_verify(psbt, musig_inputs, num_musig_inputs);
    if (ret != WALLY_OK || (ret = sp_sighash_policy(psbt)) != WALLY_OK ||
        psbt->tx_modifiable_flags)
        return ret == WALLY_OK ? WALLY_EINVAL : ret;
    ret = wally_psbt_get_sp_musig_session_digest(psbt, digest, sizeof(digest));
    if (ret != WALLY_OK || memcmp(digest, session_digest, sizeof(digest)))
        return WALLY_EINVAL;
    ret = sp_status(psbt, musig_inputs, num_musig_inputs, false, &status);
    if (ret != WALLY_OK || status != WALLY_SP_COMPLETE)
        return WALLY_EINVAL;

    /* Validate the full signing set before consuming the first secret nonce. */
    for (i = 0; i < num_musig_inputs; ++i) {
        if (!secnonces[i] ||
            !sp_musig_input_matches(ctx, psbt, &musig_inputs[i], NULL) ||
            sp_musig_signer_keys(psbt, &musig_inputs[i],
                                 priv_keys + i * EC_PRIVATE_KEY_LEN,
                                 participant, aggregate) != WALLY_OK)
            return WALLY_EINVAL;
    }
    ret = wally_psbt_clone_alloc(psbt, 0, &staged);
    if (ret != WALLY_OK)
        return ret;
    for (i = 0; ret == WALLY_OK && i < num_musig_inputs; ++i) {
        const struct wally_sp_musig_input *musig = &musig_inputs[i];
        ret = sp_musig_signer_keys(staged, musig,
                                   priv_keys + i * EC_PRIVATE_KEY_LEN,
                                   participant, aggregate);
        if (ret == WALLY_OK)
            ret = wally_psbt_musig2_agg_then_derive_sign(
                staged, musig->index, secnonces[i],
                priv_keys + i * EC_PRIVATE_KEY_LEN, EC_PRIVATE_KEY_LEN,
                participant, sizeof(participant), aggregate, sizeof(aggregate),
                musig->path, musig->path_len, 0, NULL);
    }
    if (ret == WALLY_OK) {
        old = *psbt;
        *psbt = *staged;
        *staged = old;
    }
    wally_psbt_free(staged);
    wally_clear_3(participant, sizeof(participant), aggregate, sizeof(aggregate),
                  digest, sizeof(digest));
    return ret;
}

#endif /* ndef BUILD_STANDARD_SECP */
