#include "internal.h"
#include "psbt_io.h"

#include <include/wally_address.h>
#include <include/wally_crypto.h>
#include <include/wally_psbt.h>
#include <include/wally_psbt_members.h>
#include <include/wally_script.h>
#include <include/wally_silentpayments.h>
#include <include/wally_transaction.h>

#include <stdlib.h>

#ifndef BUILD_STANDARD_SECP
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
        *is_eligible = redeem_type == WALLY_SCRIPT_TYPE_P2WPKH;
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
        memcpy(normalized, priv_keys + i * EC_PRIVATE_KEY_LEN, sizeof(normalized));
        if (!secp256k1_ec_seckey_verify(ctx, normalized))
            goto cleanup;
        if (is_taproot[i]) {
            secp256k1_pubkey pubkey;
            secp256k1_xonly_pubkey xonly;
            int parity = 0;
            if (!secp256k1_ec_pubkey_create(ctx, &pubkey, normalized) ||
                !secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, &parity, &pubkey) ||
                (parity && !secp256k1_ec_seckey_negate(ctx, normalized)))
                goto cleanup;
        }
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

/* Read the public key an eligible input is spent with. For taproot that is the
 * internal key, which the PSBT carries x-only; otherwise it is the input's sole
 * BIP32 keypath key. Returns false if the PSBT does not name a usable key,
 * which leaves any share on that input unverifiable.
 */
static bool sp_input_pub_key(const secp256k1_context *ctx,
                             const struct wally_psbt *psbt, size_t index,
                             bool is_taproot, secp256k1_pubkey *pubkey_out)
{
    const struct wally_map *keypaths = &psbt->inputs[index].keypaths;

    if (is_taproot) {
        unsigned char compressed[EC_PUBLIC_KEY_LEN];
        size_t written = 0;
        if (wally_psbt_get_input_taproot_internal_key(psbt, index, compressed + 1,
                                                      EC_XONLY_PUBLIC_KEY_LEN,
                                                      &written) != WALLY_OK ||
            written != EC_XONLY_PUBLIC_KEY_LEN)
            return false;
        /* An x-only key denotes the even-Y point, so it is already the
         * parity-normalized key that sp_sum_priv_keys() sums to.
         */
        compressed[0] = 0x02;
        return !!secp256k1_ec_pubkey_parse(ctx, pubkey_out, compressed,
                                           sizeof(compressed));
    }

    if (keypaths->num_items != 1 ||
        keypaths->items[0].key_len != EC_PUBLIC_KEY_LEN)
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
 * counterpart of sp_sum_priv_keys(). Taproot keys are read x-only and so are
 * already parity-normalized, which is what makes this agree with the sender's
 * aggregate without any private key. Computed once, on the first global share
 * that needs it.
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

int wally_psbt_sp_resolve(struct wally_psbt *psbt,
                          const unsigned char *priv_keys, size_t priv_keys_len,
                          const unsigned char *entropy, size_t entropy_len,
                          uint32_t flags)
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

    if (!psbt || !psbt->num_inputs || !priv_keys || !priv_keys_len ||
        priv_keys_len % EC_PRIVATE_KEY_LEN || !entropy ||
        entropy_len != SHA256_LEN || flags)
        return WALLY_EINVAL;

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
        size_t script_len = 0;

        /* NOTE: the output key is used as-is, ie. not re-tweaked per BIP-341 */
        if (!secp256k1_xonly_pubkey_serialize(ctx, xonly, &output_objs[i]))
            goto cleanup;
        ret = wally_scriptpubkey_p2tr_from_bytes(xonly, sizeof(xonly), 0, script,
                                                 sizeof(script), &script_len);
        if (ret == WALLY_OK)
            ret = wally_psbt_set_output_script(psbt, recipients[i].output_index,
                                               script, script_len);
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

int wally_psbt_get_sp_status(const struct wally_psbt *psbt, uint32_t flags,
                             size_t *written)
{
    const secp256k1_context *ctx = wally_get_secp_context();
    struct sp_recipient *recipients = NULL;
    secp256k1_pubkey *input_pubkeys = NULL;
    size_t *eligible = NULL;
    bool *is_taproot = NULL, *loaded = NULL;
    secp256k1_pubkey sum_pubkey;
    size_t num_recipients = 0, num_keys = 0;
    size_t i, j, is_elements = 0;
    bool all_resolved = true, all_covered = true, sum_loaded = false;
    int ret;

    if (written)
        *written = WALLY_SP_INVALID;
    if (!psbt || !psbt->num_inputs || !written || flags)
        return WALLY_EINVAL;

    if (psbt->version != WALLY_PSBT_VERSION_2 ||
        wally_psbt_is_elements(psbt, &is_elements) != WALLY_OK || is_elements)
        return WALLY_EINVAL; /* BIP-375 is PSBTv2 and bitcoin only */

    recipients = sp_collect_recipients(psbt, &num_recipients, &ret);
    if (!recipients)
        return ret == WALLY_OK ? WALLY_EINVAL : ret; /* Nothing to verify */

    ret = WALLY_ENOMEM;
    input_pubkeys = wally_calloc(psbt->num_inputs * sizeof(*input_pubkeys));
    eligible = wally_calloc(psbt->num_inputs * sizeof(*eligible));
    is_taproot = wally_calloc(psbt->num_inputs * sizeof(*is_taproot));
    loaded = wally_calloc(psbt->num_inputs * sizeof(*loaded));
    if (!input_pubkeys || !eligible || !is_taproot || !loaded)
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

    for (i = 0; i < num_recipients; ++i) {
        const struct wally_map_item *share_item, *proof_item;
        secp256k1_pubkey scan_pubkey;
        bool found_global;
        size_t script_len = 0;

        if (wally_psbt_get_output_script_len(psbt, recipients[i].output_index,
                                             &script_len) != WALLY_OK)
            goto invalid;
        if (script_len != WALLY_SCRIPTPUBKEY_P2TR_LEN)
            all_resolved = false;

        /* Duplicate scan keys are adjacent after the BIP-375 sort, and one
         * share covers them all, so only check each distinct key once.
         */
        if (i && !memcmp(recipients[i].scan_pubkey, recipients[i - 1].scan_pubkey,
                         EC_PUBLIC_KEY_LEN))
            continue;

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
                !sp_verify_share(ctx, share_item, proof_item, &scan_pubkey, &sum_pubkey))
                goto invalid;
        }

        /* Otherwise every eligible input must carry its own share and proof */
        for (j = 0; j < num_keys; ++j) {
            const struct wally_psbt_input *input = &psbt->inputs[eligible[j]];
            if (!sp_find_share(&input->sp_ecdh_shares, &input->sp_dleq_proofs,
                               recipients[i].scan_pubkey, &share_item, &proof_item))
                goto invalid;
            if (!share_item) {
                if (!found_global)
                    all_covered = false; /* This input contributes nothing here */
                continue;
            }
            if (!sp_load_pub_key(ctx, psbt, eligible[j], is_taproot[eligible[j]],
                                 &input_pubkeys[j], &loaded[j]) ||
                !sp_verify_share(ctx, share_item, proof_item, &scan_pubkey,
                                 &input_pubkeys[j]))
                goto invalid;
        }
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
    ret = WALLY_OK; /* A verdict of invalid, not a failure to reach one */

cleanup:
    wally_free(loaded);
    wally_free(is_taproot);
    wally_free(eligible);
    wally_free(input_pubkeys);
    wally_free(recipients);
    return ret;
}

#endif /* ndef BUILD_STANDARD_SECP */
