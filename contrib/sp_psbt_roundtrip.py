#!/usr/bin/env python3
"""
BIP-352 silent payment PSBT round trip (BIP-352/BIP-375/BIP-392)

Demonstrates a complete silent payment, sender and recipient:
  1. The recipient publishes a silent payment address (scan || spend pubkeys)
  2. The sender builds a PSBT with a PSBT_OUT_SP_V0_INFO output and no script
  3. The sender resolves the output, which writes the scriptPubKey and the
     BIP-375 global ECDH share and DLEQ proof
  4. The PSBT is signed, finalized and extracted
  5. The recipient scans the extracted transaction and finds the payment
  6. The recipient verifies the DLEQ proof against the share
  7. The recipient spends the payment, using the BIP-376 tweak it scanned

Run from the repo root with:
  PYTHONPATH=src/test python3 contrib/sp_psbt_roundtrip.py

The sender side is wally_psbt_sp_resolve(). Scanning is the secp256k1
silentpayments module, which wally does not wrap, so the few calls it needs
are declared here.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'test'))

from ctypes import *
from util import *

# -- Constants ----------------------------------------------------------------

EC_PRIVATE_KEY_LEN = 32
EC_PUBLIC_KEY_LEN = 33
WALLY_SP_SCAN_KEY_LEN = 65      # BIP-392 spscan: scan privkey || spend pubkey
WALLY_SP_OUTPOINT_LEN = 36

WALLY_SIGHASH_ALL = 0x01
BIP32_VER_MAIN_PRIVATE = 0x0488ADE4
BIP32_KEY_FINGERPRINT_LEN = 4
EC_SIGNATURE_LEN = 64
WALLY_PSBT_VERSION_2 = 0x2
WALLY_PSBT_EXTRACT_OPT_FINAL = 0x2
WALLY_TX_FLAG_USE_WITNESS = 0x1
EC_FLAG_GRIND_R = 0x4

# Opaque secp256k1 objects, only ever handed back to secp
SECP256K1_PUBKEY_LEN = 64
SECP256K1_XONLY_PUBKEY_LEN = 64
SECP256K1_SP_PREVOUTS_SUMMARY_LEN = 101
# xonly pubkey || 32 byte tweak || int found_with_label || 68 byte label
SECP256K1_SP_FOUND_OUTPUT_LEN = 64 + 32 + 4 + 68
SECP256K1_EC_COMPRESSED = (1 << 1) | (1 << 8)

# -- The secp256k1 silent payment scanner, which wally does not wrap -----------


def _fn(name, argtypes, restype=c_int):
    fn = getattr(libwally, name)
    fn.restype, fn.argtypes = restype, argtypes
    return fn


_secp_context = _fn('wally_get_secp_context', [], c_void_p)
_pubkey_parse = _fn('secp256k1_ec_pubkey_parse', [c_void_p, c_void_p, c_void_p, c_size_t])
_xonly_pubkey_parse = _fn('secp256k1_xonly_pubkey_parse', [c_void_p, c_void_p, c_void_p])
_prevouts_summary_create = _fn('secp256k1_silentpayments_recipient_prevouts_summary_create',
                               [c_void_p, c_void_p, c_void_p, POINTER(c_void_p), c_size_t,
                                POINTER(c_void_p), c_size_t])
_scan_outputs = _fn('secp256k1_silentpayments_recipient_scan_outputs',
                    [c_void_p, POINTER(c_void_p), POINTER(c_uint32), POINTER(c_void_p),
                     c_size_t, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p])
_pubkey_combine = _fn('secp256k1_ec_pubkey_combine',
                      [c_void_p, c_void_p, POINTER(c_void_p), c_size_t])
_pubkey_serialize = _fn('secp256k1_ec_pubkey_serialize',
                        [c_void_p, c_void_p, POINTER(c_size_t), c_void_p, c_uint])
_dleq_verify = _fn('secp256k1_dleq_verify',
                   [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p])


def _parse_pubkey(pubkey):
    obj = create_string_buffer(SECP256K1_PUBKEY_LEN)
    assert _pubkey_parse(_secp_context(), obj, pubkey, len(pubkey)) == 1, 'bad pubkey'
    return obj


def _parse_xonly(xonly):
    obj = create_string_buffer(SECP256K1_XONLY_PUBKEY_LEN)
    assert _xonly_pubkey_parse(_secp_context(), obj, xonly) == 1, 'bad x-only pubkey'
    return obj


def scan_outputs(scripts, scan_privkey, spend_pubkey, input_pubkeys, outpoint):
    """Scan transaction outputs for silent payments to (scan, spend).

    Takes the P2TR scriptPubKeys of a transaction, the public keys of its
    eligible inputs and its smallest outpoint, and returns {output index: tweak}
    for each output belonging to this wallet.
    """
    candidates = {index: script[2:34] for index, script in enumerate(scripts)
                  if len(script) == 34 and script[:2] == b'\x51\x20'}
    if not candidates:
        return {}

    pubkey_objs = [_parse_pubkey(pubkey) for pubkey in input_pubkeys]
    pubkey_ptrs = (c_void_p * len(pubkey_objs))(*[cast(o, c_void_p) for o in pubkey_objs])
    summary = create_string_buffer(SECP256K1_SP_PREVOUTS_SUMMARY_LEN)
    assert _prevouts_summary_create(_secp_context(), summary, outpoint, None, 0,
                                    pubkey_ptrs, len(pubkey_objs)) == 1, 'summary failed'

    output_objs = [_parse_xonly(xonly) for xonly in candidates.values()]
    output_ptrs = (c_void_p * len(output_objs))(*[cast(o, c_void_p) for o in output_objs])
    found_objs = [create_string_buffer(SECP256K1_SP_FOUND_OUTPUT_LEN) for _ in output_objs]
    found_ptrs = (c_void_p * len(found_objs))(*[cast(o, c_void_p) for o in found_objs])
    num_found = c_uint32(0)

    assert _scan_outputs(_secp_context(), found_ptrs, byref(num_found), output_ptrs,
                         len(output_ptrs), scan_privkey, summary,
                         _parse_pubkey(spend_pubkey), None, None) == 1, 'scan failed'

    # Each found output holds the x-only key it matched, then its spending tweak
    indexes = list(candidates)
    found = {}
    for i in range(num_found.value):
        matched = found_objs[i].raw[:SECP256K1_XONLY_PUBKEY_LEN]
        tweak = found_objs[i].raw[64:96]
        for index in indexes:
            if output_objs[indexes.index(index)].raw == matched:
                found[index] = tweak
                break
    return found


def pubkey_sum(pubkeys):
    """Sum compressed public keys, as BIP-352 does over a transaction's inputs."""
    objs = [_parse_pubkey(pubkey) for pubkey in pubkeys]
    ptrs = (c_void_p * len(objs))(*[cast(obj, c_void_p) for obj in objs])
    summed = create_string_buffer(SECP256K1_PUBKEY_LEN)
    assert _pubkey_combine(_secp_context(), summed, ptrs, len(objs)) == 1, 'combine failed'

    out, out_len = create_string_buffer(EC_PUBLIC_KEY_LEN), c_size_t(EC_PUBLIC_KEY_LEN)
    assert _pubkey_serialize(_secp_context(), out, byref(out_len), summed,
                             SECP256K1_EC_COMPRESSED) == 1
    return out.raw[:out_len.value]


def dleq_verify(proof, summed_pubkey, scan_pubkey, share):
    """Verify a BIP-375 proof that the share was made with the summed inputs.

    Returns False rather than raising for malformed keys: a verifier is given
    whatever the sender wrote, which may not be a point on the curve at all.
    """
    try:
        points = [_parse_pubkey(pubkey) for pubkey in (summed_pubkey, scan_pubkey, share)]
    except AssertionError:
        return False
    return _dleq_verify(_secp_context(), proof, *points, None) == 1


# -- Silent payment helpers over the wally API --------------------------------


def sp_address(sp_v0_info, addr_family='sp'):
    """The BIP-352 address for a recipient's scan and spend public keys."""
    ret, addr = wally_sp_address_from_bytes(sp_v0_info, len(sp_v0_info),
                                            utf8(addr_family), 0)
    assert ret == WALLY_OK
    return addr


def sp_scan_key(scan_privkey, spend_pubkey, hrp='spscan'):
    """A BIP-392 key expression, as an sp() descriptor carries."""
    payload = scan_privkey + spend_pubkey
    ret, key = wally_descriptor_sp_key_from_bytes(payload, len(payload), utf8(hrp))
    assert ret == WALLY_OK
    return key


def decode_sp_scan_key(key_expression):
    """Unpack a BIP-392 spscan1... key to (scan privkey, spend pubkey)."""
    out, out_len = make_cbuffer('00' * WALLY_SP_SCAN_KEY_LEN)
    ret, written = wally_descriptor_sp_key_to_bytes(utf8(key_expression), out, out_len)
    assert ret == WALLY_OK and written == WALLY_SP_SCAN_KEY_LEN, 'not a scan key'
    return bytes(out[:EC_PRIVATE_KEY_LEN]), bytes(out[EC_PRIVATE_KEY_LEN:])


def pubkey_from_privkey(privkey):
    """Derive the 33 byte compressed pubkey for a 32 byte private key."""
    out, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
    assert wally_ec_public_key_from_private_key(privkey, len(privkey), out,
                                                EC_PUBLIC_KEY_LEN) == WALLY_OK
    return bytes(out)


def p2wpkh_script(pubkey):
    """The P2WPKH scriptPubKey paying a compressed pubkey."""
    hash160, _ = make_cbuffer('00' * 20)
    assert wally_hash160(pubkey, len(pubkey), hash160, 20) == WALLY_OK
    return b'\x00\x14' + bytes(hash160)


def read_global(psbt, field_name, find_fn, scan_pubkey):
    """Read a BIP-375 global keyed by the recipient's scan public key."""
    ret, found = find_fn(psbt, scan_pubkey, len(scan_pubkey))
    assert ret == WALLY_OK and found, f'no {field_name} for this scan key'
    item = getattr(psbt.contents, field_name).items[found - 1]  # 1 based
    return string_at(item.value, item.value_len)


# -- Demonstration ------------------------------------------------------------

# Example keys only - never hardcode keys in production
SENDER_PRIVKEYS = [bytes([0x11] * 32), bytes([0x22] * 32)]
RECIPIENT_SCAN_PRIVKEY = bytes([0x33] * 32)
# The spend key is a BIP32 key, since BIP-376 identifies it by its derivation
RECIPIENT_SEED = bytes([0x44] * 32)
FUNDING_TXID = bytes([0xaa] * 32)
FINGERPRINT = bytes([0x00] * 4)
INPUT_AMOUNT, OUTPUT_AMOUNT, SPEND_AMOUNT = 100000, 90000, 80000


def main():
    if not wally_psbt_sp_resolve:
        print('Silent payments module not enabled in this build')
        return

    # -- Step 1: the recipient publishes a silent payment address -------------
    scan_pubkey = pubkey_from_privkey(RECIPIENT_SCAN_PRIVKEY)
    spend_key = ext_key()
    assert bip32_key_from_seed(RECIPIENT_SEED, len(RECIPIENT_SEED),
                               BIP32_VER_MAIN_PRIVATE, 0, byref(spend_key)) == WALLY_OK
    spend_pubkey = bytes(bytearray(spend_key.pub_key))
    recipient_info = scan_pubkey + spend_pubkey
    print(f'Recipient address: {sp_address(recipient_info)}')

    # The same keys as a BIP-392 key expression, which is what a watch only
    # wallet is given: the scan private key and the spend public key.
    key_expression = sp_scan_key(RECIPIENT_SCAN_PRIVKEY, spend_pubkey)
    assert decode_sp_scan_key(key_expression) == (RECIPIENT_SCAN_PRIVKEY, spend_pubkey)

    # -- Step 2: the sender builds a PSBT with an unresolved SP output --------
    sender_pubkeys = [pubkey_from_privkey(privkey) for privkey in SENDER_PRIVKEYS]

    psbt = pointer(wally_psbt())
    assert wally_psbt_init_alloc(WALLY_PSBT_VERSION_2, len(SENDER_PRIVKEYS), 1, 0, 0,
                                 psbt) == WALLY_OK
    for index, pubkey in enumerate(sender_pubkeys):
        tx_input = pointer(wally_tx_input())
        assert wally_tx_input_init_alloc(FUNDING_TXID, len(FUNDING_TXID), index, 0xffffffff,
                                         None, 0, None, tx_input) == WALLY_OK
        assert wally_psbt_add_tx_input_at(psbt, index, 0, tx_input) == WALLY_OK

        utxo = pointer(wally_tx_output())
        script = p2wpkh_script(pubkey)
        assert wally_tx_output_init_alloc(INPUT_AMOUNT, script, len(script), utxo) == WALLY_OK
        assert wally_psbt_set_input_witness_utxo(psbt, index, utxo) == WALLY_OK
        assert wally_psbt_set_input_amount(psbt, index, INPUT_AMOUNT) == WALLY_OK
        assert wally_psbt_set_input_sighash(psbt, index, WALLY_SIGHASH_ALL) == WALLY_OK
        # The signer finds its inputs by looking itself up in the keypaths
        path = (c_uint32 * 1)(index)
        assert wally_psbt_add_input_keypath(psbt, index, pubkey, len(pubkey), FINGERPRINT,
                                            len(FINGERPRINT), path, 1) == WALLY_OK

    # The output carries the recipient, but no script: only the sender, who
    # knows the input keys, can work out where the payment actually goes.
    tx_output = pointer(wally_tx_output())
    assert wally_tx_output_init_alloc(OUTPUT_AMOUNT, None, 0, tx_output) == WALLY_OK
    assert wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output) == WALLY_OK
    assert wally_psbt_set_output_amount(psbt, 0, OUTPUT_AMOUNT) == WALLY_OK
    assert wally_psbt_set_output_sp_v0_info(psbt, 0, recipient_info,
                                            len(recipient_info)) == WALLY_OK
    print(f'PSBT built with {len(SENDER_PRIVKEYS)} inputs and 1 silent payment output')

    # -- Step 3: the sender resolves the output -------------------------------
    # One private key per eligible input, in input order.
    for index in range(len(SENDER_PRIVKEYS)):
        ret, eligible = wally_psbt_get_input_sp_eligible(psbt, index)
        assert (ret, eligible) == (WALLY_OK, 1), f'input {index} is not eligible'

    priv_keys = b''.join(SENDER_PRIVKEYS)
    entropy = os.urandom(32)
    assert wally_psbt_sp_resolve(psbt, priv_keys, len(priv_keys),
                                 entropy, len(entropy), 0) == WALLY_OK

    script, _ = make_cbuffer('00' * 34)
    ret, written = wally_psbt_get_output_script(psbt, 0, script, 34)
    assert ret == WALLY_OK and written == 34
    share = read_global(psbt, 'global_sp_ecdh_shares',
                        wally_psbt_find_global_sp_ecdh_share, scan_pubkey)
    proof = read_global(psbt, 'global_sp_dleq_proofs',
                        wally_psbt_find_global_sp_dleq_proof, scan_pubkey)
    print(f'Output resolved to {bytes(script).hex()}')

    # -- Step 4: sign, finalize, extract --------------------------------------
    for privkey in SENDER_PRIVKEYS:
        assert wally_psbt_sign(psbt, privkey, len(privkey), EC_FLAG_GRIND_R) == WALLY_OK
    assert wally_psbt_finalize(psbt, 0) == WALLY_OK

    outpoint, outpoint_len = make_cbuffer('00' * WALLY_SP_OUTPOINT_LEN)
    assert wally_psbt_get_sp_smallest_outpoint(psbt, outpoint, outpoint_len) == WALLY_OK

    tx = POINTER(wally_tx)()
    assert wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_OPT_FINAL, byref(tx)) == WALLY_OK
    buf, buf_len = make_cbuffer('00' * 4096)
    ret, written = wally_tx_to_bytes(tx, WALLY_TX_FLAG_USE_WITNESS, buf, buf_len)
    assert ret == WALLY_OK
    print(f'Transaction extracted ({written} bytes)')

    # -- Step 5: the recipient scans the transaction --------------------------
    # A scanner takes the input pubkeys from the witnesses on chain; the output
    # scripts likewise come from the transaction.
    scanned_pubkeys = []
    for index in range(len(SENDER_PRIVKEYS)):
        pubkey, pubkey_len = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        ret, written = wally_tx_get_input_witness(tx, index, 1, pubkey, pubkey_len)
        assert ret == WALLY_OK and written == EC_PUBLIC_KEY_LEN
        scanned_pubkeys.append(bytes(pubkey))

    scripts = [string_at(tx.contents.outputs[index].script,
                         tx.contents.outputs[index].script_len)
               for index in range(tx.contents.num_outputs)]
    scan_privkey, scanned_spend_pubkey = decode_sp_scan_key(key_expression)
    found = scan_outputs(scripts, scan_privkey, scanned_spend_pubkey, scanned_pubkeys,
                         bytes(outpoint))
    assert list(found) == [0], f'scan found {list(found)}, expected the payment at output 0'
    print(f'Recipient found the payment at output {list(found)[0]}, '
          f'spendable with tweak {found[0].hex()}')

    # -- Step 6: verify the share and its proof -------------------------------
    # The proof says the share was created with the summed input keys, which is
    # what lets a signer trust a share it did not create itself.
    summed = pubkey_sum(scanned_pubkeys)
    assert dleq_verify(proof, summed, scan_pubkey, share), 'DLEQ proof failed'
    print('DLEQ proof verified against the summed input keys')

    # -- Step 7: the recipient spends the payment (BIP-376) -------------------
    # The private key of the payment is the spend key plus the tweak that
    # scanning found, which no BIP32 path can reach. So the PSBT carries the
    # tweak, and the spend key that it applies to.
    txid, txid_len = make_cbuffer('00' * 32)
    assert wally_tx_get_txid(tx, txid, txid_len) == WALLY_OK

    spend = pointer(wally_psbt())
    assert wally_psbt_init_alloc(WALLY_PSBT_VERSION_2, 1, 1, 0, 0, spend) == WALLY_OK
    tx_input = pointer(wally_tx_input())
    assert wally_tx_input_init_alloc(txid, txid_len, 0, 0xffffffff,
                                     None, 0, None, tx_input) == WALLY_OK
    assert wally_psbt_add_tx_input_at(spend, 0, 0, tx_input) == WALLY_OK
    utxo = pointer(wally_tx_output())
    assert wally_tx_output_init_alloc(OUTPUT_AMOUNT, scripts[0], len(scripts[0]),
                                      utxo) == WALLY_OK
    assert wally_psbt_set_input_witness_utxo(spend, 0, utxo) == WALLY_OK
    assert wally_psbt_set_input_sp_tweak(spend, 0, found[0], len(found[0])) == WALLY_OK

    fingerprint, fingerprint_len = make_cbuffer('00' * BIP32_KEY_FINGERPRINT_LEN)
    assert bip32_key_get_fingerprint(byref(spend_key), fingerprint,
                                     fingerprint_len) == WALLY_OK
    assert wally_psbt_add_input_sp_spend_keypath(spend, 0, spend_pubkey, len(spend_pubkey),
                                                 fingerprint, fingerprint_len,
                                                 None, 0) == WALLY_OK

    tx_output = pointer(wally_tx_output())
    change = p2wpkh_script(sender_pubkeys[0])
    assert wally_tx_output_init_alloc(SPEND_AMOUNT, change, len(change),
                                      tx_output) == WALLY_OK
    assert wally_psbt_add_tx_output_at(spend, 0, 0, tx_output) == WALLY_OK

    # A signer must refuse a tweak that does not give the key being spent: it
    # comes from the Updater, and signing with a wrong one produces a valid
    # signature for a key the signer does not control.
    key, key_len = make_cbuffer('00' * EC_PRIVATE_KEY_LEN)
    bad_tweak = bytes([found[0][0] ^ 1]) + found[0][1:]
    assert wally_psbt_set_input_sp_tweak(spend, 0, bad_tweak, len(bad_tweak)) == WALLY_OK
    assert wally_psbt_get_input_sp_spend_key(spend, 0, byref(spend_key),
                                             key, key_len) == WALLY_EINVAL
    assert wally_psbt_set_input_sp_tweak(spend, 0, found[0], len(found[0])) == WALLY_OK
    print('A corrupted tweak is refused')

    assert wally_psbt_sign_bip32(spend, byref(spend_key), 0) == WALLY_OK
    ret, written = wally_psbt_get_input_taproot_signature_len(spend, 0)
    assert (ret, written) == (WALLY_OK, EC_SIGNATURE_LEN), 'input was not signed'
    assert wally_psbt_finalize(spend, 0) == WALLY_OK

    spend_tx = POINTER(wally_tx)()
    assert wally_psbt_extract(spend, WALLY_PSBT_EXTRACT_OPT_FINAL,
                              byref(spend_tx)) == WALLY_OK
    ret, written = wally_tx_to_bytes(spend_tx, WALLY_TX_FLAG_USE_WITNESS, buf, buf_len)
    assert ret == WALLY_OK
    print(f'Payment spent with a BIP-376 tweak ({written} bytes)')

    wally_tx_free(spend_tx)
    wally_psbt_free(spend)
    wally_tx_free(tx)
    wally_psbt_free(psbt)
    print('Silent payment round trip complete')


if __name__ == '__main__':
    main()
