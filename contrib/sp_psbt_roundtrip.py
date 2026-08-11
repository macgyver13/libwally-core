#!/usr/bin/env python3
"""
BIP-352 silent payment PSBT round trip (BIP-352/BIP-375/BIP-392)

Demonstrates a complete silent payment, sender and recipient:
  1. The recipient publishes a silent payment address (scan || spend pubkeys)
  2. The sender builds a PSBT with a PSBT_OUT_SP_V0_INFO output and no script
  3. The sender derives the BIP-352 output and writes the BIP-375 global
     ECDH share and DLEQ proof
  4. The PSBT is signed, finalized and extracted
  5. The recipient scans the extracted transaction and finds the payment
  6. The recipient verifies the DLEQ proof against the share

Run from the repo root with:
  PYTHONPATH=src/test python3 contrib/sp_psbt_roundtrip.py

The helpers below are the protocol, not the demo: they are written against
flat secp256k1 primitives (parse/serialize/combine/tweak_mul) rather than the
secp256k1_silentpayments module, so they are an independent implementation of
BIP-352 that can be used to check one that is not.

TODO: steps 2-3 are the sender side that libwally does not expose yet. When a
wally_psbt_sp_* sender API lands, sp_derive_output()/sp_ecdh_share() here
become one call and this file documents that API instead.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'test'))

from ctypes import *
from util import *

# -- Constants ----------------------------------------------------------------

EC_PRIVATE_KEY_LEN = 32
EC_PUBLIC_KEY_LEN = 33
EC_XONLY_PUBLIC_KEY_LEN = 32
DLEQ_PROOF_LEN = 64
SP_V0_INFO_LEN = 66             # compressed scan || compressed spend
SP_SCAN_KEY_LEN = 65            # BIP-392 spscan: scan privkey || spend pubkey
OUTPOINT_LEN = 36

SECP256K1_EC_COMPRESSED = (1 << 1) | (1 << 8)
WALLY_SIGHASH_ALL = 0x01
WALLY_PSBT_VERSION_2 = 0x2
WALLY_PSBT_EXTRACT_NON_FINAL = 0x1
WALLY_PSBT_EXTRACT_OPT_FINAL = 0x2
BIP32_FLAG_KEY_PUBLIC = 0x1
WALLY_TX_FLAG_USE_WITNESS = 0x1
EC_FLAG_ECDSA, EC_FLAG_GRIND_R = 0x1, 0x4
BECH32M_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

# -- Bindings util.py does not generate ---------------------------------------


def _fn(name, argtypes, restype=c_int):
    fn = getattr(libwally, name)
    fn.restype, fn.argtypes = restype, argtypes
    return fn


_psbt_set_output_sp_v0_info = _fn('wally_psbt_set_output_sp_v0_info',
                                  [POINTER(wally_psbt), c_size_t, c_void_p, c_size_t])
_psbt_set_global_sp_ecdh_share = _fn('wally_psbt_set_global_sp_ecdh_share',
                                     [POINTER(wally_psbt), c_void_p, c_size_t, c_void_p, c_size_t])
_psbt_set_global_sp_dleq_proof = _fn('wally_psbt_set_global_sp_dleq_proof',
                                     [POINTER(wally_psbt), c_void_p, c_size_t, c_void_p, c_size_t])

_secp_context = _fn('wally_get_secp_context', [], c_void_p)
_pubkey_parse = _fn('secp256k1_ec_pubkey_parse', [c_void_p, c_void_p, c_void_p, c_size_t])
_pubkey_serialize = _fn('secp256k1_ec_pubkey_serialize',
                        [c_void_p, c_void_p, POINTER(c_size_t), c_void_p, c_uint])
_pubkey_combine = _fn('secp256k1_ec_pubkey_combine',
                      [c_void_p, c_void_p, POINTER(c_void_p), c_size_t])
_pubkey_tweak_mul = _fn('secp256k1_ec_pubkey_tweak_mul', [c_void_p, c_void_p, c_void_p])
_dleq_prove = _fn('secp256k1_dleq_prove',
                  [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p])
_dleq_verify = _fn('secp256k1_dleq_verify',
                   [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p])

# -- secp256k1 point helpers --------------------------------------------------
#
# A parsed secp256k1_pubkey is an opaque 64 byte object; it is only ever passed
# back into secp, so a plain buffer is enough to hold one.


def _parse(pubkey):
    """Parse a 33 byte compressed pubkey into its opaque 64 byte form."""
    obj = create_string_buffer(64)
    assert _pubkey_parse(_secp_context(), obj, pubkey, len(pubkey)) == 1, 'bad pubkey'
    return obj


def _serialize(obj):
    """Serialize an opaque pubkey back to 33 compressed bytes."""
    out, out_len = create_string_buffer(EC_PUBLIC_KEY_LEN), c_size_t(EC_PUBLIC_KEY_LEN)
    assert _pubkey_serialize(_secp_context(), out, byref(out_len), obj,
                             SECP256K1_EC_COMPRESSED) == 1
    return out.raw[:out_len.value]


def pubkey_from_privkey(privkey):
    """Derive the 33 byte compressed pubkey for a 32 byte private key."""
    out, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
    assert wally_ec_public_key_from_private_key(privkey, len(privkey), out,
                                                EC_PUBLIC_KEY_LEN) == WALLY_OK
    return bytes(out)


def pubkey_sum(pubkeys):
    """Sum compressed pubkeys, returning the compressed result."""
    objs = [_parse(pubkey) for pubkey in pubkeys]
    ptrs = (c_void_p * len(objs))(*[cast(obj, c_void_p) for obj in objs])
    out = create_string_buffer(64)
    assert _pubkey_combine(_secp_context(), out, ptrs, len(objs)) == 1, 'combine failed'
    return _serialize(out)


def pubkey_tweak_mul(pubkey, scalar):
    """Multiply a compressed pubkey by a 32 byte scalar."""
    obj = _parse(pubkey)
    assert _pubkey_tweak_mul(_secp_context(), obj, scalar) == 1, 'tweak_mul failed'
    return _serialize(obj)


def scalar_multiply(lhs, rhs):
    """Multiply two 32 byte scalars modulo the curve order."""
    out, _ = make_cbuffer('00' * EC_PRIVATE_KEY_LEN)
    assert wally_ec_scalar_multiply(lhs, len(lhs), rhs, len(rhs), out,
                                    EC_PRIVATE_KEY_LEN) == WALLY_OK
    return bytes(out)


# -- BIP-352 ------------------------------------------------------------------


def tagged_hash(tag, message):
    """BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag) || message)."""
    prefix = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(prefix + prefix + message).digest()


def smallest_outpoint(outpoints):
    """The lexicographically smallest txid || vout(LE) of the spent outpoints."""
    return min(txid + vout.to_bytes(4, 'little') for txid, vout in outpoints)


def input_hash(outpoint, pubkey_summed):
    """BIP-352 input_hash, committing to the outpoint and the summed inputs."""
    return tagged_hash('BIP0352/Inputs', outpoint + pubkey_summed)


def shared_secret_from_share(share, hashed_inputs):
    """Recipient shared secret from a BIP-375 ECDH share, which is untweaked."""
    return pubkey_tweak_mul(share, hashed_inputs)


def output_xonly(spend_pubkey, shared_secret, k):
    """The k'th silent payment output key: B_spend + hash(shared || k)*G."""
    tweak = tagged_hash('BIP0352/SharedSecret', shared_secret + k.to_bytes(4, 'big'))
    out, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
    assert wally_ec_public_key_tweak(spend_pubkey, EC_PUBLIC_KEY_LEN, tweak, len(tweak),
                                     out, EC_PUBLIC_KEY_LEN) == WALLY_OK
    return bytes(out)[1:]


def p2tr_script(xonly):
    """The P2TR scriptPubKey for an x-only key, used as-is (no BIP-341 tweak)."""
    out, _ = make_cbuffer('00' * 34)
    ret, written = wally_scriptpubkey_p2tr_from_bytes(xonly, len(xonly), 0, out, 34)
    assert ret == WALLY_OK and written == 34
    return bytes(out)


def scan_outputs(scripts, scan_privkey, spend_pubkey, input_pubkeys, outpoints):
    """Scan transaction outputs for silent payments to (scan, spend).

    This is the full recipient side: the shared secret is recomputed from the
    transaction itself, without needing the sender's BIP-375 ECDH share.
    Returns {output index: k} for each output belonging to this wallet.
    """
    summed = pubkey_sum(input_pubkeys)
    outpoint = smallest_outpoint(outpoints)
    tweaked = pubkey_tweak_mul(summed, input_hash(outpoint, summed))
    shared_secret = pubkey_tweak_mul(tweaked, scan_privkey)

    found, k = {}, 0
    candidates = {index: script[2:34] for index, script in enumerate(scripts)
                  if len(script) == 34 and script[:2] == b'\x51\x20'}
    while candidates:
        expected = output_xonly(spend_pubkey, shared_secret, k)
        match = [index for index, xonly in candidates.items() if xonly == expected]
        if not match:
            break  # BIP-352 scanning stops at the first k that is not present
        found[match[0]] = k
        del candidates[match[0]]
        k += 1
    return found


def dleq_verify(proof, summed_pubkey, scan_pubkey, share):
    """Verify a BIP-375 proof that the share was made with the summed inputs.

    Returns False rather than raising for malformed keys: a verifier is given
    whatever the sender wrote, which may not be a point on the curve at all.
    """
    try:
        points = [_parse(pubkey) for pubkey in (summed_pubkey, scan_pubkey, share)]
    except AssertionError:
        return False
    return _dleq_verify(_secp_context(), proof, *points, None) == 1


# -- BIP-352 addresses and BIP-392 key expressions ----------------------------


def _convertbits(data, from_bits, to_bits, pad):
    acc, bits, out = 0, 0, []
    maxv = (1 << to_bits) - 1
    for value in data:
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (to_bits - bits)) & maxv)
    elif not pad and (bits >= from_bits or ((acc << (to_bits - bits)) & maxv)):
        return None
    return out


def _bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32m_encode(hrp, version, payload):
    """Encode a versioned payload as bech32m, as BIP-352 and BIP-392 do."""
    data = [version] + _convertbits(payload, 8, 5, True)
    values = _bech32_hrp_expand(hrp) + data
    checksum = _bech32_polymod(values + [0] * 6) ^ 0x2bc830a3
    data += [(checksum >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join([BECH32M_CHARSET[d] for d in data])


def bech32m_decode(encoded):
    """Decode a bech32m string to (hrp, version, payload)."""
    encoded = encoded.lower()
    position = encoded.rfind('1')
    hrp, data = encoded[:position], [BECH32M_CHARSET.find(c) for c in encoded[position + 1:]]
    assert min(data) >= 0, 'invalid bech32m character'
    assert _bech32_polymod(_bech32_hrp_expand(hrp) + data) == 0x2bc830a3, 'bad checksum'
    payload = _convertbits(data[1:-6], 5, 8, False)
    assert payload is not None, 'invalid bech32m padding'
    return hrp, data[0], bytes(payload)


def sp_address(scan_pubkey, spend_pubkey, hrp='sp'):
    """The BIP-352 silent payment address for a (scan, spend) key pair."""
    return bech32m_encode(hrp, 0, scan_pubkey + spend_pubkey)


def decode_sp_scan_key(key_expression):
    """Unpack a BIP-392 spscan1... key to (scan privkey, spend pubkey)."""
    hrp, version, payload = bech32m_decode(key_expression)
    assert hrp in ('spscan', 'tspscan'), f'not a scan key: {hrp}'
    assert version == 0 and len(payload) == SP_SCAN_KEY_LEN, 'bad scan key payload'
    return payload[:EC_PRIVATE_KEY_LEN], payload[EC_PRIVATE_KEY_LEN:]


# -- Sender side (see the TODO at the top of this file) -----------------------


def _sum_privkeys(privkeys):
    """Sum private keys modulo the curve order.

    NOTE: taproot inputs must have odd-parity keys negated first, per BIP-352.
    Only P2WPKH inputs are used here, so there is nothing to normalize.
    """
    secret = privkeys[0]
    for privkey in privkeys[1:]:
        out, _ = make_cbuffer('00' * EC_PRIVATE_KEY_LEN)
        assert wally_ec_scalar_add(secret, len(secret), privkey, len(privkey), out,
                                   EC_PRIVATE_KEY_LEN) == WALLY_OK
        secret = bytes(out)
    return secret


def sp_derive_output(recipient_info, privkeys, outpoints, k=0):
    """Derive the k'th BIP-352 output script for a recipient, as the sender."""
    summed = pubkey_sum([pubkey_from_privkey(privkey) for privkey in privkeys])
    hashed = input_hash(smallest_outpoint(outpoints), summed)
    secret = _sum_privkeys(privkeys)
    scan_pubkey = recipient_info[:EC_PUBLIC_KEY_LEN]
    spend_pubkey = recipient_info[EC_PUBLIC_KEY_LEN:]
    shared_secret = pubkey_tweak_mul(scan_pubkey, scalar_multiply(hashed, secret))
    return p2tr_script(output_xonly(spend_pubkey, shared_secret, k)), secret


def sp_ecdh_share(scan_pubkey, summed_privkey):
    """The BIP-375 ECDH share and its DLEQ proof, both keyed by the scan key."""
    share = pubkey_tweak_mul(scan_pubkey, summed_privkey)
    proof = create_string_buffer(DLEQ_PROOF_LEN)
    assert _dleq_prove(_secp_context(), proof, summed_privkey, _parse(scan_pubkey),
                       os.urandom(32), None) == 1, 'dleq_prove failed'
    return share, proof.raw


# -- Reference vector ---------------------------------------------------------

# BIP-352 test vector "Outputs with the same script pubkey": two P2WPKH inputs
# paying one recipient. The helpers above are an independent implementation, so
# they are worth nothing unless they agree with the reference.
VECTOR = {
    'privkeys': ['eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1',
                 '93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16'],
    'scan': '0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4',
    'spend': '025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36',
    'outpoint': '169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f400000000',
    'output': '3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1',
}


def check_reference_vector():
    """Check the sender and recipient paths against the BIP-352 vector."""
    privkeys = [bytes.fromhex(privkey) for privkey in VECTOR['privkeys']]
    scan_pubkey = bytes.fromhex(VECTOR['scan'])
    spend_pubkey = bytes.fromhex(VECTOR['spend'])
    outpoint = bytes.fromhex(VECTOR['outpoint'])
    expected = bytes.fromhex(VECTOR['output'])

    summed = pubkey_sum([pubkey_from_privkey(privkey) for privkey in privkeys])
    hashed = input_hash(outpoint, summed)
    secret = _sum_privkeys(privkeys)
    shared_secret = pubkey_tweak_mul(scan_pubkey, scalar_multiply(hashed, secret))
    assert output_xonly(spend_pubkey, shared_secret, 0) == expected, 'sender mismatch'

    share, proof = sp_ecdh_share(scan_pubkey, secret)
    recovered = shared_secret_from_share(share, hashed)
    assert output_xonly(spend_pubkey, recovered, 0) == expected, 'share mismatch'
    assert dleq_verify(proof, summed, scan_pubkey, share), 'proof mismatch'


# -- Demonstration ------------------------------------------------------------

# Example keys only - never hardcode keys in production
SENDER_PRIVKEYS = [bytes([0x11] * 32), bytes([0x22] * 32)]
RECIPIENT_SCAN_PRIVKEY = bytes([0x33] * 32)
RECIPIENT_SPEND_PRIVKEY = bytes([0x44] * 32)
FUNDING_TXID = bytes([0xaa] * 32)
FINGERPRINT = bytes([0x00] * 4)
INPUT_AMOUNT, OUTPUT_AMOUNT = 100000, 90000


def p2wpkh_script(pubkey):
    hash160, _ = make_cbuffer('00' * 20)
    assert wally_hash160(pubkey, len(pubkey), hash160, 20) == WALLY_OK
    return b'\x00\x14' + bytes(hash160)


def main():
    check_reference_vector()
    print('BIP-352 reference vector verified')

    # -- Step 1: the recipient publishes a silent payment address -------------
    scan_pubkey = pubkey_from_privkey(RECIPIENT_SCAN_PRIVKEY)
    spend_pubkey = pubkey_from_privkey(RECIPIENT_SPEND_PRIVKEY)
    recipient_info = scan_pubkey + spend_pubkey
    print(f'Recipient address: {sp_address(scan_pubkey, spend_pubkey)}')

    # The same keys as a BIP-392 scan key expression, which is what a watch
    # only wallet is given: the scan private key and the spend public key.
    key_expression = bech32m_encode('spscan', 0, RECIPIENT_SCAN_PRIVKEY + spend_pubkey)
    assert decode_sp_scan_key(key_expression) == (RECIPIENT_SCAN_PRIVKEY, spend_pubkey)

    # -- Step 2: the sender builds a PSBT with an unresolved SP output --------
    sender_pubkeys = [pubkey_from_privkey(privkey) for privkey in SENDER_PRIVKEYS]
    outpoints = [(FUNDING_TXID, index) for index in range(len(SENDER_PRIVKEYS))]

    psbt = pointer(wally_psbt())
    assert wally_psbt_init_alloc(WALLY_PSBT_VERSION_2, len(SENDER_PRIVKEYS), 1, 0, 0,
                                 psbt) == WALLY_OK
    for index, (txid, vout) in enumerate(outpoints):
        tx_input = pointer(wally_tx_input())
        assert wally_tx_input_init_alloc(txid, len(txid), vout, 0xffffffff, None, 0, None,
                                         tx_input) == WALLY_OK
        assert wally_psbt_add_tx_input_at(psbt, index, 0, tx_input) == WALLY_OK

        utxo = pointer(wally_tx_output())
        script = p2wpkh_script(sender_pubkeys[index])
        assert wally_tx_output_init_alloc(INPUT_AMOUNT, script, len(script), utxo) == WALLY_OK
        assert wally_psbt_set_input_witness_utxo(psbt, index, utxo) == WALLY_OK
        assert wally_psbt_set_input_amount(psbt, index, INPUT_AMOUNT) == WALLY_OK
        assert wally_psbt_set_input_sighash(psbt, index, WALLY_SIGHASH_ALL) == WALLY_OK
        # The signer finds its inputs by looking itself up in the keypaths
        pubkey = sender_pubkeys[index]
        path = (c_uint32 * 1)(index)
        assert wally_psbt_add_input_keypath(psbt, index, pubkey, len(pubkey),
                                            FINGERPRINT, len(FINGERPRINT), path, 1) == WALLY_OK

    # The output carries the recipient, but no script: only the sender, who
    # knows the input keys, can work out where the payment actually goes.
    tx_output = pointer(wally_tx_output())
    assert wally_tx_output_init_alloc(OUTPUT_AMOUNT, None, 0, tx_output) == WALLY_OK
    assert wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output) == WALLY_OK
    assert wally_psbt_set_output_amount(psbt, 0, OUTPUT_AMOUNT) == WALLY_OK
    assert _psbt_set_output_sp_v0_info(psbt, 0, recipient_info,
                                       len(recipient_info)) == WALLY_OK
    print(f'PSBT built with {len(SENDER_PRIVKEYS)} inputs and 1 silent payment output')

    # -- Step 3: the sender resolves the output and shares the secret ---------
    script, summed_privkey = sp_derive_output(recipient_info, SENDER_PRIVKEYS, outpoints)
    assert wally_psbt_set_output_script(psbt, 0, script, len(script)) == WALLY_OK

    share, proof = sp_ecdh_share(scan_pubkey, summed_privkey)
    assert _psbt_set_global_sp_ecdh_share(psbt, scan_pubkey, len(scan_pubkey), share,
                                          len(share)) == WALLY_OK
    assert _psbt_set_global_sp_dleq_proof(psbt, scan_pubkey, len(scan_pubkey), proof,
                                          len(proof)) == WALLY_OK
    print(f'Output resolved to {script.hex()}')

    # -- Step 4: sign, finalize, extract --------------------------------------
    for privkey in SENDER_PRIVKEYS:
        assert wally_psbt_sign(psbt, privkey, len(privkey), EC_FLAG_GRIND_R) == WALLY_OK
    assert wally_psbt_finalize(psbt, 0) == WALLY_OK

    tx = POINTER(wally_tx)()
    assert wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_OPT_FINAL, byref(tx)) == WALLY_OK
    buf, buf_len = make_cbuffer('00' * 4096)
    ret, written = wally_tx_to_bytes(tx, WALLY_TX_FLAG_USE_WITNESS, buf, buf_len)
    assert ret == WALLY_OK
    print(f'Transaction extracted ({written} bytes)')

    # -- Step 5: the recipient scans the transaction --------------------------
    # A real scanner takes the input pubkeys from the witnesses on chain; the
    # outpoints and the output scripts likewise come from the transaction.
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
                         outpoints)
    assert found == {0: 0}, f'scan found {found}, expected the payment at output 0'
    print(f'Recipient found the payment at output {list(found)[0]}')

    # -- Step 6: verify the share and its proof -------------------------------
    summed_pubkey = pubkey_sum(scanned_pubkeys)
    assert dleq_verify(proof, summed_pubkey, scan_pubkey, share), 'DLEQ proof failed'

    # The share is untweaked, so tweaking it by input_hash must reproduce the
    # secret the recipient derived for itself in step 5.
    hashed = input_hash(smallest_outpoint(outpoints), summed_pubkey)
    from_share = shared_secret_from_share(share, hashed)
    assert output_xonly(spend_pubkey, from_share, 0) == scripts[0][2:34]
    print('DLEQ proof verified, share agrees with the scan')

    wally_tx_free(tx)
    wally_psbt_free(psbt)
    print('Silent payment round trip complete')


if __name__ == '__main__':
    main()
