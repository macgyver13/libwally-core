import copy
import json
import unittest
from util import *

# BIP-352 test vectors, copied verbatim from the reference implementation's
# bip352_send_and_receive_test_vectors.json.
with open(root_dir + 'src/data/bip352_test_vectors.json', 'r') as f:
    BIP352_JSON = json.load(f)

# A valid recipient, for the tests that do not need a whole vector case
RECIPIENT = BIP352_JSON[0]['sending'][0]['given']['recipients'][0]

WALLY_SP_INVALID, WALLY_SP_INCOMPLETE, WALLY_SP_COMPLETE = 0, 1, 2
ENTROPY = '00' * 32
NUMS = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
BIP32_VER_MAIN_PRIVATE = 0x0488ADE4
EC_FLAG_SCHNORR = 0x2
WALLY_PSBT_EXTRACT_NON_FINAL = 0x1

# BIP-376: an arbitrary tweak, and the x-only output key of the input it spends
TWEAK = '77' * 32
OUTPUT_KEY = NUMS
# The two BIP-376 fields as they appear in a serialized input map, for the
# tests that splice them into a PSBT the library would not produce itself
SP_TWEAK_KV = bytes([1, 0x20, 32]) + bytes.fromhex(TWEAK)
SP_SPEND_KV = (bytes([34, 0x1f]) + bytes.fromhex(RECIPIENT['spend_pub_key']) +
               bytes([4, 0, 0, 0, 0]))
CONTROL_BLOCK_TAGS = (0xc0, 0xc1)
ANNEX_TAG = 0x50


def script_pushes(script_hex):
    """The data pushes of a script, ignoring any other opcodes."""
    script, pushes, i = bytes.fromhex(script_hex), [], 0
    while i < len(script):
        op = script[i]
        i += 1
        if op < 0x4c:
            size = op
        elif op in (0x4c, 0x4d, 0x4e):
            width = 1 << (op - 0x4c)
            size = int.from_bytes(script[i:i + width], 'little')
            i += width
        else:
            continue  # Not a push
        pushes.append(script[i:i + size])
        i += size
    return pushes


def witness_stack(witness_hex):
    """The items of a serialized witness stack."""
    data, items, i = bytes.fromhex(witness_hex), [], 0
    if not data:
        return items
    count, i = data[0], 1
    for _ in range(count):
        size = data[i]
        i += 1
        items.append(data[i:i + size])
        i += size
    return items


def spending_pubkey(txin):
    """The public key an input is spent with, as a PSBT records in a keypath.

    BIP-352 cares whether it is compressed, which the prevout script cannot
    say. Taproot inputs are excluded: their keys are x-only.
    """
    if txin['prevout']['scriptPubKey']['hex'].startswith('5120'):
        return None
    items = witness_stack(txin.get('txinwitness', ''))
    if items:
        return items[-1]  # p2wpkh, or p2sh-p2wpkh
    pushes = script_pushes(txin.get('scriptSig', ''))
    return pushes[-1] if pushes else None  # p2pkh


def taproot_internal_key(witness_hex):
    """The internal key of a script path spend, from its control block.

    A key path spend has no control block, and so no internal key to record:
    the input is spendable with the output key, which is what BIP-352 wants.
    """
    items = witness_stack(witness_hex)
    # An annex, if present, follows the control block and must be stepped over
    if len(items) >= 2 and items[-1] and items[-1][0] == ANNEX_TAG:
        items = items[:-1]
    if len(items) >= 2 and items[-1] and items[-1][0] in CONTROL_BLOCK_TAGS:
        return items[-1][1:33]
    return None


@unittest.skipUnless(wally_psbt_sp_resolve, 'Silent payments module not enabled')

def hash160(hex_data):
    """hash160 of a hex string, as a hex string"""
    data, data_len = make_cbuffer(hex_data)
    out, out_len = make_cbuffer('00' * 20)
    assert wally_hash160(data, data_len, out, out_len) == WALLY_OK
    return h(out).decode('utf-8')

class SilentPaymentsTests(unittest.TestCase):

    def build_psbt(self, vin, recipients):
        """Build a PSBTv2 spending `vin` to one output per recipient."""
        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_init_alloc(2, len(vin), max(len(recipients), 1),
                                               0, 0, psbt), WALLY_OK)
        for i, txin in enumerate(vin):
            txid, txid_len = make_cbuffer(txin['txid'])
            txid = bytes(bytearray(txid)[::-1])  # txids are displayed reversed
            tx_in = pointer(wally_tx_input())
            self.assertEqual(wally_tx_input_init_alloc(txid, txid_len, txin['vout'],
                                                       0xffffffff, None, 0, None,
                                                       tx_in), WALLY_OK)
            self.assertEqual(wally_psbt_add_tx_input_at(psbt, i, 0, tx_in), WALLY_OK)

            spk, spk_len = make_cbuffer(txin['prevout']['scriptPubKey']['hex'])
            utxo = pointer(wally_tx_output())
            self.assertEqual(wally_tx_output_init_alloc(100000, spk, spk_len, utxo), WALLY_OK)
            self.assertEqual(wally_psbt_set_input_witness_utxo(psbt, i, utxo), WALLY_OK)
            self.assertEqual(wally_psbt_set_input_amount(psbt, i, 100000), WALLY_OK)

            # A PSBT carries as fields what the vectors carry in the spend:
            # the redeem script of a p2sh input, and the internal key of a
            # taproot input spent through a script path.
            pushes = script_pushes(txin.get('scriptSig', ''))
            if pushes:
                redeem, redeem_len = make_cbuffer(h(pushes[-1]).decode('utf-8'))
                self.assertEqual(wally_psbt_set_input_redeem_script(psbt, i, redeem,
                                                                    redeem_len), WALLY_OK)
            # A signer knows the key it will sign an input with, and records
            # it in a keypath; the vectors carry it in the spend instead
            pubkey = spending_pubkey(txin)
            if pubkey and len(pubkey) in (33, 65):
                key, key_len = make_cbuffer(h(pubkey).decode('utf-8'))
                path = (c_uint32 * 1)(0)
                fingerprint, fingerprint_len = make_cbuffer('00000000')
                self.assertEqual(wally_psbt_add_input_keypath(psbt, i, key, key_len,
                                                              fingerprint, fingerprint_len,
                                                              path, 1), WALLY_OK)

            internal_key = taproot_internal_key(txin.get('txinwitness', ''))
            if internal_key:
                key, key_len = make_cbuffer(h(internal_key).decode('utf-8'))
                self.assertEqual(wally_psbt_set_input_taproot_internal_key(psbt, i, key,
                                                                           key_len), WALLY_OK)

        for i, recipient in enumerate(recipients):
            tx_out = pointer(wally_tx_output())
            self.assertEqual(wally_tx_output_init_alloc(90000, None, 0, tx_out), WALLY_OK)
            self.assertEqual(wally_psbt_add_tx_output_at(psbt, i, 0, tx_out), WALLY_OK)
            self.assertEqual(wally_psbt_set_output_amount(psbt, i, 90000), WALLY_OK)
            info, info_len = make_cbuffer(recipient['scan_pub_key'] + recipient['spend_pub_key'])
            self.assertEqual(wally_psbt_set_output_sp_v0_info(psbt, i, info, info_len), WALLY_OK)
        return psbt

    def eligible_keys(self, psbt, vin):
        """The private keys of the inputs wally reports as eligible."""
        keys = ''
        for i, txin in enumerate(vin):
            ret, eligible = wally_psbt_get_input_sp_eligible(psbt, i)
            self.assertIn(ret, (WALLY_OK, WALLY_ERROR))
            if ret == WALLY_OK and eligible:
                keys += txin['private_key']
        return keys

    def output_scripts(self, psbt, num_outputs):
        """The x-only output keys of a resolved PSBT's silent payments."""
        keys = []
        for i in range(num_outputs):
            script, script_len = make_cbuffer('00' * 34)
            ret, written = wally_psbt_get_output_script(psbt, i, script, script_len)
            self.assertEqual((ret, written), (WALLY_OK, 34))
            self.assertEqual(h(script[:2]).decode('utf-8'), '5120')
            keys.append(h(script[2:]).decode('utf-8'))
        return sorted(keys)

    def test_bip352_sending(self):
        """Test resolving silent payments against the BIP-352 vectors"""
        entropy, entropy_len = make_cbuffer(ENTROPY)
        tested = 0

        for case in BIP352_JSON:
            for sending in case['sending']:
                given, expected = sending['given'], sending['expected']
                psbt = self.build_psbt(given['vin'], given['recipients'])
                keys_hex = self.eligible_keys(psbt, given['vin'])
                keys, keys_len = make_cbuffer(keys_hex) if keys_hex else (None, 0)
                ret = wally_psbt_sp_resolve(psbt, keys, keys_len, entropy, entropy_len, 0)

                # A case with no contributing inputs, or whose input keys sum
                # to zero (leaving no private key sum), cannot be sent at all
                if not expected['input_pub_keys'] or 'input_private_key_sum' not in expected:
                    self.assertNotEqual(ret, WALLY_OK, case['comment'])
                    wally_psbt_free(psbt)
                    tested += 1
                    continue

                self.assertEqual(ret, WALLY_OK, case['comment'])
                # Outputs are given as the alternative orderings that are
                # acceptable when recipients share a scan key. Cases that
                # exercise the receiving side only leave them unspecified.
                alternatives = [sorted(group) for group in expected['outputs']]
                if any(alternatives):
                    self.assertIn(self.output_scripts(psbt, len(given['recipients'])),
                                  alternatives, case['comment'])
                wally_psbt_free(psbt)
                tested += 1

        self.assertEqual(tested, len(BIP352_JSON))

    def test_bip352_addresses(self):
        """Test silent payment addresses against the BIP-352 vectors"""
        for case in BIP352_JSON:
            for receiving in case['receiving']:
                material = receiving['given']['key_material']
                info = ''
                for name in ('scan_priv_key', 'spend_priv_key'):
                    priv, priv_len = make_cbuffer(material[name])
                    pub, pub_len = make_cbuffer('00' * 33)
                    self.assertEqual(wally_ec_public_key_from_private_key(priv, priv_len, pub,
                                                                          pub_len), WALLY_OK)
                    info += h(pub).decode('utf-8')

                payload, payload_len = make_cbuffer(info)
                ret, addr = wally_sp_address_from_bytes(payload, payload_len, utf8('sp'), 0)
                # The first expected address is the unlabeled one
                self.assertEqual((ret, addr),
                                 (WALLY_OK, receiving['expected']['addresses'][0]),
                                 case['comment'])

    def make_psbt(self, scripts, recipients=None):
        """Build a PSBTv2 from scriptPubKeys, for tests that need no vectors"""
        vin = [{'txid': '%02x' % (i + 1) * 32, 'vout': i,
                'prevout': {'scriptPubKey': {'hex': script}}}
               for i, script in enumerate(scripts)]
        if recipients is None:
            recipients = [RECIPIENT]
        return self.build_psbt(vin, recipients)

    def test_smallest_outpoint(self):
        """Test the BIP-352 smallest outpoint, which is ordered by vout LE"""
        # The vout is compared as 4 bytes little endian, so 0x100 sorts first
        vin = [{'txid': '11' * 32, 'vout': 1,
                'prevout': {'scriptPubKey': {'hex': '0014' + '11' * 20}}},
               {'txid': '11' * 32, 'vout': 0x100,
                'prevout': {'scriptPubKey': {'hex': '0014' + '22' * 20}}}]
        psbt = self.build_psbt(vin, [RECIPIENT])
        out, out_len = make_cbuffer('00' * 36)
        self.assertEqual(wally_psbt_get_sp_smallest_outpoint(psbt, out, out_len), WALLY_OK)
        self.assertEqual(h(out).decode('utf-8'), '11' * 32 + '00010000')

        for args in [(None, out, out_len), (psbt, None, out_len), (psbt, out, out_len - 1)]:
            self.assertEqual(wally_psbt_get_sp_smallest_outpoint(*args), WALLY_EINVAL)
        wally_psbt_free(psbt)

    def test_input_eligible(self):
        """Test which inputs can contribute to a silent payment"""
        # P2PKH and P2WPKH are eligible, P2WSH and bare P2SH are not
        for script, eligible in [('0014' + '11' * 20, 1),
                                 ('76a914' + '11' * 20 + '88ac', 1),
                                 ('0020' + '11' * 32, 0),
                                 ('a914' + '11' * 20 + '87', 0)]:
            psbt = self.make_psbt([script])
            self.assertEqual(wally_psbt_get_input_sp_eligible(psbt, 0), (WALLY_OK, eligible))
            wally_psbt_free(psbt)

        # A P2TR input is eligible unless its internal key is the NUMS point,
        # which leaves it with no key path to sign with
        for internal_key, eligible in [(None, 1), ('11' * 32, 1), (NUMS, 0)]:
            psbt = self.make_psbt(['5120' + '11' * 32])
            if internal_key:
                key, key_len = make_cbuffer(internal_key)
                self.assertEqual(wally_psbt_set_input_taproot_internal_key(
                    psbt, 0, key, key_len), WALLY_OK)
            self.assertEqual(wally_psbt_get_input_sp_eligible(psbt, 0), (WALLY_OK, eligible))
            wally_psbt_free(psbt)

        # An unknown witness version must be refused, not called ineligible
        psbt = self.make_psbt(['5220' + '11' * 32])
        self.assertEqual(wally_psbt_get_input_sp_eligible(psbt, 0), (WALLY_ERROR, 0))
        wally_psbt_free(psbt)

        psbt = self.make_psbt(['0014' + '11' * 20])
        self.assertEqual(wally_psbt_get_input_sp_eligible(psbt, 1), (WALLY_EINVAL, 0))
        wally_psbt_free(psbt)

    def test_input_eligible_p2sh_redeem(self):
        """Test that a P2SH input's redeem script must match its prevout

        A P2SH prevout commits only to hash160 of its redeem script, so the
        script the PSBT supplies is attacker-choosable. One the prevout does
        not pay to cannot be spent with, so the input is simply ineligible,
        exactly as an unreadable one is.
        """
        redeem = '0014' + hash160('02' + '11' * 32)
        for spk, eligible in [('a914' + hash160(redeem) + '87', 1),
                              ('a914' + '22' * 20 + '87', 0)]:
            psbt = self.make_psbt([spk])
            script, script_len = make_cbuffer(redeem)
            self.assertEqual(wally_psbt_set_input_redeem_script(
                psbt, 0, script, script_len), WALLY_OK)
            self.assertEqual(wally_psbt_get_input_sp_eligible(psbt, 0),
                             (WALLY_OK, eligible))
            wally_psbt_free(psbt)

    def test_resolve_invalid(self):
        """Test resolving with invalid arguments"""
        case = BIP352_JSON[0]['sending'][0]['given']
        psbt = self.build_psbt(case['vin'], case['recipients'])
        keys, keys_len = make_cbuffer(''.join(v['private_key'] for v in case['vin']))
        entropy, entropy_len = make_cbuffer(ENTROPY)

        for args in [(None, keys, keys_len, entropy, entropy_len, 0),
                     (psbt, None, keys_len, entropy, entropy_len, 0),
                     (psbt, keys, 32, entropy, entropy_len, 0),            # Too few keys
                     (psbt, keys, keys_len - 1, entropy, entropy_len, 0),  # Ragged keys
                     (psbt, keys, keys_len, None, entropy_len, 0),
                     (psbt, keys, keys_len, entropy, 31, 0),               # Short entropy
                     (psbt, keys, keys_len, entropy, entropy_len, 1)]:     # Invalid flags
            self.assertEqual(wally_psbt_sp_resolve(*args), WALLY_EINVAL)
        wally_psbt_free(psbt)

        # A PSBT with no silent payment output has nothing to resolve
        psbt = self.build_psbt(case['vin'], case['recipients'])
        self.assertEqual(wally_psbt_clear_output_sp_v0_info(psbt, 0), WALLY_OK)
        self.assertEqual(wally_psbt_sp_resolve(psbt, keys, keys_len,
                                               entropy, entropy_len, 0), WALLY_EINVAL)
        wally_psbt_free(psbt)

    def test_resolve_existing_scripts_transactional(self):
        """Test existing scripts are validated and failures change nothing"""
        case = BIP352_JSON[0]['sending'][0]['given']
        recipients = [case['recipients'][0], case['recipients'][0]]
        keys_hex = ''.join(v['private_key'] for v in case['vin'])
        keys, keys_len = make_cbuffer(keys_hex)
        entropy, entropy_len = make_cbuffer(ENTROPY)

        expected = self.build_psbt(case['vin'], recipients)
        self.assertEqual(wally_psbt_sp_resolve(expected, keys, keys_len,
                                               entropy, entropy_len, 0), WALLY_OK)
        scripts = []
        for i in range(2):
            script, script_len = make_cbuffer('00' * 34)
            ret, written = wally_psbt_get_output_script(expected, i, script, script_len)
            self.assertEqual((ret, written), (WALLY_OK, script_len))
            scripts.append(bytes(script))
        wally_psbt_free(expected)

        # Missing scripts are populated normally.
        psbt = self.build_psbt(case['vin'], recipients)
        self.assertEqual(wally_psbt_sp_resolve(psbt, keys, keys_len,
                                               entropy, entropy_len, 0), WALLY_OK)
        self.assertEqual(psbt.contents.global_sp_ecdh_shares.num_items, 1)
        wally_psbt_free(psbt)

        # A matching proposed script is accepted and the missing one is filled.
        psbt = self.build_psbt(case['vin'], recipients)
        script, script_len = make_cbuffer(h(scripts[0]).decode('utf-8'))
        self.assertEqual(wally_psbt_set_output_script(psbt, 0, script, script_len), WALLY_OK)
        self.assertEqual(wally_psbt_sp_resolve(psbt, keys, keys_len,
                                               entropy, entropy_len, 0), WALLY_OK)
        self.assertEqual(self.output_scripts(psbt, 2),
                         sorted(h(s[2:]).decode('utf-8') for s in scripts))
        wally_psbt_free(psbt)

        # A mismatch on the later output must leave the entire PSBT unchanged.
        psbt = self.build_psbt(case['vin'], recipients)
        script, script_len = make_cbuffer(h(scripts[0]).decode('utf-8'))
        self.assertEqual(wally_psbt_set_output_script(psbt, 0, script, script_len), WALLY_OK)
        tampered = bytearray(scripts[1])
        tampered[-1] ^= 1
        script, script_len = make_cbuffer(h(tampered).decode('utf-8'))
        self.assertEqual(wally_psbt_set_output_script(psbt, 1, script, script_len), WALLY_OK)
        self.assertEqual(wally_psbt_sp_resolve(psbt, keys, keys_len,
                                               entropy, entropy_len, 0), WALLY_EINVAL)
        self.assertEqual(psbt.contents.global_sp_ecdh_shares.num_items, 0)
        self.assertEqual(psbt.contents.global_sp_dleq_proofs.num_items, 0)
        for i, expected_script in enumerate((scripts[0], bytes(tampered))):
            actual, actual_len = make_cbuffer('00' * 34)
            ret, written = wally_psbt_get_output_script(psbt, i, actual, actual_len)
            self.assertEqual((ret, written), (WALLY_OK, actual_len))
            self.assertEqual(bytes(actual), expected_script)
        wally_psbt_free(psbt)

    def test_taproot_output_key(self):
        """Test that a taproot input contributes its tweaked output key

        BIP-352 uses the taproot output key, which differs from the internal
        key whenever the output is tweaked - as every BIP-86 output is. The
        BIP-352 vectors cannot catch a confusion of the two, because their
        taproot inputs are built with an untweaked key.
        """
        priv, priv_len = make_cbuffer('55' * 32)
        pub, pub_len = make_cbuffer('00' * 33)
        self.assertEqual(wally_ec_public_key_from_private_key(priv, priv_len,
                                                              pub, pub_len), WALLY_OK)
        # The key path spend of a BIP-86 output: no merkle root, so the tweak
        # is the internal key alone, and internal key != output key
        tweaked_priv, tweaked_priv_len = make_cbuffer('00' * 32)
        tweaked_pub, tweaked_pub_len = make_cbuffer('00' * 33)
        self.assertEqual(wally_ec_private_key_bip341_tweak(
            priv, priv_len, None, 0, 0, tweaked_priv, tweaked_priv_len), WALLY_OK)
        self.assertEqual(wally_ec_public_key_bip341_tweak(
            pub, pub_len, None, 0, 0, tweaked_pub, tweaked_pub_len), WALLY_OK)
        internal_xonly = h(pub[1:]).decode('utf-8')
        output_xonly = h(tweaked_pub[1:]).decode('utf-8')
        self.assertNotEqual(internal_xonly, output_xonly)

        vin = [{'txid': '11' * 32, 'vout': 0,
                'prevout': {'scriptPubKey': {'hex': '5120' + output_xonly}}}]
        psbt = self.build_psbt(vin, [RECIPIENT])
        key, key_len = make_cbuffer(internal_xonly)
        self.assertEqual(wally_psbt_set_input_taproot_internal_key(psbt, 0, key,
                                                                   key_len), WALLY_OK)
        entropy, entropy_len = make_cbuffer(ENTROPY)
        self.assertEqual(wally_psbt_sp_resolve(psbt, tweaked_priv, tweaked_priv_len,
                                               entropy, entropy_len, 0), WALLY_OK)
        # The share is proven against, and the output derived from, the output
        # key. Using the internal key for either leaves them disagreeing.
        self.assertEqual(wally_psbt_get_sp_status(psbt, 0),
                         (WALLY_OK, WALLY_SP_COMPLETE))
        wally_psbt_free(psbt)

    def test_status_output_scripts(self):
        """Test that a resolved output must hold the derived scriptPubKey"""
        case = BIP352_JSON[0]['sending'][0]['given']
        keys, keys_len = make_cbuffer(''.join(v['private_key'] for v in case['vin']))
        entropy, entropy_len = make_cbuffer(ENTROPY)

        psbt = self.build_psbt(case['vin'], case['recipients'])
        self.assertEqual(wally_psbt_sp_resolve(psbt, keys, keys_len,
                                               entropy, entropy_len, 0), WALLY_OK)
        self.assertEqual(wally_psbt_get_sp_status(psbt, 0),
                         (WALLY_OK, WALLY_SP_COMPLETE))

        # Replacing a resolved script with another valid P2TR script must be
        # caught, even though every share and proof is untouched and valid
        script = self.output_scripts(psbt, len(case['recipients']))[0]
        tampered = '5120' + ('%02x' % (int(script[:2], 16) ^ 0xff)) + script[2:]
        buf, buf_len = make_cbuffer(tampered)
        self.assertEqual(wally_psbt_set_output_script(psbt, 0, buf, buf_len), WALLY_OK)
        self.assertEqual(wally_psbt_get_sp_status(psbt, 0),
                         (WALLY_OK, WALLY_SP_INVALID))
        wally_psbt_free(psbt)

    def build_spend_psbt(self):
        """Build a PSBTv2 with a single p2tr input, as a BIP-376 spend has."""
        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt), WALLY_OK)
        txid, txid_len = make_cbuffer('5b' * 32)
        tx_in = pointer(wally_tx_input())
        self.assertEqual(wally_tx_input_init_alloc(txid, txid_len, 0, 0xffffffff,
                                                   None, 0, None, tx_in), WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in), WALLY_OK)
        spk, spk_len = make_cbuffer('5120' + OUTPUT_KEY)
        utxo = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(100000, spk, spk_len, utxo), WALLY_OK)
        self.assertEqual(wally_psbt_set_input_witness_utxo(psbt, 0, utxo), WALLY_OK)

        tx_out = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(90000, spk, spk_len, tx_out), WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out), WALLY_OK)
        return psbt

    def serialize(self, psbt):
        """Serialize a PSBT to bytes."""
        ret, length = wally_psbt_get_length(psbt, 0)
        self.assertEqual(ret, WALLY_OK)
        buf, buf_len = make_cbuffer('00' * length)
        ret, written = wally_psbt_to_bytes(psbt, 0, buf, buf_len)
        self.assertEqual((ret, written), (WALLY_OK, length))
        return bytes(bytearray(buf))

    def parse(self, data, flags=0):
        """Parse PSBT bytes, returning the wally return code and the PSBT."""
        buf, buf_len = make_cbuffer(h(data).decode('utf-8'))
        psbt = POINTER(wally_psbt)()
        return wally_psbt_from_bytes(buf, buf_len, flags, byref(psbt)), psbt

    def test_status_key_not_paid_to(self):
        """Test that an input's named key must be the key its prevout pays to

        A non-taproot script commits only to hash160 of the key, so the PSBT
        must name the key itself, and nothing stops it naming a key the prevout
        does not pay to. A share proven against such a key is bound to nothing:
        the proof verifies, A_sum is wrong, and the recipient scanning with the
        real A_sum never finds the output.
        """
        case = BIP352_JSON[0]['sending'][0]['given']
        entropy, entropy_len = make_cbuffer(ENTROPY)

        # Repointing the prevout at another key hash, while the keypath still
        # names the original key, is the same mismatch seen from the other side
        for spk, expected in [(None, WALLY_SP_COMPLETE),
                              ('76a914' + '33' * 20 + '88ac', WALLY_SP_INVALID)]:
            vin = copy.deepcopy(case['vin'])
            if spk is not None:
                vin[0]['prevout']['scriptPubKey']['hex'] = spk
            psbt = self.build_psbt(vin, case['recipients'])
            keys, keys_len = make_cbuffer(''.join(v['private_key'] for v in vin))
            self.assertEqual(wally_psbt_sp_resolve(psbt, keys, keys_len, entropy,
                                                   entropy_len, 0), WALLY_OK)
            self.assertEqual(wally_psbt_get_sp_status(psbt, 0),
                             (WALLY_OK, expected))
            wally_psbt_free(psbt)

    def test_bip376_fields(self):
        """Test the BIP-376 silent payment spend fields round trip"""
        psbt = self.build_spend_psbt()
        tweak, tweak_len = make_cbuffer(TWEAK)
        self.assertEqual(wally_psbt_set_input_sp_tweak(psbt, 0, tweak, tweak_len), WALLY_OK)
        key, key_len = make_cbuffer(RECIPIENT['spend_pub_key'])
        fingerprint, fingerprint_len = make_cbuffer('01020304')
        path = (c_uint32 * 2)(352 | 0x80000000, 0)
        self.assertEqual(wally_psbt_add_input_sp_spend_keypath(psbt, 0, key, key_len,
                                                               fingerprint, fingerprint_len,
                                                               path, 2), WALLY_OK)
        data = self.serialize(psbt)
        wally_psbt_free(psbt)

        ret, psbt = self.parse(data)
        self.assertEqual(ret, WALLY_OK)
        out, out_len = make_cbuffer('00' * 32)
        ret, written = wally_psbt_get_input_sp_tweak(psbt, 0, out, out_len)
        self.assertEqual((ret, written), (WALLY_OK, 32))
        self.assertEqual(h(out).decode('utf-8'), TWEAK)

        ret, num_items = wally_psbt_get_input_sp_spend_keypaths_size(psbt, 0)
        self.assertEqual((ret, num_items), (WALLY_OK, 1))
        # The keypath is found by the spend pubkey, and holds fingerprint||path
        ret, found = wally_psbt_find_input_sp_spend_keypath(psbt, 0, key, key_len)
        self.assertEqual((ret, found), (WALLY_OK, 1))
        out, out_len = make_cbuffer('00' * 12)
        ret, written = wally_psbt_get_input_sp_spend_keypath(psbt, 0, 0, out, out_len)
        self.assertEqual((ret, written), (WALLY_OK, 12))
        self.assertEqual(h(out).decode('utf-8'), '01020304' + '60010080' + '00000000')
        self.assertEqual(self.serialize(psbt), data)
        wally_psbt_free(psbt)

    def test_bip376_invalid(self):
        """Test that invalid BIP-376 fields are rejected"""
        psbt = self.build_spend_psbt()
        tweak, tweak_len = make_cbuffer(TWEAK)
        # The tweak is a scalar to add to the spend key: 32 bytes, no more
        for length in [0, 31, 33]:
            self.assertEqual(wally_psbt_set_input_sp_tweak(psbt, 0, tweak, length),
                             WALLY_EINVAL)
        self.assertEqual(wally_psbt_set_input_sp_tweak(psbt, 0, tweak, tweak_len), WALLY_OK)
        # Both fields are v2 only, so a v2 PSBT carrying them cannot downgrade
        self.assertEqual(wally_psbt_set_version(psbt, 0, 0), WALLY_EINVAL)
        data = self.serialize(psbt)
        wally_psbt_free(psbt)

        # A repeated tweak is invalid: the field carries no keydata, so an
        # input can only have one. Duplicate the one the input already has.
        at = data.index(SP_TWEAK_KV)
        self.assertEqual(self.parse(data[:at] + SP_TWEAK_KV + data[at:])[0],
                         WALLY_EINVAL)

        # Splicing either field into a v0 PSBT must fail to parse. The v0
        # PSBT below ends with the (empty) input map and output map, so the
        # field is inserted before the second to last byte.
        psbt = self.build_spend_psbt()
        self.assertEqual(wally_psbt_set_version(psbt, 0, 0), WALLY_OK)
        v0 = self.serialize(psbt)
        wally_psbt_free(psbt)
        self.assertEqual(self.parse(v0)[0], WALLY_OK)
        for kv in [SP_TWEAK_KV, SP_SPEND_KV]:
            self.assertEqual(self.parse(v0[:-2] + kv + v0[-2:])[0], WALLY_EINVAL)

    def build_sp_spend(self, tweak_hex=TWEAK, spend_key=True, anonymous=False):
        """Build a signable BIP-376 spend, and return it with its signing key.

        The wallet holds the spend key b_spend; the input it spends is locked
        by x(d.G), where d = b_spend + tweak, as BIP-352 receiving produces.
        """
        seed, seed_len = make_cbuffer('00' * 32)
        master = ext_key()
        self.assertEqual(bip32_key_from_seed(seed, seed_len, BIP32_VER_MAIN_PRIVATE,
                                             0, byref(master)), WALLY_OK)
        b_spend = bytes(bytearray(master.priv_key)[1:])
        tweak, tweak_len = make_cbuffer(tweak_hex)
        d, d_len = make_cbuffer('00' * 32)
        self.assertEqual(wally_ec_scalar_add(b_spend, 32, tweak, tweak_len,
                                             d, d_len), WALLY_OK)
        output_key, output_key_len = make_cbuffer('00' * 33)
        self.assertEqual(wally_ec_public_key_from_private_key(d, d_len, output_key,
                                                              output_key_len), WALLY_OK)

        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt), WALLY_OK)
        txid, txid_len = make_cbuffer('5b' * 32)
        tx_in = pointer(wally_tx_input())
        self.assertEqual(wally_tx_input_init_alloc(txid, txid_len, 0, 0xffffffff,
                                                   None, 0, None, tx_in), WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in), WALLY_OK)
        spk, spk_len = make_cbuffer('5120' + h(output_key[1:]).decode('utf-8'))
        utxo = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(100000, spk, spk_len, utxo), WALLY_OK)
        self.assertEqual(wally_psbt_set_input_witness_utxo(psbt, 0, utxo), WALLY_OK)
        self.assertEqual(wally_psbt_set_input_sp_tweak(psbt, 0, tweak, tweak_len), WALLY_OK)
        if spend_key:
            key = bytes(bytearray(master.pub_key))
            fingerprint, fingerprint_len = make_cbuffer('00' * 4)
            if not anonymous:
                self.assertEqual(bip32_key_get_fingerprint(byref(master), fingerprint,
                                                           fingerprint_len), WALLY_OK)
            self.assertEqual(wally_psbt_add_input_sp_spend_keypath(psbt, 0, key, 33,
                                                                   fingerprint,
                                                                   fingerprint_len,
                                                                   None, 0), WALLY_OK)

        tx_out = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(90000, spk, spk_len, tx_out), WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out), WALLY_OK)
        return psbt, master, bytes(bytearray(output_key)[1:])

    def test_bip376_signing(self):
        """Test signing a BIP-376 silent payment input"""
        psbt, master, output_key = self.build_sp_spend()

        # The signing key is the spend key plus the tweak, and its x-only
        # public key must be the output key of the input being spent
        d, d_len = make_cbuffer('00' * 32)
        self.assertEqual(wally_psbt_get_input_sp_spend_key(psbt, 0, byref(master),
                                                           d, d_len), WALLY_OK)
        pubkey, pubkey_len = make_cbuffer('00' * 33)
        self.assertEqual(wally_ec_public_key_from_private_key(d, d_len, pubkey,
                                                              pubkey_len), WALLY_OK)
        self.assertEqual(h(pubkey[1:]), h(output_key))

        self.assertEqual(wally_psbt_sign_bip32(psbt, byref(master), 0), WALLY_OK)

        # BIP-376 puts the signature in PSBT_IN_TAP_KEY_SIG, and it verifies
        # against the output key with no further taproot tweaking
        sig, sig_len = make_cbuffer('00' * 64)
        ret, written = wally_psbt_get_input_taproot_signature(psbt, 0, sig, sig_len)
        self.assertEqual((ret, written), (WALLY_OK, 64))
        tx = POINTER(wally_tx)()
        self.assertEqual(wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL,
                                            byref(tx)), WALLY_OK)
        txhash, txhash_len = make_cbuffer('00' * 32)
        self.assertEqual(wally_psbt_get_input_signature_hash(psbt, 0, tx, None, 0, 0,
                                                             txhash, txhash_len), WALLY_OK)
        self.assertEqual(wally_ec_sig_verify(output_key, 32, txhash, txhash_len,
                                             EC_FLAG_SCHNORR, sig, sig_len), WALLY_OK)
        wally_tx_free(tx)
        wally_psbt_free(psbt)

        # BIP-376 lets an Updater withhold the fingerprint and path. Signing
        # the whole PSBT cannot then find the key, but a signer that knows
        # its own spend key still can, since the field is keyed by that key
        psbt, master, output_key = self.build_sp_spend(anonymous=True)
        self.assertEqual(wally_psbt_get_input_sp_spend_key(psbt, 0, byref(master),
                                                           d, d_len), WALLY_OK)
        wally_psbt_free(psbt)

    def test_bip376_signing_invalid(self):
        """Test that a BIP-376 input is not signed without a verified key"""
        # A tweak that does not produce the output key must not be signed
        # with: it would be a valid signature for a key we do not control
        psbt, master, output_key = self.build_sp_spend()
        bad, bad_len = make_cbuffer('88' * 32)
        self.assertEqual(wally_psbt_set_input_sp_tweak(psbt, 0, bad, bad_len), WALLY_OK)
        d, d_len = make_cbuffer('00' * 32)
        self.assertEqual(wally_psbt_get_input_sp_spend_key(psbt, 0, byref(master),
                                                           d, d_len), WALLY_EINVAL)
        self.assertEqual(h(d).decode('utf-8'), '00' * 32)  # Not left in the output
        ret, written = wally_psbt_get_input_taproot_signature_len(psbt, 0)
        self.assertEqual((ret, written), (WALLY_OK, 0))
        wally_psbt_free(psbt)

        # Without a spend keypath there is no key to apply the tweak to
        psbt, master, output_key = self.build_sp_spend(spend_key=False)
        self.assertEqual(wally_psbt_get_input_sp_spend_key(psbt, 0, byref(master),
                                                           d, d_len), WALLY_EINVAL)
        self.assertEqual(wally_psbt_sign_bip32(psbt, byref(master), 0), WALLY_OK)
        ret, written = wally_psbt_get_input_taproot_signature_len(psbt, 0)
        self.assertEqual((ret, written), (WALLY_OK, 0))
        wally_psbt_free(psbt)

    def test_resolve_entropy(self):
        """Test that the entropy changes the proof, but not the payment"""
        case = BIP352_JSON[0]['sending'][0]['given']
        keys, keys_len = make_cbuffer(''.join(v['private_key'] for v in case['vin']))
        proofs, scripts = [], []

        for entropy_hex in [ENTROPY, '11' * 32]:
            psbt = self.build_psbt(case['vin'], case['recipients'])
            entropy, entropy_len = make_cbuffer(entropy_hex)
            self.assertEqual(wally_psbt_sp_resolve(psbt, keys, keys_len,
                                                   entropy, entropy_len, 0), WALLY_OK)
            scripts.append(self.output_scripts(psbt, len(case['recipients'])))
            item = psbt.contents.global_sp_dleq_proofs.items[0]
            proofs.append(h(string_at(item.value, item.value_len)))
            wally_psbt_free(psbt)

        self.assertEqual(scripts[0], scripts[1])
        self.assertNotEqual(proofs[0], proofs[1])

    def contribute(self, psbt, indices, keys_hex, entropy_hex=ENTROPY):
        """Contribute per-input shares for `indices`, as one of several senders."""
        idx = (c_uint32 * len(indices))(*indices)
        keys, keys_len = make_cbuffer(keys_hex)
        entropy, entropy_len = make_cbuffer(entropy_hex)
        return wally_psbt_sp_contribute(psbt, idx, len(indices), keys, keys_len,
                                        entropy, entropy_len, 0)

    def two_signer_cases(self):
        """The BIP-352 sending vectors with exactly two eligible inputs."""
        for case in BIP352_JSON:
            for sending in case['sending']:
                given, expected = sending['given'], sending['expected']
                if len(given['vin']) != 2 or not expected['input_pub_keys'] or \
                   'input_private_key_sum' not in expected:
                    continue
                psbt = self.build_psbt(given['vin'], given['recipients'])
                keys = [self.eligible_keys(psbt, given['vin'][:1]),
                        self.eligible_keys(psbt, given['vin'][1:])]
                wally_psbt_free(psbt)
                # Both inputs must be eligible for there to be two signers
                if all(len(k) == 64 for k in keys):
                    yield case['comment'], given, keys

    def test_contribute_round_trip(self):
        """Test that two signers contributing shares reach the same outputs"""
        entropy, entropy_len = make_cbuffer(ENTROPY)
        tested = 0

        for comment, given, keys in self.two_signer_cases():
            num_outputs = len(given['recipients'])

            # What one signer holding both inputs would produce, via a global share
            expected = self.build_psbt(given['vin'], given['recipients'])
            both, both_len = make_cbuffer(keys[0] + keys[1])
            self.assertEqual(wally_psbt_sp_resolve(expected, both, both_len,
                                                   entropy, entropy_len, 0), WALLY_OK)
            expected_scripts = self.output_scripts(expected, num_outputs)
            wally_psbt_free(expected)

            # The first signer contributes for its input alone. That resolves
            # nothing: the outputs are unknown until the second signer adds its
            # share, which is what stops either of them signing early.
            psbt = self.build_psbt(given['vin'], given['recipients'])
            self.assertEqual(self.contribute(psbt, [0], keys[0]), WALLY_OK, comment)
            self.assertEqual(wally_psbt_get_sp_status(psbt, 0),
                             (WALLY_OK, WALLY_SP_INCOMPLETE), comment)
            for i in range(num_outputs):
                self.assertEqual(wally_psbt_get_output_script_len(psbt, i),
                                 (WALLY_OK, 0), comment)
            self.assertEqual(wally_psbt_sp_resolve_shares(psbt, 0), WALLY_EINVAL, comment)

            # The second signer completes the coverage, and can now resolve
            self.assertEqual(self.contribute(psbt, [1], keys[1], '11' * 32), WALLY_OK, comment)
            self.assertEqual(wally_psbt_get_sp_status(psbt, 0),
                             (WALLY_OK, WALLY_SP_INCOMPLETE), comment)
            self.assertEqual(wally_psbt_sp_resolve_shares(psbt, 0), WALLY_OK, comment)
            self.assertEqual(wally_psbt_get_sp_status(psbt, 0),
                             (WALLY_OK, WALLY_SP_COMPLETE), comment)
            self.assertEqual(self.output_scripts(psbt, num_outputs),
                             expected_scripts, comment)
            wally_psbt_free(psbt)
            tested += 1

        self.assertGreater(tested, 10)

    def test_contribute_both_inputs(self):
        """Test that per-input shares from one signer resolve as a global would"""
        entropy, entropy_len = make_cbuffer(ENTROPY)

        for comment, given, keys in self.two_signer_cases():
            num_outputs = len(given['recipients'])
            expected = self.build_psbt(given['vin'], given['recipients'])
            both, both_len = make_cbuffer(keys[0] + keys[1])
            self.assertEqual(wally_psbt_sp_resolve(expected, both, both_len,
                                                   entropy, entropy_len, 0), WALLY_OK)
            expected_scripts = self.output_scripts(expected, num_outputs)
            wally_psbt_free(expected)

            psbt = self.build_psbt(given['vin'], given['recipients'])
            self.assertEqual(self.contribute(psbt, [0, 1], keys[0] + keys[1]),
                             WALLY_OK, comment)
            self.assertEqual(wally_psbt_sp_resolve_shares(psbt, 0), WALLY_OK, comment)
            self.assertEqual(self.output_scripts(psbt, num_outputs),
                             expected_scripts, comment)
            wally_psbt_free(psbt)

    def test_contribute_wrong_key(self):
        """Test that a key must match the input it is contributed for"""
        comment, given, keys = next(iter(self.two_signer_cases()))

        # Swapping the keys proves each share against the wrong input, which
        # would leave the payment unresolvable for every other signer
        psbt = self.build_psbt(given['vin'], given['recipients'])
        self.assertEqual(self.contribute(psbt, [0], keys[1]), WALLY_EINVAL, comment)
        self.assertEqual(self.contribute(psbt, [0, 1], keys[1] + keys[0]),
                         WALLY_EINVAL, comment)
        # The failures are transactional: nothing was stored
        self.assertEqual(psbt.contents.inputs[0].sp_ecdh_shares.num_items, 0)
        self.assertEqual(psbt.contents.inputs[0].sp_dleq_proofs.num_items, 0)
        self.assertEqual(wally_psbt_get_sp_status(psbt, 0),
                         (WALLY_OK, WALLY_SP_INCOMPLETE))
        wally_psbt_free(psbt)

    def test_contribute_alongside_global(self):
        """Test that a global share stands whatever per-input shares accompany it"""
        comment, given, keys = next(iter(self.two_signer_cases()))
        entropy, entropy_len = make_cbuffer(ENTROPY)
        num_outputs = len(given['recipients'])

        psbt = self.build_psbt(given['vin'], given['recipients'])
        both, both_len = make_cbuffer(keys[0] + keys[1])
        self.assertEqual(wally_psbt_sp_resolve(psbt, both, both_len,
                                               entropy, entropy_len, 0), WALLY_OK)
        expected_scripts = self.output_scripts(psbt, num_outputs)

        # A global share already covers every input, so a per-input share added
        # afterwards is redundant - but it must still verify, and must not
        # change the outputs the global share already determined.
        self.assertEqual(self.contribute(psbt, [0], keys[0]), WALLY_OK, comment)
        self.assertEqual(wally_psbt_get_sp_status(psbt, 0),
                         (WALLY_OK, WALLY_SP_COMPLETE), comment)
        self.assertEqual(self.output_scripts(psbt, num_outputs), expected_scripts)
        wally_psbt_free(psbt)

    def test_contribute_invalid(self):
        """Test the invalid arguments of wally_psbt_sp_contribute"""
        comment, given, keys = next(iter(self.two_signer_cases()))
        psbt = self.build_psbt(given['vin'], given['recipients'])
        idx = (c_uint32 * 2)(0, 1)
        both, both_len = make_cbuffer(keys[0] + keys[1])
        entropy, entropy_len = make_cbuffer(ENTROPY)
        args = [psbt, idx, 2, both, both_len, entropy, entropy_len, 0]

        for i, invalid in [(0, None),           # NULL psbt
                           (1, None),           # NULL indices
                           (2, 0),              # No indices
                           (3, None),           # NULL keys
                           (4, both_len - 1),   # Wrong key length for the indices
                           (4, both_len + 32),
                           (5, None),           # NULL entropy
                           (6, entropy_len - 1),# Wrong entropy length
                           (7, 1)]:             # Unsupported flags
            invalid_args = args[:i] + [invalid] + args[i + 1:]
            self.assertEqual(wally_psbt_sp_contribute(*invalid_args), WALLY_EINVAL)

        # Out of range, descending and duplicate indices
        for indices in [(0, 2), (1, 0), (0, 0)]:
            bad = (c_uint32 * 2)(*indices)
            self.assertEqual(wally_psbt_sp_contribute(psbt, bad, 2, both, both_len,
                                                      entropy, entropy_len, 0),
                             WALLY_EINVAL, comment)

        # Nothing above stored anything, so the PSBT is still untouched
        self.assertEqual(wally_psbt_get_sp_status(psbt, 0),
                         (WALLY_OK, WALLY_SP_INCOMPLETE))
        self.assertEqual(wally_psbt_sp_resolve_shares(psbt, 0), WALLY_EINVAL)
        for i in [None, psbt]:
            self.assertEqual(wally_psbt_sp_resolve_shares(i, 1), WALLY_EINVAL)
        wally_psbt_free(psbt)

    def test_contribute_ineligible_input(self):
        """Test that shares cannot be contributed for an ineligible input"""
        # A P2PK input cannot contribute to a silent payment
        p2pk = '21' + '02' + '11' * 32 + 'ac'
        psbt = self.make_psbt(['0014' + '11' * 20, p2pk])
        self.assertEqual(self.contribute(psbt, [1], '11' * 32), WALLY_EINVAL)
        wally_psbt_free(psbt)


# Two valid compressed public keys, to stand in for a scan key and the
# participant keys of an aggregate input
SCAN_KEY = RECIPIENT['scan_pub_key']
PARTICIPANT_A = RECIPIENT['spend_pub_key']
PARTICIPANT_B = '02' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'


class PartialSharesTests(unittest.TestCase):
    """The per-participant share and proof fields of a aggregate input.

    Where BIP375's fields carry one share per eligible input, these carry one
    share per party contributing to a single aggregate input key, and so are
    keyed by the contributing party as well as the recipient.
    """

    def make_psbt(self):
        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt), WALLY_OK)
        txid, txid_len = make_cbuffer('11' * 32)
        tx_in = pointer(wally_tx_input())
        self.assertEqual(wally_tx_input_init_alloc(txid, txid_len, 0, 0xffffffff,
                                                   None, 0, None, tx_in), WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in), WALLY_OK)
        tx_out = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(90000, None, 0, tx_out), WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out), WALLY_OK)
        info, info_len = make_cbuffer(RECIPIENT['scan_pub_key'] +
                                      RECIPIENT['spend_pub_key'])
        self.assertEqual(wally_psbt_set_output_sp_v0_info(psbt, 0, info, info_len),
                         WALLY_OK)
        return psbt

    def set_share(self, psbt, scan_hex, participant_hex, share_hex):
        scan, scan_len = make_cbuffer(scan_hex)
        party, party_len = make_cbuffer(participant_hex)
        share, share_len = make_cbuffer(share_hex)
        return wally_psbt_input_set_sp_partial_ecdh_share(
            psbt.contents.inputs, scan, scan_len, party, party_len,
            share, share_len)

    def set_proof(self, psbt, scan_hex, participant_hex, proof_hex):
        scan, scan_len = make_cbuffer(scan_hex)
        party, party_len = make_cbuffer(participant_hex)
        proof, proof_len = make_cbuffer(proof_hex)
        return wally_psbt_input_set_sp_partial_dleq_proof(
            psbt.contents.inputs, scan, scan_len, party, party_len,
            proof, proof_len)

    def find_share(self, psbt, scan_hex, participant_hex):
        scan, scan_len = make_cbuffer(scan_hex)
        party, party_len = make_cbuffer(participant_hex)
        return wally_psbt_input_find_sp_partial_ecdh_share(
            psbt.contents.inputs, scan, scan_len, party, party_len)

    def test_set_and_find(self):
        """Test that shares are distinguished by their contributing party"""
        psbt = self.make_psbt()
        self.assertEqual(self.set_share(psbt, SCAN_KEY, PARTICIPANT_A,
                                        PARTICIPANT_A), WALLY_OK)
        self.assertEqual(self.set_share(psbt, SCAN_KEY, PARTICIPANT_B,
                                        PARTICIPANT_B), WALLY_OK)
        self.assertEqual(psbt.contents.inputs[0].sp_partial_ecdh_shares.num_items, 2)

        # Both parties' shares are retrievable under the same scan key
        self.assertEqual(self.find_share(psbt, SCAN_KEY, PARTICIPANT_A), (WALLY_OK, 1))
        self.assertEqual(self.find_share(psbt, SCAN_KEY, PARTICIPANT_B), (WALLY_OK, 2))
        # A party that has not contributed is absent, not an error
        self.assertEqual(self.find_share(psbt, PARTICIPANT_B, PARTICIPANT_A),
                         (WALLY_OK, 0))

        # Replacing a party's share leaves the other party's alone
        self.assertEqual(self.set_share(psbt, SCAN_KEY, PARTICIPANT_A,
                                        PARTICIPANT_B), WALLY_OK)
        self.assertEqual(psbt.contents.inputs[0].sp_partial_ecdh_shares.num_items, 2)
        wally_psbt_free(psbt)

    def test_invalid_args(self):
        """Test that malformed keys, shares and proofs are rejected"""
        psbt = self.make_psbt()
        short_key, odd_key = '02' + '11' * 31, '05' + '11' * 32
        for scan, party in [(short_key, PARTICIPANT_A), (SCAN_KEY, short_key),
                            (odd_key, PARTICIPANT_A), (SCAN_KEY, odd_key)]:
            self.assertEqual(self.set_share(psbt, scan, party, PARTICIPANT_A),
                             WALLY_EINVAL)
            self.assertEqual(self.set_proof(psbt, scan, party, '00' * 64),
                             WALLY_EINVAL)

        # A share must be a valid compressed point, a proof exactly 64 bytes
        for bad_share in [short_key, odd_key, '02' + '11' * 33]:
            self.assertEqual(self.set_share(psbt, SCAN_KEY, PARTICIPANT_A, bad_share),
                             WALLY_EINVAL)
        for bad_proof in ['00' * 63, '00' * 65]:
            self.assertEqual(self.set_proof(psbt, SCAN_KEY, PARTICIPANT_A, bad_proof),
                             WALLY_EINVAL)

        # Nothing above was stored
        self.assertEqual(psbt.contents.inputs[0].sp_partial_ecdh_shares.num_items, 0)
        self.assertEqual(psbt.contents.inputs[0].sp_partial_dleq_proofs.num_items, 0)
        wally_psbt_free(psbt)

    def serialized(self, psbt):
        ret, length = wally_psbt_get_length(psbt, 0)
        self.assertEqual(ret, WALLY_OK)
        buf, buf_len = make_cbuffer('00' * length)
        ret, written = wally_psbt_to_bytes(psbt, 0, buf, buf_len)
        self.assertEqual((ret, written), (WALLY_OK, length))
        return bytes(bytearray(buf)[:written])

    def test_serialization(self):
        """Test that the fields survive a serialization round trip unchanged"""
        psbt = self.make_psbt()
        self.assertEqual(self.set_share(psbt, SCAN_KEY, PARTICIPANT_A,
                                        PARTICIPANT_B), WALLY_OK)
        self.assertEqual(self.set_proof(psbt, SCAN_KEY, PARTICIPANT_A,
                                        '5a' * 64), WALLY_OK)
        original = self.serialized(psbt)

        parsed = pointer(wally_psbt())
        self.assertEqual(wally_psbt_from_bytes(original, len(original), 0, parsed),
                         WALLY_OK)
        self.assertEqual(parsed.contents.inputs[0].sp_partial_ecdh_shares.num_items, 1)
        self.assertEqual(parsed.contents.inputs[0].sp_partial_dleq_proofs.num_items, 1)
        self.assertEqual(self.find_share(parsed, SCAN_KEY, PARTICIPANT_A), (WALLY_OK, 1))
        self.assertEqual(self.serialized(parsed), original)

        # Combining is per-party, so a second signer's share merges in
        self.assertEqual(self.set_share(psbt, SCAN_KEY, PARTICIPANT_B,
                                        PARTICIPANT_A), WALLY_OK)
        self.assertEqual(wally_psbt_combine(parsed, psbt), WALLY_OK)
        self.assertEqual(parsed.contents.inputs[0].sp_partial_ecdh_shares.num_items, 2)
        wally_psbt_free(parsed)
        wally_psbt_free(psbt)

    def test_v0_disallowed(self):
        """Test that the fields cannot appear in a v0 PSBT"""
        psbt = self.make_psbt()
        self.assertEqual(self.set_share(psbt, SCAN_KEY, PARTICIPANT_A,
                                        PARTICIPANT_B), WALLY_OK)
        self.assertEqual(self.set_proof(psbt, SCAN_KEY, PARTICIPANT_A,
                                        '5a' * 64), WALLY_OK)
        # Downgrading to v0 would drop the fields silently, so it is refused
        self.assertEqual(wally_psbt_set_version(psbt, 0, 0), WALLY_EINVAL)

        wally_psbt_free(psbt)

        # And a serialized v0 PSBT carrying one is rejected on parse. wally
        # will not produce such a PSBT, so splice the field into the input map
        # of an otherwise valid v0 serialization by hand.
        v0 = self.v0_psbt_bytes()
        parsed = pointer(wally_psbt())
        self.assertEqual(wally_psbt_from_bytes(v0, len(v0), 0, parsed), WALLY_OK)
        wally_psbt_free(parsed)

        # The trailing bytes are the global, input and output map separators
        self.assertEqual(v0[-3:], bytes(3))
        keydata = bytes([0x21]) + bytes.fromhex(SCAN_KEY + PARTICIPANT_A)
        value = bytes.fromhex(PARTICIPANT_B)
        field = bytes([len(keydata)]) + keydata + bytes([len(value)]) + value
        spliced = v0[:-2] + field + v0[-2:]
        parsed = pointer(wally_psbt())
        self.assertEqual(wally_psbt_from_bytes(spliced, len(spliced), 0, parsed),
                         WALLY_EINVAL)

        # A field that v0 does allow, spliced at the same offset, parses. So
        # the failure above is the version rule, not a bad splice or keydata.
        keydata = bytes([0x06]) + bytes.fromhex(PARTICIPANT_A)  # BIP32_DERIVATION
        value = bytes.fromhex('00000000')  # Fingerprint, empty path
        legal = bytes([len(keydata)]) + keydata + bytes([len(value)]) + value
        spliced = v0[:-2] + legal + v0[-2:]
        parsed = pointer(wally_psbt())
        self.assertEqual(wally_psbt_from_bytes(spliced, len(spliced), 0, parsed),
                         WALLY_OK)
        self.assertEqual(parsed.contents.inputs[0].keypaths.num_items, 1)
        wally_psbt_free(parsed)

    def v0_psbt_bytes(self):
        """A minimal serialized PSBT with one empty input and output map."""
        tx = pointer(wally_tx())
        self.assertEqual(wally_tx_init_alloc(2, 0, 1, 1, tx), WALLY_OK)
        txid, txid_len = make_cbuffer('11' * 32)
        tx_in = pointer(wally_tx_input())
        self.assertEqual(wally_tx_input_init_alloc(txid, txid_len, 0, 0xffffffff,
                                                   None, 0, None, tx_in), WALLY_OK)
        self.assertEqual(wally_tx_add_input(tx, tx_in), WALLY_OK)
        spk, spk_len = make_cbuffer('0014' + '22' * 20)
        tx_out = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(1000, spk, spk_len, tx_out), WALLY_OK)
        self.assertEqual(wally_tx_add_output(tx, tx_out), WALLY_OK)

        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_init_alloc(0, 1, 1, 0, 0, psbt), WALLY_OK)
        self.assertEqual(wally_psbt_set_global_tx(psbt, tx), WALLY_OK)
        serialized = self.serialized(psbt)
        wally_psbt_free(psbt)
        wally_tx_free(tx)
        return serialized


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MUSIG_SKS = ['11' * 32, '22' * 32, '33' * 32]
MUSIG_PATH = (0, 7)


def tagged_hash(tag, data):
    import hashlib
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def pubkey_of(sk_hex):
    sk, sk_len = make_cbuffer(sk_hex)
    out, out_len = make_cbuffer('00' * 33)
    assert wally_ec_public_key_from_private_key(sk, sk_len, out, out_len) == WALLY_OK
    return bytes(bytearray(out))


def musig_aggregate_secret(sks, path):
    """The taproot output secret a_Q of tr(musig(sks)/path), and its output key.

    Computed here independently of the C implementation, so that the shares it
    combines can be checked against what a single party holding a_Q derives.
    """
    import hashlib, hmac
    sorted_pks = sorted(pubkey_of(sk) for sk in sks)
    blob = b''.join(sorted_pks)
    pks_hash = tagged_hash('KeyAgg list', blob)
    second = next((pk for pk in sorted_pks[1:] if pk != sorted_pks[0]), None)

    def coef(pk):
        if second is not None and pk == second:
            return 1
        return int.from_bytes(tagged_hash('KeyAgg coefficient', pks_hash + pk), 'big')

    d0 = sum(coef(pubkey_of(sk)) * int(sk, 16) for sk in sks) % SECP256K1_N

    keys, keys_len = make_cbuffer(blob.hex())
    cache = c_void_p()
    assert wally_musig_pubkey_agg(keys, keys_len, None, 0, cache) == WALLY_OK
    agg, agg_len = make_cbuffer('00' * 33)
    assert wally_musig_pubkey_get(cache, agg, agg_len) == WALLY_OK
    aggb, aggb_len = make_cbuffer(bytes(bytearray(agg)).hex())
    xpub = POINTER(ext_key)()
    assert wally_musig_pubkey_to_xpub(aggb, aggb_len, 0x0488B21E, xpub) == WALLY_OK

    tacc = 0
    for index in path:
        chain_code = bytes(bytearray(xpub.contents.chain_code))
        parent = bytes(bytearray(xpub.contents.pub_key))
        il = hmac.new(chain_code, parent + index.to_bytes(4, 'big'),
                      hashlib.sha512).digest()[:32]
        tacc = (tacc + int.from_bytes(il, 'big')) % SECP256K1_N
        child = POINTER(ext_key)()
        assert bip32_key_from_parent_alloc(xpub, index, 0x1, child) == WALLY_OK
        xpub = child

    internal = bytes(bytearray(xpub.contents.pub_key))
    gacc = 1
    if internal[0] == 0x03:  # An x-only tweak negates an odd-Y key
        gacc, tacc = -1, (-tacc) % SECP256K1_N
    tacc = (tacc + int.from_bytes(tagged_hash('TapTweak', internal[1:]), 'big')) % SECP256K1_N

    d = (gacc * d0 + tacc) % SECP256K1_N
    output_key = pubkey_of('%064x' % d)
    if output_key[0] == 0x03:  # BIP-352 uses the even-Y output key
        d = (-d) % SECP256K1_N
        output_key = pubkey_of('%064x' % d)
    return '%064x' % d, output_key[1:]


class MusigPartialSharesTests(unittest.TestCase):
    """Combining partial shares from an aggregate input's participants.

    The claim under test is BIP-352's algebraic equivalence: an input spent
    with an aggregate key must derive exactly the outputs that a single party
    holding the aggregate secret would, even though no party ever holds it.
    """

    def setUp(self):
        self.agg_secret, self.output_key = musig_aggregate_secret(MUSIG_SKS, MUSIG_PATH)
        self.pub_keys = b''.join(sorted(pubkey_of(sk) for sk in MUSIG_SKS))

    def build_psbt(self):
        """A PSBT spending one P2TR input of the aggregate to one recipient."""
        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt), WALLY_OK)
        txid, txid_len = make_cbuffer('ab' * 32)
        tx_in = pointer(wally_tx_input())
        self.assertEqual(wally_tx_input_init_alloc(txid, txid_len, 0, 0xffffffff,
                                                   None, 0, None, tx_in), WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in), WALLY_OK)
        spk, spk_len = make_cbuffer('5120' + self.output_key.hex())
        utxo = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(100000, spk, spk_len, utxo), WALLY_OK)
        self.assertEqual(wally_psbt_set_input_witness_utxo(psbt, 0, utxo), WALLY_OK)
        self.assertEqual(wally_psbt_set_input_amount(psbt, 0, 100000), WALLY_OK)

        tx_out = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(90000, None, 0, tx_out), WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out), WALLY_OK)
        self.assertEqual(wally_psbt_set_output_amount(psbt, 0, 90000), WALLY_OK)
        info, info_len = make_cbuffer(RECIPIENT['scan_pub_key'] +
                                      RECIPIENT['spend_pub_key'])
        self.assertEqual(wally_psbt_set_output_sp_v0_info(psbt, 0, info, info_len),
                         WALLY_OK)
        return psbt

    def musig_inputs(self, pub_keys=None):
        keys = pub_keys if pub_keys is not None else self.pub_keys
        self.keys_buf, keys_len = make_cbuffer(keys.hex())
        self.path_buf = (c_uint32 * len(MUSIG_PATH))(*MUSIG_PATH)
        musig = wally_sp_musig_input()
        musig.index = 0
        musig.pub_keys = cast(self.keys_buf, c_void_p)
        musig.pub_keys_len = keys_len
        musig.path = cast(self.path_buf, c_void_p)
        musig.path_len = len(MUSIG_PATH)
        return pointer(musig)

    def contribute(self, psbt, sk_hex, musig=None):
        keys, keys_len = make_cbuffer(sk_hex)
        entropy, entropy_len = make_cbuffer(ENTROPY)
        return wally_psbt_sp_musig_contribute(psbt, musig or self.musig_inputs(), 1,
                                              keys, keys_len, entropy, entropy_len, 0)

    def output_script(self, psbt):
        ret, length = wally_psbt_get_output_script_len(psbt, 0)
        self.assertEqual(ret, WALLY_OK)
        buf, buf_len = make_cbuffer('00' * length)
        ret, written = wally_psbt_get_output_script(psbt, 0, buf, buf_len)
        self.assertEqual(ret, WALLY_OK)
        return bytes(bytearray(buf)[:written])

    def single_party_script(self):
        """What one party holding the whole aggregate secret would derive."""
        psbt = self.build_psbt()
        key, key_len = make_cbuffer(self.agg_secret)
        entropy, entropy_len = make_cbuffer(ENTROPY)
        self.assertEqual(wally_psbt_sp_resolve(psbt, key, key_len,
                                               entropy, entropy_len, 0), WALLY_OK)
        script = self.output_script(psbt)
        wally_psbt_free(psbt)
        return script

    def test_equivalence(self):
        """Test that combined partial shares derive the single-party output"""
        psbt = self.build_psbt()
        musig = self.musig_inputs()

        # Each party contributes in turn. Until the last has, the outputs
        # cannot be derived and there is nothing valid to sign.
        for i, sk in enumerate(MUSIG_SKS):
            self.assertEqual(wally_psbt_get_sp_musig_status(psbt, musig, 1, 0),
                             (WALLY_OK, WALLY_SP_INCOMPLETE), 'before party %d' % i)
            self.assertEqual(wally_psbt_sp_musig_resolve_shares(psbt, musig, 1, 0),
                             WALLY_EINVAL, 'before party %d' % i)
            self.assertEqual(self.contribute(psbt, sk, musig), WALLY_OK, sk)

        self.assertEqual(psbt.contents.inputs[0].sp_partial_ecdh_shares.num_items, 3)
        self.assertEqual(psbt.contents.inputs[0].sp_partial_dleq_proofs.num_items, 3)

        # With every share present the outputs derive, and they are exactly
        # those of the equivalent single-party spend
        self.assertEqual(wally_psbt_sp_musig_resolve_shares(psbt, musig, 1, 0), WALLY_OK)
        self.assertEqual(self.output_script(psbt).hex(),
                         self.single_party_script().hex())
        self.assertEqual(wally_psbt_get_sp_musig_status(psbt, musig, 1, 0),
                         (WALLY_OK, WALLY_SP_COMPLETE))
        wally_psbt_free(psbt)

    def test_contribute_wrong_key(self):
        """Test that a key outside the aggregate cannot contribute"""
        psbt = self.build_psbt()
        self.assertEqual(self.contribute(psbt, '44' * 32), WALLY_EINVAL)
        # The failure is transactional: nothing was stored
        self.assertEqual(psbt.contents.inputs[0].sp_partial_ecdh_shares.num_items, 0)
        wally_psbt_free(psbt)

    def test_wrong_participants(self):
        """Test that the participants must aggregate to the input's own key"""
        psbt = self.build_psbt()
        musig = self.musig_inputs()
        for sk in MUSIG_SKS:
            self.assertEqual(self.contribute(psbt, sk, musig), WALLY_OK)

        # Claiming a different participant set describes an aggregate that is
        # not the key this input is spent with, so nothing may be derived
        others = b''.join(sorted(pubkey_of(sk) for sk in ['11' * 32, '22' * 32,
                                                          '44' * 32]))
        wrong = self.musig_inputs(others)
        self.assertEqual(wally_psbt_get_sp_musig_status(psbt, wrong, 1, 0),
                         (WALLY_OK, WALLY_SP_INVALID))
        self.assertEqual(wally_psbt_sp_musig_resolve_shares(psbt, wrong, 1, 0),
                         WALLY_EINVAL)
        wally_psbt_free(psbt)

    def test_tampered_share(self):
        """Test that a share which fails its proof is rejected"""
        psbt = self.build_psbt()
        musig = self.musig_inputs()
        for sk in MUSIG_SKS:
            self.assertEqual(self.contribute(psbt, sk, musig), WALLY_OK)

        # Replace one party's share with another valid point. Its DLEQ proof
        # no longer holds, which is what stops a party redirecting the payment.
        item = psbt.contents.inputs[0].sp_partial_ecdh_shares.items[0]
        scan_key, scan_len = make_cbuffer(RECIPIENT['scan_pub_key'])
        participant = bytes(bytearray(cast(item.key, POINTER(c_ubyte * 66)).contents))[33:]
        party, party_len = make_cbuffer(participant.hex())
        other, other_len = make_cbuffer(pubkey_of('55' * 32).hex())
        self.assertEqual(wally_psbt_input_set_sp_partial_ecdh_share(
            psbt.contents.inputs, scan_key, scan_len, party, party_len,
            other, other_len), WALLY_OK)

        self.assertEqual(wally_psbt_get_sp_musig_status(psbt, musig, 1, 0),
                         (WALLY_OK, WALLY_SP_INVALID))
        self.assertEqual(wally_psbt_sp_musig_resolve_shares(psbt, musig, 1, 0),
                         WALLY_EINVAL)
        wally_psbt_free(psbt)

    def test_invalid_args(self):
        """Test that malformed aggregate descriptions are rejected"""
        psbt = self.build_psbt()
        musig = self.musig_inputs()
        keys, keys_len = make_cbuffer(MUSIG_SKS[0])
        entropy, entropy_len = make_cbuffer(ENTROPY)

        # A NULL/count mismatch, a bad flag, and an out of range input index
        for args in [(psbt, None, 1, 0), (psbt, musig, 0, 0), (psbt, musig, 1, 1),
                     (None, musig, 1, 0)]:
            self.assertEqual(wally_psbt_sp_musig_resolve_shares(*args), WALLY_EINVAL)

        musig.contents.index = 1
        self.assertEqual(wally_psbt_sp_musig_resolve_shares(psbt, musig, 1, 0),
                         WALLY_EINVAL)
        musig.contents.index = 0

        # An aggregate needs at least two participants
        musig.contents.pub_keys_len = 33
        self.assertEqual(wally_psbt_sp_musig_resolve_shares(psbt, musig, 1, 0),
                         WALLY_EINVAL)
        musig.contents.pub_keys_len = len(self.pub_keys)

        for bad_len in [0, 31, 33]:
            self.assertEqual(wally_psbt_sp_musig_contribute(psbt, musig, 1, keys,
                                                            bad_len, entropy,
                                                            entropy_len, 0),
                             WALLY_EINVAL)
        wally_psbt_free(psbt)


if __name__ == '__main__':
    unittest.main()
