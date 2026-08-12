import json
import unittest
from util import *

# BIP-352 test vectors, copied verbatim from the reference implementation's
# bip352_send_and_receive_test_vectors.json.
with open(root_dir + 'src/data/bip352_test_vectors.json', 'r') as f:
    BIP352_JSON = json.load(f)

# A valid recipient, for the tests that do not need a whole vector case
RECIPIENT = BIP352_JSON[0]['sending'][0]['given']['recipients'][0]

ENTROPY = '00' * 32
NUMS = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
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


if __name__ == '__main__':
    unittest.main()
