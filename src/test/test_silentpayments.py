import unittest
from util import *

# The BIP-352 test vector "Outputs with the same script pubkey": two P2WPKH
# inputs paying one recipient
VECTOR_PRIVKEYS = ['eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1',
                   '93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16']
VECTOR_INFO = ('0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4'
               '025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36')
# The vector's outpoints, whose smallest is committed to by the input hash
VECTOR_OUTPOINTS = [('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16', 0),
                    ('a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d', 0)]
VECTOR_OUTPUT = '3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1'

ENTROPY = '00' * 32
NUMS = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'


@unittest.skipUnless(wally_psbt_sp_resolve, 'Silent payments module not enabled')
class SilentPaymentsTests(unittest.TestCase):

    def make_psbt(self, scripts, sp_info=VECTOR_INFO, outpoints=VECTOR_OUTPOINTS):
        """Build a PSBTv2 spending `scripts` to one silent payment output"""
        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_init_alloc(2, len(scripts), 1, 0, 0, psbt), WALLY_OK)
        for i, script_hex in enumerate(scripts):
            txid, vout = outpoints[i]
            txid_bytes, txid_len = make_cbuffer(txid)
            txid_bytes = bytes(bytearray(txid_bytes)[::-1])  # txids are displayed reversed
            tx_in = pointer(wally_tx_input())
            self.assertEqual(wally_tx_input_init_alloc(txid_bytes, txid_len, vout, 0xffffffff,
                                                       None, 0, None, tx_in), WALLY_OK)
            self.assertEqual(wally_psbt_add_tx_input_at(psbt, i, 0, tx_in), WALLY_OK)

            script, script_len = make_cbuffer(script_hex)
            utxo = pointer(wally_tx_output())
            self.assertEqual(wally_tx_output_init_alloc(100000, script, script_len, utxo), WALLY_OK)
            self.assertEqual(wally_psbt_set_input_witness_utxo(psbt, i, utxo), WALLY_OK)
            self.assertEqual(wally_psbt_set_input_amount(psbt, i, 100000), WALLY_OK)

        tx_out = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(90000, None, 0, tx_out), WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out), WALLY_OK)
        self.assertEqual(wally_psbt_set_output_amount(psbt, 0, 90000), WALLY_OK)
        info, info_len = make_cbuffer(sp_info)
        self.assertEqual(wally_psbt_set_output_sp_v0_info(psbt, 0, info, info_len), WALLY_OK)
        return psbt

    def vector_scripts(self):
        """The P2WPKH scriptPubKeys of the reference vector's inputs"""
        scripts = []
        for priv_hex in VECTOR_PRIVKEYS:
            priv, priv_len = make_cbuffer(priv_hex)
            pub, pub_len = make_cbuffer('00' * 33)
            self.assertEqual(wally_ec_public_key_from_private_key(priv, priv_len,
                                                                  pub, pub_len), WALLY_OK)
            hash160, hash160_len = make_cbuffer('00' * 20)
            self.assertEqual(wally_hash160(pub, pub_len, hash160, hash160_len), WALLY_OK)
            scripts.append('0014' + h(hash160).decode('utf-8'))
        return scripts

    def test_smallest_outpoint(self):
        """Test the BIP-352 smallest outpoint, which is ordered by vout LE"""
        psbt = self.make_psbt(self.vector_scripts())
        out, out_len = make_cbuffer('00' * 36)
        self.assertEqual(wally_psbt_get_sp_smallest_outpoint(psbt, out, out_len), WALLY_OK)
        # The vector's smallest outpoint, txid in internal (reversed) order
        expected = '169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f400000000'
        self.assertEqual(h(out).decode('utf-8'), expected)

        for args in [(None, out, out_len), (psbt, None, out_len), (psbt, out, out_len - 1)]:
            self.assertEqual(wally_psbt_get_sp_smallest_outpoint(*args), WALLY_EINVAL)
        wally_psbt_free(psbt)

    def test_input_eligible(self):
        """Test which inputs can contribute to a silent payment"""
        # P2WPKH and P2PKH are eligible, P2WSH and bare multisig are not
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
                self.assertEqual(wally_psbt_set_input_taproot_internal_key(psbt, 0, key,
                                                                          key_len), WALLY_OK)
            self.assertEqual(wally_psbt_get_input_sp_eligible(psbt, 0), (WALLY_OK, eligible))
            wally_psbt_free(psbt)

        # An unknown witness version must be refused, not called ineligible
        psbt = self.make_psbt(['5220' + '11' * 32])
        self.assertEqual(wally_psbt_get_input_sp_eligible(psbt, 0), (WALLY_ERROR, 0))
        wally_psbt_free(psbt)

        psbt = self.make_psbt(['0014' + '11' * 20])
        self.assertEqual(wally_psbt_get_input_sp_eligible(psbt, 1), (WALLY_EINVAL, 0))
        wally_psbt_free(psbt)

    def test_resolve(self):
        """Test resolving a silent payment against the BIP-352 vector"""
        psbt = self.make_psbt(self.vector_scripts())
        keys, keys_len = make_cbuffer(''.join(VECTOR_PRIVKEYS))
        entropy, entropy_len = make_cbuffer(ENTROPY)
        self.assertEqual(wally_psbt_sp_resolve(psbt, keys, keys_len,
                                               entropy, entropy_len, 0), WALLY_OK)

        # The output must be the vector's, as a P2TR scriptPubKey
        script, script_len = make_cbuffer('00' * 34)
        ret, written = wally_psbt_get_output_script(psbt, 0, script, script_len)
        self.assertEqual((ret, written), (WALLY_OK, 34))
        self.assertEqual(h(script).decode('utf-8'), '5120' + VECTOR_OUTPUT)

        # A BIP-375 share and proof are stored under the recipient's scan key
        scan_key = VECTOR_INFO[:66]
        for field, length in [(psbt.contents.global_sp_ecdh_shares, 33),
                              (psbt.contents.global_sp_dleq_proofs, 64)]:
            self.assertEqual(field.num_items, 1)
            item = field.items[0]
            self.assertEqual(h(string_at(item.key, item.key_len)).decode('utf-8'), scan_key)
            self.assertEqual(item.value_len, length)
        wally_psbt_free(psbt)

    def test_resolve_invalid(self):
        """Test resolving with invalid arguments"""
        psbt = self.make_psbt(self.vector_scripts())
        keys, keys_len = make_cbuffer(''.join(VECTOR_PRIVKEYS))
        entropy, entropy_len = make_cbuffer(ENTROPY)

        for args in [(None, keys, keys_len, entropy, entropy_len, 0),
                     (psbt, None, keys_len, entropy, entropy_len, 0),
                     (psbt, keys, 32, entropy, entropy_len, 0),        # Too few keys
                     (psbt, keys, keys_len - 1, entropy, entropy_len, 0),  # Ragged keys
                     (psbt, keys, keys_len, None, entropy_len, 0),
                     (psbt, keys, keys_len, entropy, 31, 0),           # Short entropy
                     (psbt, keys, keys_len, entropy, entropy_len, 1)]: # Invalid flags
            self.assertEqual(wally_psbt_sp_resolve(*args), WALLY_EINVAL)
        wally_psbt_free(psbt)

        # A PSBT with no silent payment output has nothing to resolve
        psbt = self.make_psbt(self.vector_scripts())
        self.assertEqual(wally_psbt_clear_output_sp_v0_info(psbt, 0), WALLY_OK)
        self.assertEqual(wally_psbt_sp_resolve(psbt, keys, keys_len,
                                               entropy, entropy_len, 0), WALLY_EINVAL)
        wally_psbt_free(psbt)

    def test_resolve_entropy(self):
        """Test that the entropy changes the proof, but not the payment"""
        scripts = self.vector_scripts()
        keys, keys_len = make_cbuffer(''.join(VECTOR_PRIVKEYS))
        proofs, scripts_out = [], []

        for entropy_hex in [ENTROPY, '11' * 32]:
            psbt = self.make_psbt(scripts)
            entropy, entropy_len = make_cbuffer(entropy_hex)
            self.assertEqual(wally_psbt_sp_resolve(psbt, keys, keys_len,
                                                   entropy, entropy_len, 0), WALLY_OK)
            script, script_len = make_cbuffer('00' * 34)
            wally_psbt_get_output_script(psbt, 0, script, script_len)
            scripts_out.append(h(script))
            item = psbt.contents.global_sp_dleq_proofs.items[0]
            proofs.append(h(string_at(item.value, item.value_len)))
            wally_psbt_free(psbt)

        self.assertEqual(scripts_out[0], scripts_out[1])
        self.assertNotEqual(proofs[0], proofs[1])


if __name__ == '__main__':
    unittest.main()
