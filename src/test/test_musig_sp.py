import hashlib
import unittest
from ctypes import *

import test_silentpayments as sp
from util import *


WALLY_SP_INCOMPLETE, WALLY_SP_COMPLETE = 1, 2
EC_PUBLIC_KEY_LEN = 33
SHA256_LEN = 32
BIP32_VER_MAIN_PUBLIC = 0x0488B21E
BIP32_FLAG_KEY_PUBLIC = 0x1
SIGNER_0 = (c_uint32 * 1)(0)


@unittest.skipUnless(wally_psbt_sp_musig_round1,
                     'MuSig2 silent payments module not enabled')
class MusigSilentPaymentRoundsTests(unittest.TestCase):

    def setUp(self):
        self.secret_keys = sp.MUSIG_SKS
        self.path_values = sp.MUSIG_PATH
        _, self.output_key = sp.musig_aggregate_secret(self.secret_keys,
                                                       self.path_values)
        self.participants = b''.join(sorted(sp.pubkey_of(sk)
                                            for sk in self.secret_keys))
        self.participants_buf, _ = make_cbuffer(self.participants.hex())
        self.path = (c_uint32 * len(self.path_values))(*self.path_values)

        cache = c_void_p()
        self.assertEqual(wally_musig_pubkey_agg(
            self.participants, len(self.participants), None, 0, byref(cache)),
            WALLY_OK)
        aggregate, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        self.assertEqual(wally_musig_pubkey_get(cache, aggregate,
                                                EC_PUBLIC_KEY_LEN), WALLY_OK)
        self.aggregate = bytes(aggregate)
        wally_musig_keyagg_cache_free(cache)

        xpub = POINTER(ext_key)()
        self.assertEqual(wally_musig_pubkey_to_xpub(
            self.aggregate, EC_PUBLIC_KEY_LEN, BIP32_VER_MAIN_PUBLIC,
            byref(xpub)), WALLY_OK)
        for index in self.path_values:
            child = POINTER(ext_key)()
            self.assertEqual(bip32_key_from_parent_alloc(
                xpub, index, BIP32_FLAG_KEY_PUBLIC, byref(child)), WALLY_OK)
            bip32_key_free(xpub)
            xpub = child
        self.internal_key = bytes(xpub.contents.pub_key)[1:]
        bip32_key_free(xpub)

    def build_psbt(self):
        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_init_alloc(2, 1, 1, 0, 0, psbt), WALLY_OK)
        txid, txid_len = make_cbuffer('ab' * 32)
        tx_in = pointer(wally_tx_input())
        self.assertEqual(wally_tx_input_init_alloc(
            txid, txid_len, 0, 0xffffffff, None, 0, None, tx_in), WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_input_at(psbt, 0, 0, tx_in), WALLY_OK)

        script, script_len = make_cbuffer('5120' + self.output_key.hex())
        utxo = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(
            100000, script, script_len, utxo), WALLY_OK)
        self.assertEqual(wally_psbt_set_input_witness_utxo(psbt, 0, utxo),
                         WALLY_OK)
        self.assertEqual(wally_psbt_set_input_amount(psbt, 0, 100000), WALLY_OK)
        self.assertEqual(wally_psbt_set_input_taproot_internal_key(
            psbt, 0, self.internal_key, len(self.internal_key)), WALLY_OK)
        self.assertEqual(wally_psbt_input_add_musig2_participant_pubkeys(
            psbt.contents.inputs, self.aggregate, len(self.aggregate),
            self.participants, len(self.participants)), WALLY_OK)

        tx_out = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(90000, None, 0, tx_out),
                         WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out), WALLY_OK)
        self.assertEqual(wally_psbt_set_output_amount(psbt, 0, 90000), WALLY_OK)
        info = sp.RECIPIENT['scan_pub_key'] + sp.RECIPIENT['spend_pub_key']
        info_buf, info_len = make_cbuffer(info)
        self.assertEqual(wally_psbt_set_output_sp_v0_info(
            psbt, 0, info_buf, info_len), WALLY_OK)
        return psbt

    def musig_input(self):
        value = wally_sp_musig_input()
        value.index = 0
        value.pub_keys = cast(self.participants_buf, c_void_p)
        value.pub_keys_len = len(self.participants)
        value.path = cast(self.path, c_void_p)
        value.path_len = len(self.path_values)
        return value

    def digest(self, psbt):
        result, _ = make_cbuffer('00' * SHA256_LEN)
        self.assertEqual(wally_psbt_get_sp_musig_session_digest(
            psbt, result, SHA256_LEN), WALLY_OK)
        return bytes(result)

    def test_session_digest_stable_and_framed(self):
        psbt = self.build_psbt()
        info = bytes.fromhex(sp.RECIPIENT['scan_pub_key'] +
                             sp.RECIPIENT['spend_pub_key'])
        serialized = (bytes.fromhex('02000000') + b'\x01' + bytes.fromhex('ab' * 32) +
                      bytes.fromhex('00000000ffffffff00000000') + b'\x01' +
                      (90000).to_bytes(8, 'little') + info)
        self.assertEqual(self.digest(psbt), hashlib.sha256(serialized).digest())
        before = self.digest(psbt)
        self.assertEqual(wally_psbt_set_output_amount(psbt, 0, 89999), WALLY_OK)
        self.assertNotEqual(before, self.digest(psbt))
        wally_psbt_free(psbt)

    def test_three_signer_round_trip(self):
        psbt = self.build_psbt()
        musig = self.musig_input()
        secnonces = []
        expected_digest = self.digest(psbt)

        for i, secret in enumerate(self.secret_keys):
            key, key_len = make_cbuffer(secret)
            entropy = bytes([0x30 + i]) * 32 + bytes([0x40 + i]) * 32
            nonce_out = (c_void_p * 1)()
            digest_out, _ = make_cbuffer('00' * SHA256_LEN)
            ret, status = wally_psbt_sp_musig_round1(
                psbt, byref(musig), 1, SIGNER_0, 1, key, key_len, entropy, len(entropy), 0,
                nonce_out, digest_out, SHA256_LEN)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(bytes(digest_out), expected_digest)
            self.assertEqual(status,
                             WALLY_SP_COMPLETE if i == 2 else WALLY_SP_INCOMPLETE)
            self.assertEqual(psbt.contents.inputs[0].musig2_pubnonces.num_items,
                             i + 1)
            self.assertEqual(psbt.contents.inputs[0].musig2_partial_sigs.num_items,
                             0)
            self.assertEqual(wally_psbt_get_input_taproot_signature_len(psbt, 0),
                             (WALLY_OK, 0))
            secnonces.append(nonce_out[0])

        self.assertEqual(self.digest(psbt), expected_digest)
        self.assertEqual(psbt.contents.tx_modifiable_flags, 0)
        self.assertEqual(psbt.contents.outputs[0].script_len, 34)

        for secret, secnonce in zip(self.secret_keys, secnonces):
            key, key_len = make_cbuffer(secret)
            nonce = (c_void_p * 1)(secnonce)
            self.assertEqual(wally_psbt_sp_musig_round2(
                psbt, byref(musig), 1, SIGNER_0, 1, key, key_len, nonce,
                expected_digest, len(expected_digest), 0), WALLY_OK)

        self.assertEqual(psbt.contents.inputs[0].musig2_partial_sigs.num_items, 3)
        self.assertEqual(wally_psbt_musig2_agg_then_derive_finalize_input(
            psbt, 0, self.aggregate, len(self.aggregate), self.path,
            len(self.path_values), 0), WALLY_OK)
        self.assertEqual(wally_psbt_get_input_taproot_signature_len(psbt, 0),
                         (WALLY_OK, 64))
        for secnonce in secnonces:
            wally_musig_secnonce_free(secnonce)
        wally_psbt_free(psbt)

    def test_round1_rejects_bad_sighash_and_wrong_aggregate(self):
        psbt = self.build_psbt()
        musig = self.musig_input()
        key, key_len = make_cbuffer(self.secret_keys[0])
        entropy = b'\x11' * 32 + b'\x22' * 32
        nonce_out = (c_void_p * 1)()
        digest_out, _ = make_cbuffer('00' * SHA256_LEN)
        self.assertEqual(wally_psbt_set_input_sighash(psbt, 0, 3), WALLY_OK)
        ret, _ = wally_psbt_sp_musig_round1(
            psbt, byref(musig), 1, SIGNER_0, 1, key, key_len, entropy, len(entropy), 0,
            nonce_out, digest_out, SHA256_LEN)
        self.assertEqual(ret, WALLY_EINVAL)
        self.assertEqual(psbt.contents.inputs[0].sp_partial_ecdh_shares.num_items, 0)

        self.assertEqual(wally_psbt_set_input_sighash(psbt, 0, 0), WALLY_OK)
        musig.path_len = 0
        musig.path = None
        ret, _ = wally_psbt_sp_musig_round1(
            psbt, byref(musig), 1, SIGNER_0, 1, key, key_len, entropy, len(entropy), 0,
            nonce_out, digest_out, SHA256_LEN)
        self.assertEqual(ret, WALLY_EINVAL)
        self.assertEqual(psbt.contents.inputs[0].sp_partial_ecdh_shares.num_items, 0)
        wally_psbt_free(psbt)

    def test_round1_rejects_resolved_but_modifiable_psbt(self):
        psbt = self.build_psbt()
        musig = self.musig_input()
        for i, secret in enumerate(self.secret_keys):
            proof_entropy = bytes([0x19 + i]) * SHA256_LEN
            key, key_len = make_cbuffer(secret)
            self.assertEqual(wally_psbt_sp_musig_contribute(
                psbt, byref(musig), 1, key, key_len, proof_entropy,
                len(proof_entropy), 0), WALLY_OK)
        self.assertEqual(wally_psbt_sp_musig_resolve_shares(
            psbt, byref(musig), 1, 0), WALLY_OK)
        for modifiable_flags in (1, 2, 3, 4):
            self.assertEqual(wally_psbt_set_tx_modifiable_flags(
                psbt, modifiable_flags), WALLY_OK)
            key, key_len = make_cbuffer(self.secret_keys[0])
            entropy = b'\x21' * SHA256_LEN + b'\x22' * SHA256_LEN
            nonce_out = (c_void_p * 1)()
            digest_out, _ = make_cbuffer('00' * SHA256_LEN)
            ret, _ = wally_psbt_sp_musig_round1(
                psbt, byref(musig), 1, SIGNER_0, 1, key, key_len, entropy, len(entropy), 0,
                nonce_out, digest_out, SHA256_LEN)
            self.assertEqual(ret, WALLY_EINVAL)
            self.assertFalse(nonce_out[0])
            self.assertEqual(psbt.contents.inputs[0].musig2_pubnonces.num_items, 0)
            self.assertEqual(psbt.contents.tx_modifiable_flags,
                             modifiable_flags)
        wally_psbt_free(psbt)

    def test_round1_failed_resolve_leaves_no_scripts(self):
        psbt = self.build_psbt()
        musig = self.musig_input()
        scan_a = bytes.fromhex(sp.RECIPIENT['scan_pub_key'])

        def round1(i):
            key, key_len = make_cbuffer(self.secret_keys[i])
            entropy = bytes([0x60 + i]) * 32 + bytes([0x70 + i]) * 32
            nonce_out = (c_void_p * 1)()
            digest_out, _ = make_cbuffer('00' * SHA256_LEN)
            ret, status = wally_psbt_sp_musig_round1(
                psbt, byref(musig), 1, SIGNER_0, 1, key, key_len, entropy, len(entropy), 0,
                nonce_out, digest_out, SHA256_LEN)
            self.assertEqual(ret, WALLY_OK)
            wally_musig_secnonce_free(nonce_out[0])
            return status

        self.assertEqual(round1(0), WALLY_SP_INCOMPLETE)
        self.assertEqual(round1(1), WALLY_SP_INCOMPLETE)

        # A second recipient, sorting after the first, arrives late: the last
        # participant's shares cover the first scan key but not this one
        scan_b = next(key for key in (sp.pubkey_of('%02x' % i * 32)
                                      for i in range(1, 64)) if key > scan_a)
        tx_out = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(1000, None, 0, tx_out),
                         WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_output_at(psbt, 1, 0, tx_out), WALLY_OK)
        self.assertEqual(wally_psbt_set_output_amount(psbt, 1, 1000), WALLY_OK)
        info = scan_b + bytes.fromhex(sp.RECIPIENT['spend_pub_key'])
        self.assertEqual(wally_psbt_set_output_sp_v0_info(
            psbt, 1, info, len(info)), WALLY_OK)

        self.assertEqual(round1(2), WALLY_SP_INCOMPLETE)
        # Resolving failed on the second scan key, so no script may be kept
        self.assertEqual(psbt.contents.outputs[0].script_len, 0)
        self.assertEqual(psbt.contents.outputs[1].script_len, 0)
        wally_psbt_free(psbt)

    def aggregate_of(self, secret_keys):
        """The participants, aggregate and taproot keys of tr(musig(...)/path)"""
        _, output_key = sp.musig_aggregate_secret(secret_keys, self.path_values)
        participants = b''.join(sorted(sp.pubkey_of(sk) for sk in secret_keys))
        cache = c_void_p()
        self.assertEqual(wally_musig_pubkey_agg(
            participants, len(participants), None, 0, byref(cache)), WALLY_OK)
        aggregate, _ = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        self.assertEqual(wally_musig_pubkey_get(cache, aggregate,
                                                EC_PUBLIC_KEY_LEN), WALLY_OK)
        wally_musig_keyagg_cache_free(cache)
        xpub = POINTER(ext_key)()
        self.assertEqual(wally_musig_pubkey_to_xpub(
            bytes(aggregate), EC_PUBLIC_KEY_LEN, BIP32_VER_MAIN_PUBLIC,
            byref(xpub)), WALLY_OK)
        for index in self.path_values:
            child = POINTER(ext_key)()
            self.assertEqual(bip32_key_from_parent_alloc(
                xpub, index, BIP32_FLAG_KEY_PUBLIC, byref(child)), WALLY_OK)
            bip32_key_free(xpub)
            xpub = child
        internal_key = bytes(xpub.contents.pub_key)[1:]
        bip32_key_free(xpub)
        return participants, bytes(aggregate), output_key, internal_key

    def build_mixed_psbt(self, inputs):
        """A PSBT spending 'inputs' to one recipient. Each input is either the
        secret keys of an aggregate, or the secret of a single-key p2tr input.
        Returns the psbt and the aggregate input descriptions, in input order.
        """
        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_init_alloc(2, len(inputs), 1, 0, 0, psbt),
                         WALLY_OK)
        musig_inputs = (wally_sp_musig_input * len(inputs))()
        self.keep_alive = []
        num_musig = 0
        for i, spend in enumerate(inputs):
            txid, txid_len = make_cbuffer('%02x' % (0xa0 + i) * 32)
            tx_in = pointer(wally_tx_input())
            self.assertEqual(wally_tx_input_init_alloc(
                txid, txid_len, 0, 0xffffffff, None, 0, None, tx_in), WALLY_OK)
            self.assertEqual(wally_psbt_add_tx_input_at(psbt, i, 0, tx_in),
                             WALLY_OK)
            if isinstance(spend, list):
                participants, aggregate, output_key, internal_key = \
                    self.aggregate_of(spend)
            else:
                output_key = sp.pubkey_of(spend)[1:]
            script, script_len = make_cbuffer('5120' + output_key.hex())
            utxo = pointer(wally_tx_output())
            self.assertEqual(wally_tx_output_init_alloc(
                100000, script, script_len, utxo), WALLY_OK)
            self.assertEqual(wally_psbt_set_input_witness_utxo(psbt, i, utxo),
                             WALLY_OK)
            self.assertEqual(wally_psbt_set_input_amount(psbt, i, 100000),
                             WALLY_OK)
            if not isinstance(spend, list):
                continue
            self.assertEqual(wally_psbt_set_input_taproot_internal_key(
                psbt, i, internal_key, len(internal_key)), WALLY_OK)
            self.assertEqual(wally_psbt_input_add_musig2_participant_pubkeys(
                pointer(psbt.contents.inputs[i]), aggregate, len(aggregate),
                participants, len(participants)), WALLY_OK)
            participants_buf, _ = make_cbuffer(participants.hex())
            self.keep_alive.append(participants_buf)
            musig = musig_inputs[num_musig]
            musig.index = i
            musig.pub_keys = cast(participants_buf, c_void_p)
            musig.pub_keys_len = len(participants)
            musig.path = cast(self.path, c_void_p)
            musig.path_len = len(self.path_values)
            num_musig += 1

        tx_out = pointer(wally_tx_output())
        self.assertEqual(wally_tx_output_init_alloc(90000, None, 0, tx_out),
                         WALLY_OK)
        self.assertEqual(wally_psbt_add_tx_output_at(psbt, 0, 0, tx_out), WALLY_OK)
        self.assertEqual(wally_psbt_set_output_amount(psbt, 0, 90000), WALLY_OK)
        info = bytes.fromhex(sp.RECIPIENT['scan_pub_key'] +
                             sp.RECIPIENT['spend_pub_key'])
        self.assertEqual(wally_psbt_set_output_sp_v0_info(
            psbt, 0, info, len(info)), WALLY_OK)
        return psbt, musig_inputs, num_musig

    def run_rounds(self, psbt, musig_inputs, num_musig, signers):
        """Run round 1 then round 2 for each signer. A signer is either
        ('musig', position in musig_inputs, secret) or
        ('ordinary', input index, secret).
        """
        expected_digest = self.digest(psbt)
        secnonces = {}
        for n, (kind, position, secret) in enumerate(signers):
            key, key_len = make_cbuffer(secret)
            digest_out, _ = make_cbuffer('00' * SHA256_LEN)
            if kind == 'ordinary':
                indices = (c_uint32 * 1)(position)
                proof_entropy = bytes([0x50 + n]) * SHA256_LEN
                self.assertEqual(wally_psbt_sp_contribute(
                    psbt, indices, 1, key, key_len, proof_entropy,
                    len(proof_entropy), 0), WALLY_OK)
                entropy = bytes([0x60 + n]) * SHA256_LEN
                ret, status = wally_psbt_sp_musig_round1(
                    psbt, musig_inputs, num_musig, None, 0, None, 0,
                    entropy, len(entropy), 0, None, digest_out, SHA256_LEN)
            else:
                signer = (c_uint32 * 1)(position)
                entropy = bytes([0x30 + n]) * 32 + bytes([0x40 + n]) * 32
                nonce_out = (c_void_p * 1)()
                ret, status = wally_psbt_sp_musig_round1(
                    psbt, musig_inputs, num_musig, signer, 1, key, key_len,
                    entropy, len(entropy), 0, nonce_out, digest_out, SHA256_LEN)
                secnonces[n] = nonce_out[0]
            self.assertEqual(ret, WALLY_OK, 'round 1 of signer %d' % n)
            self.assertEqual(bytes(digest_out), expected_digest)
            self.assertEqual(status, WALLY_SP_COMPLETE if n == len(signers) - 1
                             else WALLY_SP_INCOMPLETE, 'round 1 of signer %d' % n)

        self.assertEqual(psbt.contents.tx_modifiable_flags, 0)
        self.assertEqual(psbt.contents.outputs[0].script_len, 34)
        for n, secnonce in secnonces.items():
            _, position, secret = signers[n]
            key, key_len = make_cbuffer(secret)
            signer = (c_uint32 * 1)(position)
            nonce = (c_void_p * 1)(secnonce)
            self.assertEqual(wally_psbt_sp_musig_round2(
                psbt, musig_inputs, num_musig, signer, 1, key, key_len, nonce,
                expected_digest, len(expected_digest), 0), WALLY_OK,
                'round 2 of signer %d' % n)
            wally_musig_secnonce_free(secnonce)

    def test_rounds_with_an_ordinary_cosigner(self):
        ordinary_secret = '44' * 32
        participants = [('musig', 0, sk) for sk in self.secret_keys]
        ordinary = [('ordinary', 1, ordinary_secret)]
        for signers in (ordinary + participants, participants + ordinary):
            psbt, musig_inputs, num_musig = self.build_mixed_psbt(
                [self.secret_keys, ordinary_secret])
            self.assertEqual(num_musig, 1)
            self.run_rounds(psbt, musig_inputs, num_musig, signers)
            self.assertEqual(wally_psbt_musig2_agg_then_derive_finalize_input(
                psbt, 0, self.aggregate, len(self.aggregate), self.path,
                len(self.path_values), 0), WALLY_OK)
            wally_psbt_free(psbt)

    def test_rounds_with_two_aggregates(self):
        other_secrets = ['55' * 32, '66' * 32]
        psbt, musig_inputs, num_musig = self.build_mixed_psbt(
            [self.secret_keys, other_secrets])
        self.assertEqual(num_musig, 2)
        signers = [('musig', 0, sk) for sk in self.secret_keys] + \
                  [('musig', 1, sk) for sk in other_secrets]
        self.run_rounds(psbt, musig_inputs, num_musig, signers)
        wally_psbt_free(psbt)

    def test_round_signer_indices_are_checked(self):
        psbt, musig_inputs, num_musig = self.build_mixed_psbt(
            [self.secret_keys, ['55' * 32, '66' * 32]])
        key, key_len = make_cbuffer(self.secret_keys[0] + '55' * 32)
        entropy = b'\x01' * 32 + b'\x02' * 32 + b'\x03' * 32
        digest_out, _ = make_cbuffer('00' * SHA256_LEN)
        nonces = (c_void_p * 2)()
        # Out of range, repeated, descending, and a count with no indices
        for indices in ((0, 2), (0, 0), (1, 0)):
            signers = (c_uint32 * 2)(*indices)
            ret, _ = wally_psbt_sp_musig_round1(
                psbt, musig_inputs, num_musig, signers, 2, key, key_len,
                entropy, len(entropy), 0, nonces, digest_out, SHA256_LEN)
            self.assertEqual(ret, WALLY_EINVAL, indices)
        ret, _ = wally_psbt_sp_musig_round1(
            psbt, musig_inputs, num_musig, None, 2, key, key_len,
            entropy, len(entropy), 0, nonces, digest_out, SHA256_LEN)
        self.assertEqual(ret, WALLY_EINVAL)
        # Round 2 needs at least one signer
        self.assertEqual(wally_psbt_sp_musig_round2(
            psbt, musig_inputs, num_musig, None, 0, None, 0, nonces,
            bytes(digest_out), SHA256_LEN, 0), WALLY_EINVAL)
        self.assertFalse(nonces[0] or nonces[1])
        wally_psbt_free(psbt)

    def test_agg_then_derive_rejects_bad_path_binding(self):
        psbt = self.build_psbt()
        secret, secret_len = make_cbuffer(self.secret_keys[0])
        participant = sp.pubkey_of(self.secret_keys[0])
        secrand = b'\x55' * SHA256_LEN
        nonce = c_void_p()
        hardened = (c_uint32 * 1)(0x80000000)

        self.assertEqual(wally_psbt_musig2_agg_then_derive_add_nonce(
            psbt, 0, secrand, len(secrand), secret, secret_len,
            participant, len(participant), self.aggregate, len(self.aggregate),
            hardened, 1, None, 0, 0, byref(nonce)), WALLY_EINVAL)
        self.assertFalse(nonce.value)

        wrong_internal = b'\x01' * 32
        self.assertEqual(wally_psbt_set_input_taproot_internal_key(
            psbt, 0, wrong_internal, len(wrong_internal)), WALLY_OK)
        self.assertEqual(wally_psbt_musig2_agg_then_derive_add_nonce(
            psbt, 0, secrand, len(secrand), secret, secret_len,
            participant, len(participant), self.aggregate, len(self.aggregate),
            self.path, len(self.path_values), None, 0, 0, byref(nonce)),
            WALLY_EINVAL)
        self.assertFalse(nonce.value)
        wally_psbt_free(psbt)


if __name__ == '__main__':
    unittest.main()
