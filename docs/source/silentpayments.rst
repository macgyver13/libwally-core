Silentpayments Functions
========================

.. c:function:: int wally_psbt_get_input_sp_eligible(const struct wally_psbt *psbt, size_t index, size_t *written)

   
   Determine whether a PSBT input can contribute to a silent payment.
   
   :param psbt: The PSBT containing the input to check.
   :param index: The zero-based index of the input to check.
   :param written: 1 if the input is eligible, otherwise 0.
   
   BIP-352 senders may only spend to a silent payment using P2PKH, P2WPKH,
   P2SH-P2WPKH or P2TR inputs, and not a P2TR input whose internal key is the
   BIP-341 NUMS point, since such an input has no key path to sign with.
   
   .. note:: The input's UTXO must be present in the PSBT. An input whose script cannot be classified at all, such as an unknown future witness version, returns `WALLY_ERROR`: a sender must not treat it as merely ineligible, because doing so would make the payment undetectable.

   :return: See :ref:`error-codes`


.. c:function:: int wally_psbt_get_sp_smallest_outpoint(const struct wally_psbt *psbt, unsigned char *bytes_out, size_t len)

   
   Get the BIP-352 smallest outpoint of a PSBT's inputs.
   
   :param psbt: The PSBT to get the smallest outpoint of. Must have inputs.
   :param bytes_out: Destination for the outpoint.
   :param len: Size of ``bytes_out``. Must be `WALLY_SP_OUTPOINT_LEN`.
   
   The smallest outpoint is committed to by the BIP-352 input hash, which is
   what makes the derived outputs unique to this transaction.

   :return: See :ref:`error-codes`


.. c:function:: int wally_psbt_sp_resolve(struct wally_psbt *psbt, const unsigned char *priv_keys, size_t priv_keys_len, const unsigned char *entropy, size_t entropy_len, uint32_t flags)

   
   Resolve a PSBT's silent payment outputs, as the sender.
   
   :param psbt: The PSBT to resolve. Directly modifies this PSBT.
   :param priv_keys: The private keys of the PSBT's eligible inputs, concatenated in input order, one `EC_PRIVATE_KEY_LEN` key per input that `wally_psbt_get_input_sp_eligible` reports as eligible. For a taproot input this must be the key of the taproot *output* key, i.e. the BIP-341 tweaked key, not the untweaked internal key.
   :param priv_keys_len: Length of ``priv_keys`` in bytes.
   :param entropy: Randomness for the DLEQ proofs. One proof is created per unique recipient scan key, each using entropy derived from this value, so it must be unpredictable and must not be reused.
   :param entropy_len: Length of ``entropy`` in bytes. Must be 32.
   :param flags: For future use. Must be 0.
   
   For each output carrying ``PSBT_OUT_SP_V0_INFO``, derives the BIP-352
   output and stores it as the output's scriptPubKey. An existing script must
   match the derived script or the operation fails. One BIP-375 global ECDH
   share and DLEQ proof is stored per unique recipient scan key.
   
   The operation is transactional: on failure, ``psbt`` is not modified.
   
   .. note:: Only the BIP-375 *global* share is produced, which covers the sum of every eligible input, so the caller must hold every eligible input's key. Collaborative sending, where signers publish per-input shares, is not supported.

   
   .. note:: The caller is responsible for BIP-352's requirement that the inputs it signs use SIGHASH_ALL, and for refusing to sign if the resulting outputs are not what it expects.

   :return: See :ref:`error-codes`


.. c:function:: int wally_psbt_get_sp_status(const struct wally_psbt *psbt, uint32_t flags, size_t *written)

   
   Get the status of a PSBT's BIP-375 ECDH shares and DLEQ proofs.
   
   :param psbt: The PSBT to check. Not modified.
   :param flags: For future use. Must be 0.
   :param written: `WALLY_SP_INVALID`, `WALLY_SP_INCOMPLETE` or `WALLY_SP_COMPLETE`, as described below.
   
   Checks that every share for a recipient of this PSBT is accompanied by a
   proof, that every such proof verifies against the public key(s) it covers,
   and that the shares present cover every eligible input and every recipient
   scan key. Where the outputs are resolved, also checks that each one holds
   the scriptPubKey that BIP-352 derives from the shares. Requires no private
   keys, so a signer can check work done by other signers.
   
   The verdict depends on whether the silent payment outputs have been resolved:
   
   - `WALLY_SP_INVALID`: a share without its proof, a proof that does not verify, a share whose input has no key to verify it against, or - when the outputs are already resolved - incomplete coverage or a scriptPubKey that is not the one BIP-352 derives. Do not sign.
   - `WALLY_SP_INCOMPLETE`: the outputs are not resolved and coverage is not yet complete. Everything present is valid; more signers must contribute.
   - `WALLY_SP_COMPLETE`: the outputs are resolved, coverage is complete, every proof verifies and every resolved scriptPubKey is the derived one.
   
   .. note:: The derived check uses only public data: the shares are DLEQ-proven against the inputs' public keys, and BIP-352 needs nothing more than the share, the transaction's smallest outpoint and the recipient's spend key to reach the output. A signer holding none of the eligible inputs can therefore still confirm that what it is asked to sign pays the recipient.

   
   .. note:: Shares and proofs stored under a scan key that no recipient of this PSBT uses are ignored. BIP-375 does not forbid them and they cannot affect the derived outputs.

   
   .. note:: An input that cannot be classified at all, such as an unknown future witness version, returns `WALLY_ERROR`, as it does from `wally_psbt_get_input_sp_eligible`.

   :return: See :ref:`error-codes`


 
Silentpayments Constants
------------------------

.. c:macro:: WALLY_SP_OUTPOINT_LEN
 
    The BIP-352 outpoint of an input: its txid followed by a 4 byte LE vout

.. c:macro:: WALLY_SP_INVALID
 
    Shares or proofs are missing, contradictory or invalid: refuse to sign

.. c:macro:: WALLY_SP_INCOMPLETE
 
    The outputs are not resolved yet, and what is present is valid

.. c:macro:: WALLY_SP_COMPLETE
 
    The outputs are resolved, every share is covered and every proof verifies
