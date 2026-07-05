use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

/// DAYPASS passport NFT minting policy.
///
/// Parameterized with the producer's payment key hash, so the resulting
/// policyId is a stable per-producer passport namespace. Minting AND burning
/// (revocation) require the producer's signature in extra_signatories —
/// the transaction builder fills that via requiredSignersJson, and the
/// producer's vkey witness satisfies it.
validator passport_mint(producer: VerificationKeyHash) {
  mint(_redeemer: Data, _policy_id: PolicyId, self: Transaction) {
    list.has(self.extra_signatories, producer)
  }

  else(_) {
    fail
  }
}
