# Catena-X / Tractus-X integration

DAYPASS exports two Catena-X artifacts, mirroring NIGHTPASS with the
Midnight attestation replaced by the Cardano one:

- **Aspect JSON** (`passportAspectJson`): CX-0143 BatteryPass structure with an
  `integrity` block carrying the Cardano lineage (unit, policyId, fingerprint,
  payloadHash, contentRoot, anchor txs).
- **PAC** (`passportCredential`): a W3C-VC `PredicateAttestationCredential`.
  Producer surface: `/api/v1/producer/passportCredential(passportId='...')`.
  Consumer surface: `/api/v1/passport/passportCredential(payloadHash='...')`.

## Disclosure modes in the PAC

| mode | valueDisclosed | evidence | verification |
|---|---|---|---|
| `revealedValue+merkleInclusion` (Track A) | true | Merkle inclusion proof folding to the ON-CHAIN contentRoot | any Cardano API, no trust in DAYPASS |
| `zkPredicate` (Track B, ZeroJ, experimental) | false | a predicate token minted under a PINNED Groth16 verifier policy, its inline datum bound to the passport's anchored poseidonRoot | any Cardano API, against a trusted verifier-policy set |

Track A is deliberately stronger than NIGHTPASS's `indexer-trust` model: the
verifier recomputes the Merkle fold locally and compares against metadata that
any Cardano data provider serves.

For Track B the PAC carries the portable-verification material per proof:
`verifierPolicyId`, `predicateAssetName` (== passportIdHash) and the circuit
`publicInputs` (poseidonRoot, fieldKey, threshold). These are exported for
discovery, NOT for trust: the verifier pins the policy and re-derives every
binding from the chain.

## Portable verifier

```bash
node tractusx/pac/verify-pac.mjs tractusx/samples/battery-pass-pac.json <BLOCKFROST_API_KEY>
```

Standalone (only `@noble/hashes` needed). Checks, without trusting DAYPASS:

- the mint tx and the anchor metadata (payloadHash + contentRoot under the
  anchor label);
- the NFT supply (1, or 0 when revoked);
- every merkle proof folds to the on-chain contentRoot;
- every **zkPredicate** proof is a real on-chain Groth16 attestation:
  - the predicate token is minted under a verifier policy that is **pinned**
    in `verifier-policies.json` (or passed via `--trust-verifier-policy` /
    `PAC_TRUST_VERIFIER_POLICY`) — an unpinned policy fails, so a forged PAC
    pointing at some trivial always-mint policy is rejected;
  - the token's asset name equals `blake2b(passportId)` (token<->passport bind);
  - the mint tx's first-output inline datum public inputs bind to this passport:
    `poseidonRoot` == the anchored root, `fieldKey` == `blake2b31(sourceField)`,
    `threshold` == the claimed threshold, `isCompliant` == 1;
  - the predicate anchor metadata names the same passport, field and predicate.

### Pinning the verifier policy

`verifier-policies.json` is the trust root for Track B. It ships empty, so
zkPredicate checks fail until you pin the real Groth16 verifier policyId per
network and operator. Read it from a trusted running prover (never from the PAC
under test) and fill the entry for your network:

```bash
curl -s $DAYPASS_ZK_PROVER_URL/validator?op=lessOrEqual    | jq -r .scriptHash
curl -s $DAYPASS_ZK_PROVER_URL/validator?op=greaterOrEqual | jq -r .scriptHash
```

A change to the trusted setup (`zk/daypass-prover/data/*.bin`) changes the VK
and thus the policyId — re-pin after any setup change.

The sample PAC in `samples/` was produced on Preview: a demo passport was
minted, two fields disclosed, and the exported credential verified with the
command above. It carries Track A (merkle) proofs only; the Track B path is
covered by `test/unit/verify-pac.test.ts` (decoder, field-key derivation,
policy pinning, and the full bind/tamper matrix).
