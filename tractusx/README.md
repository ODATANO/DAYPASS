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
| `zkPredicate` (Track B, ZeroJ, experimental) | false | successful Groth16 verifier-script spend tx | tx validated by the chain itself |

Track A is deliberately stronger than NIGHTPASS's `indexer-trust` model: the
verifier recomputes the Merkle fold locally and compares against metadata that
any Cardano data provider serves.

## Portable verifier

```bash
node tractusx/pac/verify-pac.mjs tractusx/samples/battery-pass-pac.json <BLOCKFROST_API_KEY>
```

Standalone (only `@noble/hashes` needed): checks the mint tx, the anchor
metadata (payloadHash + contentRoot under the anchor label), the NFT supply
(1, or 0 when revoked), folds every merkle proof to the on-chain root, and
checks zk proof txs exist.

The sample PAC in `samples/` was produced on Preview: a demo passport was
minted, two fields disclosed, and the exported credential verified with the
command above.
