# @odatano/daypass (DAYPASS)

EU Battery Regulation 2023/1542 Digital Product Passport on **Cardano**: one
CIP-25 NFT per passport plus an anchor metadata label carrying the payload
hash, a Merkle content root and the public Point-1 fields. Sensitive data
stays AES-encrypted off-chain; three disclosure tiers render lawful views of
one backend. Field values can be selectively disclosed with Merkle proofs, and
threshold statements ("carbon footprint below X") proven in zero knowledge,
with the Groth16 verification executed by the Cardano ledger itself. DAYPASS
is the transparent-chain twin of NIGHTPASS (Midnight, shielded
ZK) and consumes [`@odatano/core`](https://github.com/ODATANO/ODATANO) as a
CAP plugin.

## Disclosure tiers (Annex XIII)

| Tier | Audience | Sees |
|---|---|---|
| consumer | public, phone scan | Point 1: id, manufacturer, model, category, date, weight, class |
| recycler | legitimate interest | + cell chemistry, capacity, recycled-content shares |
| authority | notified bodies | + supplier identities, carbon footprint, docs, on-chain lineage |

The boundary is enforced in the API layer; the chain carries the EVIDENCE
(anchors, pseudonymous grant audit txs), not the access control.

## On-chain

- **Mint** (attest): CIP-25 NFT under a policy bound to the producer key, plus
  anchor label 1155 with `payloadHash`, `contentRoot`, Point-1 cleartext.
- **Reattest**: metadata tx with the new payload version, chained via `prev`.
- **Grant / revoke**: optional pseudonymous audit anchors, grantee is
  `sha256(did)`, never PII.
- **Burn**: revocation; the mint/burn history nets to zero supply.

Selective disclosure reveals ONE field value with a Merkle inclusion
proof against the anchored content root. Any Cardano API can re-verify it, no
trust in DAYPASS needed.

Two metadata labels split display from evidence:

- **Label 721 (CIP-25)**: standard NFT metadata, what wallets and explorers
  show. Deliberately lean: `name` ("DPP <passportId>"), description, model,
  QR image. No integrity data lives here.
- **Label 1155 (DAYPASS anchor)**: the machine-verifiable part. `op` (mint,
  reattest, grant, revoke), passportId + its hash, `payloadHash` (blake2b of
  the canonical payload), `contentRoot` (Merkle root the field disclosures
  fold to), `poseidonRoot` (its ZK twin), anchor `version` and `prev` tx hash
  (the re-attest chain), plus the cleartext Point-1 block with all decimals as
  scaled integers (weightGrams etc.). Grant/revoke anchors carry the
  pseudonymous `grantee` and `level`; predicate anchors add field key,
  predicate, threshold and result.

The mint tx carries both labels; reattest and audit anchors are plain
metadata txs with only the 1155 label.

Example on Preview: mint + anchor tx
[`ee17c174…c0f9d6`](https://preview.cardanoscan.io/transaction/ee17c174ca5b5a6ae15bf0a1b86a3fc47ca886ecdcc97a466faa6f2bc1c0f9d6)
carries the CIP-25 passport NFT and the 1155 anchor label (payloadHash,
contentRoot, poseidonRoot, Point-1 fields).

## Zero-knowledge predicates

Beyond revealing values, DAYPASS proves THRESHOLD statements about hidden
fields ("carbon footprint <= 4000 kg CO2e") without disclosing the number:

- every anchor additionally commits a Poseidon Merkle root over the 9 provable
  fields (`poseidonRoot` in the 1155 label)
- a prover sidecar (`zk/daypass-prover`: Java 25, ZeroJ/Julc, Groth16 over
  BLS12-381, 4241 constraints) builds the proof and the Plutus V3 verifier
- `provePassportPredicate` mints a predicate NFT whose mint redeemer IS the
  proof: the validator runs the full Groth16 pairing check on-chain, so the
  statement is verified by the Cardano ledger itself. Example on Preview:
  [`b54418fc…f9aa31`](https://preview.cardanoscan.io/transaction/b54418fc4282ae686551b0a452d31fd52e3f30d10b4533aa990dc00bd6f9aa31)
  proves carbonFootprint lessOrEqual threshold against the poseidonRoot
  anchored by the mint tx linked above
- the PAC export carries these as `zkPredicate` entries next to the
  merkle-disclosure entries

## Quick start

```bash
npm install
cp .env.example .env        # fill in BLOCKFROST_API_KEY (preview); the server
                            # signing key is OPTIONAL, the cockpit signs in a
                            # CIP-30 browser wallet
npm run deploy              # creates db/daypass.db (+ demo partner seeds)
docker compose up -d daypass-prover   # ZK prover sidecar on :8799; with
                            # DAYPASS_ZK_PROVER_URL set (default in
                            # .env.example) anchoring REQUIRES it; unset the
                            # variable to run Track A only, without Docker
npm start                   # http://localhost:4004
```

- Producer cockpit: `/producer/webapp/index.html` (login producer/producer)
- Consumer viewer: `/passport/webapp/index.html` (tiers: recycler/recycler,
  authority/authority, partners BPNL000000000ACME/recycler etc.)
- QR landing: `/p/<passportId>`, hash resolver `/resolve/<payloadHash>`,
  public verification JSON `/verify/<passportId>`

## Catena-X / Tractus-X

`passportAspectJson` exports the CX-0143 BatteryPass aspect;
`passportCredential` builds a W3C-VC Predicate Attestation Credential whose
merkle-disclosure entries verify PORTABLY against Cardano:

```bash
node tractusx/pac/verify-pac.mjs tractusx/samples/battery-pass-pac.json <BLOCKFROST_KEY>
```

## Dependency patches

`patches/` (applied via `postinstall: patch-package`) carries two fixes for
bugs we found in the HarmonicLabs stack while landing the ZK track: permuted
BLS12-381 builtin flat tags in `@harmoniclabs/uplc` and a Buffer-mutating
`parseMask` in `@harmoniclabs/crypto`. Both are reported upstream.

## Docs

- `docs/architecture.md`: how the pieces fit
- `docs/producer-walkthrough.md`: cockpit tour with screenshots

## Credits

The zero-knowledge track is built on the excellent
[bloxbean](https://github.com/bloxbean) stack:
[ZeroJ](https://github.com/bloxbean/zeroj) (circuit DSL, Groth16 prover,
Poseidon) and [Julc](https://github.com/bloxbean/julc) (Java-to-Plutus
compiler for the on-chain verifier), with
[zeroj-usecases](https://github.com/bloxbean/zeroj-usecases) as the template
