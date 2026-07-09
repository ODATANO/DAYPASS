# DAYPASS - Digital Battery Passport on Cardano

![Header Image](/docs/readme_header.png)

**EU Battery Regulation 2023/1542 Digital Battery Passport with three disclosure tiers, backed by zero-knowledge attestations on Cardano.**

[![Tests](https://github.com/ODATANO/DAYPASS/actions/workflows/test.yaml/badge.svg)](https://github.com/ODATANO/DAYPASS/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/ODATANO/DAYPASS/branch/main/graph/badge.svg)](https://codecov.io/gh/ODATANO/DAYPASS)
[![@odatano/core](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FODATANO%2FDAYPASS%2Fmain%2Fpackage.json&query=%24.dependencies%5B%27%40odatano%2Fcore%27%5D&logo=npm&label=%40odatano%2Fcore&color=blue)](https://www.npmjs.com/package/@odatano/core)
[![@odatano/dayzero](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FODATANO%2FDAYPASS%2Fmain%2Fpackage.json&query=%24.zkToolchain.dayzero&logo=npm&label=%40odatano%2Fdayzero&color=8A2BE2)](https://www.npmjs.com/package/@odatano/dayzero)

EU Battery Regulation 2023/1542 Digital Battery Passport on **Cardano**: one
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
[`ae0d4c2d…05af8f`](https://preview.cardanoscan.io/transaction/ae0d4c2df24410ad4991a5ca578183b448d2b5f268e1010e489bbed0d105af8f)
carries the CIP-25 passport NFT and the 1155 anchor label (payloadHash,
contentRoot, poseidonRoot, Point-1 fields).

## Zero-knowledge predicates

Beyond revealing values, DAYPASS proves THRESHOLD statements about hidden
fields ("carbon footprint <= 4000 kg CO2e") without disclosing the number:

- every anchor additionally commits a Poseidon Merkle root over the 9 provable
  fields (`poseidonRoot` in the 1155 label)
- a prover sidecar ([@odatano/dayzero](https://www.npmjs.com/package/@odatano/dayzero):
  pure TypeScript, Groth16 over BLS12-381, coset-FFT domain, multi-core MSM)
  builds the proof; the Plutus V3 verifier is a hand-written Aiken policy
  shipped with the trust roots in `zk/artifacts/`
- `provePassportPredicate` mints a predicate token whose mint redeemer IS the
  proof: the validator runs the full Groth16 pairing check on-chain and
  enforces that the token's asset name commits to the public inputs
  (blake2b-224 over the serialised datum), so the statement is verified by
  the Cardano ledger itself. Example on Preview:
  [`5a5c0a64…57d52c`](https://preview.cardanoscan.io/transaction/5a5c0a648333f68c94064ed83385bae121ed26eca6f585a10fd90f48c457d52c)
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

The zero-knowledge track runs on
[@odatano/dayzero](https://www.npmjs.com/package/@odatano/dayzero)
(pure-TypeScript Groth16 prover, Poseidon, and the Aiken on-chain verifier).
The design of the predicate flow owes to the
[bloxbean](https://github.com/bloxbean) ZK stack
([ZeroJ](https://github.com/bloxbean/zeroj)), which powered the first
iterations of this track.
