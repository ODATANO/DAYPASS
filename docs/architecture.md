# DAYPASS architecture

## Data flow

```
Producer cockpit (SAPUI5)                  Consumer viewer (3 tiers, QR landing)
   |  CIP-30: signData sign-in,                |  anonymous / role / partner login
   |  every tx signed in the wallet            |
   v                                           v
DAYPASS CAP services    /api/v1/producer   +   /api/v1/passport
   |  passport-anchor: canonical JSON -> blake2b payloadHash,
   |  AES-256-GCM payloadCipher, blake2b Merkle contentRoot        @odatano/dayzero
   |  + Poseidon root (ZK twin) <------------------------------->  (Groth16 prover,
   v                                                                port 8799, optional)
@odatano/core (CAP plugin)
   CardanoTransactionService  BuildMintTransaction, BuildTransactionWithMetadata, Submit
   CardanoSignService         CreateSigningRequest, SubmitVerifiedTransaction, VerifyDataSignature
   CardanoODataService        GetAssetInfo, GetMetadataByTxHash, GetAssetHistory (read-back)
   |
   v
Cardano  preview -> preprod -> mainnet   (Blockfrost dev, Ogmios+Blockfrost prod)
```

## The anchor model

Every passport is one CIP-25 NFT under a Plutus V3 minting policy that is
parameterized with the payment key hash of whoever mints: the connected wallet
in the cockpit, the server key on the API path. The policyId is therefore a
stable namespace per key, and only that key can mint or burn in it. The mint
transaction carries two metadata labels:

- **721** (CIP-25): lean wallet-display block.
- **1155** (DAYPASS anchor, `daypass/anchor/v1`): `payloadHash` (blake2b-256
  of the canonical payload), `contentRoot` (blake2b Merkle root over the nine
  provable fields, values x1000, depth 4, domain-separated leaf/node hashes),
  `poseidonRoot` (the ZK twin of the contentRoot, present when the prover is
  configured), `passportIdHash`, anchor `version`, and the cleartext Annex
  XIII Point-1 block (integers only, e.g. `weightGrams`).

Updates are `reattest` metadata transactions chained via `prev`; revocation
burns the NFT, so the mint/burn history nets to zero supply. Grants and
revokes can be anchored as pseudonymous audit transactions (`sha256(did)` +
level, never PII).

## Privacy and disclosure

Point 1 is public by regulation and goes on-chain in cleartext. Everything
else lives AES-256-GCM-encrypted in the DAYPASS DB (per-passport HKDF key);
only hashes anchor it. Tier redaction (consumer / recycler / authority)
happens in `after READ` handlers of the passport service; partners see only
passports granted to them, at exactly the granted level. The chain carries
evidence, not access control.

Two disclosure tracks bind claims to the anchor:

- **Track A (merkle)**: reveal ONE field value plus a Merkle inclusion proof.
  Folding the proof to the on-chain contentRoot proves the value belongs to
  THIS passport without exposing the other fields. No transaction is needed;
  verification needs only public chain data (`tractusx/pac/verify-pac.mjs` is
  the standalone verifier).
- **Track B (zk)**: prove a threshold statement ("carbonFootprint <= 4000 kg")
  WITHOUT revealing the value. The stateless prover sidecar
  ([@odatano/dayzero](https://www.npmjs.com/package/@odatano/dayzero),
  Groth16 over BLS12-381) builds a proof bound to the anchored poseidonRoot
  and serves the Aiken-built Plutus V3 verifier from `zk/artifacts/`.
  DAYPASS uses that verifier as a MINTING POLICY: the proof travels as the
  mint redeemer, the public inputs as inline datum, so a successful mint IS
  the on-chain verification by the ledger itself.

Both tracks export into the Catena-X artifacts: the CX-0143 aspect carries a
Cardano `integrity` block; the W3C-VC PAC carries
`revealedValue+merkleInclusion` and `zkPredicate` evidence entries.

## Wallet sign-in and API scoping

Connecting a wallet is a two-step handshake: the server issues a one-time
challenge (`walletLoginChallenge`), the wallet signs it via CIP-30 signData,
and `walletLogin` verifies the COSE_Sign1 against the address (Ed25519 over
the Sig_structure AND signer-key-hash == payment credential, via the plugin's
stateless `VerifyDataSignature`). Success mints a bearer token. Requests that
carry it as `x-wallet-session` are scoped server-side to that wallet's
passports: every entity read is filtered by owner, every passport-bound
action rejects foreign passports with 403, stale tokens get 401, and
`createPassport` forces the session wallet as owner. Requests WITHOUT the
header are the trusted server-to-server integration path (Basic auth), which
stays unscoped.

## Transaction model

Two submission paths end in the same bookkeeping (a tx-log row that tracks
`submitted -> confirmed` and flips the passport status):

- **Cockpit (wallet)**: the BROWSER orchestrates the plugin's HTTP actions,
  which gives every step natural request isolation. A `prepareWallet*`
  function on DAYPASS composes policy, metadata and, for burns, the
  NFT-holder input; the build runs with the wallet as sender; ONE CIP-30
  `signTx`; the wallet's witness set goes straight to
  `SubmitVerifiedTransaction` (server-side merge + Ed25519 verification); a
  `recordWallet*` action persists the result and tracks confirmation. Attest,
  reattest, grant/revoke anchors, burn and the zk predicate mint all work
  this way; the cockpit needs no server signing key.
- **REST API (server key, optional)**: actions do local writes only and
  return `mode: submitting`; an async pipeline (collateral, build, sign,
  submit, confirm) runs after the request commits, every step in its own
  short root transaction. Reason: the plugin writes via the request
  transaction but reads via the root connection, so chain calls must never
  nest inside a long-lived request transaction.

Hardening, in both paths: past-dated `validityStartMs` on script builds
(local clock skew vs chain slot), the NFT-holder UTxO is resolved fresh on
every burn attempt, and a short stale-input retry backs off and rebuilds.
Since `@odatano/core` 1.9.4 invalidates its UTxO cache on submit, these waits
cover seconds of backend indexing lag, not cache TTLs.

## Cross-ecosystem parity with NIGHTPASS

Canonicalization, payload hashing and AES layout are byte-identical to
NIGHTPASS (the Midnight-based twin of this app), so the same payload yields
the same `payloadHash` on Midnight and Cardano, and partner identities
(`sha256(did)`) are the same pseudonymous ids in both worlds. A dual-chain
credential is a straightforward follow-up.
