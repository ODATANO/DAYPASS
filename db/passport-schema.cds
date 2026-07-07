using { cuid, managed } from '@sap/cds/common';

namespace passport;

/**
 * DAYPASS domain schema for the EU Battery Regulation 2023/1542
 * Digital Product Passport, anchored on Cardano.
 *
 * Same Annex XIII tier model and field set as NIGHTPASS, with the Midnight
 * anchor replaced by the Cardano one: a CIP-25 NFT per passport plus an
 * anchor metadata label (payloadHash + contentRoot + Point-1 fields).
 *
 * Annex XIII disclosure tiers:
 *   - Point 1        -> PUBLIC               (consumer tier)
 *   - Points 2/3     -> LEGITIMATE INTEREST  (recycler tier)
 *   - Points 2/3 + supplier identities -> AUTHORITY (notified-body tier)
 *
 * On-chain != API: Point-1 fields and hashes go into public Cardano metadata;
 * everything else stays AES-encrypted off-chain (`payloadCipher`) and the
 * disclosure tier is enforced in the API layer (there is no on-chain ACL on
 * Cardano). Grants are DAYPASS-DB rows with an optional public audit anchor.
 */

/** Battery category per Regulation 2023/1542 Art. 2. */
type BatteryCategory : String enum {
    EV;          // electric-vehicle battery
    INDUSTRIAL;  // industrial battery (>2 kWh)
    LMT;         // light means of transport (e-bike, scooter)
}

/** Producer-cockpit lifecycle of a passport (save-then-submit split). */
type PassportStatus : String enum {
    draft;      // created off-chain, not yet anchored
    anchoring;  // mint/reattest in flight
    anchored;   // mint confirmed on-chain
    revoked;    // NFT burned
    failed;     // last submit attempt failed
}

/** On-chain step kinds tracked in PassportTransactions (transaction overview). */
type TxKind : String enum {
    mint;             // CIP-25 NFT + anchor label (initial attest)
    reattest;         // new payload version, metadata-only tx chained via `prev`
    grant;            // disclosure grant audit anchor (optional)
    revoke;           // disclosure revoke audit anchor (optional)
    predicateAnchor;  // Track A predicate/disclosure anchor (optional)
    zkLock;           // Track B: lock at Groth16 verifier script
    zkProve;          // Track B: spend with proof redeemer
    burn;             // passport revocation (NFT burn)
}

/**
 * Status of a tracked on-chain step / log row. Mirrors the ODATANO submission
 * lifecycle (pending -> submitted -> confirmed | failed); `offline` = row was
 * created without a submission (draft mode / no funds).
 */
type TxStatus : String enum { offline; pending; submitted; confirmed; failed; }

type DisclosureOp  : String enum { grant; revoke; }
type PredicateOp   : String enum { lessOrEqual; greaterOrEqual; }
/** How a predicate/disclosure claim is evidenced (Track A vs Track B). */
type ProofMode     : String enum { merkle; zk; }

/** Dataspace partner role (Catena-X-style). Producers grant these tiers. */
type PartnerRole : String enum { recycler; authority; }

/**
 * Registered dataspace partners (recyclers / authorities). A partner self-
 * registers with a DID/BPN; `granteeId = sha256(utf8(did))` is the pseudonymous
 * "who" a producer grants (also the only identity that ever goes into a public
 * grant audit anchor). `secret` is the mocked login credential (stands in for
 * the real Catena-X SSI/credential layer).
 */
entity Partners : managed {
    key did      : String(200);              // DID or BPN — the partner identity + login user
    name         : String(200);
    role         : PartnerRole;
    granteeId    : String(64);               // sha256(utf8(did)) — pseudonymous grant key
    secret       : String(120);              // mock login password (demo only)
}

/**
 * Producer signing identities. The mint policy is parameterized with the
 * producer's paymentKeyHash, so the policyId (= passport namespace) is stable
 * per key. A key change silently creates a NEW namespace — this table makes
 * that explicit and lets the cockpit warn.
 */
entity ProducerKeys : cuid, managed {
    address        : String(120);            // addr... / addr_test...
    paymentKeyHash : String(56);             // 28-byte hex (ExtractPaymentKeyHash)
    policyId       : String(56);             // scriptHash of the parameterized mint policy
    label          : String(100);            // display name ("server key", "Lace main", ...)
    isActive       : Boolean default true;
}

/**
 * A battery passport. The aggregate root.
 *
 * Annex XIII Point 1 (PUBLIC): batteryCategory, manufacturerId, model,
 * manufactureDate, weightKg, performanceClass. These are the fields a consumer
 * sees from the QR landing AND the cleartext `point1` block of the on-chain
 * anchor metadata (hybrid model).
 */
@assert.unique: { passportId: [ passportId ] }
entity Passports : cuid, managed {
    passportId       : String(64) not null;  // unique battery ID per Regulation 2023/1542 (Point 1)
    owner            : String(160);          // producer wallet address; scopes the cockpit list
    manufacturerId   : String(200);          // Point 1
    batteryCategory  : BatteryCategory;      // Point 1
    model            : String(200);          // Point 1
    manufactureDate  : Date;                 // Point 1
    weightKg         : Decimal(10, 3);       // Point 1 (goes on-chain as weightGrams integer)
    performanceClass : String(1);            // Point 1. A..G per regulation.
    qrCodeUrl        : String(500);          // Point 1. Public landing URL.

    // Off-chain encrypted payload. Holds the AES-encrypted canonical payload
    // whose blake2b-256 is the on-chain `payloadHash`. The bytes never go
    // on-chain; only the hash is anchored.
    payloadCipher    : LargeBinary;

    // On-chain anchor result (Cardano).
    payloadHash       : String(64);          // hex blake2b-256 of the canonical payload
    passportIdHash    : String(64);          // hex blake2b-256(passportId)
    contentRoot       : String(64);          // hex Merkle root over provable fields
    poseidonRoot      : String(80);          // decimal Poseidon root (Track B, anchor v2)
    policyId          : String(56);          // mint policy of the producer key
    assetName         : String(64);          // asset name hex
    unit              : String(120);         // policyId + assetNameHex (asset unit)
    fingerprint       : String(64);          // CIP-14 asset1... fingerprint
    attestationTxHash : String(64);          // mint tx (32-byte hex)
    anchorVersion     : Integer default 0;   // highest anchored payload version
    lastAnchorTxHash  : String(64);          // tip of the reattest chain (mint tx if v1)
    status            : PassportStatus default #draft;

    // Compositions hold child detail. Mixed tiers are gated per field in the service.
    batteries         : Composition of many Batteries         on batteries.passport = $self;
    recycledMaterials : Composition of many RecycledMaterials on recycledMaterials.passport = $self;
    diligenceDocs     : Composition of many DiligenceDoc      on diligenceDocs.passport = $self;
}

/**
 * Per-cell-pack detail.
 *
 * cellChemistry, capacityKwh -> LEGITIMATE INTEREST (Annex XIII Points 2/3,
 * recycler tier). carbonFootprintKgCO2 -> restricted (Points 2/3). supplierName
 * -> AUTHORITY only (supplier identity).
 */
entity Batteries : cuid {
    passport             : Association to Passports;
    serialNumber         : String(100);      // legitimate interest
    cellChemistry        : String(50);       // legitimate interest (Points 2/3)
    capacityKwh          : Decimal(10, 3);   // legitimate interest (Points 2/3)
    carbonFootprintKgCO2 : Decimal(15, 3);   // RESTRICTED (Points 2/3). Provable field.
    supplierName         : String(200);      // RESTRICTED. AUTHORITY only (supplier identity).

    // Commercially sensitive numeric fields a supplier wants to keep hidden but
    // must evidence a bound on (provable fields; see PROVABLE_FIELDS). All are
    // RESTRICTED cleartext. Track A discloses the value with a Merkle inclusion
    // proof against the anchored contentRoot; Track B (zk) proves the bound
    // without disclosure.
    recycledContentPct     : Decimal(5, 2);  // Art. 8 recycled content. Prove '>= min quota'.
    cycleLife              : Integer;        // Annex IV full cycles to 80% SoH. Prove '>= N'.
    roundTripEfficiencyPct : Decimal(5, 2);  // Annex IV round-trip efficiency. Prove '>= X%'.
    leadContentPpm         : Decimal(10, 3); // hazardous-substance concentration. Prove '<= limit'.
}

/**
 * Recycled-content declaration per material.
 *
 * material, recycledPercentage -> LEGITIMATE INTEREST (Points 2/3, recycler
 * tier). sourceSupplierName -> AUTHORITY only (supplier identity).
 */
entity RecycledMaterials : cuid {
    passport           : Association to Passports;
    material           : String(50);         // legitimate interest. Li | Co | Ni | Pb
    recycledPercentage : Decimal(5, 2);      // legitimate interest (Points 2/3)
    sourceSupplierName : String(200);        // RESTRICTED. AUTHORITY only (supplier identity).
}

/**
 * Due-diligence document reference. Caller-managed storage: the bytes live at
 * `storageRef` (owned by the caller), only the sha256 travels into the hashed
 * payload. AUTHORITY tier (Points 2/3), supply-chain due-diligence evidence.
 */
entity DiligenceDoc : cuid {
    passport   : Association to Passports;
    docType    : String(100);                // e.g. "supply-chain-due-diligence-report"
    storageRef : String(500);                // caller-owned storage pointer (URL, DMS id, ...)
    sha256Hex  : String(64);                 // document hash, part of the hashed payload
}

/**
 * Per-passport on-chain transaction overview (producer cockpit). One row per
 * submitted step. `offline` status = created without a submission (no tx).
 * Feeds the Transactions tab. `buildId`/`submissionId` reference the ODATANO
 * plugin's TransactionBuilds / TransactionSubmissions rows.
 */
entity PassportTransactions : cuid, managed {
    passport     : Association to Passports;
    kind         : TxKind;
    buildId      : UUID;                     // ODATANO TransactionBuilds.ID
    submissionId : UUID;                     // ODATANO TransactionSubmissions.ID
    txHash       : String(64);
    status       : TxStatus default #offline;
    blockHash    : String(64);
    explorerUrl  : String(300);              // https://preview.cardanoscan.io/transaction/<hash>
    errorMessage : String(1000);
}

/**
 * Producer-side audit log of disclosure grants/revokes. On Cardano the ACL is
 * this DB (server-enforced); the optional on-chain audit anchor (op:"grant"
 * metadata tx, pseudonymous granteeId only) is referenced via txHash.
 */
entity DisclosureGrantLog : cuid, managed {
    passport : Association to Passports;
    grantee  : String(80);                   // 32-byte grantee id (hex) — never a cleartext DID
    level    : Integer;                      // 0=public, 1=legitimate-interest, 2=authority
    op       : DisclosureOp;
    txHash   : String(64);                   // optional audit anchor tx
    status   : TxStatus default #offline;
}

/**
 * Producer-side log of predicate/disclosure evidence (feeds the PAC).
 * Track A (`mode = merkle`): value IS disclosed, with a Merkle inclusion proof
 * against the anchored contentRoot (proofJson holds it). Track B (`mode = zk`):
 * value stays hidden; the successful verifier-script spend tx is the proof.
 */
entity PredicateProofLog : cuid, managed {
    passport    : Association to Passports;
    sourceField : String(120);               // e.g. carbonFootprintKgCO2
    mode        : ProofMode default #merkle;
    predicate   : PredicateOp;
    threshold   : Integer64;                 // scaled x1000
    unit        : String(60);
    proofJson   : LargeString;               // Track A: FieldMerkleProof JSON. Track B: public inputs.
    txHash      : String(64);
    status      : TxStatus default #offline;
    result      : Boolean;
}
