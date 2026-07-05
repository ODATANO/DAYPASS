using { passport } from '../db/passport-schema';

/**
 * ProducerService — manufacturer / ERP write surface.
 * Mirrors NIGHTPASS /api/v1/producer; the anchor is Cardano (CIP-25 NFT +
 * anchor metadata label) instead of Midnight contract circuits.
 */
@path: '/api/v1/producer'
@requires: 'producer'
service ProducerService {

    entity Passports            as projection on passport.Passports excluding { payloadCipher };
    entity Batteries            as projection on passport.Batteries;
    entity RecycledMaterials    as projection on passport.RecycledMaterials;
    entity DiligenceDoc         as projection on passport.DiligenceDoc;

    @readonly entity Partners             as projection on passport.Partners excluding { secret };
    @readonly entity ProducerKeys         as projection on passport.ProducerKeys;
    @readonly entity PassportTransactions as projection on passport.PassportTransactions;
    @readonly entity DisclosureGrantLog   as projection on passport.DisclosureGrantLog;
    @readonly entity PredicateProofLog    as projection on passport.PredicateProofLog;

    /**
     * Create a passport from the Annex XIII JSON. Always persists the local
     * rows. With `submit: true` and signMode 'server' the mint pipeline starts
     * AFTER the request returns (`mode: 'submitting'`) — watch Passports.status
     * (anchoring -> anchored | failed) and PassportTransactions for the txHash.
     */
    action createPassport(passportJson : LargeString,
                          submit       : Boolean,
                          signMode     : String enum { server; wallet } default 'server',
                          owner        : String)
        returns {
            passportId  : String;
            payloadHash : String;
            contentRoot : String;
            mode        : String;   // 'offline' | 'submitting'
        };

    /**
     * Anchor an existing passport: mints for drafts/failed, re-attests (new
     * anchor version chained via `prev`) when the payload of an anchored
     * passport changed. No-op when the anchored payload is unchanged. Async
     * like createPassport (`mode: 'submitting'`).
     */
    action submitPassport(passportId : String,
                          signMode   : String enum { server; wallet } default 'server')
        returns {
            passportId  : String;
            mode        : String;   // 'submitting' | 'unchanged'
            kind        : String;   // 'mint' | 'reattest'
            payloadHash : String;
        };

    /** Burn the passport NFT (revocation). Async (`mode: 'submitting'`),
     * final state Passports.status = 'revoked'. Requires the NFT in the producer wallet. */
    action revokePassport(passportId : String,
                          signMode   : String enum { server; wallet } default 'server')
        returns {
            passportId : String;
            mode       : String;
        };

    /**
     * Server-side on-chain re-verification: NFT exists (supply 1), anchor
     * metadata matches the recomputed payloadHash/contentRoot, decrypted
     * payload re-hashes to the anchored value.
     */
    action verifyPassportOnChain(passportId : String)
        returns {
            verified   : Boolean;
            checksJson : LargeString;
        };

    /**
     * Grant/revoke a disclosure tier to a partner (server ACL; Cardano has no
     * on-chain ACL). `grantee` is a 64-hex grantee id or a DID/BPN (derived).
     * With `anchor: true` (and an anchored passport + server creds) a public,
     * pseudonymous audit tx is also written (op grant/revoke, granteeId only).
     */
    action grantPassportDisclosure(passportId : String,
                                   grantee    : String,
                                   level      : Integer,
                                   anchor     : Boolean default false)
        returns { mode : String; grantee : String };  // 'offline' | 'submitting'

    action revokePassportDisclosure(passportId : String,
                                    grantee    : String,
                                    anchor     : Boolean default false)
        returns { mode : String; grantee : String };

    /**
     * Track A selective disclosure: reveal ONE provable field value together
     * with its Merkle inclusion proof against the anchored contentRoot. Logs a
     * PredicateProofLog row (mode 'merkle'); the verifier folds the proof and
     * compares with the on-chain anchor.
     */
    action disclosePassportValue(passportId : String, sourceField : String)
        returns {
            passportId   : String;
            sourceField  : String;
            value        : String;
            scaledValue  : String;
            fieldKey     : String;
            contentRoot  : String;
            siblingsJson : LargeString;
            dirsJson     : LargeString;
            anchorTxHash : String;   // tx carrying the contentRoot on-chain
            unit         : String;
        };

    /**
     * Track B zero-knowledge predicate: prove `sourceField <predicate> threshold`
     * WITHOUT disclosing the value. The prover sidecar (DAYPASS_ZK_PROVER_URL)
     * generates a Groth16 proof bound to the anchored poseidonRoot; the pipeline
     * mints one predicate token under the on-chain Groth16 verifier policy.
     * `threshold` is the raw value (scaled x1000 internally). Async
     * (`mode: 'submitting'`); watch PredicateProofLog + PassportTransactions.
     */
    action provePassportPredicate(passportId  : String,
                                  sourceField : String,
                                  predicate   : String enum { lessOrEqual; greaterOrEqual },
                                  threshold   : String,
                                  unit        : String)
        returns {
            passportId      : String;
            sourceField     : String;
            predicate       : String;
            thresholdScaled : String;
            poseidonRoot    : String;
            mode            : String;   // 'submitting'
        };

    /** Cockpit helper (parity with NIGHTPASS): field value + inclusion proof, no log row. */
    function passportFieldValue(passportId : String, sourceField : String)
        returns {
            value        : String;
            scaledValue  : String;
            found        : Boolean;
            fieldKey     : String;
            contentRoot  : String;
            siblingsJson : LargeString;
            dirsJson     : LargeString;
        };

    /** Catena-X CX-0143 battery-passport aspect JSON (producer-owned, no redaction). */
    function passportAspectJson(passportId : String) returns LargeString;

    /** W3C-VC PredicateAttestationCredential (PAC) with Cardano attestation +
     * exportable proofs (merkle disclosures / confirmed zk predicates). */
    function passportCredential(passportId : String) returns LargeString;

    /**
     * Wallet-mode preparation: everything the cockpit needs to call
     * BuildMintTransaction itself with the CONNECTED WALLET as sender/signer.
     * The mint policy is parameterized with the WALLET's payment key hash, so
     * wallet-minted passports live in that wallet's policy namespace.
     */
    function prepareWalletMint(passportId : String, walletAddress : String)
        returns {
            policyId            : String;
            unit                : String;
            assetNameHex        : String;
            lovelaceAmount      : String;
            mintActionsJson     : LargeString;
            mintingPolicyScript : LargeString;
            scriptParamsJson    : LargeString;
            requiredSignersJson : LargeString;
            metadataJson        : LargeString;
            validityStartMs     : String;  // past-dated to absorb local clock skew
        };

    /** Wallet-mode metadataJson for a grant/revoke audit anchor tx. */
    function prepareWalletAnchor(passportId : String, op : String, grantee : String, level : Integer)
        returns {
            metadataJson   : LargeString;
            lovelaceAmount : String;
            grantee        : String;
        };

    /**
     * Wallet-mode reattest preparation: recomputes the payload from the current
     * rows. mode 'unchanged' means there is nothing to anchor; otherwise the
     * metadataJson goes into a wallet-signed BuildTransactionWithMetadata and
     * the recomputed hashes are persisted via recordWalletReattest. Nothing is
     * written here, a canceled wallet popup leaves the passport untouched.
     */
    function prepareWalletReattest(passportId : String)
        returns {
            mode           : String;   // 'reattest' | 'unchanged'
            payloadHash    : String;
            contentRoot    : String;
            poseidonRoot   : String;
            version        : Integer;
            lovelaceAmount : String;
            metadataJson   : LargeString;
        };

    /**
     * Wallet-mode ZK predicate preparation: generates the Groth16 proof and
     * returns the verifier minting policy + redeemer/datum for a wallet-funded
     * BuildMintTransaction. When isCompliant is false there is nothing to
     * build; record the attempt via recordWalletPredicate without a txHash.
     */
    function prepareWalletPredicate(passportId : String, sourceField : String,
                                    predicate : String, threshold : String, unit : String)
        returns {
            isCompliant         : Boolean;
            thresholdScaled     : String;
            poseidonRoot        : String;
            policyId            : String;
            lovelaceAmount      : String;
            mintActionsJson     : LargeString;
            mintingPolicyScript : LargeString;
            mintRedeemerJson    : LargeString;
            inlineDatumJson     : LargeString;
            metadataJson        : LargeString;
            validityStartMs     : String;
            proofJson           : LargeString;
        };

    /**
     * Wallet-mode burn preparation: policy bound to the WALLET key (must match
     * the passport's policyId), the NFT-holder UTxO as forced input, and the
     * burn anchor metadata for a BuildMintTransaction with quantity -1.
     */
    function prepareWalletBurn(passportId : String, walletAddress : String)
        returns {
            lovelaceAmount      : String;
            mintActionsJson     : LargeString;
            mintingPolicyScript : LargeString;
            scriptParamsJson    : LargeString;
            requiredSignersJson : LargeString;
            forceInputsJson     : LargeString;
            metadataJson        : LargeString;
            validityStartMs     : String;
        };

    // --- wallet-mode callbacks (cockpit) — log txs the user signed in a CIP-30 wallet.
    action recordWalletMint(passportId : String, txHash : String, unit : String, policyId : String)
        returns { ok : Boolean };
    action recordWalletDisclosure(passportId : String, grantee : String, level : Integer,
                                  op : String, txHash : String)
        returns { ok : Boolean };
    action recordWalletPredicate(passportId : String, sourceField : String, mode : String,
                                 predicate : String, threshold : Integer64, unit : String,
                                 txHash : String, result : Boolean, proofJson : LargeString)
        returns { ok : Boolean };
    action recordWalletReattest(passportId : String, txHash : String,
                                payloadHash : String, version : Integer)
        returns { ok : Boolean };
    action recordWalletBurn(passportId : String, txHash : String)
        returns { ok : Boolean };

    /**
     * Wallet sign-in (proof of key control, CIP-8/CIP-30 signData):
     * challenge -> the wallet signs the message -> walletLogin verifies the
     * COSE_Sign1 against the address and mints a bearer token. Requests that
     * carry it as `x-wallet-session` header are scoped to that wallet's
     * passports on EVERY read and passport-bound action; requests without it
     * are the trusted server-to-server path.
     */
    action walletLoginChallenge(address : String)
        returns { nonce : String; message : String };
    action walletLogin(nonce : String, coseSignature : LargeString, coseKey : LargeString)
        returns { token : String; address : String; expiresAt : String };
    action walletLogout()
        returns { ok : Boolean };
}
