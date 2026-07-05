using {passport} from '../db/passport-schema';

/**
 * PassportService — the DAYPASS consumer surface.
 *
 * Disclosure-tier gating (consumer / recycler / authority over Annex XIII
 * fields) is enforced in `after READ` handlers; `payloadCipher` is excluded so
 * the encrypted blob is never served. Partners see only passports granted to
 * them (grant level = tier); grants live in the DAYPASS DB (server ACL).
 */
@path: '/api/v1/passport'
service PassportService {
    @readonly
    entity Passports         as
        projection on passport.Passports
        excluding {
            payloadCipher
        };

    @readonly
    entity Batteries         as projection on passport.Batteries;

    @readonly
    entity RecycledMaterials as projection on passport.RecycledMaterials;

    @readonly
    entity DiligenceDoc      as projection on passport.DiligenceDoc;

    // Registered dataspace partners
    @readonly
    entity Partners          as
        projection on passport.Partners
        excluding {
            secret
        };

    /**
     * Self-service partner registration (Catena-X-mock): a recycler /
     * authority registers a DID/BPN + a login secret and receives its
     * pseudonymous `granteeId` (sha256(did)) — the id producers grant to.
     */
    action   registerPartner(did: String,
                             name: String,
                             role: String, // 'recycler' | 'authority'
                             secret: String)         returns {
        did       : String;
        name      : String;
        role      : String;
        granteeId : String;
    };

    /**
     * Supplier resolution: given a passport `payloadHash` (the on-chain anchor
     * a producer shares), return the public identity + on-chain reference +
     * the tier-gated viewer URL.
     */
    function resolveByHash(payloadHash: String)      returns {
        passportId        : String;
        payloadHash       : String;
        manufacturerId    : String;
        model             : String;
        batteryCategory   : String;
        unit              : String;
        fingerprint       : String;
        attestationTxHash : String;
        explorerUrl       : String;
        status            : String;
        verified          : Boolean; // anchored on-chain (mint tx present)
        viewerUrl         : String; // /resolve/<hash> — tier-gated landing
    };

    /**
     * Downloadable W3C-VC Battery Passport Credential (PAC) for a passport by
     * `payloadHash`: public subject + Cardano attestation + exportable proofs.
     * The artifact a supplier verifies with tractusx/pac/verify-pac.mjs.
     */
    function passportCredential(payloadHash: String) returns LargeString;
}
