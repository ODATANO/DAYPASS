import { explorerUrl } from './cardano-submit';
import { anchorLabel } from './metadata-composer';

/**
 * Catena-X export builders: the NIGHTPASS exports with the Midnight
 * attestation block replaced by the Cardano one.
 *
 * Aspect: CX-0143 BatteryPass JSON (producer-owned, no redaction).
 * PAC: W3C-VC PredicateAttestationCredential. Evidence differs by proof mode:
 *   - merkle (Track A): the value IS disclosed, bound to the passport via a
 *     Merkle inclusion proof against the ON-CHAIN contentRoot. Stronger than
 *     NIGHTPASS's "indexer-trust": any Cardano API can re-verify.
 *   - zk (Track B, ZeroJ): value hidden; the successful verifier-script spend
 *     tx is the proof (only confirmed txs are exported).
 */

const NETWORK = () => process.env.NETWORK || 'preview';

const hex0x = (h: unknown): string | null => (h ? `0x${String(h).replace(/^0x/, '')}` : null);

export interface AspectRows {
    passport: Record<string, any>;
    cells: Array<Record<string, any>>;
    recycled: Array<Record<string, any>>;
    diligence: Array<Record<string, any>>;
}

/** CX-0143 battery-passport aspect JSON (full structured, producer-owned). */
export function buildAspectJson(rows: AspectRows): string {
    const p = rows.passport;
    const aspect = {
        aspect: 'urn:samm:io.catenax.battery.battery_pass:6.0.0#BatteryPass',
        profile: 'EU 2023/1542 Annex XIII · Catena-X CX-0143',
        passportId: p.passportId,
        general: {
            manufacturerId: p.manufacturerId,
            batteryCategory: p.batteryCategory,
            model: p.model,
            manufactureDate: p.manufactureDate,
            weightKg: p.weightKg,
            performanceClass: p.performanceClass,
            qrCodeUrl: p.qrCodeUrl
        },
        cells: rows.cells,
        recycledContent: rows.recycled,
        dueDiligence: rows.diligence,
        integrity: {
            chain: `cardano-${NETWORK()}`,
            payloadHash: p.payloadHash,
            passportIdHash: p.passportIdHash,
            contentRoot: p.contentRoot,
            policyId: p.policyId ?? null,
            assetName: p.assetName ?? null,
            unit: p.unit ?? null,
            fingerprint: p.fingerprint ?? null,
            attestationTxHash: hex0x(p.attestationTxHash),
            lastAnchorTxHash: hex0x(p.lastAnchorTxHash),
            anchorVersion: p.anchorVersion ?? 0,
            anchorMetadataLabel: anchorLabel(),
            status: p.status,
            anchored: p.status === 'anchored' && !!p.attestationTxHash
        }
    };
    return JSON.stringify(aspect, null, 2);
}

export interface PacRows {
    passport: Record<string, any>;
    /** PredicateProofLog rows (already filtered to exportable evidence). */
    proofs: Array<Record<string, any>>;
}

/** Which PredicateProofLog rows qualify as PAC evidence. */
export function isExportableProof(row: Record<string, any>): boolean {
    if (row.result !== true && row.result !== 1) return false;
    if (row.mode === 'zk') return row.status === 'confirmed' && !!row.txHash;
    return row.mode === 'merkle';
}

/** W3C-VC PredicateAttestationCredential (Catena-X PAC profile). */
export function buildPacJson(rows: PacRows): string {
    const p = rows.passport;
    const network = NETWORK();
    const credential = {
        '@context': ['https://www.w3.org/ns/credentials/v2', 'https://catena-x.net/schema/pac/v1'],
        type: ['VerifiableCredential', 'PredicateAttestationCredential'],
        id: `urn:bpass:${p.passportId}`,
        profile: 'Catena-X CX-0143 Battery Passport',
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
            passportId: p.passportId,
            // Needed by the portable verifier to bind the predicate token
            // (asset name == passportIdHash) back to this passport.
            passportIdHash: p.passportIdHash ?? null,
            standard: 'EU 2023/1542 Annex XIII',
            batteryCategory: p.batteryCategory,
            model: p.model,
            manufacturerId: p.manufacturerId,
            payloadHash: p.payloadHash,
            attestation: {
                chain: `cardano-${network}`,
                unit: p.unit ?? null,
                policyId: p.policyId ?? null,
                fingerprint: p.fingerprint ?? null,
                transactionHash: hex0x(p.attestationTxHash),
                lastAnchorTxHash: hex0x(p.lastAnchorTxHash),
                anchorVersion: p.anchorVersion ?? 0,
                anchorMetadataLabel: anchorLabel(),
                status: p.status,
                // DB-state assertion only; a verifier resolves the anchor tx on-chain.
                locallyAnchored: p.status === 'anchored' && !!p.attestationTxHash,
                verificationModel: 'cardano-metadata',
                explorer: p.attestationTxHash ? explorerUrl(String(p.attestationTxHash).replace(/^0x/, ''), network) : null
            },
            predicateProofs: rows.proofs.map((pr) => {
                if (pr.mode === 'zk') {
                    // Public inputs the mint tx committed to on-chain: the Groth16
                    // verifier policy only lets the token mint when the proof
                    // verifies against exactly these. Exporting them lets a
                    // portable verifier re-derive the expected asset unit and
                    // datum instead of trusting the mere existence of a tx.
                    let pj: any = {};
                    try { pj = pr.proofJson ? JSON.parse(pr.proofJson) : {}; } catch { /* keep {} */ }
                    return {
                        sourceField: pr.sourceField,
                        disclosureMode: 'zkPredicate',
                        claim: `${pr.sourceField} ${pr.predicate} ${pr.threshold}${pr.unit ? ' ' + pr.unit : ''}`,
                        operator: pr.predicate,
                        threshold: pr.threshold,
                        unit: pr.unit,
                        valueDisclosed: false,
                        result: true,
                        system: 'groth16-bls12381',
                        transactionHash: hex0x(pr.txHash),
                        // --- portable-verification material ---
                        // The Groth16 verifier minting policy (its scriptHash IS
                        // the policyId). A verifier MUST pin this against a
                        // trusted set; it is exported for discovery, not trust.
                        verifierPolicyId: pj.policyId ?? null,
                        // On-chain asset name of the predicate token: ODATANO's
                        // mintActions keeps only the bytes of the 64-hex
                        // passportIdHash that trail the 56-hex policyId, so the
                        // minted name is passportIdHash.slice(56). Advisory: the
                        // verifier reads the actual token from the tx outputs.
                        predicateAssetName: p.passportIdHash ? String(p.passportIdHash).replace(/^0x/, '').slice(56) : null,
                        // Circuit public inputs (decimal field elements). Advisory:
                        // the verifier recomputes fieldKey and reads poseidonRoot
                        // from the on-chain anchor rather than trusting these.
                        publicInputs: {
                            poseidonRoot: pj.poseidonRoot ?? null,
                            fieldKey: pj.fieldKey ?? null,
                            threshold: pj.threshold ?? null,
                            isCompliant: 1
                        },
                        // The poseidonRoot the predicate is bound to is anchored on
                        // this tx (mint/reattest); the verifier compares the datum
                        // root against it to prevent a valid-proof-wrong-passport swap.
                        contentRootAnchorTx: hex0x(p.lastAnchorTxHash),
                        anchorMetadataLabel: anchorLabel(),
                        verificationModel: 'cardano-onchain-groth16-mint',
                        explorer: pr.txHash ? explorerUrl(String(pr.txHash).replace(/^0x/, ''), network) : null
                    };
                }
                // Track A: revealed value + Merkle inclusion against the anchored root.
                let merkleProof: unknown = null;
                try { merkleProof = pr.proofJson ? JSON.parse(pr.proofJson) : null; } catch { /* keep null */ }
                const scaled = (merkleProof as any)?.value;
                return {
                    sourceField: pr.sourceField,
                    disclosureMode: 'revealedValue+merkleInclusion',
                    valueDisclosed: true,
                    value: scaled != null ? Number(scaled) / 1000 : null,
                    scaledValue: scaled ?? null,
                    scale: 1000,
                    merkleProof,
                    contentRootAnchorTx: hex0x(p.lastAnchorTxHash),
                    anchorMetadataLabel: anchorLabel(),
                    result: true,
                    verificationModel: 'cardano-metadata',
                    explorer: p.lastAnchorTxHash ? explorerUrl(String(p.lastAnchorTxHash).replace(/^0x/, ''), network) : null
                };
            })
        }
    };
    return JSON.stringify(credential, null, 2);
}
