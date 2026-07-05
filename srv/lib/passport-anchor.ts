import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex } from '@noble/hashes/utils';
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

/**
 * Shared passport-anchoring primitives.
 *
 * Canonicalization, payload hashing and AES encryption are IDENTICAL to
 * NIGHTPASS (its `srv/lib/passport-anchor.ts`) on purpose: the same
 * passport payload produces the same payloadHash on both chains, which enables
 * a future dual-chain credential. Do not change these without changing both.
 *
 * The content-root Merkle tree differs: NIGHTPASS hashes with the Compact
 * contract's pure circuits (Midnight persistentHash); DAYPASS has no contract,
 * so leaves/nodes are blake2b-256 with domain separation (see DOMAIN_* below).
 * Structure, field registry, ordering and x1000 scaling are kept in lockstep.
 *
 * Nothing here writes to the DB — callers own persistence.
 */

// --- Canonical JSON + hashing ------------------------------------------------

/** Recursively sort object keys so the same logical payload always hashes equal. */
export function sortKeys(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(sortKeys);
    if (value && typeof value === 'object') {
        return Object.fromEntries(
            Object.keys(value as Record<string, unknown>).sort()
                .map(k => [k, sortKeys((value as Record<string, unknown>)[k])])
        );
    }
    return value;
}

/** Deterministic canonical JSON string of a payload. */
export function canonicalize(value: unknown): string {
    return JSON.stringify(sortKeys(value));
}

/** blake2b-256 hex of a UTF-8 string (the anchoring hash scheme). */
export function blake2b256Hex(input: string): string {
    return bytesToHex(blake2b(Buffer.from(input, 'utf8'), { dkLen: 32 }));
}

/** blake2b-256 over raw bytes. */
export function blake2b256Bytes(input: Uint8Array): Uint8Array {
    return blake2b(input, { dkLen: 32 });
}

/** Canonicalize + hash a payload object -> { canonicalPayload, payloadHash }. */
export function hashPayload(payload: unknown): { canonicalPayload: string; payloadHash: string } {
    const canonicalPayload = canonicalize(payload);
    return { canonicalPayload, payloadHash: blake2b256Hex(canonicalPayload) };
}

// --- Scaling (risk #10: ONE place, imported everywhere) -----------------------

/** Provable-field scale: raw decimal x1000 -> Uint64 (milli-units). */
export const VALUE_SCALE = 1000;

/** Scale a raw numeric field value to the Uint64 integer that gets hashed/compared. */
export function scaleValue(raw: number | string): number {
    return Math.round(Number(raw) * VALUE_SCALE);
}

/** Point-1 weight for the anchor metadata: kg decimal -> integer grams. */
export function weightGramsFromKg(weightKg: number | string): number {
    return Math.round(Number(weightKg) * 1000);
}

// --- Content-root Merkle tree (field-bound disclosure/predicates) -------------
//
// Fixed depth-4 tree (16 leaves). Leaf i holds PROVABLE_FIELDS[i]
// (field_key = blake2b256(fieldName), value = scaled integer); unused leaves are
// a fixed empty leaf. The root is anchored on-chain in the anchor metadata
// (`contentRoot`); Track A discloses a value with an inclusion proof against it.

/** Provable scalar fields read directly from the (first) Battery. */
export const BATTERY_PROVABLE_FIELDS = [
    'carbonFootprintKgCO2', 'capacityKwh', 'recycledContentPct',
    'cycleLife', 'roundTripEfficiencyPct', 'leadContentPpm'
] as const;

/** Per-material recycled-content fields, sourced from RecycledMaterials rows.
 * Field key convention: `recycled<Material>Pct` (material code Co|Li|Ni). */
export const RECYCLED_MATERIAL_FIELDS = ['recycledCoPct', 'recycledLiPct', 'recycledNiPct'] as const;

/** Ordered, versioned provable-field registry. Leaf index = position here.
 * Adding a field changes the content root, so passports must be re-anchored
 * (re-attested) for the new field to become provable. */
export const PROVABLE_FIELDS = [...BATTERY_PROVABLE_FIELDS, ...RECYCLED_MATERIAL_FIELDS] as const;
export const MERKLE_DEPTH = 4;
const LEAF_COUNT = 1 << MERKLE_DEPTH; // 16
const EMPTY_LEAF_KEY = 'daypass/content-root/empty-leaf/v1';

// Domain separation: a leaf hash can never be confused with a node hash, and
// neither collides with plain payload hashing.
const DOMAIN_LEAF = Buffer.from('daypass/leaf/v1', 'utf8');
const DOMAIN_NODE = Buffer.from('daypass/node/v1', 'utf8');

function fromHex32(hex: string): Uint8Array {
    const clean = hex.replace(/^0x/, '');
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
}
function toHex(u8: Uint8Array): string {
    return Buffer.from(u8).toString('hex');
}
function u64be(v: bigint): Uint8Array {
    if (v < 0n || v > 0xffffffffffffffffn) throw new Error(`value out of Uint64 range: ${v}`);
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, v);
    return out;
}

/** Merkle leaf: blake2b256("daypass/leaf/v1" || fieldKey(32) || value_u64_be(8)). */
export function leafHash(fieldKey: Uint8Array, value: bigint): Uint8Array {
    return blake2b256Bytes(Buffer.concat([DOMAIN_LEAF, fieldKey, u64be(value)]));
}

/** Merkle node: blake2b256("daypass/node/v1" || left(32) || right(32)). */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
    return blake2b256Bytes(Buffer.concat([DOMAIN_NODE, left, right]));
}

/** Canonical 32-byte field id for a provable field name (public label hash). */
export function fieldKeyHex(fieldName: string): string {
    return blake2b256Hex(fieldName);
}

export interface FieldMerkleProof {
    fieldKey: string;   // 64-hex canonical field id
    value: string;      // decimal string of the scaled Uint64 value
    siblings: string[]; // MERKLE_DEPTH x 64-hex
    dirs: boolean[];    // MERKLE_DEPTH booleans (true = node is LEFT child)
}

export interface ContentRoot {
    contentRoot: string; // 64-hex Merkle root
    /** Inclusion proof for a provable field, or null if not provable / absent. */
    proofFor(fieldName: string): FieldMerkleProof | null;
}

/**
 * Build the content-root Merkle tree from a field -> raw-value map (raw values
 * are scaled x1000 internally). Only PROVABLE_FIELDS are placed; a field absent
 * from `values` still occupies its leaf as the empty leaf. Returns the root plus
 * a `proofFor(fieldName)` that yields the inclusion path.
 */
export function buildContentRoot(values: Record<string, number | string | null | undefined>): ContentRoot {
    const emptyLeaf = leafHash(fromHex32(fieldKeyHex(EMPTY_LEAF_KEY)), 0n);

    // Leaf layer (index 0..15).
    const leaves: Uint8Array[] = [];
    for (let i = 0; i < LEAF_COUNT; i++) {
        const fieldName = PROVABLE_FIELDS[i];
        const raw = fieldName != null ? values[fieldName] : undefined;
        if (fieldName != null && raw != null && raw !== '') {
            leaves.push(leafHash(fromHex32(fieldKeyHex(fieldName)), BigInt(scaleValue(raw))));
        } else {
            leaves.push(emptyLeaf);
        }
    }

    // Build all levels bottom-up so proofFor can read siblings per level.
    const levels: Uint8Array[][] = [leaves];
    for (let d = 0; d < MERKLE_DEPTH; d++) {
        const prev = levels[d];
        const next: Uint8Array[] = [];
        for (let i = 0; i < prev.length; i += 2) {
            next.push(nodeHash(prev[i], prev[i + 1]));
        }
        levels.push(next);
    }
    const contentRoot = toHex(levels[MERKLE_DEPTH][0]);

    return {
        contentRoot,
        proofFor(fieldName: string): FieldMerkleProof | null {
            const idx = PROVABLE_FIELDS.indexOf(fieldName as typeof PROVABLE_FIELDS[number]);
            if (idx < 0) return null;
            const raw = values[fieldName];
            if (raw == null || raw === '') return null;
            const siblings: string[] = [];
            const dirs: boolean[] = [];
            let node = idx;
            for (let d = 0; d < MERKLE_DEPTH; d++) {
                const isLeft = node % 2 === 0;
                const siblingIdx = isLeft ? node + 1 : node - 1;
                siblings.push(toHex(levels[d][siblingIdx]));
                dirs.push(isLeft); // true => current node is the LEFT child
                node = Math.floor(node / 2);
            }
            return {
                fieldKey: fieldKeyHex(fieldName),
                value: String(scaleValue(raw)),
                siblings,
                dirs
            };
        }
    };
}

/**
 * Verifier side of Track A: fold an inclusion proof back to the root and
 * compare with the anchored contentRoot. Pure function — usable in the portable
 * PAC verifier without any DAYPASS dependency.
 */
export function verifyFieldProof(proof: FieldMerkleProof, contentRoot: string): boolean {
    if (proof.siblings.length !== MERKLE_DEPTH || proof.dirs.length !== MERKLE_DEPTH) return false;
    let node = leafHash(fromHex32(proof.fieldKey), BigInt(proof.value));
    for (let d = 0; d < MERKLE_DEPTH; d++) {
        const sibling = fromHex32(proof.siblings[d]);
        node = proof.dirs[d] ? nodeHash(node, sibling) : nodeHash(sibling, node);
    }
    return toHex(node) === contentRoot.replace(/^0x/, '').toLowerCase();
}

/**
 * Unify the provable-field values of a passport: Battery scalars from the
 * first cell pack + per-material recycled percentages from RecycledMaterials.
 */
export function fieldValuesFor(p: {
    batteries?: Array<Record<string, unknown>> | null;
    recycledMaterials?: Array<{ material?: string | null; recycledPercentage?: number | string | null }> | null;
}): Record<string, number | string> {
    const out: Record<string, number | string> = {};
    const battery = p.batteries?.[0];
    if (battery) {
        for (const f of BATTERY_PROVABLE_FIELDS) {
            const v = battery[f];
            if (v != null && v !== '') out[f] = v as number | string;
        }
    }
    for (const rm of p.recycledMaterials ?? []) {
        const key = `recycled${String(rm.material ?? '')}Pct`;
        if ((RECYCLED_MATERIAL_FIELDS as readonly string[]).includes(key) && rm.recycledPercentage != null) {
            out[key] = rm.recycledPercentage;
        }
    }
    return out;
}

// --- Payload encryption ------------------------------------------------------

function deriveKey(passportId: string): Buffer {
    const masterHex = process.env.ENCRYPTION_KEY;
    const master = masterHex
        ? Buffer.from(masterHex, 'hex')
        : Buffer.from('00'.repeat(32), 'hex'); // dev fallback; prod must set ENCRYPTION_KEY
    return Buffer.from(
        hkdfSync('sha256', master, Buffer.from(passportId, 'utf8'), Buffer.from('passport-payload'), 32)
    );
}

/**
 * AES-256-GCM encrypt with a per-passport key derived via HKDF from the app
 * secret (ENCRYPTION_KEY) and passportId as salt. Output layout:
 * iv(12) || authTag(16) || ciphertext, as a Buffer for the LargeBinary column.
 * (Byte-compatible with NIGHTPASS.)
 */
export function encryptPayload(plaintext: string, passportId: string): Buffer {
    const key = deriveKey(passportId);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, ct]);
}

/** Inverse of encryptPayload. Throws on wrong key or tampered ciphertext. */
export function decryptPayload(cipherBlob: Buffer | Uint8Array, passportId: string): string {
    const blob = Buffer.isBuffer(cipherBlob) ? cipherBlob : Buffer.from(cipherBlob);
    if (blob.length < 12 + 16 + 1) throw new Error('cipher blob too short');
    const key = deriveKey(passportId);
    const decipher = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
    decipher.setAuthTag(blob.subarray(12, 28));
    return Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]).toString('utf8');
}
