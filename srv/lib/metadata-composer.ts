import { weightGramsFromKg } from './passport-anchor';

/**
 * On-chain metadata composition. ONE place builds the two labels of a
 * passport transaction, hard-coding the Point-1 whitelist (nothing beyond
 * Point 1 may ever reach public metadata in cleartext) and the integers-only
 * rule (the plugin rejects floats).
 *
 * Conventions the ODATANO metadata mapper gives us for free:
 *   - strings > 64 bytes are auto-chunked (CIP-25 style)
 *   - "0x"-prefixed even-length hex strings become CBOR bytes
 *   - floats are REJECTED -> all decimals here are scaled integers
 */

export const ANCHOR_SCHEMA = 'daypass/anchor/v1';
export const DEFAULT_ANCHOR_LABEL = 1155;

export function anchorLabel(): number {
    const raw = process.env.DAYPASS_ANCHOR_LABEL;
    if (!raw) return DEFAULT_ANCHOR_LABEL;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 0) throw new Error(`invalid DAYPASS_ANCHOR_LABEL: ${raw}`);
    return n;
}

/** Point-1 whitelist (public by Regulation 2023/1542; everything else is off-chain only). */
export interface Point1Input {
    manufacturerId?: string | null;
    batteryCategory?: string | null;
    model?: string | null;
    manufactureDate?: string | null;   // ISO date
    weightKg?: number | string | null; // converted to integer grams
    performanceClass?: string | null;
    qrCodeUrl?: string | null;
}

export type AnchorOp = 'attest' | 'reattest' | 'grant' | 'revoke' | 'predicate' | 'burn';

export interface AnchorInput {
    op: AnchorOp;
    passportId: string;
    passportIdHash: string;            // 64-hex
    payloadHash?: string;              // 64-hex (attest/reattest)
    contentRoot?: string;              // 64-hex (attest/reattest)
    poseidonRoot?: string;             // decimal field element (Track B twin of contentRoot)
    version?: number;                  // anchor version (1 on mint)
    unit?: string;                     // policyId+assetNameHex (follow-up txs link back to the NFT)
    prev?: string;                     // previous anchor tx hash (reattest chain)
    point1?: Point1Input;              // cleartext public block (attest/reattest)
    /** grant/revoke audit fields — grantee is ALWAYS the pseudonymous 32-byte id. */
    grantee?: string;
    level?: number;
    /** predicate anchor fields (Track A, optional). */
    fieldKey?: string;
    predicate?: string;
    threshold?: number;
    result?: boolean;
}

const HEX64 = /^[0-9a-f]{64}$/;

function asBytes(hex: string, name: string): string {
    const clean = hex.toLowerCase().replace(/^0x/, '');
    if (!HEX64.test(clean)) throw new Error(`${name} must be 32 bytes hex, got: ${hex}`);
    return '0x' + clean;
}

/** Poseidon root (decimal BLS12-381 field element) -> 32-byte big-endian metadata bytes. */
export function poseidonRootBytes(decimal: string): string {
    if (!/^\d+$/.test(decimal)) throw new Error(`poseidonRoot must be a decimal field element, got: ${decimal}`);
    const hex = BigInt(decimal).toString(16).padStart(64, '0');
    if (hex.length !== 64) throw new Error('poseidonRoot exceeds 32 bytes');
    return '0x' + hex;
}

/** Asset name: utf8(passportId) if it fits 32 bytes, else the 32-byte passportIdHash. */
export function assetNameHexFor(passportId: string, passportIdHash: string): string {
    const utf8 = Buffer.from(passportId, 'utf8');
    if (utf8.length > 0 && utf8.length <= 32) return utf8.toString('hex');
    return asBytes(passportIdHash, 'passportIdHash').slice(2);
}

function point1Block(p: Point1Input): Record<string, string | number> {
    // Explicit whitelist; integers only for numerics.
    const out: Record<string, string | number> = {};
    if (p.manufacturerId) out.manufacturerId = String(p.manufacturerId);
    if (p.batteryCategory) out.batteryCategory = String(p.batteryCategory);
    if (p.model) out.model = String(p.model);
    if (p.manufactureDate) out.manufactureDate = String(p.manufactureDate);
    if (p.weightKg != null && p.weightKg !== '') out.weightGrams = weightGramsFromKg(p.weightKg);
    if (p.performanceClass) out.performanceClass = String(p.performanceClass);
    if (p.qrCodeUrl) out.qrCodeUrl = String(p.qrCodeUrl);
    return out;
}

/** Build the DAYPASS anchor payload (goes under the anchor label). */
export function composeAnchor(input: AnchorInput): Record<string, unknown> {
    const anchor: Record<string, unknown> = {
        schema: ANCHOR_SCHEMA,
        v: 1,
        op: input.op,
        passportId: input.passportId,
        passportIdHash: asBytes(input.passportIdHash, 'passportIdHash')
    };
    if (input.payloadHash) anchor.payloadHash = asBytes(input.payloadHash, 'payloadHash');
    if (input.contentRoot) anchor.contentRoot = asBytes(input.contentRoot, 'contentRoot');
    if (input.poseidonRoot) anchor.poseidonRoot = poseidonRootBytes(input.poseidonRoot);
    if (input.version != null) {
        if (!Number.isInteger(input.version) || input.version < 1) throw new Error(`invalid anchor version: ${input.version}`);
        anchor.version = input.version;
    }
    if (input.unit) anchor.unit = '0x' + input.unit.toLowerCase().replace(/^0x/, '');
    if (input.prev) anchor.prev = asBytes(input.prev, 'prev');
    if (input.point1) anchor.point1 = point1Block(input.point1);
    if (input.grantee) {
        // Pseudonymous only — a cleartext DID here would be permanent public PII.
        const g = input.grantee.toLowerCase().replace(/^0x/, '');
        if (!HEX64.test(g)) throw new Error('grantee must be the 32-byte grantee id (sha256 of the DID), not a DID');
        anchor.grantee = '0x' + g;
    }
    if (input.level != null) {
        if (!Number.isInteger(input.level) || input.level < 0 || input.level > 2) throw new Error(`invalid level: ${input.level}`);
        anchor.level = input.level;
    }
    if (input.fieldKey) anchor.fieldKey = asBytes(input.fieldKey, 'fieldKey');
    if (input.predicate) anchor.predicate = String(input.predicate);
    if (input.threshold != null) {
        if (!Number.isInteger(input.threshold)) throw new Error('threshold must be a scaled integer');
        anchor.threshold = input.threshold;
    }
    // Metadata values must be ints/strings/bytes; booleans are rejected by the mapper.
    if (input.result != null) anchor.result = input.result ? 1 : 0;
    return anchor;
}

/** CIP-25 (label 721) block for the passport NFT — deliberately lean; the
 * integrity data lives under the anchor label. */
export function composeCip25(
    policyId: string,
    assetNameHex: string,
    p: { passportId: string; model?: string | null; qrPngUrl?: string | null }
): Record<string, unknown> {
    if (!/^[0-9a-f]{56}$/.test(policyId.toLowerCase())) throw new Error(`invalid policyId: ${policyId}`);
    const nameUtf8 = Buffer.from(assetNameHex, 'hex').toString('utf8');
    const isUtf8Name = Buffer.from(nameUtf8, 'utf8').toString('hex') === assetNameHex.toLowerCase()
        && /^[\x20-\x7e]+$/.test(nameUtf8);
    const meta: Record<string, unknown> = {
        name: `DPP ${p.passportId}`.slice(0, 64),
        description: 'EU Battery Passport (Regulation 2023/1542)'
    };
    if (p.model) meta.model = String(p.model).slice(0, 64);
    if (p.qrPngUrl) { meta.image = p.qrPngUrl; meta.mediaType = 'image/png'; }
    // CIP-25 v1 keys assets by UTF-8 name; fall back to v2 (hex keys) otherwise.
    const assetKey = isUtf8Name ? nameUtf8 : '0x' + assetNameHex.toLowerCase();
    const block: Record<string, unknown> = { [policyId.toLowerCase()]: { [assetKey]: meta } };
    if (!isUtf8Name) block.version = 2;
    return block;
}

/** Full metadataJson (string) for the MINT transaction: label 721 + anchor label. */
export function composeMintMetadataJson(args: {
    policyId: string;
    assetNameHex: string;
    anchor: AnchorInput;
    qrPngUrl?: string | null;
}): string {
    if (args.anchor.op !== 'attest') throw new Error('mint metadata requires op "attest"');
    if (!args.anchor.payloadHash || !args.anchor.contentRoot) {
        throw new Error('mint anchor requires payloadHash and contentRoot');
    }
    return JSON.stringify({
        [String(721)]: composeCip25(args.policyId, args.assetNameHex, {
            passportId: args.anchor.passportId,
            model: args.anchor.point1?.model,
            qrPngUrl: args.qrPngUrl
        }),
        [String(anchorLabel())]: composeAnchor(args.anchor)
    });
}

/** metadataJson (string) for follow-up anchor txs (reattest / grant / revoke / predicate / burn). */
export function composeAnchorMetadataJson(anchor: AnchorInput): string {
    return JSON.stringify({ [String(anchorLabel())]: composeAnchor(anchor) });
}
