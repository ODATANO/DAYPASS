import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
    composeAnchor, composeCip25, composeMintMetadataJson, composeAnchorMetadataJson,
    assetNameHexFor, anchorLabel, DEFAULT_ANCHOR_LABEL, ANCHOR_SCHEMA
} from '../../srv/lib/metadata-composer';
import { blake2b256Hex } from '../../srv/lib/passport-anchor';

const PID = 'BAT-PREVIEW-0001';
const PID_HASH = blake2b256Hex(PID);
const PAYLOAD_HASH = 'ab'.repeat(32);
const ROOT = 'cd'.repeat(32);
const POLICY = '8d37accd2efbeea47991b78d6c91424e85a48a47b23cd5b3bd22ddb1';

/** No float may survive anywhere in a metadata payload (plugin rejects them). */
function assertNoFloats(value: unknown, path = '$'): void {
    if (typeof value === 'number') {
        assert.ok(Number.isInteger(value), `float at ${path}: ${value}`);
    } else if (Array.isArray(value)) {
        value.forEach((v, i) => assertNoFloats(v, `${path}[${i}]`));
    } else if (value && typeof value === 'object') {
        for (const [k, v] of Object.entries(value)) assertNoFloats(v, `${path}.${k}`);
    }
}

describe('assetNameHexFor', () => {
    it('uses utf8 passportId when it fits 32 bytes', () => {
        assert.equal(assetNameHexFor(PID, PID_HASH), Buffer.from(PID, 'utf8').toString('hex'));
    });
    it('falls back to the passportIdHash for long ids', () => {
        const longId = 'X'.repeat(40);
        assert.equal(assetNameHexFor(longId, PID_HASH), PID_HASH);
    });
});

describe('composeAnchor', () => {
    it('builds an attest anchor with 0x-bytes hashes and integer-only point1', () => {
        const anchor = composeAnchor({
            op: 'attest', passportId: PID, passportIdHash: PID_HASH,
            payloadHash: PAYLOAD_HASH, contentRoot: ROOT, version: 1,
            point1: { manufacturerId: 'DE-CELLCO-001', model: 'PowerCell EV-75', weightKg: 432.5, performanceClass: 'B', batteryCategory: 'EV', manufactureDate: '2026-03-15' }
        });
        assert.equal(anchor.schema, ANCHOR_SCHEMA);
        assert.equal(anchor.payloadHash, '0x' + PAYLOAD_HASH);
        assert.equal(anchor.passportIdHash, '0x' + PID_HASH);
        assert.equal((anchor.point1 as any).weightGrams, 432500);
        assert.equal('weightKg' in (anchor.point1 as any), false);
        assertNoFloats(anchor);
    });

    it('rejects malformed hashes, versions, levels and thresholds', () => {
        const base = { op: 'attest' as const, passportId: PID, passportIdHash: PID_HASH };
        assert.throws(() => composeAnchor({ ...base, payloadHash: 'zz'.repeat(32) }), /payloadHash/);
        assert.throws(() => composeAnchor({ ...base, passportIdHash: 'ab' }), /passportIdHash/);
        assert.throws(() => composeAnchor({ ...base, version: 0 }), /version/);
        assert.throws(() => composeAnchor({ ...base, level: 3 }), /level/);
        assert.throws(() => composeAnchor({ ...base, threshold: 1.5 }), /threshold/);
    });

    it('refuses a cleartext DID as grantee (PII guard)', () => {
        assert.throws(
            () => composeAnchor({ op: 'grant', passportId: PID, passportIdHash: PID_HASH, grantee: 'did:web:acme.example' }),
            /grantee must be the 32-byte grantee id/
        );
        const ok = composeAnchor({ op: 'grant', passportId: PID, passportIdHash: PID_HASH, grantee: 'ef'.repeat(32), level: 2 });
        assert.equal(ok.grantee, '0x' + 'ef'.repeat(32));
    });
});

describe('composeCip25', () => {
    it('keys by utf8 name for displayable asset names (v1)', () => {
        const nameHex = assetNameHexFor(PID, PID_HASH);
        const block = composeCip25(POLICY, nameHex, { passportId: PID, model: 'PowerCell EV-75' });
        const asset = (block[POLICY] as any)[PID];
        assert.ok(asset, 'asset keyed by utf8 passportId');
        assert.equal(asset.name, `DPP ${PID}`);
        assert.equal('version' in block, false);
    });
    it('falls back to hex keys + version 2 for non-utf8 names', () => {
        const block = composeCip25(POLICY, PID_HASH, { passportId: 'X'.repeat(40) });
        assert.equal(block.version, 2);
        assert.ok((block[POLICY] as any)['0x' + PID_HASH]);
    });
});

describe('mint + follow-up metadataJson', () => {
    it('mint metadata carries 721 and the anchor label, JSON-parseable, no floats', () => {
        const json = composeMintMetadataJson({
            policyId: POLICY,
            assetNameHex: assetNameHexFor(PID, PID_HASH),
            anchor: {
                op: 'attest', passportId: PID, passportIdHash: PID_HASH,
                payloadHash: PAYLOAD_HASH, contentRoot: ROOT, version: 1,
                point1: { model: 'PowerCell EV-75', weightKg: 432.5 }
            }
        });
        const parsed = JSON.parse(json);
        assert.deepEqual(Object.keys(parsed).sort(), ['1155', '721']);
        assertNoFloats(parsed);
        assert.equal(anchorLabel(), DEFAULT_ANCHOR_LABEL);
    });

    it('mint requires attest op with payloadHash + contentRoot', () => {
        const anchor = { op: 'reattest' as const, passportId: PID, passportIdHash: PID_HASH, payloadHash: PAYLOAD_HASH, contentRoot: ROOT };
        assert.throws(() => composeMintMetadataJson({ policyId: POLICY, assetNameHex: 'ab', anchor }), /op "attest"/);
    });

    it('follow-up anchors chain via prev and reference the unit', () => {
        const json = composeAnchorMetadataJson({
            op: 'reattest', passportId: PID, passportIdHash: PID_HASH,
            payloadHash: 'ee'.repeat(32), contentRoot: ROOT, version: 2,
            unit: POLICY + assetNameHexFor(PID, PID_HASH), prev: 'ff'.repeat(32)
        });
        const anchor = JSON.parse(json)[String(DEFAULT_ANCHOR_LABEL)];
        assert.equal(anchor.prev, '0x' + 'ff'.repeat(32));
        assert.ok(String(anchor.unit).startsWith('0x' + POLICY));
        assert.equal(anchor.version, 2);
    });
});
