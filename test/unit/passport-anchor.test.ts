import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
    sortKeys, canonicalize, blake2b256Hex, hashPayload,
    scaleValue, weightGramsFromKg, VALUE_SCALE,
    PROVABLE_FIELDS, BATTERY_PROVABLE_FIELDS, RECYCLED_MATERIAL_FIELDS, MERKLE_DEPTH,
    fieldKeyHex, buildContentRoot, verifyFieldProof, fieldValuesFor,
    encryptPayload, decryptPayload
} from '../../srv/lib/passport-anchor';

// Independent blake2b implementation (harmoniclabs) to cross-check noble's.
import { blake2b_256 } from '@harmoniclabs/buildooor';

const SAMPLE_VALUES = {
    carbonFootprintKgCO2: 3412.75,
    capacityKwh: 75.0,
    recycledContentPct: 16.5,
    cycleLife: 4200,
    roundTripEfficiencyPct: 92.5,
    leadContentPpm: 45.0,
    recycledCoPct: 16.5,
    recycledLiPct: 12.25,
    recycledNiPct: 8.0
};

describe('canonicalize + hashPayload', () => {
    it('sorts keys recursively and deterministically', () => {
        const a = { b: 1, a: { z: [3, { y: 2, x: 1 }], k: 'v' } };
        const b = { a: { k: 'v', z: [3, { x: 1, y: 2 }] }, b: 1 };
        assert.equal(canonicalize(a), canonicalize(b));
        assert.deepEqual(sortKeys([{ b: 1, a: 2 }]), [{ a: 2, b: 1 }]);
    });

    it('array order is significant (not sorted)', () => {
        assert.notEqual(canonicalize({ a: [1, 2] }), canonicalize({ a: [2, 1] }));
    });

    it('blake2b-256 matches the RFC empty-string vector', () => {
        assert.equal(
            blake2b256Hex(''),
            '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8'
        );
    });

    it('noble and harmoniclabs blake2b-256 agree (NIGHTPASS hash parity)', () => {
        for (const input of ['', 'abc', 'daypass', canonicalize(SAMPLE_VALUES)]) {
            const noble = blake2b256Hex(input);
            const harmonic = Buffer.from(blake2b_256(new TextEncoder().encode(input))).toString('hex');
            assert.equal(noble, harmonic, `mismatch for input "${input.slice(0, 20)}"`);
        }
    });

    it('hashPayload is stable across key order', () => {
        const h1 = hashPayload({ x: 1, y: { b: 2, a: 3 } });
        const h2 = hashPayload({ y: { a: 3, b: 2 }, x: 1 });
        assert.equal(h1.payloadHash, h2.payloadHash);
        assert.match(h1.payloadHash, /^[0-9a-f]{64}$/);
    });
});

describe('scaling', () => {
    it('scales provable values x1000', () => {
        assert.equal(VALUE_SCALE, 1000);
        assert.equal(scaleValue(3412.75), 3412750);
        assert.equal(scaleValue('92.5'), 92500);
        assert.equal(scaleValue(4200), 4200000);
    });
    it('weight goes on-chain as integer grams', () => {
        assert.equal(weightGramsFromKg(432.5), 432500);
        assert.equal(weightGramsFromKg('0.001'), 1);
    });
});

describe('content-root Merkle tree', () => {
    it('registry has 9 fields in NIGHTPASS order, depth 4', () => {
        assert.equal(MERKLE_DEPTH, 4);
        assert.equal(PROVABLE_FIELDS.length, 9);
        assert.deepEqual([...PROVABLE_FIELDS], [...BATTERY_PROVABLE_FIELDS, ...RECYCLED_MATERIAL_FIELDS]);
    });

    it('root is deterministic and 64-hex', () => {
        const r1 = buildContentRoot(SAMPLE_VALUES);
        const r2 = buildContentRoot({ ...SAMPLE_VALUES });
        assert.equal(r1.contentRoot, r2.contentRoot);
        assert.match(r1.contentRoot, /^[0-9a-f]{64}$/);
    });

    it('root changes when any value changes', () => {
        const base = buildContentRoot(SAMPLE_VALUES).contentRoot;
        const tampered = buildContentRoot({ ...SAMPLE_VALUES, capacityKwh: 75.001 }).contentRoot;
        assert.notEqual(base, tampered);
    });

    it('every populated field yields a proof that verifies against the root', () => {
        const tree = buildContentRoot(SAMPLE_VALUES);
        for (const field of PROVABLE_FIELDS) {
            const proof = tree.proofFor(field);
            assert.ok(proof, `no proof for ${field}`);
            assert.equal(proof.fieldKey, fieldKeyHex(field));
            assert.equal(proof.siblings.length, MERKLE_DEPTH);
            assert.ok(verifyFieldProof(proof, tree.contentRoot), `proof for ${field} did not verify`);
            assert.ok(verifyFieldProof(proof, '0x' + tree.contentRoot), '0x-prefixed root must verify too');
        }
    });

    it('tampered proofs are rejected', () => {
        const tree = buildContentRoot(SAMPLE_VALUES);
        const proof = tree.proofFor('carbonFootprintKgCO2')!;
        assert.equal(verifyFieldProof({ ...proof, value: '3412751' }, tree.contentRoot), false);
        assert.equal(verifyFieldProof({ ...proof, fieldKey: fieldKeyHex('capacityKwh') }, tree.contentRoot), false);
        const badSiblings = [...proof.siblings];
        badSiblings[0] = '00'.repeat(32);
        assert.equal(verifyFieldProof({ ...proof, siblings: badSiblings }, tree.contentRoot), false);
        const badDirs = [...proof.dirs];
        badDirs[1] = !badDirs[1];
        assert.equal(verifyFieldProof({ ...proof, dirs: badDirs }, tree.contentRoot), false);
    });

    it('absent fields occupy empty leaves; proofFor returns null for them', () => {
        const partial = buildContentRoot({ capacityKwh: 75.0 });
        assert.notEqual(partial.contentRoot, buildContentRoot(SAMPLE_VALUES).contentRoot);
        assert.equal(partial.proofFor('carbonFootprintKgCO2'), null);
        assert.equal(partial.proofFor('notAField'), null);
        const proof = partial.proofFor('capacityKwh')!;
        assert.ok(verifyFieldProof(proof, partial.contentRoot));
    });

    it('a proof from one tree does not verify against another root', () => {
        const treeA = buildContentRoot(SAMPLE_VALUES);
        const treeB = buildContentRoot({ ...SAMPLE_VALUES, cycleLife: 4201 });
        const proof = treeA.proofFor('capacityKwh')!;
        assert.equal(verifyFieldProof(proof, treeB.contentRoot), false);
    });
});

describe('fieldValuesFor', () => {
    it('unifies battery scalars and per-material recycled percentages', () => {
        const values = fieldValuesFor({
            batteries: [{
                carbonFootprintKgCO2: 3412.75, capacityKwh: 75.0, recycledContentPct: 16.5,
                cycleLife: 4200, roundTripEfficiencyPct: 92.5, leadContentPpm: 45.0,
                supplierName: 'must-not-appear'
            }],
            recycledMaterials: [
                { material: 'Co', recycledPercentage: 16.5 },
                { material: 'Li', recycledPercentage: 12.25 },
                { material: 'Pb', recycledPercentage: 99 } // not in registry -> ignored
            ]
        });
        assert.deepEqual(Object.keys(values).sort(), [
            'capacityKwh', 'carbonFootprintKgCO2', 'cycleLife', 'leadContentPpm',
            'recycledCoPct', 'recycledContentPct', 'recycledLiPct', 'roundTripEfficiencyPct'
        ]);
        assert.equal(values.recycledCoPct, 16.5);
        assert.equal('supplierName' in values, false);
    });

    it('handles empty input', () => {
        assert.deepEqual(fieldValuesFor({}), {});
    });
});

describe('payload encryption (AES-256-GCM, NIGHTPASS layout)', () => {
    it('round-trips', () => {
        const blob = encryptPayload('{"secret":"supplier"}', 'BAT-0001');
        assert.ok(blob.length > 28);
        assert.equal(decryptPayload(blob, 'BAT-0001'), '{"secret":"supplier"}');
    });

    it('is salted per passportId (wrong id fails auth)', () => {
        const blob = encryptPayload('data', 'BAT-0001');
        assert.throws(() => decryptPayload(blob, 'BAT-0002'));
    });

    it('rejects tampered ciphertext and short blobs', () => {
        const blob = encryptPayload('data', 'BAT-0001');
        blob[blob.length - 1] ^= 0xff;
        assert.throws(() => decryptPayload(blob, 'BAT-0001'));
        assert.throws(() => decryptPayload(Buffer.alloc(10), 'BAT-0001'));
    });

    it('iv is random (same plaintext, different blobs)', () => {
        const a = encryptPayload('data', 'BAT-0001');
        const b = encryptPayload('data', 'BAT-0001');
        assert.notEqual(a.toString('hex'), b.toString('hex'));
    });
});
