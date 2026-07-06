import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { payloadFromRows, parsePassportInput } from '../../srv/lib/passport-payload';
import { hashPayload } from '../../srv/lib/passport-anchor';

describe('payloadFromRows', () => {
    it('is stable across input-vs-DB round trips (string decimals, extra fields, order)', () => {
        const fromInput = payloadFromRows({
            passportId: 'BAT-1', manufacturerId: 'M', weightKg: 432.5,
            batteries: [
                { serialNumber: 'B', capacityKwh: 75, cellChemistry: 'NMC-811', unknownField: 'ignored' },
                { serialNumber: 'A', capacityKwh: 60 }
            ],
            recycledMaterials: [{ material: 'Li', recycledPercentage: 12.25 }, { material: 'Co', recycledPercentage: 16.5 }]
        });
        // Same data, DB-shaped: decimals as strings, arrays in other order, extra DB columns.
        const fromDb = payloadFromRows({
            passportId: 'BAT-1', manufacturerId: 'M', weightKg: '432.500',
            batteries: [
                { ID: 'x', passport_ID: 'y', serialNumber: 'A', capacityKwh: '60.000' },
                { ID: 'z', passport_ID: 'y', serialNumber: 'B', capacityKwh: '75.000', cellChemistry: 'NMC-811' }
            ],
            recycledMaterials: [
                { ID: 'a', material: 'Co', recycledPercentage: '16.50' },
                { ID: 'b', material: 'Li', recycledPercentage: '12.25' }
            ]
        });
        assert.equal(hashPayload(fromInput).payloadHash, hashPayload(fromDb).payloadHash);
        assert.equal((fromInput.batteries as any[])[0].serialNumber, 'A'); // sorted
    });

    it('drops nulls and empty strings, keeps zero', () => {
        const p = payloadFromRows({
            passportId: 'BAT-2', model: '', manufacturerId: null,
            batteries: [{ serialNumber: 'S', leadContentPpm: 0, supplierName: null }]
        });
        assert.equal('model' in p, false);
        assert.equal('manufacturerId' in p, false);
        assert.equal((p.batteries as any[])[0].leadContentPpm, 0);
        assert.equal('supplierName' in (p.batteries as any[])[0], false);
    });

    it('rejects non-numeric numerics', () => {
        assert.throws(() => payloadFromRows({ passportId: 'X', weightKg: 'heavy' }), /not a number/);
    });
});

describe('parsePassportInput', () => {
    it('accepts a NIGHTPASS-shaped payload', () => {
        const input = parsePassportInput(JSON.stringify({
            passportId: 'BAT-PREVIEW-0001', manufacturerId: 'DE-CELLCO-001',
            batteries: [{ serialNumber: 'SN-1' }]
        }));
        assert.equal(input.passportId, 'BAT-PREVIEW-0001');
    });
    it('rejects garbage', () => {
        assert.throws(() => parsePassportInput('not json'), /not valid JSON/);
        assert.throws(() => parsePassportInput('[]'), /JSON object/);
        assert.throws(() => parsePassportInput('{}'), /passportId is required/);
        assert.throws(() => parsePassportInput(JSON.stringify({ passportId: 'x', batteries: 'nope' })), /must be an array/);
        assert.throws(() => parsePassportInput(JSON.stringify({ passportId: 'x', weightKg: 'heavy' })), /weightKg/);
    });
});
