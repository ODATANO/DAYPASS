import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
    unwrapCborByteString, scaledFieldValues, proverUrl,
    fetchPoseidonRoot, anchorOutdated, ZkProverUnreachableError
} from '../../srv/lib/zk-prover';
import { poseidonRootBytes, composeAnchor } from '../../srv/lib/metadata-composer';
import { blake2b256Hex } from '../../srv/lib/passport-anchor';

describe('unwrapCborByteString', () => {
    it('strips one 2-byte-length byte-string wrap (Julc getCborHex shape)', () => {
        // 59 0003 = byte string of 3 bytes
        assert.equal(unwrapCborByteString('590003aabbcc'), 'aabbcc');
    });
    it('strips a 1-byte-length wrap', () => {
        assert.equal(unwrapCborByteString('5803aabbcc'), 'aabbcc');
    });
    it('strips a short immediate-length wrap', () => {
        assert.equal(unwrapCborByteString('43aabbcc'), 'aabbcc');
    });
    it('rejects a wrap whose declared length does not span the rest', () => {
        assert.equal(unwrapCborByteString('590004aabbcc'), null);
    });
    it('rejects non-byte-string heads', () => {
        assert.equal(unwrapCborByteString('83010203'), null); // array
    });
});

describe('scaledFieldValues', () => {
    it('scales raw values x1000 and drops unknown or empty fields', () => {
        const out = scaledFieldValues({
            carbonFootprintKgCO2: '3412.75', capacityKwh: 75, notProvable: 1, recycledContentPct: ''
        } as any);
        assert.deepEqual(out, { carbonFootprintKgCO2: '3412750', capacityKwh: '75000' });
    });
});

describe('proverUrl', () => {
    it('is null when DAYPASS_ZK_PROVER_URL is unset', () => {
        delete process.env.DAYPASS_ZK_PROVER_URL;
        assert.equal(proverUrl(), null);
    });
    it('strips a trailing slash', () => {
        process.env.DAYPASS_ZK_PROVER_URL = 'http://localhost:8799/';
        assert.equal(proverUrl(), 'http://localhost:8799');
        delete process.env.DAYPASS_ZK_PROVER_URL;
    });
});

describe('fetchPoseidonRoot', () => {
    // 127.0.0.1:1 refuses connections immediately, no prover ever listens there.
    const DEAD = 'http://127.0.0.1:1';

    it('is null when the prover is not configured, even when required', async () => {
        delete process.env.DAYPASS_ZK_PROVER_URL;
        assert.equal(await fetchPoseidonRoot({ capacityKwh: 75 }, { required: true }), null);
    });
    it('throws ZkProverUnreachableError when required and the configured prover is down', async () => {
        process.env.DAYPASS_ZK_PROVER_URL = DEAD;
        await assert.rejects(
            fetchPoseidonRoot({ capacityKwh: 75 }, { required: true }),
            ZkProverUnreachableError
        );
        delete process.env.DAYPASS_ZK_PROVER_URL;
    });
    it('degrades to null without required (draft path)', async () => {
        process.env.DAYPASS_ZK_PROVER_URL = DEAD;
        assert.equal(await fetchPoseidonRoot({ capacityKwh: 75 }), null);
        delete process.env.DAYPASS_ZK_PROVER_URL;
    });
});

describe('anchorOutdated', () => {
    const H = 'aa'.repeat(32), H2 = 'bb'.repeat(32), ROOT = '123';
    it('re-attests on a changed payload', () => {
        assert.equal(anchorOutdated({ payloadHash: H2, rowPayloadHash: H, poseidonRoot: null, rowPoseidonRoot: null }), true);
    });
    it('re-attests an unchanged payload to add a now-available poseidonRoot', () => {
        assert.equal(anchorOutdated({ payloadHash: H, rowPayloadHash: H, poseidonRoot: ROOT, rowPoseidonRoot: null }), true);
    });
    it('is a no-op when payload and poseidonRoot are both anchored', () => {
        assert.equal(anchorOutdated({ payloadHash: H, rowPayloadHash: H, poseidonRoot: ROOT, rowPoseidonRoot: ROOT }), false);
    });
    it('is a no-op when unchanged and ZK is disabled', () => {
        assert.equal(anchorOutdated({ payloadHash: H, rowPayloadHash: H, poseidonRoot: null, rowPoseidonRoot: null }), false);
    });
});

describe('predicate anchor metadata', () => {
    it('renders result as integer and poseidonRoot as bytes, never booleans', () => {
        const anchor = composeAnchor({
            op: 'predicate', passportId: 'P', passportIdHash: blake2b256Hex('P'),
            poseidonRoot: '255', fieldKey: blake2b256Hex('carbonFootprintKgCO2'),
            predicate: 'lessOrEqual', threshold: 4000000, result: true
        });
        assert.equal(anchor.result, 1);
        assert.equal(anchor.poseidonRoot, '0x' + '0'.repeat(62) + 'ff');
        const walk = (v: unknown): void => {
            assert.notEqual(typeof v, 'boolean');
            if (v && typeof v === 'object') Object.values(v).forEach(walk);
        };
        walk(anchor);
    });
});

describe('poseidonRootBytes', () => {
    it('renders a decimal field element as 32-byte 0x hex', () => {
        assert.equal(poseidonRootBytes('255'), '0x' + '0'.repeat(62) + 'ff');
    });
    it('accepts a full-width BLS12-381 element', () => {
        const dec = '51085689631127762597862216412115504216034925065481983110841169560486499710249';
        const hex = poseidonRootBytes(dec);
        assert.equal(hex.length, 66);
        assert.equal(BigInt(hex).toString(10), dec);
    });
    it('rejects non-decimal input', () => {
        assert.throws(() => poseidonRootBytes('0xff'));
    });
    it('rejects values above 32 bytes', () => {
        assert.throws(() => poseidonRootBytes((1n << 256n).toString(10)));
    });
});
