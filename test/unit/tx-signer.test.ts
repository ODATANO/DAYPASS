import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Cbor, CborArray, CborMap, CborUInt, CborBytes, verifyEd25519Signature_sync, blake2b_256 } from '@harmoniclabs/buildooor';
import { signTxCbor, publicKeyFromSeed, paymentKeyHashFromSeed } from '../../srv/lib/tx-signer';

const fixture = JSON.parse(readFileSync(join(__dirname, '..', 'fixtures', 'unsigned-tx.json'), 'utf8')) as {
    unsignedTxCbor: string; txBodyHash: string;
};

// Any 32-byte seed works for the structural tests (fixture body is unsigned).
const TEST_SEED = '11'.repeat(32);

describe('tx-signer', () => {
    it('signs a real ODATANO build and keeps the body byte-identical', () => {
        const result = signTxCbor(fixture.unsignedTxCbor, TEST_SEED, fixture.txBodyHash);
        assert.equal(result.txBodyHash, fixture.txBodyHash);
        assert.equal(result.publicKeyHex, publicKeyFromSeed(TEST_SEED));

        // Re-parse the signed tx: body hash unchanged, witness present.
        const tx = Cbor.parse(result.signedTxCbor) as CborArray;
        assert.equal(Buffer.from(blake2b_256(Cbor.encode(tx.array[0]))).toString('hex'), fixture.txBodyHash);

        const wits = tx.array[1] as CborMap;
        const vkeyEntry = wits.map.find((e) => e.k instanceof CborUInt && e.k.num === 0n);
        assert.ok(vkeyEntry, 'vkey witness entry (key 0) missing');
        const witnessList = vkeyEntry!.v as CborArray;
        assert.equal(witnessList.array.length, 1);
        const [pubObj, sigObj] = (witnessList.array[0] as CborArray).array as [CborBytes, CborBytes];
        assert.equal(Buffer.from(pubObj.bytes).toString('hex'), result.publicKeyHex);
        assert.equal(sigObj.bytes.length, 64);

        // The signature must verify against the body hash.
        const bodyHash = blake2b_256(Cbor.encode(tx.array[0]));
        assert.ok(verifyEd25519Signature_sync(sigObj.bytes, bodyHash, pubObj.bytes));
    });

    it('signing twice replaces the witness instead of stacking', () => {
        const once = signTxCbor(fixture.unsignedTxCbor, TEST_SEED, fixture.txBodyHash);
        const twice = signTxCbor(once.signedTxCbor, '22'.repeat(32), fixture.txBodyHash);
        const wits = (Cbor.parse(twice.signedTxCbor) as CborArray).array[1] as CborMap;
        const vkeyEntry = wits.map.find((e) => e.k instanceof CborUInt && e.k.num === 0n)!;
        assert.equal((vkeyEntry.v as CborArray).array.length, 1);
    });

    it('rejects a wrong expected body hash', () => {
        assert.throws(
            () => signTxCbor(fixture.unsignedTxCbor, TEST_SEED, 'ab'.repeat(32)),
            /body-hash mismatch/
        );
    });

    it('rejects malformed seeds and CBOR', () => {
        assert.throws(() => signTxCbor(fixture.unsignedTxCbor, 'abcd'), /seed must be 32 bytes/);
        assert.throws(() => signTxCbor('81a0', TEST_SEED), /unexpected tx CBOR shape/);
        assert.throws(() => signTxCbor('828080', TEST_SEED), /witness set is not a map/);
    });

    it('derives the known producer paymentKeyHash from its public key scheme', () => {
        // Structural check: 28-byte hex, deterministic.
        const pkh = paymentKeyHashFromSeed(TEST_SEED);
        assert.match(pkh, /^[0-9a-f]{56}$/);
        assert.equal(pkh, paymentKeyHashFromSeed(TEST_SEED));
    });
});
