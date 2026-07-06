import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
    Cbor, CborArray, CborMap, CborBytes, CborUInt,
    blake2b_256, deriveEd25519PublicKey_sync, getEd25519Signature_sync
} from '@harmoniclabs/buildooor';
import { signTxCbor } from '../../srv/lib/tx-signer';

/**
 * Loads the BROWSER witness-merge module (sap.ui.define) via a tiny shim and
 * proves it produces byte-identical output to the server-side signer for a
 * real ODATANO build — the browser CIP-30 path and the server path must agree.
 */
function loadWalletLib(): any {
    const src = readFileSync(join(__dirname, '..', '..', 'app', 'producer', 'webapp', 'lib', 'cardano-wallet.js'), 'utf8');
    let exported: any = null;
    const sapShim = { ui: { define: (_deps: string[], factory: () => any) => { exported = factory(); } } };
    // eslint-disable-next-line no-new-func
    new Function('sap', 'window', src)(sapShim, {});
    return exported;
}

const fixture = JSON.parse(readFileSync(join(__dirname, '..', 'fixtures', 'unsigned-tx.json'), 'utf8')) as {
    unsignedTxCbor: string; txBodyHash: string;
};
const SEED = '11'.repeat(32);

/** Build the CIP-30-style witness set (map with key 0) a wallet would return. */
function walletWitnessSetHex(unsignedTxCbor: string, seedHex: string): string {
    const tx = Cbor.parse(unsignedTxCbor) as CborArray;
    const bodyHash = blake2b_256(Cbor.encode(tx.array[0]));
    const seed = new Uint8Array(Buffer.from(seedHex, 'hex'));
    const pub = Uint8Array.from(deriveEd25519PublicKey_sync(seed));
    const sig = Uint8Array.from(getEd25519Signature_sync(bodyHash, seed));
    const witnessSet = new CborMap([{
        k: new CborUInt(0),
        v: new CborArray([new CborArray([new CborBytes(pub), new CborBytes(sig)])])
    }]);
    return Buffer.from(Cbor.encode(witnessSet)).toString('hex');
}

describe('browser witness merge (cardano-wallet.js)', () => {
    const wallet = loadWalletLib();

    it('produces byte-identical output to the server signer', () => {
        const serverSigned = signTxCbor(fixture.unsignedTxCbor, SEED, fixture.txBodyHash).signedTxCbor;
        const walletWits = walletWitnessSetHex(fixture.unsignedTxCbor, SEED);
        const browserSigned = wallet.mergeWitnessSet(fixture.unsignedTxCbor, walletWits);
        assert.equal(browserSigned, serverSigned);
    });

    it('keeps the body byte-identical (txBodyHash stable)', () => {
        const walletWits = walletWitnessSetHex(fixture.unsignedTxCbor, SEED);
        const merged = wallet.mergeWitnessSet(fixture.unsignedTxCbor, walletWits);
        const tx = Cbor.parse(merged) as CborArray;
        assert.equal(Buffer.from(blake2b_256(Cbor.encode(tx.array[0]))).toString('hex'), fixture.txBodyHash);
    });

    it('bech32-encodes CIP-30 hex addresses', () => {
        // Testnet enterprise address bytes: 0x60 network 0 + 28-byte key hash.
        const hex = '60' + 'fa86ab6c36d5d32994cb6df00d40956386f6e7003e816a435aa9db88';
        const bech = wallet.addressHexToBech32(hex);
        assert.equal(bech, 'addr_test1vragd2mvxm2ax2v5edklqr2qj43cdah8qqlgz6jrt25ahzqp6kza6');
    });

    it('strips the CBOR byte-string wrapper Eternl/Lace add (TRACE pattern)', () => {
        const raw = '60' + 'fa86ab6c36d5d32994cb6df00d40956386f6e7003e816a435aa9db88'; // 29 bytes
        const wrapped = '581d' + raw; // 0x58 0x1d = bstr(29)
        assert.equal(wallet.stripCborByteString(wrapped), raw);
        assert.equal(wallet.stripCborByteString(raw), raw); // Nami-style raw passes through
        assert.equal(wallet.addressHexToBech32(wrapped), 'addr_test1vragd2mvxm2ax2v5edklqr2qj43cdah8qqlgz6jrt25ahzqp6kza6');
        assert.equal(wallet.addressHexToVkh(wrapped), 'fa86ab6c36d5d32994cb6df00d40956386f6e7003e816a435aa9db88');
    });
});
