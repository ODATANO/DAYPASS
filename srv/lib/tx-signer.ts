import {
    Cbor, CborArray, CborMap, CborBytes, CborUInt,
    blake2b_256, deriveEd25519PublicKey_sync, getEd25519Signature_sync, verifyEd25519Signature_sync
} from '@harmoniclabs/buildooor';
import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex } from '@noble/hashes/utils';

/**
 * Server-mode transaction signer.
 *
 * Works on GENERIC CBOR, not the typed `Tx` class: cardano-ledger-ts cannot
 * round-trip the tag-259 AuxiliaryData that buildooor emits ("Invalid CBOR
 * format for AuxiliaryData"). Parsed CBOR nodes keep their SubCborRef, so
 * untouched parts (body, aux data) re-encode byte-identically — which the
 * body-hash checks below enforce on EVERY sign, before and after the witness
 * splice. A drifting body would invalidate the Ed25519 signature and, for the
 * aux data, break the body's auxiliary_data_hash.
 */

export interface SignResult {
    /** Full signed transaction CBOR (hex). */
    signedTxCbor: string;
    /** blake2b-256 of the (unchanged) tx body = the future txHash. */
    txBodyHash: string;
    /** Ed25519 public key (hex) that signed. */
    publicKeyHex: string;
}

const toHex = (u8: Uint8Array): string => Buffer.from(u8).toString('hex');

/** Derive the Ed25519 public key (hex) for a 32-byte seed (hex). */
export function publicKeyFromSeed(seedHex: string): string {
    return toHex(Uint8Array.from(deriveEd25519PublicKey_sync(seedFromHex(seedHex))));
}

/** Cardano payment key hash (28-byte blake2b-224 of the public key, hex). */
export function paymentKeyHashFromSeed(seedHex: string): string {
    const pub = Uint8Array.from(deriveEd25519PublicKey_sync(seedFromHex(seedHex)));
    return bytesToHex(blake2b(pub, { dkLen: 28 }));
}

function seedFromHex(seedHex: string): Uint8Array {
    if (!/^[0-9a-fA-F]{64}$/.test(seedHex)) {
        throw new Error('signing seed must be 32 bytes hex (64 hex chars)');
    }
    return new Uint8Array(Buffer.from(seedHex, 'hex'));
}

/**
 * Sign an unsigned transaction CBOR with an Ed25519 seed and splice the vkey
 * witness into the witness set (map key 0, replacing any placeholder).
 *
 * @param expectedTxBodyHash optional 64-hex body hash from the build (e.g.
 *   ODATANO `TransactionBuilds.txBodyHash`); when given, both body-hash checks
 *   compare against it, otherwise against the freshly computed body hash.
 */
export function signTxCbor(unsignedTxCborHex: string, seedHex: string, expectedTxBodyHash?: string): SignResult {
    const seed = seedFromHex(seedHex);
    const parsedTx = Cbor.parse(unsignedTxCborHex);
    if (!(parsedTx instanceof CborArray) || parsedTx.array.length < 2) {
        throw new Error('unexpected tx CBOR shape (want [body, witnessSet, ...])');
    }
    if (!(parsedTx.array[1] instanceof CborMap)) {
        throw new Error('unexpected tx CBOR shape (witness set is not a map)');
    }

    // Before: the re-encoded body must match the builder's body hash.
    const bodyHash = blake2b_256(Cbor.encode(parsedTx.array[0]));
    const bodyHashHex = toHex(bodyHash);
    if (expectedTxBodyHash && bodyHashHex !== expectedTxBodyHash.toLowerCase()) {
        throw new Error(`body-hash mismatch before signing: ${bodyHashHex} != expected ${expectedTxBodyHash}`);
    }

    const pub = Uint8Array.from(deriveEd25519PublicKey_sync(seed));
    const sig = Uint8Array.from(getEd25519Signature_sync(bodyHash, seed));
    if (pub.length !== 32 || sig.length !== 64) {
        throw new Error(`unexpected key/signature lengths: ${pub.length}/${sig.length}`);
    }
    if (!verifyEd25519Signature_sync(sig, bodyHash, pub)) {
        throw new Error('self-verification of Ed25519 signature failed');
    }

    // Replace/insert the vkey-witness entry (key 0). The build may contain a
    // size-estimation placeholder there; ours is the real one.
    const vkeyWitness = new CborArray([new CborBytes(pub), new CborBytes(sig)]);
    const witnessSet = parsedTx.array[1] as CborMap;
    const entries = witnessSet.map.filter((e) => !(e.k instanceof CborUInt && e.k.num === 0n));
    entries.push({ k: new CborUInt(0), v: new CborArray([vkeyWitness]) });
    const signedTx = new CborArray([parsedTx.array[0], new CborMap(entries), ...parsedTx.array.slice(2)]);
    const signedTxCbor = toHex(Cbor.encode(signedTx));

    // After: re-parse the signed CBOR and prove the body bytes survived.
    const recheck = Cbor.parse(signedTxCbor) as CborArray;
    const afterHex = toHex(blake2b_256(Cbor.encode(recheck.array[0])));
    if (afterHex !== bodyHashHex) {
        throw new Error(`body bytes changed during witness splice: ${afterHex} != ${bodyHashHex}`);
    }

    return { signedTxCbor, txBodyHash: bodyHashHex, publicKeyHex: toHex(pub) };
}
