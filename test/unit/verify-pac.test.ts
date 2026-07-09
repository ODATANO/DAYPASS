import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeCbor, datumPublicInputs, fieldKeyFe, bytesToBigIntBE,
  loadPinnedPolicies, isPolicyTrusted, checkZkPredicate, findPredicateToken, blake2b256HexUtf8,
  predicateTokenName
} from '../../tractusx/pac/verify-pac.mjs';
import { buildPacJson } from '../../srv/lib/catenax';

// --- tiny CBOR encoder, only what a Plutus datum needs -----------------------
function encUint(n: bigint): number[] {
  if (n < 24n) return [Number(n)];
  if (n < 256n) return [0x18, Number(n)];
  if (n < 65536n) return [0x19, Number(n >> 8n), Number(n & 0xffn)];
  const bytes: number[] = [];
  let v = n; for (let i = 0; i < 8; i++) { bytes.unshift(Number(v & 0xffn)); v >>= 8n; }
  return [0x1b, ...bytes];
}
function encBignum(n: bigint): number[] {
  const bytes: number[] = [];
  let v = n; while (v > 0n) { bytes.unshift(Number(v & 0xffn)); v >>= 8n; }
  if (bytes.length === 0) bytes.push(0);
  const head = bytes.length < 24 ? [0x40 | bytes.length] : [0x58, bytes.length];
  return [0xc2, ...head, ...bytes]; // tag 2 (positive bignum) + byte string
}
function encList4(items: number[][]): Uint8Array {
  return Uint8Array.from([0x84, ...items.flat()]);
}
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

test('decodeCbor + datumPublicInputs round-trips a [bignum, bignum, uint, uint] list', () => {
  const root = 12345678901234567890123456789012345678901234567890n;
  const fk = fieldKeyFe('carbonFootprintKgCO2');
  const datum = encList4([encBignum(root), encBignum(fk), encUint(4000000n), encUint(1n)]);
  const inputs = datumPublicInputs(datum);
  assert.deepEqual(inputs, [root, fk, 4000000n, 1n]);
  // hex input path
  assert.deepEqual(datumPublicInputs(toHex(datum)), [root, fk, 4000000n, 1n]);
});

test('decodeCbor unwraps a constr-wrapped datum', () => {
  const inner = encList4([encUint(1n), encUint(2n), encUint(3n), encUint(4n)]);
  const wrapped = Uint8Array.from([0xd8, 0x79, ...inner]); // tag 121 -> constr 0
  const dec: any = decodeCbor(wrapped);
  assert.equal(dec.constr, 0);
  assert.deepEqual(datumPublicInputs(wrapped), [1n, 2n, 3n, 4n]);
});

test('fieldKeyFe is the first 31 bytes of blake2b256(name), != the 32-byte metadata key', () => {
  const name = 'recycledContentPct';
  const full = blake2b256HexUtf8(name);            // 32-byte metadata fieldKey
  const fe = fieldKeyFe(name);                      // 31-byte datum field element
  assert.equal(fe, bytesToBigIntBE(Uint8Array.from(Buffer.from(full.slice(0, 62), 'hex'))));
  assert.notEqual(fe, BigInt('0x' + full));
});

test('policy trust: default-deny, opts in via extra/env/registry', () => {
  const P = 'a'.repeat(56);
  // empty registry + no override -> nothing trusted
  const none = loadPinnedPolicies('preview', { registry: { policies: {} }, env: '' });
  assert.equal(isPolicyTrusted(P, 'lessOrEqual', none), false);
  // CLI/extra override
  const viaExtra = loadPinnedPolicies('preview', { registry: { policies: {} }, extra: [P], env: '' });
  assert.equal(isPolicyTrusted(P, 'lessOrEqual', viaExtra), true);
  assert.equal(isPolicyTrusted(P, 'greaterOrEqual', viaExtra), true);
  // env override
  const viaEnv = loadPinnedPolicies('preview', { registry: { policies: {} }, env: `0x${P}` });
  assert.equal(isPolicyTrusted(P, 'lessOrEqual', viaEnv), true);
  // registry file entry, scoped to the operator
  const viaReg = loadPinnedPolicies('preview', {
    registry: { policies: { 'cardano-preview': { lessOrEqual: P } } }, env: ''
  });
  assert.equal(isPolicyTrusted(P, 'lessOrEqual', viaReg), true);
  assert.equal(isPolicyTrusted(P, 'greaterOrEqual', viaReg), false); // not pinned for gte
});

// --- checkZkPredicate: build a fully-valid on-chain fixture, then tamper ------
const POLICY = 'a'.repeat(56);
const PASSPORT = 'BAT-TEST-1';
const FIELD = 'carbonFootprintKgCO2';
const MINT_TX = 'b'.repeat(64);
const ROOT = 98765432109876543210987654321098765432109876543210n;

// Tokens minted before core 1.9.5 carry only the TRAILING slice of the
// passportIdHash as their asset name (odatano bug #9); newer mints carry the
// full 64-hex hash. The verifier's suffix check must accept both, so the main
// fixture keeps the legacy sliced name and a dedicated test covers the full name.
const PID_HASH = blake2b256HexUtf8(PASSPORT);
const ASSET_NAME = PID_HASH.slice(56); // legacy: last 4 bytes / 8 hex

function fixture() {
  const datum = encList4([encBignum(ROOT), encBignum(fieldKeyFe(FIELD)), encUint(4000000n), encUint(1n)]);
  const subject = { passportId: PASSPORT, passportIdHash: PID_HASH };
  const proof = {
    sourceField: FIELD, operator: 'lessOrEqual', threshold: '4000000',
    verifierPolicyId: POLICY, transactionHash: '0x' + MINT_TX
  };
  const chain = {
    asset: { quantity: '1', initial_mint_tx_hash: MINT_TX },
    utxos: { outputs: [{ output_index: 0, inline_datum: toHex(datum), amount: [{ unit: 'lovelace', quantity: '1500000' }, { unit: POLICY + ASSET_NAME, quantity: '1' }] }] },
    metadata: [{ label: '1155', json_metadata: { op: 'predicate', passportId: PASSPORT, predicate: 'lessOrEqual', threshold: 4000000, fieldKey: blake2b256HexUtf8(FIELD), result: 1 } }],
    anchorPoseidonRootDecimal: ROOT
  };
  const trusted = loadPinnedPolicies('preview', { registry: { policies: {} }, extra: [POLICY], env: '' });
  return { subject, proof, chain, trusted };
}
const allOk = (rows: any[]) => rows.every(([, ok]) => ok);

test('findPredicateToken returns the single token under the policy with its sliced name', () => {
  const utxos = { outputs: [{ output_index: 0, amount: [{ unit: 'lovelace', quantity: '2' }, { unit: POLICY + ASSET_NAME, quantity: '1' }] }] };
  assert.deepEqual(findPredicateToken(utxos, POLICY), { unit: POLICY + ASSET_NAME, assetName: ASSET_NAME, quantity: 1n });
  // no token / ambiguous -> null
  assert.equal(findPredicateToken({ outputs: [{ amount: [{ unit: 'lovelace', quantity: '2' }] }] }, POLICY), null);
});

test('checkZkPredicate passes for a valid, pinned, passport-bound predicate mint', () => {
  const { subject, proof, chain, trusted } = fixture();
  const rows = checkZkPredicate(proof, subject, chain, trusted, '1155');
  assert.ok(allOk(rows), 'all checks pass: ' + JSON.stringify(rows.filter((r: any) => !r[1])));
});

test('checkZkPredicate passes for a token named with the FULL passportIdHash (core >=1.9.5 mints)', () => {
  const { subject, proof, chain, trusted } = fixture();
  const datum = encList4([encBignum(ROOT), encBignum(fieldKeyFe(FIELD)), encUint(4000000n), encUint(1n)]);
  const fullName = {
    ...chain,
    utxos: { outputs: [{ output_index: 0, inline_datum: toHex(datum), amount: [{ unit: 'lovelace', quantity: '1500000' }, { unit: POLICY + PID_HASH, quantity: '1' }] }] }
  };
  const rows = checkZkPredicate(proof, subject, fullName, trusted, '1155');
  assert.ok(allOk(rows), 'all checks pass: ' + JSON.stringify(rows.filter((r: any) => !r[1])));
});

test('checkZkPredicate passes for a policy-v2 token named by the datum commitment', () => {
  const { subject, proof, chain, trusted } = fixture();
  const publics = [ROOT, fieldKeyFe(FIELD), 4000000n, 1n];
  const datum = encList4([encBignum(ROOT), encBignum(fieldKeyFe(FIELD)), encUint(4000000n), encUint(1n)]);
  const v2Name = predicateTokenName(publics);
  const v2 = {
    ...chain,
    utxos: { outputs: [{ output_index: 0, inline_datum: toHex(datum), amount: [{ unit: 'lovelace', quantity: '1500000' }, { unit: POLICY + v2Name, quantity: '1' }] }] }
  };
  const rows = checkZkPredicate(proof, subject, v2, trusted, '1155');
  assert.ok(allOk(rows), 'all checks pass: ' + JSON.stringify(rows.filter((r: any) => !r[1])));
});

test('checkZkPredicate rejects a token whose name commits to neither datum nor passport', () => {
  const { subject, proof, chain, trusted } = fixture();
  const datum = encList4([encBignum(ROOT), encBignum(fieldKeyFe(FIELD)), encUint(4000000n), encUint(1n)]);
  const bogus = {
    ...chain,
    utxos: { outputs: [{ output_index: 0, inline_datum: toHex(datum), amount: [{ unit: 'lovelace', quantity: '1500000' }, { unit: POLICY + 'ff'.repeat(28), quantity: '1' }] }] }
  };
  const rows = checkZkPredicate(proof, subject, bogus, trusted, '1155');
  assert.equal(allOk(rows), false);
  assert.ok(rows.some((r: any) => /bound to the proof/.test(r[0]) && !r[1]));
});

test('checkZkPredicate rejects an untrusted verifier policy (the core forgery guard)', () => {
  const { subject, proof, chain, trusted } = fixture();
  const forged = { ...proof, verifierPolicyId: 'c'.repeat(56) }; // some trivial always-mint policy
  const rows = checkZkPredicate(forged, subject, chain, trusted, '1155');
  assert.equal(allOk(rows), false);
  assert.ok(rows.some((r: any) => /pinned\/trusted/.test(r[0]) && !r[1]));
});

test('checkZkPredicate rejects a proof bound to a different poseidonRoot (valid-proof, wrong passport)', () => {
  const { subject, proof, chain, trusted } = fixture();
  const tampered = { ...chain, anchorPoseidonRootDecimal: ROOT + 1n };
  const rows = checkZkPredicate(proof, subject, tampered, trusted, '1155');
  assert.equal(allOk(rows), false);
  assert.ok(rows.some((r: any) => /anchored root/.test(r[0]) && !r[1]));
});

test('checkZkPredicate rejects a datum threshold that does not match the claim', () => {
  const { subject, proof, chain, trusted } = fixture();
  const datum = encList4([encBignum(ROOT), encBignum(fieldKeyFe(FIELD)), encUint(9999n), encUint(1n)]);
  const tampered = { ...chain, utxos: { outputs: [{ output_index: 0, inline_datum: toHex(datum), amount: [{ unit: POLICY + ASSET_NAME, quantity: '1' }] }] } };
  const rows = checkZkPredicate(proof, subject, tampered, trusted, '1155');
  assert.ok(rows.some((r: any) => /datum threshold/.test(r[0]) && !r[1]));
});

test('checkZkPredicate rejects a token not minted by the referenced tx', () => {
  const { subject, proof, chain, trusted } = fixture();
  const tampered = { ...chain, asset: { quantity: '1', initial_mint_tx_hash: 'f'.repeat(64) } };
  const rows = checkZkPredicate(proof, subject, tampered, trusted, '1155');
  assert.ok(rows.some((r: any) => /minted by this tx/.test(r[0]) && !r[1]));
});

// --- PAC export carries the portable-verification material -------------------
test('buildPacJson exports verifierPolicyId + public inputs for a zk proof', () => {
  const passport = {
    passportId: PASSPORT, passportIdHash: blake2b256HexUtf8(PASSPORT),
    payloadHash: 'aa'.repeat(32), batteryCategory: 'EV', model: 'X', manufacturerId: 'DE-1',
    unit: POLICY + 'dd', policyId: POLICY, fingerprint: 'asset1x',
    attestationTxHash: MINT_TX, lastAnchorTxHash: MINT_TX, anchorVersion: 2, status: 'anchored'
  };
  const proofRow = {
    mode: 'zk', sourceField: FIELD, predicate: 'lessOrEqual', threshold: '4000000', unit: 'kg CO2e',
    txHash: MINT_TX, result: true, status: 'confirmed',
    proofJson: JSON.stringify({ policyId: POLICY, assetNameHex: 'ab'.repeat(28), poseidonRoot: ROOT.toString(), fieldKey: fieldKeyFe(FIELD).toString(), threshold: '4000000' })
  };
  const pac = JSON.parse(buildPacJson({ passport, proofs: [proofRow] }));
  const zk = pac.credentialSubject.predicateProofs[0];
  assert.equal(pac.credentialSubject.passportIdHash, blake2b256HexUtf8(PASSPORT));
  assert.equal(zk.disclosureMode, 'zkPredicate');
  assert.equal(zk.verifierPolicyId, POLICY);
  // v2: the prover-supplied datum commitment; legacy rows fall back to passportIdHash
  assert.equal(zk.predicateAssetName, 'ab'.repeat(28));
  const legacyRow = { ...proofRow, proofJson: JSON.stringify({ policyId: POLICY, poseidonRoot: ROOT.toString(), fieldKey: fieldKeyFe(FIELD).toString(), threshold: '4000000' }) };
  const legacyPac = JSON.parse(buildPacJson({ passport, proofs: [legacyRow] }));
  assert.equal(legacyPac.credentialSubject.predicateProofs[0].predicateAssetName, blake2b256HexUtf8(PASSPORT));
  assert.equal(zk.publicInputs.poseidonRoot, ROOT.toString());
  assert.equal(zk.publicInputs.fieldKey, fieldKeyFe(FIELD).toString());
  assert.equal(zk.publicInputs.threshold, '4000000');
  assert.equal(zk.verificationModel, 'cardano-onchain-groth16-mint');
});
