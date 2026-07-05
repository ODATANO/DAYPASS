// Portable PAC verifier: checks a DAYPASS PredicateAttestationCredential
// against Cardano DIRECTLY via Blockfrost — no DAYPASS server, no plugin.
//
//   node tractusx/pac/verify-pac.mjs <pac.json> [BLOCKFROST_API_KEY]
//
// Checks:
//   1. the attestation (mint) tx exists on-chain
//   2. the anchor metadata on lastAnchorTxHash carries the credential's
//      payloadHash + a contentRoot under the stated metadata label
//   3. the passport NFT exists (or is burned when status says revoked)
//   4. every revealed-value proof folds through its Merkle inclusion path to
//      the ON-CHAIN contentRoot (fieldKey matches the claimed sourceField)
//   5. every zk predicate proof's tx exists on-chain
//
// Standalone dependencies: @noble/hashes only (npm i @noble/hashes).
import { readFileSync } from 'node:fs';
import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex } from '@noble/hashes/utils';

// --- DAYPASS Merkle scheme (must match srv/lib/passport-anchor.ts) -----------
const MERKLE_DEPTH = 4;
const DOMAIN_LEAF = new TextEncoder().encode('daypass/leaf/v1');
const DOMAIN_NODE = new TextEncoder().encode('daypass/node/v1');
const b2b256 = (bytes) => blake2b(bytes, { dkLen: 32 });
const fromHex = (hex) => Uint8Array.from(String(hex).replace(/^0x/, '').match(/.{2}/g).map((b) => parseInt(b, 16)));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
function u64be(v) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(v));
  return out;
}
const leafHash = (fieldKey, value) => b2b256(concat(DOMAIN_LEAF, fieldKey, u64be(value)));
const nodeHash = (l, r) => b2b256(concat(DOMAIN_NODE, l, r));
const blake2b256HexUtf8 = (s) => bytesToHex(b2b256(new TextEncoder().encode(s)));

function foldProof(proof) {
  let node = leafHash(fromHex(proof.fieldKey), proof.value);
  for (let d = 0; d < MERKLE_DEPTH; d++) {
    const sibling = fromHex(proof.siblings[d]);
    node = proof.dirs[d] ? nodeHash(node, sibling) : nodeHash(sibling, node);
  }
  return bytesToHex(node);
}

// --- Blockfrost ----------------------------------------------------------------
const pacPath = process.argv[2];
const apiKey = process.argv[3] || process.env.BLOCKFROST_API_KEY;
if (!pacPath || !apiKey) {
  console.error('usage: node verify-pac.mjs <pac.json> [BLOCKFROST_API_KEY]  (or set BLOCKFROST_API_KEY)');
  process.exit(1);
}
const pac = JSON.parse(readFileSync(pacPath, 'utf8'));
const subject = pac.credentialSubject ?? {};
const att = subject.attestation ?? {};
const network = String(att.chain ?? 'cardano-preview').replace(/^cardano-/, '');
const BF = `https://cardano-${network}.blockfrost.io/api/v0`;

async function bf(path) {
  const res = await fetch(`${BF}${path}`, { headers: { project_id: apiKey } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Blockfrost ${path} -> HTTP ${res.status}`);
  return res.json();
}

const results = [];
const check = (name, ok, detail = '') => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` (${detail})` : ''}`); };
const clean = (h) => String(h ?? '').replace(/^0x/, '');

console.log(`PAC: ${subject.passportId} on cardano-${network}\n`);

// 1. attestation tx exists
const mintTx = await bf(`/txs/${clean(att.transactionHash)}`);
check('attestation (mint) tx exists on-chain', !!mintTx, clean(att.transactionHash));

// 2. anchor metadata on the last anchor tx
const label = String(att.anchorMetadataLabel ?? 1155);
const meta = await bf(`/txs/${clean(att.lastAnchorTxHash)}/metadata`);
const anchorRow = (meta ?? []).find((m) => String(m.label) === label);
const anchor = anchorRow?.json_metadata ?? null;
check(`anchor metadata present under label ${label}`, !!anchor);
const onChainPayloadHash = clean(anchor?.payloadHash);
check('on-chain payloadHash matches credential', !!anchor && onChainPayloadHash === clean(subject.payloadHash));
const onChainRoot = clean(anchor?.contentRoot);
check('on-chain contentRoot present', /^[0-9a-f]{64}$/.test(onChainRoot));

// 3. NFT state
if (att.unit) {
  const asset = await bf(`/assets/${att.unit}`);
  const qty = asset ? String(asset.quantity) : 'absent';
  if (att.status === 'revoked') check('NFT burned (quantity 0)', qty === '0', `quantity=${qty}`);
  else check('NFT exists (quantity 1)', qty === '1', `quantity=${qty}`);
}

// 4 + 5. proofs
for (const proof of subject.predicateProofs ?? []) {
  if (proof.disclosureMode === 'revealedValue+merkleInclusion') {
    const mp = proof.merkleProof;
    const label = `merkle proof: ${proof.sourceField} = ${proof.value}`;
    if (!mp || !onChainRoot) { check(label, false, 'no proof or no on-chain root'); continue; }
    const fieldKeyOk = clean(mp.fieldKey) === blake2b256HexUtf8(proof.sourceField);
    const folded = foldProof(mp);
    check(label, fieldKeyOk && folded === onChainRoot,
      fieldKeyOk ? (folded === onChainRoot ? 'folds to on-chain root' : `fold mismatch ${folded}`) : 'fieldKey does not match sourceField');
  } else if (proof.disclosureMode === 'zkPredicate') {
    const tx = await bf(`/txs/${clean(proof.transactionHash)}`);
    check(`zk predicate tx exists: ${proof.sourceField} ${proof.operator} ${proof.threshold}`, !!tx);
  }
}

const verified = results.length > 0 && results.every(Boolean);
console.log(`\n${verified ? 'PAC VERIFIED' : 'PAC VERIFICATION FAILED'} (${results.filter(Boolean).length}/${results.length} checks)`);
process.exit(verified ? 0 : 1);
