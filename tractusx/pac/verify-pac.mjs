// Portable PAC verifier: checks a DAYPASS PredicateAttestationCredential
// against Cardano DIRECTLY via Blockfrost — no DAYPASS server, no plugin.
//
//   node tractusx/pac/verify-pac.mjs <pac.json> [BLOCKFROST_API_KEY] \
//        [--trust-verifier-policy=<hash>[,<hash>]]
//
// Checks:
//   1. the attestation (mint) tx exists on-chain
//   2. the anchor metadata on lastAnchorTxHash carries the credential's
//      payloadHash + a contentRoot under the stated metadata label
//   3. the passport NFT exists (or is burned when status says revoked)
//   4. every revealed-value proof folds through its Merkle inclusion path to
//      the ON-CHAIN contentRoot (fieldKey matches the claimed sourceField)
//   5. every zk predicate proof is a REAL on-chain Groth16 attestation:
//      - minted under a PINNED verifier policy (trust root, see
//        verifier-policies.json), never merely "some tx exists"
//      - the predicate token's asset name commits to the public inputs
//        (policy v2: blake2b-224 over the serialised datum; legacy tokens:
//        a passportIdHash suffix)
//      - the token output's inline datum public inputs bind to THIS passport:
//        poseidonRoot == the anchored root, fieldKey == blake2b31(sourceField),
//        threshold == the claimed threshold, isCompliant == 1
//      - the predicate anchor metadata names the same passport/field/predicate
//
// Standalone dependencies: @noble/hashes only (npm i @noble/hashes).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex } from '@noble/hashes/utils';

// --- DAYPASS hashing (must match srv/lib/passport-anchor.ts + the prover) -----
const MERKLE_DEPTH = 4;
const DOMAIN_LEAF = new TextEncoder().encode('daypass/leaf/v1');
const DOMAIN_NODE = new TextEncoder().encode('daypass/node/v1');
const b2b256 = (bytes) => blake2b(bytes, { dkLen: 32 });
export const fromHex = (hex) => Uint8Array.from(String(hex).replace(/^0x/, '').match(/.{2}/g).map((b) => parseInt(b, 16)));
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
export const blake2b256HexUtf8 = (s) => bytesToHex(b2b256(new TextEncoder().encode(s)));

// Field-element id of a provable field: first 31 bytes of blake2b256(name) as an
// unsigned big-endian integer. Byte-identical to PoseidonTree.fieldKeyFe (Java).
export function fieldKeyFe(fieldName) {
  const h = b2b256(new TextEncoder().encode(fieldName));
  return bytesToBigIntBE(h.slice(0, 31));
}

export function bytesToBigIntBE(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

// The v2 predicate token name: blake2b-224 over the canonical plutus-core
// serialiseData CBOR of the public-input list (indefinite-length list, tag-2
// bignums above 2^64). Mirrors DAYZERO's daypassPredicateAssetName, which is
// locked against the on-chain Aiken derivation by a generated differential test.
function cborHeadU(major, value) {
  const base = major << 5;
  if (value < 24n) return [base + Number(value)];
  if (value < 1n << 8n) return [base + 24, Number(value)];
  if (value < 1n << 16n) return [base + 25, Number(value >> 8n), Number(value & 0xffn)];
  if (value < 1n << 32n) return [base + 26, Number(value >> 24n & 0xffn), Number(value >> 16n & 0xffn), Number(value >> 8n & 0xffn), Number(value & 0xffn)];
  const out = [base + 27];
  for (let shift = 56n; shift >= 0n; shift -= 8n) out.push(Number(value >> shift & 0xffn));
  return out;
}
export function predicateTokenName(publicInputs) {
  const bytes = [0x9f];
  for (const v of publicInputs) {
    if (v < 0n) throw new Error('public inputs must be non-negative');
    if (v < 1n << 64n) {
      bytes.push(...cborHeadU(0, v));
    } else {
      let hex = v.toString(16);
      if (hex.length % 2) hex = '0' + hex;
      const bs = hex.match(/../g).map((p) => parseInt(p, 16));
      bytes.push(0xc2, ...cborHeadU(2, BigInt(bs.length)), ...bs);
    }
  }
  bytes.push(0xff);
  return bytesToHex(blake2b(Uint8Array.from(bytes), { dkLen: 28 }));
}

function foldProof(proof) {
  let node = leafHash(fromHex(proof.fieldKey), proof.value);
  for (let d = 0; d < MERKLE_DEPTH; d++) {
    const sibling = fromHex(proof.siblings[d]);
    node = proof.dirs[d] ? nodeHash(node, sibling) : nodeHash(sibling, node);
  }
  return bytesToHex(node);
}

// --- Minimal CBOR / PlutusData decoder ----------------------------------------
// Enough of RFC 8949 to read a Plutus inline datum: unsigned/negative ints,
// byte strings, arrays, constr tags (121+, 1280+, 102) and bignums (tag 2/3).
// Returns BigInt for ints, Uint8Array for bytes, arrays for lists, and
// { constr, fields } for constructors.
export function decodeCbor(bytes) {
  if (typeof bytes === 'string') bytes = fromHex(bytes);
  const st = { buf: bytes, pos: 0 };
  const v = readItem(st);
  return v;
}

function readUint(st, info) {
  if (info < 24) return BigInt(info);
  if (info === 24) return BigInt(st.buf[st.pos++]);
  if (info === 25) { const n = (st.buf[st.pos] << 8) | st.buf[st.pos + 1]; st.pos += 2; return BigInt(n >>> 0); }
  if (info === 26) {
    let n = 0n; for (let i = 0; i < 4; i++) n = (n << 8n) | BigInt(st.buf[st.pos++]); return n;
  }
  if (info === 27) {
    let n = 0n; for (let i = 0; i < 8; i++) n = (n << 8n) | BigInt(st.buf[st.pos++]); return n;
  }
  throw new Error(`unsupported CBOR length info ${info}`);
}

function readItem(st) {
  const b = st.buf[st.pos++];
  if (b === undefined) throw new Error('unexpected end of CBOR');
  const major = b >> 5;
  const info = b & 0x1f;

  if (major === 0) return readUint(st, info);            // unsigned int
  if (major === 1) return -1n - readUint(st, info);      // negative int
  if (major === 2) {                                     // byte string
    if (info === 31) return readIndefBytes(st);
    const len = Number(readUint(st, info));
    const out = st.buf.slice(st.pos, st.pos + len); st.pos += len; return out;
  }
  if (major === 3) {                                     // text string
    const len = Number(readUint(st, info));
    const out = new TextDecoder().decode(st.buf.slice(st.pos, st.pos + len)); st.pos += len; return out;
  }
  if (major === 4) {                                     // array
    if (info === 31) { const arr = []; while (peek(st) !== 0xff) arr.push(readItem(st)); st.pos++; return arr; }
    const len = Number(readUint(st, info));
    const arr = []; for (let i = 0; i < len; i++) arr.push(readItem(st)); return arr;
  }
  if (major === 5) {                                     // map
    const len = Number(readUint(st, info));
    const m = new Map(); for (let i = 0; i < len; i++) { const k = readItem(st); m.set(k, readItem(st)); } return m;
  }
  if (major === 6) {                                     // tag
    const tag = Number(readUint(st, info));
    const content = readItem(st);
    if (tag === 2) return bytesToBigIntBE(content);       // positive bignum
    if (tag === 3) return -1n - bytesToBigIntBE(content); // negative bignum
    if (tag >= 121 && tag <= 127) return { constr: tag - 121, fields: content };
    if (tag >= 1280 && tag <= 1400) return { constr: tag - 1280 + 7, fields: content };
    if (tag === 102) return { constr: Number(content[0]), fields: content[1] };
    return content;                                       // unknown tag: pass through
  }
  if (major === 7) {                                     // simple / float
    if (info === 20) return false;
    if (info === 21) return true;
    if (info === 22 || info === 23) return null;
    throw new Error('floats/simple values are not valid Plutus datum ints');
  }
  throw new Error(`unsupported CBOR major type ${major}`);
}

function peek(st) { return st.buf[st.pos]; }
function readIndefBytes(st) {
  const chunks = [];
  while (peek(st) !== 0xff) chunks.push(readItem(st));
  st.pos++;
  return concat(...chunks);
}

// The datum is list [poseidonRoot, fieldKey, threshold, isCompliant]; ODATANO
// may wrap it in a constr. Return the four public inputs as BigInt.
export function datumPublicInputs(datumCborHexOrBytes) {
  const decoded = decodeCbor(datumCborHexOrBytes);
  const fields = Array.isArray(decoded) ? decoded
    : (decoded && Array.isArray(decoded.fields) ? decoded.fields : null);
  if (!fields || fields.length < 4) throw new Error('datum is not a 4-element public-input list');
  return fields.slice(0, 4).map((x) => {
    if (typeof x === 'bigint') return x;
    if (x instanceof Uint8Array) return bytesToBigIntBE(x);
    throw new Error('unexpected non-integer public input');
  });
}

// --- Verifier-policy trust root ------------------------------------------------
export function loadPinnedPolicies(network, opts = {}) {
  const key = `cardano-${network}`;
  const trusted = new Map(); // operator -> Set(hash)
  const add = (op, hash) => {
    const h = String(hash || '').toLowerCase().replace(/^0x/, '');
    if (!/^[0-9a-f]{56}$/.test(h)) return;
    if (!trusted.has(op)) trusted.set(op, new Set());
    trusted.get(op).add(h);
  };
  // 1. the committed registry file
  const registry = opts.registry ?? readRegistryFile();
  const forNet = registry?.policies?.[key] ?? {};
  for (const [op, hash] of Object.entries(forNet)) add(op, hash);
  // 2. run-time overrides (env + CLI) apply to ANY operator
  const extra = [...(opts.extra ?? [])];
  const env = (opts.env ?? process.env.PAC_TRUST_VERIFIER_POLICY) || '';
  for (const h of env.split(',')) if (h.trim()) extra.push(h.trim());
  for (const h of extra) { add('greaterOrEqual', h); add('lessOrEqual', h); }
  return trusted;
}

function readRegistryFile() {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    return JSON.parse(readFileSync(join(here, 'verifier-policies.json'), 'utf8'));
  } catch { return { policies: {} }; }
}

export function isPolicyTrusted(policyId, operator, trusted) {
  const h = String(policyId || '').toLowerCase().replace(/^0x/, '');
  return !!trusted.get(operator)?.has(h);
}

// The predicate token minted under `policyId` among a tx's outputs. Returns
// { unit, assetName, quantity } or null. DAYPASS mints exactly one, on output 0.
export function findPredicateToken(utxos, policyId) {
  const seen = new Map(); // unit -> total quantity across outputs
  for (const o of (utxos?.outputs ?? [])) {
    for (const a of (o.amount ?? [])) {
      if (a.unit !== 'lovelace' && a.unit.startsWith(policyId)) {
        seen.set(a.unit, (seen.get(a.unit) ?? 0n) + BigInt(a.quantity));
      }
    }
  }
  if (seen.size !== 1) return null;      // exactly one predicate asset expected
  const [unit, quantity] = [...seen.entries()][0];
  return { unit, assetName: unit.slice(policyId.length), quantity };
}

// --- zk predicate check (pure: operates on already-fetched chain data) --------
// chain = { asset, utxos, metadata, anchorPoseidonRootDecimal }
//   utxos:   /txs/{hash}/utxos       — authoritative for the minted token + datum
//   asset:   /assets/{discovered unit} — for the initial-mint-tx origin (or null)
//   metadata:/txs/{hash}/metadata    (or null)
export function checkZkPredicate(proof, subject, chain, trusted, anchorLabel) {
  const out = [];
  const rec = (name, ok, detail = '') => out.push([name, !!ok, detail]);
  const clean = (h) => String(h ?? '').toLowerCase().replace(/^0x/, '');
  const field = proof.sourceField;
  const op = proof.operator;
  const label = `zk predicate ${field} ${op} ${proof.threshold}`;

  // The trust root: the mint policy must be one we pin, for this operator.
  const policyId = clean(proof.verifierPolicyId);
  if (!policyId) { rec(`${label}: verifierPolicyId present`, false, 'PAC has no verifierPolicyId — regenerate with a current DAYPASS'); return out; }
  const trustedOk = isPolicyTrusted(policyId, op, trusted);
  rec(`${label}: verifier policy pinned/trusted`, trustedOk, trustedOk ? policyId : `${policyId} NOT in trusted set`);
  if (!trustedOk) return out; // nothing else can be trusted without the policy

  // Exactly one predicate token is minted under the pinned policy, and its
  // asset name binds to the proof. Policy v2 enforces on-chain that the name
  // is blake2b-224 over serialiseData of the token output's datum, so we
  // recompute exactly that from the DECODED public inputs (serialiseData is
  // canonical; the tx's raw datum bytes need not be). Legacy (pre-v2) tokens
  // carry a trailing slice of the 64-hex passportIdHash — accepted by suffix.
  const passportIdHash = blake2b256HexUtf8(subject.passportId);
  if (subject.passportIdHash && clean(subject.passportIdHash) !== passportIdHash) {
    rec(`${label}: passportIdHash matches passportId`, false, 'subject.passportIdHash != blake2b(passportId)');
  }
  const token = findPredicateToken(chain.utxos, policyId);
  const outputs = chain.utxos?.outputs ?? [];
  const tokenOutput = token ? outputs.find((o) => (o.amount ?? []).some((a) => a.unit === token.unit)) : null;
  let tokenInputs = null;
  try { tokenInputs = tokenOutput?.inline_datum ? datumPublicInputs(tokenOutput.inline_datum) : null; }
  catch { /* handled by the datum checks below */ }
  const datumBoundName = tokenInputs ? predicateTokenName(tokenInputs) : null;
  const nameBinds = !!token && token.assetName.length > 0
    && (token.assetName.toLowerCase() === datumBoundName
      || passportIdHash.endsWith(token.assetName.toLowerCase()));
  rec(`${label}: exactly one predicate token minted under the pinned policy, bound to the proof`,
    !!token && token.quantity === 1n && nameBinds,
    !token ? 'no single predicate token in the tx outputs' : `name=${token.assetName.slice(0, 16)}… qty=${token.quantity}${nameBinds ? '' : ' (name commits to neither the datum nor the passportIdHash)'}`);

  // Mint origin: the token was MINTED by this tx, not merely moved into it.
  const asset = chain.asset;
  const mintedHere = !!asset && String(asset.initial_mint_tx_hash ?? '').toLowerCase() === clean(proof.transactionHash);
  rec(`${label}: token minted by this tx (not moved in)`,
    !!asset && String(asset.quantity) === '1' && mintedHere,
    !asset ? 'asset not found' : `qty=${asset.quantity} mintTx=${String(asset.initial_mint_tx_hash).slice(0, 12)}…`);

  // Public-input binding: read the inline datum of the output carrying the
  // token (what policy v2 checks); legacy mints put it on output 0.
  const datumOut = tokenOutput?.inline_datum
    ? tokenOutput
    : (outputs.find((o) => o.output_index === 0) ?? outputs[0]);
  let inputs = null;
  try { inputs = datumOut?.inline_datum ? datumPublicInputs(datumOut.inline_datum) : null; }
  catch (e) { rec(`${label}: inline datum decodes`, false, e.message); }
  if (inputs) {
    const [datumRoot, datumField, datumThreshold, datumCompliant] = inputs;
    rec(`${label}: proof result isCompliant == 1`, datumCompliant === 1n, `isCompliant=${datumCompliant}`);
    rec(`${label}: datum threshold == claimed threshold`, datumThreshold === BigInt(proof.threshold),
      `datum=${datumThreshold} claim=${proof.threshold}`);
    rec(`${label}: datum fieldKey == blake2b31(sourceField)`, datumField === fieldKeyFe(field),
      datumField === fieldKeyFe(field) ? '' : `datum=${datumField}`);
    const anchoredRoot = chain.anchorPoseidonRootDecimal;
    rec(`${label}: datum poseidonRoot == anchored root (binds to this passport)`,
      anchoredRoot != null && datumRoot === anchoredRoot,
      anchoredRoot == null ? 'anchor carries no poseidonRoot' : (datumRoot === anchoredRoot ? '' : 'root mismatch'));
  } else if (datumOut) {
    rec(`${label}: predicate token output carries an inline datum`, false, 'no inline_datum found');
  }

  // Defense in depth: the predicate anchor metadata names this passport/field.
  const md = (chain.metadata ?? []).find((m) => String(m.label) === String(anchorLabel));
  const a = md?.json_metadata ?? null;
  const metaOk = !!a && a.op === 'predicate'
    && a.passportId === subject.passportId
    && String(a.predicate) === op
    && Number(a.threshold) === Number(proof.threshold)
    && clean(a.fieldKey) === blake2b256HexUtf8(field)
    && Number(a.result) === 1;
  rec(`${label}: predicate metadata binds passport/field/predicate`, metaOk,
    a ? `op=${a.op} field=${a.predicate}` : 'no predicate metadata');

  return out;
}

// --- CLI ----------------------------------------------------------------------
async function main() {
  const argv = process.argv.slice(2);
  const flags = argv.filter((a) => a.startsWith('--'));
  const pos = argv.filter((a) => !a.startsWith('--'));
  const pacPath = pos[0];
  const apiKey = pos[1] || process.env.BLOCKFROST_API_KEY;
  const cliTrust = flags
    .filter((f) => f.startsWith('--trust-verifier-policy='))
    .flatMap((f) => f.split('=')[1].split(','))
    .map((s) => s.trim()).filter(Boolean);

  if (!pacPath || !apiKey) {
    console.error('usage: node verify-pac.mjs <pac.json> [BLOCKFROST_API_KEY] [--trust-verifier-policy=<hash>]');
    process.exit(1);
  }
  const pac = JSON.parse(readFileSync(pacPath, 'utf8'));
  const subject = pac.credentialSubject ?? {};
  const att = subject.attestation ?? {};
  const network = String(att.chain ?? 'cardano-preview').replace(/^cardano-/, '');
  const BF = `https://cardano-${network}.blockfrost.io/api/v0`;
  const anchorLabel = String(att.anchorMetadataLabel ?? 1155);
  const trusted = loadPinnedPolicies(network, { extra: cliTrust });

  async function bf(path) {
    const res = await fetch(`${BF}${path}`, { headers: { project_id: apiKey } });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`Blockfrost ${path} -> HTTP ${res.status}`);
    return res.json();
  }

  const results = [];
  const check = (name, ok, detail = '') => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` (${detail})` : ''}`); };
  const clean = (h) => String(h ?? '').toLowerCase().replace(/^0x/, '');

  console.log(`PAC: ${subject.passportId} on cardano-${network}\n`);

  // 1. attestation tx exists
  const mintTx = await bf(`/txs/${clean(att.transactionHash)}`);
  check('attestation (mint) tx exists on-chain', !!mintTx, clean(att.transactionHash));

  // 2. anchor metadata on the last anchor tx
  const meta = await bf(`/txs/${clean(att.lastAnchorTxHash)}/metadata`);
  const anchorRow = (meta ?? []).find((m) => String(m.label) === anchorLabel);
  const anchor = anchorRow?.json_metadata ?? null;
  check(`anchor metadata present under label ${anchorLabel}`, !!anchor);
  const onChainPayloadHash = clean(anchor?.payloadHash);
  check('on-chain payloadHash matches credential', !!anchor && onChainPayloadHash === clean(subject.payloadHash));
  const onChainRoot = clean(anchor?.contentRoot);
  check('on-chain contentRoot present', /^[0-9a-f]{64}$/.test(onChainRoot));
  // The Poseidon twin of the content commitment, anchored alongside contentRoot.
  const anchorPoseidonHex = clean(anchor?.poseidonRoot);
  const anchorPoseidonRootDecimal = /^[0-9a-f]{1,64}$/.test(anchorPoseidonHex) ? BigInt('0x' + anchorPoseidonHex) : null;

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
      const txHash = clean(proof.transactionHash);
      const policyId = clean(proof.verifierPolicyId);
      // Only touch the chain once the policy is pinned — an unpinned/forged
      // policy is rejected outright, no lookups needed.
      let chain = { asset: null, utxos: null, metadata: null, anchorPoseidonRootDecimal };
      if (policyId && isPolicyTrusted(policyId, proof.operator, trusted) && txHash) {
        const [utxos, txMeta] = await Promise.all([
          bf(`/txs/${txHash}/utxos`),
          bf(`/txs/${txHash}/metadata`)
        ]);
        // Discover the minted token from the outputs, then confirm its origin.
        const token = findPredicateToken(utxos, policyId);
        const asset = token ? await bf(`/assets/${token.unit}`) : null;
        chain = { asset, utxos, metadata: txMeta, anchorPoseidonRootDecimal };
      }
      for (const [name, ok, detail] of checkZkPredicate(proof, subject, chain, trusted, anchorLabel)) {
        check(name, ok, detail);
      }
    }
  }

  const verified = results.length > 0 && results.every(Boolean);
  console.log(`\n${verified ? 'PAC VERIFIED' : 'PAC VERIFICATION FAILED'} (${results.filter(Boolean).length}/${results.length} checks)`);
  process.exit(verified ? 0 : 1);
}

// Run the CLI only when invoked directly; stay importable for unit tests.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((e) => { console.error(`FATAL: ${e.message}`); process.exit(1); });
}
