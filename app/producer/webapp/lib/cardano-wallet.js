/* eslint-disable */
/**
 * DAYPASS CIP-30 wallet helpers. Plain browser JS, zero dependencies.
 *
 *   listWallets()                     -> [{ key, name }]
 *   connect(key)                      -> CIP-30 api (enable())
 *   firstBech32Address(api)           -> "addr..." (used or unused/change)
 *   mergeWitnessSet(unsignedHex, walletWitnessSetHex) -> signedTxHex
 *
 * mergeWitnessSet does GENERIC CBOR splicing (same approach as the server's
 * tx-signer): the tx is [body, witnessSet, isValid, aux]; the wallet returns a
 * witness-set map whose entries are merged into the tx's witness set (wallet
 * entries win). Untouched byte ranges are copied verbatim, so the body — and
 * with it the signature — stays byte-identical.
 */
sap.ui.define([], function () {
  "use strict";

  // ---- hex ----------------------------------------------------------------
  function fromHex(hex) {
    var clean = String(hex).replace(/^0x/, "");
    var out = new Uint8Array(clean.length / 2);
    for (var i = 0; i < out.length; i++) { out[i] = parseInt(clean.substr(i * 2, 2), 16); }
    return out;
  }
  function toHex(bytes) {
    return Array.from(bytes, function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }

  // ---- minimal CBOR walker --------------------------------------------------
  // Returns the END offset of the data item starting at `off`.
  function skipItem(b, off) {
    var ib = b[off];
    var major = ib >> 5;
    var info = ib & 0x1f;
    var head = 1, len = info;
    if (info === 24) { len = b[off + 1]; head = 2; }
    else if (info === 25) { len = (b[off + 1] << 8) | b[off + 2]; head = 3; }
    else if (info === 26) { len = (b[off + 1] * 0x1000000) + (b[off + 2] << 16) + (b[off + 3] << 8) + b[off + 4]; head = 5; }
    else if (info === 27) {
      // 8-byte argument: fine for ints (no payload, e.g. lovelace > 2^32);
      // a 64-bit LENGTH on bytes/arrays would not fit in a browser tx anyway.
      if (major === 0 || major === 1) { return off + 9; }
      throw new Error("cbor: 8-byte length unsupported for major " + major);
    }
    else if (info === 31) { // indefinite length
      if (major === 2 || major === 3 || major === 4 || major === 5) {
        var o = off + 1;
        while (b[o] !== 0xff) { o = skipItem(b, o); if (major === 5) { o = skipItem(b, o); } }
        return o + 1;
      }
      throw new Error("cbor: unexpected indefinite item");
    }
    switch (major) {
      case 0: case 1: case 7: return off + head;               // ints / simple
      case 2: case 3: return off + head + len;                 // bytes / text
      case 4: {                                                // array
        var oa = off + head;
        for (var i = 0; i < len; i++) { oa = skipItem(b, oa); }
        return oa;
      }
      case 5: {                                                // map
        var om = off + head;
        for (var j = 0; j < len; j++) { om = skipItem(b, om); om = skipItem(b, om); }
        return om;
      }
      case 6: return skipItem(b, off + head);                  // tag
      default: throw new Error("cbor: bad major " + major);
    }
  }

  // Parse a definite-length map at `off` into [{keyStart,keyEnd,valEnd}], plus header info.
  function mapEntries(b, off) {
    var ib = b[off];
    if ((ib >> 5) !== 5) { throw new Error("cbor: expected map, got major " + (ib >> 5)); }
    var info = ib & 0x1f, head = 1, count = info;
    if (info === 24) { count = b[off + 1]; head = 2; }
    else if (info === 25) { count = (b[off + 1] << 8) | b[off + 2]; head = 3; }
    else if (info === 31) { throw new Error("cbor: indefinite witness map unsupported"); }
    var entries = [];
    var o = off + head;
    for (var i = 0; i < count; i++) {
      var ks = o, ke = skipItem(b, ks), ve = skipItem(b, ke);
      entries.push({ keyStart: ks, keyEnd: ke, valEnd: ve });
      o = ve;
    }
    return { entries: entries, end: o };
  }

  function mapHeader(count) {
    if (count < 24) { return new Uint8Array([0xa0 | count]); }
    if (count < 256) { return new Uint8Array([0xb8, count]); }
    return new Uint8Array([0xb9, (count >> 8) & 0xff, count & 0xff]);
  }

  function concatBytes(parts) {
    var total = parts.reduce(function (n, p) { return n + p.length; }, 0);
    var out = new Uint8Array(total), o = 0;
    parts.forEach(function (p) { out.set(p, o); o += p.length; });
    return out;
  }

  /** Merge the wallet's witness-set map into the unsigned tx (wallet keys win). */
  function mergeWitnessSet(unsignedTxHex, walletWitnessSetHex) {
    var tx = fromHex(unsignedTxHex);
    var ws = fromHex(walletWitnessSetHex);
    if ((tx[0] >> 5) !== 4) { throw new Error("tx cbor: expected top-level array"); }
    var arity = tx[0] & 0x1f;
    if (arity < 2 || arity > 23) { throw new Error("tx cbor: unexpected arity " + arity); }
    var bodyStart = 1;
    var bodyEnd = skipItem(tx, bodyStart);
    var txWits = mapEntries(tx, bodyEnd);
    var tail = tx.slice(txWits.end);                         // isValid + aux, verbatim

    var walletWits = mapEntries(ws, 0);
    var walletKeys = walletWits.entries.map(function (e) { return toHex(ws.slice(e.keyStart, e.keyEnd)); });

    var parts = [];
    var kept = 0;
    txWits.entries.forEach(function (e) {
      var keyHex = toHex(tx.slice(e.keyStart, e.keyEnd));
      if (walletKeys.indexOf(keyHex) >= 0) { return; }       // wallet entry replaces it
      parts.push(tx.slice(e.keyStart, e.valEnd));
      kept++;
    });
    walletWits.entries.forEach(function (e) {
      parts.push(ws.slice(e.keyStart, e.valEnd));
      kept++;
    });

    var merged = concatBytes([
      new Uint8Array([tx[0]]),
      tx.slice(bodyStart, bodyEnd),
      mapHeader(kept)
    ].concat(parts, [tail]));
    return toHex(merged);
  }

  // ---- bech32 (BIP-173) ------------------------------------------------------
  var CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  function polymod(values) {
    var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    var chk = 1;
    values.forEach(function (v) {
      var top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (var i = 0; i < 5; i++) { if ((top >> i) & 1) { chk ^= GEN[i]; } }
    });
    return chk;
  }
  function hrpExpand(hrp) {
    var out = [];
    for (var i = 0; i < hrp.length; i++) { out.push(hrp.charCodeAt(i) >> 5); }
    out.push(0);
    for (var j = 0; j < hrp.length; j++) { out.push(hrp.charCodeAt(j) & 31); }
    return out;
  }
  function toWords(bytes) {
    var out = [], bits = 0, value = 0;
    for (var i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) { bits -= 5; out.push((value >> bits) & 31); }
    }
    if (bits > 0) { out.push((value << (5 - bits)) & 31); }
    return out;
  }
  function bech32Encode(hrp, bytes) {
    var words = toWords(bytes);
    var chk = polymod(hrpExpand(hrp).concat(words).concat([0, 0, 0, 0, 0, 0])) ^ 1;
    var checksum = [];
    for (var i = 0; i < 6; i++) { checksum.push((chk >> (5 * (5 - i))) & 31); }
    return hrp + "1" + words.concat(checksum).map(function (w) { return CHARSET[w]; }).join("");
  }

  /** CIP-30 addresses come as hex CBOR-less raw address bytes -> bech32. */
  function addressHexToBech32(addrHex) {
    var bytes = fromHex(addrHex);
    var networkId = bytes[0] & 0x0f;
    return bech32Encode(networkId === 1 ? "addr" : "addr_test", bytes);
  }

  /**
   * Strip a CBOR byte-string wrapper from a CIP-30 hex address if present
   * (TRACE pattern): Eternl/Lace return cbor<address> like "5839 00ab…"
   * (0x58 = bstr with 1-byte length); Nami returns the raw address hex.
   */
  function stripCborByteString(hex) {
    var clean = String(hex).replace(/^0x/, "");
    var b0 = parseInt(clean.substr(0, 2), 16);
    if ((b0 & 0xe0) === 0x40) { // CBOR major type 2
      var addInfo = b0 & 0x1f;
      if (addInfo <= 23) { return clean.substr(2); }
      if (addInfo === 24) { return clean.substr(4); }
      if (addInfo === 25) { return clean.substr(6); }
    }
    return clean;
  }

  /** CIP-30 addresses come as (possibly CBOR-wrapped) hex bytes -> bech32. */
  function addressHexToBech32(addrHex) {
    var bytes = fromHex(stripCborByteString(addrHex));
    var networkId = bytes[0] & 0x0f;
    return bech32Encode(networkId === 1 ? "addr" : "addr_test", bytes);
  }

  /** Payment key hash (56-hex) from a (wrapped or raw) CIP-30 hex address. */
  function addressHexToVkh(addrHex) {
    var raw = stripCborByteString(addrHex);
    return raw.slice(2, 58);
  }

  // ---- CIP-30 -----------------------------------------------------------------

  // Known CIP-30 wallet ids (TRACE pattern) — window.cardano also carries
  // non-wallet keys, so an allowlist beats duck-typing alone.
  var KNOWN_WALLETS = ["lace", "eternl", "nami", "flint", "typhon", "gerowallet", "nufi", "begin", "vespr", "yoroi"];

  function listWallets() {
    var c = window.cardano || {};
    var seen = {};
    var out = [];
    KNOWN_WALLETS.concat(Object.keys(c)).forEach(function (k) {
      if (seen[k] || !c[k] || typeof c[k].enable !== "function") { return; }
      seen[k] = true;
      out.push({ key: k, name: (c[k].name || k), icon: c[k].icon || "" });
    });
    return out;
  }

  function connect(key) {
    return window.cardano[key].enable();
  }

  /** First used (or unused/change) address, as { hex (raw), bech32, vkh }. */
  async function firstAddress(api) {
    var list = await candidateAddresses(api);
    if (!list.length) { throw new Error("wallet returned no address"); }
    return list[0];
  }

  /**
   * All addresses the wallet reports (used, capped, + change address), each as
   * { hex (raw), bech32, vkh }, deduped. Multi-address wallets (Eternl) use a
   * DIFFERENT payment key per address, so the caller must pick the funded one
   * rather than blindly taking index 0.
   */
  async function candidateAddresses(api) {
    var out = [];
    var seen = {};
    function push(addrHex) {
      if (!addrHex) { return; }
      var raw = stripCborByteString(addrHex);
      if (seen[raw]) { return; }
      seen[raw] = true;
      out.push({ hex: raw, bech32: addressHexToBech32(raw), vkh: addressHexToVkh(raw) });
    }
    var used = [];
    try { used = (await api.getUsedAddresses()) || []; } catch (e) { /* ignore */ }
    used.slice(0, 20).forEach(push);
    try { push(await api.getChangeAddress()); } catch (e) { /* ignore */ }
    if (!out.length) {
      var unused = [];
      try { unused = (await api.getUnusedAddresses()) || []; } catch (e) { /* ignore */ }
      unused.slice(0, 5).forEach(push);
    }
    return out;
  }

  function utf8ToHex(s) {
    var bytes = new TextEncoder().encode(s);
    return toHex(bytes);
  }

  /**
   * CIP-30 sign-in: have the wallet sign a human-readable message (signData,
   * COSE_Sign1). The backend verifies it statelessly via the plugin's
   * VerifyDataSignature action — proof of key control, not just enable().
   * Returns { message, coseSignature, coseKey }.
   */
  async function signIn(api, addressHex, message) {
    var res = await api.signData(addressHex, utf8ToHex(message));
    return { message: message, coseSignature: res.signature, coseKey: res.key };
  }

  /** Build the canonical DAYPASS sign-in message (nonce against replay). */
  function signInMessage(bech32) {
    var nonce = new Uint8Array(16);
    (window.crypto || {}).getRandomValues ? window.crypto.getRandomValues(nonce) : null;
    return "DAYPASS sign-in\naddress: " + bech32 +
      "\nnonce: " + toHex(nonce) +
      "\nissued: " + new Date().toISOString();
  }

  return {
    listWallets: listWallets,
    connect: connect,
    firstAddress: firstAddress,
    candidateAddresses: candidateAddresses,
    signIn: signIn,
    signInMessage: signInMessage,
    stripCborByteString: stripCborByteString,
    addressHexToBech32: addressHexToBech32,
    addressHexToVkh: addressHexToVkh,
    mergeWitnessSet: mergeWitnessSet
  };
});
