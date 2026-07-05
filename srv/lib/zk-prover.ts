import { PROVABLE_FIELDS, scaleValue } from './passport-anchor';

/**
 * Client for the DAYPASS ZK prover sidecar (zk/daypass-prover).
 *
 * The sidecar is a stateless Java service wrapping ZeroJ: it builds the
 * Poseidon twin of the blake2b contentRoot, generates Groth16 BLS12-381
 * proofs for field-bound threshold predicates and serves the Julc-compiled
 * on-chain verifier policy. DAYPASS sends the scaled provable-field values
 * per request and persists nothing prover-side.
 *
 * Disabled unless DAYPASS_ZK_PROVER_URL is set. When the URL IS set, the ZK
 * commitment is part of the deployment: anchor paths call fetchPoseidonRoot
 * with { required: true } and fail loudly on an unreachable prover instead of
 * silently anchoring Track A only. Draft paths stay best-effort.
 */

export interface ZkProveResult {
    poseidonRoot: string;   // decimal string
    fieldKey: string;       // decimal string (field element)
    threshold: string;      // decimal string, scaled x1000
    isCompliant: boolean;
    proofTimeMs: number;
    redeemerJson: unknown;  // ODATANO mintRedeemerJson: constr 0 [piA, piB, piC]
    datumJson: unknown;     // ODATANO inlineDatumJson: list [root, fieldKey, threshold, isCompliant]
}

export interface ZkValidatorInfo {
    cborHex: string;
    scriptHash: string;
    op: string;
}

export function proverUrl(): string | null {
    const url = (process.env.DAYPASS_ZK_PROVER_URL || '').trim();
    return url ? url.replace(/\/$/, '') : null;
}

export function zkProverEnabled(): boolean {
    return proverUrl() !== null;
}

/** Raw field values -> the scaled x1000 integer map the prover hashes. */
export function scaledFieldValues(values: Record<string, number | string>): Record<string, string> {
    const out: Record<string, string> = {};
    for (const f of PROVABLE_FIELDS) {
        const raw = values[f];
        if (raw != null && raw !== '') out[f] = String(scaleValue(raw));
    }
    return out;
}

async function post(path: string, body: unknown): Promise<any> {
    const base = proverUrl();
    if (!base) throw new Error('DAYPASS_ZK_PROVER_URL not configured');
    const res = await fetch(`${base}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(120_000)
    });
    const json: any = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`prover ${path} failed with ${res.status}: ${json?.error ?? 'unknown'}`);
    return json;
}

export class ZkProverUnreachableError extends Error {
    constructor(cause: string) {
        super(`ZK prover configured (DAYPASS_ZK_PROVER_URL) but not usable: ${cause}. `
            + 'Start zk/daypass-prover, or unset the variable for a Track A only anchor.');
        this.name = 'ZkProverUnreachableError';
    }
}

/**
 * Poseidon root over the passport's provable fields.
 * - prover not configured: null (ZK disabled, Track A only)
 * - configured and reachable: the root
 * - configured but unreachable: throws ZkProverUnreachableError when
 *   `required` (anchor paths), else null with a warning (draft paths)
 */
export async function fetchPoseidonRoot(
    values: Record<string, number | string>,
    opts?: { required?: boolean }
): Promise<string | null> {
    if (!zkProverEnabled()) return null;
    try {
        const res = await post('/commit', { values: scaledFieldValues(values) });
        if (typeof res.poseidonRoot !== 'string') throw new Error('prover /commit returned no poseidonRoot');
        return res.poseidonRoot;
    } catch (e) {
        if (opts?.required) throw new ZkProverUnreachableError((e as Error).message);
        console.warn(`[daypass] poseidon commit skipped: ${(e as Error).message}`);
        return null;
    }
}

/**
 * An anchored passport needs a re-attest when the payload changed, or when a
 * pre-ZK anchor can now be upgraded with a freshly available poseidonRoot.
 */
export function anchorOutdated(args: {
    payloadHash: string; rowPayloadHash: string | null;
    poseidonRoot: string | null; rowPoseidonRoot: string | null;
}): boolean {
    if (args.payloadHash !== args.rowPayloadHash) return true;
    return !!args.poseidonRoot && !args.rowPoseidonRoot;
}

/** Generate a field-bound threshold proof. Throws on any failure. */
export async function provePredicate(input: {
    values: Record<string, number | string>;
    sourceField: string;
    thresholdScaled: string | number;  // already scaled x1000
    op: 'greaterOrEqual' | 'lessOrEqual';
}): Promise<ZkProveResult> {
    return await post('/prove', {
        values: scaledFieldValues(input.values),
        sourceField: input.sourceField,
        threshold: String(input.thresholdScaled),
        op: input.op
    }) as ZkProveResult;
}

/** The Julc verifier policy for an op, VK applied. */
export async function fetchValidator(op: 'greaterOrEqual' | 'lessOrEqual'): Promise<ZkValidatorInfo> {
    const base = proverUrl();
    if (!base) throw new Error('DAYPASS_ZK_PROVER_URL not configured');
    const res = await fetch(`${base}/validator?op=${op}`, { signal: AbortSignal.timeout(30_000) });
    const json: any = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`prover /validator failed with ${res.status}: ${json?.error ?? 'unknown'}`);
    return json as ZkValidatorInfo;
}

/**
 * Strip ONE CBOR byte-string wrap from a script hex, or null when the hex is
 * not a byte string that spans exactly the remaining bytes. Used to reconcile
 * Julc's getCborHex (double-wrapped) with ODATANO's single-wrap expectation.
 */
export function unwrapCborByteString(hex: string): string | null {
    const clean = hex.toLowerCase().replace(/^0x/, '');
    const head = parseInt(clean.slice(0, 2), 16);
    if (Number.isNaN(head) || (head >> 5) !== 2) return null; // major type 2 = byte string
    const info = head & 0x1f;
    let lenDigits = 0;
    if (info < 24) { // length encoded in the head byte itself
        return clean.length === 2 + info * 2 ? clean.slice(2) : null;
    }
    if (info === 24) lenDigits = 2;
    else if (info === 25) lenDigits = 4;
    else if (info === 26) lenDigits = 8;
    else return null;
    const len = parseInt(clean.slice(2, 2 + lenDigits), 16);
    const body = clean.slice(2 + lenDigits);
    return body.length === len * 2 ? body : null;
}

/** GET /health, used by smoke checks. Returns null when disabled/unreachable. */
export async function proverHealth(): Promise<{ status: string; pathBitConvention?: string } | null> {
    const base = proverUrl();
    if (!base) return null;
    try {
        const res = await fetch(`${base}/health`, { signal: AbortSignal.timeout(5_000) });
        return res.ok ? await res.json() as any : null;
    } catch {
        return null;
    }
}
