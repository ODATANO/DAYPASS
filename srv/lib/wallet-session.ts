import { randomBytes } from 'node:crypto';

/**
 * Wallet sign-in state: server-issued challenges (nonce -> message) and the
 * sessions minted after a successful CIP-30 signData verification. In-memory
 * on purpose — sessions are cheap to re-establish (one wallet popup) and the
 * dev server is a single process; a clustered deployment would move this to
 * a shared store.
 *
 * A session binds an opaque bearer token to the PROVEN wallet address; the
 * producer service scopes every read and passport-bound action to it when the
 * `x-wallet-session` header is present.
 */

const CHALLENGE_TTL_MS = 5 * 60_000;
const SESSION_TTL_MS = 8 * 60 * 60_000;

export interface WalletSession {
    address: string;   // bech32, proven via signData
    vkh: string;       // blake2b-224 of the signer public key
    expiresAt: number;
}

interface Challenge {
    address: string;
    message: string;
    expiresAt: number;
}

const challenges = new Map<string, Challenge>();
const sessions = new Map<string, WalletSession>();

function sweep(): void {
    const now = Date.now();
    for (const [k, v] of challenges) if (v.expiresAt < now) challenges.delete(k);
    for (const [k, v] of sessions) if (v.expiresAt < now) sessions.delete(k);
}

/** Issue a one-time sign-in challenge for an address. */
export function createChallenge(address: string): { nonce: string; message: string } {
    sweep();
    const nonce = randomBytes(16).toString('hex');
    const message = 'DAYPASS wallet sign-in'
        + `\naddress: ${address}`
        + `\nnonce: ${nonce}`
        + `\nissued: ${new Date().toISOString()}`;
    challenges.set(nonce, { address, message, expiresAt: Date.now() + CHALLENGE_TTL_MS });
    return { nonce, message };
}

/** Fetch AND invalidate a challenge (one attempt per nonce — anti-replay). */
export function consumeChallenge(nonce: string): { address: string; message: string } | null {
    const c = challenges.get(nonce);
    challenges.delete(nonce);
    if (!c || c.expiresAt < Date.now()) return null;
    return { address: c.address, message: c.message };
}

/** Mint a session for a verified address; returns the bearer token. */
export function createSession(address: string, vkh: string): { token: string; expiresAt: string } {
    sweep();
    const token = randomBytes(32).toString('hex');
    const expiresAt = Date.now() + SESSION_TTL_MS;
    sessions.set(token, { address, vkh, expiresAt });
    return { token, expiresAt: new Date(expiresAt).toISOString() };
}

/** Resolve a token to its session, or null when unknown/expired. */
export function sessionFor(token: string | undefined | null): WalletSession | null {
    if (!token) return null;
    const s = sessions.get(String(token));
    if (!s) return null;
    if (s.expiresAt < Date.now()) { sessions.delete(String(token)); return null; }
    return s;
}

export function dropSession(token: string | undefined | null): void {
    if (token) sessions.delete(String(token));
}
