import cds from '@sap/cds';
import { granteeIdForDid } from './lib/grantee';
import { explorerUrl } from './lib/cardano-submit';
import { buildPacJson, isExportableProof } from './lib/catenax';

const { INSERT, SELECT } = cds.ql;

// --- Disclosure tiers ----------------------------------------------------------
//
// The Annex XIII disclosure boundary is enforced HERE, in the API layer, not on
// the chain (Cardano has no on-chain ACL; the chain carries the pseudonymous
// audit anchors only). `after READ` handlers strip every field a tier may not
// see, so the same backend data renders three lawful views.
//
//   consumer  (anonymous)        -> Annex XIII Point 1 only (public metadata).
//   recycler  (role 'recycler')  -> + cell chemistry / capacity / recycled %.
//   authority (role 'authority') -> everything incl. supplier identities,
//                                   carbon footprint, docs, on-chain lineage.
type Tier = 'consumer' | 'recycler' | 'authority';

const TIER_RANK: Record<Tier, number> = { consumer: 0, recycler: 1, authority: 2 };
function maxTier(a: Tier, b: Tier): Tier { return TIER_RANK[a] >= TIER_RANK[b] ? a : b; }
function levelToTier(level: number): Tier {
    return level >= 2 ? 'authority' : level === 1 ? 'recycler' : 'consumer';
}

/** Tier from the requester's configured CAP roles (the dev/mocked-auth path). */
function localTierOf(req: any): Tier {
    const user = req.user;
    if (user?.is('authority')) return 'authority';
    if (user?.is('recycler')) return 'recycler';
    return 'consumer';
}

/** The requester's grantee ids. A partner's DID login maps directly to
 * sha256(did) — same derivation as registerPartner and the grant writer. */
function granteesOf(req: any): string[] {
    const userId = req.user?.id;
    if (!userId || userId === 'anonymous') return [];
    try { return [granteeIdForDid(String(userId))]; } catch { return []; }
}

/**
 * Effective disclosure grants for a set of grantee ids -> Map(payloadHash -> maxLevel).
 * Source: producer grant log (server ACL) — latest op per (passport, grantee)
 * counts only if it is a `grant`.
 */
async function effectiveGrantsFor(grantees: string[]): Promise<Map<string, number>> {
    const out = new Map<string, number>();
    if (!grantees.length) return out;
    try {
        const rows: any[] = await SELECT.from('passport.DisclosureGrantLog')
            .columns('grantee', 'level', 'op', 'createdAt', 'passport_ID')
            .where({ grantee: { in: grantees } })
            .orderBy('createdAt asc');
        const latest = new Map<string, any>();
        for (const r of rows) latest.set(`${r.passport_ID}|${r.grantee}`, r);
        const granted = [...latest.values()].filter((r) => r.op === 'grant');
        if (granted.length) {
            const ids = [...new Set(granted.map((r) => r.passport_ID))];
            const ps: any[] = await SELECT.from('passport.Passports').columns('ID', 'payloadHash').where({ ID: { in: ids } });
            const idToHash = new Map(ps.map((p) => [p.ID, p.payloadHash]));
            for (const r of granted) {
                const ph = idToHash.get(r.passport_ID);
                if (typeof ph !== 'string' || !ph) continue;
                out.set(ph, Math.max(out.get(ph) ?? -1, Number(r.level) || 0));
            }
        }
    } catch { /* no grants */ }
    return out;
}

/** Fields on Passports beyond Annex XIII Point 1: on-chain lineage, authority-only. */
const PASSPORT_AUTHORITY_FIELDS = [
    'payloadHash', 'passportIdHash', 'contentRoot', 'policyId', 'assetName',
    'unit', 'fingerprint', 'attestationTxHash', 'anchorVersion', 'lastAnchorTxHash'
] as const;

function strip(row: Record<string, unknown>, keys: readonly string[]): void {
    for (const k of keys) delete row[k];
}

/** Redact one Passports row (and any expanded children) for the given tier. */
function redactPassport(row: Record<string, unknown>, tier: Tier): void {
    if (tier !== 'authority') strip(row, PASSPORT_AUTHORITY_FIELDS);
    for (const child of ['batteries', 'recycledMaterials', 'diligenceDocs'] as const) {
        const val = row[child];
        if (!Array.isArray(val)) continue;
        if (tier === 'consumer') { row[child] = []; continue; }
    }
    if (Array.isArray(row.batteries)) row.batteries.forEach((b) => redactBattery(b, tier));
    if (Array.isArray(row.recycledMaterials)) row.recycledMaterials.forEach((m) => redactRecycled(m, tier));
    if (tier !== 'authority') row.diligenceDocs = [];
}

/** carbonFootprint + supplierName are authority-only; the rest is legitimate interest. */
function redactBattery(row: Record<string, unknown>, tier: Tier): void {
    if (tier !== 'authority') strip(row, ['carbonFootprintKgCO2', 'supplierName']);
}

/** sourceSupplierName (supplier identity) is authority-only. */
function redactRecycled(row: Record<string, unknown>, tier: Tier): void {
    if (tier !== 'authority') strip(row, ['sourceSupplierName']);
}

function asRows(data: unknown): Record<string, unknown>[] {
    if (Array.isArray(data)) return data as Record<string, unknown>[];
    if (data && typeof data === 'object') return [data as Record<string, unknown>];
    return [];
}

export default class PassportService extends cds.ApplicationService {
    override async init(): Promise<void> {
        this.on('registerPartner', (req) => this.onRegisterPartner(req));
        this.on('resolveByHash', (req) => this.onResolveByHash(req));
        this.on('passportCredential', (req) => this.onPassportCredential(req));

        // The disclosure gate matches grants by payloadHash, so it must be in the
        // row even when the client didn't $select it. Inject it up front; it is
        // then stripped again by redactPassport for non-authority tiers.
        this.before('READ', 'Passports', (req: any) => {
            const cols = req.query?.SELECT?.columns as any[] | undefined;
            if (Array.isArray(cols) && !cols.some((c) => c === '*' || (c?.ref && c.ref[0] === 'payloadHash'))) {
                cols.push({ ref: ['payloadHash'] });
            }
        });

        this.after('READ', 'Passports', async (data: any, req: any) => {
            const local = localTierOf(req);
            const grantees = granteesOf(req);
            // A registered dataspace partner (DID login, role 'partner') has no
            // local tier — the GRANT LEVEL per passport drives disclosure, and
            // they see ONLY passports granted to them.
            const isPartner = !!req.user?.is?.('partner');
            const effective = grantees.length ? await effectiveGrantsFor(grantees) : null;
            const kept: Record<string, unknown>[] = [];
            for (const row of asRows(data)) {
                const ph = typeof row.payloadHash === 'string' ? row.payloadHash : '';
                const grantLvl = effective && ph ? (effective.get(ph) ?? -1) : -1;
                if (isPartner && grantLvl < 0) continue; // partner: granted passports only
                const grantTier: Tier = grantLvl >= 0 ? levelToTier(grantLvl) : 'consumer';
                redactPassport(row, maxTier(local, grantTier));
                kept.push(row);
            }
            if (isPartner && Array.isArray(data)) data.splice(0, data.length, ...kept);
        });
        // Direct child reads carry no passport scope; gate on the local role only.
        this.after('READ', 'Batteries', (data: any, req: any) => {
            const tier = localTierOf(req);
            asRows(data).forEach((row) => redactBattery(row, tier));
        });
        this.after('READ', 'RecycledMaterials', (data: any, req: any) => {
            const tier = localTierOf(req);
            asRows(data).forEach((row) => redactRecycled(row, tier));
        });
        // DiligenceDoc is authority-only in full; below-tier requests get nothing.
        this.after('READ', 'DiligenceDoc', (data: any, req: any) => {
            if (localTierOf(req) === 'authority') return;
            asRows(data).forEach((row) => strip(row, Object.keys(row)));
        });

        return super.init();
    }

    private async onRegisterPartner(req: any) {
        const { did, name, role, secret } = req.data;
        if (!did || !name || !secret) return req.error(400, 'did, name and secret are required');
        if (!['recycler', 'authority'].includes(String(role))) {
            return req.error(400, 'role must be "recycler" or "authority"');
        }
        const granteeId = granteeIdForDid(String(did));
        const existing = await SELECT.one.from('passport.Partners').where({ did });
        if (existing) return req.error(409, `partner "${did}" already registered`);
        await INSERT.into('passport.Partners').entries({ did, name, role, granteeId, secret });
        return { did, name, role, granteeId };
    }

    /** Downloadable PAC by payloadHash (consumer surface). */
    private async onPassportCredential(req: any) {
        const raw = String(req.data.payloadHash ?? '').replace(/^0x/, '').toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(raw)) return req.error(400, 'payloadHash must be 32-byte hex');
        const row: any = await SELECT.one.from('passport.Passports').where({ payloadHash: raw });
        if (!row) return req.error(404, 'no battery for that payloadHash');
        const proofs: any[] = await SELECT.from('passport.PredicateProofLog')
            .columns('sourceField', 'mode', 'predicate', 'threshold', 'unit', 'proofJson', 'txHash', 'status', 'result')
            .where({ passport_ID: row.ID })
            .orderBy('createdAt asc');
        return buildPacJson({ passport: row, proofs: proofs.filter(isExportableProof) });
    }

    /** Supplier resolution by anchored payloadHash -> identity + verification + link. */
    private async onResolveByHash(req: any) {
        const raw = String(req.data.payloadHash ?? '').replace(/^0x/, '').toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(raw)) return req.error(400, 'payloadHash must be 32-byte hex');
        const row: any = await SELECT.one.from('passport.Passports')
            .columns('passportId', 'manufacturerId', 'model', 'batteryCategory', 'unit', 'fingerprint',
                'attestationTxHash', 'status', 'payloadHash')
            .where({ payloadHash: raw });
        if (!row) return req.error(404, 'no battery for that payloadHash');
        const base = (process.env.DAYPASS_PUBLIC_URL ?? 'http://localhost:4004').replace(/\/$/, '');
        return {
            passportId: row.passportId,
            payloadHash: raw,
            manufacturerId: row.manufacturerId,
            model: row.model,
            batteryCategory: row.batteryCategory,
            unit: row.unit,
            fingerprint: row.fingerprint,
            attestationTxHash: row.attestationTxHash,
            explorerUrl: row.attestationTxHash ? explorerUrl(row.attestationTxHash) : '',
            status: row.status,
            verified: row.status === 'anchored' && !!row.attestationTxHash,
            viewerUrl: `${base}/resolve/${raw}`
        };
    }
}
