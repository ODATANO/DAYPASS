/**
 * Canonical passport payload construction.
 *
 * The payload that gets hashed/encrypted is ALWAYS rebuilt from normalized
 * rows via `payloadFromRows` — both at create time (from the parsed input) and
 * at reattest time (from the DB rows). That guarantees the payloadHash is
 * reproducible from persisted state: unknown input fields never leak into the
 * hash, numeric types are normalized (SQLite may return decimals as strings),
 * and child arrays are deterministically ordered.
 */

export interface PassportInput {
    passportId: string;
    manufacturerId?: string | null;
    batteryCategory?: string | null;
    model?: string | null;
    manufactureDate?: string | null;
    weightKg?: number | string | null;
    performanceClass?: string | null;
    batteries?: Array<Record<string, unknown>> | null;
    recycledMaterials?: Array<Record<string, unknown>> | null;
    diligenceDocs?: Array<Record<string, unknown>> | null;
}

const BATTERY_FIELDS = [
    'serialNumber', 'cellChemistry', 'capacityKwh', 'carbonFootprintKgCO2', 'supplierName',
    'recycledContentPct', 'cycleLife', 'roundTripEfficiencyPct', 'leadContentPpm'
] as const;
const BATTERY_NUMERIC = new Set(['capacityKwh', 'carbonFootprintKgCO2', 'recycledContentPct', 'cycleLife', 'roundTripEfficiencyPct', 'leadContentPpm']);
const RECYCLED_FIELDS = ['material', 'recycledPercentage', 'sourceSupplierName'] as const;
const DILIGENCE_FIELDS = ['docType', 'storageRef', 'sha256Hex'] as const;

function num(v: unknown): number | null {
    if (v == null || v === '') return null;
    const n = Number(v);
    if (!Number.isFinite(n)) throw new Error(`not a number: ${String(v)}`);
    return n;
}
function str(v: unknown): string | null {
    if (v == null || v === '') return null;
    return String(v);
}

function pick(row: Record<string, unknown>, fields: readonly string[], numeric: Set<string>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const f of fields) {
        const v = numeric.has(f) ? num(row[f]) : str(row[f]);
        if (v != null) out[f] = v;
    }
    return out;
}

/**
 * Build the canonical payload object from (input or DB) rows. Child arrays are
 * sorted deterministically; numerics normalized to Number; nulls/empties dropped.
 */
export function payloadFromRows(p: {
    passportId: string;
    manufacturerId?: unknown; batteryCategory?: unknown; model?: unknown;
    manufactureDate?: unknown; weightKg?: unknown; performanceClass?: unknown;
    batteries?: Array<Record<string, unknown>> | null;
    recycledMaterials?: Array<Record<string, unknown>> | null;
    diligenceDocs?: Array<Record<string, unknown>> | null;
}): Record<string, unknown> {
    const payload: Record<string, unknown> = { passportId: p.passportId };
    const head: Array<[string, unknown]> = [
        ['manufacturerId', str(p.manufacturerId)],
        ['batteryCategory', str(p.batteryCategory)],
        ['model', str(p.model)],
        ['manufactureDate', str(p.manufactureDate)],
        ['weightKg', num(p.weightKg)],
        ['performanceClass', str(p.performanceClass)]
    ];
    for (const [k, v] of head) if (v != null) payload[k] = v;

    const batteries = (p.batteries ?? [])
        .map((b) => pick(b, BATTERY_FIELDS, BATTERY_NUMERIC))
        .sort((a, b) => String(a.serialNumber ?? '').localeCompare(String(b.serialNumber ?? '')));
    if (batteries.length) payload.batteries = batteries;

    const recycled = (p.recycledMaterials ?? [])
        .map((r) => pick(r, RECYCLED_FIELDS, new Set(['recycledPercentage'])))
        .sort((a, b) => String(a.material ?? '').localeCompare(String(b.material ?? '')));
    if (recycled.length) payload.recycledMaterials = recycled;

    const docs = (p.diligenceDocs ?? [])
        .map((d) => pick(d, DILIGENCE_FIELDS, new Set()))
        .sort((a, b) => `${a.docType}/${a.sha256Hex}`.localeCompare(`${b.docType}/${b.sha256Hex}`));
    if (docs.length) payload.diligenceDocs = docs;

    return payload;
}

/** Parse + validate a createPassport passportJson input. Throws with a clear message. */
export function parsePassportInput(passportJson: string): PassportInput {
    let parsed: unknown;
    try {
        parsed = JSON.parse(passportJson);
    } catch {
        throw new Error('passportJson is not valid JSON');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('passportJson must be a JSON object');
    }
    const p = parsed as PassportInput;
    if (!p.passportId || typeof p.passportId !== 'string' || p.passportId.length > 64) {
        throw new Error('passportId is required (string, max 64 chars)');
    }
    for (const key of ['batteries', 'recycledMaterials', 'diligenceDocs'] as const) {
        const v = p[key];
        if (v != null && !Array.isArray(v)) throw new Error(`${key} must be an array`);
    }
    if (p.weightKg != null && !Number.isFinite(Number(p.weightKg))) {
        throw new Error('weightKg must be numeric');
    }
    return p;
}
