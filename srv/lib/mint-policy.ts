import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Passport mint policy access.
 *
 * The compiled Plutus V3 artifact lives in `contracts/passport-mint-policy/`
 * (Aiken source + committed `plutus.json` blueprint, so consumers and CI never
 * need the Aiken toolchain).
 *
 * The validator is parameterized with the producer's 28-byte paymentKeyHash;
 * mint AND burn require that key in extra_signatories. ODATANO applies the
 * parameter server-side via `scriptParamsJson`; the encoding below
 * (`{"uplc":"data","value":{"bytes":<pkh>}}`) is PINNED by cross-check against
 * `aiken blueprint apply` + `aiken blueprint policy`: pkh
 * fa86ab6c36d5d32994cb6df00d40956386f6e7003e816a435aa9db88 must yield policyId
 * 8d37accd2efbeea47991b78d6c91424e85a48a47b23cd5b3bd22ddb1. Do not change one
 * side without the other.
 */

const BLUEPRINT_PATH = join(__dirname, '..', '..', 'contracts', 'passport-mint-policy', 'plutus.json');

let _compiledCode: string | null = null;

/** Unapplied (parameterized) Plutus V3 script CBOR hex from the blueprint. */
export function mintPolicyCompiledCode(): string {
    if (_compiledCode === null) {
        const blueprint = JSON.parse(readFileSync(BLUEPRINT_PATH, 'utf8')) as {
            validators: Array<{ title: string; compiledCode?: string }>;
        };
        const validator = blueprint.validators.find((v) => v.title.startsWith('passport_mint') && v.compiledCode);
        if (!validator?.compiledCode) {
            throw new Error(`passport_mint validator not found in ${BLUEPRINT_PATH} — recompile with "aiken build"`);
        }
        _compiledCode = validator.compiledCode;
    }
    return _compiledCode;
}

/** `scriptParamsJson` value applying the producer's paymentKeyHash (pinned encoding). */
export function mintPolicyParamsJson(paymentKeyHash: string): string {
    if (!/^[0-9a-fA-F]{56}$/.test(paymentKeyHash)) {
        throw new Error('paymentKeyHash must be 28 bytes hex (56 hex chars)');
    }
    return JSON.stringify([{ uplc: 'data', value: { bytes: paymentKeyHash.toLowerCase() } }]);
}

/** `requiredSignersJson` value ensuring extra_signatories carries the producer key. */
export function mintRequiredSignersJson(paymentKeyHash: string): string {
    if (!/^[0-9a-fA-F]{56}$/.test(paymentKeyHash)) {
        throw new Error('paymentKeyHash must be 28 bytes hex (56 hex chars)');
    }
    return JSON.stringify([paymentKeyHash.toLowerCase()]);
}
