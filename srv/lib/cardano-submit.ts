import cds from '@sap/cds';
import { signTxCbor } from './tx-signer';

/**
 * Server-mode submission pipeline: sign an ODATANO build in-process and
 * submit it, then poll the chain until the tx is visible. DB-free by design —
 * the producer-service handlers own PassportTransactions rows via the
 * outcome values.
 *
 * Talks to the plugin services in-process (`cds.connect.to`), not via HTTP.
 */

export interface BuildRow {
    id: string;             // TransactionBuilds.ID (buildId)
    unsignedTxCbor: string;
    txBodyHash: string;
}

export interface SubmitOutcome {
    submissionId: string;
    txHash: string;
    status: string;         // ODATANO: pending | submitted | confirmed | failed
}

export function explorerUrl(txHash: string, network: string = process.env.NETWORK || 'preview'): string {
    const host = network === 'mainnet' ? 'cardanoscan.io' : `${network}.cardanoscan.io`;
    return `https://${host}/transaction/${txHash}`;
}

/**
 * Send a plugin action in a DETACHED root transaction (fresh cds context),
 * mirroring the isolation of an HTTP call. Required when calling the ODATANO
 * services from inside an application handler: a Build persisted within the
 * caller's still-open request transaction is invisible to the plugin's
 * subsequent lookups ("Build not found"), because the plugin reads through its
 * own connection. Each detached send commits before the next one runs.
 */
export async function sendDetached(serviceName: string, action: string, data: Record<string, unknown>): Promise<any> {
    const srv = await cds.connect.to(serviceName);
    return (cds as any).tx({}, () => srv.send(action, data as any));
}

/** Sign a build with the server key and submit it. */
export async function submitServerSigned(build: BuildRow, seedHex: string): Promise<SubmitOutcome> {
    const { signedTxCbor } = signTxCbor(build.unsignedTxCbor, seedHex, build.txBodyHash);
    const submission: any = await sendDetached('CardanoTransactionService', 'SubmitTransaction', { buildId: build.id, signedTxCbor });
    return {
        submissionId: String(submission.ID ?? submission.id ?? ''),
        txHash: String(submission.txHash ?? ''),
        status: String(submission.status ?? 'submitted')
    };
}

/**
 * Ensure the address can serve Plutus collateral (the mint policy is a Plutus
 * script). ODATANO's SetCollateral is idempotent: with >= 2 qualifying UTxOs it
 * returns `collateralAvailable: true`; otherwise it builds a 5-ADA self-send,
 * which we sign, submit and wait for. Returns the collateral tx hash, or null
 * if none was needed.
 */
export async function ensureCollateral(address: string, seedHex: string, opts: ConfirmationOpts = {}): Promise<string | null> {
    const result: any = await sendDetached('CardanoTransactionService', 'SetCollateral', { address });
    if (result.collateralAvailable === true || !result.unsignedTxCbor) return null;
    const outcome = await submitServerSigned(
        { id: String(result.ID ?? result.id), unsignedTxCbor: result.unsignedTxCbor, txBodyHash: result.txBodyHash },
        seedHex
    );
    await waitForConfirmation(outcome.txHash, opts);
    return outcome.txHash;
}

export interface ConfirmationOpts {
    intervalMs?: number;   // default 15s (Preview block time ~20s + indexer lag)
    timeoutMs?: number;    // default 10min
}

/**
 * Poll until the tx is visible on-chain (via the plugin's indexer-backed
 * GetTransactionByHash). Returns the on-chain tx row. Throws on timeout.
 */
export async function waitForConfirmation(txHash: string, opts: ConfirmationOpts = {}): Promise<any> {
    const { intervalMs = 15_000, timeoutMs = 600_000 } = opts;
    const deadline = Date.now() + timeoutMs;
    let lastError = '';
    while (Date.now() < deadline) {
        try {
            const tx: any = await sendDetached('CardanoODataService', 'GetTransactionByHash', { hash: txHash });
            if (tx) return tx;
        } catch (e: any) {
            lastError = String(e?.message ?? e);
            const notFound = e?.code === 404 || e?.status === 404 || /not.?found/i.test(lastError);
            if (!notFound) throw e;
        }
        await new Promise((r) => setTimeout(r, intervalMs));
    }
    throw new Error(`tx ${txHash} not visible on-chain within ${Math.round(timeoutMs / 1000)}s (last: ${lastError})`);
}
