import cds from '@sap/cds';
import { getCardanoClient } from '@odatano/core';
import { hashPayload, blake2b256Hex, encryptPayload, decryptPayload, buildContentRoot, fieldValuesFor, scaleValue } from './lib/passport-anchor';
import { payloadFromRows, parsePassportInput } from './lib/passport-payload';
import { mintPolicyCompiledCode, mintPolicyParamsJson, mintRequiredSignersJson } from './lib/mint-policy';
import { composeMintMetadataJson, composeAnchorMetadataJson, assetNameHexFor, anchorLabel } from './lib/metadata-composer';
import { paymentKeyHashFromSeed } from './lib/tx-signer';
import { normalizeGrantee } from './lib/grantee';
import { buildAspectJson, buildPacJson, isExportableProof } from './lib/catenax';
import { submitServerSigned, waitForConfirmation, ensureCollateral, explorerUrl, sendDetached } from './lib/cardano-submit';
import { zkProverEnabled, fetchPoseidonRoot, anchorOutdated, ZkProverUnreachableError, provePredicate, fetchValidator, unwrapCborByteString, ZkProveResult } from './lib/zk-prover';
import { createChallenge, consumeChallenge, createSession, sessionFor, dropSession, WalletSession } from './lib/wallet-session';

const { INSERT, SELECT, UPDATE } = cds.ql;

const PASSPORTS = 'passport.Passports';
const BATTERIES = 'passport.Batteries';
const RECYCLED = 'passport.RecycledMaterials';
const DILIGENCE = 'passport.DiligenceDoc';
const TXLOG = 'passport.PassportTransactions';
const PRODUCER_KEYS = 'passport.ProducerKeys';
const GRANTLOG = 'passport.DisclosureGrantLog';
const PROOFLOG = 'passport.PredicateProofLog';

const MINT_LOVELACE = '2000000';
const ANCHOR_LOVELACE = '1500000';

const logger = cds.log('daypass-producer');

interface ServerCreds { seedHex: string; address: string; pkh: string; }

interface PipelineArgs {
    kind: 'mint' | 'reattest' | 'burn' | 'grant' | 'revoke' | 'zkProve';
    txRowId: string;
    passportRowId: string;
    creds: ServerCreds;
    passport: {
        passportId: string; passportIdHash: string;
        unit?: string; assetName?: string; lastAnchorTxHash?: string; anchorVersion?: number;
        point1: Record<string, unknown>;
    };
    payloadHash?: string;
    contentRoot?: string;
    poseidonRoot?: string;
    version?: number;
    /** grant/revoke audit anchor: pseudonymous grantee + level + log row to update. */
    grantee?: string;
    level?: number;
    grantLogId?: string;
    /** zkProve (Track B): predicate inputs + proof-log row; proof is generated in-pipeline. */
    zk?: {
        proofLogId: string;
        sourceField: string;
        predicate: 'lessOrEqual' | 'greaterOrEqual';
        thresholdScaled: string;
        values: Record<string, number | string>;
    };
}

/**
 * ProducerService — manufacturer / ERP write side. See producer-service.cds.
 *
 * Transaction model: the OData actions only do LOCAL writes inside the request
 * transaction and return immediately (`mode: 'submitting'`). The whole chain
 * pipeline (collateral, build, sign, submit, confirmation) runs AFTER the
 * request committed, with every step — plugin call or own DB write — in its
 * own short root transaction (`cds.tx({})`). Rationale: the plugin's actions
 * write via `cds.tx(req)` but read via the root connection, so nesting them in
 * a long-lived request transaction either misses rows ("Build not found") or
 * deadlocks on SQLite's single writer. Clients watch Passports.status and
 * PassportTransactions for txHash / confirmation.
 */
export default class ProducerService extends cds.ApplicationService {
    private policyIdCache = new Map<string, string>();

    override async init(): Promise<void> {
        this.on('createPassport', (req) => this.onCreatePassport(req));
        this.on('submitPassport', (req) => this.onSubmitPassport(req));
        this.on('revokePassport', (req) => this.onRevokePassport(req));
        this.on('verifyPassportOnChain', (req) => this.onVerifyPassportOnChain(req));
        this.on('grantPassportDisclosure', (req) => this.onDisclosureOp(req, 'grant'));
        this.on('revokePassportDisclosure', (req) => this.onDisclosureOp(req, 'revoke'));
        this.on('disclosePassportValue', (req) => this.onDisclosePassportValue(req));
        this.on('passportFieldValue', (req) => this.onPassportFieldValue(req));
        this.on('prepareWalletMint', (req) => this.onPrepareWalletMint(req));
        this.on('prepareWalletAnchor', (req) => this.onPrepareWalletAnchor(req));
        this.on('prepareWalletReattest', (req) => this.onPrepareWalletReattest(req));
        this.on('prepareWalletPredicate', (req) => this.onPrepareWalletPredicate(req));
        this.on('prepareWalletBurn', (req) => this.onPrepareWalletBurn(req));
        this.on('passportAspectJson', (req) => this.onPassportAspectJson(req));
        this.on('passportCredential', (req) => this.onPassportCredential(req));
        this.on('recordWalletMint', (req) => this.onRecordWalletMint(req));
        this.on('recordWalletDisclosure', (req) => this.onRecordWalletDisclosure(req));
        this.on('recordWalletPredicate', (req) => this.onRecordWalletPredicate(req));
        this.on('recordWalletReattest', (req) => this.onRecordWalletReattest(req));
        this.on('recordWalletBurn', (req) => this.onRecordWalletBurn(req));
        this.on('provePassportPredicate', (req) => this.onProvePassportPredicate(req));
        this.on('walletLoginChallenge', (req) => this.onWalletLoginChallenge(req));
        this.on('walletLogin', (req) => this.onWalletLogin(req));
        this.on('walletLogout', (req) => this.onWalletLogout(req));

        // Wallet-session scoping: requests carrying `x-wallet-session` see and
        // touch ONLY the passports owned by the proven wallet address.
        this.before(['READ', 'UPDATE', 'DELETE'], 'Passports', (req) => this.scopeToWallet(req, 'owner'));
        for (const entity of ['Batteries', 'RecycledMaterials', 'DiligenceDoc',
            'PassportTransactions', 'DisclosureGrantLog', 'PredicateProofLog']) {
            this.before(['READ', 'UPDATE', 'DELETE'], entity, (req) => this.scopeToWallet(req, 'passport.owner'));
        }
        this.before([
            'submitPassport', 'revokePassport', 'verifyPassportOnChain',
            'grantPassportDisclosure', 'revokePassportDisclosure',
            'disclosePassportValue', 'passportFieldValue', 'provePassportPredicate',
            'passportAspectJson', 'passportCredential',
            'prepareWalletMint', 'prepareWalletAnchor', 'prepareWalletReattest',
            'prepareWalletPredicate', 'prepareWalletBurn',
            'recordWalletMint', 'recordWalletDisclosure', 'recordWalletPredicate',
            'recordWalletReattest', 'recordWalletBurn'
        ], (req: any) => this.guardWalletAction(req));
        return super.init();
    }

    // --- config helpers -------------------------------------------------------

    private serverCreds(): ServerCreds | null {
        const seedHex = process.env.PRODUCER_PAYMENT_SKEY;
        const address = process.env.PRODUCER_ADDRESS;
        if (!seedHex || !address) return null;
        return { seedHex, address, pkh: paymentKeyHashFromSeed(seedHex) };
    }

    private publicBaseUrl(): string {
        return (process.env.DAYPASS_PUBLIC_URL ?? 'http://localhost:4004').replace(/\/$/, '');
    }

    // --- wallet-session scoping ------------------------------------------------

    /** Session behind the request's `x-wallet-session` header. No header ->
     * null (trusted server-to-server path); an invalid/expired token -> 401. */
    private walletSession(req: any): WalletSession | null {
        const token = req.headers?.['x-wallet-session'];
        if (!token) return null;
        const session = sessionFor(String(token));
        if (!session) {
            req.reject(401, 'wallet session invalid or expired — sign in with your wallet again');
            return null;
        }
        return session;
    }

    /** Narrow entity reads/writes to the session wallet's passports. */
    private scopeToWallet(req: any, ownerPath: string): void {
        const session = this.walletSession(req);
        if (!session) return;
        req.query.where({ [ownerPath]: session.address });
    }

    /** Passport-bound actions: the target passport must belong to the session
     * wallet, and any walletAddress argument must BE the session wallet. */
    private async guardWalletAction(req: any): Promise<void> {
        const session = this.walletSession(req);
        if (!session) return;
        if (req.data?.walletAddress && String(req.data.walletAddress) !== session.address) {
            return req.reject(403, 'walletAddress does not match the signed-in wallet');
        }
        const passportId = req.data?.passportId;
        if (!passportId) return;
        const row: any = await SELECT.one.from(PASSPORTS).columns('owner').where({ passportId });
        if (row && row.owner !== session.address) {
            return req.reject(403, `passport "${passportId}" belongs to another wallet`);
        }
    }

    /** Run a DB operation in its own short root transaction (commits immediately). */
    private runDetached<T>(fn: () => Promise<T>): Promise<T> {
        return (cds as any).tx({}, fn);
    }

    /** Derive (and cache) the policyId for a producer key; upsert ProducerKeys. */
    private async policyIdFor(creds: ServerCreds): Promise<string> {
        const cached = this.policyIdCache.get(creds.pkh);
        if (cached) return cached;
        const derived: any = await sendDetached('CardanoTransactionService', 'DeriveScriptAddress', {
            validatorScript: mintPolicyCompiledCode(),
            scriptParamsJson: mintPolicyParamsJson(creds.pkh)
        });
        const policyId = String(derived.scriptHash);
        await this.runDetached(async () => {
            const existing = await SELECT.one.from(PRODUCER_KEYS).where({ paymentKeyHash: creds.pkh });
            if (!existing) {
                await INSERT.into(PRODUCER_KEYS).entries({
                    address: creds.address, paymentKeyHash: creds.pkh, policyId, label: 'server key', isActive: true
                });
            }
        });
        this.policyIdCache.set(creds.pkh, policyId);
        return policyId;
    }

    /**
     * Fetch the Julc-compiled Groth16 verifier policy from the prover and make
     * sure ODATANO hashes it to the same policyId as the Java side. Julc's
     * getCborHex may carry one extra CBOR byte-string wrap compared to what
     * DeriveScriptAddress expects; if the hashes differ, retry with one layer
     * stripped. Cached per predicate op.
     */
    private zkPolicyCache = new Map<string, { cborHex: string; scriptHash: string }>();
    private async resolveZkPolicy(op: 'lessOrEqual' | 'greaterOrEqual', opts: { inRequest?: boolean } = {}): Promise<{ cborHex: string; scriptHash: string }> {
        const cached = this.zkPolicyCache.get(op);
        if (cached) return cached;
        const info = await fetchValidator(op);
        const candidates = [info.cborHex];
        const unwrapped = unwrapCborByteString(info.cborHex);
        if (unwrapped) candidates.push(unwrapped);
        // DeriveScriptAddress is read-only, so a plain send is fine inside a
        // request handler; detached sends (cds.tx({})) crash in-request.
        const txService = opts.inRequest ? await cds.connect.to('CardanoTransactionService') : null;
        for (const cborHex of candidates) {
            const derived: any = txService
                ? await txService.send('DeriveScriptAddress', { validatorScript: cborHex })
                : await sendDetached('CardanoTransactionService', 'DeriveScriptAddress', { validatorScript: cborHex });
            if (String(derived.scriptHash).toLowerCase() === info.scriptHash.toLowerCase()) {
                const resolved = { cborHex, scriptHash: info.scriptHash.toLowerCase() };
                this.zkPolicyCache.set(op, resolved);
                return resolved;
            }
        }
        throw new Error(`zk verifier policy hash mismatch: prover says ${info.scriptHash}, ODATANO derives differently for both wrap variants`);
    }

    /** Load a passport row + composition children by human-readable passportId.
     * payloadCipher must be requested explicitly (CAP omits LargeBinary from `*`). */
    private async loadPassport(passportId: string) {
        const row: any = await SELECT.one.from(PASSPORTS).columns('*', 'payloadCipher').where({ passportId });
        if (!row) return null;
        const [batteries, recycledMaterials, diligenceDocs] = await Promise.all([
            SELECT.from(BATTERIES).where({ passport_ID: row.ID }),
            SELECT.from(RECYCLED).where({ passport_ID: row.ID }),
            SELECT.from(DILIGENCE).where({ passport_ID: row.ID })
        ]);
        return { row, batteries, recycledMaterials, diligenceDocs };
    }

    /** Canonical payload + hashes + content root from row-shaped data. */
    private derivePayload(rowLike: any, batteries: any[], recycledMaterials: any[], diligenceDocs: any[]) {
        const payload = payloadFromRows({ ...rowLike, batteries, recycledMaterials, diligenceDocs });
        const { canonicalPayload, payloadHash } = hashPayload(payload);
        const fieldValues = fieldValuesFor(payload as any);
        const tree = buildContentRoot(fieldValues);
        return { payload, canonicalPayload, payloadHash, contentRoot: tree.contentRoot, fieldValues };
    }

    private point1Of(rowLike: any): Record<string, unknown> {
        return {
            manufacturerId: rowLike.manufacturerId, batteryCategory: rowLike.batteryCategory,
            model: rowLike.model, manufactureDate: rowLike.manufactureDate,
            weightKg: rowLike.weightKg, performanceClass: rowLike.performanceClass
        };
    }

    // --- background anchor pipeline ------------------------------------------------

    /** Kick off the chain pipeline after the request transaction committed. */
    private startPipeline(args: PipelineArgs): void {
        setImmediate(() => {
            this.runPipeline(args).catch(async (e) => {
                const message = String(e?.message ?? e).slice(0, 1000);
                logger.error(`pipeline ${args.kind} for ${args.passport.passportId} failed: ${message}`);
                try {
                    await this.runDetached(async () => {
                        await UPDATE.entity(TXLOG).set({ status: 'failed', errorMessage: message }).where({ ID: args.txRowId });
                        if (args.kind === 'mint' || args.kind === 'reattest') {
                            await UPDATE.entity(PASSPORTS).set({ status: 'failed' }).where({ ID: args.passportRowId });
                        }
                        if ((args.kind === 'grant' || args.kind === 'revoke') && args.grantLogId) {
                            await UPDATE.entity(GRANTLOG).set({ status: 'failed' }).where({ ID: args.grantLogId });
                        }
                        if (args.kind === 'zkProve' && args.zk) {
                            await UPDATE.entity(PROOFLOG).set({ status: 'failed' }).where({ ID: args.zk.proofLogId });
                        }
                    });
                } catch (persistErr) {
                    logger.error('could not persist pipeline failure', persistErr);
                }
            });
        });
    }

    private async runPipeline(args: PipelineArgs): Promise<void> {
        // Give the request transaction a moment to commit its rows.
        await new Promise((r) => setTimeout(r, 500));
        const { creds, passport } = args;
        const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

        // 1. Prepare (mint/burn need policy + collateral; the metadata kinds don't).
        let unit = passport.unit ?? '';
        let policyId = '';
        let assetNameHex = '';
        if (args.kind === 'mint') {
            policyId = await this.policyIdFor(creds);
            assetNameHex = assetNameHexFor(passport.passportId, passport.passportIdHash);
            unit = policyId + assetNameHex;
            await this.runDetached(async () => { await UPDATE.entity(PASSPORTS).set({ policyId, assetName: assetNameHex, unit }).where({ ID: args.passportRowId }); });
        }
        if (args.kind === 'mint' || args.kind === 'burn' || args.kind === 'zkProve') {
            const collateralTx = await ensureCollateral(creds.address, creds.seedHex);
            if (collateralTx) {
                // @odatano/core >= 1.9.4 invalidates the UTxO cache on submit;
                // this short pause only covers Blockfrost's indexing lag after
                // the confirmation (the stale-input retry below is the backstop).
                logger.info(`collateral tx ${collateralTx} confirmed, allowing for backend indexing lag`);
                await sleep(15_000);
            }
        }

        // zkProve: generate the Groth16 proof and resolve the verifier policy ONCE
        // (deterministic, reusable across build retries).
        let zkProof: ZkProveResult | null = null;
        let zkPolicy: { cborHex: string; scriptHash: string } | null = null;
        if (args.kind === 'zkProve' && args.zk) {
            zkProof = await provePredicate({
                values: args.zk.values, sourceField: args.zk.sourceField,
                thresholdScaled: args.zk.thresholdScaled, op: args.zk.predicate
            });
            logger.info(`zk proof for ${passport.passportId}.${args.zk.sourceField} generated in ${zkProof.proofTimeMs} ms, compliant: ${zkProof.isCompliant}`);
            zkPolicy = await this.resolveZkPolicy(args.zk.predicate);
            await this.runDetached(async () => {
                await UPDATE.entity(PROOFLOG).set({
                    result: zkProof!.isCompliant,
                    proofJson: JSON.stringify({
                        poseidonRoot: zkProof!.poseidonRoot, fieldKey: zkProof!.fieldKey,
                        threshold: zkProof!.threshold, isCompliant: zkProof!.isCompliant,
                        policyId: zkPolicy!.scriptHash, redeemer: zkProof!.redeemerJson, datum: zkProof!.datumJson
                    })
                }).where({ ID: args.zk!.proofLogId });
            });
        }

        const buildTx = async (): Promise<any> => {
            if (args.kind === 'mint') {
                return sendDetached('CardanoTransactionService', 'BuildMintTransaction', {
                    senderAddress: creds.address, recipientAddress: creds.address,
                    lovelaceAmount: MINT_LOVELACE,
                    mintActionsJson: JSON.stringify([{ assetUnit: assetNameHex, quantity: '1' }]),
                    validityStartMs: String(Date.now() - 300_000),
                    mintingPolicyScript: mintPolicyCompiledCode(),
                    scriptParamsJson: mintPolicyParamsJson(creds.pkh),
                    requiredSignersJson: mintRequiredSignersJson(creds.pkh),
                    metadataJson: composeMintMetadataJson({
                        policyId, assetNameHex,
                        anchor: {
                            op: 'attest', passportId: passport.passportId, passportIdHash: passport.passportIdHash,
                            payloadHash: args.payloadHash!, contentRoot: args.contentRoot!,
                            poseidonRoot: args.poseidonRoot,
                            version: 1, point1: passport.point1
                        }
                    })
                });
            }
            if (args.kind === 'reattest') {
                return sendDetached('CardanoTransactionService', 'BuildTransactionWithMetadata', {
                    senderAddress: creds.address, recipientAddress: creds.address,
                    lovelaceAmount: ANCHOR_LOVELACE,
                    metadataJson: composeAnchorMetadataJson({
                        op: 'reattest', passportId: passport.passportId, passportIdHash: passport.passportIdHash,
                        payloadHash: args.payloadHash!, contentRoot: args.contentRoot!,
                        poseidonRoot: args.poseidonRoot,
                        version: args.version!, unit: passport.unit, prev: passport.lastAnchorTxHash,
                        point1: passport.point1
                    })
                });
            }
            if (args.kind === 'burn') {
                // Resolve the NFT-holding UTxO FRESH on every attempt: any tx in
                // between (reattest, grant) may have moved the NFT to a new output.
                const utxos: any[] = await getCardanoClient().getAddressUtxos(creds.address);
                const holder = utxos.find((u: any) =>
                    (u.amount ?? []).some((a: any) => a.unit === passport.unit && BigInt(a.quantity) > 0n));
                if (!holder) throw new Error(`NFT ${passport.unit} not found in the producer wallet — cannot burn`);
                return sendDetached('CardanoTransactionService', 'BuildMintTransaction', {
                    senderAddress: creds.address, recipientAddress: creds.address,
                    lovelaceAmount: ANCHOR_LOVELACE,
                    mintActionsJson: JSON.stringify([{ assetUnit: passport.assetName, quantity: '-1' }]),
                    validityStartMs: String(Date.now() - 300_000),
                    mintingPolicyScript: mintPolicyCompiledCode(),
                    scriptParamsJson: mintPolicyParamsJson(creds.pkh),
                    requiredSignersJson: mintRequiredSignersJson(creds.pkh),
                    forceInputsJson: JSON.stringify([{ txHash: holder.txHash, outputIndex: holder.outputIndex }]),
                    metadataJson: composeAnchorMetadataJson({
                        op: 'burn', passportId: passport.passportId, passportIdHash: passport.passportIdHash,
                        unit: passport.unit, prev: passport.lastAnchorTxHash
                    })
                });
            }
            if (args.kind === 'zkProve') {
                // Track B: mint ONE predicate token under the Groth16 verifier
                // policy. The redeemer carries the proof, the first output's
                // inline datum the public inputs; the policy only passes when
                // the proof verifies on-chain AND isCompliant is 1.
                return sendDetached('CardanoTransactionService', 'BuildMintTransaction', {
                    senderAddress: creds.address, recipientAddress: creds.address,
                    lovelaceAmount: MINT_LOVELACE,
                    mintActionsJson: JSON.stringify([{ assetUnit: passport.passportIdHash, quantity: '1' }]),
                    validityStartMs: String(Date.now() - 300_000),
                    mintingPolicyScript: zkPolicy!.cborHex,
                    mintRedeemerJson: JSON.stringify(zkProof!.redeemerJson),
                    inlineDatumJson: JSON.stringify(zkProof!.datumJson),
                    metadataJson: composeAnchorMetadataJson({
                        op: 'predicate', passportId: passport.passportId, passportIdHash: passport.passportIdHash,
                        unit: passport.unit, fieldKey: blake2b256Hex(args.zk!.sourceField),
                        predicate: args.zk!.predicate, threshold: Number(args.zk!.thresholdScaled),
                        result: zkProof!.isCompliant
                    })
                });
            }
            // grant / revoke audit anchor: metadata-only, pseudonymous grantee.
            return sendDetached('CardanoTransactionService', 'BuildTransactionWithMetadata', {
                senderAddress: creds.address, recipientAddress: creds.address,
                lovelaceAmount: ANCHOR_LOVELACE,
                metadataJson: composeAnchorMetadataJson({
                    op: args.kind as 'grant' | 'revoke', passportId: passport.passportId, passportIdHash: passport.passportIdHash,
                    unit: passport.unit, grantee: args.grantee, level: args.level
                })
            });
        };

        // 2. Build -> sign -> submit, with a rebuild retry when the indexer's
        // UTxO cache served already-spent inputs (previous tx in the same window).
        let build: any;
        let outcome!: Awaited<ReturnType<typeof submitServerSigned>>;
        for (let attempt = 1; ; attempt++) {
            try {
                build = await buildTx();
                await this.runDetached(async () => { await UPDATE.entity(TXLOG).set({ buildId: build.id }).where({ ID: args.txRowId }); });
                outcome = await submitServerSigned(
                    { id: build.id, unsignedTxCbor: build.unsignedTxCbor, txBodyHash: build.txBodyHash }, creds.seedHex
                );
                break;
            } catch (e: any) {
                const msg = String(e?.message ?? e);
                const staleInputs = /inputs are spent|already spent|BadInputsUTxO|ValueNotConservedUTxO/i.test(msg);
                if (!staleInputs || attempt >= 3) throw e;
                // Cache invalidation on submit (core >= 1.9.4) makes stale reads
                // rare; when they still happen it is backend indexing lag, so a
                // short backoff per attempt is enough.
                logger.warn(`build/submit attempt ${attempt} hit stale UTxOs — backing off, then rebuilding`);
                await sleep(15_000 * attempt);
            }
        }
        await this.runDetached(async () => {
            await UPDATE.entity(TXLOG).set({
                txHash: outcome.txHash, submissionId: outcome.submissionId,
                status: 'submitted', explorerUrl: explorerUrl(outcome.txHash)
            }).where({ ID: args.txRowId });
            if (args.kind === 'mint') {
                await UPDATE.entity(PASSPORTS).set({
                    attestationTxHash: outcome.txHash, lastAnchorTxHash: outcome.txHash, anchorVersion: 1
                }).where({ ID: args.passportRowId });
            } else if (args.kind === 'reattest') {
                await UPDATE.entity(PASSPORTS).set({
                    lastAnchorTxHash: outcome.txHash, anchorVersion: args.version
                }).where({ ID: args.passportRowId });
            } else if (args.grantLogId) {
                await UPDATE.entity(GRANTLOG).set({ txHash: outcome.txHash, status: 'submitted' }).where({ ID: args.grantLogId });
            } else if (args.kind === 'zkProve' && args.zk) {
                await UPDATE.entity(PROOFLOG).set({ txHash: outcome.txHash, status: 'submitted' }).where({ ID: args.zk.proofLogId });
            }
        });

        // 3. Wait for on-chain confirmation, then finalize.
        const onChain: any = await waitForConfirmation(outcome.txHash);
        await this.runDetached(async () => { await UPDATE.entity(TXLOG).set({ status: 'confirmed', blockHash: onChain?.blockHash ?? null }).where({ ID: args.txRowId }); });

        if (args.kind === 'burn') {
            await this.runDetached(async () => { await UPDATE.entity(PASSPORTS).set({ status: 'revoked' }).where({ ID: args.passportRowId }); });
            return;
        }
        if (args.kind === 'grant' || args.kind === 'revoke') {
            if (args.grantLogId) {
                await this.runDetached(async () => { await UPDATE.entity(GRANTLOG).set({ status: 'confirmed' }).where({ ID: args.grantLogId }); });
            }
            logger.info(`pipeline ${args.kind} anchor for ${passport.passportId} confirmed: ${outcome.txHash}`);
            return;
        }
        if (args.kind === 'zkProve') {
            if (args.zk) {
                await this.runDetached(async () => { await UPDATE.entity(PROOFLOG).set({ status: 'confirmed' }).where({ ID: args.zk!.proofLogId }); });
            }
            logger.info(`pipeline zk predicate for ${passport.passportId} confirmed: ${outcome.txHash}`);
            return;
        }
        const patch: Record<string, unknown> = { status: 'anchored' };
        if (args.kind === 'mint' && unit) {
            try {
                const asset: any = await sendDetached('CardanoODataService', 'GetAssetInfo', { unit });
                if (asset?.fingerprint) patch.fingerprint = asset.fingerprint;
            } catch { /* fingerprint is cosmetic; ignore */ }
        }
        await this.runDetached(async () => { await UPDATE.entity(PASSPORTS).set(patch).where({ ID: args.passportRowId }); });
        logger.info(`pipeline ${args.kind} for ${passport.passportId} confirmed: ${outcome.txHash}`);
    }

    // --- actions -------------------------------------------------------------------

    private async onCreatePassport(req: any) {
        const { passportJson, submit } = req.data;
        const signMode = req.data.signMode || 'server';
        let input;
        try {
            input = parsePassportInput(String(passportJson ?? ''));
        } catch (e: any) {
            return req.error(400, e.message);
        }
        const existing = await SELECT.one.from(PASSPORTS).where({ passportId: input.passportId });
        if (existing) return req.error(409, `passportId "${input.passportId}" already exists`);

        let creds: ServerCreds | null = null;
        if (submit) {
            if (signMode !== 'server') {
                return req.error(400, 'signMode "wallet" is the cockpit path — use signMode "server" or submit: false');
            }
            creds = this.serverCreds();
            if (!creds) return req.error(400, 'server signing not configured (PRODUCER_PAYMENT_SKEY / PRODUCER_ADDRESS)');
        }

        const { canonicalPayload, payloadHash, contentRoot, fieldValues } = this.derivePayload(
            input, input.batteries ?? [], input.recycledMaterials ?? [], input.diligenceDocs ?? []
        );
        // Anchoring (submit) with a configured prover REQUIRES the poseidonRoot;
        // drafts stay best-effort (the root is recomputed at submit time anyway).
        let poseidonRoot: string | null;
        try {
            poseidonRoot = await fetchPoseidonRoot(fieldValues, { required: !!creds });
        } catch (e) {
            if (e instanceof ZkProverUnreachableError) return req.error(503, e.message);
            throw e;
        }
        const passportIdHash = blake2b256Hex(input.passportId);
        const qrCodeUrl = `${this.publicBaseUrl()}/p/${encodeURIComponent(input.passportId)}`;
        const passportRowId = cds.utils.uuid();
        const txRowId = cds.utils.uuid();

        await INSERT.into(PASSPORTS).entries({
            ID: passportRowId,
            passportId: input.passportId,
            // A signed-in wallet always owns what it creates; the owner param
            // only applies on the trusted server-to-server path.
            owner: this.walletSession(req)?.address || req.data.owner || process.env.PRODUCER_ADDRESS || null,
            manufacturerId: input.manufacturerId, batteryCategory: input.batteryCategory,
            model: input.model, manufactureDate: input.manufactureDate,
            weightKg: input.weightKg != null ? Number(input.weightKg) : null,
            performanceClass: input.performanceClass, qrCodeUrl,
            payloadCipher: encryptPayload(canonicalPayload, input.passportId),
            payloadHash, passportIdHash, contentRoot, poseidonRoot,
            status: submit ? 'anchoring' : 'draft',
            batteries: (input.batteries ?? []).map((b: any) => ({
                serialNumber: b.serialNumber, cellChemistry: b.cellChemistry, capacityKwh: b.capacityKwh,
                carbonFootprintKgCO2: b.carbonFootprintKgCO2, supplierName: b.supplierName,
                recycledContentPct: b.recycledContentPct, cycleLife: b.cycleLife,
                roundTripEfficiencyPct: b.roundTripEfficiencyPct, leadContentPpm: b.leadContentPpm
            })),
            recycledMaterials: (input.recycledMaterials ?? []).map((r: any) => ({
                material: r.material, recycledPercentage: r.recycledPercentage, sourceSupplierName: r.sourceSupplierName
            })),
            diligenceDocs: (input.diligenceDocs ?? []).map((d: any) => ({
                docType: d.docType, storageRef: d.storageRef, sha256Hex: d.sha256Hex
            }))
        });

        if (!submit || !creds) {
            return { passportId: input.passportId, payloadHash, contentRoot, mode: 'offline' };
        }
        await INSERT.into(TXLOG).entries({ ID: txRowId, passport_ID: passportRowId, kind: 'mint', status: 'pending' });
        this.startPipeline({
            kind: 'mint', txRowId, passportRowId, creds,
            passport: { passportId: input.passportId, passportIdHash, point1: this.point1Of(input) },
            payloadHash, contentRoot, poseidonRoot: poseidonRoot ?? undefined
        });
        return { passportId: input.passportId, payloadHash, contentRoot, mode: 'submitting' };
    }

    private async onSubmitPassport(req: any) {
        const { passportId } = req.data;
        const signMode = req.data.signMode || 'server';
        if (!passportId) return req.error(400, 'passportId is required');
        if (signMode !== 'server') {
            return req.error(400, 'signMode "wallet" is the cockpit path — use signMode "server"');
        }
        const creds = this.serverCreds();
        if (!creds) return req.error(400, 'server signing not configured (PRODUCER_PAYMENT_SKEY / PRODUCER_ADDRESS)');
        const loaded = await this.loadPassport(String(passportId));
        if (!loaded) return req.error(404, `passport "${passportId}" not found`);
        const { row, batteries, recycledMaterials, diligenceDocs } = loaded;
        if (row.status === 'anchoring') return req.error(409, 'a submission is already in flight');
        if (row.status === 'revoked') return req.error(409, 'passport is revoked');

        const { canonicalPayload, payloadHash, contentRoot, fieldValues } = this.derivePayload(row, batteries, recycledMaterials, diligenceDocs);
        // submitPassport always anchors (mint or reattest): with a configured
        // prover the poseidonRoot is mandatory, no silent Track A only anchor.
        let poseidonRoot: string | null;
        try {
            poseidonRoot = await fetchPoseidonRoot(fieldValues, { required: true });
        } catch (e) {
            if (e instanceof ZkProverUnreachableError) return req.error(503, e.message);
            throw e;
        }
        const txRowId = cds.utils.uuid();

        // Draft / failed / never anchored -> mint. Persist the recomputed payload
        // first (rows may have changed since the draft was created).
        if (!row.attestationTxHash || row.status === 'draft' || row.status === 'failed') {
            await UPDATE.entity(PASSPORTS).set({
                payloadCipher: encryptPayload(canonicalPayload, row.passportId),
                payloadHash, contentRoot, poseidonRoot, status: 'anchoring'
            }).where({ ID: row.ID });
            await INSERT.into(TXLOG).entries({ ID: txRowId, passport_ID: row.ID, kind: 'mint', status: 'pending' });
            this.startPipeline({
                kind: 'mint', txRowId, passportRowId: row.ID, creds,
                passport: { passportId: row.passportId, passportIdHash: row.passportIdHash, point1: this.point1Of(row) },
                payloadHash, contentRoot, poseidonRoot: poseidonRoot ?? undefined
            });
            return { passportId: row.passportId, mode: 'submitting', kind: 'mint', payloadHash };
        }

        // Anchored: re-attest when the payload changed, or to upgrade a pre-ZK
        // anchor with the now-available poseidonRoot (anchor v2).
        if (!anchorOutdated({ payloadHash, rowPayloadHash: row.payloadHash, poseidonRoot, rowPoseidonRoot: row.poseidonRoot })) {
            return { passportId: row.passportId, mode: 'unchanged', kind: 'reattest', payloadHash };
        }
        const version = Number(row.anchorVersion ?? 1) + 1;
        await UPDATE.entity(PASSPORTS).set({
            payloadCipher: encryptPayload(canonicalPayload, row.passportId),
            payloadHash, contentRoot, poseidonRoot, status: 'anchoring'
        }).where({ ID: row.ID });
        await INSERT.into(TXLOG).entries({ ID: txRowId, passport_ID: row.ID, kind: 'reattest', status: 'pending' });
        this.startPipeline({
            kind: 'reattest', txRowId, passportRowId: row.ID, creds,
            passport: {
                passportId: row.passportId, passportIdHash: row.passportIdHash,
                unit: row.unit, lastAnchorTxHash: row.lastAnchorTxHash, point1: this.point1Of(row)
            },
            payloadHash, contentRoot, poseidonRoot: poseidonRoot ?? undefined, version
        });
        return { passportId: row.passportId, mode: 'submitting', kind: 'reattest', payloadHash };
    }

    private async onRevokePassport(req: any) {
        const { passportId } = req.data;
        const signMode = req.data.signMode || 'server';
        if (!passportId) return req.error(400, 'passportId is required');
        if (signMode !== 'server') {
            return req.error(400, 'signMode "wallet" is the cockpit path — use signMode "server"');
        }
        const creds = this.serverCreds();
        if (!creds) return req.error(400, 'server signing not configured (PRODUCER_PAYMENT_SKEY / PRODUCER_ADDRESS)');
        const row: any = await SELECT.one.from(PASSPORTS).where({ passportId });
        if (!row) return req.error(404, `passport "${passportId}" not found`);
        if (!row.unit || row.status === 'draft') return req.error(409, 'passport was never anchored — nothing to burn');
        if (row.status === 'revoked') return req.error(409, 'passport is already revoked');
        if (row.status === 'anchoring') return req.error(409, 'a submission is already in flight');

        // Find the UTxO holding the NFT (must be in the producer wallet).
        const utxos = await getCardanoClient().getAddressUtxos(creds.address);
        const holder = utxos.find((u: any) => (u.amount ?? []).some((a: any) => a.unit === row.unit && BigInt(a.quantity) > 0n));
        if (!holder) return req.error(409, `NFT ${row.unit} not found in the producer wallet — cannot burn`);

        const txRowId = cds.utils.uuid();
        await INSERT.into(TXLOG).entries({ ID: txRowId, passport_ID: row.ID, kind: 'burn', status: 'pending' });
        this.startPipeline({
            kind: 'burn', txRowId, passportRowId: row.ID, creds,
            passport: {
                passportId: row.passportId, passportIdHash: row.passportIdHash,
                unit: row.unit, assetName: row.assetName, lastAnchorTxHash: row.lastAnchorTxHash,
                point1: this.point1Of(row)
            }
        });
        return { passportId: row.passportId, mode: 'submitting' };
    }

    // --- disclosure + Track A -------------------------------------------------------

    private async onDisclosureOp(req: any, op: 'grant' | 'revoke') {
        const { passportId, anchor } = req.data;
        if (!passportId) return req.error(400, 'passportId is required');
        let grantee: string;
        try {
            grantee = normalizeGrantee(String(req.data.grantee ?? ''));
        } catch (e: any) {
            return req.error(400, e.message);
        }
        const level = op === 'grant' ? Number(req.data.level) : 0;
        if (op === 'grant' && (!Number.isInteger(level) || level < 0 || level > 2)) {
            return req.error(400, 'level must be 0 (public), 1 (recycler) or 2 (authority)');
        }
        const row: any = await SELECT.one.from(PASSPORTS).where({ passportId });
        if (!row) return req.error(404, `passport "${passportId}" not found`);

        const wantAnchor = anchor === true || String(process.env.DAYPASS_ANCHOR_GRANTS ?? '') === 'true';
        const creds = wantAnchor ? this.serverCreds() : null;
        const doAnchor = wantAnchor && !!creds && row.status === 'anchored';

        const grantLogId = cds.utils.uuid();
        await INSERT.into(GRANTLOG).entries({
            ID: grantLogId, passport_ID: row.ID, grantee, level, op,
            status: doAnchor ? 'pending' : 'offline'
        });
        if (!doAnchor) return { mode: 'offline', grantee };

        const txRowId = cds.utils.uuid();
        await INSERT.into(TXLOG).entries({ ID: txRowId, passport_ID: row.ID, kind: op, status: 'pending' });
        this.startPipeline({
            kind: op, txRowId, passportRowId: row.ID, creds: creds!,
            passport: {
                passportId: row.passportId, passportIdHash: row.passportIdHash,
                unit: row.unit, point1: this.point1Of(row)
            },
            grantee, level, grantLogId
        });
        return { mode: 'submitting', grantee };
    }

    /** Resolve a provable field's value + inclusion proof from the current rows. */
    private async fieldProofFor(passportId: string, sourceField: string) {
        const loaded = await this.loadPassport(passportId);
        if (!loaded) return { error: 404, message: `passport "${passportId}" not found` } as const;
        const { row, batteries, recycledMaterials } = loaded;
        const values = fieldValuesFor({ batteries, recycledMaterials });
        const tree = buildContentRoot(values);
        if (tree.contentRoot !== row.contentRoot) {
            return { error: 409, message: 'current rows do not match the anchored contentRoot — re-attest first (submitPassport)' } as const;
        }
        const proof = tree.proofFor(sourceField);
        if (!proof) return { error: 404, message: `field "${sourceField}" is not provable or has no value` } as const;
        return { row, proof, rawValue: values[sourceField] } as const;
    }

    private async onPassportFieldValue(req: any) {
        const { passportId, sourceField } = req.data;
        if (!passportId || !sourceField) return req.error(400, 'passportId and sourceField are required');
        const r: any = await this.fieldProofFor(String(passportId), String(sourceField));
        if (r.error === 404 && /not provable/.test(r.message)) {
            return { value: '', scaledValue: '', found: false, fieldKey: '', contentRoot: '', siblingsJson: '[]', dirsJson: '[]' };
        }
        if (r.error) return req.error(r.error, r.message);
        return {
            value: String(r.rawValue), scaledValue: r.proof.value, found: true,
            fieldKey: r.proof.fieldKey, contentRoot: r.row.contentRoot,
            siblingsJson: JSON.stringify(r.proof.siblings), dirsJson: JSON.stringify(r.proof.dirs)
        };
    }

    private async onDisclosePassportValue(req: any) {
        const { passportId, sourceField } = req.data;
        if (!passportId || !sourceField) return req.error(400, 'passportId and sourceField are required');
        const r: any = await this.fieldProofFor(String(passportId), String(sourceField));
        if (r.error) return req.error(r.error, r.message);
        await INSERT.into(PROOFLOG).entries({
            passport_ID: r.row.ID, sourceField, mode: 'merkle',
            proofJson: JSON.stringify(r.proof), result: true, status: 'offline'
        });
        return {
            passportId: r.row.passportId, sourceField,
            value: String(r.rawValue), scaledValue: r.proof.value,
            fieldKey: r.proof.fieldKey, contentRoot: r.row.contentRoot,
            siblingsJson: JSON.stringify(r.proof.siblings), dirsJson: JSON.stringify(r.proof.dirs),
            anchorTxHash: r.row.lastAnchorTxHash ?? '', unit: r.row.unit ?? ''
        };
    }

    // --- Track B: zero-knowledge predicate ---------------------------------------------

    /**
     * Prove a threshold predicate over ONE provable field WITHOUT disclosing
     * the value: Groth16 proof from the prover sidecar, verified ON-CHAIN by
     * the Julc verifier minting policy (one predicate token per proof). Async
     * like the other pipelines (`mode: 'submitting'`); watch PredicateProofLog.
     */
    private async onProvePassportPredicate(req: any) {
        const { passportId, sourceField } = req.data;
        const predicate = String(req.data.predicate ?? '');
        if (!passportId || !sourceField) return req.error(400, 'passportId and sourceField are required');
        if (!['lessOrEqual', 'greaterOrEqual'].includes(predicate)) {
            return req.error(400, 'predicate must be lessOrEqual or greaterOrEqual');
        }
        const thresholdRaw = req.data.threshold;
        if (thresholdRaw == null || thresholdRaw === '' || Number.isNaN(Number(thresholdRaw))) {
            return req.error(400, 'threshold (raw value, e.g. 4000 for 4000 kg) is required');
        }
        if (!zkProverEnabled()) {
            return req.error(409, 'ZK prover not configured, set DAYPASS_ZK_PROVER_URL and start zk/daypass-prover');
        }
        const creds = this.serverCreds();
        if (!creds) return req.error(400, 'server signing not configured (PRODUCER_PAYMENT_SKEY / PRODUCER_ADDRESS)');

        const loaded = await this.loadPassport(String(passportId));
        if (!loaded) return req.error(404, `passport "${passportId}" not found`);
        const { row, batteries, recycledMaterials } = loaded;
        if (row.status !== 'anchored') return req.error(409, `passport is ${row.status}, predicates need an anchored passport`);
        if (!row.poseidonRoot) {
            return req.error(409, 'passport has no anchored poseidonRoot, re-attest with the ZK prover enabled first (submitPassport)');
        }

        // The proof binds to the ANCHORED root: the current rows must still match it.
        const values = fieldValuesFor({ batteries, recycledMaterials });
        if (values[String(sourceField)] == null) {
            return req.error(404, `field "${sourceField}" is not provable or has no value`);
        }
        let currentRoot: string | null;
        try {
            currentRoot = await fetchPoseidonRoot(values, { required: true });
        } catch (e) {
            if (e instanceof ZkProverUnreachableError) return req.error(503, e.message);
            throw e;
        }
        if (currentRoot !== row.poseidonRoot) {
            return req.error(409, 'current rows do not match the anchored poseidonRoot, re-attest first (submitPassport)');
        }

        const thresholdScaled = String(scaleValue(thresholdRaw));
        const proofLogId = cds.utils.uuid();
        const txRowId = cds.utils.uuid();
        await INSERT.into(PROOFLOG).entries({
            ID: proofLogId, passport_ID: row.ID, sourceField, mode: 'zk',
            predicate, threshold: thresholdScaled, unit: req.data.unit || null, status: 'pending'
        });
        await INSERT.into(TXLOG).entries({ ID: txRowId, passport_ID: row.ID, kind: 'zkProve', status: 'pending' });
        this.startPipeline({
            kind: 'zkProve', txRowId, passportRowId: row.ID, creds,
            passport: {
                passportId: row.passportId, passportIdHash: row.passportIdHash,
                unit: row.unit, point1: this.point1Of(row)
            },
            zk: {
                proofLogId, sourceField: String(sourceField),
                predicate: predicate as 'lessOrEqual' | 'greaterOrEqual',
                thresholdScaled, values
            }
        });
        return {
            passportId: row.passportId, sourceField, predicate,
            thresholdScaled, poseidonRoot: row.poseidonRoot, mode: 'submitting'
        };
    }

    // --- wallet-mode preparation ---------------------------------------------------------

    /** Everything the cockpit needs to run BuildMintTransaction with the wallet
     * as sender/signer. Recomputes the payload from the CURRENT rows (they may
     * have changed since the draft) and persists it, so the anchored hash is
     * always reproducible from DB state; with a configured prover the
     * poseidonRoot is mandatory, like every other anchor path. */
    private async onPrepareWalletMint(req: any) {
        const { passportId, walletAddress } = req.data;
        if (!passportId || !walletAddress) return req.error(400, 'passportId and walletAddress are required');
        const loaded = await this.loadPassport(String(passportId));
        if (!loaded) return req.error(404, `passport "${passportId}" not found`);
        const { row, batteries, recycledMaterials, diligenceDocs } = loaded;
        if (row.status === 'anchored' || row.status === 'revoked') {
            return req.error(409, `passport is already ${row.status}`);
        }

        const { canonicalPayload, payloadHash, contentRoot, fieldValues } =
            this.derivePayload(row, batteries, recycledMaterials, diligenceDocs);
        let poseidonRoot: string | null;
        try {
            poseidonRoot = await fetchPoseidonRoot(fieldValues, { required: true });
        } catch (e) {
            if (e instanceof ZkProverUnreachableError) return req.error(503, e.message);
            throw e;
        }
        // The minting wallet becomes the owner — the cockpit list is scoped by it.
        await UPDATE.entity(PASSPORTS).set({
            payloadCipher: encryptPayload(canonicalPayload, row.passportId),
            payloadHash, contentRoot, poseidonRoot,
            owner: walletAddress
        }).where({ ID: row.ID });

        const txService = await cds.connect.to('CardanoTransactionService');
        const extracted: any = await txService.send('ExtractPaymentKeyHash', { address: walletAddress });
        const pkh = String(extracted.paymentKeyHash);
        const derived: any = await txService.send('DeriveScriptAddress', {
            validatorScript: mintPolicyCompiledCode(),
            scriptParamsJson: mintPolicyParamsJson(pkh)
        });
        const policyId = String(derived.scriptHash);
        const assetNameHex = assetNameHexFor(row.passportId, row.passportIdHash);
        return {
            policyId,
            unit: policyId + assetNameHex,
            assetNameHex,
            lovelaceAmount: MINT_LOVELACE,
            mintActionsJson: JSON.stringify([{ assetUnit: assetNameHex, quantity: '1' }]),
            validityStartMs: String(Date.now() - 300_000),
            mintingPolicyScript: mintPolicyCompiledCode(),
            scriptParamsJson: mintPolicyParamsJson(pkh),
            requiredSignersJson: mintRequiredSignersJson(pkh),
            metadataJson: composeMintMetadataJson({
                policyId, assetNameHex,
                anchor: {
                    op: 'attest', passportId: row.passportId, passportIdHash: row.passportIdHash,
                    payloadHash, contentRoot,
                    poseidonRoot: poseidonRoot ?? undefined,
                    version: 1, point1: this.point1Of(row)
                }
            })
        };
    }

    private async onPrepareWalletAnchor(req: any) {
        const { passportId, op, level } = req.data;
        if (!passportId || !['grant', 'revoke'].includes(String(op))) {
            return req.error(400, 'passportId and op (grant|revoke) are required');
        }
        let grantee: string;
        try {
            grantee = normalizeGrantee(String(req.data.grantee ?? ''));
        } catch (e: any) {
            return req.error(400, e.message);
        }
        const row: any = await SELECT.one.from(PASSPORTS).where({ passportId });
        if (!row) return req.error(404, `passport "${passportId}" not found`);
        return {
            metadataJson: composeAnchorMetadataJson({
                op: op as 'grant' | 'revoke', passportId: row.passportId, passportIdHash: row.passportIdHash,
                unit: row.unit, grantee, level: op === 'grant' ? Number(level) || 0 : 0
            }),
            lovelaceAmount: ANCHOR_LOVELACE,
            grantee
        };
    }

    /** Wallet-mode reattest: recompute the payload from the current rows and
     * return the anchor metadata. Nothing is persisted here — a canceled
     * wallet popup must leave the passport untouched; recordWalletReattest
     * persists after the tx is submitted. */
    private async onPrepareWalletReattest(req: any) {
        const { passportId } = req.data;
        if (!passportId) return req.error(400, 'passportId is required');
        const loaded = await this.loadPassport(String(passportId));
        if (!loaded) return req.error(404, `passport "${passportId}" not found`);
        const { row, batteries, recycledMaterials, diligenceDocs } = loaded;
        if (row.status !== 'anchored') {
            return req.error(409, `passport is ${row.status} — reattest needs an anchored passport`);
        }

        const { payloadHash, contentRoot, fieldValues } =
            this.derivePayload(row, batteries, recycledMaterials, diligenceDocs);
        let poseidonRoot: string | null;
        try {
            poseidonRoot = await fetchPoseidonRoot(fieldValues, { required: true });
        } catch (e) {
            if (e instanceof ZkProverUnreachableError) return req.error(503, e.message);
            throw e;
        }
        if (!anchorOutdated({ payloadHash, rowPayloadHash: row.payloadHash, poseidonRoot, rowPoseidonRoot: row.poseidonRoot })) {
            return { mode: 'unchanged', payloadHash };
        }
        const version = Number(row.anchorVersion ?? 1) + 1;
        return {
            mode: 'reattest', payloadHash, contentRoot,
            poseidonRoot: poseidonRoot ?? null, version,
            lovelaceAmount: ANCHOR_LOVELACE,
            metadataJson: composeAnchorMetadataJson({
                op: 'reattest', passportId: row.passportId, passportIdHash: row.passportIdHash,
                payloadHash, contentRoot, poseidonRoot: poseidonRoot ?? undefined,
                version, unit: row.unit, prev: row.lastAnchorTxHash,
                point1: this.point1Of(row)
            })
        };
    }

    /** Wallet-mode ZK predicate: generate the Groth16 proof in-request and hand
     * the cockpit the verifier policy + redeemer/datum for a wallet-funded mint.
     * The wallet only pays fees/collateral — the policy passes on proof validity,
     * not on a signer. */
    private async onPrepareWalletPredicate(req: any) {
        const { passportId, sourceField } = req.data;
        const predicate = String(req.data.predicate ?? '');
        if (!passportId || !sourceField) return req.error(400, 'passportId and sourceField are required');
        if (!['lessOrEqual', 'greaterOrEqual'].includes(predicate)) {
            return req.error(400, 'predicate must be lessOrEqual or greaterOrEqual');
        }
        const thresholdRaw = req.data.threshold;
        if (thresholdRaw == null || thresholdRaw === '' || Number.isNaN(Number(thresholdRaw))) {
            return req.error(400, 'threshold (raw value, e.g. 4000 for 4000 kg) is required');
        }
        if (!zkProverEnabled()) {
            return req.error(409, 'ZK prover not configured, set DAYPASS_ZK_PROVER_URL and start zk/daypass-prover');
        }
        const loaded = await this.loadPassport(String(passportId));
        if (!loaded) return req.error(404, `passport "${passportId}" not found`);
        const { row, batteries, recycledMaterials } = loaded;
        if (row.status !== 'anchored') return req.error(409, `passport is ${row.status}, predicates need an anchored passport`);
        if (!row.poseidonRoot) {
            return req.error(409, 'passport has no anchored poseidonRoot, re-attest with the ZK prover enabled first');
        }

        // The proof binds to the ANCHORED root: the current rows must still match it.
        const values = fieldValuesFor({ batteries, recycledMaterials });
        if (values[String(sourceField)] == null) {
            return req.error(404, `field "${sourceField}" is not provable or has no value`);
        }
        let currentRoot: string | null;
        try {
            currentRoot = await fetchPoseidonRoot(values, { required: true });
        } catch (e) {
            if (e instanceof ZkProverUnreachableError) return req.error(503, e.message);
            throw e;
        }
        if (currentRoot !== row.poseidonRoot) {
            return req.error(409, 'current rows do not match the anchored poseidonRoot, re-attest first');
        }

        const thresholdScaled = String(scaleValue(thresholdRaw));
        let zkProof: ZkProveResult;
        try {
            zkProof = await provePredicate({
                values, sourceField: String(sourceField),
                thresholdScaled, op: predicate as 'lessOrEqual' | 'greaterOrEqual'
            });
        } catch (e) {
            if (e instanceof ZkProverUnreachableError) return req.error(503, e.message);
            throw e;
        }
        if (!zkProof.isCompliant) {
            return {
                isCompliant: false, thresholdScaled, poseidonRoot: zkProof.poseidonRoot,
                proofJson: JSON.stringify({
                    poseidonRoot: zkProof.poseidonRoot, fieldKey: zkProof.fieldKey,
                    threshold: zkProof.threshold, isCompliant: false
                })
            };
        }
        const zkPolicy = await this.resolveZkPolicy(predicate as 'lessOrEqual' | 'greaterOrEqual', { inRequest: true });
        return {
            isCompliant: true, thresholdScaled, poseidonRoot: zkProof.poseidonRoot,
            policyId: zkPolicy.scriptHash,
            lovelaceAmount: MINT_LOVELACE,
            mintActionsJson: JSON.stringify([{ assetUnit: row.passportIdHash, quantity: '1' }]),
            mintingPolicyScript: zkPolicy.cborHex,
            mintRedeemerJson: JSON.stringify(zkProof.redeemerJson),
            inlineDatumJson: JSON.stringify(zkProof.datumJson),
            validityStartMs: String(Date.now() - 300_000),
            metadataJson: composeAnchorMetadataJson({
                op: 'predicate', passportId: row.passportId, passportIdHash: row.passportIdHash,
                unit: row.unit, fieldKey: blake2b256Hex(String(sourceField)),
                predicate, threshold: Number(thresholdScaled), result: true
            }),
            proofJson: JSON.stringify({
                poseidonRoot: zkProof.poseidonRoot, fieldKey: zkProof.fieldKey,
                threshold: zkProof.threshold, isCompliant: true,
                policyId: zkPolicy.scriptHash, redeemer: zkProof.redeemerJson, datum: zkProof.datumJson
            })
        };
    }

    /** Everything the cockpit needs to burn the passport NFT from the wallet
     * that minted it: wallet-bound policy, NFT-holder UTxO, burn metadata. */
    private async onPrepareWalletBurn(req: any) {
        const { passportId, walletAddress } = req.data;
        if (!passportId || !walletAddress) return req.error(400, 'passportId and walletAddress are required');
        const row: any = await SELECT.one.from(PASSPORTS).where({ passportId });
        if (!row) return req.error(404, `passport "${passportId}" not found`);
        if (!row.unit || row.status === 'draft') return req.error(409, 'passport was never anchored — nothing to burn');
        if (row.status === 'revoked') return req.error(409, 'passport is already revoked');

        const txService = await cds.connect.to('CardanoTransactionService');
        const extracted: any = await txService.send('ExtractPaymentKeyHash', { address: walletAddress });
        const pkh = String(extracted.paymentKeyHash);
        const derived: any = await txService.send('DeriveScriptAddress', {
            validatorScript: mintPolicyCompiledCode(),
            scriptParamsJson: mintPolicyParamsJson(pkh)
        });
        if (String(derived.scriptHash) !== row.policyId) {
            return req.error(409, `the connected wallet did not mint this passport — only the key behind policy ${row.policyId} can burn it`);
        }
        const utxos: any[] = await getCardanoClient().getAddressUtxos(walletAddress);
        const holder = utxos.find((u: any) =>
            (u.amount ?? []).some((a: any) => a.unit === row.unit && BigInt(a.quantity) > 0n));
        if (!holder) return req.error(409, `NFT ${row.unit} not found in the connected wallet — cannot burn`);
        return {
            lovelaceAmount: ANCHOR_LOVELACE,
            mintActionsJson: JSON.stringify([{ assetUnit: row.assetName, quantity: '-1' }]),
            mintingPolicyScript: mintPolicyCompiledCode(),
            scriptParamsJson: mintPolicyParamsJson(pkh),
            requiredSignersJson: mintRequiredSignersJson(pkh),
            forceInputsJson: JSON.stringify([{ txHash: holder.txHash, outputIndex: holder.outputIndex }]),
            validityStartMs: String(Date.now() - 300_000),
            metadataJson: composeAnchorMetadataJson({
                op: 'burn', passportId: row.passportId, passportIdHash: row.passportIdHash,
                unit: row.unit, prev: row.lastAnchorTxHash
            })
        };
    }

    // --- Catena-X exports ----------------------------------------------------------------

    private async onPassportAspectJson(req: any) {
        const { passportId } = req.data;
        if (!passportId) return req.error(400, 'passportId is required');
        const row: any = await SELECT.one.from(PASSPORTS).where({ passportId });
        if (!row) return req.error(404, `passport "${passportId}" not found`);
        const [cells, recycled, diligence] = await Promise.all([
            SELECT.from(BATTERIES)
                .columns('serialNumber', 'cellChemistry', 'capacityKwh', 'carbonFootprintKgCO2',
                    'recycledContentPct', 'cycleLife', 'roundTripEfficiencyPct', 'leadContentPpm', 'supplierName')
                .where({ passport_ID: row.ID }),
            SELECT.from(RECYCLED).columns('material', 'recycledPercentage', 'sourceSupplierName').where({ passport_ID: row.ID }),
            SELECT.from(DILIGENCE).columns('docType', 'storageRef', 'sha256Hex').where({ passport_ID: row.ID })
        ]);
        return buildAspectJson({ passport: row, cells, recycled, diligence });
    }

    private async onPassportCredential(req: any) {
        const { passportId } = req.data;
        if (!passportId) return req.error(400, 'passportId is required');
        const row: any = await SELECT.one.from(PASSPORTS).where({ passportId });
        if (!row) return req.error(404, `passport "${passportId}" not found`);
        const proofs: any[] = await SELECT.from(PROOFLOG)
            .columns('sourceField', 'mode', 'predicate', 'threshold', 'unit', 'proofJson', 'txHash', 'status', 'result')
            .where({ passport_ID: row.ID })
            .orderBy('createdAt asc');
        return buildPacJson({ passport: row, proofs: proofs.filter(isExportableProof) });
    }

    // --- wallet-mode callbacks (cockpit) -------------------------------------------------

    /** Watch a wallet-submitted tx to confirmation (detached, like the pipeline). */
    private trackWalletTx(txRowId: string, txHash: string, onConfirmed?: () => Promise<void>): void {
        setImmediate(async () => {
            try {
                await new Promise((r) => setTimeout(r, 500));
                const onChain: any = await waitForConfirmation(txHash);
                await this.runDetached(async () => {
                    await UPDATE.entity(TXLOG).set({ status: 'confirmed', blockHash: onChain?.blockHash ?? null }).where({ ID: txRowId });
                });
                await onConfirmed?.();
            } catch (e: any) {
                const message = String(e?.message ?? e).slice(0, 1000);
                await this.runDetached(async () => {
                    await UPDATE.entity(TXLOG).set({ status: 'failed', errorMessage: message }).where({ ID: txRowId });
                });
            }
        });
    }

    private async onRecordWalletMint(req: any) {
        const { passportId, txHash, unit, policyId } = req.data;
        if (!passportId || !txHash) return req.error(400, 'passportId and txHash are required');
        const row: any = await SELECT.one.from(PASSPORTS).where({ passportId });
        if (!row) return req.error(404, `passport "${passportId}" not found`);
        const txRowId = cds.utils.uuid();
        await INSERT.into(TXLOG).entries({
            ID: txRowId, passport_ID: row.ID, kind: 'mint', txHash,
            status: 'submitted', explorerUrl: explorerUrl(String(txHash))
        });
        await UPDATE.entity(PASSPORTS).set({
            status: 'anchoring', unit: unit ?? row.unit, policyId: policyId ?? row.policyId,
            assetName: unit && String(unit).length > 56 ? String(unit).slice(56) : row.assetName,
            attestationTxHash: txHash, lastAnchorTxHash: txHash, anchorVersion: 1
        }).where({ ID: row.ID });
        this.trackWalletTx(txRowId, String(txHash), async () => {
            await this.runDetached(async () => {
                await UPDATE.entity(PASSPORTS).set({ status: 'anchored' }).where({ ID: row.ID });
            });
        });
        return { ok: true };
    }

    private async onRecordWalletDisclosure(req: any) {
        const { passportId, level, op, txHash } = req.data;
        if (!passportId || !txHash || !['grant', 'revoke'].includes(String(op))) {
            return req.error(400, 'passportId, txHash and op (grant|revoke) are required');
        }
        let grantee: string;
        try {
            grantee = normalizeGrantee(String(req.data.grantee ?? ''));
        } catch (e: any) {
            return req.error(400, e.message);
        }
        const row: any = await SELECT.one.from(PASSPORTS).where({ passportId });
        if (!row) return req.error(404, `passport "${passportId}" not found`);
        const grantLogId = cds.utils.uuid();
        await INSERT.into(GRANTLOG).entries({
            ID: grantLogId, passport_ID: row.ID, grantee, level: Number(level) || 0,
            op, txHash, status: 'submitted'
        });
        const txRowId = cds.utils.uuid();
        await INSERT.into(TXLOG).entries({
            ID: txRowId, passport_ID: row.ID, kind: String(op), txHash,
            status: 'submitted', explorerUrl: explorerUrl(String(txHash))
        });
        this.trackWalletTx(txRowId, String(txHash), async () => {
            await this.runDetached(async () => {
                await UPDATE.entity(GRANTLOG).set({ status: 'confirmed' }).where({ ID: grantLogId });
            });
        });
        return { ok: true };
    }

    private async onRecordWalletPredicate(req: any) {
        const { passportId, sourceField, mode, predicate, threshold, unit, txHash, result, proofJson } = req.data;
        if (!passportId || !sourceField) return req.error(400, 'passportId and sourceField are required');
        const row: any = await SELECT.one.from(PASSPORTS).where({ passportId });
        if (!row) return req.error(404, `passport "${passportId}" not found`);
        const proofLogId = cds.utils.uuid();
        await INSERT.into(PROOFLOG).entries({
            ID: proofLogId, passport_ID: row.ID, sourceField,
            mode: mode === 'zk' ? 'zk' : 'merkle',
            predicate: predicate || null, threshold: threshold ?? null, unit: unit || null,
            proofJson: proofJson || null,
            txHash: txHash || null, result: result !== false,
            status: txHash ? 'submitted' : 'offline'
        });
        if (txHash) {
            const txRowId = cds.utils.uuid();
            await INSERT.into(TXLOG).entries({
                ID: txRowId, passport_ID: row.ID,
                kind: mode === 'zk' ? 'zkProve' : 'predicateAnchor', txHash,
                status: 'submitted', explorerUrl: explorerUrl(String(txHash))
            });
            this.trackWalletTx(txRowId, String(txHash), async () => {
                await this.runDetached(async () => {
                    await UPDATE.entity(PROOFLOG).set({ status: 'confirmed' }).where({ ID: proofLogId });
                });
            });
        }
        return { ok: true };
    }

    private async onRecordWalletReattest(req: any) {
        const { passportId, txHash, payloadHash, version } = req.data;
        if (!passportId || !txHash || !payloadHash) {
            return req.error(400, 'passportId, txHash and payloadHash are required');
        }
        const loaded = await this.loadPassport(String(passportId));
        if (!loaded) return req.error(404, `passport "${passportId}" not found`);
        const { row, batteries, recycledMaterials, diligenceDocs } = loaded;

        // The rows must still derive the hash that just went on-chain; persist
        // exactly that payload so DB state and anchor stay reproducible.
        const derived = this.derivePayload(row, batteries, recycledMaterials, diligenceDocs);
        if (derived.payloadHash !== String(payloadHash)) {
            return req.error(409, `rows changed while the wallet was signing — anchor tx ${txHash} carries ${payloadHash}, `
                + `current rows derive ${derived.payloadHash}; re-attest again`);
        }
        let poseidonRoot: string | null;
        try {
            poseidonRoot = await fetchPoseidonRoot(derived.fieldValues, { required: true });
        } catch (e) {
            if (e instanceof ZkProverUnreachableError) return req.error(503, e.message);
            throw e;
        }
        const txRowId = cds.utils.uuid();
        await INSERT.into(TXLOG).entries({
            ID: txRowId, passport_ID: row.ID, kind: 'reattest', txHash,
            status: 'submitted', explorerUrl: explorerUrl(String(txHash))
        });
        await UPDATE.entity(PASSPORTS).set({
            payloadCipher: encryptPayload(derived.canonicalPayload, row.passportId),
            payloadHash: derived.payloadHash, contentRoot: derived.contentRoot, poseidonRoot,
            lastAnchorTxHash: txHash,
            anchorVersion: Number(version) || (Number(row.anchorVersion ?? 1) + 1),
            status: 'anchoring'
        }).where({ ID: row.ID });
        this.trackWalletTx(txRowId, String(txHash), async () => {
            await this.runDetached(async () => {
                await UPDATE.entity(PASSPORTS).set({ status: 'anchored' }).where({ ID: row.ID });
            });
        });
        return { ok: true };
    }

    // --- wallet sign-in (proof of key control) --------------------------------------

    private async onWalletLoginChallenge(req: any) {
        const address = String(req.data.address ?? '');
        if (!/^addr(_test)?1[0-9a-z]+$/.test(address)) {
            return req.error(400, 'address must be a bech32 Cardano address');
        }
        return createChallenge(address);
    }

    private async onWalletLogin(req: any) {
        const { nonce, coseSignature, coseKey } = req.data;
        if (!nonce || !coseSignature || !coseKey) {
            return req.error(400, 'nonce, coseSignature and coseKey are required');
        }
        const challenge = consumeChallenge(String(nonce));
        if (!challenge) return req.error(401, 'unknown or expired sign-in challenge — request a new one');

        // Stateless plugin verification: Ed25519 over the COSE Sig_structure AND
        // signer key hash == the address's payment credential.
        const signService = await cds.connect.to('CardanoSignService');
        const verified: any = await signService.send('VerifyDataSignature', {
            address: challenge.address,
            coseSignature: String(coseSignature),
            coseKey: String(coseKey),
            expectedPayload: challenge.message
        });
        if (verified?.valid !== true) {
            return req.error(401, `wallet sign-in rejected: ${verified?.reason ?? 'signature invalid'}`);
        }
        const session = createSession(challenge.address, String(verified.signerVkh ?? ''));
        logger.info(`wallet signed in: ${challenge.address.slice(0, 20)}… (vkh ${String(verified.signerVkh).slice(0, 10)}…)`);
        return { token: session.token, address: challenge.address, expiresAt: session.expiresAt };
    }

    private async onWalletLogout(req: any) {
        dropSession(req.headers?.['x-wallet-session']);
        return { ok: true };
    }

    private async onRecordWalletBurn(req: any) {
        const { passportId, txHash } = req.data;
        if (!passportId || !txHash) return req.error(400, 'passportId and txHash are required');
        const row: any = await SELECT.one.from(PASSPORTS).where({ passportId });
        if (!row) return req.error(404, `passport "${passportId}" not found`);
        const txRowId = cds.utils.uuid();
        await INSERT.into(TXLOG).entries({
            ID: txRowId, passport_ID: row.ID, kind: 'burn', txHash,
            status: 'submitted', explorerUrl: explorerUrl(String(txHash))
        });
        this.trackWalletTx(txRowId, String(txHash), async () => {
            await this.runDetached(async () => {
                await UPDATE.entity(PASSPORTS).set({ status: 'revoked' }).where({ ID: row.ID });
            });
        });
        return { ok: true };
    }

    private async onVerifyPassportOnChain(req: any) {
        const { passportId } = req.data;
        if (!passportId) return req.error(400, 'passportId is required');
        const loaded = await this.loadPassport(String(passportId));
        if (!loaded) return req.error(404, `passport "${passportId}" not found`);
        const { row, batteries, recycledMaterials, diligenceDocs } = loaded;
        const checks: Array<{ check: string; pass: boolean; detail?: string }> = [];
        const add = (check: string, pass: boolean, detail?: string) => checks.push({ check, pass, ...(detail ? { detail } : {}) });

        // 1. Off-chain integrity: encrypted payload decrypts + re-hashes to the stored hash.
        let decryptedHash = '';
        try {
            // CAP returns LargeBinary as a Readable stream on explicit selects.
            const raw: any = row.payloadCipher;
            let blob: Buffer;
            if (raw && typeof raw.pipe === 'function') {
                const chunks: Buffer[] = [];
                for await (const c of raw) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
                blob = Buffer.concat(chunks);
            } else if (typeof raw === 'string') {
                blob = Buffer.from(raw, 'base64');
            } else {
                blob = Buffer.from(raw);
            }
            const cleartext = decryptPayload(blob, row.passportId);
            decryptedHash = hashPayload(JSON.parse(cleartext)).payloadHash;
            add('payloadCipher decrypts and re-hashes to stored payloadHash', decryptedHash === row.payloadHash);
        } catch (e: any) {
            add('payloadCipher decrypts and re-hashes to stored payloadHash', false, String(e?.message ?? e));
        }

        // 2. DB rows re-derive to the stored hash/root (detects drifted child rows).
        const derived = this.derivePayload(row, batteries, recycledMaterials, diligenceDocs);
        add('DB rows re-derive stored payloadHash', derived.payloadHash === row.payloadHash);
        add('DB rows re-derive stored contentRoot', derived.contentRoot === row.contentRoot);

        if (!row.unit || !row.lastAnchorTxHash) {
            add('anchored on-chain', false, 'passport has no anchor tx');
            return { verified: false, checksJson: JSON.stringify(checks) };
        }

        // 3. On-chain: anchor metadata matches, NFT supply reflects status.
        try {
            const odata = await cds.connect.to('CardanoODataService');
            const meta: any = await odata.send('GetMetadataByTxHash', { txHash: row.lastAnchorTxHash });
            const rows: any[] = Array.isArray(meta) ? meta : (meta?.value ?? []);
            const anchorRow = rows.find((r: any) => String(r.label) === String(anchorLabel()));
            const anchor = anchorRow ? JSON.parse(anchorRow.payload) : null;
            add('anchor metadata present on last anchor tx', !!anchor);
            add('on-chain payloadHash matches', !!anchor && String(anchor.payloadHash).toLowerCase() === '0x' + String(row.payloadHash).toLowerCase());
            add('on-chain contentRoot matches', !!anchor && String(anchor.contentRoot).toLowerCase() === '0x' + String(row.contentRoot).toLowerCase());
            if (row.poseidonRoot) {
                add('on-chain poseidonRoot matches', !!anchor && !!anchor.poseidonRoot
                    && BigInt(String(anchor.poseidonRoot)).toString(10) === String(row.poseidonRoot));
            }

            if (row.status === 'revoked') {
                // GetAssetInfo may serve a cached (pre-burn) supply within indexTtlMs;
                // the append-only mint/burn history is the reliable evidence.
                const history: any = await odata.send('GetAssetHistory', { unit: row.unit, limit: 100 });
                const events: any[] = Array.isArray(history) ? history : (history?.value ?? []);
                const netSupply = events.reduce((sum, ev) => {
                    const q = BigInt(String(ev.quantity ?? '0'));
                    return String(ev.action).toLowerCase() === 'burn' ? sum - (q < 0n ? -q : q) : sum + q;
                }, 0n);
                add('NFT burned (mint/burn history nets to 0)', events.length >= 2 && netSupply === 0n, `events=${events.length} net=${netSupply}`);
            } else {
                const asset: any = await odata.send('GetAssetInfo', { unit: row.unit });
                const supply = String(asset?.totalSupply ?? asset?.quantity ?? '');
                add('NFT exists (supply 1)', supply === '1', `supply=${supply}`);
            }
        } catch (e: any) {
            add('on-chain lookups succeeded', false, String(e?.message ?? e).slice(0, 300));
        }

        const verified = checks.every((c) => c.pass);
        return { verified, checksJson: JSON.stringify(checks) };
    }
}



