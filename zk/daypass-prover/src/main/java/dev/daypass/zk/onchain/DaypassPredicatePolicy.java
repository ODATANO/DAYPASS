package dev.daypass.zk.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.ledger.ScriptInfo;
import com.bloxbean.cardano.julc.ledger.TxInfo;
import com.bloxbean.cardano.julc.ledger.TxOut;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.MintingValidator;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.lib.OutputLib;
import com.bloxbean.cardano.julc.stdlib.lib.ValuesLib;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * DAYPASS predicate-attestation minting policy: full on-chain Groth16
 * BLS12-381 verification (Plutus V3 builtins).
 *
 * The tx mints exactly one predicate token; the first output's inline datum
 * carries the public inputs [poseidonRoot, fieldKey, threshold, isCompliant];
 * the redeemer carries the compressed proof. The policy passes only when the
 * proof verifies against the datum AND isCompliant == 1. The successful mint
 * tx IS the predicate attestation — bound to a specific passport (the
 * anchored poseidonRoot) and field, with the value hidden.
 *
 * Parameterized with the verification key only, so the policyId identifies
 * the exact circuit + trusted setup a token attests against.
 */
@MintingValidator
public class DaypassPredicatePolicy {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(Groth16Proof proof, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();

        // Exactly 1 token minted under this policy.
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policyBytes = PlutusData.cast(mintInfo.policyId(), byte[].class);
        BigInteger mintCount = ValuesLib.countTokensWithQty(txInfo.mint(), policyBytes, BigInteger.ONE);
        boolean exactlyOne = mintCount.compareTo(BigInteger.ONE) == 0;

        // Public inputs from the first output's inline datum:
        // [poseidonRoot, fieldKey, threshold, isCompliant]
        TxOut firstOutput = txInfo.outputs().get(0);
        PlutusData datumData = OutputLib.getInlineDatum(firstOutput);
        PlutusData inputs = Builtins.unListData(datumData);
        PlutusData r1 = Builtins.tailList(inputs);
        PlutusData r2 = Builtins.tailList(r1);
        PlutusData r3 = Builtins.tailList(r2);
        BigInteger isCompliantPub = Builtins.asInteger(Builtins.headList(r3));
        boolean isCompliant = isCompliantPub.compareTo(BigInteger.ONE) == 0;

        boolean proofValid = Groth16BLS12381Lib.verify(datumData, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return exactlyOne && isCompliant && proofValid;
    }
}
