package dev.daypass.zk;

import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import supranational.blst.P1;
import supranational.blst.P1_Affine;
import supranational.blst.P2_Affine;
import supranational.blst.PT;
import supranational.blst.Scalar;

import java.math.BigInteger;
import java.util.List;

/**
 * Off-chain Groth16 verification via the standard pairing equation
 *   e(A, B) == e(alpha, beta) * e(L, gamma) * e(C, delta)
 * with L = IC0 + sum(pub_i * IC_{i+1}).
 *
 * Used by the boot self-test so an unsatisfied circuit (e.g. a wrong Merkle
 * path-bit convention) is caught at startup instead of failing opaquely in
 * on-chain script evaluation.
 */
public final class Groth16Check {

    private Groth16Check() {}

    public static boolean verify(Groth16SetupBLS381.SetupResult setup,
                                 Groth16ProofBLS381 proof,
                                 List<BigInteger> publicInputs) {
        var vk = ProofCompressor.compressVk(setup);
        var pr = ProofCompressor.compressProof(proof);
        List<byte[]> ic = vk.ic();
        if (publicInputs.size() != ic.size() - 1) {
            throw new IllegalArgumentException("public input count " + publicInputs.size()
                    + " does not match IC size " + ic.size());
        }

        // L = IC0 + sum(pub_i * IC_{i+1})
        P1 acc = new P1_Affine(ic.get(0)).to_jacobian();
        for (int i = 0; i < publicInputs.size(); i++) {
            byte[] scalar = to32BytesBE(publicInputs.get(i));
            P1 term = new P1_Affine(ic.get(i + 1)).to_jacobian().mult(new Scalar().from_bendian(scalar));
            acc = acc.add(term);
        }
        P1_Affine l = acc.to_affine();

        PT lhs = new PT(new P1_Affine(pr.piA()), new P2_Affine(pr.piB()));
        PT rhs = new PT(new P1_Affine(vk.alpha()), new P2_Affine(vk.beta()))
                .mul(new PT(l, new P2_Affine(vk.gamma())))
                .mul(new PT(new P1_Affine(pr.piC()), new P2_Affine(vk.delta())));
        return PT.finalverify(lhs, rhs);
    }

    private static byte[] to32BytesBE(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int src = Math.max(0, raw.length - 32);
        int len = Math.min(raw.length, 32);
        System.arraycopy(raw, src, out, 32 - len, len);
        return out;
    }
}
