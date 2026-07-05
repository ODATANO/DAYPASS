package dev.daypass.zk;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

/**
 * Off-chain Poseidon Merkle tree over the DAYPASS provable fields — the
 * field-native twin of DAYPASS's blake2b contentRoot (same registry, same
 * order, same x1000 scaling; see srv/lib/passport-anchor.ts). Depth 4,
 * 16 leaves, leaf_i = Poseidon(fieldKeyFe_i, scaledValue_i), empty leaf =
 * Poseidon(0, 0), node = Poseidon(left, right).
 *
 * fieldKeyFe = the first 31 bytes of blake2b-256(fieldName) as an unsigned
 * integer deterministic and cheap to recompute anywhere.
 */
public final class PoseidonTree {

    public static final String[] PROVABLE_FIELDS = {
            "carbonFootprintKgCO2", "capacityKwh", "recycledContentPct",
            "cycleLife", "roundTripEfficiencyPct", "leadContentPpm",
            "recycledCoPct", "recycledLiPct", "recycledNiPct"
    };
    public static final int DEPTH = 4;
    private static final int LEAVES = 1 << DEPTH;
    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    public record FieldProof(BigInteger leafValue, BigInteger fieldKeyFe,
                             BigInteger[] siblings, int[] pathBits) {}

    public record Tree(BigInteger root, BigInteger[][] levels) {}

    private PoseidonTree() {}

    public static BigInteger poseidon(BigInteger a, BigInteger b) {
        return PoseidonHash.hash(POSEIDON, a, b);
    }

    public static BigInteger fieldKeyFe(String fieldName) {
        byte[] hash = Blake2bUtil.blake2bHash256(fieldName.getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, Arrays.copyOfRange(hash, 0, 31));
    }

    public static int fieldIndex(String fieldName) {
        for (int i = 0; i < PROVABLE_FIELDS.length; i++) {
            if (PROVABLE_FIELDS[i].equals(fieldName)) return i;
        }
        return -1;
    }

    /** Build the full tree from a field -> scaled-value map (missing = empty leaf). */
    public static Tree build(Map<String, BigInteger> values) {
        BigInteger emptyLeaf = poseidon(BigInteger.ZERO, BigInteger.ZERO);
        BigInteger[][] levels = new BigInteger[DEPTH + 1][];
        levels[0] = new BigInteger[LEAVES];
        for (int i = 0; i < LEAVES; i++) {
            if (i < PROVABLE_FIELDS.length && values.containsKey(PROVABLE_FIELDS[i])) {
                levels[0][i] = poseidon(fieldKeyFe(PROVABLE_FIELDS[i]), values.get(PROVABLE_FIELDS[i]));
            } else {
                levels[0][i] = emptyLeaf;
            }
        }
        for (int d = 0; d < DEPTH; d++) {
            levels[d + 1] = new BigInteger[levels[d].length / 2];
            for (int i = 0; i < levels[d + 1].length; i++) {
                levels[d + 1][i] = poseidon(levels[d][2 * i], levels[d][2 * i + 1]);
            }
        }
        return new Tree(levels[DEPTH][0], levels);
    }

    /**
     * Inclusion proof for a field. pathBit convention: bit = position of the
     * CURRENT node at that depth (0 = left, 1 = right) — the circuit's Merkle
     * fold selects the hash order from it (self-tested at server start).
     */
    public static FieldProof proofFor(Tree tree, Map<String, BigInteger> values, String fieldName) {
        int idx = fieldIndex(fieldName);
        if (idx < 0 || !values.containsKey(fieldName)) return null;
        BigInteger[] siblings = new BigInteger[DEPTH];
        int[] pathBits = new int[DEPTH];
        int node = idx;
        for (int d = 0; d < DEPTH; d++) {
            int bit = node & 1;
            pathBits[d] = bit;
            siblings[d] = tree.levels()[d][bit == 0 ? node + 1 : node - 1];
            node = node / 2;
        }
        return new FieldProof(values.get(fieldName), fieldKeyFe(fieldName), siblings, pathBits);
    }
}
