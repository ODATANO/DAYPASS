package dev.daypass.zk;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalComparators;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * DAYPASS field-bound predicate circuit.
 *
 * Proves: "the passport whose Poseidon content root is anchored on Cardano
 * carries, at field `fieldKey`, a value that satisfies the threshold" — the
 * value itself stays a private witness.
 *
 * Public inputs (also the on-chain datum, in this order):
 *   poseidonRoot — anchored next to the blake2b contentRoot (anchor v2)
 *   fieldKey     — field-element id of the field (first 31 bytes of blake2b)
 *   threshold    — scaled x1000, like every DAYPASS provable value
 *   isCompliant  — public output, the validator requires 1
 *
 * Private witnesses: value, Merkle siblings + path bits (depth 4).
 *
 * The binding is the point (NIGHTPASS field-bound design): the leaf is
 * recomputed from (fieldKey, value) IN-CIRCUIT and folded to the anchored
 * root, so a proof cannot be replayed for another passport, field or value.
 */
public class PredicateCircuit implements CircuitSpec {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;
    /** Scaled values: cycleLife 4200 x1000 = 4.2M needs > 16 bits; 32 covers all fields. */
    private static final int COMPARE_BITS = 32;

    private final int comparisonMode; // 0 = value >= threshold, 1 = value <= threshold
    private final int depth;

    public PredicateCircuit(int comparisonMode, int depth) {
        this.comparisonMode = comparisonMode;
        this.depth = depth;
    }

    @Override
    public void define(SignalBuilder c) {
        Signal value = c.privateInput("value");
        Signal[] siblings = new Signal[depth];
        Signal[] pathBits = new Signal[depth];
        for (int i = 0; i < depth; i++) {
            siblings[i] = c.privateInput("sibling_" + i);
            pathBits[i] = c.privateInput("pathBit_" + i);
        }

        Signal poseidonRoot = c.publicInput("poseidonRoot");
        Signal fieldKey = c.publicInput("fieldKey");
        Signal threshold = c.publicInput("threshold");
        Signal isCompliant = c.publicOutput("isCompliant");

        // 1. Recompute the leaf from the PUBLIC field key and the SECRET value.
        Signal leaf = SignalPoseidon.hash(c, POSEIDON, c.signal("fieldKey"), value);

        // 2. Fold the inclusion path to the anchored root.
        SignalMerkle.verifyProof(c, leaf, c.signal("poseidonRoot"),
                siblings, pathBits, (sb, a, b) -> SignalPoseidon.hash(sb, POSEIDON, a, b));

        // 3. Threshold predicate on the hidden value.
        Signal passes;
        if (comparisonMode == 0) {
            passes = SignalComparators.greaterOrEqual(c, value, c.signal("threshold"), COMPARE_BITS);
        } else {
            passes = SignalComparators.greaterOrEqual(c, c.signal("threshold"), value, COMPARE_BITS);
        }
        c.assertEqual(isCompliant, passes);
    }

    public static CircuitBuilder build(String name, int comparisonMode, int depth) {
        var builder = CircuitBuilder.create(name)
                .publicVar("poseidonRoot")
                .publicVar("fieldKey")
                .publicVar("threshold")
                .publicVar("isCompliant")
                .secretVar("value");
        for (int i = 0; i < depth; i++) {
            builder = builder.secretVar("sibling_" + i).secretVar("pathBit_" + i);
        }
        return builder.defineSignals(new PredicateCircuit(comparisonMode, depth));
    }

    public static CircuitBuilder buildGte(int depth) { return build("daypass-predicate-gte", 0, depth); }
    public static CircuitBuilder buildLte(int depth) { return build("daypass-predicate-lte", 1, depth); }
}
