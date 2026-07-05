package dev.daypass.zk;

import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSConstraintSystem;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupCache;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.daypass.zk.onchain.DaypassPredicatePolicy;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DAYPASS ZK prover sidecar. Stateless HTTP service:
 *
 *   GET  /health            -> { status, circuits, pathBitConvention }
 *   POST /commit            -> { poseidonRoot }            body: { values: {field: scaledInt} }
 *   POST /prove             -> proof + ODATANO-ready redeemer/datum JSON
 *                              body: { values, sourceField, threshold, op }
 *   GET  /validator?op=...  -> { cborHex, scriptHash }     (VK applied)
 *
 * Values are the scaled x1000 integers of DAYPASS's provable fields. The
 * sidecar holds no passport data — DAYPASS sends the values per request.
 * Trusted setup: dev-only single-party (cached in ./data); production needs
 * an MPC ceremony.
 */
public class ProverServer {

    static final ObjectMapper JSON = new ObjectMapper();
    static final Path CACHE = Path.of("./data");
    static final int POT_POWER = 12;

    record Circuit(CircuitBuilder builder, R1CSConstraintSystem r1cs,
                   List<R1CSConstraint> constraints, Groth16SetupBLS381.SetupResult setup,
                   PlutusScript validator) {}

    static Circuit gte;
    static Circuit lte;
    /** true = circuit expects pathBit as "current node is RIGHT child" inverted; set by self-test. */
    static boolean invertPathBits = false;

    public static void main(String[] args) throws Exception {
        Files.createDirectories(CACHE);
        long t0 = System.currentTimeMillis();
        PtauImporterBLS381.SRS[] srs = new PtauImporterBLS381.SRS[1];
        gte = compile("daypass-gte", PredicateCircuit.buildGte(PoseidonTree.DEPTH), srs);
        lte = compile("daypass-lte", PredicateCircuit.buildLte(PoseidonTree.DEPTH), srs);
        System.out.println("circuits ready in " + (System.currentTimeMillis() - t0) + " ms ("
                + gte.r1cs().numConstraints() + " constraints each)");

        selfTest();

        int port = Integer.parseInt(System.getProperty("port",
                System.getenv().getOrDefault("DAYPASS_PROVER_PORT", "8799")));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/health", ex -> respond(ex, 200, JSON.createObjectNode()
                .put("status", "ok").put("constraints", gte.r1cs().numConstraints())
                .put("pathBitConvention", invertPathBits ? "inverted" : "direct")));
        server.createContext("/commit", ex -> handle(ex, ProverServer::commit));
        server.createContext("/prove", ex -> handle(ex, ProverServer::prove));
        server.createContext("/validator", ex -> handle(ex, ProverServer::validator));
        server.start();
        System.out.println("daypass-prover listening on :" + port);
    }

    // ---- endpoints ---------------------------------------------------------------

    static ObjectNode commit(HttpExchange ex, JsonNode body) {
        Map<String, BigInteger> values = readValues(body);
        var tree = PoseidonTree.build(values);
        return JSON.createObjectNode().put("poseidonRoot", tree.root().toString());
    }

    static ObjectNode prove(HttpExchange ex, JsonNode body) {
        Map<String, BigInteger> values = readValues(body);
        String field = body.path("sourceField").asText();
        BigInteger threshold = new BigInteger(body.path("threshold").asText());
        String op = body.path("op").asText("lessOrEqual");
        Circuit circuit = "greaterOrEqual".equals(op) ? gte : lte;

        var tree = PoseidonTree.build(values);
        var proofPath = PoseidonTree.proofFor(tree, values, field);
        if (proofPath == null) throw new IllegalArgumentException("field not provable or absent: " + field);

        BigInteger value = proofPath.leafValue();
        boolean compliant = "greaterOrEqual".equals(op)
                ? value.compareTo(threshold) >= 0
                : value.compareTo(threshold) <= 0;

        Map<String, List<BigInteger>> inputs = new HashMap<>();
        inputs.put("value", List.of(value));
        inputs.put("poseidonRoot", List.of(tree.root()));
        inputs.put("fieldKey", List.of(proofPath.fieldKeyFe()));
        inputs.put("threshold", List.of(threshold));
        inputs.put("isCompliant", List.of(compliant ? BigInteger.ONE : BigInteger.ZERO));
        for (int i = 0; i < PoseidonTree.DEPTH; i++) {
            int bit = invertPathBits ? 1 - proofPath.pathBits()[i] : proofPath.pathBits()[i];
            inputs.put("sibling_" + i, List.of(proofPath.siblings()[i]));
            inputs.put("pathBit_" + i, List.of(BigInteger.valueOf(bit)));
        }

        long t0 = System.currentTimeMillis();
        BigInteger[] witness = circuit.builder().calculateWitness(inputs, CurveId.BLS12_381);
        var proof = Groth16ProverBLS381.prove(circuit.setup().provingKey(), witness,
                circuit.constraints(), circuit.r1cs().numWires());
        long proveMs = System.currentTimeMillis() - t0;

        // Fail fast: never hand out a proof the on-chain verifier would reject.
        boolean valid = Groth16Check.verify(circuit.setup(), proof, List.of(
                tree.root(), proofPath.fieldKeyFe(), threshold,
                compliant ? BigInteger.ONE : BigInteger.ZERO));
        if (!valid) throw new IllegalStateException("generated proof failed the pairing check");

        var compressed = ProofCompressor.compressProof(proof);
        ObjectNode out = JSON.createObjectNode();
        out.put("poseidonRoot", tree.root().toString());
        out.put("fieldKey", proofPath.fieldKeyFe().toString());
        out.put("threshold", threshold.toString());
        out.put("isCompliant", compliant);
        out.put("proofTimeMs", proveMs);

        // ODATANO-ready mintRedeemerJson: constr 0 [piA, piB, piC]
        ObjectNode redeemer = JSON.createObjectNode();
        redeemer.put("constructor", 0);
        ArrayNode fields = redeemer.putArray("fields");
        fields.addObject().put("bytes", HexUtil.encodeHexString(compressed.piA()));
        fields.addObject().put("bytes", HexUtil.encodeHexString(compressed.piB()));
        fields.addObject().put("bytes", HexUtil.encodeHexString(compressed.piC()));
        out.set("redeemerJson", redeemer);

        // ODATANO-ready inlineDatumJson: list of the four public inputs.
        ObjectNode datum = JSON.createObjectNode();
        ArrayNode list = datum.putArray("list");
        list.addObject().put("int", tree.root().toString());
        list.addObject().put("int", proofPath.fieldKeyFe().toString());
        list.addObject().put("int", threshold.toString());
        list.addObject().put("int", compliant ? "1" : "0");
        out.set("datumJson", datum);
        return out;
    }

    static ObjectNode validator(HttpExchange ex, JsonNode ignored) throws Exception {
        String query = ex.getRequestURI().getQuery() == null ? "" : ex.getRequestURI().getQuery();
        Circuit circuit = query.contains("op=greaterOrEqual") ? gte : lte;
        ObjectNode out = JSON.createObjectNode();
        out.put("cborHex", circuit.validator().getCborHex());
        out.put("scriptHash", HexUtil.encodeHexString(circuit.validator().getScriptHash()));
        out.put("op", circuit == gte ? "greaterOrEqual" : "lessOrEqual");
        // Compressed verification key, for external off-chain verifiers.
        var vk = ProofCompressor.compressVk(circuit.setup());
        ObjectNode vkNode = out.putObject("vk");
        vkNode.put("alpha", HexUtil.encodeHexString(vk.alpha()));
        vkNode.put("beta", HexUtil.encodeHexString(vk.beta()));
        vkNode.put("gamma", HexUtil.encodeHexString(vk.gamma()));
        vkNode.put("delta", HexUtil.encodeHexString(vk.delta()));
        ArrayNode icArr = vkNode.putArray("ic");
        for (byte[] p : vk.ic()) icArr.add(HexUtil.encodeHexString(p));
        return out;
    }

    // ---- internals -----------------------------------------------------------------

    static Circuit compile(String name, CircuitBuilder builder, PtauImporterBLS381.SRS[] srs) throws Exception {
        var r1cs = builder.compileR1CS(CurveId.BLS12_381);
        var constraints = r1cs.constraints();
        Path cache = CACHE.resolve("setup-" + name + ".bin");
        Groth16SetupBLS381.SetupResult setup = null;
        if (Files.exists(cache)) {
            try {
                setup = Groth16SetupCache.loadBls12381Setup(cache);
                if (setup.provingKey().numPublic() != r1cs.numPublicInputs()
                        || setup.provingKey().pointsA().length != r1cs.numWires()) setup = null;
            } catch (Exception e) { setup = null; }
        }
        if (setup == null) {
            if (srs[0] == null) srs[0] = PowersOfTauBLS381.generate(POT_POWER);
            setup = Groth16SetupBLS381.setup(constraints, r1cs.numWires(), r1cs.numPublicInputs(), srs[0].tauScalar());
            Groth16SetupCache.saveBls12381Setup(setup, cache);
        }
        var vk = ProofCompressor.compressVk(setup);
        java.util.List<com.bloxbean.cardano.client.plutus.spec.PlutusData> ic = new java.util.ArrayList<>();
        for (byte[] p : vk.ic()) ic.add(new BytesPlutusData(p));
        PlutusScript validator = JulcScriptLoader.load(DaypassPredicatePolicy.class,
                new BytesPlutusData(vk.alpha()), new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()), new BytesPlutusData(vk.delta()),
                com.bloxbean.cardano.client.plutus.spec.ListPlutusData.of(ic.toArray(new com.bloxbean.cardano.client.plutus.spec.PlutusData[0])));
        System.out.println(name + ": " + r1cs.numConstraints() + " constraints, validator "
                + validator.getCborHex().length() / 2 + "B, hash " + HexUtil.encodeHexString(validator.getScriptHash()));
        return new Circuit(builder, r1cs, constraints, setup, validator);
    }

    /**
     * Establish the circuit's Merkle pathBit convention by generating a REAL
     * proof and running the Groth16 pairing check against the public inputs in
     * datum order. Witness calculation alone can succeed on an unsatisfied
     * circuit; only a verifying proof proves the convention is right.
     */
    static void selfTest() {
        Map<String, BigInteger> values = new HashMap<>();
        values.put("carbonFootprintKgCO2", BigInteger.valueOf(3412750));
        values.put("capacityKwh", BigInteger.valueOf(75000));
        BigInteger threshold = BigInteger.valueOf(4000000);
        for (boolean invert : new boolean[]{false, true}) {
            invertPathBits = invert;
            try {
                var tree = PoseidonTree.build(values);
                var path = PoseidonTree.proofFor(tree, values, "carbonFootprintKgCO2");
                Map<String, List<BigInteger>> inputs = new HashMap<>();
                inputs.put("value", List.of(path.leafValue()));
                inputs.put("poseidonRoot", List.of(tree.root()));
                inputs.put("fieldKey", List.of(path.fieldKeyFe()));
                inputs.put("threshold", List.of(threshold));
                inputs.put("isCompliant", List.of(BigInteger.ONE));
                for (int i = 0; i < PoseidonTree.DEPTH; i++) {
                    int bit = invert ? 1 - path.pathBits()[i] : path.pathBits()[i];
                    inputs.put("sibling_" + i, List.of(path.siblings()[i]));
                    inputs.put("pathBit_" + i, List.of(BigInteger.valueOf(bit)));
                }
                BigInteger[] witness = lte.builder().calculateWitness(inputs, CurveId.BLS12_381);
                var proof = Groth16ProverBLS381.prove(lte.setup().provingKey(), witness,
                        lte.constraints(), lte.r1cs().numWires());
                boolean valid = Groth16Check.verify(lte.setup(), proof,
                        List.of(tree.root(), path.fieldKeyFe(), threshold, BigInteger.ONE));
                if (!valid) {
                    System.out.println("pathBit " + (invert ? "inverted" : "direct") + ": proof does NOT verify");
                    continue;
                }
                System.out.println("merkle pathBit convention: " + (invert ? "inverted" : "direct") + " (proof verifies)");
                return;
            } catch (Exception e) {
                System.out.println("pathBit " + (invert ? "inverted" : "direct") + ": " + e.getMessage());
            }
        }
        throw new IllegalStateException("self-test failed: no pathBit convention yields a verifying proof");
    }

    static Map<String, BigInteger> readValues(JsonNode body) {
        Map<String, BigInteger> values = new HashMap<>();
        JsonNode v = body.path("values");
        v.fieldNames().forEachRemaining(name -> values.put(name, new BigInteger(v.get(name).asText())));
        return values;
    }

    // ---- HTTP plumbing ---------------------------------------------------------------

    interface Handler { ObjectNode apply(HttpExchange ex, JsonNode body) throws Exception; }

    static void handle(HttpExchange ex, Handler handler) throws IOException {
        try {
            JsonNode body = JSON.createObjectNode();
            if ("POST".equals(ex.getRequestMethod())) {
                body = JSON.readTree(ex.getRequestBody());
            }
            respond(ex, 200, handler.apply(ex, body));
        } catch (Exception e) {
            respond(ex, 400, JSON.createObjectNode().put("error", String.valueOf(e.getMessage())));
        }
    }

    static void respond(HttpExchange ex, int status, ObjectNode body) throws IOException {
        byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }
}
