Findings
[P1] Predicate-Token ist nicht hart an Datum/Output gebunden
Die Policy prüft “genau ein Token unter dieser Policy geminted” via Pair(_, 1), liest aber die Public Inputs nur aus dem ersten Output-Datum. Sie erzwingt nicht, dass genau dieses gemintete Token im ersten Output liegt oder dass AssetName/Token an [poseidonRoot, fieldKey, threshold, isCompliant] gebunden ist. Wenn das Token selbst als portable Attestation gelten soll, ist das semantisch zu locker. Siehe [predicate.ak (line 32)](C:/Users/max/ODATANO/DAYZERO/contracts/daypass-predicate-policy/lib/daypass/predicate.ak:32) und [predicate.ak (line 38)](C:/Users/max/ODATANO/DAYZERO/contracts/daypass-predicate-policy/lib/daypass/predicate.ak:38).

[P1] Sidecar ist als Produktionsservice zu weich abgesichert
readJson puffert Request-Bodies unbegrenzt, der Server bindet per server.listen(port) standardmäßig auf alle Interfaces, und ohne DAYZERO_DAYPASS_PROVING_KEYS fällt /prove auf den deterministischen Dev-Prover zurück. Für einen internen lokalen Bridge-Prozess okay, für Deployment ein DoS-/Footgun-Risiko. Siehe [sidecar.ts (line 114)](C:/Users/max/ODATANO/DAYZERO/src/daypass/sidecar.ts:114), [sidecar.ts (line 154)](C:/Users/max/ODATANO/DAYZERO/src/daypass/sidecar.ts:154), [predicate.ts (line 260)](C:/Users/max/ODATANO/DAYZERO/src/daypass/predicate.ts:260).

[P2] CRS-Cache ignoriert das Artefakt-Verzeichnis
CRS_SOURCES ist nur nach Operator keyed. Wenn ein Prozess erst lessOrEqual aus Verzeichnis A lädt und später explizit Verzeichnis B übergibt, wird trotzdem A wiederverwendet. Das ist gefährlich bei Trust-Root-Rotation, Tests mit mehreren Artefaktsets oder Long-running Services. Siehe [predicate.ts (line 189)](C:/Users/max/ODATANO/DAYZERO/src/daypass/predicate.ts:189) und [predicate.ts (line 203)](C:/Users/max/ODATANO/DAYZERO/src/daypass/predicate.ts:203).

[P2] Registry-Hash wird zur Laufzeit nicht validiert
Der CI-Job prüft blake2b-224(0x03 || cborHex) == scriptHash, aber daypassValidatorRegistryFromJson selbst normalisiert nur Hex/VK/Form. Eine externe oder falsch gesetzte Registry-Datei kann zur Laufzeit inkonsistente cborHex/scriptHash-Paare ausliefern. Siehe [validator-artifact.ts (line 76)](C:/Users/max/ODATANO/DAYZERO/src/daypass/validator-artifact.ts:76).

[P3] Packaging/Doku passen nicht ganz zusammen
npm pack --dry-run enthält keine artifacts/, obwohl README und Layout stark mit artifacts/* als Trust-Roots arbeiten. Das kann Absicht sein, sollte aber explizit erklärt werden: npm-Paket liefert Code/Contracts, nicht die aktiven CRS/Registry-Artefakte. Siehe [package.json (line 18)](C:/Users/max/ODATANO/DAYZERO/package.json:18) und [README.md (line 59)](C:/Users/max/ODATANO/DAYZERO/README.md:59).

[P3] Doku groth16-dev-prover.md ist stale
Sie sagt noch, Produktions-Proving-Key-Format, FFT und optimierter MSM fehlen, obwohl CRS/FFT/MSM inzwischen implementiert sind. Siehe [groth16-dev-prover.md (line 62)](C:/Users/max/ODATANO/DAYZERO/docs/groth16-dev-prover.md:62).

1. On-Chain-Bindung härten
Der wichtigste Fix: Das gemintete Predicate-Token sollte eindeutig an die Public Inputs gebunden sein.
Vorschlag:
AssetName deterministisch aus dem Datum ableiten, z. B. zk1 || blake2b_224(serializedPublicInputs).
Die Policy prüft dann:genau dieses Asset wird unter policy_id mit Menge 1 gemintet,
dieses Asset liegt im Output mit dem Inline-Datum,
das Inline-Datum ist exakt [poseidonRoot, fieldKey, threshold, isCompliant],
isCompliant == 1,
Groth16 verifiziert gegen genau diese Public Inputs.

Das würde [predicate.ak (line 32)](C:/Users/max/ODATANO/DAYZERO/contracts/daypass-predicate-policy/lib/daypass/predicate.ak:32) deutlich stärker machen. Wichtig: Das ändert PolicyIds, also vor Production sauber versionieren.
2. Sidecar produktionssicher machen
Ich würde den Dev-Prover niemals stillschweigend als Fallback erlauben.
Konkrete Änderungen:
Default bind nur auf 127.0.0.1, extern nur mit DAYPASS_PROVER_HOST=0.0.0.0.
In NODE_ENV=production ohne DAYZERO_DAYPASS_PROVING_KEYS hart fehlschlagen.
Dev-Prover nur mit explizitem DAYZERO_ALLOW_DEV_PROVER=1.
Request-Body-Limit in [sidecar.ts (line 114)](C:/Users/max/ODATANO/DAYZERO/src/daypass/sidecar.ts:114), z. B. 64 KB oder 256 KB.
Content-Type: application/json erzwingen.
Proof-Concurrency begrenzen, z. B. Queue mit max. 1-2 parallelen Proofs.
Optional: Bearer Token oder HMAC, falls der Sidecar jemals nicht nur lokal läuft.
3. CRS/Registry-Konsistenz prüfen
Aktuell können Proving-Key und Validator-Registry theoretisch auseinanderlaufen. Ich würde beim Start validieren:
Für jeden Operator: CRS-VK == Registry-VK.
Registry-scriptHash == blake2b_224(0x03 || cborHex).
/health sollte setupHash, registryHash, mode: crs/dev und Operator-Status anzeigen.
Außerdem den Cache in [predicate.ts (line 189)](C:/Users/max/ODATANO/DAYZERO/src/daypass/predicate.ts:189) nicht nur nach op, sondern nach resolvedArtifactPath + op keyen. Sonst kann ein Prozess alte Trust-Roots behalten.
4. Runtime-Registry validieren
Die CI-Prüfung ist gut, aber ich würde sie in die Library ziehen. daypassValidatorRegistryFromJson sollte inkonsistente Registry-Dateien direkt ablehnen.
Also in [validator-artifact.ts (line 76)](C:/Users/max/ODATANO/DAYZERO/src/daypass/validator-artifact.ts:76):
cborHex parsen,
Script-Hash berechnen,
mit scriptHash vergleichen,
bei Mismatch throw.
5. Packaging entscheiden
Momentan sagt README “artifacts sind Trust-Roots”, aber npm pack liefert sie nicht aus. Ich würde bewusst eine von zwei Linien wählen:
Besser für Sicherheit: npm bleibt code-only; CRS/Registry kommen als GitHub Release Assets mit Checksums.
Besser für DX: artifacts/ in package.json.files aufnehmen, aber sehr klar als Preview/demo oder konkreter Trust-Root markieren.
Dieses “halb drin, halb draußen” würde ich vermeiden.
6. Docs aktualisieren
[groth16-dev-prover.md (line 62)](C:/Users/max/ODATANO/DAYZERO/docs/groth16-dev-prover.md:62) ist veraltet. Ich würde splitten in:
groth16-dev-prover.md: nur Dev-Prover.
groth16-crs-prover.md: aktueller CRS/FFT/MSM-Pfad.
production-readiness.md: MPC, audit, artifact pinning, sidecar config.
7. Tests ergänzen
Ich würde gezielt diese Tests hinzufügen:
Aiken: Token nicht im ersten Output => reject.
Aiken: falscher AssetName trotz gültigem Proof => reject.
Aiken: Datum/Token-Hash mismatch => reject.
Node: Registry mit falschem scriptHash rejected.
Node: CRS-VK und Registry-VK mismatch rejected.
Node: anderer CRS-Ordner lädt wirklich anderes Setup.
Sidecar: zu großer Body => 413.
Sidecar: Production ohne CRS => fail.