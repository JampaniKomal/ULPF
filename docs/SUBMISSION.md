# Submission deliverables — PS 26156

Smart India Hackathon 2026 · National Technical Research Organisation
Theme: Blockchain & Cybersecurity · Category: Software
Idea submission deadline: **30 September 2026**

This page maps each required deliverable to where it lives, and records the
stated limit against what we are submitting.

---

## The five deliverables

| # | Required | Limit | Where it is | Status |
|---|---|---|---|---|
| 1 | Source Code Link | — | <https://github.com/D3v4nshPat3l/ULPF> | ✅ |
| 2 | Readme with Setup Instructions | — | [../README.md](../README.md) § Setup | ✅ |
| 3 | Architecture Document | **Max 2 pages** | [ARCHITECTURE.md](ARCHITECTURE.md) — 935 words | ✅ |
| 4 | Demo Video | **Max 2 minutes** | Recorded separately | ✅ |
| 5 | Technical Presentation | **Max 5 slides** | Prepared separately | ✅ |

The architecture document is deliberately held to two pages. The full version,
with crate boundaries and the complete list of limits, is
[ARCHITECTURE-DETAIL.md](ARCHITECTURE-DETAIL.md) — supporting material, not the
deliverable.

---

## The eleven expected solutions

Each row states how an evaluator can check the claim themselves. The commands
are collected in [EVALUATION-GUIDE.md](EVALUATION-GUIDE.md); the full feature
detail is in [FEATURES.md](FEATURES.md).

| # | Requirement | Status | How to check it |
|---|---|---|---|
| a | Preserve complete raw event data without information loss | **Done** | `ulpf raw <locator>` returns the exact original bytes for any event, including one no pack claimed. SHA-256 of the returned bytes equals the hash recorded at ingest. Vault is append-only zstd, CRC-verified, written *before* parsing |
| b | Extract and parse source-specific attributes | **Done** | `ulpf decoders` lists the ten; each pack composes them into a chain. `ulpf test --packs packs` scores field-level accuracy: **78/78 fixtures, 100.0%** |
| c | Normalize fields into a common event taxonomy | **Done** | OCSF 1.9.0, schema vendored unmodified at `schema/ocsf`. `tools/audit_pack_enums.py` checks every `activity_id` against it: **0 problems across 35 packs** |
| d | Maintain traceability between normalized and original events | **Done** | `unmapped.ulpf_raw_locator` + `raw_data_hash` + per-event fingerprint + `prev_event`. `ulpf prove` emits an RFC 6962 inclusion proof; `ulpf verify-proof` checks it holding no other part of the log |
| e | Plug-and-play onboarding of new log sources | **Done** | Copy a YAML file into `packs/` while `serve` is running; `/readyz` reports the new count within a second. No restart, no rebuild |
| f | Unified visibility across enterprise environments | **Done** | Embedded console: live table naming which pack claimed each record, source breakdown, Live Map, cluster browser, event inspector, integrity view |
| g | Efficient SIEM and Data Lake integration | **Done** | NDJSON default; `--parquet`, `--features`, `--opensearch`, `--splunk-hec`, `--forward-udp` |
| h | AI/ML-ready security and operational analytics | **Done** | `--features` writes a Hive-partitioned Parquet table with a fixed 24-column contract, version-stamped in the footer. Readable by pyarrow, DuckDB, Spark |
| i | Reduced parser development effort | **Done** | `ulpf profile` then `ulpf draft` on an unseen device: **0% → 100% over 50,000 records**, no hand-written parser, no model required |
| j | Deployable in an air-gapped network — **shall** | **Done** | No runtime network dependency on any path; console assets compiled into the binary. CI runs every build and test step `--offline`, which fails outright if Cargo would reach the network |
| k | Packaged in a container — *may* | **Done** | Two-stage build onto distroless, read-only rootfs, all capabilities dropped. `deploy/demo-compose.yaml` brings ULPF and a SIEM up in one command |

---

## Current Scope, and how the evidence maps onto it

> Build a framework that converts any **perimeter network device**-generated
> log or event — regardless of source, format, vendor, or technology — into a
> standardized, lossless, analytics-ready representation for next-generation
> SIEM and cybersecurity platforms.

Our reading, argued at length in [PROBLEM-STATEMENT.md](PROBLEM-STATEMENT.md):
the *architecture* must be general enough for anything, which is what
"universal" and "extensible" mean; the *demonstration* is scoped to perimeter
network devices.

**The headline figure is the perimeter set and nothing else:**

| | |
|---|---:|
| Real perimeter records measured | **32,414,250** |
| Normalized to OCSF | **32,380,764** |
| Coverage | **99.8967%** |
| Corpora | 13, all public capture data |
| Synthetic records included | **0** |

Reproduce with `python tools/measure_coverage.py`. Full provenance and
per-file verified counts: [DATASET-INVENTORY.md](DATASET-INVENTORY.md).

Of the 35 Source Packs, nineteen are perimeter, edge or network devices; five
are host, auth or mail sources immediately behind the perimeter; eleven are
outside it entirely and are **not** counted toward the figure above.

---

## What we are not claiming

An evaluator will find these anyway, so we state them.

- **1 billion events/day is arithmetic, not a sustained run.** File ingest
  measures 13,290 events/sec over 8,130,590 real records; 13,290 × 86,400 is
  1.148 billion. We have not run for a day and do not claim to have.
- **Over UDP the lossless ceiling is 8,000 EPS**, below the 11,574 that target
  needs. That path is bounded by the socket, not the pipeline, and
  [THROUGHPUT.md](THROUGHPUT.md) publishes the losses at every rate including
  the ones where it fails.
- **Coverage is 99.8967%, not 100%.** 33,486 records of 32,414,250 are
  unparsed — enumerated by source in [EVALUATION-GUIDE.md](EVALUATION-GUIDE.md),
  and every one of them is still vaulted, fingerprinted, chained and emitted as
  valid OCSF.
- **Three of the 35 packs have no real-corpus evidence** — generic CEF, pfSense
  and Check Point's CEF variant pass fixtures written from vendor
  documentation. Treat them as unproven.
- **Binary telemetry is not supported.** NetFlow/IPFIX and Windows EVTX need a
  decoder contract taking `&[u8]`, not another pack.
- **TCP/TLS syslog (RFC 5425) is future work.**

---

## Reproducing every figure

```bash
cargo build --release --locked          # ~3 min
cargo test --workspace --release --locked   # 405 tests
./target/release/ulpf test --packs packs    # 35 packs, 78/78 fixtures
python tools/audit_pack_enums.py            # 0 problems
python tools/fetch_datasets.py              # 5.6 GB
python tools/measure_coverage.py            # ~40 min -> the table above
```

Nothing in this submission reports a number that one of these commands does not
print. If a figure in any document does not match what the command produces on
your machine, the document is wrong.
