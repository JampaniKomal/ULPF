# Documentation index

ULPF — Universal Log Pre-processing Framework
SIH 2026 · Problem Statement 26156 · NTRO · Blockchain & Cybersecurity

---

## Start here

| Document | Read it if you want to |
|---|---|
| **[SUBMISSION.md](SUBMISSION.md)** | See the five deliverables against their stated limits, and all eleven requirements with the command that checks each |
| **[EVALUATION-GUIDE.md](EVALUATION-GUIDE.md)** | Assess this submission. Forty minutes, every claim checkable, including six ways to attack it |
| [PROBLEM-STATEMENT.md](PROBLEM-STATEMENT.md) | See how we read PS 26156, clause by clause, and where we resolved its ambiguities |
| [FEATURES.md](FEATURES.md) | See everything the framework does, mapped to requirements (a)–(k) |

## Evidence

| Document | Contents |
|---|---|
| [DATASETS.md](DATASETS.md) | Corpus provenance, measured coverage, and every miss named rather than rounded away |
| [DATASET-INVENTORY.md](DATASET-INVENTORY.md) | Every file, verified record count, origin, and how to check the counts without running ULPF |
| [THROUGHPUT.md](THROUGHPUT.md) | Measured events/sec, the method, and the rates at which it fails |
| [CAPTURING-LOGS.md](CAPTURING-LOGS.md) | How to obtain real logs for a pack that has none, and the four classes of evidence we distinguish |

## Design

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | The 2-page architecture document (submission deliverable) |
| [ARCHITECTURE-DETAIL.md](ARCHITECTURE-DETAIL.md) | Crate boundaries, data flow, and the limits, in full |
| [PROOFS.md](PROOFS.md) | Proving one event was logged without disclosing the rest |
| [PACK_GENERATOR.md](PACK_GENERATOR.md) | Clustering, the two generators, and how candidates are scored |
| [UNKNOWN_LOG_ONBOARDING.md](UNKNOWN_LOG_ONBOARDING.md) | Evidence-based identification workflow for an unseen device |
| [FEATURE_TABLE.md](FEATURE_TABLE.md) | The fixed 24-column contract for analytics and model training |

## Operations

| Document | Contents |
|---|---|
| [SINKS.md](SINKS.md) | Parquet, OpenSearch, Splunk HEC |
| [SCALING.md](SCALING.md) | Sharding past one collector, verifying a multi-chain stream |
| [WAZUH_INTEGRATION.md](WAZUH_INTEGRATION.md) | Routing corpora to a Wazuh manager for the side-by-side demonstration |
| [TESTING.md](TESTING.md) | Test strategy and what each layer catches |
| [SECURITY-EVIDENCE.html](SECURITY-EVIDENCE.html) | The security case as a standalone page: six measured properties, each with the command that produced it |

## Demonstration

| Document | Contents |
|---|---|
| [DEMO.md](DEMO.md) | The single-laptop demonstration, start to finish |

---

## The claim, in one table

Every figure below is produced by the command beside it. Nothing in this
project reports a number that one of these does not print.

| Claim | Command |
|---|---|
| 35 packs, 78/78 fixtures, 100% field accuracy | `ulpf test --packs packs` |
| 401 tests pass | `cargo test --workspace --release --locked` |
| 0 enum problems across 35 packs | `python tools/audit_pack_enums.py` |
| 32,414,250 real records at 99.8967% | `python tools/measure_coverage.py --set perimeter` |
| Tamper detection | `ulpf verify` on an altered stream |
| Single-record proof | `ulpf prove` then `ulpf verify-proof` |
| 0% → 100% onboarding, no parser written | `ulpf profile` → `ulpf draft` → approve → `ulpf run` |
| Air-gapped build | `cargo build --release --locked --offline` |

**No coverage or throughput figure anywhere in this project is measured on
synthesised data.** The ten synthetic devices exist only so the onboarding path
can be demonstrated on a source ULPF has genuinely never seen, and four
independent guards keep them out of every published number — see
[DATASET-INVENTORY.md](DATASET-INVENTORY.md#synthetic-data--excluded-by-construction).
