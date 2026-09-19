# ULPF — Architecture

**Universal Log Pre-processing Framework** · SIH 2026 · PS 26156 · NTRO
*Submission deliverable: architecture document (2 pages).*
Full detail: [ARCHITECTURE-DETAIL.md](ARCHITECTURE-DETAIL.md).

ULPF is the normalization layer between perimeter-device telemetry and security
analytics. It receives opaque records, **preserves them before interpreting
them**, extracts source-specific fields, emits OCSF 1.9.0, and binds every
normalized event to its original bytes through a verifiable integrity chain. It
is not a SIEM: correlation, alerting and detection consume ULPF output.

## Processing path

```text
receiver ─▶ raw vault ─▶ identify ─▶ decoder chain ─▶ OCSF mapping ─▶ attest ─▶ sinks
              │            │                             │                       │
              │            └─ no pack ─▶ salvage ─▶ dead letter ─▶ cluster ─▶ draft
              └─ O(1) retrieval by locator                                       │
                                                             human approves ─▶ hot reload
```

**The order is a correctness property.** The vault append precedes parsing, and
a block is flushed before any event carrying its locator is emitted. A record
that is unknown, malformed, or that crashes a decoder is still stored,
fingerprinted, chained and emitted as valid OCSF. *"Unparsed" is a routing
decision, never data loss.*

## Components

| Crate | Responsibility |
|---|---|
| `ulpf-core` | Envelope, transport, field map, raw locator, disposition |
| `ulpf-vault` | Append-only zstd archive, O(1) retrieval, crash recovery |
| `ulpf-decode` | Ten decoders (syslog 3164/5424, CEF, LEEF, JSON, XML, CSV, key-value, regex) + salvage |
| `ulpf-pack` | Pack schema, validation, compilation, fixtures, scoring |
| `ulpf-ocsf` | OCSF model, RFC 8785 JCS, hash chain, checkpoints, RFC 6962 Merkle log |
| `ulpf-generator` | Drain clustering, deterministic generator, LLM client, scorer |
| `ulpf-cli` | Ingestion, sinks, verification, proofs, embedded console |

## Raw vault — requirement (a)

Records are length-prefixed, batched into ~1 MiB zstd blocks, rotated into
segments. Each block header carries its own coordinates, lengths and a CRC-32,
and the reader re-validates it before trusting the segment index — so **the
index is an optimisation, never the source of truth**. A segment whose writer
was killed is rebuilt by scanning block headers, so a crash costs the tail
block, not the archive. `RawRef(segment, offset, len)` serialises as
`ulpf:raw:<seg>:<off>:<len>` and travels on every event at
`unmapped.ulpf_raw_locator`.

## Source Packs — requirements (b), (c), (e)

A pack is one YAML file: identity detectors, an ordered decoder chain, OCSF
field mappings, enum translations, provenance, and golden fixtures. Packs
compile once at load; the hot path performs no network or model call per event.
A filesystem watcher recompiles the library on change, so onboarding a device is
dropping in a file — no restart, no rebuild. The watcher coalesces a burst of
events and reloads after 400 ms of quiet, because a file being written emits
several events and the first one reads a half-written pack.

Fixtures run in CI, and `tools/audit_pack_enums.py` checks every `activity_id`
against the vendored schema — a pack can pass its own fixtures and still map a
vendor's verb to the wrong OCSF enum.

## Unknown sources — requirement (i)

Two mechanisms, both deterministic, both working air-gapped.

**Salvage extraction** runs on any record no pack claims, recovering addresses,
ports, MACs, URLs, emails and hostnames into OCSF `observables` — so an
un-onboarded device stays searchable by indicator. It populates *only*
`observables`: it reports that an address is present, never that it is the
source, because a wrong `src_endpoint.ip` is worse than an absent one.

**Assisted onboarding** clusters dead letters with Drain into templates ranked by
volume, then drafts a candidate pack — deterministically, or from a local model
asked only for recognition while Rust assembles the structure. Candidates are
scored against fixtures built from real samples, carry provenance, load below
every reviewed pack, and **activate only on human approval**. Measured: 0% → 100%
coverage over 50,000 records of an unseen device, no hand-written parser.

## Integrity — requirement (d), and the Blockchain theme

Every event carries the OCSF `record_integrity` profile. Its fingerprint covers
the RFC 8785 (JCS) canonical event **including** its predecessor link and
excluding only its own fingerprint, so altering event *N* invalidates every
event after it. Ed25519 checkpoints sign the chain head periodically rather than
per event: OCSF has nowhere to carry per-event signature bytes, and signing each
event would cost more than the entire throughput budget.

Each checkpoint also signs a Merkle head over the fingerprints, built to RFC
6962 with `0x00`/`0x01` domain separation. The chain gives sequential
tamper-evidence at write time; the tree gives selective proof at read time. An
inclusion proof shows one record was logged in `⌈log₂ n⌉` hashes, verifiable by a
party holding no other part of the log — which is what makes an extract from a
sensitive log shareable. Consistency proofs bridge an older tree to the current
signed root and fail if the log was rewritten rather than extended.

## Outputs and deployment — (f), (g), (h), (j), (k)

NDJSON by default; Parquet, a fixed 24-column feature table, OpenSearch Bulk,
Splunk HEC and a UDP forward sink as fan-out. The console and its assets are
compiled into the binary, so there is **no runtime network dependency of any
kind** — proved in CI by running every build and test step `--offline`.
Requirement (k) is a two-stage build onto distroless, read-only root, all
capabilities dropped.

## Measured limits

- **32,414,250 real perimeter records at 99.8967%** coverage; misses enumerated,
  not rounded away.
- **13,290 events/sec** file ingest; **8,000 EPS** lossless over UDP. Billions
  per day is a sharded deployment — chains are per-collector and verify
  independently.
- **Decoders read text.** Binary telemetry (NetFlow/IPFIX, EVTX) needs a second
  decoder contract taking `&[u8]`, not another pack.
- **UDP syslog only.** TCP/TLS (RFC 5425) is future work.
