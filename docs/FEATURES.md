# Feature catalogue

Everything ULPF does, what it is for, and — for each — the command that shows
it working. Organised by the eleven requirements of PS 26156, then by the
capabilities that do not map onto a single requirement.

Modal verbs in the statement are not decorative: (j) says the solution **shall**
be deployable air-gapped, so it is mandatory; (k) says it **may** be
containerised, so it is a differentiator rather than a baseline.

---

## (a) Preserve complete raw event data without information loss

**The words matter.** Not "keep a copy" — *complete*, and *without information
loss*. A parser that stores the fields it understood and discards the rest has
already failed this, even if it never drops a whole record.

### The vault comes first

Raw bytes are written to an append-only, zstd-block-compressed store **before**
parsing is attempted. The ordering is a correctness property, not an
implementation detail: a block is flushed before any event carrying its locator
is emitted, so a locator can never point at bytes that were not durably
written.

A record that is unknown, malformed, or that crashes a decoder is still stored,
fingerprinted, chained and emitted as valid OCSF.

### On-disk format

```
┌──────────────────────────────────────────────────────────┐
│ SEGMENT HEADER    magic "ULPFVLT1" · version · flags     │
├──────────────────────────────────────────────────────────┤
│ BLOCK 0   magic · uncompressed_start · uncompressed_len  │
│           compressed_len · crc32(uncompressed) · payload │
├──────────────────────────────────────────────────────────┤
│ BLOCK 1 …                                                │
├──────────────────────────────────────────────────────────┤
│ INDEX     n × (start, len, file_offset, compressed_len)  │
├──────────────────────────────────────────────────────────┤
│ FOOTER    index_offset · block_count · magic "ULPFIDX1"  │
└──────────────────────────────────────────────────────────┘
```

Every block carries its own coordinates and a CRC-32. **The index is an
optimisation, never the source of truth** — the reader re-validates a block
header before trusting the index, so a corrupt index cannot return wrong bytes,
and a segment whose writer was killed mid-write is recovered by scanning
forward. A crash costs the tail block, not the archive.

The CRC is deliberately redundant with zstd's own frame checking: zstd detects
corruption of its frames, the CRC covers the framing *around* it — a truncated
write leaving a structurally valid but short frame, or bit rot in the header
fields themselves.

### Retrieval is O(1), not a search

`RawRef(segment, offset, len)` serialises as
`ulpf:raw:<seg>:<off>:<len>` and travels on every event at
`unmapped.ulpf_raw_locator`. Retrieval is one seek, one block decompress, one
slice.

```bash
ulpf raw --vault data/vault ulpf:raw:0000000000000000:000000000000458a:0000003a
```

Fixed-width hex keeps locators lexicographically sortable in the same order as
the bytes they point at, which makes range scans cheap.

### Encryption at rest — optional

`--encrypt-vault` encrypts every block payload with ChaCha20-Poly1305 keyed by
an Argon2id-derived passphrase (`ULPF_VAULT_PASSPHRASE`), with a per-directory
salt file. **A segment records its own encryption state in a header flag**, so
a reader never depends on external configuration to know how to interpret it,
and a vault that had encryption enabled partway through its life reads
correctly across both kinds of segment.

Off by default, because forcing a passphrase breaks an unattended start — CI,
the compose files, a scripted demo — that has nowhere to type one.

**Check it:** [EVALUATION-GUIDE.md § Attack 1](EVALUATION-GUIDE.md#attack-1--is-an-unparsed-record-really-preserved-or-just-counted)

---

## (b) Extract and parse source-specific attributes

### Ten decoders, composed into chains

`syslog` · `syslog_rfc3164` · `syslog_rfc5424` · `keyvalue` · `csv` · `cef` ·
`leef` · `json` · `xml` · `regex`

```bash
ulpf decoders
```

The decoder count stays small because perimeter devices do not each invent a
format — they wrap one of about six bodies in one of about two envelopes. A
Source Pack names the chain (`syslog` then `keyvalue` for FortiGate, `syslog`
then `csv` for PAN-OS) rather than shipping a bespoke parser per vendor.

Every decoder is deliberately tolerant. Real devices truncate lines, omit
hostnames, emit unpaired quotes and pad absent fields with `-`. A decoder that
rejects those loses the event; one that extracts what it can keeps the pipeline
lossless.

### Field-level accuracy, not just "it produced output"

```bash
ulpf test --packs packs
# 35 packs · 78/78 fixtures passed · 100.0% field accuracy
```

Each pack carries embedded fixtures — real log lines with the exact OCSF
attributes they must produce. A pack that cannot parse its own fixtures never
reaches the loaded list.

---

## (c) Normalize fields into a common event taxonomy

### OCSF 1.9.0, vendored

The schema is an unmodified upstream snapshot at `schema/ocsf`, so the mapping
target is auditable and pinned. "Common event taxonomy" implies an existing,
documented vocabulary rather than one invented for a submission — a bespoke
schema satisfies the letter and fails the intent, because the point is that a
SIEM already understands it.

### The audit fixtures cannot perform

```bash
python tools/audit_pack_enums.py
# 0 problem(s) found across 35 packs
```

A pack can pass its own fixtures completely and still map a vendor's verb onto
the wrong OCSF enum — the fixture only proves a value survived to a path, not
that the path means what the author thought. This audits every `activity_id`
against the vendored schema.

### 35 Source Packs

Firewall and VPN (Check Point ×2, Cisco ASA, FortiGate, Juniper SRX, PAN-OS,
iptables, pfSense), network IDS (Snort, Suricata, Enterasys Dragon), WAF
(ModSecurity), proxies (Squid, Blue Coat, Proxifier), web (Apache access and
error), plus host, cloud, big-data and mobile sources that demonstrate the
framework is not perimeter-*only* — which is what "universal" in the title
requires.

---

## (d) Trace normalized events back to originals

Three independent bindings travel on every event:

| Mechanism | What it proves |
|---|---|
| `unmapped.ulpf_raw_locator` | Where the original bytes are — O(1) retrieval |
| `raw_data_hash` | What those bytes were at ingest (SHA-256) |
| `attestation_list[].fingerprint` | The normalized event has not been altered |
| `prev_event` | Its position in an unbroken chain |

### Fingerprints

Each event's fingerprint is a hash over its **RFC 8785 (JCS)** canonical form,
computed over the whole event *including* its chain links and excluding only
the fingerprint field itself. Because `prev_event` is inside the hashed
content, altering event *N* invalidates every event after it.

RFC 8785 matters more than it looks. Three rules do the work, and getting any
of them wrong makes every attestation unverifiable by a third party:

- Object keys sort by **UTF-16 code unit** sequence — not code point, not byte.
  The orders diverge above the BMP, because a supplementary character encodes
  as surrogates in `D800..DFFF`, numerically *below* `E000..FFFF`.
- Numbers serialise with ECMAScript `Number::toString`, which is not Rust's
  `Display`: Rust prints `1e21` as `1000000000000000000000`, JCS requires
  `1e+21`.
- Strings use the shortest JSON escape, leaving non-control characters as
  literal UTF-8.

BLAKE3 is available as an alternative to SHA-256. Because BLAKE3 is absent from
the OCSF `algorithm_id` enum, it is declared honestly as `Other(99)` with
free-text `algorithm` rather than squatting on a number that means something
else.

### Signed checkpoints, not per-event signatures

OCSF's `digital_signature` object has no attribute for signature bytes, so
there is nowhere standards-compliant to put one per event. That constraint
pushes toward the design one would want anyway: an Ed25519 signature costs tens
of microseconds, which at one per event would cap a core in the low tens of
thousands of events per second — the entire throughput budget, spent on
signing.

The chain is signed at checkpoints instead. Every event carries a fingerprint
and a backward link, making the chain tamper-*evident* on its own; a checkpoint
signs the head every N events, making it tamper-*proof* back to the last one.
Verification cost is identical; signing drops by three orders of magnitude.

### RFC 6962 Merkle log — proving one record without disclosing the log

The chain answers "has this stream been altered?" but only by replaying it.
Proving one record out of a million means handing over all million — often not
permitted at all for a log that is itself sensitive.

Each checkpoint also signs a Merkle tree head over the event fingerprints,
built to RFC 6962 with `0x00`/`0x01` domain separation. That prefix is not
decoration: without it an attacker can present an interior node as a leaf and
produce a proof for data that was never logged.

```bash
ulpf prove --integrity-dir data/integrity --chain default --event event.json > proof.json
ulpf verify-proof --proof proof.json --public-key data/integrity/ed25519-signing.pub
```

A few hundred bytes, `⌈log₂ n⌉` hashes, checkable by someone holding no other
part of the log.

**Consistency proofs** bridge an older tree size to the current signed root, so
a proof issued months ago still demonstrates the log was extended rather than
rewritten:

```bash
ulpf consistency --integrity-dir data/integrity --chain console --from 40000 > bridge.json
ulpf verify-proof --proof proof.json --checkpoint … --public-key … --consistency bridge.json
```

**Check it:** [EVALUATION-GUIDE.md § Attack 2](EVALUATION-GUIDE.md#attack-2--alter-one-field-and-see-whether-it-is-actually-detected)
and [§ Attack 3](EVALUATION-GUIDE.md#attack-3--can-one-record-be-proved-without-handing-over-the-log)

---

## (e) Plug-and-play onboarding

### A parser is a file, not a build

```bash
cp new-device.yaml packs/          # while `serve` is running
curl -s http://127.0.0.1:8787/readyz
# {"ready":true,"packs_loaded":36,…}
```

No restart, no rebuild, no plugin ABI. A filesystem watcher recompiles the
library on change.

**The debounce is load-bearing.** A file being written emits several filesystem
events; reloading on the first reads a half-written pack. The watcher coalesces
a burst and reloads once the directory has been quiet for 400 ms. A pack that
fails to compile is logged and skipped while the previous library stays in
service.

### A pack is five sections

```yaml
identity:   # vendor, product, and the detectors that claim an event
extract:    # an ordered decoder chain
map:        # extracted field -> OCSF attribute path, with coercions
enums:      # named lookup tables shared by the mapping
fixtures:   # sample lines and the attributes they must produce
```

Validation rejects unknown fields, empty detectors, missing base mappings,
invalid enum references and framework-owned paths — so a malformed pack fails
at load, not at the thousandth record.

Detectors run against raw text *before* decoding, so identification costs a
substring search rather than a parse.

---

## (f) Unified visibility

The operator console, compiled into the binary:

| View | What it shows |
|---|---|
| Overview | Events received, OCSF coverage, records needing a pack, vaulted bytes, chain sequence, and a live table naming which pack claimed each record |
| Live Map | Each product on the left, the shared OCSF meaning its records became on the right, band width = how many took that path — including the red band for records no pack claimed |
| Clusters | Dead-letter templates ranked by volume, each with a **specificity** score |
| Source Packs | Every loaded pack with its decoder chain and fixture score |
| Raw Logs | Original bytes read back **out of the vault by locator** and checked against the SHA-256 taken at ingest |
| Analytics | Per-source share of traffic, arrival rate, and the coverage its pack achieves |
| Integrity | Re-hashes every event in the window and walks the chain links |
| Assistant | Free-form conversation with a local model, given live context |

```bash
ulpf serve --packs packs --vault data/vault --integrity-dir data/integrity --datasets realdata
```

Light and dark themes, following the OS unless told otherwise. Dark is a tuned
second palette rather than an inversion — the page lifts off pure black so
panels still read as raised, and every accent gains lightness while losing
saturation, because a blue that is calm on white vibrates on near-black.

### Cluster specificity

Two clusters at equal count are not equally trustworthy. Specificity is the
share of a template that is still a literal token rather than a `<*>` wildcard:
one cluster may have generalised only a trailing timestamp, another may have
merged genuinely different shapes under a loose match until little but the
token count is shared. A low-specificity cluster with a high count is worth a
second look before drafting a pack from it.

---

## (g) SIEM and data-lake integration

| Sink | Flag |
|---|---|
| NDJSON | default |
| Parquet archive | `--parquet` |
| Feature table | `--features` |
| OpenSearch Bulk | `--opensearch` |
| Splunk HEC | `--splunk-hec` |
| UDP forward | `--forward-udp` |

`--forward-udp` emits each normalized event as one OCSF datagram to a SIEM's
syslog port, so the same traffic can be sent to that receiver raw *and* through
ULPF, landing in one index for side-by-side comparison. That comparison is the
centrepiece of [DEMO.md](DEMO.md).

---

## (h) AI/ML-ready analytics

`--features` writes a Hive-partitioned Parquet table with a **fixed 24-column
contract**, version-stamped in the footer.

The fixed contract is the point. A model consumer reading a raw archive
re-derives every field from JSON, and the shape they derive depends on what the
packs happened to map — add a pack and the effective schema moves underneath a
model trained on the old one, with nothing to signal that it moved.

- A pack that starts mapping a new attribute **does not** add a column.
- A pack that stops mapping one leaves its column present and empty.
- Adding a column is a deliberate edit with `CONTRACT_VERSION` bumped.

```python
import pyarrow.parquet as pq
pq.ParquetFile(path).metadata.created_by   # 'ulpf feature table v1'
```

See [FEATURE_TABLE.md](FEATURE_TABLE.md).

---

## (i) Reduce parser development effort

Two mechanisms, both deterministic, both working air-gapped.

### Salvage extraction — the unknown device is still searchable

Any record no pack claims is scanned for the entities that appear in perimeter
telemetry regardless of vendor: addresses, ports, MAC addresses, URLs, email
addresses, hostnames. These populate OCSF `observables`, so a device nobody has
onboarded is immediately searchable by the indicators an investigation pivots
on.

**It deliberately populates only `observables`.** It reports that an address is
present, never that it is the *source* — a pack knows FortiGate's `srcip` is
the source; this module sees two addresses and says so without inventing a
role. A wrong `src_endpoint.ip` is worse than an absent one, because a
detection rule will act on it.

### Assisted onboarding

```
unparsed records → Drain clustering → source profile → draft → score → human approves → hot reload
```

**Clustering.** The first level of Drain: bucket by token count, then match
within the bucket by positional similarity, generalising disagreeing positions
to `<*>`. Deliberately not the full parse tree — the deeper levels index on
leading tokens, which buys speed at thousands of templates and costs accuracy
on perimeter logs, where the leading tokens are a syslog timestamp that differs
on every line.

A merge must leave at least two literal tokens behind. Without that floor a
generalised template becomes an attractor: it matches on wildcards, wildcards
match anything of the same length, and the next unrelated source is absorbed
until the template identifies nothing.

**Profiling** keeps three answers separate, which is the honest part:

```bash
ulpf profile --input unknown.log --max-clusters 20
```

- observed **wire format** (high confidence — it is syntax)
- inferred **source family** (moderate confidence — it is vocabulary)
- exact **vendor/product** hypothesis, *only* when distinctive literals support
  one

Anonymous input stays `Unknown` rather than being given a plausible invented
brand:

```
"No vendor/product signature is strong enough. Use Unknown identity rather than inventing one."
```

**Two generators, offered explicitly:**

| | |
|---|---|
| **Heuristic** | Deterministic, rules-based. No model, no GPU, works air-gapped |
| **AI Copilot** | A local model (Ollama) drafts the pack |

Both are offered side by side rather than one hiding behind the other's
failure, because a deployment that forbids an LLM still has to be able to
onboard a device. The model is asked only for *recognition*; Rust assembles the
structure.

**Scoring and the approval gate.** A candidate is scored against fixtures built
from the actual samples before anyone is asked to approve it, and the review
pane names which generator produced it. Candidates load below every reviewed
pack and **activate only on human approval**.

Fixtures are drawn from the samples the detector actually claims, so a
generated pack cannot fail its own fixtures. Where no single token identifies a
source, the generator falls back to the longest phrase every sample shares,
then to the strongest phrase a majority share — drafting for the dominant
format and leaving the rest unclaimed, because a cluster is not always one
source.

**Measured result: 0% → 100% coverage over 50,000 records, no hand-written
parser, no model.**

**Check it:** [EVALUATION-GUIDE.md § Attack 4](EVALUATION-GUIDE.md#attack-4--does-onboarding-actually-work-or-is-there-a-parser-hidden-somewhere)

---

## (j) Air-gapped deployment — **shall**

No runtime network dependency on any path. The console, its CSS and its
JavaScript are compiled into the binary with `include_str!`: no CDN, no web
font, no telemetry, no model API.

```bash
cargo build --release --locked --offline
cargo test --workspace --locked --offline
```

CI runs **every** build and test step `--offline`, which fails outright if
Cargo would reach the network. The property is enforced on every commit rather
than asserted in a README.

---

## (k) Containerized deployment — *may*

Two-stage build onto distroless, read-only rootfs, all capabilities dropped.

```bash
docker compose -f deploy/demo-compose.yaml up -d --build
```

Brings up ULPF and a single-node Wazuh SIEM in one network namespace with
`--forward-udp` already wired.

`HEALTHCHECK` runs `ulpf healthcheck` — which exists because the distroless
runtime has no shell and no `curl`. It probes `/readyz`, not `/healthz`:
readiness, not liveness, because a collector that is up but has no packs loaded
will accept syslog and silently fail to normalize it.

```bash
curl -s http://127.0.0.1:8787/readyz
# {"ready":true,"packs_loaded":35,"vault_writable":true,"chain_signed_or_empty":true,"schema_version":"1.9.0"}
```

---

## Beyond the eleven requirements

### Console authentication

Every `/api/*` route requires a bearer token by default. The first `serve` run
generates one, stores it at `<integrity-dir>/console.token` with owner-only
permissions, and prints it once.

An Origin/Host guard sits alongside it — not instead of it. The token stops a
client that reaches the port directly (curl, a script, another host on the
segment); the Origin/Host check stops a page the operator has open in another
tab from driving the console (CSRF) and a hostile name resolving to loopback
(DNS rebinding). Neither substitutes for the other.

`/healthz` and `/readyz` are deliberately exempt so an orchestrator's probe
never needs the secret, and neither discloses event data.

`--no-auth` disables the token check for a throwaway local demo. With it set,
the browser-safety guard is the only remaining control, and anyone who reaches
the port can write a Source Pack — which decides how every subsequent record is
interpreted.

### TLS

`--tls-self-signed` serves HTTPS with a certificate generated on first run and
cached; `--tls-cert`/`--tls-key` take a real one. Plain HTTP remains the
default on `127.0.0.1`, where traffic never leaves the host.

### Signing-key encryption

`--encrypt-key` wraps a newly created key in ChaCha20-Poly1305 keyed by an
Argon2id-derived passphrase. Loading an existing key auto-detects whether it is
encrypted, so the flag only matters at creation.

Without it the key is protected by owner-only permissions, enforced at **every**
load — the collector refuses to start if they are loose.

`key_crypto.rs` in `ulpf-cli` and `crypto.rs` in `ulpf-vault` are deliberately
separate, near-identical implementations rather than shared code: the vault
crate must not depend on the binary crate that depends on it.

### Multi-collector verification

Chains are per-collector and verify independently. `ulpf verify` takes
`--checkpoint` and `--public-key` once per shard, so a merged multi-collector
stream verifies as several chains, each against its own key. See
[SCALING.md](SCALING.md).

### The traffic simulator

`/dev` replays real public corpora over UDP at a rate you set. Streams live in
the server, so they keep running whether or not the page is open. **A corpus
not on disk is reported `absent` and cannot be switched on** — there is
deliberately no fallback to invented data.

---

## What is deliberately absent

| Not supported | Why |
|---|---|
| NetFlow / IPFIX, Windows EVTX | Decoders read text. Binary telemetry needs a second decoder contract taking `&[u8]`, not another pack |
| TCP / TLS syslog (RFC 5425) | Future work. UDP has no backpressure; the receive buffer is raised at bind and the granted size printed |
| Correlation, alerting, detection | ULPF is the normalization layer. These consume its output downstream — it is not a SIEM |
| Per-event signatures | OCSF has nowhere to carry the bytes, and it would cost the entire throughput budget |
| Recursive pack directories | `packs/` is flat by design; the loader is not recursive and the mismatch with the recursive watcher would be worse than the limitation |
