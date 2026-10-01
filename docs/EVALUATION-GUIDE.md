# Evaluation guide

**ULPF — Universal Log Pre-processing Framework**
SIH 2026 · Problem Statement 26156 · NTRO · Blockchain & Cybersecurity

This document is written for an evaluator. It assumes you have a laptop, forty
minutes, and no prior knowledge of this project. It tells you what to run, what
you should see, and — more usefully — how to try to catch us out.

Every command below was executed on a clean checkout before it was written
down, and the outputs quoted are the ones it produced.

---

## Contents

- [What this project claims, in six sentences](#what-this-project-claims-in-six-sentences)
- [The fifteen-minute path](#the-fifteen-minute-path)
- [The forty-minute path — reproduce the headline figure](#the-forty-minute-path--reproduce-the-headline-figure)
- [How to attack it](#how-to-attack-it)
- [What we have not done](#what-we-have-not-done)
- [Where every number comes from](#where-every-number-comes-from)

---

## What this project claims, in six sentences

1. Any perimeter-device log goes in; OCSF 1.9 comes out.
2. The original bytes are stored **before** anything is parsed, so a record no
   parser understands is preserved, addressable and retrievable — not lost.
3. A new device is a YAML file dropped into a folder, not a code change.
4. Every emitted event carries a cryptographic fingerprint over its own
   canonical form plus a link to its predecessor, so altering any event breaks
   every event after it.
5. Records nobody has written a parser for are clustered, and a parser is
   drafted for them automatically — deterministically, with no model and no
   network, subject to human approval.
6. None of it needs a network at runtime.

Claims 2, 4 and 5 are the ones worth your scepticism. Sections below let you
test each directly.

---

## The fifteen-minute path

### 0. Prerequisites

| | |
|---|---|
| Rust | 1.85+ (pinned by `rust-toolchain.toml`) |
| Python | 3.9+, only for fetching corpora |
| Disk | ~2 GB build, ~5.6 GB corpora |

No database, no broker, no container runtime, no network at runtime.

### 1. Build

```bash
cargo build --release --locked
```

Takes about three minutes. `--locked` means the dependency tree is exactly the
one we tested; it cannot silently resolve to something else.

### 2. Run the test suite

```bash
cargo test --workspace --release --locked
```

Expect **405 tests passed, 0 failed**.

### 3. Score every parser against its own fixtures

```bash
./target/release/ulpf test --packs packs
```

Expect exactly:

```
35 packs · 78/78 fixtures passed · 100.0% field accuracy
```

A pack that cannot parse its own fixtures never reaches the loaded list, so
this is a gate, not a report.

### 4. Check the parsers against the OCSF schema

```bash
python tools/audit_pack_enums.py
```

Expect `0 problem(s) found across 35 packs`. This is a different check from
step 3 and catches something fixtures cannot: a pack can parse its own sample
perfectly and still map a vendor's verb onto the wrong OCSF enum. This audits
every `activity_id` against the vendored OCSF 1.9.0 schema in `schema/ocsf`.

### 5. Process a real capture end to end

```bash
./target/release/ulpf run --packs packs --vault data/vault \
  --integrity-dir data/integrity \
  --input realdata/linux-messages.log --output events.ndjson
```

```
  received          1166
  parsed            1156 (99.1424% coverage)
  unidentified      10
  bytes in          150252
  by pack:
    linux-syslog-host                        1156
  checkpoint        seq 1166 head 4541385a29581d06…
```

**Note the arithmetic.** 1,156 parsed, 10 unidentified — and `events.ndjson`
contains **1,166 lines**. The ten records no parser claimed were still emitted
as valid OCSF. That is the central design claim, and it is checkable with
`wc -l`.

### 6. Verify the integrity chain

```bash
./target/release/ulpf verify events.ndjson \
  --checkpoint data/integrity/default.checkpoint.json \
  --public-key data/integrity/ed25519-signing.pub
```

```
OK  1166 events verified
    chain head 01a0ba5d-5d14-7eb2-9d5f-e5fdcebc40b0 fingerprint 4541385a…
    signed checkpoint verified
    trusted public key verified
```

Now the interesting part.

---

## How to attack it

These are the tests we would run if we were evaluating this project. We have
run them; you should too, because our saying so is not evidence.

### Attack 1 — is an unparsed record really preserved, or just counted?

Find a record no parser claimed and retrieve its original bytes from the vault:

```bash
python -c "
import json
for line in open('events.ndjson', encoding='utf-8'):
    e = json.loads(line)
    if not e['metadata'].get('log_provider'):
        print('class_uid  :', e['class_uid'])
        print('locator    :', e['unmapped']['ulpf_raw_locator'])
        print('raw_data   :', repr(e['raw_data']))
        print('recorded   :', e['raw_data_hash']['value'])
        break
"
```

```
class_uid  : 0
locator    : ulpf:raw:0000000000000000:000000000000458a:0000003a
raw_data   : 'Mar 17 13:06:36 combo  -- root[17812]: ROOT LOGIN ON tty1\n'
recorded   : 8c94d736dc84f63369e68081beca2c8ba6dd0c7ca04db292bd08f0421eaf4977
```

Then pull those bytes back out of the vault by that locator and hash them
yourself:

```bash
./target/release/ulpf raw --vault data/vault ulpf:raw:0000000000000000:000000000000458a:0000003a | sha256sum
```

```
8c94d736dc84f63369e68081beca2c8ba6dd0c7ca04db292bd08f0421eaf4977
```

Byte-identical to the hash recorded at ingest. The record has `class_uid: 0`
(Base Event) and no `log_provider`, because no pack claimed it — and it is
still a first-class, fingerprinted, retrievable OCSF event.

**What this rules out:** storing a re-serialised JSON of the parsed fields and
calling it the original. The bytes are the bytes.

### Attack 2 — alter one field and see whether it is actually detected

```bash
python -c "
import json
lines = open('events.ndjson', encoding='utf-8').read().splitlines()
e = json.loads(lines[500])
e['device']['hostname'] = 'attacker-rewrote-this'
lines[500] = json.dumps(e)
open('tampered.ndjson','w',encoding='utf-8').write('\n'.join(lines) + '\n')
"
```

```bash
./target/release/ulpf verify tampered.ndjson \
  --checkpoint data/integrity/default.checkpoint.json \
  --public-key data/integrity/ed25519-signing.pub
```

```
[default] FAIL  fingerprint mismatch: event content has been altered
Error: 1 of 1 chains failed verification
```

One attribute, on one event, out of 1,166 — detected, and the process exits
non-zero.

Now the part that matters forensically. The tampered file says the hostname was
`attacker-rewrote-this`. Ask the vault:

```bash
./target/release/ulpf raw --vault data/vault <that event's locator>
```

```
Feb 25 13:29:09 combo sshd(pam_unix)[20624]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=202.110.184.100  user=root
```

The vault is append-only and was never touched. The original is still there and
is *provably* different from the altered record.

**Why this works:** each event's fingerprint covers the RFC 8785 (JCS)
canonical form of the whole event *including* its `prev_event` link and
excluding only the fingerprint field itself. Altering event *N* therefore
invalidates *N* and every event after it. See
[ARCHITECTURE.md](ARCHITECTURE.md) and `crates/ulpf-ocsf/src/integrity.rs`.

### Attack 3 — can one record be proved without handing over the log?

This is the property that makes an extract from a sensitive log shareable.

```bash
head -1 events.ndjson > one-event.json
./target/release/ulpf prove --integrity-dir data/integrity \
  --chain default --event one-event.json > proof.json
```

```
proof for event 1 of 1166: 11 hashes, 352 bytes
```

Eleven hashes — ⌈log₂ 1166⌉. Now verify it holding **nothing else**: no vault,
no chain, no other event.

```bash
./target/release/ulpf verify-proof --proof proof.json \
  --public-key data/integrity/ed25519-signing.pub
```

```
PROOF VALID
  chain:            default
  event uid:        01a0ba5d-5cc3-7e70-a517-05547f03399e
  position:         1 of 1166
  proof size:       11 hashes
  signed root:      63b2cc0792d5de4337b2a5d60c8231c21a7130a843238696e5696ed85573f441
  checkpoint:       verified against data/integrity/ed25519-signing.pub

This record was in the log when the checkpoint was signed.
```

RFC 6962 (Certificate Transparency) construction, including its `0x00`/`0x01`
domain separation — without which an interior node can be presented as a leaf
and a proof produced for data that was never logged. See [PROOFS.md](PROOFS.md).

### Attack 4 — does onboarding actually work, or is there a parser hidden somewhere?

Every real corpus already has a parser, which is exactly why a demonstration of
onboarding needs a device that is genuinely new. Ten fictional devices exist to
be unknown:

```bash
python tools/make_demo_source.py
```

Pick one and run it against the 35 shipped packs:

```bash
./target/release/ulpf run --packs packs --vault /tmp/v --integrity-dir /tmp/i \
  --input realdata/apx-ngfw-synthetic.log --output nul \
  --dead-letter dead.ndjson
```

```
  received          50000
  parsed            0 (0.0000% coverage)
  unidentified      50000
```

Zero. Now profile it, with no model and no network:

```bash
./target/release/ulpf profile --input realdata/apx-ngfw-synthetic.log --max-clusters 3
```

```json
{
  "wire_format": "keyvalue",
  "wire_format_confidence": 0.9,
  "source_family": "network-firewall",
  "source_family_confidence": 0.511,
  "source_hypotheses": [],
  "stable_detector_terms": ["sessionlog", "apx-ngfw", "verdict="],
  "warnings": [
    "No vendor/product signature is strong enough. Use Unknown identity rather than inventing one."
  ]
}
```

Note what it refuses to do. It reports the wire format with high confidence,
the source family with moderate confidence, and **declines to name a vendor**,
because nothing in the data supports one. An anonymous log stays `Unknown`
rather than being given a plausible invented brand.

Draft a parser from the dead letters:

```bash
./target/release/ulpf draft --dead-letter dead.ndjson --output candidates --max-clusters 2
```

```
drafted 2 candidate pack(s) from 50000 dead-letter record(s) into candidates
candidates remain disabled until a human reviews and approves them
```

Approve one by copying it into the pack directory, and re-run:

```
  received          50000
  parsed            50000 (100.0000% coverage)
  by pack:
    ulpf-candidate-001                       50000
```

**0% to 100% over 50,000 records, with no hand-written parser, no model, no
GPU and no network.** An AI copilot path also exists (a local Ollama model),
but it is offered alongside the deterministic generator rather than in place of
it, because a deployment that forbids an LLM still has to be able to onboard a
device.

All ten devices behave the same way. They differ in **wire format**, not just
field values — `key=value`, JSON, a vendor pipe layout, fixed columns, a
bracketed syslog tag with a pid, tab-delimited, angle-bracket attributes,
bracketed sections with a sentence, semicolon `key:value`, and a second JSON
vocabulary that must be told from the first by its keys rather than its syntax.
Each drafts a different decoder chain, which is the point.

Verify for yourself that none is pre-claimed:

```bash
for f in realdata/*-synthetic.log; do
  ./target/release/ulpf run --packs packs --vault /tmp/v --integrity-dir /tmp/i \
    --input "$f" --output nul 2>&1 | grep parsed
  rm -rf /tmp/v /tmp/i
done
```

All ten report `0 (0.0000% coverage)`.

### Attack 5 — is it really air-gapped?

```bash
cargo build --release --locked --offline
cargo test --workspace --locked --offline
```

`--offline` makes Cargo fail outright rather than reach the network. CI runs
every build and test step this way, so the property is enforced on every
commit, not asserted in a README. The console's HTML, CSS and JavaScript are
compiled into the binary with `include_str!` — no CDN, no web font, no
telemetry, no model API on any runtime path.

Confirm the binary opens no sockets it should not: `serve` binds the console
port and the UDP syslog port, and nothing else.

### Attack 6 — is the synthetic data contaminating the measurements?

It cannot, and there are four independent guards:

1. `SYNTHETIC` in `tools/measure_coverage.py` names all ten filenames.
2. An `assert` at module scope fails the tool outright if a synthetic file ever
   appears in the measured set.
3. The generated manifest carries `"coverage_eligible": false`.
4. Every address in them is an RFC 5737 documentation range (`203.0.113.0/24`,
   `198.51.100.0/24`, `192.0.2.0/24`) or RFC 1918 private space, so no line can
   be mistaken for a capture.

Grep the tool yourself — the assertion is eight lines below the `SYNTHETIC`
set.

---

## The forty-minute path — reproduce the headline figure

```bash
python tools/fetch_datasets.py
```

Fetches the thirteen perimeter corpora — roughly 5.6 GB on disk. Completed
files are skipped and partial transfers resume, so an interrupted fetch is
restarted by running the same command again. Full provenance for every file is
in [DATASETS.md](DATASETS.md).

```bash
python tools/measure_coverage.py --set perimeter
```

About forty minutes. Expect:

```
CATEGORY   SOURCE                              EVENTS    PARSED   COVERAGE
--------------------------------------------------------------------------
firewall   iptables (Honeynet SotM34)         179,752   179,752  100.0000%
IDS        Snort (Honeynet SotM34)             69,039    69,038   99.9986%
IDS        Enterasys Dragon (Honeynet)         42,899    42,899  100.0000%
web        Apache access (Honeynet)             3,554     3,553   99.9719%
web        Apache error (Loghub)               56,482    52,004   92.0718%
auth       OpenSSH (Loghub)                   655,147   655,147  100.0000%
host       Linux syslog (Honeynet)              1,166     1,156   99.1424%
host       Linux (Loghub)                      25,567    25,539   99.8905%
mail       Sendmail MTA (Honeynet)              1,172     1,164   99.3174%
proxy      Proxifier (Loghub)                  21,329    21,316   99.9391%
proxy      Squid proxy (Honeynet)             533,197   533,075   99.9771%
proxy      Blue Coat ProxySG (Honeynet)     8,130,590 8,114,594   99.8033%
network    Zeek conn.log (MACCDC 2012)      22,694,356 22,681,527   99.9435%
--------------------------------------------------------------------------
PERIMETER (the headline figure)             32,414,250 32,380,764   99.8967%
```

**32,414,250 real perimeter records at 99.8967% coverage.** Every figure is
from unmodified public capture data — Honeynet Project, Loghub and the MACCDC
2012 capture. No figure anywhere in this project is measured on synthesised
data.

You can check the record counts independently without running anything:

```bash
wc -l realdata/iptables.log     # 179752
wc -l realdata/bluecoat-proxy.log   # 8130590
wc -l realdata/zeek-conn-full.log   # 22694356
```

Two files — `Apache.full.log` and `OpenSSH.full.log` — do not end with a
newline, so their record count is `wc -l` plus one (56,482 and 655,147). That
is why the sum of `wc -l` across the thirteen files is 32,414,248 and the
record total is 32,414,250.

### The misses are named, not rounded away

We would rather you heard this from us.

33,486 records of 32,414,250 are unparsed. Where they are:

| Source | Coverage | Unparsed | What the remainder is |
|---|---:|---:|---|
| Apache error | 92.0718% | 4,478 | A bare `script not found or unable to stat` carrying no timestamp, no severity and no client. ULPF will not invent fields a record does not state. |
| Linux syslog (Honeynet) | 99.1424% | 10 | `last message repeated N times` — emitted by syslogd itself, not by a device |
| Sendmail | 99.3174% | 8 | The same syslogd `last message repeated N times` artifact |
| Squid | 99.9771% | 122 | Not yet characterised |
| Linux (Loghub) | 99.8905% | 28 | Daemon long tail |
| Proxifier | 99.9391% | 13 | Non-connection lines |
| Blue Coat | 99.8033% | 15,996 | Not yet characterised — 0.197% of 8.1 million |
| Zeek | 99.9435% | 12,829 | Not yet characterised — 0.057% of 22.7 million |
| Snort / Apache access | ~100% | 1 each | Single malformed record in each capture |

The rows marked *not yet characterised* are honest: we have the count exactly
and have not sampled the content. We would rather say that than publish a cause
we have not checked. Inspect any of them yourself with
`ulpf run … --dead-letter dead.ndjson`.

Every unparsed record above is still vaulted, fingerprinted, chained and
emitted as valid OCSF carrying its raw text. "Unparsed" is a routing decision,
never data loss — which is the whole point of the vault-first ordering.

### One figure is genuine cross-validation

The iptables pack scores **100.0000%** on the SotM34 capture. That pack was
written against a *different* capture — SotM30, 307,524 records — and was never
tuned on SotM34. It is the one row in the table that was not, in any sense,
fitted to its test set.

---

## What we have not done

Stated plainly, because you will find it anyway.

- **1 billion events/day is arithmetic, not a sustained run.** File ingest
  measures 13,290 events/sec over 8,130,590 real records; 13,290 × 86,400 is
  1.148 billion. Multiplying a measured rate out to a day is not the same as
  having run for a day, and this project does not claim it has.
- **Over UDP the lossless ceiling is 8,000 EPS**, below the 11,574 that target
  needs. That path is bounded by the socket, not the pipeline. See
  [THROUGHPUT.md](THROUGHPUT.md), which publishes the losses at every rate
  including the ones where it fails.
- **Coverage is 99.8967%, not 100%.** The remainder is enumerated above.
- **Three of the 35 packs have no real-corpus evidence** — generic CEF, pfSense
  and Check Point's CEF variant pass fixtures written from vendor
  documentation. Treat them as unproven. Real data has repeatedly broken packs
  that passed documentation-derived tests; see [DATASETS.md](DATASETS.md) for
  six cases where a pack scored 100% on its own fixtures and then 5–36% on real
  traffic.
- **Binary telemetry is not supported.** NetFlow/IPFIX and Windows EVTX need a
  decoder contract taking `&[u8]`, not another pack.
- **TCP/TLS syslog (RFC 5425) is future work.** The UDP receive buffer is
  raised at bind and the granted size printed, but UDP has no backpressure.
- **The Assistant's answer quality is limited by a 1.5B model.** It reads live
  context correctly and reasons loosely. Pack drafting deliberately does not
  depend on it.

---

## Where every number comes from

| Claim | Command |
|---|---|
| 35 packs, 78/78 fixtures, 100% field accuracy | `ulpf test --packs packs` |
| 405 tests pass | `cargo test --workspace --release --locked` |
| 0 enum problems across 35 packs | `python tools/audit_pack_enums.py` |
| 32,414,250 records at 99.8967% | `python tools/measure_coverage.py --set perimeter` |
| UDP throughput and its losses | `python tools/measure_throughput.py` |
| Byte-exact raw retrieval | `ulpf raw --vault <dir> <locator>` |
| Chain verification | `ulpf verify <ndjson> --checkpoint … --public-key …` |
| Single-record proof | `ulpf prove …` then `ulpf verify-proof …` |
| 0% → 100% onboarding | `ulpf profile` → `ulpf draft` → approve → `ulpf run` |
| Air-gapped build | `cargo build --release --locked --offline` |

Nothing in this project reports a figure that one of these commands does not
produce. If a number in any document does not match what the command prints on
your machine, the document is wrong and we want to know.

---

## Further reading

| Document | Contents |
|---|---|
| [PROBLEM-STATEMENT.md](PROBLEM-STATEMENT.md) | PS 26156 read closely, clause by clause |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The 2-page architecture document |
| [ARCHITECTURE-DETAIL.md](ARCHITECTURE-DETAIL.md) | Crate boundaries and data flow, in full |
| [FEATURES.md](FEATURES.md) | Complete feature catalogue, mapped to requirements (a)–(k) |
| [DATASETS.md](DATASETS.md) | Corpus provenance, coverage, named misses |
| [DATASET-INVENTORY.md](DATASET-INVENTORY.md) | Every file, verified record count, origin |
| [THROUGHPUT.md](THROUGHPUT.md) | Measured EPS, method, the limits found |
| [PROOFS.md](PROOFS.md) | Proving one event without disclosing the log |
| [DEMO.md](DEMO.md) | The single-laptop demonstration, start to finish |
