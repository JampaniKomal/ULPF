# Dataset inventory

Every file the coverage figure is measured on, with its origin, its verified
record count, and how to check that count yourself without running ULPF at all.

This document exists so that "32,414,250 real perimeter records" is an auditable
statement rather than an assertion. A reviewer who does not trust our pipeline
can still verify the denominator.

---

## The measured set — thirteen corpora

| # | File | Origin | Records | Bytes | Category |
|---|---|---|---:|---:|---|
| 1 | `iptables.log` | Honeynet SotM34 | 179,752 | 40,157,597 | Firewall |
| 2 | `snort.log` | Honeynet SotM34 | 69,039 | 11,158,476 | IDS |
| 3 | `dragon-nids.log` | Honeynet Dragon capture | 42,899 | 5,242,236 | IDS |
| 4 | `apache-access.log` | Honeynet SotM34 | 3,554 | 487,737 | Web |
| 5 | `Apache.full.log` | Loghub (Zenodo 8196385) | 56,482 | 5,135,876 | Web |
| 6 | `OpenSSH.full.log` | Loghub (Zenodo 8196385) | 655,147 | 73,417,506 | Auth |
| 7 | `linux-messages.log` | Honeynet SotM34 | 1,166 | 150,252 | Host |
| 8 | `Linux.full.log` | Loghub (Zenodo 8196385) | 25,567 | 2,349,686 | Host |
| 9 | `sendmail.log` | Honeynet SotM34 | 1,172 | 185,910 | Mail |
| 10 | `Proxifier.full.log` | Loghub (Zenodo 8196385) | 21,329 | 2,541,814 | Proxy |
| 11 | `squid-access.log` | Honeynet | 533,197 | 58,030,292 | Proxy |
| 12 | `bluecoat-proxy.log` | Honeynet Blue Coat capture | 8,130,590 | 2,642,664,325 | Proxy |
| 13 | `zeek-conn-full.log` | SecRepo, MACCDC 2012 | 22,694,356 | 2,718,866,065 | Network |
| | **Total** | | **32,414,250** | **5,560,387,772** | |

Roughly 5.6 GB. Fetch all thirteen with:

```bash
python tools/fetch_datasets.py
```

---

## Verifying the counts yourself

```bash
wc -l realdata/iptables.log          # 179752
wc -l realdata/bluecoat-proxy.log    # 8130590
wc -l realdata/zeek-conn-full.log    # 22694356
```

**Two files need care.** `Apache.full.log` and `OpenSSH.full.log` do not end
with a newline, so `wc -l` under-counts them by one each:

```bash
tail -c 1 realdata/Apache.full.log | xxd -p     # 2f, not 0a
wc -l realdata/Apache.full.log                  # 56481  -> 56,482 records
tail -c 1 realdata/OpenSSH.full.log | xxd -p    # 29, not 0a
wc -l realdata/OpenSSH.full.log                 # 655146 -> 655,147 records
```

This is why the sum of `wc -l` across the thirteen files is **32,414,248** and
the record total is **32,414,250**. ULPF counts records; `wc -l` counts
newlines. Loghub's own published figures are newline counts, which is why they
read 56,481 and 655,146.

Whole-set check:

```bash
cat realdata/iptables.log realdata/snort.log realdata/dragon-nids.log \
    realdata/apache-access.log realdata/Apache.full.log realdata/OpenSSH.full.log \
    realdata/linux-messages.log realdata/Linux.full.log realdata/sendmail.log \
    realdata/Proxifier.full.log realdata/squid-access.log \
    realdata/bluecoat-proxy.log realdata/zeek-conn-full.log | wc -l
# 32414248   (+2 for the two unterminated final lines = 32,414,250)
```

---

## Provenance, corpus by corpus

### Honeynet Project — Scan of the Month 34

Five of the thirteen come from one honeynet capture, so the traffic is genuine
attack traffic rather than lab noise. `tools/fetch_datasets.py` downloads
`SotM34-anton.tar.gz` and derives the flat files from it by concatenation. The
originals are kept alongside, so the derivation is checkable:

| Derived file | Built from | Check |
|---|---|---|
| `iptables.log` | `SotM34/iptables/iptablesyslog` | 179,752 = 179,752 |
| `snort.log` | `SotM34/snort/snortsyslog` | 69,039 = 69,039 |
| `apache-access.log` | `SotM34/http/access_log*` (7 rotated files) | 292+1457+538+260+229+406+372 = **3,554** |
| `sendmail.log` | `SotM34/syslog/maillog*` (7 rotated files) | 105+303+203+196+81+134+150 = **1,172** |
| `linux-messages.log` | `SotM34/syslog/messages*` (7 rotated files) | 92+195+127+127+180+256+189 = **1,166** |

Each derived file is an exact concatenation of its rotated sources — nothing
filtered, reordered or edited. Verify with:

```bash
cat realdata/SotM34/syslog/messages* | wc -l     # 1166
wc -l realdata/linux-messages.log                # 1166
```

Source: <https://honeynet.onofri.org/scans/index.html> ·
mirror <http://log-sharing.dreamhosters.com/>

### Honeynet — other captures

- **`dragon-nids.log`** — Enterasys Dragon NIDS, pipe-delimited. A second IDS
  vendor, so the IDS category is not a single-product claim. The fetcher strips
  `[MARK]` heartbeat lines, which are syslog keepalives and not device events.
- **`squid-access.log`** — Squid proxy access log, from the same Honeynet
  mirror.
- **`bluecoat-proxy.log`** — Blue Coat ProxySG, 8,130,590 records, ~2.6 GB. The
  fetcher strips the `#`-prefixed W3C header lines, which are metadata rather
  than records. This is the largest single corpus and the one the file-ingest
  throughput figure is measured on.

### Loghub — Zenodo record 8196385

Four corpora, each used byte-for-byte as published. Our counts against
Loghub's published figures:

| Corpus | Loghub published | Measured (`wc -l`) | Records |
|---|---:|---:|---:|
| Apache | 56,481 | 56,481 | 56,482 |
| Linux | 25,567 | 25,567 | 25,567 |
| OpenSSH (SSH.tar.gz) | 655,146 | 655,146 | 655,147 |
| Proxifier | 21,329 | 21,329 | 21,329 |

Exact agreement on all four. Source: <https://github.com/logpai/loghub>

**One extraction detail worth stating.** Several Loghub archives ship an
`abnormal_label.txt` beside the logs — the ground-truth answer key for anomaly
detection research. `tools/fetch_datasets.py` excludes it explicitly
(`METADATA_MEMBERS`). It is not log data, it inflates record counts, and in one
corpus its unterminated final line fused onto the first real record and
destroyed it. None of the four corpora above is affected; the exclusion is
there so it stays that way.

### SecRepo — MACCDC 2012

- **`zeek-conn-full.log`** — the complete Zeek/Bro `conn.log` from the MACCDC
  2012 competition capture, 22,694,356 records, ~2.7 GB. Streamed to disk from
  a gzip so it does not need to be held in RAM.

This corpus is also the reason one pack was corrected. `zeek-conn`'s column
order originally came from a general description of `conn.log` rather than a
capture, and was wrong: real Zeek output puts `missed_bytes`, `history` and the
packet counts immediately after `conn_state`, not the `local_orig`/`local_resp`
pair the documentation-derived order assumed. Coverage stayed high while
specific fields were quietly one column off. Measuring real data caught it.

Source: <https://www.secrepo.com/>

---

## Cross-validation corpus

`SotM30-anton.log` — 307,524 records, a **second, independent** iptables
capture from Honeynet Scan of the Month 30.

The `linux-iptables-firewall` pack was written against this file and never
tuned on SotM34. Its 100.0000% on SotM34 in the coverage table is therefore
genuine held-out validation, not a fitted result. This is the only row in the
table with that property, and we would rather name it than let it be assumed of
the others.

It is used for pack development only and is **not** counted in the 32,414,250.

---

## Synthetic data — excluded by construction

Ten fictional devices exist so the onboarding workflow can be demonstrated on a
device ULPF has genuinely never seen. Every real corpus above already has a
parser, which is exactly the problem: you cannot demonstrate onboarding a *new*
device using one that is already supported.

```bash
python tools/make_demo_source.py     # writes all ten into realdata/
```

| Device | File | Records | Wire format |
|---|---|---:|---|
| Aperture APX NGFW | `apx-ngfw-synthetic.log` | 50,000 | ISO timestamp + `key=value` |
| Meridian VaultGate | `meridian-vaultgate-synthetic.log` | 50,000 | vendor pipe layout |
| Corvid Edge Gateway | `corvid-edge-synthetic.log` | 50,000 | JSON |
| Halyard SCADA Relay | `halyard-relay-synthetic.log` | 50,000 | fixed-width columns |
| Nimbus DNS Firewall | `nimbus-dnsfw-synthetic.log` | 50,000 | bracketed syslog tag with pid |
| Tidelock File Audit | `tidelock-audit-synthetic.log` | 50,000 | tab-delimited |
| Quarrystone BMS | `quarrystone-bms-synthetic.log` | 50,000 | bracketed sections + sentence |
| Axiom WAF Gateway | `axiom-wafgw-synthetic.log` | 50,000 | angle-bracket attributes |
| Hollowbrook Switch | `hollowbrook-txn-synthetic.log` | 50,000 | semicolon `key:value` |
| Kestrel Cluster Audit | `kestrel-k8s-audit-synthetic.log` | 50,000 | second JSON vocabulary |
| | **Total** | **500,000** | |

They differ in **wire format**, not merely in field values — the tenth has to
be distinguished from the third by its keys rather than its syntax. Each drafts
a different decoder chain, which is the point.

### Four guards keep them out of every published figure

1. `SYNTHETIC` in `tools/measure_coverage.py` names all ten filenames.
2. A module-scope `assert` fails the tool outright if a synthetic file ever
   enters the measured set — a contaminated number cannot be produced silently.
3. `synthetic-datasets.manifest.json` records `"coverage_eligible": false`
   alongside a SHA-256 for each file.
4. Every address is an RFC 5737 documentation range (`203.0.113.0/24`,
   `198.51.100.0/24`, `192.0.2.0/24`) or RFC 1918 private space, so no line can
   be mistaken for a real capture.

**No coverage or throughput figure in this project includes any of these
records.** 32,414,250 + 500,000 = 32,914,250, a number that appears nowhere.

Confirm independently that none of the ten is pre-claimed by a shipped pack:

```bash
for f in realdata/*-synthetic.log; do
  ./target/release/ulpf run --packs packs --vault /tmp/v --integrity-dir /tmp/i \
    --input "$f" --output nul 2>&1 | grep parsed
  rm -rf /tmp/v /tmp/i
done
```

All ten report `parsed 0 (0.0000% coverage)`.

---

## The one committed sample

`testdata/mixed.log` — 7,319 invented records mixing eight vendor formats (CEF,
iptables, Snort, Squid, FortiGate, PAN-OS, Juniper SRX, syslog), so the
pipeline can be tried without first downloading several gigabytes.

It is **synthetic**, uses RFC 5737 addresses, is never measured, and never
appears in a published number. It is the only synthetic file committed to the
repository; the ten devices above are generated on demand and `realdata/` is
git-ignored.

---

## Licence

The log corpora are **not** redistributed in this repository.
`tools/fetch_datasets.py` retrieves them from the Honeynet Project, Loghub and
SecRepo, whose terms apply to that data. Vendoring them would silently
relicense third-party material.
