ULPF ingests heterogeneous security logs, keeps the exact original bytes in an
append-only vault, and emits OCSF 1.9 with a signed, tamper-evident chain over
every record. Built by the ULPF team for Smart India Hackathon 2026
(PS 26156); see the README for who built it and what changed in this
repository.

### Downloads

| Archive | Platform |
|---|---|
| `ulpf-*-x86_64-unknown-linux-gnu.tar.gz` | Linux x86_64 (glibc 2.35 or newer) |
| `ulpf-*-x86_64-pc-windows-msvc.zip` | Windows x86_64 |

Each archive holds the `ulpf` binary, the 35 Source Packs it loads at runtime,
and the licence. `SHA256SUMS` lists the checksums.

### Try it

```bash
./ulpf test --packs packs
./ulpf serve --packs packs --vault data/vault --integrity-dir data/integrity
```

The first command scores every pack against its fixtures (78/78). The second
starts the collector and console on http://127.0.0.1:8787; it prints a bearer
token once at startup.

Licensed under Apache-2.0. See LICENSE and NOTICE.
