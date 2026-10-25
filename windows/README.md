# Windows pivot collector (`collect.ps1`)

For authorized internal assessments where the operator **only has a Windows pivot** — no Linux
box in path and no tunnel — so the normal `k1rby scan` (Linux/Python, off-host) can't reach the
DC, and `ADRecon.ps1` is auto-quarantined on sight (signature / name / hash).

The split keeps the pivot footprint minimal:

```
  Windows pivot                         Linux box (anywhere, later)
  ┌───────────────────────────┐         ┌──────────────────────────────────┐
  │ collect.ps1                │  dump   │ k1rby offline <dump>.json          │
  │  read-only LDAP only       │ ──────► │  → <CLIENT>-AD-Assessment.xlsx     │
  │  (no analysis, no render)  │  .json  │  → <CLIENT>-AD-Assessment.html     │
  └───────────────────────────┘         │  (same engine as `k1rby scan`)     │
                                         └──────────────────────────────────┘
```

`collect.ps1` runs **only** `SearchRequest` (read-only LDAP) via built-in
`System.DirectoryServices.Protocols` — no modules, no `Add-Type -TypeDefinition`/`csc.exe`
compilation, no reflection, no network download, nothing written back to AD. All parsing,
the 19 findings, posture scoring and xlsx/HTML rendering happen off-host in `k1rby offline`,
so none of those behaviours run on the pivot.

## Run

On the pivot (run from disk; sign it if you have a cert):

```powershell
.\collect.ps1 -Domain corp.local -Server 10.0.0.10 -Username <user> -Password '<pass>' -Out corp-dump.json
# or current Kerberos context (domain-joined pivot):
.\collect.ps1 -Domain corp.local -Server dc01.corp.local -Out corp-dump.json
# LDAPS:  add -Ssl    |  non-default port: -Port 3269
```

Use the **domain-admin** account for full coverage (readable LAPS passwords, security
descriptors); a domain-user account works but sees less. It is still pure read-only LDAP SEARCH
either way — no writes, no account auth attempts, no lockout.

Off-host, on any Linux box with k1rby installed:

```bash
k1rby offline corp-dump.json -o corp-AD-Assessment.xlsx
```

## Honest scope

- **Host side:** this avoids the pivot's EDR/AV auto-blocking the tool (the thing that kills
  ADRecon), because almost nothing analytical executes locally.
- **DC side:** it does **not** make the LDAP recon quieter at the DC — the read-only sweeps and
  their attribute bundles generate the same Directory-Service / Defender-for-Identity / honeytoken
  signals no matter where the collector runs. For an authorized test the correct control is
  **deconfliction with the blue team** (source-IP allowlist + timebox + telling them the
  characteristic LDAP pattern is expected), not trying to evade the queries.
- **Constrained Language Mode:** if the pivot enforces strict WDAC/AppLocker CLM, instantiating
  the .NET LDAP types may be blocked; in that case the off-host `k1rby scan` path is the fallback.
- **Not captured offline:** the DC SMB-dialect/signing probe (an active negotiate the Linux `scan`
  does) and the BloodHound DCOnly collection are skipped in the pivot→offline flow.
