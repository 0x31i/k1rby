# k1rby

**Read-only Active Directory recon in one shot — one `.xlsx`, one HTML dashboard, severity-rated findings, and a BloodHound collection for the graph.**

k1rby is the "run everything safe, once" button for AD enumeration — and then it does what
ADRecon won't: **it analyzes what it found.**

It opens a single read-only LDAP bind, pulls the full directory (users, computers, groups, GPOs,
trusts, sites/subnets, password policy, Kerberos, delegation, DNS, LAPS, gMSA, certificate
templates, schema, …), optionally runs the best OSS collectors alongside it (BloodHound DCOnly,
netexec, certipy), and produces **three** things: a tidy **xlsx** (ADRecon-parity inventory), a
**findings report** (severity-rated issues with affected objects, remediation, MITRE mapping, and
an overall **posture score**), and a **modern HTML dashboard**. The raw-data dump is the floor,
not the deliverable.

It is built to be **boring to your defenders' host tooling**: everything is an LDAP *search*, and
it can run either from a Linux box (so Windows AV never scans or quarantines it) or as a tiny
read-only collector on a Windows pivot that does **no** analysis on-host.

> **Authorized use only.** k1rby is read-only directory *reconnaissance*. The characteristic LDAP
> sweep is visible to a DC's telemetry (Directory Service / Defender-for-Identity) no matter where
> the collector runs — that is by design. On an engagement, **deconflict with the blue team**
> (source-IP allowlist + timebox); k1rby does not and should not try to make its queries quieter.

### Beyond ADRecon

| | ADRecon | k1rby |
|---|---|---|
| Inventory sheets | ✅ | ✅ (parity) |
| **Findings + severity** | ❌ (raw data only) | ✅ 34 rules, MITRE-mapped |
| **ACL-rights analysis (DCSync / AdminSDHolder / priv-object takeover)** | ❌ | ✅ off-host SD decode |
| **Posture score** | ❌ | ✅ 0–100 |
| **Modern HTML dashboard** | ❌ (xlsx only) | ✅ score, donut, ranked findings |
| **BloodHound graph** | ❌ | ✅ bundled DCOnly collection |
| Runs off Windows (AV-safe) | ❌ (PowerShell on-host) | ✅ Linux/python, or a thin on-pivot collector |

## Safe by construction

- **LDAP SEARCH only.** The only request type issued is a search. k1rby never writes to the
  directory — no add/modify/delete.
- **One bind, your own creds.** No password spraying, no auth attempts against other accounts →
  **no account lockout.**
- **No exploitation.** It reports Kerberoastable / AS-REP-roastable / delegation *exposure*; it
  does not roast, dump, or abuse anything. (Cracking and dumping are a different phase and a
  different tool.)

## Two ways to run it

### A) Linux live scan (default)

Run from a Linux box (Kali/WSL/etc.) against a reachable DC. Host AV never sees the tool.

```bash
pipx install k1rby            # or: pip install .
# optional external collectors (invoked only if present on PATH):
pipx install bloodhound-ce netexec certipy-ad

k1rby scan example.local -u operator -p 'password' --dc 10.0.0.10 -o example-ad.xlsx
```

Options: `--ssl` (LDAPS 636), `--simple` (SIMPLE bind, pair with `--ssl`), `--no-bloodhound`,
`--no-external` (ldap3 only), `--no-smb` (skip the DC SMB-posture probe → pure LDAP), `--roast`
(see below).

**The default run is pure read-only enumeration.** `--roast` is the one knob that goes *active*:
it requests AS-REP / TGS (Kerberoast) tickets — non-destructive and no lockout, but it hits the
KDC and is logged, so it's off by default. k1rby already *identifies* roastable accounts
(SPN / `DONT_REQ_PREAUTH`) over LDAP without requesting anything.

### B) Windows pivot → offline ingest (no tunnel, no on-host analysis)

For engagements where the only foothold is a Windows pivot — no Linux box in path, no tunnel, and
tools like `ADRecon.ps1` get auto-quarantined on sight. A tiny collector does **only** read-only
LDAP searches on the pivot and writes a raw JSON dump; **all** analysis, findings, scoring and
rendering happen later, off-host, from the dump — so none of that runs on the pivot.

```powershell
# on the Windows pivot (uses the current Kerberos context — no password on the command line):
.\windows\collect.ps1 -Domain $env:USERDNSDOMAIN -Server ($env:LOGONSERVER.TrimStart('\')) -Ssl `
  -Out .\$($env:USERDNSDOMAIN)-dump.json
```

```bash
# later, on any Linux box with k1rby installed — identical report engine as `k1rby scan`:
k1rby offline example.local-dump.json -o example-ad.xlsx
```

See [`windows/README.md`](windows/README.md) for the full pivot workflow, the host-side vs
DC-side scope, the Constrained-Language-Mode caveat, and a clean-run / data-custody checklist.
`collect.ps1` uses only built-in `System.DirectoryServices.Protocols` — no modules, no
compilation, no reflection, no network download.

> A standard **domain-user** account collects most of the inventory; a **domain-admin** (or
> suitably delegated) account additionally reads privilege-gated data: LAPS passwords, BitLocker
> recovery keys, and fine-grained password policies. Those sheets are simply empty on a
> non-privileged run — not an error.

## What you get

- **`<domain>-k1rby.html`** — modern report: posture score, severity donut, findings ranked by
  severity (each with affected objects, remediation, MITRE technique), and the full inventory in
  collapsible tables. Dark, self-contained, print-to-PDF ready.
- **`<domain>-k1rby.xlsx`** — **Summary** (posture score) + **Findings** sheet + one sheet each
  (ADRecon-parity inventory):
  Domain, Forest, **Schema History**, Password Policies (FGPP), Password Policy (Compliance),
  Domain Controllers, Trusts,
  Sites, Subnets, Users (UAC flags decoded), Kerberoastable, AS-REP Roastable, Privileged Users,
  Delegation (unconstrained/constrained/RBCD), Computers (OS, delegation), **Computer SPNs**,
  **LAPS** (readable local-admin passwords), **BitLocker** (recovery keys), **gMSA**,
  **Certificate Templates** (AD CS), Groups, Group Members (all groups), Privileged Members, OUs,
  **Printers**, GPOs, GPO Links (gPLinks), DNS Records (AD-integrated), **dSHeuristics**. Risky
  rows are shaded.
- **`bloodhound/`** *(live `scan` only)* — BloodHound `DCOnly` collection. Load it into the
  BloodHound CE GUI for attack-path and ACL/DACL analysis — k1rby collects it, the graph lives
  where it belongs.
- **`nxc-ldap.txt` / `certipy-adcs.txt`** *(live `scan`, when installed)* — password policy,
  roastable lists, and AD CS / ESC exposure from `netexec` and `certipy`.

## Findings

34 severity-rated rules (AD-001 … AD-034), each MITRE-mapped with remediation and the list of
affected objects, feeding a 0–100 posture score. Coverage includes: stale krbtgt, unconstrained
delegation on non-DCs, Kerberoastable / AS-REP-roastable privileged accounts, EOL domain
controllers and member hosts, machine-account-quota abuse, weak or no-lockout password policy,
password-not-required / never-expires / reversible-encryption accounts, stale privileged and
computer accounts, readable LAPS, active trusts, security-relevant schema extensions, anonymous-
LDAP via dSHeuristics, non-empty Schema Admins, delegable/RC4-only privileged accounts, DCs that
still accept RC4/DES, orphaned adminCount residue, and an **off-host ACL-rights analysis** of the
captured security descriptors: **DCSync** rights held by non-default principals, dangerous rights
on **AdminSDHolder**, and non-default principals with takeover rights (GenericAll/WriteDacl/
WriteOwner/GenericWrite/force-password-reset) over privileged objects.

The posture score (100 = clean) uses a multiplicative *defense-erosion* model: each finding erodes
a fraction of the remaining score by severity (saturating with object count), so impact compounds
but a handful of serious findings never instantly floor the score at 0.

## Running the live scan through a pivot (Linux path)

If you have a Linux box but must egress through a Windows jump host, forward the DC's ports over
SSH and point k1rby at the forward — traffic egresses from the authorized host, nothing executes
on it:

```bash
ssh -L 3389:DC_IP:389 -L 3636:DC_IP:636 user@jumpbox      # (plus 445/88 for bloodhound/kerberos)
k1rby scan example.local -u operator -p 'pass' --dc 127.0.0.1 --port 3389
```

For the **full** run (including bloodhound-python) through a pivot, use a SOCKS dynamic forward and
route k1rby through it — `--dns-tcp` makes bloodhound-python's DNS traverse SOCKS (UDP cannot):

```bash
ssh -D 1080 user@jumpbox                                  # SOCKS pivot
proxychains k1rby scan example.local -u operator -p 'pass' --dc DC_IP --dns-tcp
```

(When there is *no* Linux box in path at all, use the Windows pivot → offline workflow in **B**
above instead.)

## Collectors it orchestrates (live `scan`)

| Source | Gives you |
|---|---|
| k1rby `ldap3` (built-in) | the full inventory xlsx — source of truth |
| `bloodhound-python` (DCOnly) | the attack-path graph (ACLs, delegations, GPO links) |
| `netexec ldap` | password policy, AS-REP / Kerberoast candidate lists |
| `certipy find` | AD CS templates / ESC1-8 exposure |

## Data handling

Every output file type (`*.xlsx`, `*.html`, `*.csv`, `*.json`, `*.zip`, `*.b64`, and the external-
tool text outputs) is git-ignored so client data is never committed. Dumps and reports contain
sensitive material (LAPS/BitLocker secrets, PII) — treat them as credential-grade: move them off
the collection host over an encrypted channel and store them with the rest of the engagement data.

## License

MIT. Authorized security testing only — you are responsible for having permission to enumerate
the target directory.
