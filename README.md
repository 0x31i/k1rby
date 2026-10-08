# k1rby

**Read-only Active Directory recon in one shot — one `.xlsx`, plus a BloodHound collection for the graph.**

k1rby is the "run everything safe, once" button for AD enumeration. It opens a single read-only
LDAP bind, pulls the directory the way ADRecon/PingCastle do (users, computers, groups, GPOs,
trusts, password policy, Kerberos, delegation), optionally runs the best open-source collectors
alongside it, and writes a single tidy workbook with the risky rows highlighted.

It is built to be **boring to your defenders' tooling**: everything is an LDAP *search*, it runs
from a Linux box (so Windows AV never scans or quarantines it), and it carries a neutral name.

## Safe by construction

- **LDAP SEARCH only.** The `ldap3` connection is opened `read_only=True`, which makes the library
  refuse add/modify/delete. k1rby never writes to the directory.
- **One bind, your own creds.** No password spraying, no auth attempts against other accounts →
  **no account lockout.**
- **No exploitation.** It reports Kerberoastable / AS-REP-roastable / delegation *exposure*; it
  does not roast, dump, or abuse anything. (Cracking and dumping are a different phase and a
  different tool.)

## Install

```bash
pipx install k1rby            # or: pip install .
# optional external collectors (invoked if present on PATH):
pipx install bloodhound-ce netexec certipy-ad
```

## Use

```bash
k1rby scan example.local -u operator -p 'password' --dc 10.0.0.10 -o example-ad.xlsx
```

Options: `--ssl` (LDAPS 636), `--no-bloodhound`, `--no-external` (ldap3 only), `--roast` (see below).

**The default run is pure read-only enumeration.** `--roast` is the one knob that goes *active*:
it has `netexec` request AS-REP / TGS (Kerberoast) tickets — non-destructive and no lockout, but
it hits the KDC and is logged, so it's off by default. k1rby already *identifies* roastable
accounts (SPN / `DONT_REQ_PREAUTH`) over LDAP without requesting anything.

## What you get

- **`<domain>-k1rby.xlsx`** — Summary tab + one sheet each (ADRecon-parity): Domain, Forest,
  Password Policies (FGPP), Domain Controllers, Trusts, **Sites**, **Subnets**, Users (UAC flags
  decoded), Kerberoastable, AS-REP Roastable, Privileged Users, Delegation (unconstrained/
  constrained/RBCD), Computers (OS, delegation), **LAPS** (readable local-admin passwords),
  Groups, **Group Members** (all groups), Privileged Members, OUs, GPOs, **GPO Links** (gPLinks),
  **DNS Records** (AD-integrated). Risky rows are shaded.
  *ACLs/DACLs are collected by the bundled BloodHound run (the graph), not duplicated into the xlsx.*
- **`bloodhound/`** — BloodHound `DCOnly` collection (`--zip`). Load it into the BloodHound CE GUI
  for attack-path analysis — k1rby collects it, the graph lives where it belongs.
- **`nxc-ldap.txt` / `certipy-adcs.txt`** — password policy, roastable lists, and AD CS / ESC
  exposure from `netexec` and `certipy` when they're installed.

## Running off-box (dodge AV *and* host constraints)

If the only foothold is a Windows jump box you'd rather not run tools on, forward the DC's ports
to your Linux box over SSH and point k1rby at the forward — traffic still egresses from the
authorized host, but nothing executes on it:

```bash
ssh -L 3389:DC_IP:389 -L 3636:DC_IP:636 user@jumpbox      # (plus 445/88 for bloodhound/kerberos)
k1rby scan example.local -u operator -p 'pass' --dc 127.0.0.1 --port 3389
```

## Collectors it orchestrates

| Source | Gives you |
|---|---|
| k1rby `ldap3` (built-in) | the full inventory xlsx — source of truth |
| `bloodhound-python` (DCOnly) | the attack-path graph (ACLs, delegations, GPO links) |
| `netexec ldap` | password policy, AS-REP / Kerberoast candidate lists |
| `certipy find` | AD CS templates / ESC1-8 exposure |

## License

MIT. Authorized security testing only — you are responsible for having permission to enumerate
the target directory.
