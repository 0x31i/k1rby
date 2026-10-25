"""k1rby — read-only Active Directory recon in one shot.

    k1rby scan example.local -u operator -p 'pass' --dc 10.0.0.1 -o example-ad.xlsx

Opens ONE read-only LDAP bind, enumerates the directory (users/computers/groups/GPOs/trusts/
policy/kerberos/delegation), optionally runs the OSS collectors (bloodhound-python DCOnly, nxc,
certipy), and writes a single multi-sheet xlsx plus the BloodHound zip for the CE GUI.

Safe by construction: LDAP SEARCH only (no writes, no auth attempts against accounts, no
exploitation) — no lockout, no changes. Built to run from a Linux box (e.g. Kali/WSL) so host
AV never sees or quarantines it.
"""

from __future__ import annotations

import argparse
import os
import sys
import time


def _banner() -> str:
    return r"""
  k 1 r b y   ·  read-only AD recon
"""


def _steps(c):
    """(sheet name, collector method) in sheet order. Shared by `scan` and `offline` so both
    produce an identical report from an identical pipeline."""
    return [
        ("Domain", c.domain_info),
        ("Forest", c.forest_info),
        ("dSHeuristics", c.ds_heuristics),
        ("Schema History", c.schema_history),
        ("Password Policies (FGPP)", c.password_policies_fgpp),
        ("Password Policy (Compliance)", c.password_policy_compliance),
        ("Domain Controllers", c.domain_controllers),
        ("Trusts", c.trusts),
        ("Sites", c.sites),
        ("Subnets", c.subnets),
        ("Users", c.users),
        ("Kerberoastable", c.kerberoastable),
        ("AS-REP Roastable", c.asrep_roastable),
        ("Privileged Users", c.privileged_users),
        ("Delegation", c.delegation),
        ("Computers", c.computers),
        ("Computer SPNs", c.computer_spns),
        ("Key Credentials", c.key_credentials),
        ("LAPS", c.laps),
        ("LAPS Coverage", c.laps_coverage),
        ("BitLocker", c.bitlocker),
        ("gMSA", c.gmsa),
        ("Certificate Templates", c.cert_templates),
        ("Certificate Authorities", c.cert_authorities),
        ("Groups", c.groups),
        ("Group Members", c.group_members_all),
        ("Privileged Members", c.privileged_group_members),
        ("Foreign Security Principals", c.foreign_sps),
        ("OUs", c.ous),
        ("Printers", c.printers),
        ("GPOs", c.gpos),
        ("GPO Links", c.gpo_links),
        ("DNS Records", c.dns_records),
        ("ACLs (raw)", c.acls),
    ]


def _collect(c) -> dict:
    sections = {}
    for name, fn in _steps(c):
        try:
            rows = fn()
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"[!] {name}: {e}\n")
            rows = []
        sections[name] = rows
        sys.stderr.write(f"[+] {name}: {len(rows)}\n")
    return sections


def _write_report(out: str, domain: str, sections: dict, external, t0: float) -> int:
    from . import findings as fnd, htmlreport, report
    flist = fnd.analyze(sections)
    score = fnd.posture_score(flist)
    sc = fnd.severity_counts(flist)
    counts = report.build(out, domain, sections, external, findings=flist, score=score)
    html_out = os.path.splitext(out)[0] + ".html"
    with open(html_out, "w", encoding="utf-8") as fh:
        fh.write(htmlreport.build(domain, flist, sections, external))
    total = sum(counts.values())
    sys.stderr.write(
        f"\n[✓] {total} objects, {len(flist)} findings | posture {score}/100 "
        f"(C:{sc['critical']} H:{sc['high']} M:{sc['medium']} L:{sc['low']}) ({time.time() - t0:.0f}s)\n"
        f"    xlsx -> {out}\n    html -> {html_out}\n")
    if external and any("bloodhound" in k.lower() for k in external):
        sys.stderr.write("    bloodhound/ -> load into BloodHound CE for attack paths\n")
    return 0


def run_offline(args) -> int:
    """Build the report from a raw LDAP dump produced on a Windows pivot (no live DC)."""
    from . import offline
    t0 = time.time()
    try:
        dump = offline.load_dump(args.dump)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"[!] could not read dump {args.dump}: {e}\n")
        return 2
    domain = args.domain or dump.get("meta", {}).get("domain", "")
    if not domain:
        sys.stderr.write("[!] dump has no meta.domain; pass --domain\n")
        return 2
    out = args.out or f"{domain}-k1rby.xlsx"
    sys.stderr.write(_banner())
    sys.stderr.write(f"[*] offline ingest of {args.dump} (domain {domain}) — no DC contacted\n")
    c = offline.OfflineCollector(dump)
    sections = _collect(c)
    return _write_report(out, domain, sections, None, t0)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="k1rby", description="Read-only Active Directory recon -> xlsx (+ BloodHound).")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="enumerate a domain and write the report")
    s.add_argument("domain", help="FQDN, e.g. example.local")
    s.add_argument("-u", "--username", required=True)
    s.add_argument("-p", "--password", required=True)
    s.add_argument("--dc", required=True, help="domain controller IP/host")
    s.add_argument("-o", "--out", default=None, help="output .xlsx (default: <domain>-k1rby.xlsx)")
    s.add_argument("--ssl", action="store_true", help="LDAPS (636) instead of LDAP (389)")
    s.add_argument("--port", type=int, default=None)
    s.add_argument("--simple", action="store_true",
                   help="SIMPLE bind (user@domain) instead of NTLM — pair with --ssl. Needed on "
                        "modern Python/OpenSSL 3 where NTLM's MD4 is unavailable.")
    s.add_argument("--insecure-tls", action="store_true",
                   help="skip TLS cert validation (e.g. LDAPS reached through a port-forward)")
    s.add_argument("--no-bloodhound", action="store_true", help="skip bloodhound-python collection")
    s.add_argument("--no-external", action="store_true", help="skip ALL external tools (ldap3 only)")
    s.add_argument("--dns-tcp", action="store_true",
                   help="force DNS over TCP for bloodhound-python — required when running k1rby "
                        "through a SOCKS pivot (e.g. `proxychains k1rby ...`)")
    s.add_argument("--no-smb", action="store_true",
                   help="skip the DC SMB posture probe (SMB1/dialects/signing). The probe is an "
                        "active negotiate-only connection to 445 (no auth); --no-smb keeps the run "
                        "pure read-only LDAP.")
    s.add_argument("--roast", action="store_true",
                   help="ALSO request AS-REP/Kerberoast tickets (active, logged; OFF by default so "
                        "the standard run stays pure read-only enumeration)")

    o = sub.add_parser("offline",
                       help="build the report from a raw LDAP dump (windows/collect.ps1) "
                            "— no DC is contacted")
    o.add_argument("dump", help="path to the JSON dump produced on the pivot")
    o.add_argument("-o", "--out", default=None, help="output .xlsx (default: <domain>-k1rby.xlsx)")
    o.add_argument("--domain", default=None, help="override domain (else taken from dump meta)")

    args = ap.parse_args(argv)
    if args.cmd == "offline":
        return run_offline(args)
    if args.cmd != "scan":
        ap.print_help()
        return 0

    from . import ldapcollect, report
    out = args.out or f"{args.domain}-k1rby.xlsx"
    outdir = os.path.dirname(os.path.abspath(out)) or "."
    sys.stderr.write(_banner())
    sys.stderr.write(f"[*] binding {args.username}@{args.domain} via {args.dc} (read-only)\n")

    t0 = time.time()
    try:
        c = ldapcollect.Collector(args.dc, args.domain, args.username, args.password,
                                  use_ssl=args.ssl, port=args.port,
                                  auth="simple" if args.simple else "ntlm",
                                  tls_verify=not args.insecure_tls)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"[!] bind failed: {e}\n")
        return 2
    c.smb = not args.no_smb

    # order defines sheet order (Summary is injected first by report.build)
    sections = _collect(c)
    c.close()

    external = None
    if not args.no_external:
        from . import external as ext
        sys.stderr.write("[*] external collectors (best-effort, read-only)...\n")
        external = ext.run_all(outdir, args.dc, args.domain, args.username, args.password,
                               with_bloodhound=not args.no_bloodhound, roast=args.roast,
                               dns_tcp=args.dns_tcp, use_ssl=args.ssl)
        for tool, status in external.items():
            sys.stderr.write(f"[+] {tool}: {status}\n")

    return _write_report(out, args.domain, sections, external, t0)


if __name__ == "__main__":
    raise SystemExit(main())
