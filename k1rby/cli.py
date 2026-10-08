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
    s.add_argument("--roast", action="store_true",
                   help="ALSO request AS-REP/Kerberoast tickets (active, logged; OFF by default so "
                        "the standard run stays pure read-only enumeration)")

    args = ap.parse_args(argv)
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

    # order defines sheet order (Summary is injected first by report.build)
    sections = {}
    steps = [
        ("Domain", c.domain_info),
        ("Forest", c.forest_info),
        ("Password Policies (FGPP)", c.password_policies_fgpp),
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
        ("LAPS", c.laps),
        ("Groups", c.groups),
        ("Group Members", c.group_members_all),
        ("Privileged Members", c.privileged_group_members),
        ("OUs", c.ous),
        ("GPOs", c.gpos),
        ("GPO Links", c.gpo_links),
        ("DNS Records", c.dns_records),
    ]
    for name, fn in steps:
        try:
            rows = fn()
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"[!] {name}: {e}\n")
            rows = []
        sections[name] = rows
        sys.stderr.write(f"[+] {name}: {len(rows)}\n")
    c.close()

    external = None
    if not args.no_external:
        from . import external as ext
        sys.stderr.write("[*] external collectors (best-effort, read-only)...\n")
        external = ext.run_all(outdir, args.dc, args.domain, args.username, args.password,
                               with_bloodhound=not args.no_bloodhound, roast=args.roast)
        for tool, status in external.items():
            sys.stderr.write(f"[+] {tool}: {status}\n")

    # ---- analysis (the "more than ADRecon" layer) ----
    from . import findings as fnd, htmlreport
    flist = fnd.analyze(sections)
    score = fnd.posture_score(flist)
    sc = fnd.severity_counts(flist)

    counts = report.build(out, args.domain, sections, external, findings=flist, score=score)
    html_out = os.path.splitext(out)[0] + ".html"
    with open(html_out, "w", encoding="utf-8") as fh:
        fh.write(htmlreport.build(args.domain, flist, sections, external))

    total = sum(counts.values())
    sys.stderr.write(
        f"\n[✓] {total} objects, {len(flist)} findings | posture {score}/100 "
        f"(C:{sc['critical']} H:{sc['high']} M:{sc['medium']} L:{sc['low']}) ({time.time() - t0:.0f}s)\n"
        f"    xlsx -> {out}\n    html -> {html_out}\n")
    if external and any("bloodhound" in k.lower() for k in external):
        sys.stderr.write("    bloodhound/ -> load into BloodHound CE for attack paths\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
