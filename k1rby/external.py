"""k1rby external collectors — orchestrate best-of-breed OSS AD tools when present.

All invocations are READ-ONLY enumeration:
  - bloodhound-python --collectionmethod DCOnly  (LDAP-only graph collection for the GUI)
  - netexec (nxc) ldap ... --pass-pol / safe enum modules
  - certipy find                                  (AD CS / ESC exposure, enumeration only)

Each is best-effort and isolated: a missing binary or a failure is recorded and never aborts
the run. k1rby's own ldap3 collector is the source of truth for the xlsx; these add the
BloodHound graph + a couple of checks the raw attributes don't cover.
"""

from __future__ import annotations

import os
import shutil
import subprocess


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run(cmd: list[str], cwd: str, timeout: int = 900) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)[-4000:]
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except Exception as e:  # noqa: BLE001
        return 1, str(e)


def bloodhound(outdir: str, dc: str, domain: str, user: str, password: str,
               dns_tcp: bool = False) -> str:
    """DCOnly collection -> BloodHound JSON in outdir/bloodhound/ (load into the CE GUI).

    dns_tcp=True forces DNS over TCP, required when k1rby is run through a SOCKS pivot
    (e.g. `proxychains k1rby ...`) because UDP DNS cannot traverse SOCKS."""
    if not _have("bloodhound-python"):
        return "skipped (bloodhound-python not installed)"
    bdir = os.path.join(outdir, "bloodhound")
    os.makedirs(bdir, exist_ok=True)
    cmd = ["bloodhound-python", "-d", domain, "-u", user, "-p", password,
           "-ns", dc, "-c", "DCOnly", "--zip", "-op", "k1rby"]
    if dns_tcp:
        cmd.append("--dns-tcp")
    rc, out = _run(cmd, cwd=bdir)
    jsons = [f for f in os.listdir(bdir) if f.endswith((".json", ".zip"))]
    if jsons:
        return f"ok -> {bdir} ({len(jsons)} file(s))"
    return f"ran rc={rc}: {out.strip().splitlines()[-1] if out.strip() else 'no output'}"


def nxc_ldap(outdir: str, dc: str, domain: str, user: str, password: str,
             roast: bool = False) -> str:
    """Password policy (read-only) by default. roast=True ALSO requests AS-REP/TGS tickets —
    that is ACTIVE (non-destructive, no lockout, but it hits the KDC and is logged), so it is
    opt-in and off by default to keep the standard run pure read-only enumeration. k1rby's LDAP
    core already *identifies* roastable accounts (SPN / DONT_REQ_PREAUTH) without requesting
    anything."""
    if not _have("nxc") and not _have("netexec"):
        return "skipped (netexec not installed)"
    binary = "nxc" if _have("nxc") else "netexec"
    logf = os.path.join(outdir, "nxc-ldap.txt")
    jobs = [("pass-pol", ["--pass-pol"])]   # read-only LDAP
    if roast:   # opt-in, active
        jobs += [("asreproast", ["--asreproast", os.path.join(outdir, "asrep.txt")]),
                 ("kerberoast", ["--kerberoasting", os.path.join(outdir, "kerb.txt")])]
    collected = []
    for label, extra in jobs:
        rc, out = _run([binary, "ldap", dc, "-u", user, "-p", password, "-d", domain] + extra,
                       cwd=outdir, timeout=300)
        collected.append(f"===== {label} (rc={rc}) =====\n{out}\n")
    with open(logf, "w", encoding="utf-8") as fh:
        fh.write("\n".join(collected))
    return f"ok -> {logf}" + ("" if roast else " (pass-pol only; --roast for ticket requests)")


def certipy_find(outdir: str, dc: str, domain: str, user: str, password: str,
                 use_ssl: bool = False, dns_tcp: bool = False) -> str:
    """AD CS / ESC enumeration (find only — no requests/abuse).

    use_ssl=False forces `-ldap-scheme ldap` (plain 389, NTLM-signed): certipy v5 defaults to
    LDAPS, which breaks on DCs that have no LDAPS certificate. dns_tcp=True adds `-ns dc -dns-tcp`
    so name resolution traverses a SOCKS pivot."""
    if not _have("certipy") and not _have("certipy-ad"):
        return "skipped (certipy not installed)"
    binary = "certipy" if _have("certipy") else "certipy-ad"
    cmd = [binary, "find", "-u", f"{user}@{domain}", "-p", password, "-dc-ip", dc]
    cmd += ["-ldap-scheme", "ldaps" if use_ssl else "ldap"]
    if dns_tcp:
        cmd += ["-ns", dc, "-dns-tcp"]
    cmd.append("-stdout")
    rc, out = _run(cmd, cwd=outdir, timeout=300)
    logf = os.path.join(outdir, "certipy-adcs.txt")
    with open(logf, "w", encoding="utf-8") as fh:
        fh.write(out)
    vuln = "ESC" if "ESC" in out else ""
    return f"ok -> {logf}" + (f" ({vuln} finding present)" if vuln else "")


def run_all(outdir: str, dc: str, domain: str, user: str, password: str,
            with_bloodhound: bool = True, roast: bool = False,
            dns_tcp: bool = False, use_ssl: bool = False) -> dict[str, str]:
    results: dict[str, str] = {}
    if with_bloodhound:
        results["bloodhound-python (DCOnly)"] = bloodhound(
            outdir, dc, domain, user, password, dns_tcp=dns_tcp)
    results["netexec ldap"] = nxc_ldap(outdir, dc, domain, user, password, roast=roast)
    results["certipy find"] = certipy_find(
        outdir, dc, domain, user, password, use_ssl=use_ssl, dns_tcp=dns_tcp)
    return results
