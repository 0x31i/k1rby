"""k1rby findings engine — the layer ADRecon doesn't have.

Takes the raw collected sections and derives SECURITY FINDINGS: severity-rated issues with the
exact affected objects, a remediation, and a MITRE ATT&CK mapping — plus an overall posture
score. This is the PingCastle/PurpleKnight-style analysis on top of the ADRecon-style inventory.
Every rule is pure analysis of already-collected read-only data (no extra queries).
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    mitre: str
    remediation: str
    description: str
    affected: list = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.affected)


# ---- helpers ----------------------------------------------------------------------------------
def _age_days(datestr: str) -> float | None:
    if not datestr or datestr in ("never", ""):
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            d = datetime.datetime.strptime(str(datestr)[:16], fmt)
            return (datetime.datetime.now() - d).days
        except ValueError:
            continue
    return None


def _first(sections, name, default=None):
    rows = sections.get(name) or []
    return rows[0] if rows else (default or {})


# ---- rules: each returns the list of affected objects (empty = finding does not fire) ----------
def _r_krbtgt_old(s):
    for u in s.get("Users", []):
        if u.get("sAMAccountName", "").lower() == "krbtgt":
            age = _age_days(u.get("pwdLastSet"))
            if age and age > 180:
                return [{"account": "krbtgt", "pwdAgeDays": int(age)}]
    return []


def _r_mac_quota(s):
    q = _first(s, "Domain").get("machineAccountQuota")
    try:
        if q not in (None, "", "0") and int(q) > 0:
            return [{"ms-DS-MachineAccountQuota": q}]
    except (TypeError, ValueError):
        pass
    return []


def _r_kerberoast_priv(s):
    return [k for k in s.get("Kerberoastable", []) if str(k.get("adminCount")) == "1"]


def _r_kerberoast(s):
    return [k for k in s.get("Kerberoastable", []) if str(k.get("adminCount")) != "1"]


def _r_asrep_priv(s):
    return [a for a in s.get("AS-REP Roastable", []) if str(a.get("adminCount")) == "1"]


def _r_asrep(s):
    return [a for a in s.get("AS-REP Roastable", []) if str(a.get("adminCount")) != "1"]


def _r_unconstrained(s):
    dcs = {d.get("name", "").upper() for d in s.get("Domain Controllers", [])}
    out = []
    for d in s.get("Delegation", []):
        if "unconstrained" in str(d.get("delegation", "")) and d.get("object", "").upper().rstrip("$") not in dcs:
            out.append(d)
    return out


def _r_constrained(s):
    return [d for d in s.get("Delegation", []) if d.get("delegation") == "constrained"]


def _r_rbcd(s):
    return [d for d in s.get("Delegation", []) if "RBCD" in str(d.get("delegation", ""))]


def _r_pwd_not_req(s):
    return [{"account": u["sAMAccountName"]} for u in s.get("Users", [])
            if u.get("pwdNotRequired") and u.get("enabled")]


def _r_priv_never_expire(s):
    return [{"account": u.get("sAMAccountName")} for u in s.get("Privileged Users", [])
            if u.get("pwdNeverExpires")]


def _r_weak_policy(s):
    d = _first(s, "Domain")
    try:
        mpl = int(d.get("minPwdLength") or 0)
    except (TypeError, ValueError):
        return []
    if mpl and mpl < 12:
        return [{"minPwdLength": mpl, "recommended": "14+"}]
    return []


def _r_no_lockout(s):
    d = _first(s, "Domain")
    if str(d.get("lockoutThreshold")) == "0":
        return [{"lockoutThreshold": 0, "note": "accounts never lock — unlimited password guessing"}]
    return []


def _r_laps_readable(s):
    return s.get("LAPS", [])


def _r_stale_priv(s):
    out = []
    for u in s.get("Privileged Users", []):
        age = _age_days(u.get("lastLogon"))
        if u.get("enabled") and age is not None and age > 90:
            out.append({"account": u.get("sAMAccountName"), "lastLogonDays": int(age)})
    return out


def _r_eol_dc(s):
    eol = ("2000", "2003", "2008", "2012")
    return [{"dc": d.get("name"), "os": d.get("os")} for d in s.get("Domain Controllers", [])
            if any(y in str(d.get("os", "")) for y in eol)]


def _r_guest_enabled(s):
    return [{"account": u["sAMAccountName"]} for u in s.get("Users", [])
            if u.get("sAMAccountName", "").lower() == "guest" and u.get("enabled")]


def _r_old_pwd(s):
    out = []
    for u in s.get("Users", []):
        age = _age_days(u.get("pwdLastSet"))
        if u.get("enabled") and age is not None and age > 365:
            out.append({"account": u.get("sAMAccountName"), "pwdAgeDays": int(age)})
    return out[:500]


def _r_external_trusts(s):
    return [t for t in s.get("Trusts", []) if t.get("direction") in ("Bidirectional", "Outbound", "Inbound")]


_RULES = [
    ("AD-001", "KRBTGT password not rotated (>180 days)", "critical", "Kerberos",
     "T1558.001 (Golden Ticket)",
     "Reset the krbtgt password TWICE (with a wait between) to invalidate forged tickets.",
     "A stale krbtgt password lets an attacker who ever obtained its hash forge Golden Tickets indefinitely.",
     _r_krbtgt_old),
    ("AD-002", "Unconstrained delegation on a non-DC", "critical", "Delegation",
     "T1558.003 / T1134",
     "Remove TRUSTED_FOR_DELEGATION; use constrained/RBCD, and add admins to Protected Users.",
     "A host with unconstrained delegation can capture and reuse any user's TGT (incl. DAs) that authenticates to it.",
     _r_unconstrained),
    ("AD-003", "Privileged account is Kerberoastable (has SPN)", "critical", "Kerberos",
     "T1558.003 (Kerberoasting)",
     "Use group-managed service accounts (gMSA) or 25+ char passwords; remove SPNs from admin accounts.",
     "An admin account with an SPN can be Kerberoasted and cracked offline -> direct path to privilege.",
     _r_kerberoast_priv),
    ("AD-004", "Domain controller on an end-of-life OS", "critical", "Infrastructure",
     "T1210",
     "Upgrade DCs to a supported Windows Server release and decommission EOL hosts.",
     "An unsupported DC receives no security patches (e.g. Zerologon-class bugs) and anchors the whole domain.",
     _r_eol_dc),
    ("AD-005", "Privileged account is AS-REP roastable", "critical", "Kerberos",
     "T1558.004 (AS-REP Roasting)",
     "Enable Kerberos pre-authentication (clear DONT_REQ_PREAUTH) on privileged accounts.",
     "An admin without pre-auth yields a crackable AS-REP to any unauthenticated attacker.",
     _r_asrep_priv),
    ("AD-006", "Machine account quota allows any user to add computers", "high", "Configuration",
     "T1136.001 / RBCD",
     "Set ms-DS-MachineAccountQuota to 0 and delegate computer-join to a dedicated group.",
     "With quota > 0, any authenticated user can create computer accounts, enabling RBCD and other attacks.",
     _r_mac_quota),
    ("AD-007", "AS-REP roastable accounts", "high", "Kerberos", "T1558.004",
     "Enable Kerberos pre-authentication on these accounts.",
     "Accounts without pre-auth yield offline-crackable AS-REP hashes.",
     _r_asrep),
    ("AD-008", "Kerberoastable service accounts", "high", "Kerberos", "T1558.003",
     "Move to gMSA or long random passwords; rotate regularly.",
     "SPN accounts can be Kerberoasted; weak passwords crack quickly.",
     _r_kerberoast),
    ("AD-009", "Accounts with 'password not required'", "high", "Accounts", "T1078",
     "Remove the PASSWD_NOTREQD flag and enforce the password policy on these accounts.",
     "These accounts can have empty/weak passwords regardless of policy.",
     _r_pwd_not_req),
    ("AD-010", "No account-lockout policy", "high", "Policy", "T1110",
     "Set a lockout threshold (e.g. 5-10) with a reasonable duration.",
     "Without lockout, online password guessing/spraying is unlimited.",
     _r_no_lockout),
    ("AD-011", "Weak domain minimum password length", "high", "Policy", "T1110",
     "Raise minimum length to 14+ and consider a passphrase/fine-grained policy.",
     "Short minimums make offline and online guessing far easier.",
     _r_weak_policy),
    ("AD-012", "Local-admin (LAPS) passwords readable by this account", "high", "Credentials",
     "T1552.006",
     "Scope ms-Mcs-AdmPwd / Windows LAPS read rights to admins only.",
     "If a non-admin can read LAPS passwords, local-admin creds are exposed broadly.",
     _r_laps_readable),
    ("AD-013", "Constrained delegation configured", "medium", "Delegation", "T1558.003",
     "Review each constrained-delegation target; remove where not required; prefer RBCD.",
     "Constrained delegation can be abused to impersonate users to the target service.",
     _r_constrained),
    ("AD-014", "Resource-based constrained delegation (RBCD) present", "medium", "Delegation",
     "T1134.001",
     "Audit msDS-AllowedToActOnBehalfOfOtherIdentity on these objects.",
     "RBCD entries can be an attacker-planted privilege-escalation path.",
     _r_rbcd),
    ("AD-015", "Privileged accounts with non-expiring passwords", "medium", "Accounts", "T1078",
     "Remove DONT_EXPIRE_PASSWORD on admin accounts; rotate regularly.",
     "Non-expiring admin passwords increase the window for credential compromise.",
     _r_priv_never_expire),
    ("AD-016", "Stale but enabled privileged accounts (>90d no logon)", "medium", "Accounts",
     "T1078",
     "Disable or review privileged accounts that are no longer in use.",
     "Unused admin accounts are prime, low-noise targets.",
     _r_stale_priv),
    ("AD-017", "User accounts with very old passwords (>1 year)", "medium", "Accounts", "T1110",
     "Enforce password rotation; investigate accounts that never rotate.",
     "Old passwords are more likely cracked/leaked and never re-secured.",
     _r_old_pwd),
    ("AD-018", "Guest account enabled", "low", "Accounts", "T1078.001",
     "Disable the built-in Guest account.",
     "An enabled Guest account is an unnecessary anonymous-ish foothold.",
     _r_guest_enabled),
    ("AD-019", "Active domain/forest trusts", "info", "Trusts", "T1482",
     "Review trust direction/type; ensure SID filtering on external trusts.",
     "Trusts expand the attack surface across security boundaries.",
     _r_external_trusts),
]


def analyze(sections: dict) -> list[Finding]:
    out = []
    for fid, title, sev, cat, mitre, rem, desc, check in _RULES:
        try:
            affected = check(sections) or []
        except Exception:  # noqa: BLE001
            affected = []
        if affected:
            out.append(Finding(fid, title, sev, cat, mitre, rem, desc, affected))
    out.sort(key=lambda f: (SEV_ORDER.index(f.severity), -f.count))
    return out


def posture_score(findings: list[Finding]) -> int:
    """100 = clean. Each finding subtracts a weighted penalty (capped), scaled by how many
    objects it hits (saturating) so one huge finding doesn't zero the score by itself."""
    penalty = 0.0
    for f in findings:
        w = _SEV_WEIGHT.get(f.severity, 0)
        # saturating scale: 1 object = 1.0x, grows slowly with count, cap 2x
        scale = 1.0 + min(0.5, (f.count - 1) * 0.02) if f.count else 1.0
        penalty += w * scale
    return max(0, round(100 - min(penalty, 100)))


def severity_counts(findings: list[Finding]) -> dict:
    c = {s: 0 for s in SEV_ORDER}
    for f in findings:
        c[f.severity] += 1
    return c
